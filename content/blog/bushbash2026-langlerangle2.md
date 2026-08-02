+++
title = "BushBash CTF 2026 (\\langle\\rangle)*6 writeup"
date = 2026-08-02
+++

warning this post sucks i wrote it in like 15 minutes

this weekend bushbash ctf ran!
it's a ctf run by the anu (australian national university) computer science club which is awesome!!
i ended up not doing too many challenges because my teammates were too quick but i did do this one with an apparently very unintended solution!
there is also a writeup comp so yknow i have to (but the prize is claude code so ....... idk... i don't exactly want claude code lol)

anyways the challenge was called \langle\rangle\langle\rangle\langle\rangle\langle\rangle\langle\rangle\langle\rangle (yeah it's a very long name the name actually didn't fit into the box of the challenge description) and was the second c++ template challenge after a challenge called just \langle\rangle\langle\rangle (which i didn't do or even look at).
you're given two c++ files
```cpp
// main.cpp
#include "<><><><><><>.hpp"
#include <iostream>
#include <stdio.h>

int main() {
    for (int i = 0; i < 16; i++) {
        std::cout << output[i] << ',';
    }
    std::cout << '\n';
    return 0;
}
```
main.cpp just prints some buffer which must have been defined in `<><><><><><>.hpp` so lets look at that... (warning you will have to scroll a lot)
```cpp
template <int TFKN>
struct IDXV {
    static constexpr int VWMN = TFKN;
};

template <typename KCJO, typename FTCO>
struct OWRC {
    using EGXM = KCJO;
    using LHQO = FTCO;
};
struct YVDD {};

template<typename DKMV, int FEHF>
struct TWDL;

template<typename KCJO, typename FTCO> struct TWDL<OWRC<KCJO, FTCO>, 0> {
    using NUQH = KCJO;
};
template<typename KCJO, typename FTCO, int FEHF> struct TWDL<OWRC<KCJO, FTCO>, FEHF> {
    using NUQH = typename TWDL<FTCO, FEHF - 1>::NUQH;
};

template <typename JCVL, typename NUQH>
struct RCYK {
    using NYUB = JCVL;
    using LGZI = NUQH;
};

template<typename WOED, typename VVZX, typename AGWU> struct BJDC;

template<typename OCWC, typename QGCB, typename TJLU, typename KUMJ>
struct BJDC<OCWC, OWRC<RCYK<OCWC, TJLU>, KUMJ>, QGCB> {
    using NUQH = TJLU;
};

template<typename OCWC, typename CWYF, typename QGCB, typename KSCB, typename KUMJ>
struct BJDC<OCWC, OWRC<RCYK<CWYF, KSCB>, KUMJ>, QGCB> {
    using NUQH = typename BJDC<OCWC, KUMJ, QGCB>::NUQH;
};

template<typename OCWC, typename QGCB>
struct BJDC<OCWC, YVDD, QGCB> {
    using NUQH = QGCB;
};

template<typename QEEX, typename NIBK> struct XBGW;

template <int XFVU, typename NIBK> struct XBGW<IDXV<XFVU>, NIBK> {
    using NUQH = IDXV<XFVU>;
};

template <typename JLJC> struct OGYP;
template <typename UWDA, typename NIBK> struct XBGW<OGYP<UWDA>, NIBK> {
    using NUQH = typename BJDC<UWDA, NIBK, IDXV<0>>::NUQH;
};

struct EPMS;
template <typename RZVH, typename GFIL, typename NIBK> struct XBGW<OWRC<EPMS, OWRC<RZVH, OWRC<GFIL, YVDD>>>, NIBK> {
    using NUQH = IDXV<XBGW<RZVH, NIBK>::NUQH::VWMN + XBGW<GFIL, NIBK>::NUQH::VWMN>;
};

struct KZRJ;
template <typename RZVH, typename GFIL, typename NIBK> struct XBGW<OWRC<KZRJ, OWRC<RZVH, OWRC<GFIL, YVDD>>>, NIBK> {
    using NUQH = IDXV<XBGW<RZVH, NIBK>::NUQH::VWMN * XBGW<GFIL, NIBK>::NUQH::VWMN>;
};

struct RCOB;
template <typename RZVH, typename GFIL, typename NIBK> struct XBGW<OWRC<RCOB, OWRC<RZVH, OWRC<GFIL, YVDD>>>, NIBK> {
    using NUQH = IDXV<XBGW<RZVH, NIBK>::NUQH::VWMN % XBGW<GFIL, NIBK>::NUQH::VWMN>;
};
struct QVTC;
template <typename RZVH, typename GFIL, typename NIBK> struct XBGW<OWRC<QVTC, OWRC<RZVH, OWRC<GFIL, YVDD>>>, NIBK> {
    using NUQH = IDXV<XBGW<RZVH, NIBK>::NUQH::VWMN ^ XBGW<GFIL, NIBK>::NUQH::VWMN>;
};
template<typename BVNE, typename NFRW, typename FNCM>
using IEYF = OWRC<BVNE, OWRC<NFRW, OWRC<FNCM, YVDD>>>;



struct CFDD;
template <typename DJSC, typename RHKC, typename NIBK> struct XBGW<IEYF<CFDD, DJSC, RHKC>, NIBK> {
    using NJNO = typename XBGW<RHKC, NIBK>::NUQH;
    using ULMH = typename XBGW<DJSC, NIBK>::NUQH;
    using JGNJ = typename TWDL<ULMH, NJNO::VWMN>::NUQH;
    using NUQH = typename XBGW<JGNJ, NIBK>::NUQH;
};


struct FKMU;
struct HJAJ;
struct LWDC;
struct RLGL;
struct FNHJ;
struct WYUQ;

// SIFL KFUG HWSJ
template<typename UVBG, typename UYNP> struct CWCE;


template<typename FVCY, typename QEEX>
struct JLLV;

template<typename FVCY, typename QEEX, typename UYNP> struct CWCE<JLLV<FVCY, QEEX>, UYNP> {
    using OJTA = OWRC<RCYK<FVCY, typename XBGW<QEEX, UYNP>::NUQH>, UYNP>;
};

template<typename FVCY, typename QEEX>
struct JWTR;

template<typename FVCY, typename QEEX, typename UYNP> struct CWCE<JWTR<FVCY, QEEX>, UYNP> {
    using IQYW = typename XBGW<OGYP<FVCY>, UYNP>::NUQH;
    using YNMX = typename XBGW<QEEX, UYNP>::NUQH;
    using OJTA = OWRC<RCYK<FVCY, OWRC<YNMX, IQYW>>, UYNP>;
};

template<typename FVCY, typename UVBG>
struct ITFH;

template<typename FVCY, typename CYSS, typename UYNP> struct CWCE<ITFH<FVCY, CYSS>, UYNP> {
    using IQYW = typename BJDC<FVCY, UYNP, IDXV<0>>::NUQH;
    using ELXE = typename CWCE<CYSS, UYNP>::OJTA;
    using OJTA = OWRC<RCYK<FVCY, IQYW>, ELXE>;
};

template<typename FCEA>
struct KJAT;

template<typename UYNP> struct CWCE<KJAT<YVDD>, UYNP> {
    using OJTA = UYNP;
};
template<typename BQOF, typename KUMJ, typename UYNP> struct CWCE<KJAT<OWRC<BQOF, KUMJ>>, UYNP> {
    using OPZU = typename CWCE<BQOF, UYNP>::OJTA;
    using OJTA = typename CWCE<KJAT<KUMJ>, OPZU>::OJTA;
};

template<typename UVBG, int LXHT>
struct HPFP;

template<typename UVBG, typename UYNP> struct CWCE<HPFP<UVBG, 0>, UYNP> {
    using OJTA = UYNP;
};
template<typename UVBG, typename UYNP, int LXHT> struct CWCE<HPFP<UVBG, LXHT>, UYNP> {
    using OJTA = typename CWCE<KJAT<OWRC<UVBG, OWRC<HPFP<UVBG, LXHT - 1>, YVDD>>>, UYNP>::OJTA;
};

struct WYUQ;
struct ARVM;
struct QFKV;
struct GMDA;
struct EZUR;
struct SMSW;
struct DLHK;
struct WVTF;

using ZCHU = IEYF<RCOB, IEYF<KZRJ, IEYF<EPMS, OGYP<FNHJ>, OGYP<SMSW>>, IDXV<17>>, IDXV<135>>;

using IZUF = KJAT<OWRC<
    ITFH<FKMU,
    ITFH<HJAJ, 
    ITFH<DLHK,
    ITFH<WYUQ,
        KJAT<OWRC<JLLV<DLHK, IDXV<0>>, OWRC<
        HPFP<
            KJAT<OWRC<
                JLLV<SMSW, IEYF<CFDD, OGYP<WYUQ>, OGYP<DLHK>>>, OWRC<
                JLLV<SMSW, IEYF<EPMS, IEYF<KZRJ, OGYP<SMSW>, OGYP<WVTF>>, OGYP<WVTF>>>, OWRC<
                JLLV<ARVM, OGYP<FNHJ>>, OWRC<
                JLLV<QFKV, IEYF<QVTC, OGYP<RLGL>, ZCHU>>, OWRC<
                JLLV<RLGL, OGYP<ARVM>>, OWRC< 
                JLLV<FNHJ, OGYP<QFKV>>,OWRC<
                JLLV<DLHK, IEYF<EPMS, OGYP<DLHK>, IDXV<1>>>, YVDD
                >>>>
            >>>>
        , 16>, OWRC<JLLV<WVTF, IEYF<EPMS, OGYP<WVTF>, IEYF<EPMS, OGYP<RLGL>, OGYP<FNHJ>>>>, YVDD>>>
    >>
    >
    >
    >
, YVDD>>;

using GEUE = OWRC<IDXV<10>, OWRC<IDXV<21>, OWRC<IDXV<99>, OWRC<IDXV<4>, OWRC<IDXV<534>, OWRC<IDXV<24>, OWRC<IDXV<63>, OWRC<IDXV<57>, OWRC<IDXV<102>, OWRC<IDXV<38>, OWRC<IDXV<0>, OWRC<IDXV<123>, OWRC<IDXV<53>, OWRC<IDXV<674>, OWRC<IDXV<12>, OWRC<IDXV<57>, YVDD>>>>>>>>>>>>>>>>;

struct AWNQ;
struct AXEK;
// This is where the flag should go if you were encrypting it.
using KVRP = OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, YVDD>>>>>>>>>>>>>>>>>>;
using KYNN = OWRC<
RCYK<WYUQ, GEUE>
, OWRC<
RCYK<RLGL, IDXV<0>>
, OWRC<
RCYK<FNHJ, IDXV<0>>
, OWRC<
RCYK<AWNQ, KVRP>
, OWRC<
RCYK<AXEK, YVDD>
, OWRC<
RCYK<WVTF, IDXV<1>>
, YVDD>>>>>>;


using TFGD = KJAT<OWRC<
    JLLV<DLHK, IDXV<0>>    
, OWRC<
    HPFP<
    KJAT<OWRC<
        JLLV<RLGL, IEYF<CFDD, OGYP<AWNQ>, OGYP<DLHK>>>
    , OWRC<
        JLLV<FNHJ, IEYF<CFDD, OGYP<AWNQ>, IEYF<EPMS, OGYP<DLHK>, IDXV<1>>>>
    , OWRC<
        IZUF
    , OWRC<
        JWTR<AXEK, OGYP<RLGL>>
    , OWRC<
        JWTR<AXEK, OGYP<FNHJ>>
    , OWRC<
        JLLV<DLHK, IEYF<EPMS, OGYP<DLHK>, IDXV<2>>>
    , YVDD>>>>>>>
    , 9>
, YVDD>>>;

using YGSV = typename CWCE<TFGD, KYNN>::OJTA;

template<int TFKN>
using BCAD = typename TWDL<BJDC<AXEK, YGSV, IDXV<-1>>::NUQH, TFKN>::NUQH;

using DAIO = BCAD<0>;
const int output[18] = {
    BCAD<17>::VWMN,
    BCAD<16>::VWMN,
    BCAD<15>::VWMN,
    BCAD<14>::VWMN,
    BCAD<13>::VWMN,
    BCAD<12>::VWMN,
    BCAD<11>::VWMN,
    BCAD<10>::VWMN,
    BCAD<9>::VWMN,
    BCAD<8>::VWMN,
    BCAD<7>::VWMN,
    BCAD<6>::VWMN,
    BCAD<5>::VWMN,
    BCAD<4>::VWMN,
    BCAD<3>::VWMN,
    BCAD<2>::VWMN,
    BCAD<1>::VWMN,
    BCAD<0>::VWMN,
};
```
WHAT IS THIS!!!!!!!!
this is a ginormous mess and i do not want to understand any of it!!!
especially because it's c++!
i've only ever heard horror stories about c++ templates!!
(also lol this code block is completely breaking my static site generator's syntax highlighter oh well)

okay so what do we do?
well, we can at least run the program with `g++ main.cpp && ./a.out` and it prints out some numbers
```
86,144,33,4,217,96,126,210,214,48,94,97,130,41,2,179,
```

oh yeah i forgot to mention the challenge description gave two lists of numbers
```
key: [10, 21, 99, 4, 534, 24, 63, 57, 102, 38, 0, 123, 53, 674, 12, 57]
message: [221, 75, 97, 125, 30, 124, 51, 122, 15, 186, 39, 46, 74, 175, 120, 83, 219, 165]
```
so the printed numbers are probably a message for a different input, and the message given in the challenge description is probably the encoded message of the flag!

looking through the ginormous template mess, we see something that looks a little tiny bit readable:
```cpp
using GEUE = OWRC<IDXV<10>, OWRC<IDXV<21>, OWRC<IDXV<99>, OWRC<IDXV<4>, OWRC<IDXV<534>, OWRC<IDXV<24>, OWRC<IDXV<63>, OWRC<IDXV<57>, OWRC<IDXV<102>, OWRC<IDXV<38>, OWRC<IDXV<0>, OWRC<IDXV<123>, OWRC<IDXV<53>, OWRC<IDXV<674>, OWRC<IDXV<12>, OWRC<IDXV<57>, YVDD>>>>>>>>>>>>>>>>;

struct AWNQ;
struct AXEK;
// This is where the flag should go if you were encrypting it.
using KVRP = OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, YVDD>>>>>>>>>>>>>>>>>>;
```
GEUE and KVRP sure look like cons lists!
moreover, GEUE seems to have the key typed in for us!
how nice of them.

if we change some of the numbers in KVRP and run the program again, we get a different output! (im not going to show this it's too hard)
so i thought "hmm! what if i type in a part of the flag, and see what happens!"
```cpp
using KVRP = OWRC<IDXV<'b'>, OWRC<IDXV<'u'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'b'>, OWRC<IDXV<'a'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'{'>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<0>, OWRC<IDXV<'}'>, YVDD>>>>>>>>>>>>>>>>>>;
```
and we get the numbers
```
33,90,123,0,106,29,26,0,60,84,110,24,60,32,61,65,
```
uhhh okay that doesn't look similar to the given message at all...
darn!

from this point i ended up just typing random guesses into the 0s after the open brace, and saw this pattern...
```cpp
using KVRP = OWRC<IDXV<'b'>, OWRC<IDXV<'u'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'b'>, OWRC<IDXV<'a'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'{'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'}'>, YVDD>>>>>>>>>>>>>>>>>>;
// prints 33,90,123,0,106,29,26,0,159,70,30,76,18,54,191,107,
```
woah!! the start of the array looks so similar!
that's so interesting...
with some more experimenting:

```cpp
// change the last } to a b
using KVRP = OWRC<IDXV<'b'>, OWRC<IDXV<'u'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'b'>, OWRC<IDXV<'a'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'{'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'b'>, YVDD>>>>>>>>>>>>>>>>>>;
// prints 33,90,123,0,106,29,26,0,159,70,30,76,18,54,191,107,
// nothing changed??
```

it hit me that the for loop in main.cpp only iterates 16 times, so i changed that to 18 and then re-did some experimenting: (sorry i literally just fiddled with stuff until i spotted a pattern so it's kinda hard to explain a thought process)

```cpp
using KVRP = OWRC<IDXV<'b'>, OWRC<IDXV<'u'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'b'>, OWRC<IDXV<'a'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'{'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'}'>, YVDD>>>>>>>>>>>>>>>>>>;
// prints 33,90,123,0,106,29,26,0,159,70,30,76,18,54,191,107,110,14,

// change the last } to a b
using KVRP = OWRC<IDXV<'b'>, OWRC<IDXV<'u'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'b'>, OWRC<IDXV<'a'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'{'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'b'>, YVDD>>>>>>>>>>>>>>>>>>;
// prints 33,90,123,0,106,29,26,0,159,70,30,76,18,54,191,107,229,18,
// only the last two bytes changed!

// change the second last character to b
using KVRP = OWRC<IDXV<'b'>, OWRC<IDXV<'u'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'b'>, OWRC<IDXV<'a'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'{'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'b'>, OWRC<IDXV<'}'>, YVDD>>>>>>>>>>>>>>>>>>;
// prints 33,90,123,0,106,29,26,0,159,70,30,76,18,54,191,107,225,84,
// oh, again only the last two bytes changed!

// change the third last character to b
using KVRP = OWRC<IDXV<'b'>, OWRC<IDXV<'u'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'b'>, OWRC<IDXV<'a'>, OWRC<IDXV<'s'>, OWRC<IDXV<'h'>, OWRC<IDXV<'{'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'a'>, OWRC<IDXV<'b'>, OWRC<IDXV<'a'>, OWRC<IDXV<'}'>, YVDD>>>>>>>>>>>>>>>>>>;
// prints 33,90,123,0,106,29,26,0,159,70,30,76,18,54,62,79,249,63,
// the last four bytes changed!!
```
so from this experimenting, it seems like pairs of characters affect pairs of output characters and muddle up everthing afterwards, but *not* before!
what this means is that we can brute force the first two letters of the "flag" (or secret), until the first two bytes of the output match the target, then continue to the next two, and repeat until the very end!
also it seems like KVRP does not store the flag and going back to the challenge again it says that the flag is of the form `bushbash{password}` so we're actually figuring out a password apparently

anyways yeah i wrote a big python script that did this brute force and it took a few hours to run and was horribly written but it did the job
```py
flag = '??????????????????'

SOURCE = """
// ... imagine all of the source code pasted here
// format string nonsense so we can set the flag lol
using KVRP = OWRC<IDXV<'{0}'>, OWRC<IDXV<'{1}'>, OWRC<IDXV<'{2}'>, OWRC<IDXV<'{3}'>, OWRC<IDXV<'{4}'>, OWRC<IDXV<'{5}'>, OWRC<IDXV<'{6}'>, OWRC<IDXV<'{7}'>, OWRC<IDXV<'{8}'>, OWRC<IDXV<'{9}'>, OWRC<IDXV<'{10}'>, OWRC<IDXV<'{11}'>, OWRC<IDXV<'{12}'>, OWRC<IDXV<'{13}'>, OWRC<IDXV<'{14}'>, OWRC<IDXV<'{15}'>, OWRC<IDXV<'{16}'>, OWRC<IDXV<'{17}'>, YVDD>>>>>>>>>>>>>>>>>>;
// the rest of the code blah blah blah

//#include <iostream>
#include <stdio.h>

int main() {{
    for (int i = 0; i < 18; i++) {{
        // aha if we use printf it compiles faster!!
        //std::cout << output[i] << ',';
        printf("%d,", output[i]);
    }}
    //std::cout << '\\n';
    printf("\\n");
    return 0;
}}
"""
import os
import subprocess

def get_out(f):
    # replace the flag in the source code with our guess f, compile the program and read the output
    f = ['\\\'' if c == '\'' else '\\\\' if c == '\\' else c for c in f]
    s = SOURCE.format(f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12], f[13], f[14], f[15], f[16], f[17])
    with open('source.cpp', 'w') as f:
        f.write(s)
    subprocess.run(['g++', 'source.cpp'])
    res = subprocess.run(['./a.out'], capture_output=True)
    # yeah im using eval... im sorry......
    arr = eval('[' + res.stdout[:-2].decode() + ']')
    return arr

GOAL = [221, 75, 97, 125, 30, 124, 51, 122, 15, 186, 39, 46, 74, 175, 120, 83, 219, 165]

from itertools import product

for i in range(9):
    progr = False
    # 32 to 127 is the printable ascii range btw! very useful numbers to have memorised if you want to write brute force scripts :yum:
    for a, b in product(list(map(chr, (range(32, 127)))), repeat=2):
        flag2 = flag[:2*i] + a + b + flag[2*(i+1):]
        out = get_out(flag2)
        print(flag2, out)
        if out[2*i:2*(i+1)] == GOAL[2*i:2*(i+1)]:
            flag = flag2
            progr = True
            print(flag)
            break
    if not progr:
        raise "oops"
```
compiling was very slow

and in the end the password was `ma5B3_sf1NAe_neXt?`.
apparently sfinae is some c++ thing and i was terrified that this password hinted at the existence of a soon to be released third c++ template challenge in the second wave of challenges, but fortunately there was not any!

anyways yeah the challenge author said this solution was extremely unintended, and that the intended solution was to actually read the code!
there's no way i was doing that!
(and of course the solution most people would have actually done was get an ai to read the code... but alas)
yeah fun and silly challenge
