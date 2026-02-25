+++
title = "Fast search-like algorithms on grids using epic bit manipulation tricks"
date = 2025-04-25
+++

This post will be a introduction to bitboards, which are an extremely efficient way to represent small grids of Boolean values.
In this representation, we perform most operations with only a couple simple bitwise operations, which CPUs are very good at executing!
At the end we'll walk through some applications of this to get big speed-ups! (spoiler: double digit speed-ups!)

# Basics

For this section I will assume we are working with 8x8 boards, as done in computer chess (where I think bitboards originated from).
The techniques applied here will work for smaller boards, and can be extended to work on larger boards as well (which we will see later).

## Floodfill

```rs
fn floodfill(mut bb: u64) -> u64 {
    let mut last = !bb
    while last != bb {
        last = bb;
        bb |= (last & 0x0101010101010101) >> 1;
        bb |= (last & 0x8080808080808080) << 1;
        bb |= last >> 8;
    }
}
```

# AOC 2024 day 18
