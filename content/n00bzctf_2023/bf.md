---
title: Bf
date: 2023-06-16T15:20:45+03:00
description: Writeup for BF [n00bzctf 2023]
tags:
- rev
draft: false
---

## Challenge Description

Mal sehen, ob Sie dieses Mal Ihren Verstand in den Griff bekommen.  
Author: Heith

## Note

We did not solve this challenge during this CTF. This writeup is just a
descirption of the thought process we went through while attempting to solve
this, and ultimately how we solved it based on this
[writeup](https://gist.github.com/matthw/688bd912a40e47fba7946fec2a1c601b) [^1] by
matthw. So credits to him.

## Attempts

Clearly you can't read brainfuck. And this one was particularly hard to read.  
Snippet from the challenge:

```brainfuck
>->>>>>,[----------[++++++++++>>>>>,>]<]>---<+[-<+]->>>>>[<+++++++++++++++++++++
+++++++++++[>>[-]+>[-]<<-<->[>-]>[-<<[-]>>>]<<<]>+++++++++++++++++++++++++++++++
++++++++++++++++>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++<[>->+<[>]>[<+>-]<<[<]>-]>[-]>[-<<+>>]>>>]+[-<+]-
>>>>>-------------------------------[[-]--+[-<+]-<[-]+>++[-->++]]>>>>>----------
-----------------------------------------------------[[-]--+[-<+]-<[-]+>++[-->++
]]>>>>>---------------------------------------------------------------[[-]--+[-<
+]-<[-]+>++[-->++]]>>>>>-------------------[[-]--+[-<+]-<[-]+>++[-->++]]>>>>>---
----------------------------------------[[-]--+[-<+]-<[-]+>++[-->++]]>>>>>------
...
```

What we tried was to convert this to C, with the hope that the transpiler used
would optimize (and deobfuscate as a consequence) the code. After some research
and many tries, the we got the best results using
[esotope-bfc](https://github.com/lifthrasiir/esotope-bfc)[^2], which specifically . This yielded some
pretty clean `c` code that could be further cleaned up as there were some
pretty big chunks of repeating code. Despite this, we couldn't figure at all
from the code how the input was transformed.

Other things we tried, were to take the generated code and compiler it with the
highest levels of optimization (`-O3`) and try to open the resulted binary in
ghidra with the hopes that the compiler would be able to abstract away the
confusion. That didn't work either, as the decompilation looked just as bad as
the original code.

Also, we tried to fuzz the input, but didn't manage to draw any significant
conclusions from these experiments.

## The Solution

In his writeup, the OP used callgrind[^3] to count the instructions executed on
different inputs. The inputs are given incrementally one character at a time,
with byte-values in increasing order. What we notice is a drop in the
instruction count when **a prefix of the flag** is given as input. We can use
this to build the flag character by character.

## Why this works

I don't know. But intuitively, the instruction count goes up as the values of
the given bytes goes up because of the way brainfuck works and because the
compilers aren't able to get rid of every set of inefficient operations. Also,
it drops because (maybe) the checks for a matching character require less
operations.

The author's solution [^1] was a mix of python and shell script. I rewritten it
entirely in `shell`, which anecdotally makes it faster.

As a side note, the author had a prefix of `____{` given to the script, which
in my case was not necessary. No clue why.

```sh
#!/bin/sh

f=""
s=""

while :; do
    prev=0
    for i in {30..127}; do
        hex="\x$(printf "%x" $i)"
        s="${f}${hex}\x00"
        result=$(echo -ne ${s} | \
            valgrind --tool=callgrind ./ccode 2>&1 | \
            grep -Eo ": [0-9]+$" | \
            cut -c 3-)

        echo -en "\rtrying: $s"
        if [ "$result" -lt "$prev" ]; then
            f="${f}${hex}"
            echo -e "\n$f"
            break;
        fi
        prev="$result"

        rm -r callgrind* 2>/dev/null
        rm -r vgcore* 2>/dev/null
    done
done
```

### Flag

**n00bz{Y0u_60D_1t_60d4Mm17_1m_Pr0Ud_0f_y0U_N0W_t4K3_Re57!!!}**

## Resources

[^1]: Thanks to matthw for the writeup: (https://gist.github.com/matthw/688bd912a40e47fba7946fec2a1c601b)
[^2]: Esotope Brainfuck to C compiler: (https://github.com/lifthrasiir/esotope-bfc)
[^3]: Callgrind: a valgrind profiler: https://valgrind.org/docs/manual/cl-manual.html

