---
title: MyPin
date: 2023-06-15T12:43:32+03:00
description: Writeup for MyPin [n00bzctf 2023]
tags:
- rev
draft: true
---

## Challenge Description

I made a safe with a pin of only two digits.
Author: Heith

## First steps

We're provided with a `.jar`, so we are are working with Java. My tool of 
choice for this has been `jadx-gui`, which decompiles Java bytecode pretty
nicely (be careful that it can misinterpret sometimes. Ghidra is an alternative for such cases).

Pulling up the disassembled code, we see two buttons, listeners, and some
processing based on single digit (0 or 1) input from the two buttons. Seems safe to
run, so we run it with `java -jar My-pin.jar`. This spawns a window with two buttons, which generate an output on press.

## Solution

Looking further into the code we notice that the output is generated from **at most 9
1s or 0s** stringed together. This yields a very small search space. The disassembled 
code is very accurate, so we can just copy-paste the relevant parts and write a few lines which generate all possible inputs and the corresponding output.

Find below the generator as well as the call one of the disassembled functions which
expects the generated input.

```java
public static void main(String[] args) {
    int cnt = 10;
    for (int i = 0; i < ((1 << cnt) - 1); ++i) {
        Main s = new Main();
        for (int j = 0; j < cnt; ++j) {
            int bit = 0;
            if ((i & (1 << j)) != 0) {
                bit = 1;
            }
            s.process((char)('0' + bit));
            System.out.println(s.getData());
        }
        System.out.println("=============================");
    }
}
```
Searching through the output for _n00bz{_ gets us the flag.

### Flag

**n00bz{y0uuu_n33d_t0_bRutefoRc3_1s_e4zyY_}**

bruteforce is what thy wanted all along huh?
