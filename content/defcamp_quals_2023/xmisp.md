---
title: xmisp
type: writeup
date: 2023-10-22T09:56:31+03:00
description: Writeup for xmisp [Defcamp Quals 2023]
author: sunbather
tags:
  - rev
draft: false
---

___

## Challenge Description

It's MIPS or MISP i dont know.

Flag format: CTF{sha256}

### Intuition

We decompile the binary and see it's a MIPS binary. We find it does some XORing with some specific bytes. We can take the encrypted flag and the beginning of the flag (``CTF{``) to perhaps find the key for each byte.

### Solution

Did it in an interactive python session:

```py
# Extract the string from Ghidra
>>> s = b"ER@}>062eb6d1bbb36031>6c2522?gg1gcgebd657053>b15434342b26`g3e3`e3>7?{"
>>> for i in range(len(s)):
...     print(chr(0x6 ^ s[i]), end='')
... 
CTF{8604cd0b7ddd5065780e43449aa7aeacdb0316358d73252524d40fa5c5fc5819}>>> 
```

#### Flag

```CTF{8604cd0b7ddd5065780e43449aa7aeacdb0316358d73252524d40fa5c5fc5819}```
