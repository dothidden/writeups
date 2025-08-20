---
title: Vm
type: writeup
date: 2023-06-15T12:16:46+03:00
description: Writeup for VM
author: zenbassi
tags:
- rev
draft: false
---

---

## Challenge Description

Ever tried reversing a VM? Here's a simple one!  
Author: NoobHacker

## Analyzing in Ghidra

Opening the `vm` in ghidra, we can that each byte from the `code` is checked
and interpreted accordingly. There are not too many possible instructions.
Based on the decompilation we create a disassembler in python and parse the
`code` with it. 

Snippet from the python disassembler:
```python
f = open("./code", "rb")
instructions = f.read()

i = 0
while i < len(instructions):
    op = instructions[i]
    if op == 0:
        print('nop')
    elif op == 1:
        r = instructions[i + 1]
        print(f'push r{r}')
        i += 1
    elif op == 2:
        r = instructions[i + 1]
        print(f'pop r{r}')
        i += 1
    elif op == 3: 
        r1 = instructions[i + 1]
        r2 = instructions[i + 2]
        print(f'mov r{r1} <- r{r2}')
        i += 2
    ...
```

Disassembled code:
```
push read()
pop r0
mov r1 <- 110
r0 ^= r1
print(r0)     # 1st character 110 | n
push read()
pop r0
mov r1 <- 48
r0 ^= r1
print(r0)     # 2nd character 48 | 0
push read()
pop r0
mov r1 <- 48
r0 ^= r1
print(r0)     # 3rd character 48 | 0
push read()
pop r0
mov r1 <- 98
r0 ^= r1
print(r0)     # 4th character 98 | b
push read()
pop r0
mov r1 <- 122
r0 ^= r1
print(r0)     # 5th character 122 | z
push read()
```
It's easy to see all the code does is to print the flag. The flag is obtained
by converting the numbers from all the mov instructions to ASCII and concatenating
all the characters together.

### Flag

n00bz{x0r_XoR_xOR}

## Post CTF upsolve

Some other teams reported solving this just by opening the `code` in a hex editor.
Considering how the disassembled code looked, this made sense. And indeed, using
`xxd -c 11 code | head -n 18` the following is obtained:

```hex
00000000: 0d02 0004 016e 0900 010c 00  .....n.....
0000000b: 0d02 0004 0130 0900 010c 00  .....0.....
00000016: 0d02 0004 0130 0900 010c 00  .....0.....
00000021: 0d02 0004 0162 0900 010c 00  .....b.....
0000002c: 0d02 0004 017a 0900 010c 00  .....z.....
00000037: 0d02 0004 017b 0900 010c 00  .....{.....
00000042: 0d02 0004 0178 0900 010c 00  .....x.....
0000004d: 0d02 0004 0130 0900 010c 00  .....0.....
00000058: 0d02 0004 0172 0900 010c 00  .....r.....
00000063: 0d02 0004 015f 0900 010c 00  ....._.....
0000006e: 0d02 0004 0158 0900 010c 00  .....X.....
00000079: 0d02 0004 016f 0900 010c 00  .....o.....
00000084: 0d02 0004 0152 0900 010c 00  .....R.....
0000008f: 0c00 0d02 0004 015f 0900 01  ......._...
0000009a: 0c00 0d02 0004 0178 0900 01  .......x...
000000a5: 0c00 0d02 0004 014f 0900 01  .......O...
000000b0: 0c00 0d02 0004 0152 0900 01  .......R...
000000bb: 0c00 0d02 0004 017d 0900 01  .......}...
```

Which, btw, is just sad.
