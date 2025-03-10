---
title: Very Serious Cryptography
date: 2025-03-10T03:15:35+03:00
description: Writeup for Very Serious Cryptography [KalmarCTF 2025]
author: h3pha 
tags:
- crypto
draft: false
---
___

>This writeup is just a better explanation of [this](https://connor-mccartney.github.io/cryptography/other/KalmarCTF2025#very-serious-cryptography) one. Make sure to check it too!

## Challenge Description

As CTF becomes more mainstream, a troubling new trend is emerging of player fanclubs becoming so large that top players and challenge authors are having their lives disrupted from the sheer volume of valentines gifts they are receiving! With some instances of the extreme valentines pressure even leading to the last minute postponement of major CTFs!?!

As such, we have decided to expand our traditional CTF valentines cards service, to provide a utility for efficiently generating meaningful, romantic gifts. We hope this will enable busy CTF players to be all set for the upcoming white day, and the huge number of return gifts they will inevitably have to send back, ensuring that no more CTF's will have to be postponed this year!

Note: Our infra team was worried that the sheer number of gifts required could take down our servers. But luckily i stumbled upon a solution that lets me generate them much more efficiently! Thanks to [https://x.com/veorq/status/1805877920306499868](https://x.com/veorq/status/1805877920306499868)

nc very-serious.chal-kalmarc.tf 2257

## Intuition

Challenge file:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

with open("flag.txt", "rb") as f:
    flag = f.read()

key = os.urandom(16)

# Efficient service for pre-generating personal, romantic, deeply heartfelt white day gifts for all the people who sent you valentines gifts
for _ in range(1024):
    # Which special someone should we prepare a truly meaningful gift for? 
    recipient = input("Recipient name: ")

    # whats more romantic than the abstract notion of a securely encrypted flag?
    romantic_message = f'Dear {recipient}, as a token of the depth of my feelings, I gift to you that which is most precious to me. A {flag}'
    
    aes = AES.new(key, AES.MODE_CBC, iv=b'preprocessedlove')
    print(f'heres a thoughtful and unique gift for {recipient}: {aes.decrypt(pad(romantic_message.encode(), AES.block_size)).hex()}')
```

The idea behind this one is to use the decryption property of `AES-CBC` that uses the IV to decrypt the first block and then it uses the past blocks to decrypt next blocks of data.

This means that we can brute force each character of the flag like this:

Text to encrypt: `Dear {our input} , as a token of the depth of my feelings, I gift to you that which is most precious to me. A {flag}`

To brute force the first character we ensure that the input we give will pad the text in such a way so that the first character of the flag is the last character in a block.

=> `len("Dear {our input} , as a token of the depth of my feelings, I gift to you that which is most precious to me. A") == 15 mod 16` => `padding`

We encrypt the text and then we can use as input this:
`Dear {padding} , as a token of the depth of my feelings, I gift to you that which is most precious to me. A ` + character to brute force.

Now if we compare all the encrypted messages with the original encrypted text we can find the character from the flag.

Repeating this for all the characters until we reach `}` will give us the whole flag.

## Solution

Solver:
```python
from pwn import *

charset = "abcdefghijklmnopqrstuvwxyz'{}_"
prefix = "Dear "
middle = ", as a token of the depth of my feelings, I gift to you that which is most precious to me. A "
flag = ""
p = process(["python", "chal.py"])
# p = remote("very-serious.chal-kalmarc.tf", 2257)

def send_input_list(p, input_list):
    output_list = []
    for i in input_list:
        p.sendline(i.encode())
        # takes only the encrypted text
        output = bytes.fromhex(p.recvline().decode().split()[-1]) 
        output_list.append(output)
    return output_list

while "}" not in flag:
    try:
	    # ensure that the character we are searching is at the end of the block
        padding = "_" * ((15 - len(prefix + middle + flag)) % 16)
        # this is where the original flag is encrypted
        original = send_input_list(p, [padding])[0]
        # create all possible variants of the characters withing the flag
        brute_input = [padding + middle + flag + c for c in charset] 
        # send the variants, and receive all encryptions
        brute_output = send_input_list(p, brute_input)
        # this is the position of the end of the block
        character_position = len(prefix + padding + middle + flag) + 1
        for i in range(len(brute_output)):
            if brute_output[i][:character_position] == original[:character_position]:
                flag += charset[i]
        print(flag)
    except EOFError:
        p = process(["python", "chal.py"])
```

### Flag

`kalmar{i_wonder_how_many_challenges_have_been_made_based_off_this_tweet}`
