---
title: krotate
date: 2024-04-14T22:43:54+03:00
description: Writeup for krotate [Unbreakable 2024]
type: writeup
author: zenbassi
tags:
- crypto
draft: false
---
___

## Challenge Description

We managed to intercept communication with a critical mission. We can't decipher
it but managed to break into the system and recover what looks like part of the
communication and an algorithm for it.

Can you get the full message?

## Intuition

Analysing the encryption algorithm enables us to make a few interesting and useful
observations. Firstly, the cipher-text is obtained by splitting the clear-text into
blocks, xoring each block with a key and then joining the xored blocks together.

```python
def xor_text(text, key):
    return bytes([text[i] ^ key[i] for i in range(len(text))])

def encrypt(text, key):
    ciphertext = b""
    blocks = [text[i : i + KEY_LEN] for i in range(0, len(text), KEY_LEN)]
    for i, block in enumerate(blocks):
        ciphertext += xor_text(block, key)
        key = next_key(key)
    return ciphertext
```

Secondly, the key for each block is derived from the previous key, by xoring each
byte of the key with a pre-determined value.


```python
def RGEN():
    global R
    R = ((R << 1) ^ (0x71 if (R & 0x80) else 0)) & 0xFF
    return R

def next_key(key):
    return bytes([key[i] ^ RGEN() for i in range(len(key))])
```

Since we know a crib with the length ~600 bytes and the key is only 100 bytes in length,
we can retrieve the key by guessing the correct position of the crib, and the use the key
to decrypt the message.

## Solution

We made our job a lot easier by first eliminating every change inflicted by the `R` component
of the key variation algorithm. We can do this by _encrypting_ the cipher-text with a zeroed-out
key. The result is simply the plain-text xored block-wise with the unmodified key. We then
use a simple brute-force algorithm to find the crib offset and the key offset within the crib
section. We filter all possible variations based on some extra plain-text we extracted during
failed attempts at fully decrypting the message.

```python
# cipher with R xored out
cypher = open("./unfucked_cipher.txt", "rb").read()
known = open("./known", "rb").read()

offset = 0

while True:
    full_plain = offset * b"K" + known
    if len(full_plain) > len(cypher):
        break
    full_plain += b"K" * (len(cypher) - len(full_plain))

    kinda_key = [full_plain[i] ^ cypher[i] for i in range(len(full_plain))]

    key_offset = (offset // 100 + 1) * 100
    actual_key = kinda_key[key_offset: key_offset + KEY_LEN]
    dec = encrypt(cypher, actual_key)

    # just inspect every output. there's not so many of them
    # one of them will contain the flag :D
    if b"Godspeed" in dec:
        print(offset, key_offset)
        print(dec)
    offset += 1
```

### Flag

`CTF{cc64393474865290892e5197153ad6109151d8ee2fd5e316d81b80c3d825bd82}`
