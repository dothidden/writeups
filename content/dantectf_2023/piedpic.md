---
title: Piedpic
date: 2023-06-08T12:43:14+03:00
description: piedpic writeup
tags:
- crypto
author: zenbassi
draft: false
---

## Description

Dante took many pictures of his journey to the afterlife. They contain many revelations. I'll give you one of these pictures if you'll give me one of yours!

## Key observations

Looking at the code we notice 2 things:
1. pixels are xored with 255 (aka bitwise reversed) for each odd bit among the
    3 least significant bits of the key at that index
2. pixels are scrambled based on $k_i$ (mod 6)

Knowing this, we conclude that the relevant part of the key is a tuple $(kl_i, km_i)$, where $kl_i$ holds the 3-lsb of $k_i$ and $km_i$ holds $k_i % 6$.

## Solution

To find $(kl_i, km_i)$, we can send an image where every pixel is $(2^0, 2^1, 2^2)$, because this way we can uniquely identify each channel of the pixel after the transformation and this way also reverse the transformation and recover the key.

## Source Code

We used this script to get the images from the oracle.

``` python
from pwn import *
from PIL import Image
from base64 import b64encode, b64decode
from io import BytesIO
import numpy as np
from time import sleep

io = remote('challs.dantectf.it', 31511)

print(io.recvline())
print(io.recvline())
print(io.recvuntil(b'?'))
io.sendline(b'y')

print(io.recvline())
print(io.recvline())
enc_flag = io.recvline()
print(io.recvline())

print('encflag received')
enc_flag_bytes = b64decode(enc_flag.decode().strip())
enc_flag_img = Image.open(BytesIO(enc_flag_bytes))
enc_flag_img.save("enc_flag_img.png", "png")
my_img = enc_flag_img.copy()
pixels = list(my_img.getdata())
for i in range(len(pixels)):
    pixels[i] = (1, 2, 4)
my_img.putdata(pixels)

print(io.recvuntil(b':'))
my_img_data = b64encode(my_img.tobytes())
io.sendline(my_img_data)
print(io.recvline())
print(io.recvline())

enc = io.recvline()
enc_img_bytes = b64decode(enc.strip())
enc_img = Image.open(BytesIO(enc_img_bytes))
enc_img.save("my_enc_img.png", "png")
print(io.recvline())
print(io.recvline())
print(io.recvline())
```

After retrieving both images, we used this script to decode the final image

``` python
from PIL import Image
from math import log2

perm_table = {
    0: (0, 1, 2),
    1: (0, 2, 1),
    2: (1, 0, 2),
    3: (1, 2, 0),
    4: (2, 0, 1),
    5: (2, 1, 0)}

perm_table_inv = { v: k for k, v in perm_table.items() }

perm_rev_table = {}

for k, v in perm_table.items():
    print(k)
    li = [0, 0, 0]
    for i in range(3):
        li[v[i]] = i
    perm_rev_table[k] = tuple(li)

def get_key():
    my_enc_img = Image.open("./my_enc_img.png")

    key = []
    pixels = list(my_enc_img.getdata())
    for i, p in enumerate(pixels):
        p = list(p)
        k_lsb = []
        for idx in range(3):
            if p[idx] > 4:
                k_lsb.append(1)
                p[idx] ^= 255
            else:
                k_lsb.append(0)
            p[idx] = int(log2(p[idx]))

        # k_lsb = k_lsb[::-1] this doesn't work??
        pixels[i] = p
        tp = tuple(p[:3])
        k_mod6 = perm_table_inv[tp]

        r, g, b = perm_rev_table[k_mod6]
        k_lsb = [k_lsb[r], k_lsb[g], k_lsb[b]]
        # I've got no fking clue why you have to reverse
        # this exactly here but it works lol
        k_lsb = k_lsb[::-1]
        k_lsb = int(''.join([str(x) for x in k_lsb]), 2)

        key.append((k_lsb, k_mod6))

    return key

def decrypt(key, path):
    flag = Image.open(path)

    pixels = list(flag.getdata())
    for i in range(len(pixels)):
        k_lsb, k_mod6 = key[i]
        r, g, b = perm_rev_table[k_mod6]
        colors = pixels[i]
        colors = (colors[r], colors[g], colors[b])
        pixels[i] = tuple([c ^ 255 if k_lsb & (1 << i) 
                     else c for i, c in enumerate(colors)])

    flag.putdata(pixels)
    flag.save("./result.png")
    flag.show()

key = get_key()
decrypt(key, "./enc_flag_img.png")
```

## Result

![result](/images/dantectf_2023/piedpic.png)

### Flag

DANTE{Att4cks_t0_p1x3L_Encrypt3d_piCtUrES_511f0c49f8be}
