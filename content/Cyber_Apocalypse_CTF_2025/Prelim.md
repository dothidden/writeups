---
title: Prelim
date: 2025-03-27T17:57:30+03:00
description: Writeup for Prelim [Cyber Apocalypse CTF 2025]
author: h3pha 
tags:
- crypto
draft: false
---
___

## Challenge Description

> Cedric has now found yet another secret message, but he dropped it on the floor and it got all scrambled! Do you think you can find a way to undo it?

## Intuition

We are given 2 files:

`souce.py`:
```python
from random import shuffle
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

n = 0x1337
e = 0x10001

def scramble(a, b):
    return [b[a[i]] for i in range(n)]

def super_scramble(a, e):
    b = list(range(n))
    while e:
        if e & 1:
            b = scramble(b, a)
        a = scramble(a, a)
        e >>= 1
    return b

message = list(range(n))
shuffle(message)

scrambled_message = super_scramble(message, e)

flag = pad(open('flag.txt', 'rb').read(), 16)

key = sha256(str(message).encode()).digest()
enc_flag = AES.new(key, AES.MODE_ECB).encrypt(flag).hex()

with open('tales.txt', 'w') as f:
    f.write(f'{scrambled_message = }\n')
    f.write(f'{enc_flag = }')
```

and `tales.txt`:
```
scrambled_message = [ -- random permutation here -- ]
enc_flag = 'ca9d6ab65e39b17004d1d4cc49c8d6e82f9fa7419824d07096d41ee41f0578fe6835da78bc31dd46587a86377883e0b7'
```

So the flag was encrypted with `AES` (mode `ECB`), and the key is the hash of the `shuffle()` function over a list of size `n` which is basically a permutation.

The `scramble()` function only multiplies two permutations, and `super_scramble()` is doing a fast exponentiation of a permutation.

Let's assume our key is `m`. `super_scramble(m, e)` will return `m^e`. So to retrieve the flag we need to find `m` by knowing `m^e`.

The solution to this is knowing that the multiplication of permutations is periodic (by multiplying the same permutation over and over you will eventually reach the one you started with). This period can be calculated and it is the `lcm` (least common multiple) of the sizes of the cycles in the permutation (let's say `p`).

Now, we have `m^e` and we know that `m^p == m`. What we have to do is raise `m^e` to a power which is a multiple of `p`: 

```
(m^e)^x == m^ex
if ex % p == 0 -> m^ex == m
```

So we need to find the inverse of `e` in the finite group `Z_p`.

## Solution

Solver:
```python
from math import gcd
import ast
from functools import reduce
from hashlib import sha256
from Crypto.Cipher import AES

n = 0x1337
e = 0x10001

file = open("tales.txt", "r")
scrambled_message = ast.literal_eval(file.readline().split(" = ")[1])
enc_flag = file.readline().split(" = ")[1].strip("'")
file.close()

def scramble(a, b):
    return [b[a[i]] for i in range(len(a))]

def super_scramble(message, e):
    b = list(range(len(message)))
    while e:
        if e & 1:
            b = scramble(b, message)
        message = scramble(message, message)
        e >>= 1
    return b

def lcm(a, b):
    return a * b // gcd(a, b)

def permutation_order(perm):
    n = len(perm)
    visited = [False] * n
    cycle_lengths = []

    for i in range(n):
        if not visited[i]:
            cycle_length = 0
            x = i
            while not visited[x]:
                visited[x] = True
                x = perm[x]
                cycle_length += 1
            cycle_lengths.append(cycle_length)

    return reduce(lcm, cycle_lengths, 1)

o = permutation_order(scrambled_message)  
d = pow(e, -1, o) # inverse of e mod o
print("encrypted flag:", enc_flag)
print("permutation order:", o)
print("d:", d)
print("scrambled message:", scrambled_message)
message = super_scramble(scrambled_message, d)
print("initial message:", message)

key = sha256(str(message).encode()).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(enc_flag)).decode()
print("flag:", flag)
```

### Flag

`HTB{t4l3s_fr0m___RS4_1n_symm3tr1c_gr0ups!}`
