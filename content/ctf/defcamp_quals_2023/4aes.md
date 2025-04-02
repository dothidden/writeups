---
title: 4aes
date: 2023-10-22T09:56:31+03:00
description: Writeup for 4aes [Defcamp Quals 2023]
author: sunbather
tags:
  - crypto
draft: false
---

___

## Challenge Description

Chall:

```py
k1 = random1 + b"A"*29
k2 = random2 + b"A"*29
plain = b'This is a non-secret message....'
cipher = AES(k1,AES(k2,plain)) # ECB mode
print(plain,'\n',cipher)
> b'7\xcf7\xce\xa6 \xbe\t\xba\x03\xe4\xac\x9e\x86\x85\xf5YZYa_7\xae\xa1\xe6\xc1\xd1\xad\xfb\x9c\x99s'
```

Flag:

```py
sha256 = hashlib.sha256(k1+k2).hexdigest()
print("CTF{"+sha256+"}")
```

### Intuition

We can use a meet-in-the-middle technique to bruteforce the missing bytes.

### Solution

Simple bruteforce script:

```py
#!/usr/bin/env python3
from Crypto.Cipher import AES
import hashlib
from threading import Thread


ct = b'7\xcf7\xce\xa6 \xbe\t\xba\x03\xe4\xac\x9e\x86\x85\xf5YZYa_7\xae\xa1\xe6\xc1\xd1\xad\xfb\x9c\x99s'
plain = b'This is a non-secret message....'

everything_dec = {}
everything_enc = {}

def find_dec():
    for i in range(256):
        for j in range(256):
            for k in range(256):
                r = bytes([i, j, k])
                k2 = r + b"A"*29
                d = AES.new(k2, AES.MODE_ECB)
                dec = d.decrypt(ct[:16])
                everything_dec[dec] = k2

def find_enc():
    for i in range(256):
        for j in range(256):
            for k in range(256):
                r = bytes([i, j, k])
                k1 = r + b"A"*29
                e = AES.new(k1, AES.MODE_ECB)
                enc = e.encrypt(plain[:16])
                everything_enc[enc] = k1

# Multi-thread them just for fun
t1 = Thread(target=find_dec)
t2 = Thread(target=find_enc)

print("Starting threads...")

t1.start()
t2.start()

t1.join()
t2.join()

print("Searching results...")

for d in everything_dec.keys():
    if d in everything_enc:
        print("Found!")
        print(everything_enc[d], everything_dec[d])
```

Then apply the transformations explained in the description.

#### Flag

```CTF{91e6611654e4fe66d6876f728b8dfd54999ed752f89239ab82ecd9e520c1e003}```
