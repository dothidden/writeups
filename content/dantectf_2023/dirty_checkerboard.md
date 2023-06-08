---
title: Dirty Checkerboard
date: 2023-06-08T14:51:29+03:00
description: Dirty Checkerboard writeup
tags:
- forensics
draft: true
---

## Challenge Description

I bought a new chessboard but every time I use it I have this feeling... Like it's dirty or something.

## Key observation

Notice a set of weird pixels in the bottom left side of the image.

![dirty pixels](/images/dantectf_2023/dirty_pixels.png)

## Solution

Crop the image and interpret the data as bytes.

``` python
im = Image.open("./cropped_dirty.bmp").tobytes()
s = im.decode()
print(s)
```

### Result

    jefotulktcya hbwdtvpbk, tog-3mi yes./ fiue calu r:caloo mDkgkst /obo
                                                             ^
    rnuaA_i  ra/mmo ssgN0csaitg/aki eiTukh c ijg ni cEt}onkhtwiojfik{_ w
        ^              ^              ^              ^              ^
    i thicue m!ca

We get seemingly garbage, but on a close look, we can see the characters we're
looking for just scrambled up. The distance between them is constant. We should 
just reorder the characters.

## Unscramble

After a number of failed attempts, we got to this solution:

``` python
i = 57
step = 15
sol =''
cnt = 0
for off in range(0, 15):
    start = i + off
    tmp = ''
    for _ in range(16):
        tmp += s[start]
        start += step
        if start >= 150: 
            start -= 150
    sol += tmp[6:]

print(sol)
```

This outputs:

    c - DANTE{ah3ck_0ut_ bmagick} jwilk showed us a nifty trick over at
    https://github.com/jwilk/abmagick, look out for injections if you us
    e imagemagick!

The flag looks a bit wrong, so we just changed it manually to better match the text.

## Flag

DANTE{ch3ck_0ut_abmagick}

