---
title: Imago Qualitatis
date: 2023-06-08T15:11:49+03:00
description: Image Qualitatis writeup
tags:
- forensics
draft: false
---

## Description

A wondrous electromagnetic wave was captured by a metal-stick-handed devil. "But.. What? No, not this way. Maybe, if I turn around like this... Aha!"

## Key observation

Doing some reasearch on the file name we find out that this is a `raw gqrx IQ radio file`.

## Solution

Open the file in `gqrx` ([link](https://github.com/gqrx-sdr/gqrx) here) and play the file.

![gqrx photo](/images/dantectf_2023/gqrx.png)

### Flag

DANTE{n3w_w4v35_0ld_5ch00l}
