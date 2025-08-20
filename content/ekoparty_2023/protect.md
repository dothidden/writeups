---
title: Protect
type: writeup
date: 2023-11-12T18:53:58+02:00
description: Writeup for Protect [Ekoparty 2023]
author: sunbather
tags:
- rev
draft: false
---
___

## Challenge Description

So, because we wrote this writeup kinda late, we don't have the original description anymore. The idea is that some binary on the EKONET (which was some online file server you could access through Gopher) was modified in some way, to be different than its intended, original version. That was what the original description implied.

## Intuition

There was a binary called ``protect.exe`` which fit too well with the name of the challenge. On inspection, we find a copyright string leading us to [this website](https://darkside.com.au/snow/). It's a cool, open-source text steganography tool called *Snow*, that can hide (and even encrypt) your message in the whitespaces of text. Maybe we can compile the source files ourselves and compare with the ``protect.exe`` binary.

## Solution

After compiling and opening both binaries side-by-side in Ghidra, we can manually rename the functions and variables in the stripped ``protect.exe`` binary. We notice the decoding and decryption routines are completely missing in the EKONET version. Trying to run them indeed proves nothing is being executed for them. Initially this is where we lost the track, because there didn't seem to be anything different going on. Later on, we started looking through the ``.data`` section, scrolling for any other clues, when we noticed that Ghidra decodes some ASCII in the ``sxor`` bit of the ``ICE sbox``. We notice each byte of the flag is used as a 4-byte value in the sbox.

How the ``ice_sxor`` looked in Ghidra:

```
					 ice_sxor                                        XREF[5]:     ice_key_create:004029c1(*), 
																				  ice_key_create:00402b27(*), 
																				  ice_key_create:00402b34(*), 
																				  ice_key_create:00402b3d(*), 
																				  ice_key_create:00402b46(*)  
00407d20 45              ??         45h    E
00407d21 00              ??         00h
00407d22 00              ??         00h
00407d23 00              ??         00h
00407d24 4b              ??         4Bh    K
00407d25 00              ??         00h
00407d26 00              ??         00h
00407d27 00              ??         00h
00407d28 4f              ??         4Fh    O
00407d29 00              ??         00h
00407d2a 00              ??         00h
00407d2b 00              ??         00h
00407d2c 7b              ??         7Bh    {
00407d2d 00              ??         00h
00407d2e 00              ??         00h
00407d2f 00              ??         00h
00407d30 72              ??         72h    r
00407d31 00              ??         00h
00407d32 00              ??         00h
00407d33 00              ??         00h
00407d34 34              ??         34h    4
00407d35 00              ??         00h
00407d36 00              ??         00h
00407d37 00              ??         00h
00407d38 6e              ??         6Eh    n
00407d39 00              ??         00h
00407d3a 00              ??         00h
00407d3b 00              ??         00h
00407d3c 64              ??         64h    d
00407d3d 00              ??         00h
00407d3e 00              ??         00h
00407d3f 00              ??         00h
00407d40 30              ??         30h    0
00407d41 00              ??         00h
00407d42 00              ??         00h
00407d43 00              ??         00h
00407d44 6d              ??         6Dh    m
00407d45 00              ??         00h
00407d46 00              ??         00h
00407d47 00              ??         00h
00407d48 5f              ??         5Fh    _
00407d49 00              ??         00h
00407d4a 00              ??         00h
00407d4b 00              ??         00h
00407d4c 73              ??         73h    s
00407d4d 00              ??         00h
00407d4e 00              ??         00h
00407d4f 00              ??         00h
00407d50 62              ??         62h    b
00407d51 00              ??         00h
00407d52 00              ??         00h
00407d53 00              ??         00h
00407d54 30              ??         30h    0
00407d55 00              ??         00h
00407d56 00              ??         00h
00407d57 00              ??         00h
00407d58 78              ??         78h    x
00407d59 00              ??         00h
00407d5a 00              ??         00h
00407d5b 00              ??         00h
00407d5c 7d              ??         7Dh    }
00407d5d 00              ??         00h
00407d5e 00              ??         00h
00407d5f 00              ??         00h
```

### Flag

EKO{r4ndr4nd0m_sb0x}

