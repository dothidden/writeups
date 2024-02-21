---
title: Shattered-Memories
date: 2024-02-18T20:04:26+02:00
description: Writeup for Shattered-Memories [LA CTF 2024]
author: H0N3YP0T
tags:
- rev
draft: false
---
___

## Challenge Description

I swear I knew what the flag was, but I can't seem to remember it anymore... can you dig it out from my inner psyche?

## Intuition

Let's open first the program using `ghidra` and see what we can find.

![Ghidra](/images/lactf_2024/stack.png)

It seems the flag is split into different parts into the stack.

## Solution

We can start looking at the first offset `local_98` which is the `lactf{no` string in the Ghidra representation where this input is used int the `strncmp` function. Then because the 
stack use the _LIFO_ method, we have to reconstruct the flag by taking the highest offset after `local_98` which is
`acStack_90`, then `acStack_88` and so on. By looking on all those offset we can find the flag.

![Flag](/images/lactf_2024/flag_memories.png)

### Flag

`lactf{not_what_forgive_and_forget_means}`

