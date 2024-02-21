---
title: OneByOne
date: 2024-02-18T20:03:57+02:00
description: Writeup for OneByOne [LA CTF 2024]
author: H0N3YP0T
tags:
- misc
draft: false
---
___

## Challenge Description

One..... by.......... one............... whew I'm tired, this form is waaaaaaay too long.

Note: the flag does have random characters at the end - that is intentional.

## Intuition

I may have to use the same technique as in the [Infinite loop](/lactf_2024/infiniteloop/) challenge, so let's look at the source code.

## Solution

In the script tag, we see a huge list of characters that we can choose from the select. I quickly noticed a weird 
pattern where all characters have the same number except one per list. By taking note of the character with the different number for every list, I was able to reconstruct the flag.

![google form.png](/images/lactf_2024/form3.png)

Putting the script in a beautifier can help.

![Beautify 1](/images/lactf_2024/beautify.png)

![Beautify 2](/images/lactf_2024/beautfy2.png)

...
SNIP
...


### Flag

`lactf{1_by_0n3_by3_un0_*,\"g1'}`

