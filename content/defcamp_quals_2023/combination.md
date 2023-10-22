---
title: Combination
date: 2023-10-22T15:53:57+03:00
description: Writeup for Combination [Defcamp Quals 2023]
author: Honesty
tags:
  - rev
draft: false
---

___

## Challenge Description

There are not that many combinations one can do here.

**NOTE:** The format of the flag is CTF{}, for example: CTF{foobar}. The flag must be submitted in full, including the
CTF and curly bracket parts.

## Intuition

The binary “combined” stores a big array of 4 byte strings each representing a hex number such as “0x32”. This array is
used to validate the user input by comparing each character of the input to an entry in the array with an increment of
nine.
By taking all multiples of 9 index entries and converting from hex => ascii we get the flag.

## Solution

Taking a look at the decompiled binary using ghidra we can see a pointer to the user input string being
passed to a validator function. verify is an array of 4 byte strings each representing a character string of a hex
number such as “0x32”. On the right hand side of the if condition we can see that verify is iterated on an increment of
nine. Given this clue we copy all the hex values from ghidra and keep only the ones with an index that is a multiple of
nine. We then convert these hex values to ascii (
using [this](https://www.rapidtables.com/convert/number/hex-to-ascii.html))
leading us to the flag.

![combination.png](/images/defcamp_quals_2023/combination.png)

### Flag

`CTF{fe402183ea30417f5d333b40c22d9b26c1aebed4}`

