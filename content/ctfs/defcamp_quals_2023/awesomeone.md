---
title: Awesomeone
type: writeup
date: 2023-10-22T15:39:52+03:00
description: Writeup for Awesomeone [Defcamp Quals 2023]
author: Honesty
tags:
  - rev
draft: false
---

___

## Challenge Description

One would simply want to be with the rest.

**NOTE:** The format of the flag is CTF{}, for example: CTF{foobar}. The flag must be submitted in full, including the
CTF and curly bracket parts.

## Intuition

Decompiling the agoodone binary leads to the check_password function which uses the length of the encrypted flag in a
xor operation together with the user input. The flag is encrypted but the length is constant allowing us to craft an
input that can pass this check. The solution is then used as a xor cipher key on the encrypted flag leading us to the
solution.

## Solution

Firstly we want to take a look at the decompiled binary using ghidra. User input is passed to check_password. This
function is a check for the bitwise operation on line 16. Both c and len are derived from the user input, while
enc_flag_length is always the same. We can determine enc_flag_length by following the enc_flag pointer leading us to the
encrypted flag that is a null terminated string of 69 characters. We now know that enc_flag_length = 69 (0b01000101).
The next step is crafting an input string that will validate the check on line 16. The string “D” is enough to validate
this condition as “D” has ascii code of 68 xored with the length of 1 giving us 69 (0b01000101). Now we can copy the
encrypted flag from ghidra as a byte string and use a xor decipher with 0b01000101 as a key giving us the final flag.

![mainrev.png](/images/defcamp_quals_2023/mainrev.png)
![password.png](/images/defcamp_quals_2023/password.png)

### Flag

`CTF{fc3a41a577ff10786a2fdbfcad18ef47ea78d426a47d097a49e3803f7e9c0e96}`

