---
title: InfniteLoop
date: 2024-02-18T20:03:20+02:00
description: Writeup for InfniteLoop [La ctf 2024]
author: H0N3YP0T
tags:
- misc
draft: false
---
___

## Challenge Description

I found this google form but I keep getting stuck in a loop! Can you leak to me the contents of form and the message at the end so I can get credit in my class for submitting? Thank you!


## Intuition

If I submit the form, I keep having to fill it out again. So maybe I can find something in the source code ?

![from](/images/lactf_2024/form.png)

## Solution

If we look in the source code, in the script tag, we can see the that the flag is hidden in two parts.

![from](/images/lactf_2024/form2.png)

### Flag

`lactf{l34k1ng_4h3_f04mz_s3cr3tz}`

