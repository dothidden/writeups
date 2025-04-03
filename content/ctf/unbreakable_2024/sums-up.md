---
title: sums-up
date: 2024-04-07T14:22:19+03:00
description: Writeup for sums-up [Unbreakable 2024]
type: writeup
author: H0N3YP0T
tags:
- network
draft: false
---
___

## Challenge Description

Our SOC analysts saw some strange DNS traffic. Wanted you to figure out what was exfiltrated, can you check it and sum it up ?

## Intuition

Since it is a `.pcap` let's open using Wireshark,and we notice a lot of DNS requests to different websites. I am used to this kind
of challenges and I started to scroll down to search for some patterns since the capture is small.

![img.png](/images/unbreakable_2024/sums.png)

## Solution

I immediately noticed the flag pattern by scrolling down. The flag starts at the Google request and continues with Amazon, Facebook, ...

![img.png](/images/unbreakable_2024/google.png)
![img.png](/images/unbreakable_2024/amazon.png)
![img_1.png](/images/unbreakable_2024/facebook.png)

### Flag

`ctf{4cp_4nd_4dp_ch3cksum5_4r3_3v1l_pr00v3_m3_wr0ng_jhunidr}`

