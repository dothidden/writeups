---
title: Demonic Navigation Skills
date: 2023-06-08T22:42:49+03:00
description: Demonic Navigation Skills writeup
tags:
- misc
author: zenbassi
draft: false
---

## Description

A friend told me that they are creating a new celestial network, way better than our Internet even though it is based on some long forgotten tech. Do you have the skills to find the Holy Record? Start your search at `gates.hell.dantectf`.

## Solution

We were given an ip address running a **udp** service. A quick internet search confirms that DNS runs on
udp so we try to `dig` the domain. After a few queries and many failed attempts we find the flag.

``` bash
dig @challs.dantectf.it -p 31553 gates.hell.dantectf             # SOA    beach.purgatory.dantectf
dig @challs.dantectf.it -p 31553 beach.purgatory.dantectf SOA    # CLASS9 skies.paradise.dantectf
dig @challs.dantectf.it -p 31553 skies.paradise.dantectf CLASS9  # CLASS9 flag.paradise.dantectf
dig @challs.dantectf.it -p 31553 flag.paradise.dantectf CLASS9 
```
### Flag

DANTE{wh0_r3m3mb3r5_ch405n3t_4nd_h3s10d}
