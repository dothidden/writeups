---
title: Log-Forensics
date: 2023-10-22T20:05:26+02:00
description: Writeup for Log-Forensics [Defcamp Quals 2023]
author: zenbassi
tags:
- forensics
draft: true
---
___

## Challenge Description

We know for sure that an attacker attempted to dump the user's passwords on the targeted system. Using your favourite text editor or Terminal commands please help us find answers to the following questions.

## Intuition & Solution

We basically just used `grep`, `find` and `vim` to go through logs and terminal
command hystory to find most of the answers. Some of the answer we could figure
out just by searching on the internet.

### Flag

![all flags proof](/images/defcamp_quals_2023/log-forensics-flags.png)
