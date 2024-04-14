---
title: Wicked-Monitoring
date: 2024-04-07T18:00:08+03:00
description: Writeup for Wicked-Monitoring [Unbreakable 2024]
author: H0N3YP0T
tags:
- forensics
draft: false
---
___

## Challenge Description

Some weird events happened during this week. Please check and provide the necessary info.

## Intuition

The challenge provides a `.evtx` file which is a Windows Event Log file. Therefore, I will use
the Windows events viewer to analyze the logs. Hopefully the logs are not too big, so, I can easily find suspicious events by scrolling down.

## Question 1

Identify the compromised account

## Solution 1

I found the following log which uses Putty and SSH and it makes weird commands:

![img.png](/images/unbreakable_2024/event.png)

By looking closer I saw the account used in the attack is `IEUser`.

## Question 2

Provide the name of the malicious executable used in the attack.

## Solution 2

By looking at the screenshot above, I saw the attacker used a program called `plink.exe`.

## Question 3

What is the protocol exploited in the attack?

## Solution 3

We see the command use port 3389 which is the Remote Desktop Protocol (RDP). Therefore, the protocol exploited in the attack is `rdp`.