---
title: threat-monitoring
date: 2024-04-07T14:23:05+03:00
description: Writeup for threat-monitoring [Unbreakable 2024]
author: H0N3YP0T
tags:
- threat hunting
- incident response
draft: false
---
___

## Challenge Description

You never thought that this thing was possible, but this morning you have received a request to investigate some malicious events from 2013. What happened more than 10 years ago?

## Intuition

This is a Kibana search challenge where I have to find different information. Let's open it and first let's 
filter the logs by adjusting the time range to 2013.

![img.png](/images/unbreakable_2024/kibana.png)

## Question 1

Provide the name of the compromised domain

## Solution 1

I got it by filtering the logs with hosts and payload_data:

![img.png](/images/unbreakable_2024/filter1.png)

By scrolling down we found the compromised domain in the Referer HTTP header:

![img.png](/images/unbreakable_2024/spammers.png)

I knew the malicious requests were the followings because they include suspicious URL endoded in base64 and administratprs keywords:

![img.png](/images/unbreakable_2024/cyberchef.png)

Therefore, the compromised domain is `spammers-paradise`.

## Question 2

Provide the name of the malicious domain where victims were redirected

## Solution 2

By clicking on the `hosts` filter, we can visualize all available hosts in the logs. I noticed
3 different hosts in the logs:

- `spammers-paradise`
- `brainsync`
- `alnera`

![img.png](/images/unbreakable_2024/alnera.png)

I already knew about the two first domain, but I didn't know about `alnera`. By filtering the logs with the `alnera` domain I found the following:

![img.png](/images/unbreakable_2024/malicious.png)

The malicious domain where victims were redirected is `alnera`.

## Question 3

Provide the IP of the compromised website

## Solution 3

Since I already resolved the first question, I just need to apply a filter on the hosts: `spammers-paradise`:

![img.png](/images/unbreakable_2024/ip.png)

The IP of the compromised website is `94.76.245.25`
