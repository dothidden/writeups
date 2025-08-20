---
title: Who Can Haz Flag
type: writeup
date: 2023-06-02
tags:
  - network
  - forensics
author: H0N3YP0T
---

___

## Description of the challenge

A little spirit spied on this mortal transmission. He noticed that the human was after something, but what was it ?

## Solution

The challenge provide a Wireshark capture, let's open it first.
By the name of the challenge we can guess that the flag might be related to the ARP or DNS protocol because those
protocols
are used to translate a domain into IP address in the case of DNS and for
ARP we send request in order to identify a device based on his IP address.

If we sort the capture by protocol we see the following result where we can see a lot of ARP request with the message "
Who has"

![wireshark capture](/images/dantectf_2023/whoCanARP.png)

What is fascinating is that if we take the last character from the hexdump of each ARP request, we find the
flag of the challenge (assuming packets are also sort by id).

![wireshark capture](/images/dantectf_2023/arp0.png)
![wireshark capture](/images/dantectf_2023/arp1.png)
![wireshark capture](/images/dantectf_2023/arp2.png)
![wireshark capture](/images/dantectf_2023/arp3.png)
![wireshark capture](/images/dantectf_2023/arp4.png)

Continue until the end of the ARP capture and you will get `DANTE{wh0_h4s_fl4g_ju5t_45k}`.