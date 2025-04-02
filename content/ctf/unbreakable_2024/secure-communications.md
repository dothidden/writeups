---
title: secure-communications
date: 2024-04-14T22:17:52+03:00
description: Writeup for secure-communications [Unbreakable 2024]
author: zenbassi
tags:
- network 
- forensics
draft: false
---
___

## Challenge Description

We captured some pretty bizzare looking communications, but part of them are encrypted.

Can you help?

Flag Format: CTF{sha256}

## Intuition

We opened the `.pcapng` file in Wireshark. Inspecting the packet's hierarchy, we see 
some packets sent over `websocket`. Sorting by size we find a _TLS Secrets Log File_.
This can be used to decrypt the communications and find the flag.

## Solution

The payload of the top 2 packets by size contain the _TLS Secrets Log File_
[^tls]. We extracted the payload from the two packets, saved it as a text file
and imported the file into Wireshark (Preferences -> Protocols -> TLS ->
(Pre)-Master-Secret log filename). The packets are now decrypted. Inspecting 
them, we find one in particular that holds the flag in plain text.

![secure-communications-flag](/images/unbreakable_2024/secure-communications.png)

## References

[^tls]: https://wiki.wireshark.org/TLS
