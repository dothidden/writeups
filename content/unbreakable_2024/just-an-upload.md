---
title: Just-an-Upload
date: 2024-04-07T14:22:29+03:00
description: Writeup for Jusst-an-Upload [Unbreakable 2024]
author: H0N3YP0T
tags:
- network
- forensics
draft: false
---
___

## Challenge Description

Our team captured this traffic. Can you find what's in there ?

## Intuition

We got a `pcap` file, let's open it with `Wireshark` and see what's inside. The capture contains a lot of traffic and different
protocols. Therefore, let's filter the traffic by protocol. As we can notice below, it seems someone uploaded a zip file
under HTTP which is not encrypted. Furthermore, the call is made from `/upload.php` which is a big hint coming from
the challenge name.

![img.png](/images/unbreakable_2024/just_uploaded.png)

## Solution

In the wireshark menu we can go to `File -> Export Objects -> HTTP` and we can see the zip file that was uploaded.
I can save them all on my computer and I will use `binwalk` to extract the contents of the zip file.

![img.png](/images/unbreakable_2024/zip.png)

```shell
❯ cat upload.php 
-----------------------------42161681521897329847366789097
Content-Disposition: form-data; name="exfiltrate"; filename="test.zip"
Content-Type: application/zip

+flag.txtUT	w=�e[=�eux
+��flag.txtUTw=�eux       ���J.I�v3�1�-�10I�1�w6�6.*3.��K�υ�\P�RGX!�}
                   ��PKNm
-----------------------------42161681521897329847366789097
Content-Disposition: form-data; name="submit"

Upload Image
-----------------------------42161681521897329847366789097--
```
```shell
❯ binwalk -e upload.php 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
165           0xA5            Zip archive data, at least v2.0 to extract, compressed size: 43, uncompressed size: 149, name: flag.txt
352           0x160           End of Zip archive, footer length: 22

```
```shell
·························································
❯ cd _upload.php.extracted 
···································
❯ ls
A5.zip  flag.txt
···································
❯ cat flag.txt 

ctf{F1l3_Upl04d_T0_C2_S3rv3r}

```

### Flag

`ctf{F1l3_Upl04d_T0_C2_S3rv3r}`

