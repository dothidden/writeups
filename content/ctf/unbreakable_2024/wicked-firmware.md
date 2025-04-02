---
title: wicked-firmware
date: 2024-04-14T23:10:18+03:00
description: Writeup for wicked-firmware [Unbreakable 2024]
author: zenbassi
tags:
- rev
draft: false
---
___

## Challenge Description

We need some info that is found inside this firmware.

## Solution

We extract the filesystem of the firmware with `binwalk`.
The flag is comprised of information such as the `u-boot` version,
the extra entry in the `hosts` file and the admin line from
the `passwd` file.

```bash
$ binwalk -e firmware.bin
DECIMAL   	HEXADECIMAL 	DESCRIPTION
--------------------------------------------------------------------------------
22372     	0x5764      	U-Boot version string, "U-Boot 1.1.4-g4df6eb16-dirty (Nov 30 2018 - 12:33:02)"
                                                    ^ this one
...

$ cd _firmware.bin.extracted/squashfs-root/

$ cat ./etc/hosts <- this one
...
127.0.1.1 842v3_un

$ cat ./etc/passwd
...
admin:x:1000:0:admin:/var:/bin/false <- this one
...
```
