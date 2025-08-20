---
title: image abomination
type: writeup
date: 2024-04-28T23:58:34+03:00
description: Writeup for image abomination [UMDCTF_2024]
author: sunbather
tags:
- misc
- forensics
draft: false
---
___

## Challenge Description

paul gave his mentat an encrypted thirst trap jpeg bitstream. the mentat was supposed to decrypt and give to chani, but he must've corrupted it along the way. can you help chani thirst over paul?

## Intuition

We get a ``flag.jpg``. It's corrupted. Usually you can trivially fix the issues by checking the jpeg format, maybe with help from [corkami](https://github.com/corkami/pics). This time the issue seems a bit more complicated.

![flag.jpg](/images/umdctf_2024/flag.jpg)

## Solution

While exploring the jpeg, [Koyossu](https://github.com/SecioreanuStefanita) found this [cool script for jpeg analysis](https://github.com/DidierStevens/Beta/blob/master/jpegdump.py). We opened the image in GIMP and we got an error that said ``unexpected marker f7`` or something like that. We deduced there might be weird markers in the jpeg that were corrupting it. So we removed any unknown markers, after identifying them with ``jpegdump.py``:

```
$ ./jpegdump.py --dump flag.jpg 
File: flag.jpg
  1 p=0x00000000 d=0: m=ffd8 SOI
  2 p=0x00000002 d=0: m=ffe0 APP0  l=   16 e=2.352746 a=19.538462
  3 p=0x00000014 d=0: m=ffe2 APP2  l=  688 e=4.046972 a=39.554745
  4 p=0x000002c6 d=0: m=ffdb DQT   l=   67 e=0.114676 a=0.015625 remark: 65/65 = 1.000000
  5 p=0x0000030b d=0: m=ffdb DQT   l=   67 e=0.000000 a=0.000000 remark: 65/65 = 1.000000
  6 p=0x00000350 d=0: m=ffc0 SOF0  l=   17 e=2.689246 a=9.071429 remark: p=8 h=1024 w=2048 c=3
  7 p=0x00000363 d=0: m=ffc4 DHT   l=   31 e=2.815937 a=0.750000
  8 p=0x00000384 d=0: m=ffc4 DHT   l=  181 e=7.270047 a=13.168539
  9 p=0x0000043b d=0: m=ffc4 DHT   l=   31 e=2.799180 a=0.642857
 10 p=0x0000045c d=0: m=ffc4 DHT   l=  181 e=7.243483 a=18.140449
 11 p=0x00000513 d=0: m=ffdd DRI   l=    4 e=1.000000 a=16.000000
 12 p=0x00000519 d=0: m=ffda SOS   l=   12 e=2.446439 a=21.222222
                                  entropy-coded data: l=94290 e=7.911588 a=86.362449 #ff00=947
 13 p=0x00017579 d=0: m=ff61       l=61155 e=7.913298 a=86.300072
 14 p=0x000377cc d=70510: m=ffd1 RST1
 15 p=0x0003dc82 d=25780: m=fff7       l=43300 e=7.922818 a=84.261150
 16 p=0x00056565 d=57277: m=ffd2 RST2
 17 p=0x0005d0bd d=27478: m=ff99       l=61426 e=7.929195 a=85.205184
 18 p=0x000757ef d=38718: m=ffd3 RST3
 19 p=0x0007ec74 d=38019: m=ff5d       l=64505 e=7.946895 a=84.141267
 20 p=0x000981ff d=39312: m=ffd4 RST4
 21 p=0x000a7f1d d=64796: m=ffe4 APP4  l=58091 e=7.939837 a=85.541248
 22 p=0x000cfeff d=105717: m=ffd6 RST6
 23 p=0x000ed8f9 d=121336: m=fff7       l=58344 e=7.956777 a=85.968832
Negative trailing
```

You can see the weird unrecognized markers at lines 13, 15, 17, 19, 23... We also notice the APP4 marker, ``ffe4``. I'm unsure if that's normal, but we deduced that APP4 marker should actually be a RST5 marker, seeing how there's only RST sections in consecutive order. So we changed that ``ffe4`` to a ``ffd5``. That fixed some of the final strips of the flag and gave us enough to see the flag. Here is the script that patches everything:

```py
#!/usr/bin/env python3

delete_this = [0x61, 0xf7, 0x99, 0x52, 0x5d, 0xcb]

img = open("./flag.jpg", "rb").read()

new_img = []

skip_two = False # skip two bytes

for i in range(len(img)):
    if skip_two:
        skip_two = False
        continue
    if img[i] == 0xff:
        if img[i+1] in delete_this:
            skip_two = True
            continue
        if img[i+1] == 0xe4:
            new_img.append(0xd5)
            continue
    new_img.append(img[i])

open("./patched.jpg", "wb").write(bytearray(new_img))
```

![flag.jpg](/images/umdctf_2024/patched.jpg)

### Flag

``UMDCTF{mY4Rrr4K15myDuN3!!1}``

