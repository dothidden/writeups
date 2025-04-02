---
title: Almost Perfect Remote Signing
date: 2023-06-08T21:51:59+03:00
description: Almost Perfect Remote Signing writeup
tags:
- forensics
- radio
author: zenbassi
draft: false
---

## Description
I c4n't re?d you Are_you a beacon fAom 1200 0r smthing?

## Solution

We were provided with a `.wav` file. Listening to it, the only thing
you could hear was a nondescript noise. After a bit of digging for the 
name of the file (`aprs`), we find that APRS is an _Automatic Position Reporting System_ used by _hams_[^hams]. It uses **packet radio** to send **GPS tracking** information among other things.

[^hams]: [Radio terms Glossary](https://www.icomamerica.com/en/amateur/amateurtools/HamRadioTerms-2011.pdf)

Quoting Wikipedia[^wiki] _In its most widely used form, APRS is transported over the AX.25_. Supposing what it is, we need to demodulate is and the tool for the job is 
[multimon-ng](https://github.com/EliasOenal/multimon-ng). But first, we need to convert it from `.wav` to `.raw`. Searching some more on the internet we stumble upon
[this writeup](http://g4ngli0s.logdown.com/posts/1422073-bsidessfctf-for-latlong) from 2017. Following the steps there we confirm the 2 peaks in audacity and convert the file using sox.


``` bash
sox -t wav aprs_out.wav -esigned-integer -b16 -r 22050 -t raw aprs_out.raw
```

With multimon-ng we get the 1080 transmitted packets

``` bash
multimon-ng -t raw -a AFSK1200 aprs_out.raw
```
    ...
    AFSK1200: fm N0CALL-0 to APN001-0 UI  pid=F0
    !4345.59N\01116.54EgHello flag! Pkt 0099/1080
    AFSK1200: fm N0CALL-0 to APN001-0 UI  pid=F0
    !4345.59N\01117.08EgHello flag! Pkt 0100/1080
    AFSK1200: fm N0CALL-0 to APN001-0 UI  pid=F0
    !4345.56N\01116.51EgHello flag! Pkt 0102/1080
    AFSK1200: fm N0CALL-0 to APN001-0 UI  pid=F0
    !4345.56N\01116.54EgHello flag! Pkt 0103/1080
    AFSK1200: fm N0CALL-0 to APN001-0 UI  pid=F0
    !4345.56N\01117.08EgHello flag! Pkt 0104/1080
    AFSK1200: fm N0CALL-0 to APN001-0 UI  pid=F0
    !4345.52N\01116.48EgHello flag! Pkt 0105/1080
    ...

The sender, receiver and _Hello flag!_ repeat among all packets,
so we shift our attention to the geo coordinates. We notice that
from beginning to end the **N** oscillated slightly up and down and 
the **E** smoothly increases. Thus we suspect that the flag is 
drawn on the map using the coordinates.

Using a plotting tool we get the flag.

![geo plotting](/images/dantectf_2023/gps.png)

# References 

[^wiki]: APRS [techinical information](https://en.wikipedia.org/wiki/Automatic_Packet_Reporting_System#Technical_information)
