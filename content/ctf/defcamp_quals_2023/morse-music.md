---
title: Morse-Music
date: 2023-10-22T19:46:13+02:00
description: Writeup for Morse-Music [Defcamp Quals 2023]
type: writeup
author: zenbassi
tags:
- stego
- crypto
draft: false
---
___

## Challenge Description

You might need to cross listen the message within the morse code.

## Intuition

Putting the audio through a morse decoder, we got a message saying the something along the lines of "it's not about the morse code" and also a password. We opened the audio in audacity and looking at the histogram we saw a QR-code.

## Solution

Scanning the QR-code led to a string. We base64-decoded it which
lead to some binary data. Since we had the _password_ already, we
just thought of using that to "decrypt" the message, so we
cyclically xor-ed the data with the password and got the flag.

base64-encoded string from the QR: `Njw0SGcLVwJVZ358MC0xBmUMClMKanlzZSpnAjVeBgVRMX0lYyliA2RaB1UDY3ghMHw0UGUPAQAH
NysnNClmAjMPA1VO`

`./file` contains the binary data from the base64-encoded string.

### Solution

```py
with open("./file", "rb") as f:
    data = f.read();
    key1 = b"UHR3V8203RJD"
    key2 = b"uhr3v8203rjd"

    for i, x in enumerate(data):
        print(chr(x ^ key1[i % 12]), end = "")
```

### Flag

`ctf{13e2f548eec5348c98370b51cf45bc7a6a002b5e012ee4fc37304eacaa41e71e}`
