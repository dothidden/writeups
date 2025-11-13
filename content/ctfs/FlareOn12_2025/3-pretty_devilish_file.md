---
title: 3.pretty_devilish_file
type: writeup
date: 2025-10-01T18:42:50+02:00
description: Writeup for pretty_devilish_file [FlareOn 2025]
author: PineBel
tags:
- rev
draft: false
---

# Challenge 3 (pretty_devilish_file)

I didn't really enjoy this challenge since it was pretty guessy.
In this challenge we only receive a PDF file.
To analyse it I used [pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py) and [pdfid.py](https://github.com/Rafiot/pdfid/blob/master/pdfid/pdfid.py).

By running `pdfid.py` we get the information that the pdf has an encrypted section. I initially thought that this was the goal of the challenge but after spending quite some time to understand how that section works I gave up since I couldn't extract anything usefull from it. At least I won a massive rabbit hole lol.

If we analyse the structure of the PDF with `strings` only, it's pretty clear that the pdf is broken:
```
7 0 obj
<</Filter /Standard/V 5/R 6/Length 256/P -1/EncryptMetadata true/CF <</StdCF <</AuthEvent /DocOpen/CFM /AESV3/Length 32>>>>/StrF /StdCF/StmF /StdCF/U (
12Jw)/O (v/
Ll9W`
)/UE (
WHa}?
)/OE (
\\zR
)/Perms (G
trailer <<
  /Root 2 0 R
  /#52#6F#6F#74 1
  % /Size 15
  /Encrypt 7 0 R
```

object 7 doesn't end, there are two roots? really strange.

After my Encrypt side-quest I decided to analyse the 4th object from the PDF since it contained a stream and maybe something was hidden in there.
I also tried multiple tools to analyse the pdf.
After playing around with multiple tools, I found something interesting with `qpdf`:
```
qpdf --show-object=4 --filtered-stream-data pretty_devilish_file.pdf
WARNING: pretty_devilish_file.pdf: file is damaged
WARNING: pretty_devilish_file.pdf: can't find startxref
WARNING: pretty_devilish_file.pdf: Attempting to reconstruct cross-reference table
WARNING: pretty_devilish_file.pdf (trailer, offset 1412): dictionary has duplicated key /Root; last occurrence overrides earlier ones
WARNING: pretty_devilish_file.pdf (object 7 0, offset 1402): expected endobj
WARNING: pretty_devilish_file.pdf (trailer, offset 1410): invalid /ID in trailer dictionary
WARNING: pretty_devilish_file.pdf (object 4 0, offset 915): expected endobj
q 612 0 0 10 0 -10 cm
BI /W 37/H 1/CS/G/BPC 8/L 458/F[
/AHx
/DCT
]ID
ffd8ffe000104a46494600010100000100010000ffdb00430001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001002501011100ffc40017000100030000000000000000000000000006040708ffc400241000000209050100000000000000000000000702050608353776b6b7030436747577ffda0008010100003f00c54d3401dcbbfb9c38db8a7dd265a2159e9d945a086407383aabd52e5034c274e57179ef3bcdfca50f0af80aff00e986c64568c7ffd9
EI Q 

q
BT
/ 140 Tf
10 10 Td
(Flare-On!)'
ET
Q
```

The stream is a bit strange since there is quite a lot of data without the Flare-On part.
So I gave the code to CyberChef which detected that it was an image.
So I now used `pdfimages` to extract the image from the pdf.
The strange thing about the image was the size 1x37 which lead me to think that maybe the pixels have the flag value.

Using the following command: `convert extracted.jpg text`.
I extracted the pixel intenstities which would fit the ANSI chars.
So I copied the values and decoded them and got the flag.


### Another cool solve
After the competition finished, I read a cool solution which was: 
```
evince pretty_devilish_file.pdf # or any pdf reader
ps aux | grep pretty # get the PID
gcore $pid # this dumps the process memory into a file called core.$pid
strings core.$pid | grep -i '@flare'
```