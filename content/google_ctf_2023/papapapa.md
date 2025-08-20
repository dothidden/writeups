---
title: Papapapa
type: writeup
date: 2023-06-30T13:11:37+03:00
description: Writeup for Papapapa [Google Ctf 2023]
author: zenbassi
tags:
- misc
draft: false
---
___

## Challenge Description

Is this image really just white?

## Intuition

Well... probably not. Checking all the pixel values we only get white, so
the data must be somewhere else. Checking the metadata we see nothing.

## Solution

At one point we generated a full white image with the same dimensions as the
provided one and the same format. The result? An image much smaller in size! So
the data is there. At the suggesionts of [mehanix](https://github.com/mehanix) we
identified the bytes which specify the image size [^1] and changed them to
something bigger. Thus we obtained some black specs on the image!

So this is it! The image was just encoded with a smaller dimension, than its
real one. After some fiddling, we got the the correct size of **512x528** which
clearly shows the flag on the right margin.

![papapapa flag](/images/google_ctf_2023/papapapa.jpg)

## References

[^1]: cool and very useful article about the structure of a jpeg file: https://www.ccoderun.ca/programming/2017-01-31_jpeg/
