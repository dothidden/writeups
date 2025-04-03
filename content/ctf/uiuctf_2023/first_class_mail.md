---
title: First Class Mail
date: 2023-07-01T15:47:00+02:00
description: Writeup for First Class Mail [UIUCTF 2023]
type: writeup
author: H0N3YP0T
tags:
- osint
draft: false
---
___

## Challenge Description

Jonah posted a picture online with random things on a table. Can you find out what zip code he is located in? Flag format should be uiuctf{zipcode}, ex: uiuctf{12345}.
![first_class_mail.png](/images/uiuctf_2023/first_class_mail.jpg)

## Intuition

Let's begin by analyzing the image as the challenge description does not really provide any useful information, we only know that we have to find out a zipcode.
The two related things to a zipcode are the envelope with some barcode and the letter. Unfortunately, we can only see the expected zipcode on the letter, the destination zipcode is not visible on the envelope because it's hidden by the banana.
Let's focus on the envelope with the barcode.


## Solution

We see on the envelope a barcode and after some research it the encoded address / zipcode of the destination. The difficulty here
is to identify which code it uses because there are different codes used on envelops around the world.
Luckily for us, we know that is a US envelop because the other envelop suggest it, and we know from previous challenges 
that Jonah is currently in the US. Therefore, we can focus on the US codes. We also know that there are 52 digits in the barcode so,
I searched on Google "barcode used on envelops US with 52 digits" and I clicked on the first [link](https://bizfluent.com/how-6765456-read-postal-bar-codes.html),
and I discovered it was a `POSTNET` code.

Now, we need to decode this code using the following website: [https://www.dcode.fr/barcode-postnet](https://www.dcode.fr/barcode-postnet).
And by enteering `1` for the big lines and `0` for the small lines, we get the following result:
![first_class_mail_decrypt.png](/images/uiuctf_2023/mail_decrypt.png)

We only need to keep the first 5 digits to get the zipcode: `60661`.

### Flag

`uiuctf{60661}`


