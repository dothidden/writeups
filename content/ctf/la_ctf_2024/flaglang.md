---
title: Flaglang
date: 2024-02-18T20:04:40+02:00
description: Writeup for Flaglang [LA CTF 2024]
author: H0N3YP0T
tags:
- web
draft: false
---
___

## Challenge Description

Do you speak the language of the flags?

## Intuition

The website has two dropdown where I can choose two countries and see how they say "Hello world". But, in the list there is also another country
which is the `Flagistan`. If I try to select it, the website returns an error. To resume I need access to the Flagistan language.

![flag web](/images/la_ctf_2024/flag_chall.png)

![error](/images/la_ctf_2024/flagistan.png)

## Solution

The solution is really simple, I can just capture the request using Burp and I notice that a cookie is set by using the ISO code of the country. I can just change the value of the cookie to `FL` for flagistan (I know this ISO code by looking in the source code) and I will have access to the Flagistan page. It is an insecure token vulnerability.

![flag](/images/la_ctf_2024/flag_flagistan.png)

### Flag

`lactf{n0rw3g7an_y4m7_f4ns_7n_sh4mbl3s}`

