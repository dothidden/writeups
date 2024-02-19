---
title: GateCrash
date: 2023-12-10T13:37:49+02:00
description: Writeup for GateCrash [HTB University 2023]
author: H0N3YP0T
tags:
  - web
draft: false
---
___

## Challenge Description

An administrative portal for the campus parking area has been identified, bypassing it's authentication and gaining access to the gate control would allow us to unlock it and use staff vehicles for securing the campus premises way faster.

## Intuition

When expecting the code I noticed only the User-Agent was white-listed, so I changed it to `Mozilla/7.0` because it' one that would pass the check for the 'browser unsupported error'.
Also, I noticed in the backend code (in Go) a function that checked for SQLi in the body of the request. The function that check for the User-Agent (in Nim) iss vulnerable to CRLF injection.

![browser error](/images/HTB_University_2023/browser.png)

## Solution

I need to use a Nim CRLF injection in order to perform an SQLi by inserting new credentials in the database, so I can log in.

![injection](/images/HTB_University_2023/inject.png)

The CRLF injection is performed by adding '%0d%0a%0d%0a' which is the URL encoded version of CRLF. Then, I append the regular body by beginning with the username
but I will also perfom my SQLi by inserting a new user with the username `foo` and the password `bar` (encrypted with bcrypt).

![login](/images/HTB_University_2023/flag.png)

The last step is to log in with the new credentials and get the flag.



### Flag

`HTB{d0_th3_d45h_on_th3_p4r53r}`


