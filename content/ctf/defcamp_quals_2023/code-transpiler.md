---
title: Code-Transpiler
date: 2023-10-22T14:04:13-04:00
description: Writeup for Code-Transpiler [Defcamp Quals 2023]
type: writeup
author: Koyossu
tags:
- web
draft: false
---
___

## Challenge Description

Bypass the security restriction and get th flag.

Flag format CTF{sha256}.

*This challenge is proudly sponsored by UNbreakable Romaia (program with a focus on beginners in cyber security). You might find writeups online but you should act like you don't know that. *


## Intuition

Once entered the address we get redirected to / .

![img.png](/images/defcamp_quals_2023/web21.png)

What we see from this page after inspecting the network tab is that the server is in werkzeug python. Another info we can see is that the main page asks us for an input file that 
will get compiled? Interesting.

Let's try making a common python page with the most basic import and print.

```python
print(exec('import os; os.system("cat flag")'))
```

![img.png](/images/defcamp_quals_2023/web22.png)


Bingo! This is a confirmation that we are on the right track. This is indeed a classic challange that needs you to escape a python jail and has a block-list of banned words and commands. 

## Solution

Having reached this step we tried the most common escape technique for detecting words in python, the good old "'" :) We tought common words such as: import, os, system and maybe flag and cat are banned so we escaped them using the ' trick.
Final Payload:

```python
print(exec('im''port o''s; o''s.sys''tem("ca''t fl''ag")'))
```

![img.png](/images/defcamp_quals_2023/web23.png)

### Flag
Here is the final flag, and a proof from the website :)

![img.png](/images/defcamp_quals_2023/compilerProof.png)

`CTF{4e08cd8cc051a304f94dd905b66af29572e3aa8fa56d93200bfd34727e2a892a}`

