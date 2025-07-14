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

## Intuition

The search for characters happens before the flag gets overwritten.
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
flag = "L3AK{"
can_try = True
while can_try:
    for char in string.printable:
        query = f"{flag[-2:]}{test_char}"
        # query the app to see if "Not the flag?" post is present
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
