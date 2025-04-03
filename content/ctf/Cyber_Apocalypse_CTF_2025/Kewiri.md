---
title: Kewiri
date: 2025-03-27T14:28:56+03:00
description: Writeup for Kewiri [HTB Cyber Apocalypse CTF 2025]
type: writeup
author: h3pha
tags:
- crypto
draft: false
---
___

> Disclaimer: I am not a math pro or something. In this writeup I will make a lot of assumptions. I do not understand most of them myself, they are a result of me talking to LLMs and putting my trust into them.

## Challenge Description

> The Grand Scholars of Eldoria have prepared a series of trials, each testing the depth of your understanding of the ancient mathematical arts. Those who answer wisely shall be granted insight, while the unworthy shall be cast into the void of ignorance. Will you rise to the challenge, or will your mind falter under the weight of forgotten knowledge?
The instance might take 1-2 minutes to start.

## Intuition

The challenge is pretty straight forward. I had to complete 6 different tasks after connecting to the server:

##### Introduction

```
[!] The ancient texts are being prepared...
You have entered the Grand Archives of Eldoria! The scholars shall test your wisdom. Answer their questions to prove your worth and claim the hidden knowledge.
You are given the sacred prime: p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
```

##### Task 1
```
[1] How many bits is the prime p? >
```
This one is simple, I won't get into details.

##### Task 2

```
[2] Enter the full factorization of the order of the multiplicative group in the finite field F_p in ascending order of factors (format: p0,e0_p1,e1_ ..., where pi are the distinct factors and ei the multiplicities of each factor) >
```
We know that `p` is a prime number, so the order of `F_p` is `p-1`.
> Note: The server never changes the prime number. Every time I connect and I restart the container I get the same `p`.

I factorized `p-1` on [sage cell](https://sagecell.sagemath.org/):

```python
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
factor(p - 1)
# result: 2^2 * 5 * 635599 * 2533393 * 4122411947 * 175521834973 * 206740999513 * 1994957217983 * 215264178543783483824207 * 10254137552818335844980930258636403
```
And then asked chatGPT to put the result into the necessary format:
`2,2_5,1_635599,1_2533393,1_4122411947,1_175521834973,1_206740999513,1_1994957217983,1_215264178543783483824207,1_10254137552818335844980930258636403,1`

##### Task 3

```
[3] For this question, you will have to send 1 if the element is a generator of the finite field F_p, otherwise 0.
```
Then the server will send 17 numbers, and for each we have to respond with the correct bit.

This is the function that will give the correct answer for each number:

```python
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
factors = {
    2: 2,
    5: 1,
    635599: 1,
    2533393: 1,
    4122411947: 1,
    175521834973: 1,
    206740999513: 1,
    1994957217983: 1,
    215264178543783483824207: 1,
    10254137552818335844980930258636403: 1
}

def is_generator(g):
    phi = p - 1  # Order of the multiplicative group F_p*

    # Check if g^(phi/q) != 1 (mod p) for all prime factors q
    for q in factors.keys():
        if pow(g, phi // q, p) == 1:
            return False  # g is not a generator
    return True
```

##### Task 4

```
The scholars present a sacred mathematical construct, a curve used to protect the most guarded secrets of the realm. Only those who understand its nature may proceed.
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
[4] What is the order of the curve defined over F_p?
```

Same as before `a` and `b` are always the same.

I used this sage script:

```python
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134

E = EllipticCurve(GF(p), [a, b])
print(E.order())
```

The result is simply `p`.

##### Task 5

```
[5] Enter the full factorization of the order of the elliptic curve defined over the finite field F_{p^3}. Follow the same format as in question 2 >
```

For this one I used this sage script to get the order:
```python
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
F = GF(p)
E = EllipticCurve(F, [a, b])
N_p = E.order()  # Order over F_p
F3.<x> = GF(p^3)
E3 = EllipticCurve(F3, [a, b])
N_p3 = E3.order()  # Order over F_{p^3}
print(N_p3)
# result: 9547468349770605965573984760817208987986240857800275642666264260062210623470017904319931275058250264223830562439645572562493214488086970563135688265933076141657703804791593446020774169988605421998202682898213433784381043211278976059744771523119218399190407965593665262490269084642700982261912090274007278407746985341700600062580644280196871035164
```

Now we have to factorize that really large number, which might have been impossible if we didn't kown that `N_p3 % p == 0`

```python
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
print(factor(N_p3 // p))
# result: 2^2 * 7^2 * 2296163171090566549378609985715193912396821929882292947886890025295122370435191839352044293887595879123562797851002485690372901374381417938210071827839043175382685244226599901222328480132064138736290361668527861560801378793266019
# factorization of N_p3: 2^2 * 7^2 * 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061 * 2296163171090566549378609985715193912396821929882292947886890025295122370435191839352044293887595879123562797851002485690372901374381417938210071827839043175382685244226599901222328480132064138736290361668527861560801378793266019
```
And this is the response:
`2,2_7,2_21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061,1_2296163171090566549378609985715193912396821929882292947886890025295122370435191839352044293887595879123562797851002485690372901374381417938210071827839043175382685244226599901222328480132064138736290361668527861560801378793266019,1`

##### Task 6

```
The final trial awaits. You must uncover the hidden multiplier "d" such that A = d * G.
⚔️ The chosen base point G has x-coordinate: 10754634945965100597587232538382698551598951191077578676469959354625325250805353921972302088503050119092675418338771
🔮 The resulting point A has x-coordinate: 1910045914355078387768654907297648182483451746817223253449399704951513874387487122032980615521840123993743790111683
[6] What is the value of d? >
```
The value G always stays the same, while A changes every time. This means that I cannot precompute the response anymore.

The only solution to calculate `d` fast enough was through sage. The problem was that I could not install sage on my machine or a VM. So to solve this problem I create a docker container which runs a sage server that I can query for a response.

This is the docker file I used:

```dockerfile
# dockerfile
FROM sagemath/sagemath:latest

WORKDIR /sage

COPY server.sage /sage/server.sage
# make sure that enrypoint.sh has execution permissions
COPY entrypoint.sh /sage/entrypoint.sh

USER root

RUN apt-get update && apt-get install -y netcat

EXPOSE 1337

CMD ["/sage/entrypoint.sh"]
```

Since the docker container had a netcat binary that does not have the option to run the server on each connection. ChatGPT showed me this cool trick with a fifo to achieve the same functionality:
```sh
#!/bin/sh
# entrypoint.sh

# Create a named pipe (FIFO)
mkfifo /tmp/fifo

# Start listening on port 1337, redirect input to the SageMath script
while true; do
    cat /tmp/fifo | sage /sage/server.sage | nc -l -p 1337 > /tmp/fifo
done
```

And this is the `server.sage` file:

```python
#!/usr/bin/env sage
# server.sage

import sys

p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134

Fp = GF(p)
E = EllipticCurve(Fp, [a, b])

# Define base point G
x_G = 10754634945965100597587232538382698551598951191077578676469959354625325250805353921972302088503050119092675418338771
G = E.lift_x(Fp(x_G))

# Read x_A from netcat input
try:
    x_A = int(sys.stdin.readline().strip())
    A = E.lift_x(Fp(x_A))
    
    # Solve for d using discrete logarithm
    d = G.discrete_log(A)

    # ✅ Verification Step
    computed_A = d * G  # Compute d * G
    if computed_A == A:
        print(f"d = {d}")
        print("✅ Verification passed! d is correct.")
    else:
        print("❌ Verification failed! d is incorrect.")

except Exception as e:
    print(f"Error: {e}")
```

Use this to build the container and run it (might require `sudo`):
```sh
docker build -t sage_server .
docker run -p 1337:1337 sage_server
```

## Solution

Solver:
```python
from pwn import *

r = remote("94.237.56.65", 35587)

a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134

# Receiving p
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
r.readuntil(b"p = ")
pc = int(r.readline()[:-1])
if pc != p:
    print("Prime numbers do not match!")
    exit()

# TASK 1
print(r.readuntil(b"> "))
r.sendline(str(p.bit_length()).encode())

# TASK 2
factors_str = "2,2_5,1_635599,1_2533393,1_4122411947,1_175521834973,1_206740999513,1_1994957217983,1_215264178543783483824207,1_10254137552818335844980930258636403,1"
print(r.readuntil(b"> "))
r.sendline(factors_str.encode())

# TASK 3
print(r.readuntil(b"0.\n"))

factors = {
    2: 2,
    5: 1,
    635599: 1,
    2533393: 1,
    4122411947: 1,
    175521834973: 1,
    206740999513: 1,
    1994957217983: 1,
    215264178543783483824207: 1,
    10254137552818335844980930258636403: 1
}

def is_generator(g):
    phi = p - 1  # Order of the multiplicative group F_p*

    # Check if g^(phi/q) != 1 (mod p) for all prime factors q
    for q in factors.keys():
        if pow(g, phi // q, p) == 1:
            return False  # g is not a generator
    return True

for i in range(17):
    x = r.readuntil(" > ")
    if b"?" in x:
        g = int(x[:-4])
    if not is_generator(g):
        r.sendline(b"0")
    else:
        r.sendline(b"1")

# TASK 4
print(r.readuntil(b"a = "))
ac = int(r.readline()[:-1])
print(r.readuntil(b"b = "))
bc = int(r.readline()[:-1])

if not (ac == a and bc == b):
    print("a and b do not match!")
    exit()

print(r.readuntil(b" > "))
r.sendline(str(p).encode())

# TASK 5
factors2_str = "2,2_7,2_21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061,1_2296163171090566549378609985715193912396821929882292947886890025295122370435191839352044293887595879123562797851002485690372901374381417938210071827839043175382685244226599901222328480132064138736290361668527861560801378793266019,1"

print(r.readuntil(b" > "))
r.sendline(factors2_str.encode())

# TASK 6 (requires a running docker container that is listening on localhost:1337)
Gx = 10754634945965100597587232538382698551598951191077578676469959354625325250805353921972302088503050119092675418338771

print(r.readuntil(b"te: "))
Gxc = int(r.readline()[:-1])

if Gxc != Gx:
    print("Gxc does not match Gx!")
    exit()

print(r.readuntil(b"te: "))
Ax = int(r.readline()[:-1])

# query the sage server
r2 = remote("127.0.0.1", 1337)
r2.sendline(str(Ax).encode())
r2.readuntil(b"d = ")
d = int(r2.readline()[:-1])

# return response
r.sendline(str(d).encode())
r2.close()

r.interactive()
```

### Flag

`HTB{Welcome_to_CA_2k25!Here_is_your_anomalous_flag_for_this_challenge_and_good_luck_with_the_rest:)_d86c36b3ec84306bef8024f194294f5a}`

