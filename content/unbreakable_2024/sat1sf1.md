---
title: sat1sf1
date: 2024-04-14T21:39:26+03:00
description: Writeup for sat1sf1 [Unbreakable 2024]
author: zenbassi
tags:
- rev
- crypto
draft: false
---
___

## Challenge Description

Made my own hashing function sah652.

Here the super-secure hash of my secret:
`2033251f4b3161e4455a4c261e3f631e18653c3a6c136e30304037373e6e1f6c6f6448673e686b1e18603d10306d323f3a4b626eee636c3c3c62483592123e6d6c6c3a49ca`

Feeling generous to share some hints about my secret that you definitely will
not able to recover:

Text length: 69 characters

Flag regex: CTF\{[a-f0-9]{64}\}

Flag contains somewhere the text: beebeef

## Intuition

Analysing the implementation we deduce that each byte of the hash is obtained
by xoring together some of the bytes which make up the original flag, and
potentially some other known values. Moreover, we know part of the original
flag and a crib. This is enough information to logically deduce some unknown
bytes. This creates a cascading effect, which enables us to recover the full
flag, if we know the position of the crib, which is brute-forcible.

## Solution

Our original solution involved lazily building the equations which form each
byte of the hash. We used a few tricks to reduce these equations. Firstly, we
noticed a number of equation with only one unknown variable. The unknown in
these instanced can be obtained by xor-ing the corresponding byte from the hash
with the other known values. There second trick was that we could xor together
two different equations which had overlapping terms, such that the result would
be a different equation with fewer unknown terms. These tricks, paired with
brute-forcing the crib's position enables us to recover the flag. 

On a closer inspection, we notice that we're dealing with a logical formula
where the unknown terms are the characters of the flag. If it's satisfiable,
the model for this formula should be unique, and should correspond to our flag.
After an upsolving session and some discord hints, we came up with a simpler
solution based on the Z3 SMT solver [^z3]. We build the formula in the z3
format and then find a model for it. A partial solution can be checked out
below.

```python
variables = {i: BitVec(f'v_{i}', 7) for i in range(200)}
state0 = [variables[i] for i in range(200)]
out = SAH3_652(state0)

hashul = bytes.fromhex("2033251f4b3161e4455a4c261e3f631e18653c3a6c136e3" \
                        "0304037373e6e1f6c6f6448673e686b1e18603d10306d32" \
                        "3f3a4b626eee636c3c3c62483592123e6d6c6c3a49ca")
s = Solver()
for i in range(69):
    # add constraints based on hash
    s.add(simplify(out[i] == int(hashul[i])))

# add constraints based on known values
s.add(variables[0]  == ord('C'))
s.add(variables[1]  == ord('T'))
s.add(variables[2]  == ord('F'))
s.add(variables[3]  == ord('{'))
s.add(variables[68] == ord('}'))

for i in range(69, 200):
    s.add(variables[i] == 0)

# add constraints based on crib
and_conds = []
ss = 'beebeef'
for off in range(8, 58):
    # for each offset, we have a set of possible constraints
    terms = [variables[off + i] == ord(c) for i, c in enumerate(ss)]
    and_conds.append(And(*terms))
s.add(Or(*and_conds))

# check for satisfiability and get model
print(f'our theorem is:', s.check())
m = s.model()

# print solution
print("".join([chr(m[variables[i]].as_long()) for i in range(69)]))
```

### Flag

`CTF{45adda2019d24619435fcb0a0b644f576c8baeffeeb603d1618cdbeebeefaead}`

## References

[^z3]: https://github.com/Z3Prover/z3
