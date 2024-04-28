---
title: typecheck
date: 2024-04-28T23:58:34+03:00
description: Writeup for typecheck [UMDCTF_2024]
author: sunbather
tags:
- rev
- z3
draft: false
---
___

## Challenge Description

My C++ code won't type check. Can you fix that for me?

Note: you will need to set -ftemplate-depth=10000 when compiling.

## Intuition

So uh... apparently C++ templates are turing complete? Yeah this challenge implements a VM in C++ templates. Oh boy...

Of course, who'd wanna reverse a VM written in _TEMPLATES_? Nobody, that's who. So my initial reaction is to try to reverse the program without reversing the templates. Which doesn't prove to be terribly hard. I'll attach the entire main.cpp and templates.hpp in the Annex section of the writeup, at the bottom. We can notice some big numbers in the ``prog_t`` list. I deduce the program probably checks your flag, byte by byte with those big numbers. Obviously, ascii values can't be that big, so I thought maybe there's some relation between ``40701`` (the first number checked) and the ascii value for ``U`` (from ``UMDCTF``). You can find some relations, but they don't apply to the other known values, so I deduce maybe that the ascii value is input to a linear function or something, but I still can't find the relation. So instead I wrote a bruteforcer. If you actually try to compile the program, you'll get a huge error and it will basically fail when comparing your result to one of the big numbers mentioned earlier. If you extract this output programatically, you can use the value in the error to check what your result is.

Another important thing I noticed is that changing characters didn't _always_ change the result. Only some of them did. So I wrote a function that detects which character affects the first output.

Sadly I ripped apart the bruteforcer during the solve, but it went something like this:
1. Start with a known flag: ``UMDCTF{....................}`` (ensure length is 60).
2. Incrementally try flags with one different character to see which characters changes the output.
3. Start bruteforcing the found character.

But after doing this, none of the resulting values ever matched the expected value ``40701``. The results were all 24 values apart, though. Which made me think about it again. What if it's a linear equation made up of _MULTIPLE_ characters from the flag? You can notice the 24 next to the value 12, in the first few opcodes of the ``vm program``: ``2, 0, 3, 2, 2, 47, 1, 0, 3, 12, 2, 24, 1, 0, 3, 16, 2, [...]``.

Here are some scraps of the bruteforcer that were still intact:

```py
CMD = b"g++ gen.cpp -ftemplate-depth=10000 -o test 2>&1"
def run_prog():
    try:
        out = check_output(CMD, shell=True)
    except CalledProcessError as exc:
        out = exc.output
    
    x, y = out.split(b'\n')[3].split()[-4:-2]
    x = int(x[2:-1])
    y = int(y[7:-2])
    return x, y


def find_next_pos(flag):
    for i in range(flag.find('.'), len(flag) - 1):
        test_flag = flag[:i] + "x" + flag[i+1:]
        #print(test_flag)
        write_main(test_flag)
        
        x, y = run_prog()

        # number for '.'
        if y != 19940:
            return i
            
        continue
    return -1

```
I started looking for a pattern and decided that after every ``3`` opcode, there should be a position from the flag. Then, 2 indices to the right we should find the factor for that position. Add every ``var * factor`` together and then check the sum with ``40701``, or whatever the big number for that part was. After several experiments to test this theory, I could reliably confirm it was the case. However, after writing a z3 script to solve the constraints, my model was unsat! I was a bit at a loss, started checking the script several times over...

## Solution

Of course, on Sunday [zenbassi](https://github.com/Stefan-Radu) woke from his slumber (after solving some complex rev at Open ECSC, no less) and joined Discord. After explaining the whole situation he just said "yeah lemme reverse the templates real quick" and he did it in like 5-10 minutes. He's just built different, I guess. I then wrote a disassembler directed by him and extracted the equations and constraints like that. Then we made a z3 solver and ran it to get the model and with that, the flag. I'm really proud of the fact that I deduced what the program does without reversing though lol. I think I might have messed up an equation previously or something stupid like that. Here is the final script:

```py
#!/usr/bin/env python3

from z3 import *

# extracted program from prog_t, truncated so it doesn't take the whole page
prog = [...] 

instr_map = {
    0 : "add", # add two nums on stack
    1 : "mul", # multiply two nums on stack
    2 : "psh", # push arg on stack
    3 : "get", # get character from flag (arg is pos) and push on stack
    4 : "chk"  # check value on stack == arg
}

s = Solver()

variables = {i: Int(f'v_{i}') for i in range(60)}

# add some printable ascii constraints
for i in range(len(variables)):
    s.add(variables[i] > 35)
    s.add(variables[i] < 126)

# the known letters
for i, c in enumerate("UMDCTF{"):
    s.add(variables[i] == ord(c))
s.add(variables[59] == ord('}'))

sym_vars = []
i = 0
while i < len(prog):
    if prog[i] < 2:
        print(instr_map[prog[i]])
    else:
        print(instr_map[prog[i]], prog[i+1])
        if prog[i] == 3:
            pos = prog[i+1]
        if prog[i] == 2:
            factor = prog[i+1]
            if factor == 0:
                pass
            else:
                sym_vars.append(variables[pos] * factor)
        if prog[i] == 4:
            s.add(Sum(sym_vars) == prog[i+1])
            sym_vars = []
        i += 1

    i += 1

print("WORKING? ", s.check())
model = s.model()
print(model)
print("".join([chr(model[variables[i]].as_long()) for i in range(60)]))
```

### Flag

``UMDCTF{c++_templates_are_the_reason_for_the_butlerian_jihad}``

### Annex

```c
#include "templates.hpp"

// flag is 60 chars
using flag_t = int_list_t <'s','o','m','e','f','l','a','g'>;
using prog_t = int_list_t <2, 0, 3, 2, 2, 47, 1, 0, 3, 12, 2, 24, 1, 0, 3, 16, 2, 67, 1, 0, 3, 18, 2, 89, 1, 0, 3, 22, 2, 59, 1, 0, 3, 41, 2, 61, 1, 0, 3, 51, 2, 19, 1, 0, 3, 56, 2, 45, 1, 0, 4, 40701, 2, 0, 3, 0, 2, 66, 1, 0, 3, 11, 2, 8, 1, 0, 3, 21, 2, 64, 1, 0, 3, 26, 2, 15, 1, 0, 3, 30, 2, 8, 1, 0, 3, 43, 2, 91, 1, 0, 3, 46, 2, 14, 1, 0, 3, 56, 2, 70, 1, 0, 4, 32663, 2, 0, 3, 22, 2, 20, 1, 0, 3, 28, 2, 71, 1, 0, 3, 29, 2, 4, 1, 0, 3, 34, 2, 93, 1, 0, 3, 48, 2, 92, 1, 0, 3, 56, 2, 11, 1, 0, 3, 59, 2, 22, 1, 0, 4, 32897, 2, 0, 3, 13, 2, 55, 1, 0, 3, 14, 2, 82, 1, 0, 3, 24, 2, 36, 1, 0, 3, 25, 2, 94, 1, 0, 3, 36, 2, 97, 1, 0, 3, 38, 2, 97, 1, 0, 3, 45, 2, 33, 1, 0, 3, 48, 2, 84, 1, 0, 4, 62800, 2, 0, 3, 11, 2, 11, 1, 0, 3, 15, 2, 43, 1, 0, 3, 16, 2, 73, 1, 0, 3, 22, 2, 88, 1, 0, 3, 28, 2, 88, 1, 0, 3, 40, 2, 34, 1, 0, 3, 43, 2, 71, 1, 0, 3, 49, 2, 25, 1, 0, 3, 56, 2, 89, 1, 0, 4, 54188, 2, 0, 3, 0, 2, 47, 1, 0, 3, 1, 2, 38, 1, 0, 3, 3, 2, 76, 1, 0, 3, 15, 2, 2, 1, 0, 3, 24, 2, 9, 1, 0, 3, 26, 2, 41, 1, 0, 3, 27, 2, 100, 1, 0, 3, 36, 2, 35, 1, 0, 3, 43, 2, 1, 1, 0, 4, 31113, 2, 0, 3, 7, 2, 97, 1, 0, 3, 10, 2, 79, 1, 0, 3, 29, 2, 27, 1, 0, 3, 30, 2, 84, 1, 0, 3, 31, 2, 39, 1, 0, 3, 35, 2, 13, 1, 0, 3, 37, 2, 40, 1, 0, 3, 52, 2, 7, 1, 0, 4, 38898, 2, 0, 3, 2, 2, 15, 1, 0, 3, 15, 2, 67, 1, 0, 3, 25, 2, 19, 1, 0, 3, 32, 2, 12, 1, 0, 3, 44, 2, 97, 1, 0, 3, 48, 2, 76, 1, 0, 3, 49, 2, 3, 1, 0, 3, 51, 2, 75, 1, 0, 4, 36639, 2, 0, 3, 1, 2, 54, 1, 0, 3, 3, 2, 11, 1, 0, 3, 9, 2, 30, 1, 0, 3, 13, 2, 52, 1, 0, 3, 21, 2, 61, 1, 0, 3, 24, 2, 58, 1, 0, 3, 38, 2, 35, 1, 0, 3, 43, 2, 79, 1, 0, 3, 58, 2, 26, 1, 0, 4, 37375, 2, 0, 3, 2, 2, 32, 1, 0, 3, 4, 2, 14, 1, 0, 3, 13, 2, 66, 1, 0, 3, 18, 2, 70, 1, 0, 3, 20, 2, 33, 1, 0, 3, 39, 2, 1, 1, 0, 3, 43, 2, 53, 1, 0, 3, 54, 2, 40, 1, 0, 4, 30121, 2, 0, 3, 7, 2, 46, 1, 0, 3, 21, 2, 34, 1, 0, 3, 25, 2, 37, 1, 0, 3, 40, 2, 31, 1, 0, 3, 44, 2, 33, 1, 0, 3, 48, 2, 98, 1, 0, 3, 53, 2, 68, 1, 0, 3, 55, 2, 67, 1, 0, 3, 57, 2, 72, 1, 0, 4, 49351, 2, 0, 3, 6, 2, 21, 1, 0, 3, 8, 2, 72, 1, 0, 3, 17, 2, 59, 1, 0, 3, 22, 2, 69, 1, 0, 3, 28, 2, 55, 1, 0, 3, 38, 2, 75, 1, 0, 3, 42, 2, 87, 1, 0, 4, 42951, 2, 0, 3, 4, 2, 56, 1, 0, 3, 6, 2, 75, 1, 0, 3, 10, 2, 23, 1, 0, 3, 16, 2, 6, 1, 0, 3, 25, 2, 45, 1, 0, 3, 35, 2, 68, 1, 0, 3, 42, 2, 91, 1, 0, 3, 44, 2, 33, 1, 0, 3, 52, 2, 79, 1, 0, 4, 49491, 2, 0, 3, 0, 2, 8, 1, 0, 3, 9, 2, 10, 1, 0, 3, 21, 2, 80, 1, 0, 3, 28, 2, 51, 1, 0, 3, 31, 2, 76, 1, 0, 3, 41, 2, 69, 1, 0, 3, 54, 2, 60, 1, 0, 3, 56, 2, 21, 1, 0, 3, 57, 2, 57, 1, 0, 4, 42336, 2, 0, 3, 5, 2, 21, 1, 0, 3, 32, 2, 1, 1, 0, 3, 33, 2, 43, 1, 0, 3, 41, 2, 98, 1, 0, 3, 42, 2, 19, 1, 0, 3, 50, 2, 57, 1, 0, 3, 55, 2, 77, 1, 0, 3, 57, 2, 4, 1, 0, 4, 32927, 2, 0, 3, 10, 2, 10, 1, 0, 3, 11, 2, 16, 1, 0, 3, 21, 2, 64, 1, 0, 3, 33, 2, 59, 1, 0, 3, 38, 2, 95, 1, 0, 3, 41, 2, 99, 1, 0, 3, 42, 2, 22, 1, 0, 4, 38911, 2, 0, 3, 2, 2, 75, 1, 0, 3, 3, 2, 21, 1, 0, 3, 12, 2, 81, 1, 0, 3, 13, 2, 30, 1, 0, 3, 18, 2, 56, 1, 0, 3, 33, 2, 48, 1, 0, 3, 38, 2, 52, 1, 0, 3, 41, 2, 28, 1, 0, 3, 43, 2, 21, 1, 0, 4, 39777, 2, 0, 3, 1, 2, 10, 1, 0, 3, 19, 2, 51, 1, 0, 3, 28, 2, 39, 1, 0, 3, 42, 2, 25, 1, 0, 3, 43, 2, 93, 1, 0, 3, 44, 2, 2, 1, 0, 3, 45, 2, 99, 1, 0, 3, 49, 2, 68, 1, 0, 3, 54, 2, 67, 1, 0, 4, 48333, 2, 0, 3, 0, 2, 53, 1, 0, 3, 4, 2, 6, 1, 0, 3, 24, 2, 52, 1, 0, 3, 45, 2, 88, 1, 0, 3, 47, 2, 59, 1, 0, 3, 50, 2, 57, 1, 0, 3, 54, 2, 90, 1, 0, 3, 55, 2, 32, 1, 0, 3, 57, 2, 64, 1, 0, 4, 51710, 2, 0, 3, 15, 2, 31, 1, 0, 3, 16, 2, 80, 1, 0, 3, 18, 2, 70, 1, 0, 3, 39, 2, 29, 1, 0, 3, 43, 2, 75, 1, 0, 3, 44, 2, 79, 1, 0, 3, 45, 2, 76, 1, 0, 3, 46, 2, 29, 1, 0, 4, 48056, 2, 0, 3, 0, 2, 85, 1, 0, 3, 7, 2, 64, 1, 0, 3, 9, 2, 85, 1, 0, 3, 14, 2, 1, 1, 0, 3, 18, 2, 45, 1, 0, 3, 24, 2, 26, 1, 0, 3, 37, 2, 42, 1, 0, 3, 38, 2, 74, 1, 0, 3, 39, 2, 90, 1, 0, 4, 45991, 2, 0, 3, 13, 2, 76, 1, 0, 3, 23, 2, 33, 1, 0, 3, 39, 2, 40, 1, 0, 3, 43, 2, 6, 1, 0, 3, 44, 2, 66, 1, 0, 3, 47, 2, 12, 1, 0, 3, 48, 2, 67, 1, 0, 3, 58, 2, 35, 1, 0, 3, 59, 2, 15, 1, 0, 4, 35893, 2, 0, 3, 3, 2, 1, 1, 0, 3, 4, 2, 11, 1, 0, 3, 10, 2, 9, 1, 0, 3, 12, 2, 47, 1, 0, 3, 26, 2, 99, 1, 0, 3, 38, 2, 33, 1, 0, 3, 40, 2, 43, 1, 0, 3, 47, 2, 2, 1, 0, 3, 53, 2, 90, 1, 0, 4, 34405, 2, 0, 3, 12, 2, 8, 1, 0, 3, 16, 2, 54, 1, 0, 3, 18, 2, 66, 1, 0, 3, 25, 2, 98, 1, 0, 3, 27, 2, 71, 1, 0, 3, 38, 2, 83, 1, 0, 3, 55, 2, 70, 1, 0, 3, 57, 2, 38, 1, 0, 4, 51749, 2, 0, 3, 2, 2, 6, 1, 0, 3, 5, 2, 13, 1, 0, 3, 13, 2, 19, 1, 0, 3, 43, 2, 70, 1, 0, 3, 45, 2, 47, 1, 0, 3, 47, 2, 88, 1, 0, 3, 56, 2, 26, 1, 0, 3, 57, 2, 65, 1, 0, 3, 58, 2, 63, 1, 0, 4, 40351, 2, 0, 3, 3, 2, 48, 1, 0, 3, 5, 2, 32, 1, 0, 3, 20, 2, 3, 1, 0, 3, 27, 2, 95, 1, 0, 3, 39, 2, 15, 1, 0, 3, 41, 2, 10, 1, 0, 3, 42, 2, 68, 1, 0, 3, 51, 2, 32, 1, 0, 3, 59, 2, 77, 1, 0, 4, 37398, 2, 0, 3, 2, 2, 72, 1, 0, 3, 13, 2, 20, 1, 0, 3, 27, 2, 31, 1, 0, 3, 32, 2, 46, 1, 0, 3, 34, 2, 12, 1, 0, 3, 37, 2, 11, 1, 0, 3, 39, 2, 36, 1, 0, 3, 58, 2, 76, 1, 0, 3, 59, 2, 23, 1, 0, 4, 31933, 2, 0, 3, 4, 2, 61, 1, 0, 3, 8, 2, 81, 1, 0, 3, 18, 2, 13, 1, 0, 3, 35, 2, 38, 1, 0, 3, 41, 2, 37, 1, 0, 3, 48, 2, 29, 1, 0, 3, 49, 2, 1, 1, 0, 3, 52, 2, 62, 1, 0, 3, 53, 2, 80, 1, 0, 4, 34841, 2, 0, 3, 4, 2, 38, 1, 0, 3, 6, 2, 26, 1, 0, 3, 7, 2, 14, 1, 0, 3, 25, 2, 1, 1, 0, 3, 26, 2, 16, 1, 0, 3, 32, 2, 42, 1, 0, 3, 36, 2, 22, 1, 0, 3, 47, 2, 93, 1, 0, 3, 51, 2, 22, 1, 0, 4, 28808, 2, 0, 3, 27, 2, 10, 1, 0, 3, 40, 2, 49, 1, 0, 3, 54, 2, 2, 1, 0, 3, 56, 2, 14, 1, 0, 3, 57, 2, 70, 1, 0, 4, 15152, 2, 0, 3, 1, 2, 22, 1, 0, 3, 8, 2, 16, 1, 0, 3, 21, 2, 9, 1, 0, 3, 24, 2, 45, 1, 0, 3, 31, 2, 7, 1, 0, 3, 45, 2, 89, 1, 0, 3, 56, 2, 16, 1, 0, 3, 59, 2, 73, 1, 0, 4, 29411, 2, 0, 3, 1, 2, 96, 1, 0, 3, 25, 2, 21, 1, 0, 3, 26, 2, 84, 1, 0, 3, 35, 2, 39, 1, 0, 3, 39, 2, 80, 1, 0, 3, 50, 2, 21, 1, 0, 3, 53, 2, 25, 1, 0, 3, 55, 2, 98, 1, 0, 3, 57, 2, 19, 1, 0, 4, 46582, 2, 0, 3, 27, 2, 57, 1, 0, 3, 28, 2, 59, 1, 0, 3, 29, 2, 28, 1, 0, 3, 36, 2, 84, 1, 0, 3, 43, 2, 26, 1, 0, 3, 49, 2, 28, 1, 0, 3, 56, 2, 54, 1, 0, 3, 58, 2, 53, 1, 0, 4, 39700, 2, 0, 3, 2, 2, 87, 1, 0, 3, 11, 2, 26, 1, 0, 3, 24, 2, 56, 1, 0, 3, 29, 2, 59, 1, 0, 3, 31, 2, 19, 1, 0, 3, 42, 2, 38, 1, 0, 3, 48, 2, 30, 1, 0, 3, 54, 2, 34, 1, 0, 3, 58, 2, 8, 1, 0, 4, 34093, 2, 0, 3, 0, 2, 21, 1, 0, 3, 2, 2, 44, 1, 0, 3, 13, 2, 14, 1, 0, 3, 27, 2, 57, 1, 0, 3, 34, 2, 96, 1, 0, 3, 38, 2, 64, 1, 0, 3, 41, 2, 73, 1, 0, 3, 53, 2, 66, 1, 0, 3, 59, 2, 13, 1, 0, 4, 45403, 2, 0, 3, 6, 2, 3, 1, 0, 3, 8, 2, 37, 1, 0, 3, 16, 2, 89, 1, 0, 3, 18, 2, 60, 1, 0, 3, 21, 2, 49, 1, 0, 3, 31, 2, 48, 1, 0, 3, 32, 2, 80, 1, 0, 3, 49, 2, 22, 1, 0, 3, 57, 2, 81, 1, 0, 4, 45627, 2, 0, 3, 8, 2, 64, 1, 0, 3, 9, 2, 6, 1, 0, 3, 10, 2, 29, 1, 0, 3, 24, 2, 83, 1, 0, 3, 25, 2, 91, 1, 0, 3, 26, 2, 39, 1, 0, 3, 37, 2, 11, 1, 0, 3, 39, 2, 68, 1, 0, 3, 55, 2, 28, 1, 0, 4, 38883, 2, 0, 3, 0, 2, 76, 1, 0, 3, 2, 2, 15, 1, 0, 3, 24, 2, 25, 1, 0, 3, 25, 2, 52, 1, 0, 3, 27, 2, 48, 1, 0, 3, 28, 2, 52, 1, 0, 3, 40, 2, 49, 1, 0, 3, 46, 2, 4, 1, 0, 3, 51, 2, 88, 1, 0, 4, 40359, 2, 0, 3, 11, 2, 97, 1, 0, 3, 19, 2, 31, 1, 0, 3, 32, 2, 36, 1, 0, 3, 42, 2, 100, 1, 0, 3, 48, 2, 62, 1, 0, 3, 53, 2, 61, 1, 0, 3, 59, 2, 8, 1, 0, 4, 42114, 2, 0, 3, 7, 2, 38, 1, 0, 3, 12, 2, 62, 1, 0, 3, 23, 2, 2, 1, 0, 3, 35, 2, 19, 1, 0, 3, 36, 2, 55, 1, 0, 3, 49, 2, 59, 1, 0, 3, 55, 2, 77, 1, 0, 3, 58, 2, 96, 1, 0, 4, 42052, 2, 0, 3, 1, 2, 77, 1, 0, 3, 8, 2, 50, 1, 0, 3, 9, 2, 43, 1, 0, 3, 13, 2, 68, 1, 0, 3, 36, 2, 94, 1, 0, 3, 48, 2, 57, 1, 0, 3, 58, 2, 15, 1, 0, 4, 34185, 2, 0, 3, 16, 2, 10, 1, 0, 3, 20, 2, 67, 1, 0, 3, 29, 2, 85, 1, 0, 3, 35, 2, 8, 1, 0, 3, 38, 2, 10, 1, 0, 3, 49, 2, 8, 1, 0, 3, 54, 2, 88, 1, 0, 3, 58, 2, 42, 1, 0, 3, 59, 2, 58, 1, 0, 4, 40615, 2, 0, 3, 6, 2, 97, 1, 0, 3, 14, 2, 65, 1, 0, 3, 17, 2, 27, 1, 0, 3, 27, 2, 14, 1, 0, 3, 39, 2, 81, 1, 0, 3, 44, 2, 44, 1, 0, 3, 49, 2, 22, 1, 0, 3, 59, 2, 49, 1, 0, 4, 44397, 2, 0, 3, 0, 2, 28, 1, 0, 3, 5, 2, 9, 1, 0, 3, 8, 2, 27, 1, 0, 3, 14, 2, 47, 1, 0, 3, 16, 2, 88, 1, 0, 3, 22, 2, 86, 1, 0, 3, 29, 2, 65, 1, 0, 3, 50, 2, 87, 1, 0, 4, 44320, 2, 0, 3, 3, 2, 94, 1, 0, 3, 9, 2, 83, 1, 0, 3, 24, 2, 62, 1, 0, 3, 26, 2, 9, 1, 0, 3, 27, 2, 88, 1, 0, 3, 33, 2, 51, 1, 0, 3, 41, 2, 73, 1, 0, 3, 48, 2, 43, 1, 0, 4, 43177, 2, 0, 3, 4, 2, 32, 1, 0, 3, 7, 2, 38, 1, 0, 3, 9, 2, 81, 1, 0, 3, 13, 2, 16, 1, 0, 3, 31, 2, 89, 1, 0, 3, 35, 2, 58, 1, 0, 3, 40, 2, 52, 1, 0, 3, 59, 2, 4, 1, 0, 4, 32352, 2, 0, 3, 0, 2, 45, 1, 0, 3, 3, 2, 51, 1, 0, 3, 8, 2, 30, 1, 0, 3, 9, 2, 84, 1, 0, 3, 21, 2, 51, 1, 0, 3, 43, 2, 53, 1, 0, 3, 46, 2, 22, 1, 0, 3, 52, 2, 89, 1, 0, 3, 59, 2, 61, 1, 0, 4, 42093, 2, 0, 3, 6, 2, 53, 1, 0, 3, 12, 2, 75, 1, 0, 3, 14, 2, 91, 1, 0, 3, 22, 2, 43, 1, 0, 3, 24, 2, 76, 1, 0, 3, 28, 2, 8, 1, 0, 3, 37, 2, 99, 1, 0, 3, 47, 2, 1, 1, 0, 3, 48, 2, 63, 1, 0, 4, 54628, 2, 0, 3, 5, 2, 78, 1, 0, 3, 8, 2, 55, 1, 0, 3, 13, 2, 16, 1, 0, 3, 22, 2, 92, 1, 0, 3, 38, 2, 97, 1, 0, 3, 42, 2, 16, 1, 0, 3, 51, 2, 97, 1, 0, 3, 54, 2, 41, 1, 0, 3, 56, 2, 87, 1, 0, 4, 55534, 2, 0, 3, 0, 2, 36, 1, 0, 3, 3, 2, 58, 1, 0, 3, 5, 2, 21, 1, 0, 3, 15, 2, 64, 1, 0, 3, 16, 2, 81, 1, 0, 3, 17, 2, 9, 1, 0, 3, 18, 2, 76, 1, 0, 3, 39, 2, 29, 1, 0, 3, 43, 2, 14, 1, 0, 4, 35990, 2, 0, 3, 0, 2, 16, 1, 0, 3, 2, 2, 50, 1, 0, 3, 13, 2, 49, 1, 0, 3, 18, 2, 19, 1, 0, 3, 21, 2, 89, 1, 0, 3, 24, 2, 4, 1, 0, 3, 29, 2, 66, 1, 0, 3, 32, 2, 50, 1, 0, 4, 34307, 2, 0, 3, 3, 2, 53, 1, 0, 3, 21, 2, 31, 1, 0, 3, 24, 2, 96, 1, 0, 3, 27, 2, 28, 1, 0, 3, 31, 2, 92, 1, 0, 3, 33, 2, 93, 1, 0, 3, 37, 2, 68, 1, 0, 3, 40, 2, 89, 1, 0, 4, 55625, 2, 0, 3, 2, 2, 82, 1, 0, 3, 9, 2, 85, 1, 0, 3, 10, 2, 92, 1, 0, 3, 18, 2, 59, 1, 0, 3, 38, 2, 83, 1, 0, 3, 46, 2, 17, 1, 0, 3, 53, 2, 54, 1, 0, 3, 54, 2, 18, 1, 0, 3, 58, 2, 72, 1, 0, 4, 49602, 2, 0, 3, 14, 2, 46, 1, 0, 3, 17, 2, 7, 1, 0, 3, 28, 2, 64, 1, 0, 3, 33, 2, 98, 1, 0, 3, 37, 2, 77, 1, 0, 3, 40, 2, 4, 1, 0, 3, 41, 2, 24, 1, 0, 3, 48, 2, 87, 1, 0, 3, 55, 2, 32, 1, 0, 4, 46576, 2, 0, 3, 6, 2, 50, 1, 0, 3, 7, 2, 55, 1, 0, 3, 15, 2, 91, 1, 0, 3, 24, 2, 64, 1, 0, 3, 46, 2, 10, 1, 0, 3, 47, 2, 48, 1, 0, 3, 48, 2, 54, 1, 0, 3, 53, 2, 62, 1, 0, 3, 54, 2, 92, 1, 0, 4, 54943, 2, 0, 3, 3, 2, 93, 1, 0, 3, 4, 2, 43, 1, 0, 3, 7, 2, 64, 1, 0, 3, 19, 2, 77, 1, 0, 3, 20, 2, 5, 1, 0, 3, 33, 2, 57, 1, 0, 3, 44, 2, 39, 1, 0, 3, 51, 2, 95, 1, 0, 3, 53, 2, 10, 1, 0, 4, 45823, 2, 0, 3, 0, 2, 99, 1, 0, 3, 1, 2, 65, 1, 0, 3, 2, 2, 48, 1, 0, 3, 6, 2, 80, 1, 0, 3, 17, 2, 17, 1, 0, 3, 39, 2, 43, 1, 0, 3, 46, 2, 73, 1, 0, 3, 55, 2, 96, 1, 0, 4, 51129, 2, 0, 3, 2, 2, 16, 1, 0, 3, 5, 2, 82, 1, 0, 3, 25, 2, 46, 1, 0, 3, 31, 2, 61, 1, 0, 3, 33, 2, 92, 1, 0, 3, 35, 2, 35, 1, 0, 3, 38, 2, 53, 1, 0, 3, 50, 2, 36, 1, 0, 4, 41440, 2, 0, 3, 1, 2, 89, 1, 0, 3, 3, 2, 99, 1, 0, 3, 4, 2, 44, 1, 0, 3, 17, 2, 72, 1, 0, 3, 38, 2, 91, 1, 0, 3, 40, 2, 55, 1, 0, 3, 42, 2, 2, 1, 0, 3, 46, 2, 31, 1, 0, 3, 50, 2, 54, 1, 0, 4, 51756, 2, 0, 3, 0, 2, 73, 1, 0, 3, 14, 2, 38, 1, 0, 3, 22, 2, 61, 1, 0, 3, 25, 2, 78, 1, 0, 3, 38, 2, 63, 1, 0, 3, 42, 2, 44, 1, 0, 3, 50, 2, 75, 1, 0, 3, 52, 2, 63, 1, 0, 3, 54, 2, 78, 1, 0, 4, 61162>;


int main() {
    vm_t<nil_t, prog_t, flag_t> b;

    b = (nil_t)b;
}
```

```c
#include <type_traits>

struct nil_t {};

template<class T, class U>
struct cons {
    using car = T;
    using cdr = U;
};

template <class T>
using car_t = typename T::car;

template <class T>
using cdr_t = typename T::cdr;

template <class ... Ts>
struct list;

template <>
struct list<> {
    using type = nil_t;
};

template <class T, class ... Ts>
struct list<T, Ts...> {
    using type = cons<T, list<Ts...>>;
};

template <class ... Ts>
using list_t = typename list<Ts...>::type;

template <int v> struct V { static const constexpr int value = v ; };

template <int ... is>
struct int_list;

template <int i>
struct int_list<i> {
    using type = cons<V<i>, nil_t>;
};

template <int i, int ... is> 
struct int_list<i, is...> {
    using type = cons<V<i>, typename int_list<is...>::type>;
};

template <int ... is>
using int_list_t = typename int_list<is...>::type;


template <int i, typename T>
struct g;

template <int v, typename R>
struct g<0, cons<V<v>, R>> {
    static const constexpr int value = v;
};

template <int N, typename X, typename R>
struct g<N, cons<X, R>> {
    static const constexpr int value = g<N-1, R>::value;
};
template <typename S>
struct A;

template <int a, int b, typename rest>
struct A<cons<V<a>, cons<V<b>, rest>>> {
    using type = cons<V<a + b>, rest>;
};

template <typename S>
using A_t = typename A<S>::type;


template <typename S>
struct M;

template <int a, int b, typename rest>
struct M<cons<V<a>, cons<V<b>, rest>>> {
    using type = cons<V<a * b>, rest>;
};

template <typename S>
using M_t = typename M<S>::type;

template <int v, typename S>
struct P {
    using type = cons<V<v>, S>;
};

template <int v, typename S>
using P_t = typename P<v, S>::type;


template <int v, typename S>
struct T;

template <int v, int v_, typename R>
struct T<v, cons<V<v_>, R>> {
    using type = std::enable_if_t<v == v_, R>;
};

template <int v, typename S>
using T_t = typename T<v, S>::type;


template <typename S, typename IT, typename In>
struct vm;

template <typename S, typename In>
struct vm<S, nil_t, In> {
    using type = S;
};

template <typename S, typename R, typename In>
struct vm<S, cons<V<0>, R>, In>  {
    using type = typename vm<A_t<S>, R, In>::type;
};

template <typename S, typename R, typename In>
struct vm<S, cons<V<1>, R>, In>  {
    using type = typename vm<M_t<S>, R, In>::type;
};

template <typename S, int PV, typename R, typename In>
struct vm<S, cons<V<2>, cons<V<PV>, R>>, In>  {
    using type = typename vm<P_t<PV, S>, R, In>::type;
};

template <typename S, int N, typename R, typename In>
struct vm<S, cons<V<3>, cons<V<N>, R>>, In> {
    using type = typename vm<cons<V<g<N, In>::value>, S>, R, In>::type;
};

template <typename S, int PV, typename R, typename In>
struct vm<S, cons<V<4>, cons<V<PV>, R>>, In>  {
    using type = typename vm<T_t<PV, S>, R, In>::type;
};

template <typename S, typename IT, typename In>
using vm_t = typename vm<S, IT, In>::type;
```
