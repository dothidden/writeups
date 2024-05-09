---
title: flavors
date: 2024-05-08T12:53:05+03:00
description: Writeup for flavors [UMDCTF 2024]
author: zenbassi
tags:
- rev
draft: false
---
___

## Challenge Description

ah, elixirs, the sweet liquid flavor that brings a little spice to my life

desired output is AD38A5970B000E1500041F0B00011617AA85109204082D1485040326051D13012716BF081189AB990E2D0F182CA824

## Intuition

I'm writing this writeup about two weeks after the CTF. Mostly because I was
very lazy. As such, you kind reader will have to excuse a few missing details.
Now let's start!

What we're dealing with is an erlang byte-code (`.beam`) file, compiled from
Elixir code.

Similar to other languages, the Elixir dev kit comes with an interactive shell
called `ixe`. [sunbather](https://github.com/costinteo) somehow figured we can
just run `Flavors.main` inside `ixe`. Recent searches through a decent search
engine on the web provide some missing details. Our file `Elixir.Flavors.main`
should define an elixir `Flavors` module. The `main` functions among others is
part of this module module. We can further list other functions by typing the
module's name `Flavors` followed by a dot and them spamming **tab** for
autocompletion. Needless to say, we didn't do that when solving the challenge.

We instead ran the main function and were asked for the flag. Inputting some
random garbage lead to it crashing somewhere in the `a` function. In an attempt
to understand what the code is doing we looked into ways to disassemble the
`.beam` bytecode. We found a wonderful blog [^1], where we copy pasted the
following `Elixir` code from:

```elixir
f = './Elixr.Flavors.beam'
{:ok, beam} = File.read(f)
IO.inspect :beam_disasm.file(beam), pretty: true
```

The above outputs the (pretty) garbage of a disassembly that follows:

```
...
  {:function, :main, 0, 24,
    [
      {:line, 13},
      {:label, 23},
      {:func_info, {:atom, Flavors}, {:atom, :main}, 0},
      {:label, 24},
      {:allocate, 0, 0},
      {:move, {:literal, "Flag: "}, {:x, 0}},
      {:line, 14},
      {:call_ext, 1, {:extfunc, IO, :gets, 1}},
      {:call_ext, 1, {:extfunc, String, :trim, 1}},
      {:put_map_assoc, {:f, 0}, {:literal, %{}}, {:x, 0}, 1,
       {:list, [atom: :i, integer: 0, atom: :in, x: 0]}},
      {:call, 1, {Flavors, :a, 1}},
      {:line, 15},
      {:call, 1, {Flavors, :b, 1}},
      {:line, 16},
      {:call_ext_last, 1, {:extfunc, IO, :puts, 1}, 0}
    ]},
...
```

The actual output is much longer. The above sample is just the main function.
We can see that it prints "Flag:" on the screen, calls gets to read from stdin,
trims the input, does something with a map and then calls the `a` and `b`
functions. For us it was rather difficult to read, and it only got worse with the other functions. What next?

We resentfully copy and pasted everything into Chat-GPT. We started asking
questions and it seemed to understand everything. What a good robot! The it
told us exactly what each function does, perfectly described the process through
which the input is converted into a hash, and provided a valid input for the
program. We then gave it the _expected output_ and it identified the correct 
input for the program, which was exactly the flag.

Yeah, no, of course that didn't happen. We quickly realised it was printing
nonsense. We also realised that our disassembly had incomplete function
definitions. We changed course at that point.

This is the part where you'll have to excuse some missing details. We were
looking at the `a` function. It takes in a mapping as input and checks if
some key-value pairs exist. One these includes the number 47. We also knew
that the output's desired length is $94 = 47 \times 2$. Through an educated
guess we figured the desired input length is $47$. By feeding it a string of
47 characters, the program outputted a 94-character string, formatted similarly 
with the desired output.

By testing some input variations, we noticed that if we change on character in
the input, exactly two adjacent characters from the output change. At that
point we just assumed that the whole program just maps each character of the
input to a pair of two characters in the output and then permutes them into the
final hash-string. This is the assumption that lead to retrieving the flag.

## Solution

The solution consists of two parts. Firstly, we extracted the permutation by
running the program with inputs that differ by only one character, and
comparing the results.

```python
s = 'A' * 47
d = {i:i for i in range(47)}
h = check_output(f'echo -n "{s}" | elixir -e "Flavors.main"', shell=True)
r = h.split()[2].decode()

for i in range(47):
    s = 'A' * i + 'B' + 'A' * (47 - i - 1)
    assert(len(s) == 47)
    h = check_output(f'echo -n "{s}" | elixir -e "Flavors.main"', shell=True)
    h = h.split()[2].decode()
    for j in range(47):
        rr = r[j*2:(j + 1) * 2]
        hh = h[j*2:(j + 1) * 2]
        if rr != hh:
            d[i] = j

print(d)
```

Them, we can just brute-forceed each character from the flag, aiming to match
the corresponding two-character hash with the one in the desired output.

```python
target = "AD38A5970B000E1500041F0B00011617AA85109204082D1485040326051D13012716BF081189AB990E2D0F182CA824"

alphabet = '}_?' + string.ascii_letters + string.digits

sol = 'UMDCTF{what_about_melange_b'

for i in range(len(sol), 47):
    print(f'finding {i}')
    for c in alphabet:
        print(f'testing {c}', end='\r')
        s = 'A' * i + c + 'A' * (47 - i - 1)
        h = check_output(f'echo -n "{s}" | elixir -e "Flavors.main"', shell=True)
        h = h.split()[2].decode()

        tt = target[d[i] * 2: (d[i] + 1) * 2]
        hh = h[d[i] * 2: (d[i] + 1) * 2]
        if tt == hh:
            sol += c
            break

    print(f'flag now: {sol}')

print(sol)
```

Manually assisting the script with some more educated guesses lead to a rather
quick retrieval of the flag.

### Flag

`UMDCTF{what_about_melange_but_in_elixir_form_?}`

## References

[^1]: https://medium.com/learn-elixir/disassemble-elixir-code-1bca5fe15dd1
