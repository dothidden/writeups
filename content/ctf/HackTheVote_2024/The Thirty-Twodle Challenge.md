---
title: The Thirty-Twodle Challenge
date: 2024-11-06T22:20:02+03:00
description: Writeup for The Thirty-Twodle Challenge [HackTheVote 2024]
type: writeup
author: MettleSphee
tags:
  - rev
draft: false
---
## Challenge Description
We found the source of our opponent's fake news generator, but our crack team
of interns got side tracked playing the -dles! Can you crack this disinformation
machine and help us predict their each and every future story?

## Intuition
This write-up is going to be less of a technical one because I (MettleSphee) took a weird approach: I like thinking about how games would work technically by looking at how they behave. Therefore, I found the directions to the flag without looking myself at the code, but the help I've gotten was incredible. I couldn't have written such amazing scripts/solutions for the challenge, and the credit goes to (zenbassi) for basically doing the harder part of the challenge :) .

## Write-up
``Authors: MettleSphee, zenbassi``

My teammate was doing the whole reversing process, while I chimed in and just wanted to try and run the binary to see what happens.

Alright, who knows Wordle? The game has the player try to guess a 5 letter word, while allowing a total of 6 guesses. While guessing, each letter is marked in the word as follows:
- Gray = the letter doesn't exist in that word;
- Yellow = the letter exists in the word, but it's not in the right position;
- Green = the letter is correct and in the right position;

Sounds simple, right? Well, here's where the twist comes in: You have to guess 32 words in one go. Now it feels like a challenge.
But don't worry, it's not *that* hard. This game has some specific caveats:
- The executable asks you for a seed; this means the words to guess are the same every run on a specific seed (and therefore, can be guessed after multiple rounds);
- Whenever you have all the correct letters for (1) word, it will do something called auto-solve; This time, instead of the word being highlighted in green, we have a new color:
  - Purple = the word has been auto-solved by the program;
- Auto-solves *consume* 1 guess from the total number of guesses;
- You have 37 guesses to find all the words;

That's a lot of information. Okay, so that means we just have to input all words and we win, right?
![wordle1](/images/HackTheVote_2024/wordle1.png)
Guess not. By looking through the code, it gives access to ``/bin/sh`` only when (simplified) all words are auto-solved. Given that it adds a guess whenever it auto-solves a word, we basically have 37 - 32 = 5 guesses which we can use to add words that contribute to auto-solving. How do we do that?

We can extract the full wordlist from the binary, and we can get the solution for that seed. As it turns out, finding the right words to auto-solve for a specific seed *may* be difficult. Factors which include having too many letters. As we have only 5 guesses with 5 letters each, that means a total of 25 letters. Given that we don't have many vowels, or other characters that repeat more often than not, we're going to have to find a good seed. The words are taken in a pseudo-random order from the wordlist using libc's ``srand(seed)`` function.

To get a good 'seed', we had to find a seed that had all of the 32 solutions with fewer distinct characters, and preferabily more repeating letters. Then, we would calculate the score based on the following explanation:
For each word in the solution we computed a dictionary with the letter frequency. We then computed the union of these dictionaries, taking the maximum from the common values. The score is the sum of the values in the union divided by 5. It represents something like the average number of unique letters from the solution alphabet, that each of our chosen words is expected to contain. This number is relevant, because a score greater than 5 will mean that we cannot find a solution, given that we're limited to words of size 5.


(zenbassi) wrote the scripts to do the following things (simplified):
- Find a seed with a score less than 5; the lower score the easier result;
- Find (bruteforce) valid words to be used in the solve that are NOT part of the 32 words to be found;


While doing all of this, I decided to keep the script running for the lulz to see if I can find a seed with a score low enough. Turns out I found one with a score as low as 4.2, which was a very, very good candidate.


After lots of trial and error due to some seeds being too difficult during testing, the scripts were ready. All that was left to do was to test the found words and get the flag:
![wordle2](/images/HackTheVote_2024/wordle2.png)
After we got the flag, I wanted to combine all scripts into a singular one for solving to make it slightly more clean.
![wordle_solve](/images/HackTheVote_2024/wordle_solve.png)
## Flag
``flag{my_opening_words_are_stare_and_doing_wbu}``
## Appendix
```py
#!/usr/bin/env python3		#imports, definitions
from ctypes import CDLL
from pwn import *
libc = CDLL("./libc.so.6")
words = []
with open("wordlist", "r") as f:
    words = [x.strip() for x in f.readlines()]
    #print(words[:3])
valid = []
with open("valids", "r") as f:
    valid = [x.strip() for x in f.readlines()]
    #print(valid[:3])

def gen_solution(seed):
    libc.srand(seed)
    solution = []
    for _ in range(32):
        solution.append(words[libc.rand() % 2313])
    return solution

def compute_score(solution):
    letters = {}
    for w in solution:
        letters_in_word = {}
        for c in w:
            if c not in letters_in_word:
                letters_in_word[c] = 1
            else:
                letters_in_word[c] += 1

        for k, v in letters_in_word.items():
            if k not in letters:
                letters[k] = v
            else:
                letters[k] = max(letters[k], v)
    return (sum(letters.values()) / 5)
			#we start to find the seed whose words give us a score of <4.2> or lower,
			#ideally anything below 5 should be good

sc = 10
#seed = 0
seed = 13263600		#for the sake of getting to the seed faster
while (sc > 4.2):	#score required to be low for the sake of making it easier afterwards
    seed += 1
    s = gen_solution(seed)
    sc = compute_score(s)
    for w in s:
        se = list(set(w))
        if len(se) != len(w):
            sc = 10
            break
print("Score (ideally under 5):",sc)
print("Found seed: ",seed)
print("The 32 solutions wordlist: ",s)

			#then, we start counting the letters
letters = {}
for w in s:
    letters_in_word = {}
    for c in w:
        if c not in letters_in_word:
            letters_in_word[c] = 1
        else:
            letters_in_word[c] += 1

    for k, v in letters_in_word.items():
        if k not in letters:
            letters[k] = v
        else:
            letters[k] = max(letters[k], v)

			#now we find the solution words (that are NOT exact words found above)
			# ... with *some* workarounds for the seed we found
def find_words(lett, sol):
    if len(sol) == 5:
        execute_order_66(sol)
        exit(0)

    target = min(len(lett.keys()), 5)
    for w in valid:
        if w in sol:
            continue
        if w in s:
            continue

        if 'l' in w and 'w' in w and w.index('l') < w.index('w'):
            continue

        if len(set(w)) != len(w):
            continue

        cnt = 0
        for c in w:
            if c in lett:
                cnt += 1
        if cnt != target:
            continue

        sol.append(w)
        for c in w:
            if c in lett:
                lett.pop(c)

        find_words(lett, sol)

        assert(w == sol[-1])
        sol.remove(w)
        for c in w:
            lett[c] = 1

#print("".join(letters.keys()))

			#and now we just deploy the solution and get our flag!
def execute_order_66(solution):
	print("The 5-word solution: ",solution)
	target = remote("the-thirty-twodle-challenge.chal.hackthe.vote", 1337)
	target.sendline(bytes(hex(seed),'utf-8'))
	for word in solution:
		target.sendline(bytes(word,'utf-8'))
	target.recvuntil(b"challenge!\n")
	target.sendline(b'cat flag')
	print(target.recvall(0.2))
	target.close

find_words(letters, [])
```
