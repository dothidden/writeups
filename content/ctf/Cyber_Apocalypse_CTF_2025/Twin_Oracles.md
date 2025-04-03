---
title: Twin Oracles
date: 2025-03-27T19:00:25+03:00
description: Writeup for Twin Oracles [HTB Cyber Apocalypse CTF 2025]
type: writeup
author: h3pha 
tags:
- crypto
draft: false
---
___

## Challenge Description

> A powerful artifact—meant to generate chaos yet uphold order—has revealed its flaw. A misplaced rune, an unintended pattern, an oversight in the design. The one who understands the rhythm of its magic may predict its every move and use it against its creators. Will you be the one to claim its secrets?

## Intuition

We are given this file (`server.py`):

```python
from Crypto.Util.number import *

FLAG = bytes_to_long(open('flag.txt', 'rb').read())

MENU = '''
The Seers await your command:

1. Request Knowledge from the Elders
2. Consult the Seers of the Obsidian Tower
3. Depart from the Sanctum
'''

class ChaosRelic:
    def __init__(self):
        self.p = getPrime(8)
        self.q = getPrime(8)
        self.M = self.p * self.q
        self.x0 = getPrime(15)
        self.x = self.x0
        print(f"The Ancient Chaos Relic fuels the Seers' wisdom. Behold its power: M = {self.M}")
        
    def next_state(self):
        self.x = pow(self.x, 2, self.M)
        
    def get_bit(self):
        self.next_state()
        return self.extract_bit_from_state()
    
    def extract_bit_from_state(self):
        return self.x % 2


class ObsidianSeers:
    def __init__(self, relic):
        self.relic = relic
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.n = self.p * self.q
        self.e = 65537 
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)

    def sacred_encryption(self, m):
        return pow(m, self.e, self.n)

    def sacred_decryption(self, c):
        return pow(c, self.d, self.n)

    def HighSeerVision(self, c):
        return int(self.sacred_decryption(c) > self.n//2)
    
    def FateSeerWhisper(self, c):
        return self.sacred_decryption(c) % 2
    
    def divine_prophecy(self, a_bit, c):
        return self.FateSeerWhisper(c) if a_bit == 0 else self.HighSeerVision(c)
        
    def consult_seers(self, c):
        next_bit = self.relic.get_bit()
        response = self.divine_prophecy(next_bit, c)
        return response
    


def main():
    print("You stand before the Seers of the Obsidian Tower. They alone hold the knowledge you seek.")
    print("But be warned—no force in Eldoria can break their will, and their wisdom is safeguarded by the power of the Chaos Relic.")
    my_relic = ChaosRelic()
    my_seers = ObsidianSeers(my_relic)
    counter = 0

    while counter <= 1500:
        print(MENU)
        option = input('> ')

        if option == '1':
            print(f"The Elders grant you insight: n = {my_seers.n}")
            print(f"The ancient script has been sealed: {my_seers.sacred_encryption(FLAG)}")
        elif option == '2':
            ciphertext = int(input("Submit your encrypted scripture for the Seers' judgement: "), 16)
            print(f'The Seers whisper their answer: {my_seers.consult_seers(ciphertext)}')
        elif option == '3':
            print("The doors of the Sanctum close behind you. The Seers watch in silence as you depart.")
            break
        else:
            print("The Seers do not acknowledge your request.")
            continue

        counter += 1

    print("The stars fade, and the Seers retreat into silence. They shall speak no more tonight.")

if __name__ == '__main__':
    main()
```

The server outpus the encrypted flag (encrypted with RSA) and the modulus `n`, we also know the public exponent `e`.

We are given 2 oracles. One that gives us the last bit of a decrypted ciphertext we provide, and one that tells us whether the decrypted ciphertext is larger that `n//2`.

The problem is that these 2 oracles are called randomly using `ChaosRelic`.

This means we have to do 2 things to get the flag: 1. break the pseudo random generator (PRG) and 2. decrypt the flag using the oracles.

##### Breaking ChaosRelic

We can notice that ChaosRelic is a LSFR-like PRG, and that it uses a prime of 15 bits, which is very small, to generate a random sequence. So we can bruteforce all sequences for all prime numbers of 15 bits and see the one that matches with what we've got on the server:

```python
known_sequence = get_first_sequence()
x0 = 0
for i in range(1, 2**15):
    x = i
    if not isPrime(x):
        continue
    sequence = []
    for _ in range(sequence_len): 
        x = pow(x, 2, M)
        sequence.append(0 if x % 2 == 1 else 1)
    
    
    if sequence == known_sequence:
        x0 = i  
        print(f"Recovered x0: {x0}")
        break
```

Now the problem is: how do I know what function was called for each bit received?
I found that I can send `1` to the server and it will return 0 if `HighSeerVision()` got called and 1 for `FateSeerWhisper()`.

##### Breaking encryption

I read about the LSB Oracle Attack (find in refrences), and by knowing the last bit of the decryption we can implement a binary-search of the plaintext.

But what about the other oracle? well apparently the other oracle is similar to the first one, and the difference is explained in the solution script.

## Solution

> Note: The solution messes up the last byte, don't know why, but it doesn't matter since we know it's `}`

Solver:
```python
from Crypto.Util.number import *
from sympy import factorint
from pwn import *

# proc = process(["python", "server.py"])
proc = remote("83.136.251.68", 53323)

def oracle_query(ct):
    proc.sendline(b"2")
    proc.readuntil(b"nt: ")
    proc.sendline(long_to_bytes(ct).hex().encode())
    proc.readuntil(b"er: ")
    return int(proc.readline()[:-1])

def isPrime(n, k=5):  # Miller-Rabin primality test
    from random import randint
    if n < 2: return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0: return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for _ in range(k):
        x = pow(randint(2, n - 1), d, n)
        if x == 1 or x == n - 1: continue
        for r in range(1, s):
            x = (x * x) % n
            if x == 1: return False
            if x == n - 1: break
        else: return False
    return True

# Get data
proc.readuntil(b"M = ")
e = 65537
M = int(proc.readline()[:-1])

# get encrypted flag and n
proc.sendline(b"1")
proc.readuntil(b"n = ")
n = int(proc.readline()[:-1])
proc.readuntil(b"led: ")
flag = int(proc.readline()[:-1])

# Break ChaosRelic
sequence_len = 30

def get_first_sequence(): # gets the first 30 responses from server
    sequence = []
    for i in range(sequence_len):
        sequence.append(oracle_query(1))
    return sequence

def verify_sequence(x): # verifies if we predicted correctly 10 responses from server
    for i in range(10):
        x = pow(x, 2, M)
        c = 0 if x % 2 == 1 else 1
        if c != oracle_query(1):
            return False
    return True


known_sequence = get_first_sequence()
x0 = 0
# bruteforce x0
for i in range(1, 2**15):
    x = i
    if not isPrime(x):
        continue
    sequence = []
    for _ in range(sequence_len): 
        x = pow(x, 2, M)
        sequence.append(0 if x % 2 == 1 else 1)
    
    
    if sequence == known_sequence:
        x0 = i  
        print(f"Recovered x0: {x0}")
        break

# since we asked the server 30 times we need to update our PRG
for _ in range(sequence_len):
    x0 = pow(x0, 2, M)

if verify_sequence(x0):
    print("Verified!")
else:
    print("Nope")

# update PRG after verification
for _ in range(10):
    x0 = pow(x0, 2, M)


# Break encryption
low, high = 0, n  # boundaries for binary search
is_LSB = True # prediction variable (True) if FateSeerWhisper() gets called
for i in range(1, 1450):
    print(i) # progress tracker
    # predicting next call
    x0 = pow(x0, 2, M)
    if x0 % 2 == 0:
        is_LSB = True
    else:
        is_LSB = False
    
    # if is_LSB is true
    # ct1 = flag * 2^ei
    # else
    # ct2 = flag * 2^e(i-1)
    # HighSeerVision() works the same for ct2 as FateSeerWhisper() for ct1
    ct = (flag * pow(2, e * (i - (0 if is_LSB else 1)), n)) % n
    
    response = oracle_query(ct)
    if response == 0:
        high = (low + high) // 2
    else:
        low = (low + high) // 2

    if high == low:
        break

print(f"Recovered plaintext: {long_to_bytes(low)}")
```


### Flag

`HTB{1_l0v3_us1ng_RS4_0r4cl3s___3v3n_4_s1ngl3_b1t_1s_3n0ugh_t0_g3t_m3_t0_3ld0r14!_682d527b98516eb161539c96b4b47ea8}`

## References

[LSB Oracle Attack](https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-LSBit-Oracle/README.md)
