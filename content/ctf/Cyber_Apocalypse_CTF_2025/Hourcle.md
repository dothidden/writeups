---
title: Hourcle
date: 2025-03-27T18:33:57+03:00
description: Writeup for Hourcle [HTB Cyber Apocalypse CTF 2025]
author: h3pha
tags:
- crypto
draft: false
---
___

## Challenge Description

> A powerful enchantment meant to obscure has been carelessly repurposed, revealing more than it conceals. A fool sought security, yet created an opening for those who dare to peer beyond the illusion. Can you exploit the very spell meant to guard its secrets and twist it to your will?

## Intuition

We are given this file (`server.py`):
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, string, random, re

KEY = os.urandom(32)

password = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])

def encrypt_creds(user):
    padded = pad((user + password).encode(), 16)
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    ciphertext = cipher.decrypt(padded)
    return ciphertext

def admin_login(pwd):
    return pwd == password


def show_menu():
    return input('''
=========================================
||                                     ||
||   🏰 Eldoria's Shadow Keep 🏰       ||
||                                     ||
||  [1] Seal Your Name in the Archives ||
||  [2] Enter the Forbidden Sanctum    ||
||  [3] Depart from the Realm          ||
||                                     ||
=========================================

Choose your path, traveler :: ''')

def main():
    while True:
        ch = show_menu()
        print()
        if ch == '1':
            username = input('[+] Speak thy name, so it may be sealed in the archives :: ')
            pattern = re.compile(r"^\w{16,}$")
            if not pattern.match(username):
                print('[-] The ancient scribes only accept proper names-no forbidden symbols allowed.')
                continue
            encrypted_creds = encrypt_creds(username)
            print(f'[+] Thy credentials have been sealed in the encrypted scrolls: {encrypted_creds.hex()}')
        elif ch == '2':
            pwd = input('[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: ')
            if admin_login(pwd):
                print(f"[+] The gates open before you, Keeper of Secrets! {open('flag.txt').read()}")
                exit()
            else:
                print('[-] You salt not pass!')
        elif ch == '3':
            print('[+] Thou turnest away from the shadows and fade into the mist...')
            exit()
        else:
            print('[-] The oracle does not understand thy words.')

if __name__ == '__main__':
    main()
```

To get the flag we need the secret password that the server generates. We can provide a username and the server will append the password to it, encrypt it and return the ciphertext.

The first thing that I observed is that the server uses `AES` in `CBC` mode, but instead of encrypting the text, it decrypts it and returns the result.

I have solved a similar CTF challenge in which I explained how to attack a system like this [here](https://dothidden.xyz/kalmarctf_2025/very_serious_cryptography/). Actually I used the same script to solve this challenge, I just adapted it for this situation.

## Solution

> Note: the script takes a while to run on a remote target.

Solver:
```python
from pwn import *

charset = string.ascii_letters+string.digits
def send_input_list(p, input_list):
    output_list = []
    for i in input_list:
        p.readuntil(b":: ")
        p.sendline(b"1")
        p.readuntil(b":: ")
        p.sendline(i.encode())
        p.readuntil(b"lls: ")
        output = bytes.fromhex(p.recvline()[:-1].decode())
        output_list.append(output)
    return output_list

password = ""
input_size = 16 + 16 + 15 
# 16 is the minimum allowed, and we add 15 to make sure that the first character of the password
# is at the end of the block, I also added one more block because the length of the passowrd is 20

# p = process(["python", "server.py"])
p = remote("94.237.55.91", 38990)

while len(password) != 20:
    try:
	    # ensure that the character we are searching is at the end of the block
        padding = "_" * (input_size - len(password))
        # this is where the original flag is encrypted
        original = send_input_list(p, [padding])[0]
        # create all possible variants of the characters withing the flag
        brute_input = [padding + password + c for c in charset]
        # send the variants, and receive all encryptions
        brute_output = send_input_list(p, brute_input)
        # this is the position of the end of the block
        character_position = len(padding + password) + 1 
        for i in range(len(brute_output)):
            if brute_output[i][32:character_position] == original[32:character_position]:
                password += charset[i]
        print(password)
            
    except EOFError:
        p.close()
        p = remote("94.237.55.91", 38990)
        # p = process(["python", "server.py"])
        password = ""

p.sendline(b"2")
p.sendline(password)
p.interactive()
```


### Flag

`HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_6f5aea60aea8dee076ad6ff61d768d05}`

