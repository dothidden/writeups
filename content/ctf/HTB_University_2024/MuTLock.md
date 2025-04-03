---
title: MuTLock
date: 2024-12-22T12:53:45+02:00
description: Writeup for MuTLock [HTB University 2024]
type: writeup
author: GabrielMajeri
tags:
  - crypto
draft: false
---

---

## Challenge Description

> The Frontier Board encrypts their secrets using a system tied to the ever-shifting cosmic cycles, woven with patterns that seem random to the untrained eye. To outwit their defenses, you'll need to decipher the hidden rhythm of time and unlock the truth buried in their encoded transmissions. Can you crack the code and unveil their schemes?

We are given the Python source code for a custom cipher used to encode the secret flag, as well as an `output.txt` file with the encrypted output.

## Initial Analysis

Looking at the source code, we can easily tell that this is a pretty weak and broken cipher. The way it works is as follows:
1. Split the flag into two halves.
2. For each half:
    1. Generate two integers, a _key seed_ and an _XOR key_ (which will be used in the final encryption step). They are generated based on the parity of the current timestamp (in seconds).
    2. Expand the key seed into a string of random letters, of length 16 (using Python's `random.seed` and `random.choice`).
    3. Perform a polyalphabetic substitution on the plaintext, using the generated key. The result is then base64-encoded.
    4. XOR the resulting bytes with the XOR key.
    5. Store the resulting ciphertext in an array, **wait for one second** and then encrypt the other half of the flag.
3. Write the two encoded halves of the flag into a text file, as hex.

This cipher is symmetric and reversible, _if_ we were to know the values of the key seed and the XOR key. The decryption works by applying the steps described above backwardly (i.e. read the encrypted data, XOR it with the key, perform the [polyalphabetic substitution](https://en.wikipedia.org/wiki/Polyalphabetic_cipher) in reverse). Since we don't have any way of determining what the values of the keys are (since we don't have any information on **when** the encryption code was run), we'll have to guess them. Fortunately, the [key space](https://en.wikipedia.org/wiki/Key_size) isn't very large:
* For even timestamps, the key seed is a random integer in the range $[1, 1000]$ and the XOR key is the constant $42$.
* For odd timestamps, the key seed is the constant $42$ and the XOR key is a random integer in the range $[1, 255]$.

## Solution

We are going to perform what is basically a [known-plaintext attack](https://en.wikipedia.org/wiki/Known-plaintext_attack), since we are certain that the decrypted flag will start with the string `HTB{`.

The code used to perform the actual brute force attack is available below:

```python
import random
import string
import base64


# I've hardcoded the values of the ciphertext here,
# instead of reading it from the input file
flag_first_half = bytes.fromhex('00071134013a3c1c00423f330704382d00420d331d04383d00420134044f383300062f34063a383e0006443310043839004315340314382f004240331c043815004358331b4f3830')
flag_second_half = bytes.fromhex('5d1f486e4d49611a5d1e7e6e4067611f5d5b196e5b5961405d1f7a695b12614e5d58506e4212654b5d5b196e4067611d5d5b726e4649657c5d5872695f12654d5d5b4c6e4749611b')

# We'll mount a known-plaintext brute force attack against this weak cipher
flag_start = 'HTB{'


## This function is taken from the original source code
def generate_key(seed, length=16):
    random.seed(seed)
    key = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
    return key

## This function is the `polyalphabetic_encrypt` function, but written in reverse
def polyalphabetic_decrypt(ciphertext, key):
    key_length = len(key)
    plaintext = []
    for i, char in enumerate(ciphertext):
        key_char = key[i % key_length]
        decrypted_char = chr((ord(char) - ord(key_char)) % 256)
        plaintext.append(decrypted_char)
    plaintext = ''.join(plaintext)
    return plaintext

## This is mostly the same as the original,
## but we're given the ciphertext as input (not the plain text)
def xor_cipher(ciphertext: bytes, key: int):
    return ''.join(chr(c ^ key) for c in ciphertext)

## This function performs the encryption steps in reverse
def perform_decryption(encrypted_bytes: bytes, key_seed: int, xor_key: int):
    # Reverse the XOR cipher
    decrypted = xor_cipher(encrypted_bytes, xor_key)

    # Reverse the base64-encoding
    try:
        decrypted_half = base64.b64decode(decrypted).decode()
    except:
        return ''

    # Generate a key based on the seed
    key = generate_key(key_seed)

    # Perform the decryption
    return polyalphabetic_decrypt(decrypted_half, key)

## Brute force the cipher knowing that the decrypted message
## should start with a certain sequence of characters
def try_keys(encrypted_bytes: bytes, known_plaintext: str, key_seed: int, xor_key: int):
    decrypted = perform_decryption(encrypted_bytes, key_seed, xor_key)

    if decrypted.startswith(known_plaintext):
        print(decrypted)
        return True
    else:
        return False


## Decrypt the first half of the flag
print("Attempting to crack first half of the flag...")
for i in range(1, 255):
    key_seed = 42
    xor_key = i
    if try_keys(flag_first_half, flag_start, key_seed, xor_key):
        print("Found correct seed and XOR key!")
        print("key_seed =", key_seed)
        print("xor_key =", xor_key)

print("Attempting to crack second half of the flag...")
for i in range(1, 1000):
    key_seed = i
    xor_key = 42
    if try_keys(flag_second_half, 'ion', key_seed, xor_key):
        print("Found correct seed and XOR key!")
        print("key_seed =", key_seed)
        print("xor_key =", xor_key)
```

Output:

```text
Attempting to crack first half of the flag...
HTB{timestamp_based_encrypt
Found correct seed and XOR key!
key_seed = 42
xor_key = 119
Attempting to crack second half of the flag...
ion_is_so_secure_i_promise}
Found correct seed and XOR key!
key_seed = 433
xor_key = 42
```

**Note**: When I first wrote the code, I didn't know whether the first half of the flag was encrypted using $42$ as the key seed and a random XOR key in the range $[1, 255]$, or if the key seed was a random integer in the range $[1, 1000]$ and the XOR key was 42. I had to switch around the last two `for` ranges in the code above before the encryption worked.

Also, note that after I managed to decrypt the first half of the flag starting with the known plaintext `HTB{`, I've noticed that it ended with the word `encrypt`, so I guessed the second half must start with the known plaintext `ion`.

### Flag

`HTB{timestamp_based_encryption_is_so_secure_i_promise}`
