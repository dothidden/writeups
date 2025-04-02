---
title: StangeBytes
date: 2023-06-05
tags:
  - misc
author: H0N3YP0T
---

___

> Disclaimer: This challenge was resolved after the end of the CTF, so it doesn't count for the final ranking.

## Description of the challenge

I got hacked by a ransomware, and it encrypted some important files. Some crypto analyst told me they were encrypted
using AES CBC, but there is something strange in them which can probably be exploited. I don't have enough money to give
the job to proper crypto analysts, could you decrypt them for me please?

## Solution

This challenge provided a zip file containing 250 encrypted files with random names (names of the files were not part of
the challenge).
The description of the challenge tells us many of useful information:

* The encryption algorithm is AES CBC.
* There is something strange inside the files that we could exploit.
* The title of the challenge is "StrangeBytes", we can assume that the strange thing is related to the bytes of the
  files.

Let's open a random file with a hex editor and see what we can find.
The first we can notice is that there is the following char sequence: `:CBC`, let's open
another file and see if we can find the same sequence.

![hexdump of the first file](/images/dantectf_2023/strangeBytes1.png)
![hexdump of another random file](/images/dantectf_2023/strangeBytes2.png)

We can see that the sequence `:CBC` is present in all the files, so it's probably related to the flag. Furthermore, we
can see that not only the
`:CBC` is present in all the files but also the following pattern:

```
\...o.....m..(g ...4c...U.M..3..:..%yD..Ob...{..\:CBC
``` 

which has the following hex code:

```
5c f3 c0 f0 6f fb 02 fe a3 9b 6d ab de 28 67 20 9e 96 86 34 63 a4 b7 8b 55 aa 4d 88 b0 33 81 1e 3a ba 1b 25 79 44 af df 4f 62 0b 0f e4 7b a1 b8 5c 3a 43 42 43
```

This pattern has a length of 53 bytes in total and if we remove the `:CBC` pattern we got a length of 49 bytes.
If we assume that the first 32 bytes are the AES 256 key, the next 17 bytes are the IV. We can now try to decrypt the
files after removing the pattern using the following python script:

```python
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def hex_edit_file(directory):
    if not "edited" in os.listdir(directory):
        os.mkdir(directory + "/edited")
    # Hex pattern to remove
    hex_pattern = bytes.fromhex(
        "5cf3c0f06ffb02fea39b6dabde2867209e96863463a4b78b55aa4d88b033811e3aba1b257944afdf4f620b0fe47ba1b85c3a434243")
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        if os.path.isfile(file_path) and '.ipynb' not in file_path:
            with open(file_path, "rb") as file:
                content = file.read()
                # remove the pattern
                edited_content = content.replace(hex_pattern, b'')
                # create a new file without the pattern in edited dir
                with open('./edited/' + file_path[2:] + '.enc', 'wb') as edited_file:
                    edited_file.write(edited_content)
                    edited_file.close()


def decrypt_file(file):
    for filename in os.listdir(directory + '/edited'):
        if not 'DS_Store' in filename:
            with open(directory + '/edited/' + filename, 'rb') as file:
                ciphertext = file.read()
                cipher = AES.new(key, AES.MODE_CBC, iv)
                # Decrypt the ciphertext
                decrypted_data = cipher.decrypt(ciphertext)
                # Write the decrypted data to a new file in the ./decrypted_files directory
                if not "decrypted" in os.listdir(directory):
                    os.mkdir(directory + "/decrypted")
                decrypted_file_path = directory + 'decrypted/' + filename[:-4] + '.dec'
                with open(decrypted_file_path, 'wb') as file:
                    file.write(decrypted_data)


def find_flag(directory_path):
    for filename in os.listdir(directory + '/decrypted'):
        with open(directory + '/decrypted/' + filename, 'rb') as file:
            content = file.read()
            if b'DANTE' in content:
                print(content)


# Provide the directory path
directory_path = "."
key = bytes.fromhex(
    "5cf3c0f06ffb02fea39b6dabde2867209e96863463a4b78b55aa4d88b033811e3aba1b257944afdf4f620b0fe47ba1b85c3a434243"[0:64])
iv = bytes.fromhex(
    "5cf3c0f06ffb02fea39b6dabde2867209e96863463a4b78b55aa4d88b033811e3aba1b257944afdf4f620b0fe47ba1b85c3a434243"[64:96])
hex_edit_file(directory_path)
decrypt_file(directory_path)
find_flag(directory_path)


```

The `find_flag` function will print the flag if we find the pattern `DANTE` into a decrypted file.
The final result will be the following where we can see the
flag `DANTE{AHh9HhH0hH_ThAat_RAnsomware_maDe_m3_SaD_FFFFAAABBBBDDDD67}`:

```
b'\xe6\xc3S(H\xa89\xf5a"O\x9b\xdc\xae]\xbcJptXFiXMNqAJXFurPPgPYMSWgFRsLbFkdwQXLpBNQDSsJYRqdvYGsRrQxELqXxYjjyAdAWQZijTTPILOBmMJefZooyVmVvhoRoLPOhglTpBrnVFfAQyxrYKcErXIGvoeIMbwSoPwTImkwoByqkaSLhPmhraomgIqkynvRzyGzMBEHfYVxyKQRRQWUqIGnnlmCLICQDlwUeklDqQkHyfTzsGYttyRZvCSPJDANTE{AHh9HhH0hH_ThAat_RAnsomware_maDe_m3_SaD_FFFFAAABBBBDDDD67}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
```