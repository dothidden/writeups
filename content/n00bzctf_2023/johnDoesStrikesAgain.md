---
title: John Does Strikes Again
date: 2023-06-10
tags:
  - osint
---

___

## Description

John Doe has escaped our high secruity[^1] prison again! We managed to intercept an xor key that he uses to send
encrypted
messages to people! Your aim is to find classified information on his top secret website! Start with the encrypted
message -`b'\x13\x00\x1d-A*!\x00Q\x16R\x02\x12\x07\n\x1b>\x0e\x06\x1a~O-D CU\t\x0e\x06 E2\n\x17bA#\x0b\t>O\x11\x011O\tH*\x1b\x10-\x08\x00)E\x02\nMck~)\x07"\x01H*+\n_\x01\x00\x00\x00c\n\x00!\x12V\r\x1d4A\x19\x16\x0b"O!N(\x00\x13Dy\x02\x000\x08\rn\x16\x19E\x16,\x0fS\x17H+\x1c\x03N)\nEU1\x0e\x01c\x10\x1b+\x16\x02\x0c\x1d-A\x11\x15\r8\x16H\x0f#\x0e\x0cOx'`
and the secret key -`YouCanNeverCatchJohnDoe!`We also intercepted the name of his
account -`31zdugxvkayexc4hzqhixxcfxb4y`

Author: NoobMaster

## Solution

Let's start by decrypting the message provided with the key `YouCanNeverCatchJohnDoe!`. The message is obvisouly in
bytes, so we need to
convert it to string and apply the XOR decryption by using the key as suggested in the challenge description.

```python

import itertools

key = "YouCanNeverCatchJohnDoe!"
message = b'\x13\x00\x1d-A*!\x00Q\x16R\x02\x12\x07\n\x1b>\x0e\x06\x1a~O-D CU\t\x0e\x06 E2\n\x17bA#\x0b\t>O\x11\x011O\tH*\x1b\x10-\x08\x00)E\x02\nMck~)\x07"\x01H*+\n_\x01\x00\x00\x00c\n\x00!\x12V\r\x1d4A\x19\x16\x0b"O!N(\x00\x13Dy\x02\x000\x08\rn\x16\x19E\x16,\x0fS\x17H+\x1c\x03N)\nEU1\x0e\x01c\x10\x1b+\x16\x02\x0c\x1d-A\x11\x15\r8\x16H\x0f#\x0e\x0cOx'

decrypted_message = bytearray([m ^ k for (m, k) in zip(message, itertools.cycle(key.encode()))])

print(decrypted_message.decode())

```

The output is the following: `John Doe: You know how much I love music so don't ask me that question every again! `
This output is a clue to find the name of the account of John Doe on Spotify or another music website. So let's go to
Spotify but can we find the name of the account of John Doe? No, we can't. So let's go back to the challenge description
and see if we can find something else. We notice that we did not use this information `31zdugxvkayexc4hzqhixxcfxb4y`.
It does not look like any cipher I know and after some reflection I thought it could be the Spotify URL and actually it
is.

> https://open.spotify.com/user/31zdugxvkayexc4hzqhixxcfxb4y

There are not a lot of information on the Spotify account of John Doe, but we can see the following empty playlist:

![John Doe playlist](/images/n00bzctf_2023/spotify.png)

Let's decrypt the message of the playlist with the same key as before[^2].

```python

message2 = b'\x10O\x1d"\x17\x0bn\x04\x18E\x13.\x00\x0e\n\x06-O\x18\x1c+\t\x0cM<O\x05*\x02\x1a;\x17\x13E\x16,\x0fS\x17H3\x00\x1dN0\x07\x0cO2P'

decrypted_message2 = bytearray([m ^ k for (m, k) in zip(message2, itertools.cycle(key.encode()))])

print(decrypted_message2.decode())

# OUTPUT: I have an amazing profile picture don't you think?

```

After decryption, the playlist description suggest to take a look at the profile picture of the playlist which is the
Discord logo.
I lost so much time on this part because I did not know what to do with this image and I tried to look for some
steganography
inside the picture. But actually the solution is to look at the Discord server of the `N00bz CTF` because John Doe
joined
the server.

![John Doe Discord](/images/n00bzctf_2023/john_discord.png)

The Discord profile of John has the following description:
`Busy doing n00bzCTF! Check out my profile!`
Maybe he is also doing the CTF ? Let's check if we find something on the N00bz CTF website.

![John Doe CTF](/images/n00bzctf_2023/john_ctf.png)

> https://ctf.n00bzunit3d.xyz/users/110

Got it ! We can see the following team name:
`\r\x07\x1c-\nN\x19\x04\x0fE0"\x02\x1f7\x00#\x01\x03N\x13\x0e\x1c\x01`
Let's decrypt it again:

```python

message3 = b'\r\x07\x1c-\nN\x19\x04\x0fE0"\x02\x1f7\x00#\x01\x03N\x13\x0e\x1c\x01'

decrypted_message3 = bytearray([m ^ k for (m, k) in zip(message3, itertools.cycle(key.encode()))])

print(decrypted_message3.decode())

# OUTPUT: Think way back

```

The message `Think way back` is easy to understand for experimented OSINTERS (I don't have any idea if this word
exists). We have to look on the Wayback machine:

> https://web.archive.org/web/20220715000000*/https://ctf.n00bzunit3d.xyz/teams

We do not find anything so let's take a look at `Click here to search for all archived pages`, then if we go to page
number 2 we find the team of John Doe with a linked
website.

> https://ctf.n00bzunit3d.xyz/teams?page=2

![John Doe team](/images/n00bzctf_2023/john_secret.png)

> https://ctf.n00bzunit3d.xyz/t0ps3cr3t

The website seems empty but if you `CTRL + a` on the page you will see the hidden
string `7_E!\x1b\x15 U)U\x1cp>\x17W\x06\x15\\\x1b\rp\x1fV~\x14=[sT_\x00RZ:\x1cs\x15+P\x1ey\x017$t'+~\x1d_Fb\x1c`

Let's decode it again:

```python

message4 = b"7_E!\x1b\x15 U)U\x1cp>\x17W\x06\x15\\\x1b\rp\x1fV~\x14=[sT_\x00RZ:\x1cs\x15+P\x1ey\x017$t'+~\x1d_Fb\x1c"

decrypted_message4 = bytearray([m ^ k for (m, k) in zip(message4, itertools.cycle(key.encode()))])

print(decrypted_message4.decode())

# OUTPUT: n00bz{n0_0n3_c4n_3sc4p3_MR.051N7,_n0t_3v3n_J0HN_D03!}

```

**BINGO** We finally got the flag `n00bz{n0_0n3_c4n_3sc4p3_MR.051N7,_n0t_3v3n_J0HN_D03!}`.

[^1]: The typo is part of the original challenge description :).
[^2]: When we did the challenge the playlist description was still encrypted, and we had to decrypt is with the same
method used previously for the first message.

