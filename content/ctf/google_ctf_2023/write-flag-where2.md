---
title: Write-Flag-Where2
date: 2023-06-30T13:11:29+03:00
description: Writeup for Write-Flag-Where2 [Google Ctf 2023]
author: sunbather
tags:
- pwn
draft: false
---

## Challenge Description

This challenge is not a classical pwn
In order to solve it will take skills of your own
An excellent primitive you get for free
Choose an address and I will write what I see
But the author is cursed or perhaps it's just out of spite
For the flag that you seek is the thing you will write
ASLR isn't the challenge so I'll tell you what
I'll give you my mappings so that you'll have a shot.

(this is the description from the first challenge, but it describes well what we have to do)

## Solution

Basically we are given the following main function, that prints the mapping for the current process and then we're given the possibility to write the flag to any address.

```c
undefined8 main(void)
{
  int iVar1;
  ssize_t sVar2;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  uint local_2c;
  __off64_t local_28;
  int local_20;
  undefined4 local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  
  local_c = open("/proc/self/maps",0);
  read(local_c,maps,0x1000);
  close(local_c);
  local_10 = open("./flag.txt",0);
  if (local_10 == -1) {
    puts("flag.txt not found");
  }
  else {
    sVar2 = read(local_10,flag,0x80);
    if (0 < sVar2) {
      close(local_10);
      local_14 = dup2(1,10);
      local_18 = open("/dev/null",2);
      dup2(local_18,0x10);
      dup2(local_18,0x11);
      dup2(local_18,0x12);
      close(local_18);
      alarm(0);
      dprintf(local_14,
              "Was that too easy? Let\'s make it tough\nIt\'s the challenge from before, but I\'ve r emoved all the fluff\n"
             );
      dprintf(local_14,"%s\n\n",maps);
      while( true ) {
        local_78 = 0;
        local_70 = 0;
        local_68 = 0;
        local_60 = 0;
        local_58 = 0;
        local_50 = 0;
        local_48 = 0;
        local_40 = 0;
        sVar2 = read(local_14,&local_78,0x40);
        local_1c = (undefined4)sVar2;
        iVar1 = __isoc99_sscanf(&local_78,"0x%llx %u",&local_28,&local_2c);
        if ((iVar1 != 2) || (0x7f < local_2c)) break;
        local_20 = open("/proc/self/mem",2);
        lseek64(local_20,local_28,0);
        write(local_20,flag,(ulong)local_2c);
        close(local_20);
      }
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    puts("flag.txt empty");
  }
  return 1;
}
```
The solution to the first challenge was to simply write the flag inside the string used in the ``puts`` to print it out. This time, nothing gets printed. So the next idea is to find a jump that we could modify to go somewhere up the ``.text`` section, possibly hitting the original ``dprintf`` of the ``maps``. After looking for some time through the assembly and trying some jumps, we find this:

```asm
        00101428 8b 45 e8        MOV        EAX,dword ptr [RBP + local_20]
        0010142b 89 c7           MOV        EDI,EAX
        0010142d e8 4e fc        CALL       libc.so.6::close                                 int close(int __fd)
                 ff ff
        00101432 e9 1d ff        JMP        LAB_00101354
                 ff ff
                             LAB_00101437                                    XREF[1]:     001013d0(j)  
        00101437 90              NOP
        00101438 eb 01           JMP        LAB_0010143b
                             LAB_0010143a                                    XREF[1]:     001013d8(j)  
        0010143a 90              NOP
```
The first jump, at ``00101432`` is used to jump back to the beginning of the while loop. We can use it to maybe jump even higher. We try to overwrite the ``1d`` byte (which is the relative offset of the jump) with the first byte of the flag, which is greater (``C == 0x43``). Sadly, this is not useful, it will jump even lower, because the offset is actually negative (see the ``ff`` bytes after, signifying it's a negative value). So we would have to get a _lower_ value than ``1d``, which sucks because ASCII letters start a lot higher. But, the flag _should_ end with null bytes, so maybe we can overwrite the beginning of the flag with a null byte and then use that to overwrite the jump offset to null. Then, we just write the flag to ``maps`` and re-print it with ``dprintf``. There is an issue with this though, now the flag won't print because it has a null byte in the beginning. So we have to do it in another order:

1. Write the flag to ``maps``
2. Write last byte of flag to first byte of flag (the null byte)
3. Write the first byte of flag (null) to the ``1d`` byte.
4. ???
5. Profit

This will jump higher and print the ``maps`` variable again, which now contains the flag. Great success!
