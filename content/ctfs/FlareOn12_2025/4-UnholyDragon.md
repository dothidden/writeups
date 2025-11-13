---
title: 4.UnholyDragon
type: writeup
date: 2025-10-01T18:42:50+02:00
description: Writeup for UnholyDragon [FlareOn 2025]
author: PineBel
tags:
- rev
draft: false
---

# Challenge 4 (UnholyDragon)

## Cheese
For this challenge we get a Windows executable (`UnholyDragon-150.exe`).  
The first thing we can observe is that the header is malformed (the first byte is incorrect).  
This is easily fixed in a hex editor (I used HxD) by changing the first byte to `0x4D` (`M`).  
We can also use `Detect It Easy` to analyze the binary.

After patching the executable, I decided to do some dynamic analysis with Procmon first.

Strangely, when running it, three other files were created: `UnholyDragon-151.exe` -> `UnholyDragon-154.exe`.  
So I renamed the executable to something else (`a.exe`) and ran it again. This time it generated `UnholyDragon-1.exe` up to `UnholyDragon-150.exe`.  
I patched the 150th copy and then ran `UnholyDragon-150.exe` again, and I got the flag.

## Understanding

After the competition finished, I decided to try to understand the challenge by ~following the official writeup.  
The idea was to first check how the generated binaries are different, so I did this with the following command:

![ch4-byte_differences_from_150_to_154](/images/FlareOn12_2025/ch4-byte_differences_from_150_to_154.png)

If we compare the original file with the other four copies, it seems that the file is cloned: one byte is changed (at a random offset), and then the new binary executes and creates another clone with another changed byte.

Now the interesting part is that we received a corrupted binary, which had the wrong signature.  
What if `UnholyDragon-150.exe` was generated from `UnholyDragon-149.exe`? We can just copy the patched binary and rename it to `UnholyDragon-149` and test it. This indeed works.

Since `UnholyDragon-150.exe` always has a damaged signature, it means that the offsets that change in the binary are generated in a predictable way.

#### Reversing

I decided to RE the binary to find the logic where/how the bytes were modified.

One cool way to get a starting point in RE is by using API Monitor.  
I read about this in the following writeup: https://gist.github.com/superfashi/563425ee96d505c0263373230335e41a

After that, I checked what API calls were made by the binary.

![ch4-api_monitor](/images/FlareOn12_2025/ch4-api_monitor.png)

One interesting chain of API calls were:
* CreateFile
* SetFilePointer
* ReadFile
* SetFilePointer
* WriteFile

I was most interested in the `WriteFile` call since that's most likely the function that changes the bytes in the new binary. This is also a nice shortcut in RE since we can get the address where `WriteFile` is called.

![ch4-api_monitor-writefile](images/FlareOn12_2025/ch4-api_monitor-writefile.png)

The official writeup suggests it's easier to find the main function by searching for the string `"Unholy-"` in Ghidra, which also works. I personally prefer the API Monitor approach because we can see which function called the API and then inspect the function call trees in Ghidra to see where it's referenced.

Since this is written in TwinBASIC, it's a bit difficult to RE.

Basically, I wanted to find how the `SetFilePointer` offset changes and how the buffer for `WriteFile` was constructed.

Some other ideas to make RE easier inspired from [source](https://www.youtube.com/watch?v=syFEZwoI5q4):
* We know that the binary creates multiple copies, so we could search in Ghidra and check what functions use the `CreateProcess` WinAPI. Luckily for us, it's just one. We can go from there and search for the main function.

* By looking at the references of main, we can also see that the address of main is somehow used in the entry. Not really important, but I mentioned this since you can't clearly see from the entry where the call to main is done.

* Compiling a basic TwinBASIC program (the wordplay ;) ) and RE-ing it would also help a lot in skipping useless code lines in Ghidra by comparing the structes of the two programs.

* IDA is a lot better at decompiling TwinBASIC. I mainly RE-ed it in Ghidra, but I was also using IDA at the same time since it's easier to read the pseudocode. This is how I found a weird XOR with a constant which in Ghidra wasn't visible in the decompile panel.

* In x32dbg we can see that if we break on the XOR, the constant value `0x6746` is XORed with `0x96`, which is 150 (I ran this instance with `UnholyDragon_150.exe`).  
So most likely, for the other files, the other XOR values will be the number from the file.

![ch4-xor_x32dbg](/images/FlareOn12_2025/ch4-xor_x32dbg.png)

* Interestingly, we can see that a function is called twice (`FUN_004a86a3`). This takes as the first argument the result of the strange XOR: once for computing the offset to write the byte, and once to compute a value for the XOR.  
Since these values are most likely somehow random, I would assume this is a random function or something similar.


Important part of the main function reversed in Ghidra:

![ch4-ghidra_main](/images/FlareOn12_2025/ch4-ghidra_main.png)

I analyzed this with dynamic analysis and by going from the `WriteFile` WinAPI "up".

So basically what the binary does:

1. Get the number from the current filename and XOR it with `0x6746` (this happens at the weird XOR comment in the Ghidra picture).  
2. Compute the offset for the byte to be changed (also using the result from step 1). This uses a PRNG.  
3. Read the byte from the current file.  
4. XOR the byte from the file with a random key (also using the PRNG from step 2).  
5. Write the new byte into the copied file.

We can actually confirm this by comparing the original binary (first argument from the pic) that we got, with the binary generated from running `a.exe` (meaning that the 150th copy will contain ALL the changes) in the following picture:

![ch4-full-compare](/images/FlareOn12_2025/ch4-full-compare.png)