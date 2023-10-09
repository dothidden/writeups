---
title: merger_2077
date: 2023-10-09
tags:
  - reverse
author: MettleSphee
---

## Challenge description

Title: merger-2077

Description:
After a long and tiring ctf challenge, you decided to play a phone game to relax yourself. 
Note: Flag is hidden somewhere in memory, and this challenge is safe to run directly on your device. 
If you manage to run it on emulators, you shall fix it on your own.

Challenge Author: asef18766

## Solution

One very straight-forward Android challenge, that doesn't really require much reversing at all.

We get the following: 
- the APK which contains the flag;
- the information that the flag is in RAM;
- problems on emulators, which could make this harder (presumably)?

First thing I did (against all information given) was to decompile the APK with APKtool. Of course, nothing was found in the strings.
Then I tried a second decompiler (with JADX) and looked through some of the .java files.
Either it was about the way the physics works, or the way the flag was revealed,
Although it seems irrelevant, I had the feeling that the flag was not available right when the app was executed.

![title](/images/balsnctf_2023/Untitled.png)

And I held that feeling to heart.

To approach this, there aren't very many known memory browsing tools on Android, and very few (if any!) that can run on an unrooted device.
A program that I could use was GameGuardian. It's just like a 'Cheat Engine', but for Android.
It very rarely works without root access, so I needed a rooted device. Conveniently, I have one.
After installing the two apps, we first run the tool:

![title](/images/balsnctf_2023/Screenshot_20231009-153536_Svphk.png)

Then the flag app:

![title](/images/balsnctf_2023/Screenshot_20231009-153552_balsn-ctf-2023.png)

We select the process:

![title](/images/balsnctf_2023/Screenshot_20231009-153600_balsn-ctf-2023.png)

Then at first, we have to scan for the type UTF-8 string "BALSN{", but to spare you a lot of reading,
my hunch was right and I needed to 'play' the game for a bit until the string appeared in memory.
I played until this point (approx. the 3rd generation of the strings in memory):

![title](/images/balsnctf_2023/Screenshot_20231009-163420_balsn-ctf-2023.png)

I searched for the string again, found the memory address of the string (each letter is a separate value),
then jumped to the memory address, copied the memory address, then started to dump memory from that address:

![title](/images/balsnctf_2023/Screenshot_20231009-163510_balsn-ctf-2023.png)
![title](/images/balsnctf_2023/Screenshot_20231009-163528_balsn-ctf-2023.png)
![title](/images/balsnctf_2023/Screenshot_20231009-163536_balsn-ctf-2023.png)
![title](/images/balsnctf_2023/Screenshot_20231009-163602_balsn-ctf-2023.png)
![title](/images/balsnctf_2023/Screenshot_20231009-153618_balsn-ctf-2023.png)
![title](/images/balsnctf_2023/Screenshot_20231009-153640_balsn-ctf-2023.png)
![title](/images/balsnctf_2023/Screenshot_20231009-154357_balsn-ctf-2023.png)

After that, I read through the memory dump using HxD, search for "BALSN{", and the flag shall be revealed:

![title](/images/balsnctf_2023/image.png)

