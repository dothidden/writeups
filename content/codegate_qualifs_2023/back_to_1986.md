---
title: Back to 1986
type: writeup
date: 2023-06-30T15:05:27+03:00
description: Writeup for Back to 1986 [Codegate Qualifs 2023]
author: zenbassi
tags:
- rev
draft: false
---
___

## Challenge Description

We're given a Linux kernel which when run starts an instance of the 1986
[arkanoid](https://en.wikipedia.org/wiki/Arkanoid) game.

## Intuition

We can see that the shape of the bricks corresponds with a letter. In later levels,
the letters are obfuscated with extra grey shaped bricks, but those can be easily 
removed because they're all of the same colour. The solution would be to skip levels
and convert each level's letter to an ASCII value.

This is written way after the competition and it's based on what others used to
solve it, which is `cheatengine`. Opening it in cheatengine and fiddling around we
can find a memory address which corresponds to the number of bricks left in the
level. Setting that to 0 automatically skips the level. Now, how can we automate this?

## Solution
 
The solution I arrived at is written on Linux, where `cheatengine` doesn't work
(reliably at least). For this use case tho, `gameconqueror` does the trick. In the
beginning, I used it to find the memory address that interests us.

I wrote a program which changes the value at an address to 0 using `ptrace`:

```c
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    long data = 0;
    int pid = atoi(argv[1]);
    int *address = (int*)strtol(argv[2], NULL, 16);

    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, NULL, WUNTRACED);
    ptrace(PTRACE_POKETEXT, pid, address, (void*)data);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    return 0;
}
```
I used this as part of a shell script to automate the retrieval and de-obfuscation of
each letter. The main flow is the following:

1. send key using `xdotool` to start level
2. take a screenshot of the window using `spectacle`
3. skip level using the c program
4. goto step 1 if there's still letters to process
5. clean-up all images using `imagemagick`
6. stitch all images together using `imagemagick`

This is the full script:
```sh
#!/usr/bin/env sh

pid=$1
address=$2
window=`xdotool search qemu 2>/dev/null | tail -n1`

rm -r ./captures
mkdir ./captures

# focus on the window
xdotool windowactivate "$window"

for i in {000..270}; do
    # go to next level
    xdotool key Left
    sleep 0.05
    # start level
    xdotool key Left
    sleep 0.05
    # take screenshot
    spectacle -aebno "captures/img$i.png"
    wait
    sudo ./skip_level "$pid" "$address" &>/dev/null
    echo "$i done"
done

for i in {000..270}; do
    file="./captures/img$i.png"
    # remove grey
    convert "$file" -fill "#000" -opaque "#a9a9a9" "$file"
    # remove white
    convert "$file" -fill "#000" -opaque "#ffffff" "$file"
    # remove red
    convert "$file" -fill "#000" -opaque "#ff0000" "$file"
    # remove blue from the paddle
    convert "$file" -fill "#000" -opaque "#add8e6" "$file"
    echo "done $i"
done

echo "stitching all together"
# append horizontally
convert +append ./captures/img*.png out.png
```

The flag can be easily transcribed form the resulting picture.

### Flag

`codegate2023{.hidden-is-cool-and-solved-this-in-the-end}`
