---
title: Circle
type: writeup
date: 2023-10-22T18:52:45+02:00
description: Writeup for Circle [Defcamp Quals 2023]
author: zenbassi
tags:
- rev
- crypto
draft: false
---
___

## Challenge Description

Can you make it a line?

## Intuition

We got a `gen` executable and an `flagenc.txt` file, intuitively we deal with an encryption algorithm. After opening the executable in `ghidra` we figure that there are two input strings (let's call them `a` and `b`) and only one of them is relevant. All relevant operations were related to a for loop reconstructed below. In the end the encrypted flag was printed (the content of `flagenc.txt`), so most likely going back from the output to the input by reversing the encryption steps will lead to the flag.

```c
void foo(unsigned char* param_1) {
  for (int i = 1; i <= 10; i++) {
    ctf_stringify_16(param_1);
    permutare(param_1);
    if (i == 10) break;
    for_xors(param_1);
  }
  return;
}

for (int i = 0; i < 5; i = i + 1) {
    foo_rev(a + (i << 4));
}
```

## Solution

I would separate the solution into three parts, each related to each of the functions applied in `foo`. You'll find below an overview for each component and also the full solution in the [Appendix](appendix);

### ctf_stringify_16

There is a char array of length 256 in memory that I named `ctf_string` that is used as permutation. This is reversible if all elements are unique and in the range $[0, 255]$, which they are. For reversing this function we just construct the reverse of the permutation and use that instead.

### permutare

This function just manually makes a permutation of a 16-byte block. Similarly, just make a function which reverses the permutation and use that instead.

### for_xors

This function was a pain to reverse. For each 4-byte block out of a 16-byte block it separates it into 4 1-byte components and applies some **xor** magic on them. If we take each 1-byte component after the transformation and expand the transformation for each bit, it becomes clear how it can be reversed (more **xor** magic). Solving it involved solving each bit separately, but since the formulas used were cyclic (circle??) we only had to come up with a formula for each of the 8 bits and just adjust offsets for each of the 4 1-byte elements.

### Flag

`DCTF{b39dd1d2427c8e8e43535642433a110b126d83027d327b09a14043cda617b33a}`

## Appendix

```c
#include <assert.h>
#include <stdio.h>

#define X 0
#define Y 1
#define Z 2
#define T 3

unsigned char ctf_string[256] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b,
    0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
    0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 
    0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 
    0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23,
    0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b,
    0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 
    0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1,
    0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 
    0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 
    0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 
    0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 
    0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 
    0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 
    0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 
    0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 
    0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 
    0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 
    0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 
    0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

unsigned char ctf_string_rev[256];

void init_ctf_string_rev() {
    for (int i = 0; i < 256; ++i) {
        ctf_string_rev[(int)ctf_string[i]] = i;
    }
}

unsigned char* some_weird_string = "";

void init_string_c(unsigned char* param_1, unsigned char *param_2) {
    int i, x, y;
    unsigned char a, b, c, d;

    for (i = 0; i < 16; i = i + 1) {
        param_1[i] = param_2[i];
    }

    for (i = 4; i < 44; i = i + 1) {
        x = (i - 1) * 4;
        a = param_1[x];
        b = param_1[x + 1];
        c = param_1[x + 2];
        d = param_1[x + 3];
        if ((i & 3) == 0) {
            x = b;
            b = ctf_string[(int)c];
            c = ctf_string[(int)d];
            d = ctf_string[(int)a];
            a = some_weird_string[i >> 2] ^ ctf_string[(int)x];
        }
        x = i * 4;
        y = (i - 4) * 4;
        param_1[x] = a ^ param_1[y];
        param_1[x + 1] = b ^ param_1[y + 1];
        param_1[x + 2] = c ^ param_1[y + 2];
        param_1[x + 3] = d ^ param_1[y + 3];
    }
}

void init_string_c_rev(unsigned char* param_1, unsigned char *param_2) {
    int i, x, y;
    unsigned char a, b, c, d;

    for (i = 43; i >= 4; i = i - 1) {
        // elementele de tura trecuta
        x = (i - 1) * 4;
        a = param_1[x];
        b = param_1[x + 1];
        c = param_1[x + 2];
        d = param_1[x + 3];

        if ((i & 3) == 0) {
            x = b;
            b = ctf_string[(int)c];
            c = ctf_string[(int)d];
            d = ctf_string[(int)a];
            a = some_weird_string[i >> 2] ^ ctf_string[(int)x];
        }

        // same op
        x = i * 4;
        y = (i - 4) * 4;
        param_1[x] = a ^ param_1[y];
        param_1[x + 1] = b ^ param_1[y + 1];
        param_1[x + 2] = c ^ param_1[y + 2];
        param_1[x + 3] = d ^ param_1[y + 3];
    }
}

void ctf_stringify_16(unsigned char *param_1) {
    // pot face reverse daca valorile din ctf_string sunt unice
    // tested. primele 168 cel putin sunt unice. yey
    for (int i = 0; i < 16; i = i + 1) {
        param_1[i] = ctf_string[(int)param_1[i]];
    }

// inainte 
    /*int i, j;*/
    /*for (i = 0; i < 4; i = i + 1) {*/
        /*for (j = 0; j < 4; j = j + 1) {*/
            /*param_1[i + j * 4] = ctf_string[param_1[i + j * 4]];*/
        /*}*/
    /*}*/
}

void ctf_stringify_16_rev(unsigned char *param_1) {
    for (int i = 15; i >= 0; i = i - 1) {
        /*printf("%u ", param_1[i]);*/
        param_1[i] = ctf_string_rev[param_1[i]];
        /*printf("%u\n", param_1[i]);*/
    }
}

void permutare(unsigned char *param_1) {
//  | 0 | 1 |  2 |  3 | 4 | 5 |  6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
//  | 0 | 5 | 10 | 15 | 4 | 9 | 14 | 3 | 8 | 13 | 2 |  7 | 12 |  1 |  6 | 11 |
    
    unsigned char aux;
    aux = param_1[1];
    param_1[1] = param_1[5];
    param_1[5] = param_1[9];
    param_1[9] = param_1[13];
    param_1[13] = aux;
    aux = param_1[2];
    param_1[2] = param_1[10];
    param_1[10] = aux;
    aux = param_1[6];
    param_1[6] = param_1[14];
    param_1[14] = aux;
    aux = param_1[3];
    param_1[3] = param_1[15];
    param_1[15] = param_1[11];
    param_1[11] = param_1[7];
    param_1[7] = aux;
}

void permutare_rev(unsigned char *param_1) {
//  | 0 | 1 |  2 |  3 | 4 | 5 |  6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
//  | 0 | 5 | 10 | 15 | 4 | 9 | 14 | 3 | 8 | 13 | 2 |  7 | 12 |  1 |  6 | 11 |
//
//
//  | 0 |  1 |  2 |  3 | 4 | 5 |  6 |  7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
//  | 0 | 13 | 10 |  7 | 4 | 1 | 14 | 11 | 8 | 5 |  2 | 15 | 12 |  9 |  6 |  3 |
    
    unsigned char aux;
    aux = param_1[1];
    param_1[1] = param_1[13];
    param_1[13] = param_1[9];
    param_1[9] = param_1[5];
    param_1[5] = aux;

    aux = param_1[2];
    param_1[2] = param_1[10];
    param_1[10] = aux;

    aux = param_1[3];
    param_1[3] = param_1[7];
    param_1[7] = param_1[11];
    param_1[11] = param_1[15];
    param_1[15] = aux;

    aux = param_1[6];
    param_1[6] = param_1[14];
    param_1[14] = aux;
}

unsigned char xor_something(unsigned char k) {
    // k = 10010111
    // 1 * 00011011 ^ 00101110
    // 00011011 ^ 00101110 = 00110101
    //
    // 10010111
    // 00110101
    // ?signed(k) * 00011011 ^ (k << 1)
  return (k >> 7) * 27 ^ k << 1;
}

void for_xors(unsigned char *param_1) {
  unsigned char a, b, c;
  int i;
  
  for (i = 0; i < 4; i = i + 1) {
    c = param_1[i * 4 + 0];
    a = param_1[i * 4 + 0] ^
        param_1[i * 4 + 1] ^
        param_1[i * 4 + 3] ^
        param_1[i * 4 + 2];

    b = xor_something(param_1[i * 4 + 1] ^ param_1[i * 4 + 0]);
    param_1[i * 4 + 0] = param_1[i * 4 + 0] ^ b ^ a;

    b = xor_something(param_1[i * 4 + 2] ^ param_1[i * 4 + 1]);
    param_1[i * 4 + 1] = param_1[i * 4 + 1] ^ b ^ a;

    b = xor_something(param_1[i * 4 + 3] ^ param_1[i * 4 + 2]);
    param_1[i * 4 + 2] = param_1[i * 4 + 2] ^ b ^ a;

    b = xor_something(param_1[i * 4 + 3] ^ c);
    param_1[i * 4 + 3] = param_1[i * 4 + 3] ^ b ^ a;
  }
}

unsigned char bit(unsigned char val, int b) {
    return (val & (1 << b)) ? 1 : 0;
}

unsigned char bit7(int i, unsigned char x, unsigned char y, unsigned char z, unsigned char t, unsigned char a) {
    unsigned char v[4] = {x, y, z, t};
    unsigned char ret = 
          bit(v[(i + X) % 4], 7) 
        ^ bit(v[(i + X) % 4], 6)
        ^ bit(v[(i + Y) % 4], 6)
        ^ bit(v[(i + X) % 4], 5)
        ^ bit(v[(i + Z) % 4], 5)
        ^ bit(a, 4);
    return ret;
}

unsigned char bit6(int i, unsigned char x, unsigned char y, unsigned char z, unsigned char t, unsigned char a) {
    unsigned char v[4] = {x, y, z, t};
    unsigned char ret = 
          bit(v[(i + X) % 4], 6) 
        ^ bit(v[(i + X) % 4], 5)
        ^ bit(v[(i + Y) % 4], 5)
        ^ bit(v[(i + X) % 4], 4)
        ^ bit(v[(i + Z) % 4], 4)
        ^ bit(a, 3)
        ^ bit(a, 7);
    return ret;
}

unsigned char bit5(int i, unsigned char x, unsigned char y, unsigned char z, unsigned char t, unsigned char a) {
    unsigned char v[4] = {x, y, z, t};
    unsigned char ret = 
          bit(v[(i + X) % 4], 5) 
        ^ bit(v[(i + X) % 4], 4)
        ^ bit(v[(i + Y) % 4], 4)
        ^ bit(v[(i + X) % 4], 3)
        ^ bit(v[(i + Z) % 4], 3)
        ^ bit(a, 2)
        ^ bit(v[(i + Y) % 4], 7) 
        ^ bit(v[(i + T) % 4], 7) 
        ^ bit(a, 6);
    return ret;
}

unsigned char bit4(int i, unsigned char x, unsigned char y, unsigned char z, unsigned char t, unsigned char a) {
    unsigned char v[4] = {x, y, z, t};
    unsigned char ret = 
          bit(v[(i + X) % 4], 4) 
        ^ bit(v[(i + X) % 4], 3)
        ^ bit(v[(i + Y) % 4], 3)
        ^ bit(v[(i + X) % 4], 2)
        ^ bit(v[(i + Z) % 4], 2)
        ^ bit(a, 1)
        ^ bit(v[(i + Y) % 4], 7) 
        ^ bit(v[(i + Z) % 4], 7) 
        ^ bit(v[(i + Y) % 4], 6) 
        ^ bit(v[(i + T) % 4], 6) 
        ^ bit(a, 5);
    return ret;
}

unsigned char bit3(int i, unsigned char x, unsigned char y, unsigned char z, unsigned char t, unsigned char a) {
    unsigned char v[4] = {x, y, z, t};
    unsigned char ret = 
          bit(v[(i + X) % 4], 3) 
        ^ bit(v[(i + X) % 4], 2)
        ^ bit(v[(i + Y) % 4], 2)
        ^ bit(v[(i + X) % 4], 1)
        ^ bit(v[(i + Z) % 4], 1)
        ^ bit(a, 0)
        ^ bit(v[(i + Z) % 4], 7) 
        ^ bit(v[(i + T) % 4], 7) 
        ^ bit(v[(i + Z) % 4], 6) 
        ^ bit(v[(i + X) % 4], 6) 
        ^ bit(a, 5);
    return ret;
}

unsigned char bit2(int i, unsigned char x, unsigned char y, unsigned char z, unsigned char t, unsigned char a) {
    unsigned char v[4] = {x, y, z, t};
    unsigned char ret = 
          bit(v[(i + X) % 4], 2) 
        ^ bit(v[(i + X) % 4], 1)
        ^ bit(v[(i + Y) % 4], 1)
        ^ bit(v[(i + X) % 4], 0)
        ^ bit(v[(i + Z) % 4], 0)
        ^ bit(v[(i + Y) % 4], 7) 
        ^ bit(v[(i + T) % 4], 7) 
        ^ bit(a, 6);
    assert(ret == 0 || ret == 1);
    return ret;
}

unsigned char bit1(int i, unsigned char x, unsigned char y, unsigned char z, unsigned char t, unsigned char a) {
    unsigned char v[4] = {x, y, z, t};
    unsigned char ret = 
          bit(v[(i + X) % 4], 1) 
        ^ bit(v[(i + X) % 4], 0)
        ^ bit(v[(i + Y) % 4], 0)
        ^ bit(v[(i + Y) % 4], 7)
        ^ bit(v[(i + Z) % 4], 7)
        ^ bit(v[(i + Y) % 4], 6)
        ^ bit(v[(i + T) % 4], 6)
        ^ bit(a, 5);
    return ret;
}

unsigned char bit0(int i, unsigned char x, unsigned char y, unsigned char z, unsigned char t, unsigned char a) {
    unsigned char v[4] = {x, y, z, t};
    unsigned char ret = 
          bit(v[(i + X) % 4], 0) 
        ^ bit(v[(i + X) % 4], 7)
        ^ bit(v[(i + Y) % 4], 7)
        ^ bit(v[(i + X) % 4], 6)
        ^ bit(v[(i + Z) % 4], 6)
        ^ bit(a, 5);
    return ret;
}

unsigned char reconstruct(unsigned char vals[8]) {
    unsigned char ret = 0;
    for (int i = 0; i < 8; ++i) {
        ret = (ret << 1) | vals[i];
    }
    return ret;
}

void for_xors_rev(unsigned char *param_1) {
    unsigned char x, y, z, t, a;
    for (int i = 3; i >= 0; i = i - 1) {
        x = param_1[i * 4 + X];
        y = param_1[i * 4 + Y];
        z = param_1[i * 4 + Z];
        t = param_1[i * 4 + T];
        a = x ^ y ^ z ^ t;

        x = x ^ a;
        y = y ^ a;
        z = z ^ a;
        t = t ^ a;

        param_1[i * 4 + X] = reconstruct((unsigned char[]){
                bit7(X, x, y, z, t, a),
                bit6(X, x, y, z, t, a),
                bit5(X, x, y, z, t, a),
                bit4(X, x, y, z, t, a),
                bit3(X, x, y, z, t, a),
                bit2(X, x, y, z, t, a),
                bit1(X, x, y, z, t, a),
                bit0(X, x, y, z, t, a) });
        param_1[i * 4 + Y] = reconstruct((unsigned char[]){
                bit7(Y, x, y, z, t, a),
                bit6(Y, x, y, z, t, a),
                bit5(Y, x, y, z, t, a),
                bit4(Y, x, y, z, t, a),
                bit3(Y, x, y, z, t, a),
                bit2(Y, x, y, z, t, a),
                bit1(Y, x, y, z, t, a),
                bit0(Y, x, y, z, t, a) });
        param_1[i * 4 + Z] = reconstruct((unsigned char[]){
                bit7(Z, x, y, z, t, a),
                bit6(Z, x, y, z, t, a),
                bit5(Z, x, y, z, t, a),
                bit4(Z, x, y, z, t, a),
                bit3(Z, x, y, z, t, a),
                bit2(Z, x, y, z, t, a),
                bit1(Z, x, y, z, t, a),
                bit0(Z, x, y, z, t, a) });
        param_1[i * 4 + T] = reconstruct((unsigned char[]){
                bit7(T, x, y, z, t, a),
                bit6(T, x, y, z, t, a),
                bit5(T, x, y, z, t, a),
                bit4(T, x, y, z, t, a),
                bit3(T, x, y, z, t, a),
                bit2(T, x, y, z, t, a),
                bit1(T, x, y, z, t, a),
                bit0(T, x, y, z, t, a) });
    }
}

void foo(unsigned char* param_1) {
  for (int i = 1; i <= 10; i++) {
    ctf_stringify_16(param_1);
    permutare(param_1);
    if (i == 10) break;
    for_xors(param_1);
  }
  return;
}

void foo_rev(unsigned char* param_1) {
    for (int i = 10; i>= 1; --i) {
        if (i != 10) {
            for_xors_rev(param_1);
        }
        permutare_rev(param_1);
        ctf_stringify_16_rev(param_1);
    }
}

void print_16(unsigned char* param_1) {
    int i;
    for (i = 0; i < 16; i = i + 1) {
        printf("%.2x",param_1[i]);
    }
}

int main(void) {
    init_ctf_string_rev();

    unsigned char a[80] = {0xc5, 0x5e, 0x8b, 0x7b, 0x42,
        0xcf, 0x7a, 0x35, 0x9a, 0x92, 0x27, 0xbc, 0x14, 0x82,
        0x2a, 0x92, 0x7a, 0xc5, 0xc9, 0x81, 0x7d, 0xba, 0x99,
        0x8, 0x32, 0x7f, 0xa, 0x87, 0x9f, 0x68, 0x3e, 0xda,
        0xc8, 0xbd, 0xdc, 0x70, 0xc9, 0xbd, 0x9b, 0x75, 0xcf,
        0xa9, 0xc8, 0x87, 0xd9, 0x1d, 0x3f, 0xb7, 0xf4, 0x5,
        0x19, 0x1f, 0x51, 0xc, 0x53, 0x77, 0xa5, 0x5f, 0x4a,
        0x8b, 0x6c, 0x65, 0x84, 0xe0, 0x3e, 0xcc, 0x5c, 0x7d,
        0x10, 0x31, 0xba, 0xa9, 0x10, 0x24, 0x83, 0x2c, 0x72,
        0xcc, 0x77, 0x20};

    /*for (int i = 0; i < 256; ++i) {*/
        /*printf("%d ", ctf_string_rev[i]);*/
    /*}*/
    /*printf("\n");*/
    /*return 0;*/

    for (int i = 0; i < 5; i = i + 1) {
        foo_rev(a + (i << 4));
    }

    for (int i = 0; i < 80; ++i) {
        printf("%c", a[i]);
    }
    printf("\n");
}
```
