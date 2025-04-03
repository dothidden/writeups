---
title: SecurityInFront
date: 2025-02-28T12:33:22+02:00
description: Writeup for SecurityInFront [HTB University 2024]
type: writeup
author: Mega
tags:
- rev
---
___

## Intuition

We are given a single `index.html` file. Opening it we are greeted with a login page.

![Login Page Image](/images/HTB_University_2024/image.png)

Viewing the page source, we see a very interesting Javascript function, `checkCredentials()`. It seems to be obfuscated, so we can run it through a [deobfuscator](https://deobfuscate.relative.im/).

```js
async function checkCredentials() {
    var t = document.getElementById('access-user').value,
      r = document.getElementById('access-code').value
    c1 = 'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    c2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    n1 = [5, 6, 7, 8, 9, 0, 1, 2, 3, 4]
    n2 = '0123456789'
    var n = (e, t, r) => e.reduce((e, r, n) => r.apply(e, t[n]), r),
      c = [''],
      i = String.prototype.split,
      a = Array.prototype.join,
      o = Array.prototype.filter,
      p = Array.prototype.map,
      l = String.prototype.slice,
      y = String.prototype.repeat,
      u = Array.prototype.indexOf,
      s = Array.prototype.reduce,
      d = Array.prototype.reverse,
      h = function (e) {
        return this == e
      },
      f = function (e) {
        return indexedDB.cmp(this, e)
      },
      A = String.prototype.charAt
    if (
      [
        [
          [i, p, f, h],
          [
            c,
            [(e) => (-1 == u.call(c2, e) ? e : c1[u.call(c2, e)])],
            [['n', 'q', 'z', 'v', 'a']],
            [0],
          ],
          t,
        ],
        [
          [l, y, i, p, o, f, h],
          [
            [0, 4],
            [3],
            c,
            [(e) => (-1 == u.call(c2, e) ? e : c1[u.call(c2, e)])],
            [(e, t) => t % 3 == 1],
            [['G', 'U', '{', 'O']],
            [0],
          ],
          r,
        ],
        [
          [
            l,
            function () {
              return encodeURI(this)
            },
            l,
            function (e) {
              return parseInt(this, e)
            },
            function (e) {
              return this ^ e
            },
            h,
          ],
          [[-1], [], [-2], [16], [96], [29]],
          r,
        ],
        [[i, s, h], [c, [(e) => e + e, 1], [16777216]], r],
        [
          [y, i, p, s, h],
          [
            [21],
            c,
            [(e) => n1[u.call(n2, e)]],
            [(e, t) => e + h.apply(t, [8]), 0],
            [63],
          ],
          r,
        ],
        [
          [i, o, p, d, a, h],
          [
            c,
            [(e, t) => ~u.call([4, 11, 13, 14, 16, 17, 20, 22], t)],
            [(e) => c1[u.call(c2, e)]],
            [],
            ['-'],
            ['E-X-U-P-J-C-Q-S'],
          ],
          r,
        ],
        [
          [
            function () {
              return Array.from(this)
            },
            f,
            h,
          ],
          [[], [['_']], [0]],
          new Set(
            n(
              [l, i, d, o],
              [[12, 16], c, [], [(e, t) => ~u.apply([0, 3], [t])]],
              r
            )
          ),
        ],
        [
          [
            i,
            d,
            o,
            function () {
              return this.slice(2, this.length).concat(this.slice(0, 2))
            },
            d,
            a,
            h,
          ],
          [
            c,
            [],
            [(e, t) => ~u.apply([18, 13, 4, 16, 15], [t])],
            [],
            [],
            [''],
            ['ncrnt'],
          ],
          r,
        ],
        [[A, h], [[6], ['0']], r],
      ].reduce((e, t) => e && n.apply(void 0, t), true)
    ) {
      var v = new Uint8Array(new TextEncoder().encode(r)),
        g = new Uint8Array(await crypto.subtle.digest('SHA-256', v)),
        m = new Uint8Array([
          9, 87, 39, 96, 151, 202, 140, 186, 120, 235, 167, 229, 47, 231, 6, 212,
          77, 205, 58, 14, 248, 104, 169, 79, 116, 140, 236, 98, 126, 26, 100,
          120,
        ])
      0 == indexedDB.cmp(g, m)
        ? activate()
        : alert('User is not authorized. This incident will be reported.')
    } else {
      alert('User is not authorized.')
    }
  }
```

Safe to say, it's not a pretty view.

## Solution

The first thing that we should do is clean up the mess. It seems that many Javascript functions have been replaced with letters, so we'll replace them back to get a better view. The `if` statement is very confusing, but after a while I realized that each element of the array is a condition. So the code is just checking if all conditions are true. The next step is taking all of the conditions and trying to satisfy them.

### First condition

```js
[String.prototype.split, Array.prototype.map, f, h],
[
    [''],
    [(e) => (-1 == Array.prototype.indexOf.call(c2, e) ? e : c1[Array.prototype.indexOf.call(c2, e)])],
    [['n', 'q', 'z', 'v', 'a']],
    [0],
],
t,
```

The first array represents the functions applied to `t`, while the second array represent the arguments of those functions. In other words, this whole condition translates to:

```js
t.split('').map((e) => c1[c2.indexOf(e)]) == "nqzva"
```

Looking at `c1` and `c2`, they seem to be shifted $13$ positions relative to eachother, so all of this looks like a ROT13 cipher. Fair enough, putting `nqzva` through ROT13 yields `admin`. So let's simplify more:

```js
t == "admin"
```

Onto the next one.

### Second condition

```js
[String.prototype.slice, String.prototype.repeat, String.prototype.split, Array.prototype.map, Array.prototype.filter, f, h],
[
  [0, 4],
  [3],
  [''],
  [(e) => (-1 == Array.prototype.indexOf.call(c2, e) ? e : c1[Array.prototype.indexOf.call(c2, e)])],
  [(e, t) => t % 3 == 1],
  [['G', 'U', '{', 'O']],
  [0],
],
r,
```

Rewriting it gives us

```js
r .slice(0, 4)
  .repeat(3)
  .split('')
  .map([(e) => (-1 == Array.prototype.indexOf.call(c2, e) ? e : c1[Array.prototype.indexOf.call(c2, e)])])
  .filter((e, t) => t % 3 == 1) == "GU{O"
```

We've seen the map function before, so we know it's just a ROT13. Let's take `r = "abcd"` for now and see what happens

- "abcd" => "abcdabcdabcd" (repeat(3))
- "abcdabcdabcd" => ROT13("abcdabcdabcd")
- ROT13("abcdabcdabcd") => ROT13("bacd") (filter)

So we just swap $2$ pairs of characters, and put them through ROT13, and then comparing to `"GU{O"`. Finding the first $4$ characters of `r` is equivalent to taking the ROT13 of `"GU{O"` and swapping the characters. Evidently enough, this gives us `"HTB{"` which seems to be the beginning of our flag. So, let's simplify again:

```js
r.substr(0, 4) == "HTB{"
```

### Third condition

```js
[
  String.prototype.slice,
  function () {
    return encodeURI(this)
  },
  String.prototype.slice,
  function (e) {
    return parseInt(this, e)
  },
  function (e) {
    return this ^ e
  },
  h,
],
[[-1], [], [-2], [16], [96], [29]],
r
```

Rewriting this gives us

```js
parseInt(encodeURI(r.slice(-1)).slice(-2), 16) ^ 96 == 29
```

This is pretty straight forward. It's clear that the flags ends ends with `}`. The above condition just checks if the last character is indeed equal to `}`.

```js
Welcome to Node.js v20.11.1.
Type ".help" for more information.
> encodeURI("}")
'%7D'
> parseInt(encodeURI("}").slice(-2), 16) ^ 96
29
```

Simplifying again we get

```js
r.substr(-1) == "}"
```

### Fourth condition

```js
[String.prototype.split, Array.prototype.reduce, h], 
[
  [''], 
  [(e) => e + e, 1], 
  [16777216]
], 
r
```

Rewriting this gives us

```js
r.split('').reduce((e) => e + e, 1) == 16777216
```

This checks whether $2^{|r|} = 2^{24} = 16777216$. In other words, the flag has $24$ characters.

Simplifying again, we get

```js
r.length == 24
```

### Fifth condition

```js
[String.prototype.repeat, String.prototype.split, Array.prototype.map, Array.prototype.reduce, h],
[
  [21],
  [''],
  [(e) => n1[Array.prototype.indexOf.call(n2, e)]],
  [(e, t) => e + h.apply(t, [8]), 0],
  [63],
],
r
```

Rewriting this gives us

```js
r.repeat(21)
  .split('')
  .map((e) => n1[Array.prototype.indexOf.call(n2, e)])
  .reduce((e, t) => e + (t == [8])) 
  == 63
```

We have something similar to the ROT13 above, but this one is done only on the digits of `r`, esentially doing a ROT5 on them. So, the code above checks whether `r` repeated $21$ times contains $63$ values of ROT5(8) = 3, ergo `r` contains $3$ values of $3$.

Simplifying again, we get

```js
r.replace(/[^3]/g, "").length == 3 
```

Javascript why can't you just have a `count()` function?

### Sixth condition

```js
[String.prototype.split, Array.prototype.filter, Array.prototype.map, Array.prototype.reverse, Array.prototype.join, h],
[
  [''],
  [(e, t) => ~Array.prototype.indexOf.call([4, 11, 13, 14, 16, 17, 20, 22], t)],
  [(e) => c1[Array.prototype.indexOf.call(c2, e)]],
  [],
  ['-'],
  ['E-X-U-P-J-C-Q-S'],
],
r,
```

Rewriting this gives us

```js
r.split('')
  .filter((e, t) => ~Array.prototype.indexOf.call([4, 11, 13, 14, 16, 17, 20, 22], t))
  .map((e) => c1[Array.prototype.indexOf.call(c2, e)])
  .reverse()
  .join('-') 
  == "E-X-U-P-J-C-Q-S"
```

This takes the letters from the flag at those positions, does a ROT13 on them, reverses them and then joins them with the `-` separator. Doing them in reverse, we can start deducing some letters of the flag.

`HTB{F333???D?PW?CH??K?R}`

### Seventh condition

```js
[
  function () {
    return Array.from(this)
  },
  f,
  h,
],
[[], [['_']], [0]],
new Set(
  n(
    [String.prototype.slice, String.prototype.split, Array.prototype.reverse, Array.prototype.filter],
    [[12, 16], [''], [], [(e, t) => ~Array.prototype.indexOf.apply([0, 3], [t])]],
    r
  )
),
```

This one contains a nested condition, so this is more fun. Let's solve the second one first. Rewriting it gives us

```js
[String.prototype.slice, String.prototype.split, Array.prototype.reverse, Array.prototype.filter],
[[12, 16], [''], [], [(e, t) => ~Array.prototype.indexOf.apply([0, 3], [t])]],
r
```

```js
r.slice(12, 16)
  .split('')
  .reverse()
  .filter((e, t) => ~Array.prototype.indexOf.apply([0, 3], [t]))
```

The code extracts a substring from `r`, splits it, reverses it, selects only the elements at indices $0$ and $3$ of the reversed array, and then constructs a set with that filtered array. Let's call this set `s`. Next, let's look at the second condition

```js
[
  function () {
    return Array.from(this)
  },
  f,
  h,
],
[[], [['_']], [0]],
s
```

This converts the set back into an array and compares it to the symbol `_`. Since only one comparison is being made, we can deduce that the set only contains one element; thus, the flag has underscores both at positions $12$ and $15$. Flag for now:

`HTB{F??????D_PW_CH??K?R}`

### Eigth condition

```js
[
  String.prototype.split,
  Array.prototype.reverse,
  Array.prototype.filter,
  function () {
    return this.slice(2, this.length).concat(this.slice(0, 2))
  },
  Array.prototype.reverse,
  Array.prototype.join,
  h,
],
[
  [''],
  [],
  [(e, t) => ~Array.prototype.indexOf.apply([18, 13, 4, 16, 15], [t])],
  [],
  [],
  [''],
  ['ncrnt'],
],
r
```

Rewriting it gives us

```js
r.split('')
  .reverse()
  .filter((e, t) => ~Array.prototype.indexOf.apply([18, 13, 4, 16, 15], [t]))
  .slice(2, this.length).concat(this.slice(0, 2)) 
  // Note that we are taking substrings from the filtered flag, not the original
  // This is not valid code, but helps us to understand better
  .reverse()
  .join('')
  == "ncrnt"
```

This reverses `r`, filters only the indices at positions $18$, $13$, $4$, $16$, $15$ in the reversed string, does a circular shift of 2 positions and then reverses it again. Note that even if the indices are shuffled, we should take them in ascending order. Doing everything in reverse order we get:

`"nrcnt" => "tnrcn" => "cntnr"`

Now, we reverse the flag and put the letters in the corresponding order:

- `c` -> $4$
- `n` -> $13$
- `t` -> $15$
- `n` -> $16$
- `r` -> $18$

```text
}R?Kc?HC_WP_Dn?tn?rF{BTH
012345678901234567890123
```

`HTB{Fr?nt?nD_PW_CH?cK?R}`

### Last condition

```js
[
  [A, h], 
  [[6], ['0']], 
  r
]
```

This translates to

```js
r[6] == '0'
```

`HTB{Fr0nt?nD_PW_CH?cK?R}`

Filling in the $3$'s from the previous condition we get our final flag.

### Flag

`HTB{Fr0nt3nD_PW_CH3cK3R}`

## Thoughts

I really like deobfuscating challenges, since you get a feeling of getting closer and closer to a final result, while making sense of more and more code as you go along. I can say that this challenge has definitely increased my hatred for Javascript and I am convinced that the obfuscation for it can become way worse than this.

For a quick laugh I recommend [wtfjs](https://github.com/denysdovhan/wtfjs).
