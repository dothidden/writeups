---
title: {{ replace .Name "_" " " | title }}
date: {{ .Date }}

description: page description [optional]
tldr: page tldr [optional]

place: final place !only if this is _index delete otherwise!
total: total number of participants !only if this is _index delete otherwise!

tags:
- category1 [optional]
- category2

draft: true
---

#       header1
##      header2
###     header3
####    header4
#####   header5
######  header6

Normal Text

> block quote

_italics_
**bold**
**_bold italics_**

~~strike~~

* list
    * very list
    * a lot of list
    * liiiist
        1. [more indent](somurl)
        1. indeent
            * back
            * again

1. ordered
2. list
3. this
3. is

---
***
___

[text link](example.com)
[text link with title](https://duckduckgo.com "DDG Home")


`inline code`

    scrollable long text block that is very long and can be very very very very very very very very very very very very very very very very very very very
    scrolled

```c
int main() {
    while (1) {
        printf("this is supposed to be some code");
        if (0) {
            break;
        }
        continue;
    }
}
```

[^1]: My reference.   
[^2]: Every new line should be prefixed with 2 spaces.  
  This allows you to have a footnote with multiple lines.
[^note]: Named footnotes will still render with numbers instead of the text but allow easier identification and linking.  

Here is a simple footnote[^1].  
A footnote can also have multiple lines[^2].  
You can also use words, to fit your writing style more closely[^note].  


![image](https://picsum.photos/600/400)

Colons can be used to align columns.

| Tables        | Are           | Cool  |
| ------------- |:-------------:| -----:|
| col 3 is      | right-aligned | $1600 |
| col 2 is      | centered      |   $12 |
| zebra stripes | are neat      |    $1 |

There must be at least 3 dashes separating each header cell.
The outer pipes (|) are optional, and you don't need to make the 
raw Markdown line up prettily. You can also use inline Markdown.

Markdown | Less | Pretty
--- | --- | ---
*Still* | `renders` | **nicely**
1 | 2 | 3


# References
