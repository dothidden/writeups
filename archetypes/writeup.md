---
{{- $title := replace .Name "_" " " | title -}}
{{- $parts := split .Path "/" -}}
{{- $ctf := index $parts (sub (len $parts) 2) -}}

title: {{ $title }}
type: writeup
date: {{ .Date }}
description: Writeup for {{ $title }} [{{ replace $ctf "_" " " | title }}]
author: author [optional]
tags:
- tag1 [change it]
- tag2
---
___

## Challenge Description

**you can copy paste from the website**

## Intuition

**what lead you to the solution**

## Solution

**the actual solution**

### Flag

`bestctf{I_love_.hidden}`

## References (in case you used [^footnotes] thingies)