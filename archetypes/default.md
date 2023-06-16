---
{{ $title := replace .Name "_" " " | title -}}
title: {{ $title }}
date: {{ .Date }}
{{ $sectionHeading := .Site.GetPage .Section .Section -}}
description: Writeup for {{ $title }} [{{ $sectionHeading.Title }}]
tags:
- tag1 [change it]
- tag2
draft: true
---
___

## Challenge Description

**you can copy paste from the website**

## Intuition

**what lead you to the solution**

## Solution

**the actual solution**

### Flag

**bestctf{I_love_.hidden}**

## References (in case you used [^footnotes] thingies)
