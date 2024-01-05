---
{{ $title := replace .Name "_" " " | title -}}
title: {{ $title }}
date: {{ .Date }}
description: Writeups for [{{ $title }}]
place: final place
total: total number of participants
---
