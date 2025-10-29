---
{{ $title := replace .Name "_" " " | title -}}
{{ $date := getenv "HUGO_EVENT_DATETIME" }}
title: {{ $title }}
type: events
date: {{ $date }}
---

| Title <div style="width:290px"></div> | Speaker <div style="width:90px"></div> | Place <div style="width:100px"></div> | Datetime <div style="width:150px"></div> | Slides <div style="width:40px"></div> |
| :---: | :-----: |:------------------------------------:| :------: | :----: |
