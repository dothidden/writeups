---
{{ $title := replace .Name "_" " " | title -}}
{{ $date := getenv "HUGO_EVENT_DATETIME" }}
{{ $location := getenv "HUGO_EVENT_LOCATION" }}
title: {{ $title }}
type: event
date: {{ $date }}
location: {{ $location }}
---

# {{ $title }}

**Time & Date**: `{{ $date | time | time.Format "15:04, 02 Jan 2006" }}`

**Location**: `{{ $location }}`