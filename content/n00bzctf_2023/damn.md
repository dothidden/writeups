---
title: Damn
date: 2023-06-10
tags:
  - osint
author: H0N3YP0T
---

___

## Description

Damn bro, Dam! -- Note: Find out the city that this dam is in. Flag format is n00bz{City_Name}

Author: NoobMaster

## Solution

The challenge provides us with the following image:

![dam.png](/images/n00bzctf_2023/dam.png)

This was probably the easiest OSINT challenge we resolved, because we do not have a lot
of information the best thing to do here is to reverse search the image using Google Lens and check the source of it.

> https://lens.google.com/search?ep=gisbubb&hl=en-RO&re=df&p=ATHekxfbtZPLxbS5VWTnJ-WuLCAo-vzoDOQ-4gLRUspP7kWr2lYTj0R7OoEy3Y4uWz2nKffhb7qsBzw5anHW4R8Q0F_cimQ97oynpQhI9qSFBNUjV9wYSy6QdfV3m7_gnGihiyFyMR3xaRl9Pmo8zbHr5hhl1opzMqf8HDMeo1kgZZ4msecXVhxPOKp2cyu1x_PXUBTGuTq91Dpl4CVqc-Tt#lns=W251bGwsbnVsbCxudWxsLG51bGwsbnVsbCxudWxsLDEsIkVrY0tKR0U1WXpGbVlXTmhMV1V5WkdFdE5HWmxZUzFoTWpZekxUWXdZV0ptTUdGbFpUTXlZaElmVFRobVRGQnliSGhXVEhkWlVVUjFWV2RKVkUxaWJEVkJYekExVFdsb1p3PT0iLG51bGwsbnVsbCxbW251bGwsbnVsbCwiMy0wIl0sWyIyNjViMzAyYS1jOWQxLTQzZjgtYmZlMy1hMTE3NzA4NWRhZTQiXV0sbnVsbCxudWxsLG51bGwsW251bGwsMTIsW11dXQ==

When it is done, we see a lot of articles and newspaper about this Ukrainian dam located in Nova Nekrasovka:

> https://english.alarabiya.net/News/world/2023/06/07/Moscow-backed-official-says-Russian-army-gains-advantage-from-Ukraine-dam-breach

![Nova_Kakhovka.png](/images/n00bzctf_2023/nova.png)

The flag is  `n00bz{Nova_Kakhovka}`.