---
title: Mission Moon
date: 2023-06-10
tags:
  - osint
type: writeup
author: H0N3YP0T
---

---

## Description

A mission, had planned to land on the moon. Can you find where it planned to land on the moon and the name of the lander
and rover? Flag is latitude longitude upto one decimal place.

- Note: Flag format `n00bz{Lander_Rover_latitude_longitude} for eg - n00bz{Examplelander_Examplerover_12.3_45.6}`. Also
  note that flag is **case sensitive!**
- Note: Due to a quite big range of answers, to narrow down your search, use the latitude and longitude provided from
  this site: `blog.jatan.space`

Author: NoobMaster

## Solution

Let's open the image provided in the challenge description.
![mission moon](/images/n00bzctf_2023/mission_moon.webp)

1) First we use Google Lens to reverse the image we got and check the source.
2) We select the first website to see if we find any useful information about this image.

> https://m.sakshipost.com/national/2019/09/07/setback-to-moon-mission-as-link-to-lander-lost

3) We go inside the article, and we execute a `CTRL + F` to search for the word `lander` and we find the name of the
   lander
   `Vikram` and then we do the same for the rover and we find `Pragyan`.

4) Now that we got the two first information, let's open the link provided in the challenge
   description in order to find the landing coordinates.

> blog.jatan.space

5) The home page does not provide any useful information so let's check the archive page, we should be
   able to find the article about the landing coordinates.
6) Aain, we have to scroll down in order to load all the articles because the page use lazy loading, and then we can
   find the article we are looking for by using `CTRL + F` and searching for the word `Vikram`.

![Vikram](/images/n00bzctf_2023/vikram.png)

7) By scrolling through the article we can find the landing coordinates `70.9°S 22.8°E` and we can now build the flag
   `n00bz{Vikram_Pragyan_70.9_22.8}`.

![Vikram](/images/n00bzctf_2023/landing.png)