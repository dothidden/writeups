---
title: Lost
type: writeup
date: 2023-06-10
tags:
  - osint
author: H0N3YP0T
---

___

## Description

I got lost. Help me find out where I am. Flag format is n00bz{Name_Of_Pin_On_Google_Maps}.

Author: Spectral

## Solution

First of all, let's open the image `where.png` which is given by the challenge.
We can see a bridge and a city in the background and the image seems to have a filter on it because the red and purple
colors are more present than the others.
Furthermore, some elements of the image are duplicated (same effect as beeing drunk).

![where.png](/images/n00bzctf_2023/where.png)

Second reflex to have is to check the metadata of the image with exiftool.
Exiftool tell us the location of the image is San Fransisco, by having this information we can now try to identify the
bridges by using Google Maps: we see it's the Oakland Bay Bridge
because of structure, the island on the left and the color of the bridge.

By using the orientation of the picture and the relief let's check for a similar spot with a view on a straight road
until a "pier":

![maps.png](/images/n00bzctf_2023/maps.png)

It should be around this place and after a few researches we found it: `Vallejo Steps`.

![vallejo.png](/images/n00bzctf_2023/road.png)

The flag is `n00bz{Vallejo_Steps}`.