---
title: Closed
date: 2024-02-18T20:03:33+02:00
description: Writeup for Closed [LA CTF 2024]
author: H0N3YP0T
tags:
- OSINT
draft: false
---
___

## Challenge Description

Over spring break, my friend sent me this picture of a place they went to, and said it was their favorite plate to visit but it closed :(.

Where is this rock?

Answer using the coordinates of the bottom left corner of the rock, rounded to the nearest thousandth. If the coordinates were the physical location of the [bruin bear statue](https://www.google.com/maps/place/34°04'15.5%22N+118°26'42.0%22W/@34.0710041,-118.4450305,39m/data=!3m1!1e3!4m4!3m3!8m2!3d34.070968!4d-118.445002?entry=ttu), the flag would be lactf{34.071,-118.445}. Note that there is no space in the flag.

![closed](/images/lactf_2024/closed.png)

## Intuition

Reverse image search does not yield any results. But I can see that the image is part of the State of California. I also
noticed the sea which means that the location is near the coast. The panel is also translated in Spanish, so I can assume that the location is in California near the Mexican border. I will use Google Maps to find the location.
Further more I see the beginning of a trail path called ***ore trail.

## Solution

We have to look manually for the location starting from the south of California and I found it here:

![closed maps](/images/lactf_2024/closed1.png)

![closed rock](/images/lactf_2024/rock.png)

### Flag

`lactf{36.516,-121.949}`


