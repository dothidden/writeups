---
title: Finding Artifacts 2
type: writeup
date: 2023-07-01T15:47:00+02:00
description: Writeup for Finding Artifacts 2 [UIUCTF 2023]
author: H0N3YP0T
tags:
- osint

draft: false
---
___

## Challenge Description

New York City is known for its sprawling subway system. However, none of that would have been possible without modern earth-moving equipment. Find where the first ever shovel was used to start digging the subway. Flag format should be in **uiuctf{name_of_museum}**

## Intuition

The first step of the reflexion I had was the following: I need to deal with the different information
the challenge gives me.

- Where: New York
- What: First shovel used to build the subway
- Information I need : The museum where the shovel is stored.

I started by looking for the creation date of the subway in New York. I found out that the first subway was built in 1904 (thank you [Wikipedia](https://en.wikipedia.org/wiki/New_York_City_Subway)).
Then, I did a Google research with the following sentence: "Museum shovel New York subway 1904", and I clicked on the first the see the source of it.
![artifact2_shovel.png](/images/uiuctf_2023/artifact2_shovel.png)


## Solution

After following the original link of the image, we can scroll down a little bit on the page and we can see it as follows:

![artifact2_shovel.png](/images/uiuctf_2023/artifact2_museum.png)

By looking under the image we can see the reference of the shovel and the museum where it is stored.
`Tiffany and Company. Ceremonial shovel used in making the first excavation for the subway on March 24, 1900. 1900. Museum of the City of New York. 54.733.`
Therefore, we now know how to build our flag.

### Flag

`uiuctf{museum_of_the_city_of_new_york}`

