---
title: What's for Dinner
type: writeup
date: 2023-07-01T19:41:58+02:00
description: Writeup for Whats for Dinner [UIUCTF 2023]
author: H0N3YP0T
tags:
- osint
draft: false 
---
___

## Challenge Description

Jonah Explorer, world renowned, recently landed in the city of Chicago, so you fly there to try and catch him. He was spotted at a joyful Italian restaurant in West Loop. You miss him narrowly but find out that he uses a well known social network and and loves documenting his travels and reviewing his food. Find his online profile.

## Intuition

We know that Jonah is in Italian restaurant somewhere in Chicago, more precisely in West Loop.
Due to extreme large amount of restaurants in West Loop neighbourhood, we need to find a way to narrow down the research.
![italian_restaurants.png](/images/uiuctf_2023/chicago_restaurant.png)
Luckily, we also know that Jonah uses social networks to review his food and he was standing in a "joyful" restaurant.

## Solution

If we look at the above picture, we can see that there is a restaurant called "Gioia Chicago" this one catch my attention because Gioia means "Joy" in Italian.
I need to confirm that this is the right restaurant, so I did a Google research with the following sentence: "Gioia Chicago Jonah" and the first link is a Yelp page of the restaurant with some reviews.
Now, if we sort the reviews by "Most recent", we can see that the second review is from Jonah Explorer.
![jonah_review.png](/images/uiuctf_2023/jonah_yelp.png)

__BINGO__ we found Jonah's twitter account, let's check his profile.
![jonah_twitter.png](/images/uiuctf_2023/jonah_twitter.png)


### Flag

`uiuctf{i_like_spaghetti}`

