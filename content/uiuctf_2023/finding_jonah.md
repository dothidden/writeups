---
title: Finding Jonah
date: 2023-07-01T19:40:40+02:00
description: Writeup for Finding Jonah [UIUCTF 2023]
author: H0N3YP0T
tags:
- osint
draft: false
---
___

## Challenge Description

Jonah offered a reward to whoever can find out what hotel he is staying in. Based on the past information (chals), can you find out what the hotel he stayed at was? Flag should be uiuctf{hotel_name_inn}
![finding_jonah.png](/images/uiuctf_2023/chicago.jpeg)

## Intuition

First thing I did is to reverse search the image with Google Lens but unfortunately, I didn't find anything interesting so I had to find something else and I decided to manually look for the hotel on Google Earth.
Let's recap what we know:
- From the previous challenge, I don't know anything about Jonah because I only resolved [Finding Artifacts 2](/uiuctf_2023/finding_artifacts_2) and [First Class Mail](/uiuctf_2023/first_class_mail).
- The name of the image is `chicago.jpeg` so I decided to look for hotels in Chicago.
- Also, I finally decided to look at the [What's for Dinner](/uiuctf_2023/whats_for_dinner) description to see if I can find something interesting and I found out that Jonah was indeed in Chicago.
- On the image we mainly see big buildings and skyscrapers, so I decided to look for hotels in the center of Chicago.
- The buildings on the background of the image seem to be quite far from the ones in the foreground so maybe the river is between them.

With all those information, the hotel is probably on the right side of Chicago because we can see on the following image that the
skyscrapers are close of the sea:
![chicago_map.png](/images/uiuctf_2023/earth.png)

## Solution

After some more research, I saw on the image that there is something that looks like train station, so I decided to look for train stations in Chicago and I found the following one which meet all the above criteria (also the 3D feature of Google Earth is really useful):
![chicago_map.png](/images/uiuctf_2023/chicago_train.png)
Now, if I rotate the camera to have the same point of view as the image, I can see the following, and we can notice it is exactly the same:
![chicago_map_boeing.png](/images/uiuctf_2023/boeing.png)
I'm now 100% sure to have the right location because I can now see the Boeing building in front of the hotel, the logo seems to be the same as the one on the image.
If I go to Google maps this time in order to find the name of the hotel, I can see that the hotel is the `Hampton Inn`:
![hotel.png](/images/uiuctf_2023/hotel.png)
### Flag

`uiuctf{hampton_inn}`

