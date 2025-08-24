---
title: The Online Odyssey
type: writeup
date: 2023-06-10
tags:
  - osint
author: H0N3YP0T
---

___

## Description

My friend `blackhat_abhinav` gave me a ctf challenge and told me that the challenge is full of mystery and he wanted me
to solve the mystery and get the flag. Can you help me to get the flag?

Flag format:- n00bz{fl4g_h3r3}

## Solution

The most important information we have is the username `blackhat_abhinav` so let's start our research with this
username.

When I have to work with username I really appreciate to use the following website: https://whatsmyname.app/ but
unfortunately
I did not find any results for the username `blackhat_abhinav`. My second resource is the following
website: https://www.aware-online.com/en/osint-tools/username-search-tool/.

![abhinav research](/images/n00bzctf_2023/abhinav1.png)

My first reflex is to check this username for the social media such as Instagram, Twitter, Facebook and GitHub.
I am lucky, I found the Instagram account of the user `blackhat_abhinav`:

> https://www.instagram.com/blackhat_abhinav/

![abhinav instagram](/images/n00bzctf_2023/instagram.png)

From the instagram account we can get following information:

- Discord `noob_abhinav#4962`
- Secret https://goo.gl/maps/gHbUHjqFyNcB7aqi9
- Website https://abhinav.abhinavkumar65.repl.co/

But wait...
What is the secret ? Let's click on it.
![abhinav secret](/images/n00bzctf_2023/secret.png)
We see the following comment:
> If you like nature and water this is a nice spot to visit. Make sure to have a look at - @Abhinav78082932

Ok, the `@` suggests that it is a Twitter account. Let's check it.

> https://twitter.com/Abhinav78082932

![abhinav twitter](/images/n00bzctf_2023/twitter.png)

I see that the most recent post has an `alt` attribute.
**BINGO** we go the flag `n00bz{gr0tt4_1sl4nd_1s_4_n1c3_pl4c3_t0_v1s1t}`.

![abhinav flag](/images/n00bzctf_2023/abhinav_flag.png)
