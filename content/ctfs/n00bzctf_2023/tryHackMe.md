---
title: Try Hack Me
type: writeup
date: 2023-06-10
tags:
  - osint
author: H0N3YP0T
---

___

## Description of the challenge

My friend `brayannoob` gave me a ctf challenge and told me `Try to hack me`.

Author: noob_abhinav

## Solution

First, let's start our research with the username `brayannoob`.

When I have to work with username I really appreciate to use the following website: https://whatsmyname.app/.
Let's check the results I got for the username `brayannoob`:
![whatsmyname](/images/n00bzctf_2023/tryHackMeBrayan.png)

When dealing with username I always start with social network such as Instagram, Twitter, Facebook and GitHub so let's
open the GitHub account we found. It's very interesting because we see on the profile that the user committed something
in a repository recently. I will not go through the code because I will lose time, going directly to the commits history
is
more efficient because we can see the commit message and the changes made into the project.

![github](/images/n00bzctf_2023/tryHackMeGithubAccount.png)

> https://github.com/brayannoob
>
If we check the most recent commit we can see a secret username `brayan234` (others secrets were present in past commits
and even passwords, but we know that they are not
relevant because the admin told us that we do not have to use any credentials to solve the challenge).

![commit](/images/n00bzctf_2023/tryHackMeCommit.png)

> https://github.com/brayannoob/BrayanResearch/commit/933cac4259ae48dde17252963da468f23684d908

Now, because of the challenge description speaks about `Try to hack me` and CTF challenges, as experienced players, we
know that there is a
popular website called `Try Hack Me` where hackers
can learn and practice their skills. Let's check if the username `brayan234` is present on the website.

> https://tryhackme.com/

But how can we find a specific user on the website? Let's check the profile of one of the player in the leaderboard for
example

> https://tryhackme.com/p/Kn1ght1972

Now, we know the pattern used by the website to render a user profile. Let's replace `Kn1ght1972` by the username we
found in the commit:

> https://tryhackme.com/p/brayan234

**BINGO** , we got it `n00bz{y0u_p4ss3d_th3_ch4ll3ng3_c0ngr4tul4t10ns_7c48179d2b7547938409152641cf8e}`

![flag](/images/n00bzctf_2023/tryHackMeFlag.png)
