---
title: Jonahs Journal
type: writeup
date: 2023-07-01T19:42:39+02:00
description: Writeup for Jonahs Journal [UIUCTF 2023]
author: H0N3YP0T
tags:
- osint
draft: false
---
___

## Challenge Description

After dinner, Jonah took notes into an online notebook and pushed his changes there. His usernames have been relatively consistent but what country is he going to next? Flag should be in format uiuctf{country_name}

## Intuition

Because I resolved [What's for dinner](/uiuctf_2023/whats_for_dinner) before, I knew that I had to look for the same username `Jonahexplorer`.
I know from the challenge description that I have to look for an online notebook and the hint of the challenge was the following:
`forks, trees, pushing, and pulling`, so there is a high chance that the notebook is on GitHub.

## Solution

I started by looking for the username `jonahexplorer` on GitHub and I found the following profile:
![jonahexplorer_github.png](/images/uiuctf_2023/jonah_github.png)

As we can see there is only one repository, so I clicked on it and I found the following repository description:
![jonahexplorer_github.png](/images/uiuctf_2023/jonah_github_repo.png)

Great, we can try the following flag: `uiuctf{china}` but unfortunately it is not the right one, we have to dig a little bit more.
Hopefully, we also notice there is another branch `entry-2` with 4 different commits, so we can try to look at them. If 
we look at the first commit, we can see the following:
![jonahexplorer_github.png](/images/uiuctf_2023/jonah_destination.png)

> I dont know how these things work but my next destination is not China but actually italy. After I check out from my hotel in the west loop, I'll be heading there.

Now, if we try the following flag: `uiuctf{italy}` it is the right one!


### Flag

`uiuctf{italy}`

