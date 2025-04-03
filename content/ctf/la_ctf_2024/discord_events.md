---
title: Discord Events
date: 2024-02-18T12:18:57+02:00
description: Writeup for Discord Events [LA CTF 2024]
type: writeup
author: H0N3YP0T
tags:
- misc
- forensics
draft: false
---
___

## Challenge Description

I wrote a new script to sync PBR's events to a bunch of places. I even deployed it to the LA CTF server with a flag as an event id!

Note: the event ID is formatted in the normal flag format lactf{...} - it is not the discord numerical ID.

## Intuition

The main hint I have here is the name of the challenge himself `Discord Events`. I thought the flag was hidden in the discord events of the LA CTF server. Also the challenge description says something about syncing `PBR events` and I noticed that the event was created by the user
`Power Brick Robot` which in short version is `PBR`. When visiting the profile of this bot, I noticed a link to a [GitHub repository](https://github.com/pbrucla/cyanea/tree/main/packages/cyanea-discord).

![event](/images/la_ctf_2024/event.png)
![bot](/images/la_ctf_2024/bot.png)

## Solution

The solution is hidden in the `index.ts` file of the repository.

![repo](/images/la_ctf_2024/repo.png)

Between line 38 and 48, there is the following code:

```typescript
interface StegcloakdCyaneaMetadata {
  // event id
  i: string
  // event banner url
  b?: string | undefined
}

function stegcloakEventDescription(id: string, banner: string | null | undefined, description: string): string {
  const metadata: StegcloakdCyaneaMetadata = { i: id, ...(banner ? { b: banner } : {}) }
  return stegcloak.hide(JSON.stringify(metadata), "", description)
}
```
This piece of code is very important because I remembered that the challenge description says that the flag is the event id and as we can see, the event id is a parameter of a function called `stegcloakEventDescription`.
After a quick search on the internet, I found that `stegcloak` is a tool to hide a secret based on another string. I decided to use the website [stegcloak](https://stegcloak.surge.sh/) to decode the discord event description without using any password.
The result was the following:


![flag](/images/la_ctf_2024/reveal.png)


### Flag

`lactf{j311yf15h_1n_da_cyb3r_s3a}`

## Acknowledge

Thanks to [sunbather](https://github.com/costinteo) for working with me on this challenge.
