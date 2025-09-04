---
title: Nsort
type: writeup
date: 2023-10-22T16:00:34+03:00
description: Writeup for Nsort [Defcamp Quals 2023]
author: Koyossu
tags:
  - web
draft: false
---

___

## Challenge Description

Can you escape the sandbox? Do you have all the needed info?

## Intuition

The vulnerability was a RCE given through the use of eval in php web page. It was a RCE vulnerability written in the
style of a web injection. There was a hidden parameter when doing a get request on the index.html page. If we had that
param the page executed an eval on a formatted string that, we guessed was of this
format  `eval(“somePHPSortingFunction($_GET[‘poc’])”)`. thus For the vulnerability to be exploited we needed to escape
and close the sorting function then execute our wanted code.

## Solution

Going on the / route or index.php in browser we get this message

![img.png](/images/defcamp_quals_2023/web1.png)

We see flag.php mentioned, and we try to visit the site. The page has the following content.

![img.png](/images/defcamp_quals_2023/web2.png)

Having seen this message we know that this is yet another web jail/escape. Referring to the content of index.php we so
the last # that looked suspicious. Missing poc in get might mean that there is a param in the url named poc, that is
expected when we do a get on the page. We tried this

![img.png](/images/defcamp_quals_2023/web3.png)

Bingo! Our suspicion was correct! This is yet another escape with the use of eval. From here onwards we try different
payloads to see the results.The challenge description asked us if we have all we need to solve the chall. We thinked
that maybe there are some hints outside the web page, in the challenge description and in the title. The challenge
name is nsort. In php there is a sorting function called natsort, so we were thinking that maybe the php webpage is
doing an eval of a string that calls a sorting function with our input as parameters.
We tried giving the sorting algorithm an array as input and closing the function, so we can write custom code that will
give us a different input because the sorting does not have any return echoed.
Here is our process:

![img.png](/images/defcamp_quals_2023/web4.png)

![img.png](/images/defcamp_quals_2023/web5.png)

So what we have gathered, This is a RCE with an injection like payload, due to the comments at the end, the errors we
received managed to tell us how to close the function that had our input wrapped into it, thus having no syntax error.
So our we now need to simply find the flag. The index.php file said that the flag.php had the flag, when inspecting it
we see no commented code, surely the page must have the flag inside its code, so we try echoing the file contents, thus
arriving at the final payload.

![img.png](/images/defcamp_quals_2023/web6.png)

### Flag

`ctf{38754723ac2ce496f98359fc7f0acdea211269d812a3f4d30e779bc2aae6565`

