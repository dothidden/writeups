---
title: Boze
date: 2023-10-22T18:37:18-04:00
description: Writeup for Boze [Defcamp Quals 2023]
author: Koyossu
tags:
- web
draft: false
---
___

## Challenge Description

How smart and capable is the smarty lib?

## Intuition

This challange was a php RCE jail escape. When you enter the site on the / route you are greeted with the source code of the page. How thoughtful is that :)

![img.png](/images/defcamp_quals_2023/boze2.png)

Upon inspection we can see that the main page behaves differently if we have a param named content. We see that with this parameter we call the display function unsanitized from the smarty library. Upon further investigation online we see that this smarty library, in specific the display function is vulnerable to RCE. We try puting everything in a payload at first. Writing php code to see if we can list the files in the current directory. 

![img.png](/images/defcamp_quals_2023/boze5.png)

As we can see, we see flag.php, surely this is where the flag is. So we only need to get the content of the file. If only there were a php function that did that. Oh wait, there actually is :) 
## Solution
The road to the payload was funny, there actually was a list put in place that we did not see that blocked the execution of some known functions that let you do exec for example. We found this by fuzzing the address and finding a hidden directory where there was a file that explicilty showed a blacklist put in place in php.ini.

The final payload was this `string:{file_get_contents(reset(array_slice(scandir('./'), 4, 1)))}` big shout out to steven from sourincite for the incredibly useful article about smarty, the inner works and the template injection.
Here you can see the article -> https://srcincite.io/blog/2021/02/18/smarty-template-engine-multiple-sandbox-escape-vulnerabilities.html

![img.png](/images/defcamp_quals_2023/bozeFlagFinal.png)


### Flag

Here is the final flag, and a proof from the website :)

![img.png](/images/defcamp_quals_2023/boze1.png)

`ctf{72874605748965cbd4350a538e09abbfb20fbc47a8443addcd5c4adfd57dca79}`
