---
title: "Ipv6 Evil"
type: writeup
date: 2023-05-24T22:00:43+03:00
tags:
  - network
author: H0N3YP0T
---

* Open the ipv6Evil capture with wireshark
* The challenge description and title give us good hints:
    * DNS Buffer Overflow is not for everyone !
    * Ipv6 evil
* We can deduce that we need to look to a bad ipv6 request that causes DNS buffer overflow
* Use the filter ipv6 and sort the result by size ( a buffer overflow packet is supposed to have a large and unusual
  size due to the added padding
* Check every result by starting from the heaviest packet
* Check the ASCII result of each packet you should see some unusual results with a lot of "A"
* Unfortunately the first one is not the right flag see image

![wireshark capture](/images/unbreakable_2023/ipv6_evil/wireshark_capture.png)

* Continue to check the others
* By going from the heaviest to the lightest packet we notice some other unusual strings:

![img1](/images/unbreakable_2023/ipv6_evil/img1.png)
![img2](/images/unbreakable_2023/ipv6_evil/img2.png)
![img3](/images/unbreakable_2023/ipv6_evil/img3.png)

* If we concate all those strings we get: We_Ar3_N0t_th3_Same what makes sense
* Now do not forget to encrypt it with sha256 and now you got the flag

![cyber chef encode](/images/unbreakable_2023/ipv6_evil/cyberchef.png)
