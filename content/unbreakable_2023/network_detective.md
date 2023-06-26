---

title: "Network Detective"
date: 2023-05-24T22:17:09+03:00
tags:
- network
author: H0N3YP0T
---

* Open the network-detective capture with wireshark
* Open the HTTP packet
* We know that HTTP does not encrypt data we should see the following result:

![wireshark capture](/images/unbreakable_2023/network_detective/wireshark.png)

* The X-HERE header is an unusual header furthermore we notice that the data is quiet suspicious and looks like a ROT
  encryption because if we shift from 1 to right, DUG gave is CTF which is the flag format.
* Go to [rot-cipher](https://www.dcode.fr/rot-cipher) and enter the data string
* Select ROT 1 (which is equal to shift one to right)
* Select full ASCII table
* Here you go :)

![get the flag](/images/unbreakable_2023/network_detective/dcode.png)
