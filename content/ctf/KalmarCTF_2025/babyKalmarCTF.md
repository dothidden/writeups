---
title: babyKalmarCTF
date: 2025-03-10T03:10:19+03:00
description: Writeup for babyKalmarCTF [KalmarCTF 2025]
type: writeup
author: h3pha
tags:
- misc
draft: false
---
___

## Challenge Description

Ever played a CTF inside a CTF?

We were looking for a new scoring algorithm which would both reward top teams for solving super hard challenges, but also ensure that the easiest challenges wouldn't go to minimum straight away if more people played than we expected.

Thats when we came across this ingenious suggestion! https://github.com/sigpwny/ctfd-dynamic-challenges-mod/issues/1

We've implemented it this scoring idea(see here: https://github.com/blatchley/ctfd-dynamic-challenges-mod ) and spun up a small test ctf to test it out.

If you manage to win babykalmarCTF, we'll even give you a flag at /flag!

Spin up your own personal babykalmarCTF here: https://lab1.kalmarc.tf/

Note: Rather than each member starting their own, we encourage one person to make a remote for your team, and then share the link with everyone else! Please be nice to instances, getting flag doesn't involve heavy compute/"hacking CTFd" or abuse on remote.
Its solvable through very normal interactions with a CTFd instance. We encourage the whole team working together on the same remote.

## Intuition

After analyzing the links provided, I saw that the points for the completed challenges are based on the number of teams paying the CTF. So if we manage to create a lot of teams we can increase the points for each challenge.

## Solution


Create users with this script:
```python
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time

url = "https://4ff92cbb806a6203161d7da5b1400ac4-39338.inst1.chal-kalmarc.tf/"

driver = webdriver.Chrome()

for i in range(0, 100):
    driver.get(url + "register")
	time.sleep(0.5)
	
	# create user
    driver.find_element(By.NAME, "name").send_keys(str(i))
    driver.find_element(By.NAME, "email").send_keys(str(i) + "@a.a")
    driver.find_element(By.NAME, "password").send_keys(str(i))
    driver.find_element(By.ID, "_submit").click()
    time.sleep(0.3)

	# create team
    driver.get(url + "/teams/new")
    time.sleep(0.3)

    driver.find_element(By.NAME, "name").send_keys(str(i))
    driver.find_element(By.NAME, "password").send_keys(str(i))
    driver.find_element(By.ID, "_submit").click()
	time.sleep(0.3)
    
    driver.get(url + "/logout")
    time.sleep(0.3)

driver.quit()
```

I let the script create around 100 teams.

Solved the challenges inside the babyCTF:

Welcome challenge: `babykalmar{welcome_to_babykalmar_CTF}`

Rev challenge: `babykalmar{string_compare_rev_ayoooooooo}`

Misc challenge: `BABYKALMAR{SUPERORIGINALMORSECODECHALLENGE}`

Crypto challenge: `babykalmar{wow_you_are_an_rsa_master!!!!!}`

OSINT challenge: `babykalmar{aarhus}`

And got the flag at `/flag`.

### Flag

`kalmar{w0w_y0u_b34t_k4lm4r_1n_4_c7f?!?}`

## Additional

For RSA challenge:
```python
import math
from Crypto.Util.number import long_to_bytes

n1 = 92045071469462918382808444819504749563961839349096597384482544087908047186245341810642171828493439415203636331750819922984117530107215197072782880474039650967711411408034481971170502798025943494586125686145145275611434604037182033168196599652119558449773401870500131970644786235514317736653798125756404891127
c1 = 83837022114533675382122799116377123399567305874353525217531313052347013266429457590484976944405567987615711918756165213164809141929523845319047846779529628627662566542055574929528850262048285117600900265045865263948170688845876052722196561247534915037323009007843324908963180407442831108561689170430284682827
n2 = 138872353325175299307460237192549876070806082965466021111327520189900415231224864814489473847190673904249096844311163666118481717154197936898625500598207447786178788728989474031735348581801399821380599701957041743964351118199095341359179067904834006929292304447601473687076874217599854120530320878903822568483
n3 = 96873643524161216047523283610645732806192956944624208819078561364455621631633510067022852244593247313195537163455457833157440906743895116798782534912117642844197952559448815829606193149605373700004399064513744456542191695589096233791113561406431990041145854326610075794048654641871205275800952496149515217589
e = 65537

# Factor the moduli using GCD
q = math.gcd(n1, n2)
p = n1 // q
r = n2 // q

assert p * r == n3, "Factorization failed"

# Compute private exponent for n1
phi_n1 = (p - 1) * (q - 1)
d1 = pow(e, -1, phi_n1)

# Decrypt the flag
m = pow(c1, d1, n1)
flag = long_to_bytes(m)

print(flag.decode())
```
