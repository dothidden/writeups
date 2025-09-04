---
title: Soc-Is-Mandatory
type: writeup
date: 2023-10-22T14:06:48+03:00
description: Writeup for Soc-Is-Mandatory [Defcamp Quals 2023]
author: H0N3YP0T
tags:
  - threat hunting
  - incident response
draft: false
---

___

## Challenge Description

You are part of a cybersecurity team working in a state-of-the-art Security Operations Center (SOC). Your SOC has been
tasked with monitoring a critical infrastructure network that includes various servers, databases, and communication
channels. As a SOC analyst, it's your duty to keep this infrastructure secure and ensure that it remains operational.

Early this morning, your team received alerts from the intrusion detection system (IDS) indicating suspicious network
activities. The alerts suggest a potential security incident. Your SOC has just received an official request to
investigate this incident.

**Objective**

Your mission is to identify, analyze, and provide information about the threats inside the affected network.

**Notes**

- the logs dashboard (index-pattern) is soc-is-mandatory
- the logs are from 4 years ago, therefore a timeframe should be set accordignally.

The challenge is divided into **4** questions.

## Provided Files

The challenge provides a link to a Kibana dashboard.

## Question 1

> Provide the IP of the infected host.

### Intuition

For all the questions, we need to set the index
to `soc-is-mandatory*`, put the date filter as `Last 4 years rounded to the year` and use the `Discover` tab.
To find the IP of the infected host, we can use the `source_ip` field and see how many records are there for each IP.
The private IP with the most records is the one we are looking for.

### Solution

Use the `source_ip` field and see how many records are there for each IP. The private IP with the most records is the
one we are looking for.

![ip.png](/images/defcamp_quals_2023/ip.png)

### Flag

`10.0.0.168`

## Question 2

> Provide the name of the malware used to infect the host.

### Intuition

Let's look for some suspicious activity. For our IP by adding the `payload_data` field and start scrolling down.

### Solution

The `payload_data` field contains the payload of the request. We can see that there is a request that contains a
suspicious
url `ckav.ru` and the following data `Admin GSNTPAWQ GSNTPAWQ`. If we google this url we can find the malware name.

![ckav.png](/images/defcamp_quals_2023/ckav.png)

![loki.png](/images/defcamp_quals_2023/loki.png)

### Flag

`loki`

## Question 3

> Provide the malicious URL path which was the start point of the infection.

### Intuition

I have to search for an HTTP request that looks suspicious after the date of the request I found
in [question 2](#question-2).

### Solution

The request is the second log above the request from [question 2](#question-2). The request is a POST method with
the `Mozilla/4.08 (Charon; Inferno)` user-agent
as described in the following [doc](https://unit42.paloaltonetworks.com/lokibot-spike-analysis/) of the `loki` malware.

![request.png](/images/defcamp_quals_2023/request.png)

### Flag

`/~element/page.php?id=484`

## Question 4

> Provide the time when the first malicious request was sent.

### Intuition

I have to copy the `timestamp` field of the malicious request from [question 3](#question-3).

### Solution

This one is very easy but tricky because the correct answer is not the timestamp of the first request but the time (
hour, minute, second and millisecond) of the first request.

### Flag

`20:36:44.000`

