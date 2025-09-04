---
title: woauth a laundry
type: writeup
date: 2024-05-09T13:39:57+03:00
description: Writeup for woauth a laundry [openECSC 2024 (2nd Round)]
author: zenbassi
tags:
- web
---
___

## Challenge Description

Welcome to our innovative business, the only ONE Laundry capable of completely sanitize your clothing by removing 100% of bacteria and viruses.

Flag is in /flag.txt.

Site: http://woauthalaundry.challs.open.ecsc2024.it

## Intuition

I'm not good with web challenges, so I was very proud when I solved this challenge, even though it was one of most solved.

After logging in, I inspected the session storage. There, I immediately noticed an admin entry with the value 0. Setting its value to 1 revealed an `/admin` page with a `Generate Report` button. Pressing the button generates a POST request. After getting a response with status code `401` Unauthorised, I assumed our user does not have enough privileges. I logged out, and more carefully inspected the login process.

The login consists of two requests:
* first, a request to `/api/v1/creds`, which acquires the `client_id` and the `client_secret`
* followed by a request to `/openid/authentication`, which authenticates the user with the given `client_id` for the given `scope` list.

That scope list seemed interesting. By default, it is populated with `openid laundry amenities`. Since we desire access to a feature of the `/admin` page I intercepted the request, updated the scope list to `openid laundry amenities admin` and forwarded it. The session obtained in this manner indeed gave me access to the `Generate Report` request, which returns a PDF.

We also notice a `GET` request to `/api/v1/admin` which returns some docs of the `generate_report` request:

```json
{"admin_endpoints":[{"exampleBody":{"requiredBy":"John Doe"},"methods":["POST"],"path":"/generate_report"}]}
```

Now we're talking! The POST request made to `/generate_report` accepts an optional parameter `requiredBy`. By default, the request is made without this optional parameter, and as a result the PDF file holds the text _Required by Anonymous_. Sending the request including the `requiredBy` key with some value of our own generates the PDF with the respective value rendered in the PDF.

We just have to figure out a method read the flag from the disk and load its value into the PDF.

## Solution

After some trial and error, I ruled out any SSTI. Inputting an HTML tag lead to it being correctly parsed, so I assumed we're dealing with a Server Side XSS. I got the flag by filling the `requiredBy` field with `<object data=\"/flag.txt\"></object>`.

### Flag

`openECSC{On3_l4uNdrY_70_ruL3_7h3m_4l1!_d208a530}`
