---
title: bbsqli
date: 2024-05-27T14:51:02+03:00
description: Writeup for bbsqli [L3akCTF]
type: writeup
author: Hust
tags:
- web
- sqli
draft: false
---

## Challenge Description

SO Classic !

## Intuition

Automated tools like sqlmap or bruteforcing are not allowed for this challenge. 

This challange involves a flask application where the login function does not use a prepared statement and it uses a raw query, vulnerable to sql injection.
For now, this looks like an easy sql injection challange, but the twist is this code section:

```python
if user and user['username'] == username and user['password'] == hash_password(password):
    session['username'] = user['username']
    session['email'] = user['email']
    return redirect(url_for('dashboard'))
```
Where it checks if the username of the user found is the same as the username we submitted in the form, so if we just send the payload as username value, it will not match.

Since bruteforcing, including time based or error based sql injection is not allowed, my idea was to create a user with the same username as the payload. 

## Solution

1. **Crafting the payload**

    ```sql
    hust1" or password="57ba172a6be125cca2f449826f9980caa" UNION SELECT (select username from users where password="57ba172a6be125cca2f449826f9980ca") as username, flag, '57ba172a6be125cca2f449826f9980ca' FROM flags WHERE id=1--
    ```
    
    This statement uses a UNION query which:
    1. Selects the username of the user we created, so the username is in the last row which will be checked
    2. Selects the flag instead of the email, so the flag will be set in the `session['email']` available to retrieve
    3. Selects the password of the user we created
    
    The result will look something like this:
    
    | username     | email | password |
    |--------------|-------|----------|
    | payload      | email | password |
    | payload      | flag  | password |
    
    The row that will be checked against the username and password will be the second row, and it will set the session email to the flag value. A

2. **Registering the user**

    Register an user with the username equal to the payload above. 

3. **Execute the payload**

    Login with the username (payload), after the login, the page displays the user data set in the session variables, including the email which takes the value of the flag.

### Flag

`L3ak{__V3RY_B4S1C_SQLI}`

