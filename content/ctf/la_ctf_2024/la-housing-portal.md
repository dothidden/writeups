---
title: La-Housing-Portal
date: 2024-02-18T20:05:09+02:00
description: Writeup for La-Housing-Portal [LA CTF 2024]
type: writeup
author: H0N3YP0T
tags:
- web
draft: false
---
___

## Challenge Description

Portal Tips Double Dashes ("--") Please do not use double dashes in any text boxes you complete or emails you send through the portal. The portal will generate an error when it encounters an attempt to insert double dashes into the database that stores information from the portal.

Also, apologies for the very basic styling. Our unpaid LA Housing(tm) RA who we voluntold to do the website that we gave FREE HOUSING for decided to quit - we've charged them a fee for leaving, but we are stuck with this website. Sorry about that.

Please note, we do not condone any actual attacking of websites without permission, even if they explicitly state on their website that their systems are vulnerable.

## Intuition

The website is a simple one, we can enter our username and then choose among different values in a dropdown menu and the site will return
a table with a list of match. I try to edit the parameter in Burp Suite in order to perfom an SLQ injection it seems that the website is vulnerable to it.
Furthermore, the challenge description gives us a hint about the `--` character which is the comment character in SQL.

![welcome](/images/la_ctf_2024/housing.png)

![table](/images/la_ctf_2024/housing_table.png)

## Solution

If I try to make a basic SQL injection by using the `--` character, I can see that the website return a special page:

![hacker](/images/la_ctf_2024/hacker.png)

Unfortunately the `/*` character is also blocked so the only solution is to finish the query to make it a valid one. Let's open the code:

```py
@app.route("/submit", methods=["POST"])
def search_roommates():
    data = request.form.copy()

    if len(data) > 6:
        return "Invalid form data", 422
    
    
    for k, v in list(data.items()):
        if v == 'na':
            data.pop(k)
        if (len(k) > 10 or len(v) > 50) and k != "name":
            return "Invalid form data", 422
        if "--" in k or "--" in v or "/*" in k or "/*" in v:
            return render_template("hacker.html")
        
    name = data.pop("name")

    
    roommates = get_matching_roommates(data)
    return render_template("results.html", users = roommates, name=name)
    

def get_matching_roommates(prefs: dict[str, str]):
    if len(prefs) == 0:
        return []
    query = """
    select * from users where {} LIMIT 25;
    """.format(
        " AND ".join(["{} = '{}'".format(k, v) for k, v in prefs.items()])
    )
    print(query)
    conn = sqlite3.connect('file:data.sqlite?mode=ro', uri=True)
    cursor = conn.cursor()
    cursor.execute(query)
    r = cursor.fetchall()
    cursor.close()
    return r
```

The original query is the following: `select * from users where {} LIMIT 25;` and in order to escape it I can transform it in the following query:

![payload](/images/la_ctf_2024/sql_housing.png)

The final payload is the following is `'+UNION+SELECT+1,*,3,4,5,6+FROM+flag+WHERE+''='`

![flag](/images/la_ctf_2024/housing_flag.png)


### Flag

`lactf{us3_s4n1t1z3d_1npu7!!!}`


