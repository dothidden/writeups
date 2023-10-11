---
title: Web3
date: 2023-10-11
tags:
  - misc
author: expnx
---

# Web3

Description: Hello Web3!

Challenge Author: ysc

We only have a url with port 3000
We can see the source code for the index page by sending a request to the url

```javascript
const express = require("express");
const ethers = require("ethers");
const path = require("path");

const app = express();

app.use(express.urlencoded());
app.use(express.json());

app.get("/", function (_req, res) {
    res.sendFile(path.join(__dirname + "/server.js"));
});

function isValidData(data) {
    if (/^0x[0-9a-fA-F]+$/.test(data)) {
        return true;
    }
    return false;
}

app.post("/exploit", async function (req, res) {
    try {
        const message = req.body.message;
        const signature = req.body.signature;
        if (!isValidData(signature) || isValidData(message)) {
            res.send("wrong data");
            return;
        }

        const signerAddr = ethers.verifyMessage(message, signature);
        if (signerAddr === ethers.getAddress(message)) {
            const FLAG = process.env.FLAG || "get flag but something wrong, please contact admin";
            res.send(FLAG);
            return;
        }
    } catch (e) {
        console.error(e);
        res.send("error");
        return;
    }
    res.send("wrong");
    return;
});

const port = process.env.PORT || 3000;
app.listen(port);
console.log(`Server listening on port ${port}`);
```

We notice at the beginning that there is an import for ethers.js library which is used for interacting with the Ethereum blockchain

```javascript
function isValidData(data) {
    if (/^0x[0-9a-fA-F]+$/.test(data)) {
    return true;
    }
    return false;
}
```

This method verifies that data is similar to an Ethereum signature

```javascript
app.post("/exploit", async function (req, res) {
    try {
        const message = req.body.message;
        const signature = req.body.signature;
        if (!isValidData(signature) || isValidData(message)) {
            res.send("wrong data");
            return;
        }

        const signerAddr = ethers.verifyMessage(message, signature);
        if (signerAddr === ethers.getAddress(message)) {
            const FLAG = process.env.FLAG || "get flag but something wrong, please contact admin";
            res.send(FLAG);
            return;
        }
    } catch (e) {
        console.error(e);
        res.send("error");
        return;
    }
    res.send("wrong");
    return;
})
};
```

Looking at the code we observe that a message on the Ethereum blockchain is needed, for which the content is its own address.
We log a message and sign it using : https://etherscan.io/verifiedSignatures by connecting a wallet.
Using the address in the request would violate the isValidData function check. Luckily, ethers.getAddress also works on ICAP addresses
which do pass the check in isValidData. We can get the ICAP address using ethers.getIcapAddress(address).
The request should look like this:

```http request
    address: "0xSOMETHING"
    message: "XSOMETHING" (the ICAP form for 0xSOMETHING)
    signature: "0xSIGNATURE" (the signature generated for our message)
```

Sending the POST request with the following body will return the flag

```http request
    "address": "0x2a3052ef570a031400BffD61438b2D19e0E8abef",
    "message": "XE97E4KDO45K5GZ6UCOPEL3T1Z2GOYDAWI9",
    "signature": "0x3b71cd519a6fc7a04c45bd421e1920490bb9530b64a1e2aa8f8fd513e3fbc1ff2d86e8db337d15e75e5ae67894e5886a71db1867d097d77794a7010d56d1e5fe1b",
```