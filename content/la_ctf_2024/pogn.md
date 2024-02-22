---
title: Pogn
date: 2024-02-22T01:42:10+02:00
description: Writeup for Pogn [LA CTF 2024]
author: sunbather
tags:
- web
draft: false
---
___

## Challenge Description

Pogn in mong.

pogn.chall.lac.tf

## Intuition

We have a Pong game where one paddle is controlled by the client user and the other by the server script. Naturally, the server paddle always follows the ball with enough speed to never miss it. Looking throught the client code, we can see that the entire game is mirrored on it, while the real game state is maintained on the server-side.

```js
// CLIENT CODE
// basic number ops
const min = (a, b) => (a < b) ? a : b;
const max = (a, b) => (a > b) ? a : b;
const clamp = (x, low, high) => min(max(x, low), high);

const Msg = {
  GAME_UPDATE: 0,
  CLIENT_UPDATE: 1,
  GAME_END: 2
};

const serverToViewport = ([x, y]) => [
  x * innerWidth / 100,
  (y + 30) * 0.5 * innerHeight / 30
];

const viewportToServer = ([x, y]) => [
  x * 100 / innerWidth,
  y * 30 / (0.5 * innerHeight) - 30
];

let ballPos = [50, 0];
let userPos = [0, innerHeight / 2];
let serverPos = [100, 0];

const wsurl = new URL('https://pogn.chall.lac.tf');
wsurl.protocol = 'wss'
wsurl.pathname = '/ws';

const ws = new WebSocket(wsurl);

ws.addEventListener('open', () => {
  ws.addEventListener('message', (e) => {
    const msg = JSON.parse(e.data);
    switch (msg[0]) {
      case Msg.GAME_UPDATE:
        ballPos = serverToViewport(msg[1][0]);
        serverPos = serverToViewport(msg[1][1]);
        updateFromRemote();
        break;
      case Msg.GAME_END:
        alert(msg[1]);
        break;
    }
  })

  const interval = setInterval(() => {
    if (!moved) return;
    ws.send(JSON.stringify([
      Msg.CLIENT_UPDATE,
      [ userPos, v ]
    ]));
  }, 50);

  ws.addEventListener('close', () => clearInterval(interval));
});

const $ = x => document.querySelector(x);

const userPaddle = $('.user.paddle');
const serverPaddle = $('.server.paddle');
const ball = $('.ball');

let moved = false;
let p_x = 0;
let p_y = 0;
let v = [0, 0];
window.addEventListener('mousemove', (e) => {
  moved = true;
  const x = clamp(e.clientX, 0, innerWidth / 2 - 48);
  const y = e.clientY;
  userPaddle.style = `--x: ${x}px; --y: ${y}px`;
  userPos = viewportToServer([ x, y ]);
  v = viewportToServer([0.01 * (x - p_x), 0.01 * (y - p_y)]);
  p_x = x;
  p_y = y;
});

const updateFromRemote = () => {
  ball.style = `--x: ${ballPos[0]}px; --y: ${ballPos[1]}px`;
  serverPaddle.style = `--x: ${serverPos[0]}px; --y: ${serverPos[1]}px`;
};

```
In the event listeners for the websocket, we can see that the only inputs we can control and send to the game server are the user position and the velocity of the paddle. But how to win the game? After looking closely through the server code, I couldn't come up with anything... The only thing that seemed interesting was the fact that the velocity of the user paddle affects the speed of the ball. Also, the ball position is updated AFTER the server paddle and BEFORE the win condition check. So I thought that, if the ball speed is high enough it will teleport directly after the server paddle and win. Here is the server code, with comments from me denoted with ``SUNBATHER``:

```js
const express = require('express');
const expressWs = require('express-ws');
const path = require('path');
const fs = require('fs');

const flag = process.env.FLAG || 'lactf{test_flag}';

const app = express();

expressWs(app);

app.use('/assets', express.static(path.join(__dirname, '../assets')));
app.use('/', express.static(__dirname));

app.ws('/ws', (ws, req) => {
  const yMax = 30;
  const collisionDist = 5;
  const Msg = {
    GAME_UPDATE: 0,
    CLIENT_UPDATE: 1,
    GAME_END: 2
  };

  // game state
  let me = [95, 0];    // my paddle position
  let op = [0, 0];     // user's paddle position
  let opV = [0, 0];    // user's paddle velocity
  let ball = [50, 0];  // balls location
  let ballV = [+5, 0]; // balls speed

  // basic number ops
  const min = (a, b) => (a < b) ? a : b;
  const max = (a, b) => (a > b) ? a : b;
  const clamp = (x, low, high) => min(max(x, low), high);

  // vector ops
  const add = ([x1, y1], [x2, y2]) => [x1 + x2, y1 + y2];
  const sub = ([x1, y1], [x2, y2]) => [x1 - x2, y1 - y2];
  const mul = ([x1, y1], k) => [k * x1, k * y1];
  const bmul = ([x1, y1], [x2, y2]) => [x1 * x2, y1 * y2];
  const norm = ([x, y]) => Math.sqrt(x ** 2 + y ** 2);
  const normalize = (v) => mul(v, 1 / norm(v));

  // validation
  const isNumArray = (v) => Array.isArray(v) && v.every(x => typeof x === 'number');

  let prev = Date.now();
  const interval = setInterval(() => {
    try {
      const dt = (Date.now() - prev) / 100;
      prev = Date.now();

      // move server's paddle to be same y as the ball
      me[1] = ball[1];

      // give ball some movement if it stagnates
      if (Math.abs(ballV[0]) < 0.5) {
        ballV[0] = Math.random() * 2;
      }

      // collision with user's paddle
	  // SUNBATHER: I thought this was super interesting because you
	  //            can influence the ball speed with a parameter that
	  //            the client side controls
      if (norm(sub(op, ball)) < collisionDist) {
        ballV = add(opV, mul(normalize(sub(ball, op)), 1 / norm(ballV)));
      }

      // collision with server's paddle
      if (norm(sub(me, ball)) < collisionDist) {
        ballV = add([-3, 0], mul(normalize(sub(ball, me)), 1 / norm(ballV)));
      }
	
      // update ball position
	  // SUNBATHER: Then you can jump directly to the end
	  //            in theory. But you need high nummbers.
      ball[0] += ballV[0] * dt;
      ball[1] += ballV[1] * dt;

      // wall bouncing
      if (ball[1] < -yMax || ball[1] > yMax) {
        ball[1] = clamp(ball[1], -yMax, yMax);
        ballV[1] *= -1;
      }

      // check if there has been a winner
      // server wins
      if (ball[0] < 0) {
        ws.send(JSON.stringify([
          Msg.GAME_END,
          'oh no you have lost, have you considered getting better'
        ]));
        clearInterval(interval);

      // game still happening
      } else if (ball[0] < 100) {
        ws.send(JSON.stringify([
          Msg.GAME_UPDATE,
          [ball, me]
        ]));

      // user wins
      } else {
        ws.send(JSON.stringify([
          Msg.GAME_END,
          'omg u won, i guess you considered getting better ' +
          'here is a flag: ' + flag,
          [ball, me]
        ]));
        clearInterval(interval);
      }
    } catch (e) {}
  }, 50); // roughly 20fps

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      if (msg[0] === Msg.CLIENT_UPDATE) {
        const [ paddle, paddleV ] = msg[1];
        if (!isNumArray(paddle) || !isNumArray(paddleV)) return;
        op = [clamp(paddle[0], 0, 50), paddle[1]];
		// SUNBATHER: User velocity is normalized.
		//            Eternal sadness.
        opV = mul(normalize(paddleV), 2);
      }
    } catch (e) {}
  });

  ws.on('close', () => clearInterval(interval));
});

app.listen(3000);
```
Sadly, as seen in my last comment, the user velocity is normalized, which only after refreshing a bit on vector math I realized can't have crazy numbers. So I read and re-read the entire thing and thought about what to do.

As a fun fact: This CTF I used ChatGPT a lot more than in others (which means I used it more than 0 times). I found it mostly useless, which is funny because when it first came out it helped us with one particular complex task pretty nicely. But now it wasn't able to even see the vulnerability in this code, which I think it should have been able to see, as it's not an uncommon one in Javascript and even Python.

## Solution

Weird/impossible math usually ends up with weird results. To cover these cases, Javascript and Python (and probably others too) have a special value for it, ``NaN``. When you start using ``NaN``, things get weird, your comparisons won't evaluate as expected. But how do you get to ``NaN``? Just do impossible math. Take a look at the number ops:
```js
  const add = ([x1, y1], [x2, y2]) => [x1 + x2, y1 + y2];
  const sub = ([x1, y1], [x2, y2]) => [x1 - x2, y1 - y2];
  const mul = ([x1, y1], k) => [k * x1, k * y1];
  const bmul = ([x1, y1], [x2, y2]) => [x1 * x2, y1 * y2];
  const norm = ([x, y]) => Math.sqrt(x ** 2 + y ** 2);
  const normalize = (v) => mul(v, 1 / norm(v));
```

What if ``norm(v)`` was 0? We can do that by passing a ``[0, 0]`` vector for our paddle velocity, to mess up this line: ``opV = mul(normalize(paddleV), 2);``.

Then, when the ball collides with the paddle, its position will turn into ``NaN``, which will evaluate the win condition (``ball[0] >= 100``) to ``true``, giving us the flag. Thanks, division by zero!

To send 0 to the websocket, I modified the original client code to send ``[0, 0]`` as the paddle velocity and also the websocket url to the real url and not localhost, then ran it. I used a simple trick to run it, just embedded into an html file and opened it in browser (Thanks [MettleSphee](https://github.com/MettleSphee/)!)

### Flag

``lactf{7_supp0s3_y0u_g0t_b3773r_NaNaNaN}``
