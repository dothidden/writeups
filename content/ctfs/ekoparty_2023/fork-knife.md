---
title: Fork Knife
type: writeup
date: 2023-11-12T19:56:46+02:00 
description: Writeup for Fork Knife [Ekoparty 2023]
author: Honesty
tags:
- misc
draft: false
---
___

## Challenge Description

You must solve the second challenge to get the answer, all you need is inside the Lobby.

We have access to a GitHub repository with two files and a GitHub action executed for pull requests.

## Intuition

All the necessary information should be within this repository. We start by examining the action file at `.github/workflows/grade.yml`

```yml
on:
  pull_request_target

jobs:
  build:
    name: Grade the test
    runs-on: ubuntu-latest
    steps:

    - uses: actions/checkout@v2
      with:
        ref: ${{ github.event.pull_request.head.sha }}
        
    - name: Run build & tests
      id: build_and_test
      env: 
        EXPECTED_OUTPUT: ${{ secrets.FLAG }}
      run: |
        /bin/bash ./build.sh > output.txt && /bin/bash ./test.sh

    - uses: actions/github-script@v3
      with:
        github-token: ${{secrets.GITHUB_TOKEN}}
        script: |
          github.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: "👋 Your code looks great, good job! You've passed the exam!"
          })
```

## Solution

Before the `run` section, an environment variable `EXPECTED_OUTPUT` is created with the value of our flag.
The `run` section executes two scripts `build.sh` and `test.sh` both present in our repository.

To exploit this, we create a fork of the repository and commit a modified version of `test.sh`.

```sh
echo $EXPECTED_OUTPUT | rev
```

This alteration prints the reversed value of the flag. Reversing it prevents the GitHub action console from detecting and censoring the value.

The console after submitting our new pull request:

![github-action-console-fork-knife](/images/ekoparty_2023/fork-knife-console.png)

The flag is obtained by reversing the value.

### Flag

EKO{pr3v3nt_PWN_r3qu3stS}
