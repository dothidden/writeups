---
title: "Do You Hunt 2"
date: 2023-05-24T22:15:11+03:00
tags:
  - threat hunting
type: writeup
author: H0N3YP0T
---

```python
def convert_to_ascii(file_path):
    with open(file_path, 'r') as file:
        data = file.read()

    numbers = [int(line.split('#')[-1]) for line in data.split('\n') if '#' in line]
    ascii_chars = [chr(num) for num in numbers]

    result = ''.join(ascii_chars)
    print(result)


# Provide the path to the text file
file_path = 'do-you-hunt2-final'
convert_to_ascii(file_path)
```
