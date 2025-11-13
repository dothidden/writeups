---
title: 2.project_chimera
type: writeup
date: 2025-10-01T18:42:50+02:00
description: Writeup for project_chimera [FlareOn 2025]
author: PineBel
tags:
- rev
draft: false
---


For the second challenge we receive a python file only.
The file is pretty small:

```py
# These are my encrypted instructions for the Sequencer.
encrypted_sequencer_data = b'x\x9cm\x96K\xcf\xe2\xe6\x15.....' # this is longer

print(f"Booting up {f"Project Chimera"} from Dr. Khem's journal...") # apperently this exists to indicate that a version of Python 3.12+ should be used, I didn't have this issue though

# Activate the Genetic Sequencer. From here, the process is automated.
sequencer_code = zlib.decompress(encrypted_sequencer_data)
exec(marshal.loads(sequencer_code)) # load bytecode and execute
```
 
So basically what we get is some bytecode which is then loaded and executed.

If we try to run it we get some errors that some libraries are missing.
To have an idea what the code does we can just look at the dissasembled code with dis (dis.dis(marshal.loads(sequencer_code))).

If we look at the disassembled bytecodes we get:
```py
  0           0 RESUME                   0

  2           2 LOAD_CONST               0 (0)
              4 LOAD_CONST               1 (None)
              6 IMPORT_NAME              0 (base64)
              8 STORE_NAME               0 (base64)

  3          10 LOAD_CONST               0 (0)
             12 LOAD_CONST               1 (None)
             14 IMPORT_NAME              1 (zlib)
             16 STORE_NAME               1 (zlib)

  4          18 LOAD_CONST               0 (0)
             20 LOAD_CONST               1 (None)
             22 IMPORT_NAME              2 (marshal)
             24 STORE_NAME               2 (marshal)

  5          26 LOAD_CONST               0 (0)
             28 LOAD_CONST               1 (None)
             30 IMPORT_NAME              3 (types)
             32 STORE_NAME               3 (types)

  8          34 LOAD_CONST               2 (b'..') # again a lot of bytes
             36 STORE_NAME               4 (encoded_catalyst_strand)

 10          38 PUSH_NULL
             40 LOAD_NAME                5 (print)
             42 LOAD_CONST               3 ('--- Calibrating Genetic Sequencer ---')
             44 CALL                     1
             52 POP_TOP

 11          54 PUSH_NULL
             56 LOAD_NAME                5 (print)
             58 LOAD_CONST               4 ('Decoding catalyst DNA strand...')
             60 CALL                     1
             68 POP_TOP

 12          70 PUSH_NULL
             72 LOAD_NAME                0 (base64)
             74 LOAD_ATTR               12 (b85decode) # decoding
             94 LOAD_NAME                4 (encoded_catalyst_strand)
             96 CALL                     1
            104 STORE_NAME               7 (compressed_catalyst)

 13         106 PUSH_NULL
            108 LOAD_NAME                1 (zlib)
            110 LOAD_ATTR               16 (decompress)
            130 LOAD_NAME                7 (compressed_catalyst)
            132 CALL                     1
            140 STORE_NAME               9 (marshalled_genetic_code)

 14         142 PUSH_NULL
            144 LOAD_NAME                2 (marshal)
            146 LOAD_ATTR               20 (loads)
            166 LOAD_NAME                9 (marshalled_genetic_code)
            168 CALL                     1
            176 STORE_NAME              11 (catalyst_code_object)

 16         178 PUSH_NULL
            180 LOAD_NAME                5 (print)
            182 LOAD_CONST               5 ('Synthesizing Catalyst Serum...')
            184 CALL                     1
            192 POP_TOP

 19         194 PUSH_NULL
            196 LOAD_NAME                3 (types)
            198 LOAD_ATTR               24 (FunctionType)
            218 LOAD_NAME               11 (catalyst_code_object)
            220 PUSH_NULL
            222 LOAD_NAME               13 (globals)
            224 CALL                     0
            232 CALL                     2
            240 STORE_NAME              14 (catalyst_injection_function)

 22         242 PUSH_NULL
            244 LOAD_NAME               14 (catalyst_injection_function)
            246 CALL                     0
            254 POP_TOP
            256 RETURN_CONST             1 (None)
```

So we can see that the code contains another part where bytecode is loaded. We can just take the bytes from `encoded_catalyst_strand` and apply the same process as the original script, but we also need to decode the bytes with `b85decode`.

```py
import base64, zlib, marshal, dis

second_bytecode = b'c$|e+O>7&-6`m!Rz....'
second_bytecode = base64.b85decode(second_bytecode)
second = zlib.decompress(second_bytecode)
print(dis.dis(marshal.loads(second)))
```

We now have access to the full disassembled bytecode.
It's pretty long so I won't paste it in here.

This could also be done more elegantly (from the official writeup) like this:
```py
import zlib, marshal, importlib

encrypted_sequencer_data = (
    b'x\x9cm\x96K\xcf\xe2\xe6\x15\xc7\xfd\xcedf\x92\xe6\xd2J\x93\xce...'
)
decompressed = zlib.decompress(encrypted_sequencer_data)
co = marshal.loads(decompressed)

# Convert marshal code object `co` to a .pyc file
# See: https://stackoverflow.com/a/73454818/6245337
pyc_data = importlib._bootstrap_external._code_to_timestamp_pyc(co)

# Write .pyc file to disk
with open("payload1.pyc", "wb") as f:
    f.write(pyc_data)
```

After that you can use a decompiler like `pycdc` to get a nicer, readable source.

We can see that it imports several non-standard modules (emoji, cowsay, etc.). After installing them, we find the challenge goal: log in as an admin.
```py
16           6 LOAD_CONST               1 (b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS')
              8 STORE_FAST               0 (LEAD_RESEARCHER_SIGNATURE)

 17          10 LOAD_CONST               2 (b'r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90')
             12 STORE_FAST               1 (ENCRYPTED_CHIMERA_FORMULA)

    ...

 22          58 LOAD_GLOBAL              3 (NULL + os)
             68 LOAD_ATTR                4 (getlogin)
             88 CALL                     0
             96 LOAD_ATTR                7 (NULL|self + encode)
            116 CALL                     0
            124 STORE_FAST               2 (current_user)

 25         126 LOAD_GLOBAL              9 (NULL + bytes)
            136 LOAD_CONST               5 (<code object <genexpr> at 0x772c353ccc30, file "<catalyst_core>", line 25>)
            138 MAKE_FUNCTION            0
            140 LOAD_GLOBAL             11 (NULL + enumerate)
            150 LOAD_FAST                2 (current_user)
            152 CALL                     1
            160 GET_ITER
            162 CALL                     0
            170 CALL                     1
            178 STORE_FAST               3 (user_signature)


....
 32         254 LOAD_FAST                3 (user_signature)
            256 LOAD_FAST                0 (LEAD_RESEARCHER_SIGNATURE)
            258 COMPARE_OP              40 (==)
            262 POP_JUMP_IF_FALSE      112 (to 488)

 33         264 LOAD_GLOBAL             17 (NULL + art)
            274 LOAD_ATTR               18 (tprint)
            294 LOAD_CONST               8 ('AUTHENTICATION   SUCCESS') # the goal
            296 LOAD_CONST               9 ('small')
            298 KW_NAMES                10 (('font',))
            300 CALL                     2
            308 POP_TOP

...
 37         354 LOAD_GLOBAL             21 (NULL + ARC4)
            364 LOAD_FAST                2 (current_user)
            366 CALL                     1
            374 STORE_FAST               5 (arc4_decipher)

 38         376 LOAD_FAST                5 (arc4_decipher)
            378 LOAD_ATTR               23 (NULL|self + decrypt)
            398 LOAD_FAST                1 (ENCRYPTED_CHIMERA_FORMULA)
            400 CALL                     1
            408 LOAD_ATTR               25 (NULL|self + decode)
            428 CALL                     0
            436 STORE_FAST               6 (decrypted_formula)
```

So the idea would be to see how the `current_user` is transformed in the `user_signature` so that we can reverse that process. The transformation is done through a generator which is defined as:

```py
Disassembly of <code object <genexpr> at 0x772c353ccc30, file "<catalyst_core>", line 25>:
 25           0 RETURN_GENERATOR
              2 POP_TOP
              4 RESUME                   0
              6 LOAD_FAST                0 (.0)
        >>    8 FOR_ITER                15 (to 42)
             12 UNPACK_SEQUENCE          2
             16 STORE_FAST               1 (i)
             18 STORE_FAST               2 (c)
             20 LOAD_FAST                2 (c)
             22 LOAD_FAST                1 (i)
             24 LOAD_CONST               0 (42)
             26 BINARY_OP                0 (+)
             30 BINARY_OP               12 (^)
             34 YIELD_VALUE              1
             36 RESUME                   1
             38 POP_TOP
             40 JUMP_BACKWARD           17 (to 8)
```

To not manually revert this, I gave it to GPT which did a pretty good job in converting the disassembled code into source code.
After a couple of prompts I got the correct result of the generator expression:
```py
user_signature = bytes( (c ^ (i + 42)) for i, c in enumerate(current_user))
```

Since we know that the `user_signature` should match `LEAD_RESEARCHER_SIGNATURE`, we just need to reverse the xor operation.
Which is:
```py
goal = bytes( (c ^ (i + 42)) for i, c in enumerate(LEAD_RESEARCHER_SIGNATURE)) 
```

We then get that the current user name should be:`G0ld3n_Tr4nsmut4t10n`.

We can then just replace the login name with the one computed earlier (`os.getlogin = lambda: "G0ld3n_Tr4nsmut4t10n"`) and we get the flag.