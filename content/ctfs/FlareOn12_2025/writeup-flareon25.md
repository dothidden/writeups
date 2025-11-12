---
title: FlareOn 
type: writeup
date: 2025-10-01T18:42:50+02:00
description: Writeup for FlareOn [FlareOn 2025]
author: PineBel
tags:
- rev
draft: false
---

# Challenge 1 (Drill Baby Drill!)

The first challenge in Flare-On starts with a game where the source code is provided.

>This game is written in PyGame. It is about a baby trying to drill to recover its lost teddy bears.
The source code is provided, along with a runnable PyInstaller EXE file.

When running the game, we can see that we control a baby who can move horizontally and drill downward. If we hit a rock with the drill, it's game over. The goal is to find the teddy bears without hitting the rocks.

I solved this challenge in a lazy way. Afterwards, I felt bad about it and also solved it using the intended method.

### The lazy solve

Since we have access to the source code, we can just print the boulder layout and avoid them.

```py
background_tiles = BuildBackground()
player = DrillBaby(7, 2, max_drill_level)
boulder_layout = []
for i in range(0, tiles_width):
    if (i != len(LevelNames[current_level])):
        boulder_layout.append(random.randint(2, max_drill_level))
    else:
        print("Placing bear at: " + str(i) + LevelNames[current_level])
        boulder_layout.append(-1) # no boulder
print("Boulder Layout: " + str(boulder_layout))
```

This is easy to do since we also have the index of the baby displayed in the UI. 
After you do this for all the levels, you get the flag.

### Intended way

If we actually read the source code, there is a function that generates the flag. That function just XORs an encoded string with a sum, which is passed as a parameter to the function.  
We could:  
 a) try to brute-force it (which I didn't),  
 b) see how the sum is created.  

If we trace the sum, we can see that it's created in the following way:  

```py
flag_text = GenerateFlagText(bear_sum)
if player.hitBear():
    player.drill.retract()
    bear_sum *= player.x
```

So the flag is created by multiplying the position of the baby when it hits a rock.  
A bear represents the value -1 in the boulder array:  

```py
for i in range(0, tiles_width):
    if (i != len(LevelNames[current_level])):
        boulder_layout.append(random.randint(2, max_drill_level))
    else:
        boulder_layout.append(-1)  # no boulder
```

So we can see that the boulders are always placed at the length of the level index.  
We can just compute the sum like this:  

```py
for level in LevelNames:
    print("Level: " + str(len(level)))
    anw *= len(level)
print(f"Sum is {anw}")
```

After that we can just call GenerateFlagText(anw) and we get the flag.  

---

# Challenge 2 (project_chimera)

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

---

# Challenge 3 (pretty_devilish_file)

I didn't really enjoy this challenge since it was pretty guessy.
In this challenge we only receive a PDF file.
To analyse it I used [pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py) and [pdfid.py](https://github.com/Rafiot/pdfid/blob/master/pdfid/pdfid.py).

By running `pdfid.py` we get the information that the pdf has an encrypted section. I initially thought that this was the goal of the challenge but after spending quite some time to understand how that section works I gave up since I couldn't extract anything usefull from it. At least I won a massive rabbit hole lol.

If we analyse the structure of the PDF with `strings` only, it's pretty clear that the pdf is broken:
```
7 0 obj
<</Filter /Standard/V 5/R 6/Length 256/P -1/EncryptMetadata true/CF <</StdCF <</AuthEvent /DocOpen/CFM /AESV3/Length 32>>>>/StrF /StdCF/StmF /StdCF/U (
12Jw)/O (v/
Ll9W`
)/UE (
WHa}?
)/OE (
\\zR
)/Perms (G
trailer <<
  /Root 2 0 R
  /#52#6F#6F#74 1
  % /Size 15
  /Encrypt 7 0 R
```

object 7 doesn't end, there are two roots? really strange.

After my Encrypt side-quest I decided to analyse the 4th object from the PDF since it contained a stream and maybe something was hidden in there.
I also tried multiple tools to analyse the pdf.
After playing around with multiple tools, I found something interesting with `qpdf`:
```
qpdf --show-object=4 --filtered-stream-data pretty_devilish_file.pdf
WARNING: pretty_devilish_file.pdf: file is damaged
WARNING: pretty_devilish_file.pdf: can't find startxref
WARNING: pretty_devilish_file.pdf: Attempting to reconstruct cross-reference table
WARNING: pretty_devilish_file.pdf (trailer, offset 1412): dictionary has duplicated key /Root; last occurrence overrides earlier ones
WARNING: pretty_devilish_file.pdf (object 7 0, offset 1402): expected endobj
WARNING: pretty_devilish_file.pdf (trailer, offset 1410): invalid /ID in trailer dictionary
WARNING: pretty_devilish_file.pdf (object 4 0, offset 915): expected endobj
q 612 0 0 10 0 -10 cm
BI /W 37/H 1/CS/G/BPC 8/L 458/F[
/AHx
/DCT
]ID
ffd8ffe000104a46494600010100000100010000ffdb00430001010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001002501011100ffc40017000100030000000000000000000000000006040708ffc400241000000209050100000000000000000000000702050608353776b6b7030436747577ffda0008010100003f00c54d3401dcbbfb9c38db8a7dd265a2159e9d945a086407383aabd52e5034c274e57179ef3bcdfca50f0af80aff00e986c64568c7ffd9
EI Q 

q
BT
/ 140 Tf
10 10 Td
(Flare-On!)'
ET
Q
```

The stream is a bit strange since there is quite a lot of data without the Flare-On part.
So I gave the code to CyberChef which detected that it was an image.
So I now used `pdfimages` to extract the image from the pdf.
The strange thing about the image was the size 1x37 which lead me to think that maybe the pixels have the flag value.

Using the following command: `convert extracted.jpg text`.
I extracted the pixel intenstities which would fit the ANSI chars.
So I copied the values and decoded them and got the flag.


### Another cool solve
After the competition finished, I read a cool solution which was: 
```
evince pretty_devilish_file.pdf # or any pdf reader
ps aux | grep pretty # get the PID
gcore $pid # this dumps the process memory into a file called core.$pid
strings core.$pid | grep -i '@flare'
```

---

# Challenge 4 (UnholyDragon)

## Cheese
For this challenge we get a Windows executable (`UnholyDragon-150.exe`).  
The first thing we can observe is that the header is malformed (the first byte is incorrect).  
This is easily fixed in a hex editor (I used HxD) by changing the first byte to `0x4D` (`M`).  
We can also use `Detect It Easy` to analyze the binary.

After patching the executable, I decided to do some dynamic analysis with Procmon first.

Strangely, when running it, three other files were created: `UnholyDragon-151.exe` -> `UnholyDragon-154.exe`.  
So I renamed the executable to something else (`a.exe`) and ran it again. This time it generated `UnholyDragon-1.exe` up to `UnholyDragon-150.exe`.  
I patched the 150th copy and then ran `UnholyDragon-150.exe` again, and I got the flag.

## Understanding

After the competition finished, I decided to try to understand the challenge by ~following the official writeup.  
The idea was to first check how the generated binaries are different, so I did this with the following command:

![ch4-byte_differences_from_150_to_154](/images/FlareOn12_2025/ch4-byte_differences_from_150_to_154.png)

If we compare the original file with the other four copies, it seems that the file is cloned: one byte is changed (at a random offset), and then the new binary executes and creates another clone with another changed byte.

Now the interesting part is that we received a corrupted binary, which had the wrong signature.  
What if `UnholyDragon-150.exe` was generated from `UnholyDragon-149.exe`? We can just copy the patched binary and rename it to `UnholyDragon-149` and test it. This indeed works.

Since `UnholyDragon-150.exe` always has a damaged signature, it means that the offsets that change in the binary are generated in a predictable way.

#### Reversing

I decided to RE the binary to find the logic where/how the bytes were modified.

One cool way to get a starting point in RE is by using API Monitor.  
I read about this in the following writeup: https://gist.github.com/superfashi/563425ee96d505c0263373230335e41a

After that, I checked what API calls were made by the binary.

![ch4-api_monitor](/images/FlareOn12_2025/ch4-api_monitor.png)

One interesting chain of API calls were:
* CreateFile
* SetFilePointer
* ReadFile
* SetFilePointer
* WriteFile

I was most interested in the `WriteFile` call since that's most likely the function that changes the bytes in the new binary. This is also a nice shortcut in RE since we can get the address where `WriteFile` is called.

![ch4-api_monitor-writefile](images/FlareOn12_2025/ch4-api_monitor-writefile.png)

The official writeup suggests it's easier to find the main function by searching for the string `"Unholy-"` in Ghidra, which also works. I personally prefer the API Monitor approach because we can see which function called the API and then inspect the function call trees in Ghidra to see where it's referenced.

Since this is written in TwinBASIC, it's a bit difficult to RE.

Basically, I wanted to find how the `SetFilePointer` offset changes and how the buffer for `WriteFile` was constructed.

Some other ideas to make RE easier inspired from [source](https://www.youtube.com/watch?v=syFEZwoI5q4):
* We know that the binary creates multiple copies, so we could search in Ghidra and check what functions use the `CreateProcess` WinAPI. Luckily for us, it's just one. We can go from there and search for the main function.

* By looking at the references of main, we can also see that the address of main is somehow used in the entry. Not really important, but I mentioned this since you can't clearly see from the entry where the call to main is done.

* Compiling a basic TwinBASIC program (the wordplay ;) ) and RE-ing it would also help a lot in skipping useless code lines in Ghidra by comparing the structes of the two programs.

* IDA is a lot better at decompiling TwinBASIC. I mainly RE-ed it in Ghidra, but I was also using IDA at the same time since it's easier to read the pseudocode. This is how I found a weird XOR with a constant which in Ghidra wasn't visible in the decompile panel.

* In x32dbg we can see that if we break on the XOR, the constant value `0x6746` is XORed with `0x96`, which is 150 (I ran this instance with `UnholyDragon_150.exe`).  
So most likely, for the other files, the other XOR values will be the number from the file.

![ch4-xor_x32dbg](/images/FlareOn12_2025/ch4-xor_x32dbg.png)

* Interestingly, we can see that a function is called twice (`FUN_004a86a3`). This takes as the first argument the result of the strange XOR: once for computing the offset to write the byte, and once to compute a value for the XOR.  
Since these values are most likely somehow random, I would assume this is a random function or something similar.


Important part of the main function reversed in Ghidra:

![ch4-ghidra_main](/images/FlareOn12_2025/ch4-ghidra_main.png)

I analyzed this with dynamic analysis and by going from the `WriteFile` WinAPI "up".

So basically what the binary does:

1. Get the number from the current filename and XOR it with `0x6746` (this happens at the weird XOR comment in the Ghidra picture).  
2. Compute the offset for the byte to be changed (also using the result from step 1). This uses a PRNG.  
3. Read the byte from the current file.  
4. XOR the byte from the file with a random key (also using the PRNG from step 2).  
5. Write the new byte into the copied file.

We can actually confirm this by comparing the original binary (first argument from the pic) that we got, with the binary generated from running `a.exe` (meaning that the 150th copy will contain ALL the changes) in the following picture:

![ch4-full-compare](/images/FlareOn12_2025/ch4-full-compare.png)

---

# Challenge 5 (ntfsm)

We get a really big Windows executable in this challenge.  
It's most likely this big because of the jump table:  
![ch5-jumptable](/images/FlareOn12_2025/ch5-jumptable.png)

Initially I found it pretty difficult to RE statically altough dynamic analysis definitely helped a lot.  
Through dynamic analysis you can see that the binary writes to some ADS streams (hence the `ntfs` from the challenge name). These are:

* `state` : represents the index in the jump table. It specifies which branch to jump to.  
* `input` : the user input.  
* `position` : index from the input to check.  
* `transitions` : keeps track of how many characters have been verified and are valid.

We can also find an interesting function in the binary that prints `"your reward"`, so this is most likely our target.  
This function basically takes the program's input argument and uses it as a private key to decrypt the flag. So the goal is to find this private key, which we know has 16 bytes. To enter this function we need to have the `input` and `position` ADS set to 16.

To make more sense of the program, we also need to analyze some of the possible branches from the jump table. But that's pretty difficult since it has over 90k branches...  
![ch5-ghidra-jt-array](/images/FlareOn12_2025/ch5-ghidra-jt-array.png)

One easy way to solve this is to compute once where the jump table would jump to, and then decompile that target (press `D` in Ghidra).
After looking at multiple of these branches, we can observe that:

* All branches start with the `RDTSC` instruction.  
* In most branches there are multiple comparisons done with certain characters. If the comparisons fail, there is always an else branch that executes “random” things (e.g., logging you out of Windows).  
* All branches have the same ending pattern.

Branch 0 (state is zero):
![ch5-fn-structure](/images/FlareOn12_2025/ch5-fn-structure.png)

On L24-L34 we can see an example of how the comparisons are made.  
This basically compares the character from the `input` ADS stream at the `position` specified in the `position` ADS stream with the character in the `if` condition.  
If there is a match, the `transitions` ADS will increment by one (`stack_00058ab8`) and a new state is set (`stack_00058d30`). For example, if the input matches `'J'` the new state will be `2`; if it matches `'U'` the new state will be `3`, and so on.  
If there isn't a match, it will execute the command from L37 and stop there (no update to `state`/`transitions`). This path should be avoided.

There is also an interesting epilogue part for each of these branches, they will always:
* increment the `position` (L41),
* write the new `transitions` value (L44),
* write the new `state` if there is a new state (L48).

So from what we know so far, most likely the goal is to find an input that will follow a path through the branches where `position` and `transitions` both reach `16`.  
We can't do this manually since there are too many branches, the easiest way is to write a script which automatically parses the possible next inputs to reach another state.

I did this with Capstone since the branches have a pretty similar structure and you can easily extract the information that's needed.

Here are my scripts that I used during this challenge:

##### Writing to ADS streams:

```py
import sys

data = bytes([0x00])
path = r"C:\Users\test\Downloads\ntfsm.exe:state"
with open(path,"wb") as f:
        f.write(data)

data=bytes([0x10])
path = r"C:\Users\test\Downloads\ntfsm.exe:position"
with open(path,"wb") as f:
		f.write(data)
        
data=bytes([0x10])
path = r"C:\Users\test\Downloads\ntfsm.exe:transitions"
with open(path,"wb") as f:
        f.write(data)

text = 'iqg0nSeCHnOMPm2Q'
data = text.encode("utf-8")
path = r"C:\Users\test\Downloads\ntfsm.exe:input"
with open(path,"wb") as f:
        f.write(data)
```

##### Reading from ADS stream:

```py
import sys

path = r"C:\Users\test\Downloads\ntfsm.exe:state"
with open(path,"rb") as f:
        print(f"State:{f.read()}", end='-')
path = r"C:\Users\test\Downloads\ntfsm.exe:position"
with open(path,"rb") as f:
        print(f"Position:{f.read()}", end='-')
path = r"C:\Users\test\Downloads\ntfsm.exe:transitions"
with open(path,"rb") as f:
        print(f"Transitions:{f.read()}", end='-')
path = r"C:\Users\test\Downloads\ntfsm.exe:input"
with open(path,"rb") as f:
        print(f"Input:{f.read()}", end='-')
```
######  Important functions of my solving script
 I would've insert it all but it's messy.

```py
def get_states(state):
    offset = get_jump_table_index(state)
    function_address_va = base_address + offset
    function_address = va_to_file_offset(pe, function_address_va)
    code = file_byte_reader(function_address, 125)

    states = []
    insns = list(md.disasm(code, function_address_va))
    # find the correct values for the next state
    for i in range(len(insns) - 1):
        i1, i2  = insns[i], insns[i+1]
        if (i1.mnemonic == "cmp" and "byte ptr" in i1.op_str and  (i2.mnemonic == "jz" or i2.mnemonic == "je")):
            letter_state = []
            if i1.mnemonic == 'cmp' and 'byte ptr' in i1.op_str:
                letter_state.append(i1.op_str.split(', ')[-1])
            jump_target_str = i2.op_str.strip()
            try:
                jump_target_va = int(jump_target_str, 16)
            except ValueError:
                print(f"Invalid jump target address: {jump_target_str}")
                continue
            
            try:
                jump_file_offset = va_to_file_offset(pe, jump_target_va)
                jump_code = file_byte_reader(jump_file_offset, 16)
                for target_insn in md.disasm(jump_code, jump_target_va):
                    if target_insn.mnemonic == 'mov' and 'qword ptr' in target_insn.op_str:
                        letter_state.append((target_insn.op_str.split(', ')[-1]))
                if len(letter_state) > 0:
                    states.append(letter_state)
            except ValueError:
                pass 
            
    return states

	
def create_branches(state):
    inputs_and_states = get_states(state.state)
    state.position = (int.from_bytes(state.position, byteorder='big') + 1).to_bytes(1, byteorder='big')
    state.transitions = (int.from_bytes(state.transitions, byteorder='big') + 1).to_bytes(1, byteorder='big')
    old_input = state.input_field
    all_states = []
    for input_value, next_state in inputs_and_states:
        new_input = old_input +  bytes([int(input_value, 16)]) 
        if int(next_state,16) > 90781: 
            temp_state = State(b'', state.transitions, new_input, state.position)
            print("hahaha")
        else:
            temp_state = State(struct.pack('<i',int(next_state,16) ), state.transitions, new_input, state.position)
        all_states.append(temp_state)
    return all_states
	
def create_graph(node):
    global itteration
    input_cpy = node.input_field
    itteration += 1
    states = create_branches(node)
    if not len(states): 
        graph[node.state].append((node.transitions,input_cpy+b'X')) # mark final with X
        return 
    
    for state in states:
        if (int.from_bytes(state.transitions, 'big') == 16 or int.from_bytes(state.position, 'big') == 16) or not len(state.state):
            graph[node.state].append((node.transitions,state.input_field[1:]+b'X'))
            return 
        graph[node.state].append((state.state,state.transitions))
        create_graph(state)
```

After running it we get only one valid path which we can give to the program and we receive the flag.
This was a really fun challenge.

---

# Challenge 6 (chain of demands)

While I didn't solve this challenge, I feel I was pretty close but got sidetracked down a rabbit hole.  
For this challenge we get a Linux executable. When running it we get a console application that acts as a chat client.  
The most important part of this is that we have a `Last Convo` button which displays the following:

```json
[
  {
    "conversation_time": 0,
    "mode": "LCG-XOR",
    "plaintext": "Hello",
    "ciphertext": "e934b27119f12318fe16e8cd1c1678fd3b0a752eca163a7261a7e2510184bbe9"
  },
  {
    "conversation_time": 4,
    "mode": "LCG-XOR",
    "plaintext": "How are you?",
    "ciphertext": "25bf2fd1198392f4935dcace7d747c1e0715865b21358418e67f94163513eae4"
  },
  // 5 more LCG-XOR messages 
  {
    "conversation_time": 242,
    "mode": "RSA",
    "plaintext": "[ENCRYPTED]",
    "ciphertext": "680a65364a498aa87cf17c934ab308b2aee0014aee5b0b7d289b5108677c7ad1eb3bcfbcad7582f87cb3f242391bea7e70e8c01f3ad53ac69488713daea76bb3a524bd2a4bbbc2cfb487477e9d91783f103bd6729b15a4ae99cb93f0db22a467ce12f8d56acaef5d1652c54f495db7bc88aa423bc1c2b60a6ecaede2f4273f6dce265f6c664ec583d7bd75d2fb849d77fa11d05de891b5a706eb103b7dbdb4e5a4a2e72445b61b83fd931cae34e5eaab931037db72ba14e41a70de94472e949ca3cf2135c2ccef0e9b6fa7dd3aaf29a946d165f6ca452466168c32c43c91f159928efb3624e56430b14a0728c52f2668ab26f837120d7af36baf48192ceb3002"
  },
  {
    "conversation_time": 249,
    "mode": "RSA",
    "plaintext": "[ENCRYPTED]",
    "ciphertext": "6f70034472ce115fc82a08560bd22f0e7f373e6ef27bca6e4c8f67fedf4031be23bf50311b4720fe74836b352b34c42db46341cac60298f2fa768f775a9c3da0c6705e0ce11d19b3cbdcf51309c22744e96a19576a8de0e1195f2dab21a3f1b0ef5086afcffa2e086e7738e5032cb5503df39e4bf4bdf620af7aa0f752dac942be50e7fec9a82b63f5c8faf07306e2a2e605bb93df09951c8ad46e5a2572e333484cae16be41929523c83c0d4ca317ef72ea9cde1d5630ebf6c244803d2dc1da0a1eefaafa82339bf0e6cf4bf41b1a2a90f7b2e25313a021eafa6234643acb9d5c9c22674d7bc793f1822743b48227a814a7a6604694296f33c2c59e743f4106"
  }
]
```

So it's clear that we need to decrypt the RSA-encrypted messages. We also receive a public key for the RSA from that convo.

When RE-ing it, it's pretty clear that it's a PyInstaller-packed binary. To unpack it I used `pyinstxtractor` (https://github.com/extremecoders-re/pyinstxtractor).  
After that I analyzed the contents a bit and found a file called `challenge_to_compile.pyc` since this seemed to be the most important file, so I decided to decompile it.

To decompile it I used `pycdc` (https://github.com/zrax/pycdc), but it was failing, so I followed this guide to bypass the errors: https://idafchev.github.io/blog/Decompile_python/.  
While reading other writeups I found that we could also use https://pylingual.io/, which is pretty accurate.  
Or we could just disassemble the bytecode with the built-in disassembler and give it to Claude AI (see: https://gist.github.com/superfashi/563425ee96d505c0263373230335e41a#6---chain-of-demands).

The code also uses some smart contracts to do the computations for the LCG‑XOR. Since I got sidetracked thinking something was wrong with my decompiled code, I deployed the contracts locally with Ganache to ensure I hadn't made a mistake (fun fact: I didn't).  
We could also look at the decompiled EVM bytecode of the contracts on [Dedaub](https://app.dedaub.com/decompile).

The code where the contracts are locally deployed (there are also some minor changes I made to test things):

```py
import sys
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime
import hashlib
import platform
import time
import math
import os
from Crypto.Util.number import inverse
from web3 import Web3



def resource_path(relative_path):
    '''
    Get the absolute path to a resource, which works for both development
    and for a PyInstaller-bundled executable.
    '''
    base_path = sys._MEIPASS
    return os.path.join(base_path, relative_path)
    if Exception:
        base_path = os.path.abspath('.')


class LCGOracle:
    
    def __init__(self, multiplier, increment, modulus, initial_seed):
        self.multiplier = multiplier
        self.increment = increment
        self.modulus = modulus
        self.state = initial_seed
        self.contract_bytes = '6080604052348015600e575f5ffd5b506102e28061001c5f395ff3fe608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063115218341461002d575b5f5ffd5b6100476004803603810190610042919061010c565b61005d565b6040516100549190610192565b60405180910390f35b5f5f848061006e5761006d6101ab565b5b86868061007e5761007d6101ab565b5b8987090890505f5f8411610092575f610095565b60015b60ff16905081816100a69190610205565b858260016100b49190610246565b6100be9190610205565b6100c89190610279565b9250505095945050505050565b5f5ffd5b5f819050919050565b6100eb816100d9565b81146100f5575f5ffd5b50565b5f81359050610106816100e2565b92915050565b5f5f5f5f5f60a08688031215610125576101246100d5565b5b5f610132888289016100f8565b9550506020610143888289016100f8565b9450506040610154888289016100f8565b9350506060610165888289016100f8565b9250506080610176888289016100f8565b9150509295509295909350565b61018c816100d9565b82525050565b5f6020820190506101a55f830184610183565b92915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f61020f826100d9565b915061021a836100d9565b9250828202610228816100d9565b9150828204841483151761023f5761023e6101d8565b5b5092915050565b5f610250826100d9565b915061025b836100d9565b9250828203905081811115610273576102726101d8565b5b92915050565b5f610283826100d9565b915061028e836100d9565b92508282019050808211156102a6576102a56101d8565b5b9291505056fea2646970667358221220c7e885c1633ad951a2d8168f80d36858af279d8b5fe2e19cf79eac15ecb9fdd364736f6c634300081e0033'
        self.contract_abi = [
            {
                'inputs': [
                    {
                        'internalType': 'uint256',
                        'name': 'LCG_MULTIPLIER',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': 'LCG_INCREMENT',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': 'LCG_MODULUS',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': '_currentState',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': '_counter',
                        'type': 'uint256' }],
                'name': 'nextVal',
                'outputs': [
                    {
                        'internalType': 'uint256',
                        'name': '',
                        'type': 'uint256' }],
                'stateMutability': 'pure',
                'type': 'function' }]
        self.deployed_contract = None

    def connect_local(self):
        self.web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        if not self.web3.is_connected():
            raise Exception("Cannot connect to local blockchain")
        self.account = self.web3.eth.accounts[0]  
        self.web3.eth.default_account = self.account 

    def deploy_contract(self):
        # Create contract factory
        contract_factory = self.web3.eth.contract(
            abi=self.contract_abi,
            bytecode=self.contract_bytes
        )

        # Deploy contract
        tx_hash = contract_factory.constructor().transact()
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        # Create deployed contract instance
        self.deployed_contract = self.web3.eth.contract(
            address=tx_receipt.contractAddress,
            abi=self.contract_abi
        )

        print(f"Contract deployed at: {tx_receipt.contractAddress}")
        return self.deployed_contract  # Return the deployed instance


    def get_next(self, counter):
        if not self.deployed_contract:
            raise Exception("Contract not deployed yet")

        print(f"\n[+] Calling nextVal() with _currentState={self.state}")
        
        # Call the nextVal function on the deployed contract
        self.state = self.deployed_contract.functions.nextVal(
            self.multiplier,
            self.increment,
            self.modulus,
            self.state,
            counter
        ).call()

        print(f"  _counter = {counter}: Result = {self.state}")
        return self.state

   # def get_next(self, counter):
   #     # Apply the LCG formula
   #     for _ in range(counter):
   #         self.state = (self.multiplier * self.state + self.increment) % self.modulus
   #     #print(f'''[+] LCG Next Value: {self.state} (Counter: {counter})''')
   #     return self.state


class TripleXOROracle:
    
    def __init__(self):
        self.contract_bytes = '61030f61004d600b8282823980515f1a6073146041577f4e487b71000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b305f52607381538281f3fe7300000000000000000000000000000000000000003014608060405260043610610034575f3560e01c80636230075614610038575b5f5ffd5b610052600480360381019061004d919061023c565b610068565b60405161005f91906102c0565b60405180910390f35b5f5f845f1b90505f845f1b90505f61007f85610092565b9050818382181893505050509392505050565b5f5f8290506020815111156100ae5780515f525f5191506100b6565b602081015191505b50919050565b5f604051905090565b5f5ffd5b5f5ffd5b5f819050919050565b6100df816100cd565b81146100e9575f5ffd5b50565b5f813590506100fa816100d6565b92915050565b5f5ffd5b5f5ffd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b61014e82610108565b810181811067ffffffffffffffff8211171561016d5761016c610118565b5b80604052505050565b5f61017f6100bc565b905061018b8282610145565b919050565b5f67ffffffffffffffff8211156101aa576101a9610118565b5b6101b382610108565b9050602081019050919050565b828183375f83830152505050565b5f6101e06101db84610190565b610176565b9050828152602081018484840111156101fc576101fb610104565b5b6102078482856101c0565b509392505050565b5f82601f83011261022357610222610100565b5b81356102338482602086016101ce565b91505092915050565b5f5f5f60608486031215610253576102526100c5565b5b5f610260868287016100ec565b9350506020610271868287016100ec565b925050604084013567ffffffffffffffff811115610292576102916100c9565b5b61029e8682870161020f565b9150509250925092565b5f819050919050565b6102ba816102a8565b82525050565b5f6020820190506102d35f8301846102b1565b9291505056fea26469706673582212203fc7e6cc4bf6a86689f458c2d70c565e7c776de95b401008e58ca499ace9ecb864736f6c634300081e0033'
        self.contract_abi = [
            {
                'inputs': [
                    {
                        'internalType': 'uint256',
                        'name': '_primeFromLcg',
                        'type': 'uint256' },
                    {
                        'internalType': 'uint256',
                        'name': '_conversationTime',
                        'type': 'uint256' },
                    {
                        'internalType': 'string',
                        'name': '_plaintext',
                        'type': 'string' }],
                'name': 'encrypt',
                'outputs': [
                    {
                        'internalType': 'bytes32',
                        'name': '',
                        'type': 'bytes32' }],
                'stateMutability': 'pure',
                'type': 'function' }]
        self.deployed_contract = None

    
 
    def deploy_triple_xor_contract(self):
        contract_factory = self.web3.eth.contract(
        abi=self.contract_abi,
        bytecode=self.contract_bytes)

        tx_hash = contract_factory.constructor().transact()
        tx_receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        # Create deployed contract instance
        self.deployed_contract = self.web3.eth.contract(
            address=tx_receipt.contractAddress,
            abi=self.contract_abi
        )

        print(f"Contract deployed at: {tx_receipt.contractAddress}")
        return self.deployed_contract  # Return the deployed instance

    def connect_local(self):
        self.web3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        if not self.web3.is_connected():
            raise Exception("Cannot connect to local blockchain")
        self.account = self.web3.eth.accounts[0]  
        self.web3.eth.default_account = self.account 

    def encrypt(self, prime_from_lcg, conversation_time, plaintext_bytes):
        print(f'''\n[+] Calling encrypt() with prime_from_lcg={prime_from_lcg}, time={conversation_time}, plaintext={plaintext_bytes}''')
        ciphertext = self.deployed_contract.functions.encrypt(prime_from_lcg, conversation_time, plaintext_bytes).call()
        print(f'''  _ciphertext = {ciphertext.hex()}''')
        return ciphertext

def get_seed():
    artifact = platform.node().encode('utf-8')
    hash_val = hashlib.sha256(artifact).digest()
    seed_hash = int.from_bytes(hash_val, 'little')
    #seed_hash = 72967016216206426977511399018380411256993151454761051136963936354667101207529
    return seed_hash

def generate_primes_from_hash(seed_hash):
    primes = []
    current_hash_byte_length = (seed_hash.bit_length() + 7) // 8
    current_hash = seed_hash.to_bytes(current_hash_byte_length, 'little')
    print('[SETUP] Generating LCG parameters from system artifact...')
    iteration_limit = 10000
    iterations = 0
    while len(primes) < 3 and iterations < iteration_limit:
        current_hash = hashlib.sha256(current_hash).digest()
        candidate = int.from_bytes(current_hash, 'little')
        iterations += 1
        if candidate.bit_length() == 256 and isPrime(candidate):
            primes.append(candidate)
            print(f'[SETUP]  - Found parameter {len(primes)}: {str(candidate)[:20]}...')
    if len(primes) < 3:
        error_msg = '[!] Error: Could not find 3 primes within iteration limit.'
        print('Current Primes: ', primes)
        print(error_msg)
        exit()
    return (primes[0], primes[1], primes[2])

seed_hash = get_seed()
m, c, n = generate_primes_from_hash(seed_hash)
lcg_oracle = LCGOracle(m,c,n,seed_hash)
lcg_oracle.connect_local()
lcg_oracle.deploy_contract()
xor_oracle = TripleXOROracle()
xor_oracle.connect_local()
xor_oracle.deploy_triple_xor_contract()

d = 0
n = 0
def generate_rsa_key_from_lcg():
    global n
    global d
    print('[RSA] Generating RSA key from on-chain LCG primes...')
    lcg_for_rsa = LCGOracle(lcg_oracle.multiplier, lcg_oracle.increment, lcg_oracle.modulus, seed_hash)
    lcg_for_rsa.connect_local()
    lcg_for_rsa.deploy_contract()

    primes_arr = []
    rsa_msg_count = 0
    iteration_limit = 10000
    iterations = 0
    while len(primes_arr) < 8 and iterations < iteration_limit:
        candidate = lcg_for_rsa.get_next(rsa_msg_count)
        rsa_msg_count += 1
        iterations += 1
        if candidate.bit_length() == 256 and isPrime(candidate):
            if candidate not in primes_arr:
                primes_arr.append(candidate)
                print(f'[RSA] - Found 256-bit prime #{len(primes_arr)}')

    print('Primes Array: ', primes_arr)
    if len(primes_arr) < 8:
        error_msg = '[RSA] Error: Could not find 8 primes within iteration limit.'
        print(error_msg)
        return error_msg

    n = 1  
    for p_val in primes_arr:
        n *= p_val
    phi = 1
    for p_val in primes_arr:
        phi *= p_val - 1

    e = 65537
    if math.gcd(e, phi) != 1:
        error_msg = '[RSA] Error: Public exponent e is not coprime with phi(n). Cannot generate key.'
        print(error_msg)
        return error_msg

    rsa_key = RSA.construct((n, e))
    with open("testpublic.pem", "wb") as f:
        f.write(rsa_key.export_key("PEM"))

    print("[RSA] Keys saved to private.pem and public.pem")
    return rsa_key


#rsa_key = generate_rsa_key_from_lcg()
rsa_key = ''
seed_hash = get_seed()
m, c, n = generate_primes_from_hash(seed_hash)
lcg_oracle = LCGOracle(m,c,n,seed_hash)
lcg_oracle.connect_local()
lcg_oracle.deploy_contract()
xor_oracle = TripleXOROracle()
xor_oracle.connect_local()
xor_oracle.deploy_triple_xor_contract()

option = int(sys.argv[1]) 
message = str(sys.argv[2])
#seed_hash = 72967016216206426977511399018380411256993151454761051136963936354667101207529
message = "How are you?"
message_count = 1
conversation_start_time = 0

def process_message(plaintext):
    global conversation_start_time
    global message_count
    if conversation_start_time == 0:
        conversation_start_time = time.time()
    conversation_time = 4
    print(conversation_time)
    if option == 5:
        plaintext_bytes = plaintext.encode('utf-8')
        plaintext_enc = bytes_to_long(plaintext_bytes)
        _enc = pow(plaintext_enc, rsa_key.e, rsa_key.n)
        ciphertext = _enc.to_bytes(rsa_key.n.bit_length(), 'little').rstrip(b'\x00')
        encryption_mode = 'RSA'
        plaintext = '[ENCRYPTED]'
    else:
        prime_from_lcg = lcg_oracle.get_next(message_count)
        ciphertext = xor_oracle.encrypt(prime_from_lcg, conversation_time, plaintext)
        encryption_mode = 'LCG-XOR'
    log_entry = {
        'conversation_time': conversation_time,
        'mode': encryption_mode,
        'plaintext': plaintext,
        'ciphertext': ciphertext.hex() }
    message_count += 1
    return (f'''[{conversation_time}s] {plaintext}''', f'''[{conversation_time}s] {ciphertext.hex()}''')
```

So basically what this program does is:

* Generate a seed based on the host machine name. With this seed, three prime numbers are computed for the LCG (`m`, `c`, and `n`).  
* The seed and the three prime numbers are also used in the RSA key pair.

The LCG algorithm is pretty intuitive and does the following:

```py
def gen_next(self, counter):
    for _ in counter:
        self.state = (self.multiplier * self.state + self.increment)  % self.modulus
    return self.state
```

The triple XOR just takes the time, the text, and the LCG value and XORs them to get the ciphertext.

The bug comes from the fact that the first time the LCG is used, if the counter is zero the state itself is returned which is actually the seed (this is visible in the LCG constructor). So with the first message from the conversation we can retrieve the original seed since we have the time, the message and the ciphertext:

    ciphertext = message ^ time ^ seed
    => seed = ciphertext ^ time ^ message

So with the logic of the program, I expected to get the RSA keys with this seed. This doesn't happen which is really strange since it should do this.
I also tested it with local conversations and it worked. Here is where I fell into a rabbit hole and thought I missed something.
Apperantly the conversation that we get isn't generated with this program.

The actual solution for this is to reverse the LCG algorithm to compute the multiplier, increment and the modulus based on the seed we leaked.
There is a nice [resource](https://msm.lt/posts/cracking-rngs-lcgs/) on this which explain the math nicely.
But the main idea is that we can find the modulus by using the fact that random multiples of x, most likely have the gcd x. To use this we need to transform our expressions into a form where we have X = d*modulus.

My solve script:
```py
import json
import math
from functools import reduce
from sympy import isprime as isPrime

lcg_values = []
rsa_texts = []
conversations = json.load(open("chat_log_original.json", "r"))
messages = []
for msg in conversations:
    messages.append((msg["conversation_time"], msg["plaintext"], msg["ciphertext"]))
    lcg_values.append((msg["conversation_time"] ^ int.from_bytes(msg["plaintext"].encode('utf-8')[:32].ljust(32, b'\x00'), 'big') ^ int(msg["ciphertext"],16)))

# only need the LCG values
lcg_values = lcg_values[:7]
rsa_texts = messages[7:]

for i, v in enumerate(lcg_values):
    print(f"LCG state {i}: {v}")

# These values follow the LCG formula: X_{n+1} = (a * X_n + c) mod m
# So now we need to solve a,c and m for X_0, X_1, X_2, ..., X_6

#compute the differences to eliminate c to use the target equation (t2*t0 - t1*t1 = (m*m*t0 * t0) - (m*t0 * m*t0) = 0 (mod n))
t = [s1-s0 for s0, s1 in zip(lcg_values, lcg_values[1:])]
zero_mods = [t2*t0 - t1*t1 for t0, t1, t2 in zip(t, t[1:], t[2:])]

# try to compute the gcd of these values to get m
m = abs(reduce(math.gcd, zero_mods))
print(f"Modulus m: {m}")

# just solve the equations to get a and c
a = (lcg_values[3] - lcg_values[2]) * pow(lcg_values[2] - lcg_values[1], -1, m) % m 
print(f"Multiplier a: {a}")

c = (lcg_values[1] - lcg_values[0]*a) % m

print(f"Increment c: {c}")

original = (lcg_values[0]- c) * pow(a, -1, m) % m
print(f"seed: {original}")


# use the RSA implementation from generate_rsa_from_lcg
primes_arr = []
rsa_msg_count = 0
iteration_limit = 10000
iterations = 0
while len(primes_arr) < 8 and iterations < iteration_limit:
    candidate = (a * original + c) % m
    original = candidate
    iterations += 1
    if candidate.bit_length() == 256 and isPrime(candidate):
        if candidate not in primes_arr:
            primes_arr.append(candidate)

print('Primes Array: ', primes_arr)

n = 1  
for p_val in primes_arr:
    n *= p_val
phi = 1
for p_val in primes_arr:
    phi *= p_val - 1
e = 65537
d = pow(e, -1, phi)

for text in rsa_texts:
    c = int.from_bytes(bytes.fromhex(text[2]), 'little')
    msg_int = pow(c, d, n)
    msg_bytes = msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big')
    msg_str = msg_bytes.decode('utf-8')
    print(msg_str)
```

While I don't like the fact that the conversation was generated with another code, I should've stepped back and iterated again on what information I had.
There are also persons that solved this using [factordb](http://www.factordb.com/) with the [result](http://www.factordb.com/index.php?query=966937097264573110291784941768218419842912477944108020986104301819288091060794069566383434848927824136504758249488793818136949609024508201274193993592647664605167873625565993538947116786672017490835007254958179800254950175363547964901595712823487867396044588955498965634987478506533221719372965647518750091013794771623552680465087840964283333991984752785689973571490428494964532158115459786807928334870321963119069917206505787030170514779392407953156221948773236670005656855810322260623193397479565769347040107022055166737425082196480805591909580137453890567586730244300524109754079060045173072482324926779581706647).
