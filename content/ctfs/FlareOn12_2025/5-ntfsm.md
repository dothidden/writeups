---
title: 5.ntfsm
type: writeup
date: 2025-10-01T18:42:50+02:00
description: Writeup for ntfsm [FlareOn 2025]
author: PineBel
tags:
- rev
draft: false
---


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