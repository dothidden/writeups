---
title: Zzz
date: 2023-06-10
type: writeup
author: sunbather
tags:
  - rev
  - angr
---

## Description of the challenge

3z

Author: NoobHacker

## Solution

This is obviously a z3 challenge. We can open the binary in Ghidra and see various constraints. Instead of solving them manually, let's just try some angr magic. I won't even attempt to add the constraints. I'll just add the beginning of the flag.

```py
#!/usr/bin/env python3
import angr
import claripy
import sys

def is_successful(state):
    #Successful print
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b'You got it!' in stdout_output

def should_abort(state):
    #Avoid this print
    stdout_output = state.posix.dumps(sys.stdout.fileno())
    return b"That's wrong!" in stdout_output

proj = angr.Project('./chall')

flag = claripy.BVS("flag", 8 * 30)

state = proj.factory.entry_state(stdin = flag)

state.solver.add(flag.get_byte(0) == ord('n'))
state.solver.add(flag.get_byte(1) == ord('0'))
state.solver.add(flag.get_byte(2) == ord('0'))
state.solver.add(flag.get_byte(3) == ord('b'))
state.solver.add(flag.get_byte(4) == ord('z'))
state.solver.add(flag.get_byte(5) == ord('{'))

for i in range(6, 30):
    state.solver.add(flag.get_byte(i) >= 33)
    state.solver.add(flag.get_byte(i) <= 125)

sm = proj.factory.simulation_manager(state)

sm.explore(find=is_successful, avoid=should_abort)

if sm.found:
    sol = sm.found[0]
    print(sol.posix.dumps(sys.stdin.fileno()))
else:
    print("no sol")
```
We run the script:
```
$ ./solve.py
WARNING  | 2023-06-23 01:35:39,568 | angr.simos.simos | stdin is constrained to 30 bytes (has_end=True). If you are only providing the first 30 bytes instead of the entire stdin, please use stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).
b'n00bz{ZzZ_zZZ_zZz_ZZz_zzZ_Zzz}'
```

It's _that_ easy!
