---
title: 1.Drill_Baby_Drill!
type: writeup
date: 2025-10-01T18:42:50+02:00
description: Writeup for Drill Baby Drill! [FlareOn 2025]
author: PineBel
tags:
- rev
draft: false
---


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