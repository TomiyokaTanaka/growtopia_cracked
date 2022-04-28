# Turtorial
In this turtorial I will show you how to reverse engineer a game(growtopia)

# Why?
In the game you can't open a multiple instances of the game, which is really annoying
when you want to play with multiple account on the same device(who wants to buy a new device
just to play on multiple account? lol)

![problem_image](detector.png)

# Requirements
To understand/follow along this article a knowledge of things listed here is required
- basic knowledge of x86 assembly 
- some knowledge about how if else statements work at the low level
- [C programming language](https://en.wikipedia.org/wiki/C_(programming_language))
- [ghidra](https://github.com/NationalSecurityAgency/ghidra)
- Windows OS

# Table Of contents
- [Overview](#overview)

- Installation of the game and ghidra



# Turtorials

```
Notes : 
this functions names that I mentioned in the article, in the microsoft docs or by the ghidra decompiler are the same and interexchangeable
I mention this because the microsoft docs and the output from the ghidra decompiler are different in naming both of this functions

OpenMutexW == OpenMutexA
CreateMutexW == CreateMutexA
```
## Overview

In this turtorial we will try to break the validator as shown in [Why? Section](#why) using [reverse engineering](https://en.wikipedia.org/wiki/Reverse_engineering)
with the [ghidra framework][ghidra_link]


A common way and easy way to check if a windows program is running with multiple instances is by using 
the win32 api [CreateMutexA][CreateMutexA_link] and [OpenMutexW][OpenMutexW_link], 


this is a pseudo code of how the program achieve this
```
  // if OpenMutexA fails because no mutex object has been prevously created 
  // then it will return NULL 
  // so to check if multiple instances are running, it can be done this way
  // which won't create new mutex if the mutex has been created previously
  program_handle = OpenMutexA(0x1f0001,0,"Growtopia");
  if ((program_handle == (HANDLE)0x0))
	program_handle = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,"Growtopia");

```

We can remove the lock by trying to make an unconditional jump by patching the binary at 
```
  if ((program_handle == (HANDLE)0x0))
```
with ghidra's disassembler to jump straight to 

```
program_handle = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,"Growtopia");
```
example of patching binary via modifying the assembly 
![patch_example](turtorials/39.png)


![patch_example](turtorials/40.png)


![patch_example](turtorials/41.png)


after the "lock" has been **disabled**, we can play Growtopia on multiple windows with multiple accounts simultaneously


![patch_example](turtorials/sucsess.png)
![patch_example](turtorials/succsess2.png)

[//]: # (Common Links used by this article)
[ghidra_link]: https://github.com/NationalSecurityAgency/ghidra
[CreateMutexA_link]: https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa
[OpenMutexW_link]: https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-openmutexw


