# Crackme

## crackme1
In order to get the interesting positions for breakpoints I opened the file in the CodeBrowser of ghidra and found the following address in the is_being_debugged function: 0x201b31, where a jnz/jne instruction jumps over the instructions causing a sigsev. By setting the $eflags in gdb with gef to 0, we avoid the crashing of the program while using a debugger.

```bash
break *0x201b31 # Set breakpoint
set $eflags = 0 # Set eflags to 0 set $eflags |= (0 << 6) doesn't work for some reason
```

The next breakpoint is at: 0x00201e19
In order to get into the loop comparing the entered password with the correct one, we jump to the target with the jz/je at the breakpoint by setting the ZF to 1 and using next to jump to the next step. We don't actually need to do that, since the flag is already in the rdx register at the breakpoint, but we can.
```bash
set $eflags |= (1 << 6)
# alternatively
set $ZF = 0
set $eflags |= (1 << $ZF)

# go to next step
next
```

## crackme2
The breakpoint for is_being_debugged is at: 0x00201af1

```bash
break *0x00201af1 # Set breakpoint
set $eflags = 0 # Set eflags to 0 set $eflags |= (0 << 6) doesn't work for some reason
```

The second breakpoint is at: 0x00201dfd
This refers to the instruction after the binary and, that creates the Flag chars one by one in hex format and stores them in the ecx register. Since they are created one by one, to get all the characters the following two commands are executed in a loop until we reach the 0x0 value in the ecx register. 

```bash
# gives hex value with 0x header
info r $ecx
# alternative, translates to ASCII automatically
printf "%c", $ecx

# continues to next breakpoint
c
```
The most difficult thing to figure out was, where the correct password was being generated in the code and where in the execution it could be read from the registers.