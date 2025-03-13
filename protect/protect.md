# Protect - Lab Report

Your license check key: `b19dbbc8a7c7571f18155d9020901635297d10f8`
License for user "Hello": `1MsoyMlm2g`

## 1. Obfuscation

### 1.1 Encode Data

Tigress-command:

```sh
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=EncodeData --LocalVariables='calc_fibonacci:nth_fib_num,fib_num,first,second;generate_license_key:key_length,username_char_pos,secret_key_char_pos' --out=keycheck_1.c keycheck.c
```

#### 1.1.1 Observations

The Data Encoding seems to work with function parameters as well, as long as the parameter is not argc. The Encoding also works with chars, but only with either only char or only ints, it's not possible to combine them. 
Regarding the changes to the code, the first thing to notice is that the obfuscated program has a bunch of seemingly unnecessary code and also doesn't seem to need any \"\#include\" declarations. It also uses large hardcoded integer numbers to hide the actual values, that only during runtime get calculated and make everything work. This includes array positions of character arrays. The hardcoded strings of the character arrays have been split into seperate chars and are beeing initialized like that (including the null-terminator at the end of the string). Also any existing for loops seem to have been split into while loops. 

#### 1.1.2 Estimated Impact on Runtime

I think this will impact performance quite a bit, since the data encoding requires more calculations for each step.



### 1.2 Opaque Predicates

Tigress-command:

```sh
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=InitOpaque --Functions=main,calc_fibonacci,mult_chars,generate_license_key --Transform=AddOpaque --Functions=main,calc_fibonacci,mult_chars,generate_license_key --out=keycheck_2.c keycheck.c
```

#### 1.2.1 Observations

Regarding the changes to the code, the first thing to notice is that the obfuscated program has a bunch of seemingly unnecessary code and also doesn't seem to need any \"\#include\" declarations. The hardcoded strings of the character arrays have been split into seperate chars and are beeing initialized like that (including the null-terminator at the end of the string). Also any existing for loops seem to have been split into while loops. At the beginning of every method there are obfuscation structures, that are initialized and later used in always true/false if-statements, confusing any reverse-engineer as to their structures purpose,  as well as several new temporal variables, that are mixed into the mathematical operation instead of directly calculating the values.


#### 1.2.2 Estimated Impact on Runtime

I think this will impact performance a bit, similar to data encoding, since both require more calculations for each step.




### 1.3 Control-Flow Flattening

Tigress-command:

```sh
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=Flatten --Functions=main,calc_fibonacci,mult_chars,generate_license_key --out=keycheck_3.c keycheck.c

```

#### 1.3.1 Observations

Regarding the changes to the code, the first thing to notice is that the obfuscated program has a bunch of seemingly unnecessary code and also doesn't seem to need any \"\#include\" declarations. The hardcoded strings of the character arrays have been split into seperate chars and are beeing initialized like that (including the null-terminator at the end of the string). All loops and if statements within the original functions seem to have been replaced by while loops controlled by switch statements. Which leads to the intended effect, splitting all the different basic blocks into cases of a switch statement within the respective loops.

#### 1.3.2 Estimated Impact on Runtime

I expect a small but existent impact on the performance of the program, since the switch statements require many more comparisons to break the loops than the original loops of the program.



### 1.4 Virtualization

Tigress-command:

```sh
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=Virtualize --Functions=main,calc_fibonacci,mult_chars,generate_license_key --out=keycheck_4.c keycheck.c

```

#### 1.4.1 Observations

Regarding the changes to the code, the first thing to notice is that the obfuscated program has a bunch of seemingly unnecessary code and also doesn't seem to need any \"\#include\" declarations. It has more than 2000 LOC compared to 88 LOC in the original program. The functions that were present in the original code seem to be consisting mostly of while-switch loops that seem to serve the purpose of interpreting the code based on the randomly generated instruction set(s) from Tigress.

#### 1.4.2 Estimated Impact on Runtime

This version of the program cannot be called performant anymore, since it looses the advantage of c as a language, that, after compiled, can run without any issues and doesn't need to be translated to bytecode anymore and creates a custom interpreter with the goal of hiding what the program actually does.



### 1.5 Combination A

Tigress-command:

```sh
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=EncodeData --LocalVariables='calc_fibonacci:nth_fib_num,fib_num,first,second;generate_license_key:key_length,username_char_pos,secret_key_char_pos' --Transform=InitOpaque --Functions=main,calc_fibonacci,mult_chars,generate_license_key --Transform=AddOpaque --Functions=generate_license_key,mult_chars --out=keycheck_5.c keycheck.c
```

#### 1.5.1 Observations

The Data Encoding seems to work with function parameters as well, as long as the parameter is not argc. The Encoding also works with chars, but only with either only char or only ints, it's not possible to combine them. 
Regarding the changes to the code, the first thing to notice is that the obfuscated program has a bunch of seemingly unnecessary code and also doesn't seem to need any \"\#include\" declarations. It also uses large hardcoded integer numbers to hide the actual values, that only during runtime get calculated and make everything work. This includes array positions of character arrays. The hardcoded strings of the character arrays have been split into seperate chars and are beeing initialized like that (including the null-terminator at the end of the string). Also any existing for loops seem to have been split into while loops. At the beginning of every method there are obfuscation structures, that are initialized and later used in always true/false if-statements, confusing any reverse-engineer as to their structures purpose,  as well as several new temporal variables, that are mixed into the mathematical operation instead of directly calculating the values. Needed to reduce the functions for AddOpaque, since the program functionality would break otherwise.

#### 1.5.2 Estimated Impact on Runtime

Since I estimate that both methods have roundabout the same performance indications, I estimate that the worst case scenario is that the program takes twice as much time as the one obfuscated with Data Encoding.



### 1.6 Combination B

Tigress-command:

```sh
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=Flatten --Functions=main,calc_fibonacci,mult_chars,generate_license_key --Transform=EncodeData --LocalVariables='calc_fibonacci:nth_fib_num,fib_num,first,second;generate_license_key:key_length,username_char_pos,secret_key_char_pos' --out=keycheck_6.c keycheck.c
```

#### 1.6.1 Observations

The Data Encoding seems to work with function parameters as well, as long as the parameter is not argc. The Encoding also works with chars, but only with either only char or only ints, it's not possible to combine them. 
Regarding the changes to the code, the first thing to notice is that the obfuscated program has a bunch of seemingly unnecessary code and also doesn't seem to need any \"\#include\" declarations. It also uses large hardcoded integer numbers to hide the actual values, that only during runtime get calculated and make everything work. This includes array positions of character arrays. The hardcoded strings of the character arrays have been split into seperate chars and are beeing initialized like that (including the null-terminator at the end of the string). Also any existing for loops seem to have been split into while loops. Which is where the falattening takes effect, splitting all the different basic blocks into cases of a switch statement within the loop.

#### 1.6.2 Estimated Impact on Runtime

Performancewise it seems like the flattening doesn't take as much as a toll on runtime, which is why I estimate it will at worst take as long as the Data Encoding.



### 1.7 Combination C

Tigress-command:

```sh
tigress --Environment=x86_64:Linux:Gcc:4.6 --Transform=Flatten --Functions=main,calc_fibonacci,mult_chars,generate_license_key --Transform=Virtualize --Functions=main,calc_fibonacci,mult_chars,generate_license_key --out=keycheck_7.c keycheck.c
```

#### 1.7.1 Observations

Regarding the changes to the code, the first thing to notice is that the obfuscated program has a bunch of seemingly unnecessary code and also doesn't seem to need any \"\#include\" declarations. The hardcoded strings of the character arrays have been split into seperate chars and are beeing initialized like that (including the null-terminator at the end of the string). The program has more than 2000 LOC compared to 88 LOC in the original program. All loops and if statements within the original functions seem to have been replaced by while loops controlled by switch statements. Which leads to the intended effect, splitting all the different basic blocks into cases of a switch statement within the respective loops, which seem to serve the purpose of interpreting the code based in the randomly generated instruction set(s) from Tigress.

#### 1.7.2 Estimated Impact on Runtime

The runtime shouldn't be significantly more than the runtime for the virtualized program, since the runtime price of the flattening should be insignifcant compared to the cost of virtualisation.



## 2. Disassembly/Analysis

Used disassembler: `ghidra`

### 2.1 Disassembly

General tigresss changes for generate_license_key: the amount of undefinded local variables drastically increased

Encode Data: The value of the numeric variables has been obfuscated, by adding complex calculations to the variables, that end up not changing the real values.

Opaque Predicates: Opaque predicate structures ae beeing initialized at the beginning of the function, a always true if statement is added and the original string pointer is assigned to another pointer.

Control-Flow Flattening: A switch statement within a do-while function is added, that implements the functions original behaviour without needing complex, multilevel Control Flow Patterns.

Virtualization: A switch statement within a do-while function is added, that implements the functions original behaviour, that is encoded in a complex artificially generated instruction set.

### 2.2 CFG Reconstruction

Encode Data: No relevant changes

Opaque Predicates: A move Operation was moved to a intermediary "if block" that splits one of the original basic blocks into two.

Control-Flow Flattening: The flattening seems to have created a lot more basic blocks than before centered around the switch statement in the do-while loop, which is supposed to flatten the Graph everywhere, but seems somewhat less effective than expected.

Virtualization: The CFG created is similar to the one from Flattening, but with more branches to basic blocks (cases).

### 2.3 Extraction of Strings

With the strings \[filename\] command it was possible to extarct the Alphabet and the secret key from the keycheck.bin file, but not from any of the files obfuscated by tigress

### 2.4 Data/Code Ratio

Using the size \[filename\] command (adding bss and data together) I determined the following data/code ratios:

    Default Program -> 656/3302 ~ 0,1987

    Encode Data -> 680/3857 ~ 0,1763

    Opaque Predicates -> 816/5486 ~ 0,14874

    Control-Flow Flattening -> 680/4367 ~ 0,1557

    Virtualization -> 6632/10896 ~ 0,60866

## 3. Performance

Sample size (for performance measurement): 100000

Command-line arguments: usr 3t26WIexMB

| File | Average Runtime (seconds) |
|----------|----------|
| keycheck.bin   | 0.0007412251663208008 |
| keycheck_1.bin | 0.0007371445035934448 |
| keycheck_2.bin | 0.0007429677271842956 |
| keycheck_3.bin | 0.0007533416819572448 |
| keycheck_4.bin | 0.0008030409169197082 |
| keycheck_5.bin | 0.0007851715755462646 |
| keycheck_6.bin | 0.0007855094528198243 |
| keycheck_7.bin | 0.0008611883687973022 |

All in all there were some discrepancies in the estiamtions compared to the actual runtimes:

    Encode Data -> Obscured Program faster than original

    Opaque Predicates -> Program slower than Encode Data, but faster than expected

    Control-Flow Flattening -> Bigger impact than expected

But in general the deviations were smaller than expected, which probably lead to a comparably big measurement fault, therefore the data collected by the python program is highly unreliable.
