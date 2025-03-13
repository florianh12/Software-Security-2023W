# Step 1: Disassembling the binary
The first thing I did to figure out what was going on, was to dissassemble ragequit_000. In doing so I found that there was a function, that was called via a function pointer 2 times in the binary. Once with the argument 0 and a key variable and once with the argument 1 and a key variable. After going through the binary for a while, I could make an educated guess that the function referenced was rageme, and that the only relevant run of rageme was the one with the argument 1.


# Step 2: Setting up angr
After getting a rough idea about the layout of the program, I stared by setting up angr. The first thing I did, was finding the function in which the pointer to the yet unchanged secret was loaded into memory and the actual work of the program begun.

I found the address of the key (the second argument in rageme, therfore in register rsi).

I then fabricated a call-state with the rageme fuction address as starting point and 1 and the address of the secret as parameters and state as the base_state.

After that I explored for the point in the program, where it was finished scrambling the key, which turned into the payment reference and saved the address of it, as well as the function I was currently at.

I then created symbolic variables for the bytes of the scrambled key and explored for the corresponding function address.

The last steps were to get the found state and constrain the scrambled bytes with the actual bytes received by the output and loading the secret from the memory and solving it with the solver. For some reason constraining the bytes with a loop as long as the key length only gave $\frac{1}{4}th$ of the key so I iterated 4 times as long, which gave me the entire key.

# Step 3: Decrypting using pynacl is fun, not overly complicated and badly documented at all!!!
After getting the key the only remaining step was to decrypt the encrypted file using pynacl and printing the original file.

The first step is to instantiate a crypto_secretstream_xchacha20poly1305_state object and seperate the header and the ciphertext from the encrypted data.

After that the crypto_secretstream_xchacha20poly1305_init_pull function is called to initialize the instantiated state, using the state, header and ciphertext as variables.

At last the crypto_secretstream_xchacha20poly1305_pull function is called, using state, ciphertext and pyton-None (null) as parameters. This finally decrypts the ciphertext.

Note that the nacl.secret.SecretBox does not support ChaCha20, but XSalsa20.

# Annex: Python Code
```python
#!/usr/bin/env python3
import angr
import sys
import nacl.bindings as bind


key_size = 32


def chacha20_decrypt(key,encrypted_data):

    #instantiate state
    state = bind.crypto_secretstream_xchacha20poly1305_state()

    #seperate header(nonce) and ciphertext
    header = encrypted_data[:bind.crypto_secretstream_xchacha20poly1305_HEADERBYTES]
    ciphertext = encrypted_data[bind.crypto_secretstream_xchacha20poly1305_HEADERBYTES:]

    #initialize state
    bind.crypto_secretstream_xchacha20poly1305_init_pull(state=state,header=header,key=key)

    #decrypt message
    return bind.crypto_secretstream_xchacha20poly1305_pull(state=state,c=ciphertext,ad=None)[0]

def is_hex(string):
    return all(character.isnumeric() or character.lower() in 'abcdef' for character in string)

#Path to output file on argv[2]
def get_hex_from_output():
    with open(sys.argv[2],"r") as file:
        target = ""
        for target_part in file.read().split("\n"):
            if is_hex(target_part):
                target += target_part
    return target

if __name__ == "__main__":
    # The base_addr option aligns the address-space of angr with the ghidra address space
    proj = angr.Project(sys.argv[1], load_options={'main_opts':{'base_addr': 0x100000}, 'auto_load_libs':False})
    
    # Creating a simulation manager and explore for the "SUPER ENCRYPTED FILE BACKUP" string(marks key addr).
    simgr = proj.factory.simgr()
    simgr.explore(find=lambda s: b"SUPER ENCRYPTED FILE BACKUP" in s.posix.dumps(1))

    # We take the state we found and get the address of the current function,
    # which is rageme(int param1,? param2).
    state = simgr.found[0]
    rageme_addr = state.callstack.func_addr

    # Use a simulation manager to directly find the address of rageme(int param1,? param2).
    simgr = proj.factory.simgr()
    simgr.explore(find=rageme_addr)

    # Retrieve the value of the second argument (rsi), which is the address of the secret
    state = simgr.found[0]
    secret_addr = state.regs.rsi

    # since the key (param2) only gets changed if param1 == 1 -> supplied param to cstate,
    #  also added state as base_state to supress warning
    cstate = proj.factory.call_state(rageme_addr, 1, secret_addr, base_state=state)

    # Creating a simulation manager and explore for the "Payment reference:" string.
    # Note that we are now using cstate to initialize a simulation manager
    simgr = proj.factory.simgr(cstate)
    simgr.explore(find=lambda s: b"Payment reference:" in s.posix.dumps(1))
    
    # We take the state we found and get the address of the current function,
    # which is print_result(? param1).
    state = simgr.found[0]
    print_addr = state.callstack.func_addr


    # Use a simulation manager to directly find the address
    # of print_result(? param1).
    simgr = proj.factory.simgr(cstate)
    simgr.explore(find=print_addr)


    # Retrieve the value of the first argument (rdi), which is the address of
    # the scrambling buffer
    state = simgr.found[0]
    scrambled_addr = state.regs.rdi

    # The secret is 32 characters long, each character/byte gets its own
    # symbolic variable
    for i in range(key_size):
        cstate.mem[secret_addr + i].byte = cstate.solver.BVS('key', 8)

    # Go to print_result
    simgr = proj.factory.simgr(cstate)
    simgr.explore(find=print_addr)

    # Store target state
    target_state = simgr.found[0]

    # Convert the input to bytes and constrain the actual bytes of the
    # buffer to be equal to the bytes from the output need to multiply range of loop by 4 to get full key
    target_bytes = bytes.fromhex(get_hex_from_output())
    for i in range(key_size*4):
        buffer_byte = target_state.memory.load(scrambled_addr + i, 1)
        target_byte = target_bytes[i]
        target_state.add_constraints(buffer_byte == target_byte)

    # Load all the secret bytes into a variable
    secret = target_state.memory.load(secret_addr, key_size)

    #evaluate secret to get the key
    key = target_state.solver.eval(secret, cast_to=bytes)

    #get data from encrypted file
    with open(sys.argv[3],"rb") as file:
        encrypted_data = file.read()

    # Decryption
    decrypted_data = chacha20_decrypt(key, encrypted_data)

    #print decrypted file to standard output
    print(decrypted_data.decode('utf-8'))
    ```