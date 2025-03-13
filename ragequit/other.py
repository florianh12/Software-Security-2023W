'''
def ex1_string_found(state):
    return b"EXAMPLE1_STRING" in state.posix.dumps(1)

proj = angr.Project('./ex1', auto_load_libs=False)
simulation_manager = proj.factory.simgr()
simulation_manager.explore(find=ex1_string_found)
print(simulation_manager)

state = simulation_manager.found[0]
address = state.callstack.func_addr
print(hex(address))

simulation_manager = proj.factory.simgr()
simulation_manager.explore(find=address)
print(simulation_manager)
'''
'''
import angr

proj = angr.Project('./ragequit/ragequit_000', auto_load_libs=False)


simgr1 = proj.factory.simgr()
simgr1.explore(find=lambda s: b"Payment reference: " in s.posix.dumps(1))
s = simgr1.found[0]
var = s.mem[s.regs.rsi - 0x18].qword.resolved;
'''
'''
import sys
def is_hex(string):
    return all(character.isnumeric() or character.lower() in 'abcdef' for character in string)

with open(sys.argv[1],"r") as file:
    target = ""
    for target_part in file.read().split("\n"):
        if is_hex(target_part):
            target += target_part
print(target)
'''
'''
import nacl.secret
import nacl.utils
import sys

def chacha20_encrypt(key, plaintext):
    # Generate a random nonce
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    # Create a ChaCha20 cipher with the provided key
    cipher = nacl.secret.SecretBox(key)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext, nonce)

    return ciphertext

def chacha20_decrypt(key, ciphertext):
    # Extract the nonce from the ciphertext
    nonce = ciphertext[:nacl.secret.SecretBox.NONCE_SIZE]

    # Create a ChaCha20 cipher with the provided key
    cipher = nacl.secret.SecretBox(key)

    # Decrypt the ciphertext
    try:
        decrypted = cipher.decrypt(ciphertext[nacl.secret.SecretBox.NONCE_SIZE:], nonce)
        return decrypted
    except nacl.exceptions.CryptoError as e:
        print(f"Decryption failed: {e}")
        return None

# Example usage:
key = b'\x08\x05\x95B\x08a\x82H\x08\x8d\xdeH\t#\xbe\xf7?\xc7\xb3\xef?o\x826>\x00\x00\x00\x00\x00\x00\x00'
plaintext = b'This is a secret message.'

# Encryption
with open(sys.argv[1],"rb") as file:
    encrypted_data = file.read()

# Decryption
decrypted_data = chacha20_decrypt(key, encrypted_data)
if decrypted_data is not None:
    print(f'Decrypted: {decrypted_data.decode()}')
else:
    print("Decryption failed. Check key and nonce.")
print(encrypted_data)
'''
'''
import angr
import nacl.secret
import nacl.utils

key_size = 32

def chacha20_decrypt(key, ciphertext):
    # Extract the nonce from the ciphertext
    nonce = ciphertext[:nacl.secret.SecretBox.NONCE_SIZE]

    # Create a ChaCha20 cipher with the provided key
    cipher = nacl.secret.SecretBox(key)

    # Decrypt the ciphertext
    try:
        decrypted = cipher.decrypt(ciphertext[nacl.secret.SecretBox.NONCE_SIZE:], nonce)
        return decrypted
    except nacl.exceptions.CryptoError as e:
        print(f"Decryption failed: {e}")
        return None

def is_hex(string):
    return all(character.isnumeric() or character.lower() in 'abcdef' for character in string)

#Path to output file on argv[2]
def get_hex_from_output():
    with open("./ragequit/ragequit_output.txt","r") as file:
        target = ""
        for target_part in file.read().split("\n"):
            if is_hex(target_part):
                target += target_part
    return target

proj = angr.Project('./ragequit/ragequit_000', auto_load_libs=False)

# Creating a simulation manager and explore for the "Welcome!" string.
# Instead of creating a find function, we can just use a lambda function.
# Hint: ragequit's equivalent to "Welcome!" is "SUPER ENCRYPTED FILE BACKUP"
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"SUPER ENCRYPTED FILE BACKUP" in s.posix.dumps(1))

# We take the state we found and get the address of the current function,
# which is crackme(const char *).
state = simgr.found[0]
crackme_addr = state.callstack.func_addr
# Use a simulation manager to directly find the address of crackme(const char *).
simgr = proj.factory.simgr()
simgr.explore(find=crackme_addr)

# Retrieve the value of the second argument (rsi), which is the address of the secret
state = simgr.found[0]
secret_addr = state.regs.rsi

cstate = proj.factory.call_state(crackme_addr, 1, secret_addr, base_state=state)

# Creating a simulation manager and explore for the "Scrambled secret is:" string.
# Hint: ragequit's equivalent would be "Payment reference:"
# Also: note that we are now using cstate to initialize a simulation manager
simgr = proj.factory.simgr(cstate)
simgr.explore(find=lambda s: b"Payment reference:" in s.posix.dumps(1))

# We take the state we found and get the address of the current function,
# which is print_scrambled(const unsigned char *).
state = simgr.found[0]
print_addr = state.callstack.func_addr

# Use a simulation manager to directly find the address
# of print_scrambled(const unsigned char *).
simgr = proj.factory.simgr(cstate)
simgr.explore(find=print_addr)

# Retrieve the value of the first argument (rdi), which is the address of
# the scrambling buffer
state = simgr.found[0]
scrambled_addr = state.regs.rdi

# The secret is 32*4 characters long, each character/byte gets its own
# symbolic variable
for i in range(key_size):
    cstate.mem[secret_addr + i].byte = cstate.solver.BVS('key', 8)

# Go to print_scrambled
simgr = proj.factory.simgr(cstate)
simgr.explore(find=print_addr)

# Store target state
target_state = simgr.found[0]

# Convert the input to bytes and constrain the actual bytes of the
# buffer to be equal to the bytes from the output *4 needed to get full key
target_bytes = bytes.fromhex(get_hex_from_output())
for i in range(key_size*4):
    buffer_byte = target_state.memory.load(scrambled_addr + i, 1)
    target_byte = target_bytes[i];
    target_state.add_constraints(buffer_byte == target_byte)

# Load all the secret bytes into a variable
secret = target_state.memory.load(secret_addr, key_size)
key = target_state.solver.eval(secret, cast_to=bytes)
print(key)
print(len(key))


# Encryption
with open("./ragequit/info.secenv-submission.rgq","rb") as file:
    encrypted_data = file.read()

# Decryption
decrypted_data = chacha20_decrypt(key, encrypted_data)
if decrypted_data is not None:
    print(f'Decrypted: {decrypted_data.decode()}')
else:
    print("Decryption failed. Check key and nonce.")
print(encrypted_data)
'''
import nacl.bindings as bind

with open("./ragequit/info.secenv-submission.rgq","rb") as file:
    encrypted_data = file.read()

state1 = bind.crypto_secretstream_xchacha20poly1305_state()
header = encrypted_data[:bind.crypto_secretstream_xchacha20poly1305_HEADERBYTES]
ciphertext = encrypted_data[bind.crypto_secretstream_xchacha20poly1305_HEADERBYTES:]
key = b'\x14\xb6\x10Z\xcd\xb0<\x81\x03:\xcd|(6,\xd4K~Y6\x8cy \x82(_\xfe\xee\xcf\x86\xbc\x04'
bind.crypto_secretstream_xchacha20poly1305_init_pull(state=state1,header=header,key=key)
print(bind.crypto_secretstream_xchacha20poly1305_pull(state=state1,c=ciphertext,ad=None))