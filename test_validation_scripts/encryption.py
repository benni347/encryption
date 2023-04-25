from hashlib import blake2b

h = blake2b(digest_size=64)

msg = b"faddasfjdk102173781284---...,,,...---##''++\"\\sfklaskfdakjfojdsakdfsda.-012312"

h.update(msg)

digest = h.digest()
hexdigest = h.hexdigest()


byte_array = bytes.fromhex(hexdigest)

# Convert byte array to a list of integers in the desired format
int_list = [f'0x{b:02x},' for b in byte_array]

# Print the list of integers with the desired format
for i in int_list:
    print(i)
