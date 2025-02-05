def format_hex_u32(values):
    """Convert a list of u32 integers to a continuous hex string with a single leading '0x'."""
    return "0x" + "".join(f"{num:08X}" for num in values)

# Example usage
A = [
    0xD56CA1A5, 0xA9FB7F83, 0xEDD3D803, 0xE5406DB1, 0x1C6F9D8, 0xAE36DE1E, 0x30EDD541, 0xE43DD121
]

result = format_hex_u32(A)
print(result)

def format_list_display(hex_list):
    """Format a list of hex strings to look like a Python list but without quotes."""
    return "[" + ", ".join(hex_list) + "]"

def parse_hex_u32(hex_string):
    """Convert a continuous hex string with a single leading '0x' into a list of hex strings with '0x' prefixes."""
    if not hex_string.startswith("0x"):
        raise ValueError("Invalid format: must start with '0x'")
    
    hex_string = hex_string[2:]  # Remove the leading '0x'
    
    # Split into 8-character chunks and format as hex strings with '0x'
    return [f"0x{hex_string[i:i+8]}" for i in range(0, len(hex_string), 8)]

# Example usage
hex_str = "0x3c609d594a3eae9cb85f88944be7a619497801f461809fcd60f29c8f83bbd509"

result = parse_hex_u32(hex_str)
print(format_list_display(result))

# A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
# X = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
# B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
# Y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
# N = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

# Results of online calculator
# AX mod N = 0xb604c34b004a1e50c65ec1f8920da67d99d990cf54d50156e036ddfb924a6d83
# X^3 mod N = 0x3c609d594a3eae9cb85f88944be7a619497801f461809fcd60f29c8f83bbd509
# X^2 mod N = 0x98f6b84d29bef2b281819a5e0e3690d833b699495d694dd1002ae56c426b3f8c
# X^3 + AX mod N = 0x279cda92dd1f26906f8d2a1d0cb892092f28b71575f05c03a7612c5c7df8cb16
# X^3 + AX + B mod N  = 0x4f6f3ade18ed62cf3be0db1371d598b9a5c13dd229dc1959519bc043d8bf00ee
#  Y^2 mod N =  0x55df5d5850f47bad82149139979369fe498a9022a412b5e0bedd2cfc21c3ed91

# Results of cryptocell
# x^3 = 0x58E426DC1796B9EAE0AB91931562102B867A90BAA08A93E12CCB972F18EED1DD
# y^2 = 0x9AA8BAFCF3FD1D358319A134711F620D0EDF9B543D50250D16ECDBED0926AE2E
# x^2 = 0xD56CA1A5A9FB7F83EDD3D803E5406DB101C6F9D8AE36DE1E30EDD541E43DD121