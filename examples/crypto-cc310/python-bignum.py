class LargeHexNumber:
    @staticmethod
    def mod_add(hex1, hex2, mod_n):
        """Modular addition: (hex1 + hex2) mod N"""
        return f'{(int(hex1, 16) + int(hex2, 16)) % int(mod_n, 16):x}'

    @staticmethod
    def mod_subtract(hex1, hex2, mod_n):
        """Modular subtraction: (hex1 - hex2) mod N"""
        return f'{(int(hex1, 16) - int(hex2, 16)) % int(mod_n, 16):x}'

    @staticmethod
    def mod_multiply(hex1, hex2, mod_n):
        """Modular multiplication: (hex1 * hex2) mod N"""
        return f'{(int(hex1, 16) * int(hex2, 16)) % int(mod_n, 16):x}'

    @staticmethod
    def mod_power(hex1, hex2, mod_n):
        """Modular exponentiation: (hex1 ^ hex2) mod N"""
        return f'{pow(int(hex1, 16), int(hex2, 16), int(mod_n, 16)):x}'

    @staticmethod
    def mod_inverse(hex1, mod_n):
        """Modular multiplicative inverse of hex1 mod N"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            else:
                gcd, x, y = extended_gcd(b % a, a)
                return gcd, y - (b // a) * x, x

        a = int(hex1, 16)
        m = int(mod_n, 16)
        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            raise ValueError('Modular inverse does not exist')
        else:
            return f'{x % m:x}'
    
    @staticmethod
    def add(hex1, hex2):
        """Normal addition: hex1 + hex2"""
        return f'{int(hex1, 16) + int(hex2, 16):x}'
    
    @staticmethod
    def divide(hex1, hex2):
        """Normal division: hex1 / hex2"""
        if int(hex2, 16) == 0:
            raise ValueError('Division by zero is not allowed')
        return f'{int(hex1, 16) // int(hex2, 16):x}'
    
    @staticmethod
    def mod_reduce(hex1, mod_n):
        """Reduction modulo N: hex1 mod N"""
        return f'{int(hex1, 16) % int(mod_n, 16):x}'

def format_list_display(hex_list):
    """Format a list of hex strings to look like a Python list but without quotes."""
    return "[" + ", ".join(hex_list) + "]"

def parse_hex_u32(hex_string):
    """Convert a continuous hex string with a single leading '0x' into a list of hex strings with '0x' prefixes."""
    # Split into 8-character chunks and format as hex strings with '0x'
    return [f"0x{hex_string[i:i+8]}" for i in range(0, len(hex_string), 8)]



# Example usage
if __name__ == "__main__":
    # 256-bit hex number examples
    test_a = '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFE'
    a = '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC'
    N = '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'
    p = 'FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'
    b = '0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'
    x = '0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'
    x = '0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296'
    y = '0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5'
    P_PLUS_1_DIV_4 = '0x3FFFFFFF400000004000000040000000400000003FFFFFFFFFFFFFFF3FFFFFFF'
    test_b = '0x100000000'
    
    # print("Mod Add:", LargeHexNumber.mod_add(a, b, N))
    # print("Mod Multiply:", format_list_display(parse_hex_u32(LargeHexNumber.mod_multiply(N, test_b, N))))

    print("Mod Square:", format_list_display(parse_hex_u32(LargeHexNumber.mod_multiply(x, x, N))))
    x_3 = LargeHexNumber.mod_power(x, '0x3', N)
    print("Mod cube:", format_list_display(parse_hex_u32(x_3)))
    ax = LargeHexNumber.mod_multiply(a, x, N)
    print("Mod ax:", format_list_display(parse_hex_u32(ax)))
    sum_1 = LargeHexNumber.mod_add(x_3, ax, N)
    print("Mod x^3 + ax:", format_list_display(parse_hex_u32(sum_1)))
    sum_2 = LargeHexNumber.mod_add(sum_1, b, N)
    print("Mod x^3 + ax + b:", format_list_display(parse_hex_u32(sum_2)))
    print("Mod  y Square:", format_list_display(parse_hex_u32(LargeHexNumber.mod_multiply(y, y, N))))
    # print("Mod square test_a:", LargeHexNumber.mod_multiply(test_a,test_a, N))

    p_sum_1 = LargeHexNumber.add(N, '0x1')
    p_sum_1_div_4 = LargeHexNumber.divide(p_sum_1, '0x4')
    print("p_sum_1 :",format_list_display(parse_hex_u32(p_sum_1)))
    print("p_sum_1_div_4:",format_list_display(parse_hex_u32(p_sum_1_div_4)))

    sqrt_1 = LargeHexNumber.mod_power(sum_2, p_sum_1_div_4, N)
    print("Mod sqrt sum_2 (1):",format_list_display(parse_hex_u32(sqrt_1)))
    sqrt_2 = LargeHexNumber.mod_subtract(N,sqrt_1, N)
    print("Mod sqrt sum_2 (2):", format_list_display(parse_hex_u32(sqrt_2)))

    temp = '0000FFF6FFFEFFFE00000001FFFFFFFDFFFF001100000004000000020000FFF8'
    print("Mod reduce:", format_list_display(parse_hex_u32(temp)))

