def calculate_np(operand_size_bits, n_parts, a=32, x=8):
    """
    Calculate NP value for Barrett reduction.
    
    Args:
        operand_size_bits: Size of the operand in bits (N)
        n_parts: Array of 32-bit words representing N
        a: Size of the PKA engine word in bits (default 32)
        x: Maximal count of extra bits in PKA operations (default 8)
    
    Returns:
        list: Array of 32-bit words representing NP
    """
    # Calculate total bits needed for 2^(N+A+X-1)
    print("operand_size_bits: {}   a: {}   x: {}  ".format(operand_size_bits,a,x))
    total_bits = operand_size_bits + a + x - 1
    
    # Calculate word and bit indices
    word_index = total_bits // 32
    bit_index = total_bits % 32
    print("word_index: {} Bit_index: {} ".format(word_index, bit_index))

    # Create the numerator array with same size as input
    numerator = [0] * (len(n_parts) + 3)
    
    # Set the appropriate bit
    if word_index < len(n_parts) + 3:
        numerator[len(n_parts) + 3 - 1 - word_index] = 1 << bit_index
    print("Numerator in hex: [" + ", ".join(f"0x{x:08X}" for x in numerator) + "]")

    # Convert numerator and n_parts to integers for division
    num = 0
    n = 0
    for i in range(len(n_parts) + 3):
        num = (num << 32) | numerator[i]
    for i in range(len(n_parts)):
        n = (n << 32) | n_parts[i]
    print("numerator: {}  n: {}".format(num,n))
    
    if n == 0:
        raise ValueError("N cannot be zero")
        
    # Perform division
    result  = num // n
    print("NP: {}".format(result))
   # Convert to array of u32 values
    result_array = []
    
    # Extract 32 bits at a time
    while result > 0:
        result_array.insert(0, result & 0xFFFFFFFF)
        result >>= 32
        
    # Print array in hexadecimal format
    print("NP in Hex: [" + ", ".join(f"0x{x:08X}" for x in result_array) + "]")
    
    return result_array

def print_in_array_format(value, part_size, bit_width):
    """
    Prints a large number in array format (split into chunks of bits).
    
    Args:
    - value (int): The value to be printed.
    - part_size (int): The number of bits in each part (e.g., 32 for 32 bits).
    - bit_width (int): The total bit width of the number (e.g., 256).
    """
    num_parts = bit_width // part_size
    result_array = []
    for i in range(num_parts):
        shift_amount = (num_parts - 1 - i) * part_size
        part = (value >> shift_amount) & ((1 << part_size) - 1)
        result_array.append(f"0x{part:08X}")
    
    return result_array


# Example usage
if __name__ == "__main__":
    # Example input array
    # N_parts = [0x00000000, 0x00000000, 0x00000000, 0x00000000,
    #            0x00000000, 0x00000000, 0x00000000, 0x00000015]
    # Example of N prime of 64 bits: 9223372036854775837
    N_parts = [0x80000000, 0x0000001d]

    # Count the significant bits used in the array
    operand_size_bits = 64
    # operand_size_bits = sum(len(hex(part).lstrip('0x')) * 4 for part in N_parts)

    print("N_bits: ",operand_size_bits)  # Should give 8 bits

    NP_parts = calculate_np(operand_size_bits, N_parts)