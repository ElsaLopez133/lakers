def format_hex_string(hex_str, line_length=20):
    # Remove '0x' prefix if present
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]

    try:
        data_bytes = bytes.fromhex(hex_str)
    except ValueError:
        return "Invalid hex string. Make sure it contains only hex characters."

    # Group bytes and insert line break after every `line_length` bytes
    lines = []
    for i in range(0, len(data_bytes), line_length):
        line = ' '.join(f"{b:02X}" for b in data_bytes[i:i+line_length])
        lines.append(line)

    return '\n'.join(lines)

# Ask user for input
user_input = input("Enter a hex string (e.g., 0x...): ").strip()
formatted_output = format_hex_string(user_input)
print("\nFormatted output:")
print(formatted_output)
