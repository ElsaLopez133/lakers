# Comments
# VMA (Virtual Memory Address): The address the section is located at during execution.
# LMA (Load Memory Address): The address the section is located at in the binary image.
# Size: The size of the section in bytes.
# Align: The alignment requirement of the section.

import re
import sys

def analyze_memory_usage(input_file, output_file):
    # Define the substrings to search for
    patterns = [
        'responder-',
        'initiator-',
        'liblakers-',
        'liblakers_shared'
    ]

    # Initialize section sizes
    sections = {
        '.text': 0,
        '.rodata': 0,
        '.data': 0,
        '.bss': 0,
        '.uninit': 0,
        '.defmt': 0
    }
    current_section = None
    previous_section = None

    # Open the input and output files
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            # print(line.strip())
            # Check if the line contains a section header
            section_match = re.search(r'\s*(\.text|\.rodata|\.data|\.bss| \.uninit| \.defmt)\s*', line)
            if section_match:
                current_section = section_match.group(1).strip()
                if current_section != previous_section:
                    outfile.write(f"Current Section: {current_section}\n")
                    previous_section = current_section

            # Check if the line contains any of the patterns
            match = re.search(r'(\w+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(.*)', line)
            if current_section and any(pattern in line for pattern in patterns):
                if match:
                    vma, lma, size, align, symbol = match.groups()
                    size_int = int(size, 16)  # Convert hex size to int
                    sections[current_section] += size_int
                    outfile.write(f"Section: {current_section}, VMA: {vma}, LMA: {lma}, Size: {size}, Symbol: {symbol}\n")

        # Write summary at the end
        total_size = sum(sections.values())
        outfile.write("\nMemory Usage Summary:\n")
        for section, size in sections.items():
            percentage = (size / total_size) * 100 if total_size > 0 else 0
            outfile.write(f"{section}: {size} bytes ({percentage:.2f}%)\n")
        outfile.write(f"Total size: {total_size} bytes\n")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py input_file output_file")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    analyze_memory_usage(input_file, output_file)
    print(f"Memory usage analysis has been written to {output_file}")
