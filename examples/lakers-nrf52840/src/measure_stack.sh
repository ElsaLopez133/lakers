#!/bin/bash

# first, check it compiles
if ! cargo build --target=thumbv7em-none-eabihf 2>/dev/null; then
    echo "Compilation failed"
    exit 1
fi
echo "Compilation successful"

# flash and get the amount of bytes painted
echo "Flashing..."
cargo_output=$(cargo run --target=thumbv7em-none-eabihf 2>/dev/null | egrep -o "==.*==")
painted_bytes=$(echo $cargo_output | grep -o "total of [0-9]\+" | awk '{print $3}')
from_to=$(echo $cargo_output | grep -o "from.*")
stack_start=$(echo $from_to | awk '{print $2}')
stack_end=$(echo $from_to | awk '{print $4}')
printf "Painted $painted_bytes bytes from $stack_start to $stack_end\n"

# divide by 4 to get the number of words
words=$((painted_bytes / 4))

# get the amount of memory used
# example concrete command: probe-rs read b32 0x20000080 434 --chip nRF52840_xxAA | tr ' ' '\n' | grep deaddead | wc -l | awk '{print $1*4}'
remaining=$(
    probe-rs read b32 $stack_end $words --chip nRF52840_xxAA | \
    tr ' ' '\n' | \
    grep deadbeef | \
    wc -l | \
    awk '{print $1*4}'
)
used=$((painted_bytes - remaining))
printf "Used $used bytes\n"