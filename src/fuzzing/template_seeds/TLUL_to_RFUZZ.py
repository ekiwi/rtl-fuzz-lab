# This script will generate a binary for the RFUZZ harness that produces the same VCD at a TLUL input
import sys
from ast import literal_eval as make_tuple

# TODO: 21 is generated for the pop function defined in the RFUZZ harness. Please generalize 21 as such.
bytesPerCycle = 21

def main(input_file):
    with open(input_file, "r") as file:
        input_data = file.read()

    cycles = input_data.split('---')
    allInsts = [cycle.split('\n') for cycle in cycles]
    parsed_instructions = [[make_tuple(inst) for inst in cycle if inst] for cycle in allInsts]

    allCycleBinary = []
    for cycle in parsed_instructions:
        binary = 0
        cumulative_size = 0
        for inst in cycle:
            _, size, value = inst
            mask = (1 << size) - 1
            binary = ((value & mask) << cumulative_size) | binary
            cumulative_size += size
        cumulative_size = bytesPerCycle*8

        zero_padding = cumulative_size - len(bin(binary)[2:])
        full_value = "0"*zero_padding + bin(binary)[2:]
        binary = [full_value[i:i+8] for i in range(0, len(full_value), 8)]
        binary.reverse()
        binary = ''.join(binary)
        allCycleBinary.append(binary)

    finalBinary = int(''.join(allCycleBinary), 2)

    output_file = "binary/RFUZZ_longSeed.hwf"
    with open(output_file, "wb") as file:
        print(finalBinary.to_bytes(21*len(cycles), byteorder='big'))
        file.write(finalBinary.to_bytes(21*len(cycles), byteorder='big'))

def ceil_8(num):
    remainder = num % 8
    if remainder:
        num += 8 - remainder
    return num // 8


if __name__ == "__main__":
    main(sys.argv[1])
