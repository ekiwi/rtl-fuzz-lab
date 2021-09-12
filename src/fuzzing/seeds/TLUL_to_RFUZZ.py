# This script will generate a binary for the RFUZZ harness that produces the same VCD at a TLUL input
import sys
from ast import literal_eval as make_tuple

# (name, size, value)
def main(input_file):
    with open(input_file, "r") as file:
        input_data = file.read()

    cycles = input_data.split('---')
    instructions = [cycle.split('\n') for cycle in cycles]
    parsed_instructions = [[make_tuple(inst) for inst in cycle if inst] for cycle in instructions]

    cumulative_size = 0
    binary = 0
    for cycle in parsed_instructions:
        for instruction in cycle:
            _, size, value = instruction
            mask = (1 << size) - 1
            binary = ((value & mask) << cumulative_size) | binary
            cumulative_size += size

    def ceil_8(num):
        remainder = num % 8
        if remainder:
            num += 8 - remainder
        return num // 8

    output_file = "binary/rfuzz_test.hwf"
    with open(output_file, "wb") as file:
        print(binary.to_bytes(ceil_8(cumulative_size), byteorder='big'))
        file.write(binary.to_bytes(ceil_8(cumulative_size), byteorder='big'))

if __name__ == "__main__":
    main(sys.argv[1])