import sys
import json
import glob
import os


"""This script will take in an out folder from RFUZZ and convert each input (stored as a JSON) into its binary form"""


"""Iterates through provided output folder and generates the binary form for each input"""
def convertFilesToBinary(input_folder, output_folder):
    if not os.path.isdir(output_folder):
        os.mkdir(output_folder)

    for filepath in glob.glob(input_folder + '/*'):
        filename = filepath.split("/")[-1]
        if filename != "latest.json" and filename != "config.json":
            print("Processing: " + filename)

            with open(filepath) as input:
                data = json.load(input)
            binary = generateBinary(data)
            with open(output_folder + "/" + filename.split(".")[0] + ".hwf", 'wb') as new_file:
                new_file.write(binary)


"""Converts data from a single file into binary input"""
def generateBinary(data):
    byteArray = bytearray(data['entry']['inputs'])
    print(byteArray)
    return byteArray

if __name__ == "__main__":
    input_folder = sys.argv[1]
    output_folder = sys.argv[2]
    convertFilesToBinary(input_folder, output_folder)