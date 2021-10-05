import argparse
import os
import sys
import shutil
import time

# Fuzz using the following parameters

parser = argparse.ArgumentParser(description="Run the RTL fuzzer")
parser.add_argument('--firrtl', type=bool, required=True,
                    help="Whether you want to compile FIRRTL")
parser.add_argument('--harness', type=str, required=True,
                    help="The harness under test")
parser.add_argument('-t', '--time', type=int, required=True,
                    help="The in minutes, to run the fuzzer")
parser.add_argument('-f', '--folder', type=str,
                    help="The output folder location")
parser.add_argument('-i', '--iterations', type=int, required=True,
                    help="The number of iterations to run")
parser.add_argument('-a', '--afl-path', type=str, default='~/AFL',
                    help="The path to the AFL folder on disk")

args = parser.parse_args()
print(args)

seconds = args.time * 60
shifted = seconds + 5

print("Creating jar file...")
os.system("sbt assembly")

os.environ['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'
os.environ['AFL_SKIP_CPUFREQ'] = '1'

if not os.path.isdir(args.folder):
    os.mkdir(args.folder)
    print("Generated output folder to store results")

# Performs ITERATIONS fuzzing runs for given parameters
for i in range(args.iterations):
    print()
    out_folder_run = os.path.join(args.folder, str(i) + ".out")
    print("Starting fuzzing run:")
    print("Fuzzing on: \n FIRRTL:     {FIRRTL} \n HARNESS:     {HARNESS} \n MINUTES:    {MINUTES} \n OUT_FOLDER:     {OUT_FOLDER_RUN}".format(
                        MINUTES=args.time,
                        FIRRTL=args.firrtl,
                        HARNESS=args.harness,
                        OUT_FOLDER_RUN=args.folder))

    # Prevent overwriting OUT_FOLDER_RUN
    if os.path.exists(out_folder_run):
        print("WARNING! DESIRED OUTPUT WOULD BE OVERWRITTEN: {OUT_FOLDER_RUN}".format(
                        OUT_FOLDER_RUN=args.folder))
        sys.exit(1)

    # Calls AFLDriver to setup fuzzing
    print("Calling AFLDriver on: {FIRRTL} input a2j j2a {HARNESS}".format(
                        FIRRTL=args.firrtl,
                        HARNESS=args.harness))

    # Option 1 (preferred due to slightly better memory usage and possible slightly better execution speed)
    os.system("java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.afl.AFLDriver -d {FIRRTL} input a2j j2a {HARNESS} & sleep 14s".format(
                        HARNESS=args.harness,
                        FIRRTL=args.firrtl))

    os.system('timeout $time_string "{AFL_PATH}"/afl-fuzz -i seeds -o temp_out -f input -- ./fuzzing/afl-proxy a2j j2a log'.format(\
                        AFL_PATH=args.AFL_PATH))

    while not os.path.exists("temp_out/end_time"):
        time.sleep(1)

    shutil.move('temp_out', out_folder_run)

    os.system("java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.coverage.CoverageAnalysis {FIRRTL} {OUT_FOLDER_RUN} {HARNESS}".format(FIRRTL = args.firrtl, HARNESS=args.harness, OUT_FOLDER_RUN=args.folder))

sys.exit(0)
