import argparse
import os
import sys
import shutil
import time

# Fuzz using the following parameters

parser = argparse.ArgumentParser(description="Run RTLFuzzLab")

# Python Arguments
parser.add_argument('-t', '--time', type=int, required=True,
                    help="The time, in minutes, to run the fuzzer")
parser.add_argument('-f', '--folder', type=str,
                    help="The output folder location")
parser.add_argument('-i', '--iterations', type=int, required=True,
                    help="The number of iterations to run")
parser.add_argument('-a', '--afl-path', type=str, default='~/AFL',
                    help="The path to the AFL folder")
parser.add_argument('--seed', type=str, default="",
                    help="Name of the seed in src/fuzzing/template_seeds/ to fuzz on")

# Scala Arguments
parser.add_argument('--firrtl', type=str, required=True,
                    help="Path to FIRRTL")
parser.add_argument('--harness', type=str, required=True,
                    help="The harness under test")
parser.add_argument('-d', '--directedness', type=bool, default=False,
                    help="Whether to fuzz the entire hardware")
parser.add_argument('--vcd', type=bool, default=False,
                    help="Generate VCD")
parser.add_argument('--feedback', type=int, default=255,
                    help="Number of toggles counted per input")
parser.add_argument('--mtc', type=bool, default=False,
                    help="False = MuxToggleCoverage, True = Full MTC")

args = parser.parse_args()

supported_harnesses = ['rfuzz', 'tlul']
if args.harness not in supported_harnesses:
    print("ERROR: Unrecognized harness")
    sys.exit(-1)

seconds = args.time * 60
shifted = seconds + 5

print("Creating jar file...")
os.system("sbt assembly")

os.environ['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'
os.environ['AFL_SKIP_CPUFREQ'] = '1'

if not os.path.isdir(args.folder):
    os.mkdir(args.folder)
    print("Generated output folder to store results")

# Moves seed to correct folder
if args.seed:
    print("Clearing seeds folder...")
    for filename in os.listdir('seeds'):
        file_path = os.path.join('seeds', filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print('Failed to delete %s. Reason: %s' % (file_path, e))
            exit()

    print("Copying seed to seeds folder:", args.seed)
    f = os.path.join('src/fuzzing/template_seeds', args.seed)
    shutil.copy(f, 'seeds')

# Performs ITERATIONS fuzzing runs for given parameters
for i in range(args.iterations):
    print()
    out_folder_run = os.path.join(args.folder, str(i) + ".out")
    print("Starting fuzzing run:", i)
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
    print("java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.afl.AFLDriver --FIRRTL {FIRRTL} --Harness {HARNESS} --Directedness {DIRECTEDNESS} --Feedback {FEEDBACK} --VCD {VCD} --MuxToggleCoverage {MTC}".format(FIRRTL=args.firrtl,
                        HARNESS=args.harness,
                        DIRECTEDNESS=str(args.directedness).lower(),
                        FEEDBACK=args.feedback,
                        VCD=str(args.vcd).lower(),
                        MTC=str(args.mtc).lower()))
    os.system("java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.afl.AFLDriver --FIRRTL {FIRRTL} --Harness {HARNESS} --Directedness {DIRECTEDNESS} --Feedback {FEEDBACK} --VCD {VCD} --MuxToggleCoverage {MTC} &".format(FIRRTL=args.firrtl,
                        HARNESS=args.harness,
                        DIRECTEDNESS=str(args.directedness).lower(),
                        FEEDBACK=args.feedback,
                        VCD=str(args.vcd).lower(),
                        MTC=str(args.mtc).lower()))

    os.system("sleep 13s")

    os.system('timeout {TIME_STRING}s {AFL_PATH}/afl-fuzz -d -i seeds -o temp_out -f input -- ./fuzzing/afl-proxy a2j j2a log'.format(
                        AFL_PATH=args.afl_path,
                        TIME_STRING=str(shifted)))

    while not os.path.exists("temp_out/end_time"):
        time.sleep(1)

    shutil.move('temp_out', out_folder_run)

    os.system("java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.coverage.CoverageAnalysis {FIRRTL} {OUT_FOLDER_RUN} {HARNESS}".format(
                        FIRRTL=args.firrtl,
                        HARNESS=args.harness,
                        OUT_FOLDER_RUN=args.folder))

sys.exit(0)
