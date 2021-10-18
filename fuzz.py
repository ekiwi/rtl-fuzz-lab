import argparse
import os
import sys
import shutil
import time

if ' -- ' not in " ".join(sys.argv):
    print("Please provide Scala arguments")
    sys.exit(-1)

python_args, scala_args = " ".join(sys.argv).split(' -- ')
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

args = parser.parse_args(python_args.split()[1:])

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
    print("Fuzzing on: \n MINUTES:    {MINUTES} \n OUT_FOLDER:     {OUT_FOLDER_RUN}".format(
                        MINUTES=args.time,
                        OUT_FOLDER_RUN=args.folder))

    # Prevent overwriting OUT_FOLDER_RUN
    if os.path.exists(out_folder_run):
        print("WARNING! DESIRED OUTPUT WOULD BE OVERWRITTEN: {OUT_FOLDER_RUN}".format(
                        OUT_FOLDER_RUN=args.folder))
        sys.exit(1)

    # Calls AFLDriver to setup fuzzing
    print("Calling AFLDriver on: {SCALA_ARGS} input a2j j2a ".format(SCALA_ARGS=scala_args))

    os.system("java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.afl.AFLDriver {SCALA_ARGS}".format(
                        SCALA_ARGS=scala_args))

    os.system("sleep 13s")

    os.system('timeout {TIME_STRING}s {AFL_PATH}/afl-fuzz -d -i seeds -o temp_out -f input -- ./fuzzing/afl-proxy a2j j2a log'.format(
                        AFL_PATH=args.afl_path,
                        TIME_STRING=str(shifted)))

    while not os.path.exists("temp_out/end_time"):
        time.sleep(1)

    shutil.move('temp_out', out_folder_run)

sys.exit(0)
