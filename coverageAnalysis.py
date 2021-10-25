#!/usr/bin/python
import os
import sys

print("\nCreating jar file...\n")
os.system("sbt assembly")

print("\nCalling CoverageAnalysis...\n")

arguments = ' '.join(sys.argv[1:])
os.system("java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.coverage.CoverageAnalysis {SCALA_ARGS}".format(SCALA_ARGS=arguments))
sys.exit(0)
