#!/bin/bash
# This script will perform fuzzing on the following parameters for a certain number of times

OUT=results/TLI2C.TLUL.0seed.ShortSeed.MTC.DNC.255
MINUTES=20
HARNESS=tlul
FIRRTL=src/test/resources/fuzzing/TLI2C.fir


for i in {1..3}
do
  echo "Starting fuzzing run: ${i}"
  echo "Calling fuzz.sh on: ${OUT}/${i}.out ${MINUTES} ${HARNESS} ${FIRRTL}"
  echo ""
  src/main/scala/chiseltest/fuzzing/fuzz.sh ${OUT}/${i}.out ${MINUTES} ${HARNESS} ${FIRRTL}
done
