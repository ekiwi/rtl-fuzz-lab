#!/bin/bash
# This script will perform fuzzing on the following parameters for a certain number of times

OUT=results/TLI2C.TLUL.0seed.ShortSeed.MTC.DNC.255
MINUTES=20
HARNESS=tlul
FIRRTL=test/resources/fuzzing/TLI2C.fir


# Creates parent folder if it doesn't exist
if ! [ -d ${OUT} ]; then
  mkdir ${OUT}
  echo "Generated output folder to store results: ${OUT}."
  echo ""
fi

for i in {1..3}
do
  echo "Starting fuzzing run: ${i}"
  echo "Calling fuzz.sh on: ${OUT}/${i}.out ${MINUTES} ${HARNESS} ${FIRRTL}"
  echo ""
  src/fuzzing/fuzz.sh ${OUT}/${i}.out ${MINUTES} ${HARNESS} ${FIRRTL}
done
