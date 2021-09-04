#!/bin/bash
# Fuzz using the following parameters

OUT=results/example
MINUTES=1
HARNESS=tlul
FIRRTL=test/resources/fuzzing/TLI2C.fir
ITERATIONS=3


# Creates parent folder if it doesn't exist
if ! [ -d ${OUT} ]; then
  mkdir ${OUT}
  echo "Generated output folder to store results: ${OUT}."
  echo ""
fi

for ((i=0; i<ITERATIONS; i++))
do
  echo "Starting fuzzing run: ${i}"
  echo "Calling fuzz.sh on: ${OUT}/${i}.out ${MINUTES} ${HARNESS} ${FIRRTL}"
  echo ""
  src/fuzzing/fuzz.sh ${OUT}/${i}.out ${MINUTES} ${HARNESS} ${FIRRTL}
done
