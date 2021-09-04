#!/bin/bash
# Fuzz using the following parameters

if ! [ $# -eq 6 ] ; then
    echo "Incorrect number of arguments! Must pass in arguments: FIRRTL HARNESS MINUTES OUT_FOLDER ITERATIONS AFL_PATH" >&2
    exit 1
fi

FIRRTL=$1
HARNESS=$2
MINUTES=$3
OUT_FOLDER=$4
ITERATIONS=$5
AFL_PATH=$6


re='^[0-9]+$'
if ! [[ $MINUTES =~ $re ]] ; then
   echo "MINUTES argument must be a number" >&2
   exit 1
fi

# Add 5 seconds to fuzzing time to account for startup time to fuzzing
((SECONDS=$MINUTES*60))
((shifted=$SECONDS+5))
time_string=${shifted}s


# Creates parent folder if it doesn't exist
if ! [ -d ${OUT_FOLDER} ]; then
  mkdir ${OUT_FOLDER}
  echo "Generated output folder to store results: ${OUT_FOLDER}"
  echo ""
fi


# Creates jar file to allow execution of Scala code using terminal commands
sbt assembly


# Performs ITERATIONS fuzzing runs for given parameters
for ((i=1; i<=ITERATIONS; i++))
do
  echo ""
  echo "Starting fuzzing run: ${i}"
  OUT_FOLDER_RUN="${OUT_FOLDER}/${i}.out"
  echo -e "Fuzzing on: \n FIRRTL:     ${FIRRTL} \n HARNESS:    ${HARNESS} \n MINUTES:    ${MINUTES} \n OUT_FOLDER: ${OUT_FOLDER_RUN}"
  echo ""


  # Prevent overwriting OUT_FOLDER_RUN
  if [ -d ${OUT_FOLDER_RUN} ]; then
    echo "WARNING! DESIRED OUTPUT FOLDER WOULD BE OVERWRITTEN: ${OUT_FOLDER_RUN}. Exiting to preserve fuzzing results."
    exit 1
  fi


  # Calls AFLDriver to setup fuzzing
  echo "Calling AFLDriver on: ${FIRRTL} input a2j j2a ${HARNESS}"
  echo ""

  # Option 1 (preferred due to slightly better memory usage and possible slightly better execution speed)
  java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.afl.AFLDriver ${FIRRTL} input a2j j2a ${HARNESS} &
  sleep 13s
  # Option 2
  #sbt "runMain fuzzing.afl.AFLDriver test/resources/fuzzing/TLI2C.fir input a2j j2a TLUL" &
  #sleep 20s


  # Calls AFL to fuzz for the specified period of time
  timeout $time_string "${AFL_PATH}"/afl-fuzz -i seeds -o temp_out -f input -- ./fuzzing/afl-proxy a2j j2a log

  # Moves result to desired location. Wait until end_time file is generated by AFLDriver.
  while ! [ -f "temp_out/end_time" ]; do
    sleep 1
  done

  mv temp_out ${OUT_FOLDER_RUN}

  # Generate coverage results with CoverageAnalysis.scala
  java -cp target/scala-2.12/rtl-fuzz-lab-assembly-0.1.jar fuzzing.coverage.CoverageAnalysis ${FIRRTL} ${OUT_FOLDER_RUN} ${HARNESS}


done
exit 0