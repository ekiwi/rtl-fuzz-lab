# RTLFuzzLab: a modular hardware fuzzing framework

RTLFuzzLab is designed to allow for easy experimentation with Coverage Directed Mutational Fuzz Testing on RTL designs.

![Visualization of software framework](overview.svg)

For details about RTLFuzzLab, please see our abstract released in WOSET 2021.

[Abstract](https://woset-workshop.github.io/WOSET2021.html#article-10)

Fajardo, Brandon and Laeufer, Kevin and Bachrach, Jonathan and Sen, Koushik. **RTLFuzzLab: Building A Modular Open-Source Hardware Fuzzing Framework.** In *Workshop on Open-Source EDA Technology (WOSET)*, 2021.

BibTeX citation:
```
@inproceedings{fajardo2021rtlfuzzlab,
  title={{RTLFuzzLab: Building A Modular Open-Source Hardware Fuzzing Framework}},
  author={Fajardo, Brandon and Laeufer, Kevin and Bachrach, Jonathan and Sen, Koushik},
  booktitle={Workshop on Open-Source EDA Technology (WOSET)},
  year={2021}
}
```

## Installation

### Dependencies
The following dependencies are required to run this software:
* make
* gcc
* g++
* java
* sbt
* verilator
* matplotlib
* scipy


### Get AFL Fork
```.sh
git clone https://github.com/ekiwi/AFL AFL_rtl_fuzz_lab
cd AFL_rtl_fuzz_lab
make
```
This AFL fork is functionally identical to upstream AFL.
Our version produces some additional meta-data that is used to produce better plots.


### Clone repo
```.sh
git clone https://github.com/ekiwi/rtl-fuzz-lab
```

### Run setup script (setup.sh)
```.sh
./setup.sh
```
This will create two fifos (`a2j` and `j2a`), a `seeds` directory and compile the proxy to interface with AFL.

## Usage
### Run fuzzing script (fuzz.sh)
Script takes in two sets of arguments, separated by '---'.
1. First set is arguments to the Python script, fuzz.py.
> Execute "fuzz.py -h ---" for argument options to the Python script

> Existing seeds for --seed argument are available in: `rtl-fuzz-lab/src/fuzzing/template_seeds/binary`

2. Second set is arguments passed to the Scala script, AFLDriver.
The following are options to pass in:
> --FIRRTL <path>: FIRRTL design which is to be fuzzed. Existing designs under: test/resources/fuzzing

> --Harness <rfuzz/tlul>: Handles converting input bytes to hardware inputs. Current options: rfuzz, tlul (bus-centric)

> --Directed: Flag for ignoring coverage in bus-monitors

> --VCD: Flag for generating a VCD (value change dump)

> --Feedback <number>: Maximum number of times a coverage point can trigger per input

> --MuxToggleCoverage <boolean>: Options: false (Mux Toggle Coverage), true (Full Mux Toggle Coverage)

Example:
```.sh
python3 fuzz.py -time 3 -folder ./example -iterations 1 -alf-path ~/AFL_rtl_fuzz_lab --seed TLI2C_longSeed.hwf --- --FIRRTL test/resources/fuzzing/TLI2C.fir --Harness tlul --Directed --MuxToggleCoverage false --Feedback 255
```

### Analyze coverage (coverageAnalysis.py)
Script takes in set of arguments equivalent to second set of arguments to fuzz.py described above.
In addition, script takes in --Folder <folder> argument to specify location of folder to analyze.

Example:
```.sh
python3 coverageAnalysis.py --FIRRTL test/resources/fuzzing/TLI2C.fir --Harness tlul --Directed --MuxToggleCoverage false --Feedback 255 --Folder example/0.out
```

### Plot results (plotCoverage.py)
Takes in arguments: `do_average PATH [PATH ...]`
> See plotCoverage.py -h for argument options
Outputs png of generated plot as rtl-fuzz-lab/coveragePlot.png

Example:
```.sh
python3 plotCoverage.py true example
```

## Acknowledgments
Integrating AFL with our Scala based fuzz bench would not have been possible without the awesome AFL proxy infrastructure from the [JQF](https://github.com/rohanpadhye/JQF) project.

## License
This code is open-source under a BSD license. See the `LICENSE` file for more information.
