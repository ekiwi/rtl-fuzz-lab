# RTLFuzzLab: Building A Modular Open-Source Hardware Fuzzing Framework

RTLFuzzLab is a software designed to allow for easy experimentation with Coverage Directed Mutational Fuzz Testing on RTL designs.

[Software framework visualization](https://github.com/ekiwi/rtl-fuzz-lab/files/7111369/Slide5.pdf)

## Installation

### Get AFL Fork
```.sh
git clone https://github.com/ekiwi/AFL
cd AFL
make
```
This AFL fork is logically identical to AFL. The only addition is birth times to the names of generated inputs for improved plotting.


### Download repo
```.sh
git clone https://github.com/ekiwi/rtl-fuzz-lab
```

### Run setup script
```.sh
./setup.sh
```

## Usage
### Populate seeds folder
Existing seeds are available in the folder: `rtl-fuzz-lab/src/fuzzing/seeds/binary`

Example:
```.sh
cp src/fuzzing/seeds/binary/TLI2C_shortSeed.hwf seeds
```

### Run fuzzing script
Takes in arguments: FIRRTL Harness Minutes Out_folder Iterations AFL_path

Example:
```.sh
./fuzz.sh test/resources/fuzzing/TLI2C.fir tlul 1 results/example 3 ~/AFL
```

#### Arguments:
* FIRRTL: FIRRTL design which is to be fuzzed

> Existing FIRRTL designs can be found under test/resources/fuzzing

* Harness: Method for applying input bytes to the hardware design

> Current available harness options: rfuzz (direct), tlul (bus-centric)

> The tlul harness should only be used on TL FIRRTL designs, as it is bus-central to TL-UL designs

* Minutes: Number of minutes to fuzz for (per fuzzing iteration)
* Out_folder: Folder in which to output fuzzing results
* Iterations: Number of iterations to performing fuzzing using current parameters
* AFL_path: Path to forked AFL folder



### Plot results
Takes in arguments: do_average PATH [PATH ...]

Example:
```.sh
python3 plotCoverage.py true results/example
```

> Run script with -h option to get script information

> Produces png of plot at coveragePlot.png


## License
This code is open-source under a BSD license.
