import argparse
import json
import matplotlib.pyplot as plt
import numpy as np
import os
from scipy.interpolate import interp1d
from matplotlib.lines import Line2D

# Code for manually adding labels modeled from following:
# https://stackoverflow.com/questions/39500265/manually-add-legend-items-python-matplotlib

"""Plot data found at each path in JSON_PATHS"""
def plot_json(do_average, json_paths):
    data_per_path = load_json(json_paths)
    for i, (data, json_files) in enumerate(data_per_path):
        plot_lines(do_average, data, json_files, json_paths[i])

    # Configure and show plot
    plt.title("Coverage Over Time")
    plt.ylabel("Cumulative coverage %")
    plt.yticks([x for x in range(0, 110, 10)])
    plt.xlabel("Seconds")
    plt.xlim([-10, 1200])

    colors = ['darkorange', 'royalblue', 'green']
    lines = [Line2D([0], [0], color=c, linewidth=2, linestyle='-') for c in colors]
    labels = ['Zeros Seed', 'Relevant Seed', 'Zeros Seed -- Only Valid']
    manual_legend = False
    if manual_legend:
        plt.legend(lines, labels)
    else:
        plt.legend()

    plt.savefig("coveragePlot.png")
    plt.show()


"""Gets plotting data from JSON files found recursively at each path in JSON_PATHS.
   Return: List of tuples (INPUT_DATA, JSON_FILENAMES) for each path"""
def load_json(json_paths):
    json_files_per_path = [recursive_locate_json([json_path]) for json_path in json_paths]

    for i, names in enumerate(json_files_per_path):
        assert names, "Path contains no JSON files: {}".format(json_paths[i])

    data_per_path = []
    for json_files in json_files_per_path:
        files = [open(file, 'r') for file in json_files]
        data = [json.load(file) for file in files]
        [file.close() for file in files]
        data_per_path.append((data, json_files))
    return data_per_path


"""Locates all paths to JSON files. Searches recursively within folders.
   Input (JSON_PATHS): List of files and folders that contain JSON files. 
   Return: List of all JSON files at JSON_PATHS."""
def recursive_locate_json(json_paths):
    json_files = []

    for path in json_paths:
        if os.path.isfile(path) and path.split(".")[-1].lower() == "json":
            json_files.append(path)
        elif os.path.isdir(path):
            subpaths = [os.path.join(path, subpath) for subpath in os.listdir(path)]
            json_files.extend(recursive_locate_json(subpaths))

    return json_files


"""Converts inputted JSON data to plots"""
def plot_lines(do_average, json_data, json_files, json_path):
    plotting_data = [extract_plotting_data(input) for input in json_data]

    # Plot data (Averaging code modeled from RFUZZ analysis.py script: https://github.com/ekiwi/rfuzz)
    if do_average:
        # Collects all times seen across passed in JSON files
        all_times = []
        [all_times.extend(creation_times) for (creation_times, _) in plotting_data]
        all_times = sorted(set(all_times))

        all_coverage = np.zeros((len(plotting_data), len(all_times)))
        for i, (creation_times, cumulative_coverage) in enumerate(plotting_data):
            # Returns function which interpolates y-value(s) when passed x-value(s). Obeys step function, using previous value when interpolating.
            interp_function = interp1d(creation_times, cumulative_coverage, kind='previous', bounds_error=False, assume_sorted=True)
            # Interpolates coverage value for each time in all_times. Saved to all_coverage matrix
            all_coverage[i] = interp_function(all_times)
        means = np.mean(all_coverage, axis=0)
        plt.step(all_times, means, where='post', label="Averaged: " + json_path)

    else:
        for i in range(len(plotting_data)):
            (creation_time, cumulative_coverage) = plotting_data[i]
            plt.step(creation_time, cumulative_coverage, where='post', label=json_files[i])


"""Extract plotting data from a single JSON file's data"""
def extract_plotting_data(input_data):
    creation_times = []
    cumulative_coverage = []
    for input in input_data['coverage_data']:
        creation_times.append((input['creation_time']))
        cumulative_coverage.append(input["cumulative_coverage"] * 100)

    # Extract end time from JSON file and add it to plotting data
    creation_times.append(input_data['end_time'])
    cumulative_coverage.append(cumulative_coverage[-1])

    assert len(creation_times) == len(cumulative_coverage), "NUMBER OF TIMES SHOULD EQUAL NUMBER OF COVERAGE READINGS"

    return (creation_times, cumulative_coverage)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script to plot fuzzing results', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('do_average', help='Average plotting data per path')
    parser.add_argument('json_paths', metavar='PATH', nargs='+', help='Path to recursively search for JSON files to plot\nAdd multiple paths to plot against each other')
    args = parser.parse_args()

    lower_do_average = args.do_average.lower()
    if lower_do_average == "true":
        do_average = True
    elif lower_do_average == "false":
        do_average = False
    else:
        raise argparse.ArgumentTypeError("DO_AVERAGE ARGUMENT MUST BE TRUE/FALSE, NOT: {}".format(args.do_average))

    for path in args.json_paths:
        if not (os.path.isfile(path) or os.path.isdir(path)):
            raise argparse.ArgumentTypeError("PATH DOES NOT EXIST: {}".format(path))

    plot_json(do_average, args.json_paths)
