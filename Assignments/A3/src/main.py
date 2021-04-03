#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = "Ryan Barclay"
__version__ = "0.0.1"


import sys

import a3_functions


def main():

    # Check what we cap files we are looking at
    cap_files = a3_functions.get_cap_files(sys.argv)
    # print(cap_files)

    # For every file we want to do the requirements for the a3 assignment
    for file in cap_files:
        print("File Name: " + file)

        # open cap file
        binary = a3_functions.import_file(file)

        relevant_packets = a3_functions.list_packets(binary)
        print(len(relevant_packets))
        # Check if user wants to open another file
        if file is not cap_files[-1]:
            if not a3_functions.keep_going():
                break


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()
