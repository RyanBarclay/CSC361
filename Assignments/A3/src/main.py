#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = "Ryan Barclay"
__version__ = "0.0.1"


import sys
import os

import a3_functions
from global_header import GlobalHeader
from packet import Packet
from ip_header import IPHeader
from tcp_header import TCPHeader


# Globals
SIZE_OF_GLOBAL_HEADER = 24
SIZE_OF_PACKET_HEADER = 16
SIZE_OF_ETHERNET_HEADER = 14
PATH_OF_PCAP_FILES = "../PcapFiles"


def main():

    # Check what we cap files we are looking at
    cap_files = []
    if len(sys.argv) == 1:
        # only main.py in argument
        for root, dirs, files in os.walk(PATH_OF_PCAP_FILES):
            for filename in files:
                cap_files.append(PATH_OF_PCAP_FILES + "/" + filename)
    else:
        # get list of argumets after file
        for file in sys.argv[1:]:
            cap_files.append(file)
    # print(cap_files)

    loop = True

    for file in cap_files:
        binary = a3_functions.importFile(file)
        # Open up cap file
        global_header_binary, binary = a3_functions.get_next_bytes(
            binary, SIZE_OF_GLOBAL_HEADER
        )
        global_header_obj = GlobalHeader()
        global_header_obj.get_global_header_into(global_header_binary)

        # Check if user wants to open another file
        if file is not cap_files[-1]:
            separator = "-------------------------------------------------\n"
            while True:
                usr_input = input(
                    separator + "Do you want to process the next cap file [Y/N]: "
                )
                print(separator)
                if usr_input in ["Y", "y", "N", "n"]:
                    if usr_input in ["N", "n"]:
                        loop = False
                    break

            if not loop:
                break


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()
