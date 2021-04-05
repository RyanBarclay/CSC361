#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = "Ryan Barclay"
__version__ = "0.0.1"


import sys

import a3_functions

from packet import Packet


def main():

    # Check what we cap files we are looking at
    cap_files = a3_functions.get_cap_files(sys.argv)
    # print(cap_files)

    # For every file we want to do the requirements for the a3 assignment
    for file in cap_files:
        print("File Name: " + file)

        # open cap file
        binary = a3_functions.import_file(file)

        packet_split = a3_functions.list_packets(binary)

        if len(packet_split[0]) == 0:
            # No UDP Packets
            # Windows Trace route
            print("Windows")
            a3_functions.handle_windows_case(packet_split)
        else:
            # Linux Trace route
            print("Linux")
            a3_functions.handle_linux_case(packet_split)
            # pass
        # Check if user wants to open another file
        if file is not cap_files[-1]:
            if not a3_functions.keep_going():
                break
            else:
                # reset packets
                Packet.IP_header = None
                Packet.inner_protocol = None
                Packet.inner_protocol_type = None
                Packet.timestamp = 0
                Packet.packet_No = 0
                Packet.RTT_value = 0
                Packet.RTT_flag = False
                Packet.buffer = None
                Packet.orig_time = 0
                Packet.incl_len = 0
                Packet.orig_len = 0
                Packet.fragmented = None
                Packet.last_frag_offset = None


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()
