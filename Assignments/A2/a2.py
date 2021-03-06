#!/usr/bin/python3

# Not allowed to use any big boy libraries

""" Assignment 2

    Requirements:
        Given a TCP Trace file, write a python file for parsing and processing the trace file. Note, we are only allowed specific packages that are
        on the UVic linux servers.
        The program should:
            * process the trace file and compute a summary of the information

        The summary should include for each TCP connection:
            * State of connection
            * Starting time
            * Ending time
            * Duration of each complete connnetion
            * Number of packets sent in each direction, on each complete
              connection
            * Total number of packets
            * Number of bytes sent in each direction, on each complete
              connection
            * Total bytes, excluding TCP and IP protocols

        The summary should include for each cap file:
            * Number of reset TCP connections
            * Number of TCP connections still open when @ end of file
            * Number of complete TCP connections observed in file
                * Time durations
                    * Min
                    * Max
                    * Mean
                * RRT (Round Trip Times) values
                    * Min
                    * Max
                    * Mean
                * Number of packets in both directions sent
                    * Min
                    * Max
                    * Mean
                * Receive window sizes, both sides
                    * Min
                    * Max
                    * Mean

        For more info on the requirements look at the pdf contained in the A2 folder.

    Grading:
        25% - Total Number of connections
        30% - Connections' details
        20% - General Statistics
        20% - Complete TCP connections
        5%  - Readme.txt and coding style
"""


import socket
import struct
import sys
import re
import ssl
import basic_structures
from extra_functions import *

DEFAULT_HTTP_PORT = 80


# Globals
SIZE_OF_GLOBAL_HEADER = 24
SIZE_OF_PACKET_HEADER = 16
SIZE_OF_ETHERNET_HEADER = 14

packets = []
indent = "    "


def main():
    # import cap file
    capFile = importFile()
    global_header_binary, remaining_capFile = getNextBytes(
        capFile, SIZE_OF_GLOBAL_HEADER
    )

    # Get global header info
    global_header_obj = basic_structures.Global_Header()
    global_header_obj.get_global_header_into(global_header_binary)

    # We check the endian of this cap file
    endian = global_header_obj.endian

    # We now iterate through the capFile to section off each packet
    # This will also store each packet in packets[]
    while remaining_capFile:
        remaining_capFile = parsePacket(remaining_capFile, endian)

    # Now we group the packets by unique tuple
    local_packets = packets

    # Parse out the connections
    connections = []
    while local_packets:
        local_packets, connection = parseConnections(local_packets, connections)

    # create list for connection list so we can iterate thought the connections with ease
    connection_obj_list = []

    # print part A
    partA(connections)

    # print and do part B
    print("B) Connections' details:\n")
    for connection in connections:
        connection_obj = basic_structures.Connection_detail()
        connection_obj.get_info(connection)
        connection_obj.print_partb()
        connection_obj_list.append(connection_obj)

    # print and do part C
    reset_TCP_connections = 0
    open_TCP_connections = 0
    complete_connections = []
    print("\nC) General\n")

    for connection_obj in connection_obj_list:
        if connection_obj.complete:
            complete_connections.append(connection_obj)

        if connection_obj.status[2] != 0:
            reset_TCP_connections += 1

        if connection_obj.status[1] == 0:
            open_TCP_connections += 1

    print(
        "Total number of complete TCP connections: {}".format(len(complete_connections))
    )
    print("Number of reset TCP connections: {}".format(reset_TCP_connections))
    print(
        "Number of TCP connections that were still open when the trace capture ended: {}".format(
            open_TCP_connections
        )
    )

    # Part D
    print("\nD) Complete TCP connections:\n")
    partD(complete_connections)


def importFile():
    try:
        with open(sys.argv[1], "rb") as f:
            return f.read()
    except OSError:
        print("An OSError was thrown in importFile")
        sys.exit()
    except Exception:
        print("There was an error in importFile")
        sys.exit()


def parsePacket(binary, endian):
    # Get packet header and store
    packet_header, binary = getNextBytes(binary, SIZE_OF_PACKET_HEADER)

    # init the packet header
    packet_obj = basic_structures.packet()
    size_packet_data = packet_obj.get_info(packet_header, endian)

    # Parse out remainder of packet
    remaining_packet, binary = getNextBytes(binary, size_packet_data)

    # Parse packet data and format
    packet_obj.packet_data(remaining_packet, endian)

    # Add complete packet to list
    # print(packet_obj)
    packets.append(packet_obj)

    return binary


def parseConnections(local_packets, connections):
    # Look at packet at top of local_packets
    top = local_packets[0]
    # print(top)

    # get its unique tuple
    unique_tuple = top.get_unique_tuple()

    # see if that tuple is in connections
    in_connections = False
    # print(connections)
    for index, connection in enumerate(connections):
        unique_tuple_existing = connection[0].get_unique_tuple()
        # print(unique_tuple_existing)
        if unique_tuple[0] in unique_tuple_existing:
            if unique_tuple[1] in unique_tuple_existing:
                # if so add it to the end of that connection
                in_connections = True
                connection.append(top)
                connections[index] = connection
                return local_packets[1:], connections

    if not in_connections:
        # if not in connections add it to the end
        connection = [top]
        connections.append(connection)
        # print("new connection")
        return local_packets[1:], connections


def partA(connections):
    print("A) Total number of TCP connections: {}\n".format(len(connections)))


def partD(complete_connections):

    times = []
    rtts = []
    packets = []
    windows = []

    for connection_obj in complete_connections:
        times.append(connection_obj.duration)
        rtts.append(0)
        packets.append(connection_obj.packets_total)
        for window in connection_obj.window_list:
            windows.append(window)

    min_time_duration = min(times)
    mean_time_duration = round(sum(times) / len(times), 6)
    max_time_duration = max(times)

    min_rtt = min(rtts)
    mean_rtt = round(sum(rtts) / len(rtts), 6)
    max_rtt = max(rtts)

    min_packets = min(packets)
    mean_packets = round(sum(packets) / len(packets), 6)
    max_packets = max(packets)

    min_window = min(windows)
    mean_window = round(sum(windows) / len(windows), 6)
    max_window = max(windows)

    print("Minimum time duration: {} seconds".format(min_time_duration))
    print("Mean time duration: {} seconds".format(mean_time_duration))
    print("mean_time_duration: {} seconds\n".format(max_time_duration))

    print("Minimum RTT value: {} seconds".format(min_rtt))
    print("Mean RTT value: {} seconds".format(mean_rtt))
    print("Maximum RTT value: {} seconds\n".format(max_rtt))

    print(
        "Minimum number of packets including both send/received: {} packets".format(
            min_packets
        )
    )
    print(
        "Mean number of packets including both send/received: {} packets".format(
            mean_packets
        )
    )
    print(
        "Maximum number of packets including both send/received: {} packets\n".format(
            max_packets
        )
    )

    print(
        "Minimum receive window size including both send/received: {} bytes".format(
            min_window
        )
    )  # TODO
    print(
        "Mean receive window size including both send/received: {} bytes".format(
            mean_window
        )
    )  # TODO
    print(
        "Maximum receive window size including both send/received: {} bytes".format(
            max_window
        )
    )  # TODO


if __name__ == "__main__":
    main()
