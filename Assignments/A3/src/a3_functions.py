import sys
import os
import math

from global_header import GlobalHeader
from packet import Packet

# Globals
SIZE_OF_GLOBAL_HEADER = 24
SIZE_OF_PACKET_HEADER = 16
SIZE_OF_ETHERNET_HEADER = 14
PATH_OF_PCAP_FILES = "../PcapFiles"


def get_next_bytes(binary, bytes):
    """
    This Function gets the next n bytes of data from a raw binary file and
    returns both the n bytes and the original binary minus the n bytes

    Args:
        binary (List): List of bytes
        bytes (int): n bytes to cut

    Returns:
        output (List):  List of bytes from start of binary to n bytes
        binary (List):  Remaining elements in original binary list
    """
    output = binary[0:bytes]
    binary = binary[bytes:]
    return output, binary


def import_file(file):
    try:
        with open(file, "rb") as f:
            output = f.read()
            f.close()
            return output
    except OSError:
        print("An OSError was thrown in importFile")
        sys.exit()
    except Exception:
        print("There was an error in importFile")
        sys.exit()


def get_cap_files(args):
    PATH_OF_PCAP_FILES = "../PcapFiles"
    cap_files = []
    if len(args) == 1:
        # only main.py in argument
        for root, dirs, files in os.walk(PATH_OF_PCAP_FILES):
            for filename in files:
                cap_files.append(PATH_OF_PCAP_FILES + "/" + filename)
        cap_files.sort()
    else:
        # get list of arguments after file
        for file in args[1:]:
            cap_files.append(file)
    return cap_files


def keep_going():
    separator = "-------------------------------------------------\n"
    while True:
        usr_input = input(
            "\n" + separator + "Do you want to process the next cap file [Y/N]: "
        )
        print(separator)
        if usr_input in ["Y", "y", "N", "n"]:
            if usr_input in ["N", "n"]:
                return False
            else:
                return True


def list_packets(binary):
    """This will return a list of packet object that are what we care about

    Args:
        binary (binary): This is the binary of a cap file
    """
    packets = []
    udp_list = []
    icmp_list = []

    # get and process header for cap file. Will progress binary past the data needed
    global_header_binary, binary = get_next_bytes(binary, SIZE_OF_GLOBAL_HEADER)
    global_header_obj = GlobalHeader()
    global_header_obj.get_global_header_into(global_header_binary)
    # print(global_header_obj.endian)

    # we are going to go through the doc in in the format of [packet]
    while binary:
        # set up packet header, will also get the size of packet
        packet_header, binary = get_next_bytes(binary, SIZE_OF_PACKET_HEADER)
        packet_obj = Packet()

        # Parse out remainder of packet
        remaining_packet, binary = get_next_bytes(
            binary,
            packet_obj.get_info(
                packet_header, global_header_obj.endian, global_header_obj.micro_sec
            ),
        )

        # Parse packet data and format.
        # Will only store UDP packets we care about and ICMP packets.
        # All fragment packets will be set with a fragmented flag in the packet but
        # will store the type.
        packet_obj.packet_data(remaining_packet, global_header_obj.endian)

        # Add complete packet to list
        if packet_obj.inner_protocol_type == "ICMP":
            icmp_list.append(packet_obj)
        elif packet_obj.inner_protocol_type == "UDP":
            udp_list.append(packet_obj)

    for packet in udp_list:
        # lets match the flagged packet
        if packet.fragmented:
            # We have found a flagged packet now lets match it with the end of fragment
            for other_packet in udp_list:
                if (
                    packet.IP_header.identification
                    == other_packet.IP_header.identification
                ):
                    # print(other_packet)
                    # print(other_packet.IP_header)
                    if other_packet.fragmented is False:
                        # this is the "Root" of this fragmentation
                        # time to grab the important stuff
                        packet.inner_protocol.src_port = (
                            other_packet.inner_protocol.src_port
                        )
                        packet.inner_protocol.dst_port = (
                            other_packet.inner_protocol.dst_port
                        )
    # TODO? make one for fragments for icmp
    packets.append(udp_list)
    packets.append(icmp_list)
    return packets


def handle_windows_case(packet_split):
    pass
    # Deal with first packet
    first_packet = packet_split[1][0]

    # Find src_ip
    src_node_ip = first_packet.IP_header.src_ip

    # Find ult_dest_ip
    ult_dest_node_ip = first_packet.IP_header.dst_ip

    # match senders with reicevers
    pairs = []
    for icmp_packet in packet_split[1]:
        pass


def handle_linux_case(packet_split):

    # Deal with first packet
    first_packet = packet_split[0][0]

    # Find src_ip
    src_node_ip = first_packet.IP_header.src_ip

    # Find ult_dest_ip
    ult_dest_node_ip = first_packet.IP_header.dst_ip

    # Find number of fragments of first packet
    # TODO

    # Split into pairs
    pairs = []
    for udp_packet in packet_split[0]:
        # for each udp packet we want to match it with a icmp packet
        udp_src_port = udp_packet.inner_protocol.src_port

        payload = []
        for icmp_packet in packet_split[1]:
            # find matching icmp packet
            icmp_container = icmp_packet.inner_protocol

            if "UDP" in icmp_container.inner_protocols:
                icmp_err_src_port = icmp_container.inner_protocols["UDP"].src_port

                if icmp_err_src_port == udp_src_port:
                    # Match
                    payload = [udp_packet, icmp_packet]
                    break
            else:
                print("This ICMP does not have a UDP packet inside")
                print(icmp_packet)
                print("ICMP")
                print(icmp_container)

        if payload == []:
            # print("UDP packet could not find matching UDP")
            # print(udp_packet)
            # print(udp_packet.inner_protocol)
            # print(udp_packet.IP_header)
            pass
        else:
            pairs.append(payload)

    # Order by TTL
    index_pairs = []
    for pair in pairs:
        ttl = ttl_in_pair_linux(pair)
        index_pairs.append([ttl, pair])

    sorted_index_pairs = sort_list(index_pairs)

    # Find all int_dest_ip
    int_dest_ip = []  # element = [ttl, ip, [ [udp,icmp],[udp,icmp],[udp,icmp]... ] ]
    ult_dest_ip = []
    for element in sorted_index_pairs:
        ttl = element[0]
        icmp_packet = element[1][1]
        router_ip = icmp_packet.IP_header.src_ip
        if router_ip != ult_dest_node_ip:
            # we have hit a router and want to store
            payload = [ttl, router_ip, [element[1]]]
            in_list = False
            for i, existing_payload in enumerate(int_dest_ip):

                if (
                    payload[0] == existing_payload[0]
                    and payload[1] == existing_payload[1]
                ):
                    # have same ttl and router ip

                    # Add packet pair to pairs in list
                    existing_pairs = existing_payload[2]
                    existing_pairs.append(payload[2][0])

                    # set up the new payload to be stored
                    new_payload = [
                        existing_payload[0],
                        existing_payload[1],
                        existing_pairs,
                    ]

                    # now override with the new payload
                    int_dest_ip[i] = new_payload
                    in_list = True
                    break

            if not in_list:
                int_dest_ip.append(payload)
        else:
            # this pair is the between src and dest
            payload = [ttl, router_ip, [element[1]]]
            in_list = False
            for i, existing_payload in enumerate(ult_dest_ip):

                if payload[1] == existing_payload[1]:
                    # have same ttl and router ip

                    # Add packet pair to pairs in list
                    existing_pairs = existing_payload[2]
                    existing_pairs.append(payload[2][0])

                    # set up the new payload to be stored
                    new_payload = [
                        existing_payload[0],
                        existing_payload[1],
                        existing_pairs,
                    ]

                    # now override with the new payload
                    ult_dest_ip[i] = new_payload
                    in_list = True
                    break

            if not in_list:
                ult_dest_ip.append(payload)

    # Values in protocol fields
    # protocols = {"UDP": True, "ICMP": True}

    # Print out the stuff
    print("The IP address of the source node: {}".format(src_node_ip))
    print("The IP address of ultimate destination node: {}".format(ult_dest_node_ip))
    print("The IP addresses of the intermediate destination nodes:")
    for router_num, unique_pair in enumerate(int_dest_ip):
        print(
            "    router {}: {}, distance to source: {}".format(
                router_num + 1, unique_pair[1], unique_pair[0]
            )
        )
    print("\nThe values in the protocol field of IP headers:")
    print("    1: ICMP")
    print("    17: UDP")
    print(
        "\nThe number of fragments created from the original datagram is: {}".format(0)
    )
    print("The offset of the last fragment is: {}".format(0))
    print("")
    for unique_pair in int_dest_ip:
        # list of pairs per unique ttl and ip
        rtt_list = []
        for pair in unique_pair[2]:
            # calc rtt stuff in here
            rtt = (pair[1].timestamp - pair[0].timestamp) * 1000
            rtt_list.append(rtt)

        mean = get_mean(rtt_list)
        std = get_std(rtt_list)

        print(
            "The avg RTT between {} and {} is: {} ms, the s.d. is: {} ms ".format(
                src_node_ip, unique_pair[1], mean, std
            )
        )
    for unique_pair in ult_dest_ip:
        # list of pairs per unique ttl and ip
        rtt_list = []
        for pair in unique_pair[2]:
            # calc rtt stuff in here
            rtt = pair[1].timestamp - pair[0].timestamp
            rtt_list.append(rtt)

        mean = get_mean(rtt_list)
        std = get_std(rtt_list)

        print(
            "The avg RTT between {} and {} is: {} ms, the s.d. is: {} ms ".format(
                src_node_ip, unique_pair[1], mean, std
            )
        )

    return


def ttl_in_pair_linux(pair):
    return pair[0].IP_header.ttl


def sort_list(pairs_with_ttl):
    n = len(pairs_with_ttl)

    # sorting algorithm from https://www.geeksforgeeks.org/bubble-sort/
    # TODO: Optimize

    # Traverse through all array elements
    for i in range(n):
        # Last i elements are already in place
        for j in range(0, n - i - 1):

            # traverse the array from 0 to n-i-1
            # Swap the pair if the ttl of pair found is greater
            # than the next pairs ttl
            if pairs_with_ttl[j][0] > pairs_with_ttl[j + 1][0]:

                pairs_with_ttl[j], pairs_with_ttl[j + 1] = (
                    pairs_with_ttl[j + 1],
                    pairs_with_ttl[j],
                )
    return pairs_with_ttl


def get_std(list_of_values):
    # work out mean
    mean = get_mean(list_of_values)

    squared_list = []
    # for each number subtract mean and square the value
    for number in list_of_values:
        squared_list.append(math.pow(number - mean, 2))

    # find mean on those diffs
    mean = get_mean(squared_list)

    # do square rt on that
    return math.sqrt(mean)


def get_mean(list_of_values):
    sum = 0
    for value in list_of_values:
        sum += value
    return sum / len(list_of_values)
