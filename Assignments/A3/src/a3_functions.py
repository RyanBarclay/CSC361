import sys
import os

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

    while binary:
        # set up packet header, will also get the size of packet
        packet_header, binary = get_next_bytes(binary, SIZE_OF_PACKET_HEADER)
        packet_obj = Packet()

        # Parse out remainder of packet
        remaining_packet, binary = get_next_bytes(
            binary, packet_obj.get_info(packet_header, global_header_obj.endian)
        )

        # Parse packet data and format
        # Will only store UDP packets we care about and ICMP packets
        packet_obj.packet_data(remaining_packet, global_header_obj.endian)

        # Add complete packet to list
        if packet_obj.inner_protocol_type == "ICMP":
            icmp_list.append(packet_obj)
        elif packet_obj.inner_protocol_type == "UDP":
            udp_list.append(packet_obj)
    packets.append(udp_list)
    packets.append(icmp_list)
    return packets


def handle_linux_case(packet_split):

    # Deal with first packet
    first_packet = packet_split[0][0]
    src_node_ip = first_packet.IP_header.src_ip
    ult_dest_node_ip = first_packet.IP_header.dst_ip

    # Split into pairs

    # Order by TTL

    # group by TTL?

    # Find src_ip

    # Find ult_dest_ip

    # Find all int_dest_ip

    # Values in protocol fields
    protocols = {"UDP": True, "ICMP": True}

    return
