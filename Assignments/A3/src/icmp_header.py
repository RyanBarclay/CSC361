import struct

import a3_functions

from ip_header import IPHeader
from udp_header import UDPHeader

SIZE_OF_ICMP_HEADER = 8


class ICMPHeader:
    type = None
    code = None
    # checksum = None
    add_info_raw = None
    inner_protocols = None

    # fill in inner protocols

    def __init__(self):
        self.type = None
        self.code = None
        # self.checksum = None
        self.add_info_raw = None
        self.inner_protocols = {}

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def get_info(self, binary, endian):
        icmp_header, binary = a3_functions.get_next_bytes(binary, SIZE_OF_ICMP_HEADER)

        # Type
        self.get_type(icmp_header[0:1], endian)

        # Code
        self.get_code(icmp_header[1:2], endian)

        # Check Sum

        # Additional info raw
        self.add_info_raw = icmp_header[4:8]

        if self.type in [11, 3]:
            # ICMP that have IP under add info area
            # IP Header
            ip_head = IPHeader()
            binary = ip_head.get_info(binary, endian)
            self.inner_protocols["IP4"] = ip_head

            if ip_head.protocol == 17:
                # IP type is UDP so let's do that
                udp_head = UDPHeader()
                binary = udp_head.get_info(binary, endian)
                self.inner_protocols["UDP"] = udp_head
        return binary

    def get_type(self, buffer, endian):
        self.type = struct.unpack("!B", buffer)[0]

    def get_code(self, buffer, endian):
        self.code = struct.unpack("!B", buffer)[0]

    # def get_checksum(self, buffer, endian):

    def get_add_info(self, buffer, endian):
        self.add_info = struct.unpack("!I", buffer)[0]
