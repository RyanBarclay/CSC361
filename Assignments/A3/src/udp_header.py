import struct

import a3_functions

SIZE_OF_UDP_HEADER = 8


class UDPHeader:
    src_port = None
    dst_port = None
    length = None

    def __init__(self):
        self.src_port = None
        self.dst_port = None
        self.length = None

    def get_info(self, binary, endian):
        udp_header, binary = a3_functions.get_next_bytes(binary, SIZE_OF_UDP_HEADER)

        # Source port
        self.get_src_port(udp_header[0:2], endian)

        # Destination port
        self.get_dst_port(udp_header[2:4], endian)

        # Length
        self.get_length(udp_header[4:6], endian)

        return binary

    def get_src_port(self, buffer, endian):
        self.src_port = struct.unpack("!H", buffer)[0]

    def get_dst_port(self, buffer, endian):
        self.dst_port = struct.unpack("!H", buffer)[0]

    def get_length(self, buffer, endian):
        self.length = struct.unpack("!H", buffer)[0]

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)
