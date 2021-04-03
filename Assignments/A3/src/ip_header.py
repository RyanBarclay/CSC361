import struct

import a3_functions


class IPHeader:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>
    identification = None
    flags = {}
    fragment_offset = None
    ttl = None
    protocol = None

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
        self.identification = None
        self.flags = {}
        self.fragment_offset = None
        self.ttl = None
        self.protocol = None

    def get_info(self, binary, endian):
        # determine length of IPV4 header
        self.get_header_len(binary[0:1])

        # We could get IP V# here, but we are gonna skip it
        # Get relevant data listed in tut4.pdf

        # Not a ip4 header
        if self.ip_header_len < 20 or self.ip_header_len > 60:
            return binary

        # Parse out ip4 header
        ip4_header, binary = a3_functions.get_next_bytes(binary, self.ip_header_len)

        # Total Length
        self.get_total_len(ip4_header[2:4])

        # Identification
        self.get_identification(ip4_header[4:6], endian)

        # Flags
        self.get_flags(ip4_header[6:7])

        # Fragment Offset
        self.get_fragment_offset(ip4_header[6:8])

        # Time To Live
        self.get_ttl(ip4_header[8:9])

        # Protocol
        self.get_protocol(ip4_header[9:10])

        # src and dst ip
        self.get_IP(ip4_header[12:16], ip4_header[16:20])
        # print(self)

        return binary

    def get_identification(self, buffer, endian):
        # print(buffer)
        self.identification = struct.unpack(">H", buffer)[0]

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        reserved = value & 0b10000000 >> 7
        df = (value & 0b01000000) >> 6
        mf = (value & 0b0100000) >> 5
        self.flags["reserved"] = reserved
        self.flags["df"] = df
        self.flags["mf"] = mf

    def get_fragment_offset(self, buffer):
        value = struct.unpack("BB", buffer)[0]
        self.fragment_offset = value & 0b0001111111111111

    def get_ttl(self, buffer):
        self.ttl = struct.unpack("B", buffer)[0]

    def get_protocol(self, buffer):
        self.protocol = struct.unpack("B", buffer)[0]

    def ip_set(self, src_ip, dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self, length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def get_IP(self, buffer1, buffer2):
        src_addr = struct.unpack("BBBB", buffer1)
        dst_addr = struct.unpack("BBBB", buffer2)
        s_ip = (
            str(src_addr[0])
            + "."
            + str(src_addr[1])
            + "."
            + str(src_addr[2])
            + "."
            + str(src_addr[3])
        )
        d_ip = (
            str(dst_addr[0])
            + "."
            + str(dst_addr[1])
            + "."
            + str(dst_addr[2])
            + "."
            + str(dst_addr[3])
        )
        self.ip_set(s_ip, d_ip)

    def get_header_len(self, value):
        result = struct.unpack("B", value)[0]
        length = (result & 15) * 4
        self.header_len_set(length)

    def get_total_len(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        length = num1 + num2 + num3 + num4
        self.total_len_set(length)

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)
