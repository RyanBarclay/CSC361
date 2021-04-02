import struct

from a3_functions import get_next_bytes


class IPHeader:
    src_ip = None  # <type 'str'>
    dst_ip = None  # <type 'str'>
    ip_header_len = None  # <type 'int'>
    total_len = None  # <type 'int'>

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0

    def get_info(self, binary, endian):
        # determine length of IPV4 header
        self.get_header_len(binary[0:1])

        # We could get IP V# here, but we are gonna skip it
        # Get relevant data listed in tut4.pdf

        # Parse out ip4 header
        ip4_header, binary = get_next_bytes(binary, self.ip_header_len)

        # Total Length
        self.get_total_len(ip4_header[2:4])

        # src and dst ip
        self.get_IP(ip4_header[12:16], ip4_header[16:])
        # print(self)

        return binary

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
