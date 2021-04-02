import struct

from ip_header import IPHeader
from tcp_header import TCPHeader

SIZE_OF_ETHERNET_HEADER = 14


class packet:

    # pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    orig_time = 0
    incl_len = 0
    orig_len = 0

    def __init__(self):
        self.IP_header = IPHeader()
        self.TCP_header = TCPHeader()
        # self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.orig_time = packet.orig_time
        self.incl_len = 0
        # self.orig_len = 0

    def get_bytes(self):
        header_size = self.IP_header.ip_header_len + self.TCP_header.data_offset
        len_with_no_buffer = self.IP_header.total_len
        return len_with_no_buffer - header_size

    def get_info(self, header_binary, endian):
        ts_sec = header_binary[0:4]
        ts_usec = header_binary[4:8]
        incl_len = struct.unpack(endian + "I", header_binary[8:12])[0]
        # orig_len = struct.unpack(endian + "I", header_binary[12:])[0]
        self.timestamp_set(ts_sec, ts_usec, self.orig_time)
        self.packet_No_set()
        self.incl_len = incl_len
        return incl_len

    def packet_data(self, binary, endian):
        # ethernet header
        binary = binary[SIZE_OF_ETHERNET_HEADER:]

        binary = self.IP_header.get_info(binary, endian)
        # binary is remaining packet data minus the

        binary = self.TCP_header.get_info(binary)

        # ip_4 header

    def timestamp_set(self, buffer1, buffer2, orig_time):
        seconds = struct.unpack("I", buffer1)[0]
        microseconds = struct.unpack("<I", buffer2)[0]
        self.timestamp = round(seconds + microseconds * 0.000001 - orig_time, 6)
        # print(self.timestamp,self.packet_No)

    def packet_No_set(self):
        packet.packet_No += 1
        self.packet_No = packet.packet_No
        if self.packet_No == 1:
            packet.orig_time = self.timestamp
            self.orig_time = self.timestamp
            self.timestamp = 0

        # print(self.packet_No)

    def get_RTT_value(self, p):
        rtt = p.timestamp - self.timestamp
        self.RTT_value = round(rtt, 8)

    def get_unique_tuple(self):
        return (
            [self.IP_header.src_ip, self.TCP_header.src_port],
            [self.IP_header.dst_ip, self.TCP_header.dst_port],
        )

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)
