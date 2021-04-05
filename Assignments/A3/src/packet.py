import struct

from ip_header import IPHeader
from tcp_header import TCPHeader
from udp_header import UDPHeader
from icmp_header import ICMPHeader


SIZE_OF_ETHERNET_HEADER = 14


class Packet:

    # pcap_hd_info = None
    IP_header = None
    inner_protocol = None
    inner_protocol_type = None
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
        self.inner_protocol = None
        # self.pcap_hd_info = pcap_ph_info()
        self.inner_protocol_type = None
        self.timestamp = 0
        self.packet_No = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        self.orig_time = Packet.orig_time
        self.incl_len = 0
        # self.orig_len = 0

    # def get_bytes(self):
    #     header_size = self.IP_header.ip_header_len + self.TCP_header.data_offset
    #     len_with_no_buffer = self.IP_header.total_len
    #     return len_with_no_buffer - header_size

    def get_info(self, header_binary, endian, micro_sec):
        ts_sec = header_binary[0:4]
        ts_usec = header_binary[4:8]
        incl_len = struct.unpack(endian + "I", header_binary[8:12])[0]
        # orig_len = struct.unpack(endian + "I", header_binary[12:])[0]
        self.timestamp_set(ts_sec, ts_usec, self.orig_time, micro_sec)
        self.packet_No_set()
        self.incl_len = incl_len
        return incl_len

    def packet_data(self, binary, endian):
        # ethernet header
        binary_after_e = binary[SIZE_OF_ETHERNET_HEADER:]

        # check to make sure we are using ip4 in the next part

        binary = self.IP_header.get_info(binary_after_e, endian)
        if binary != binary_after_e:
            # binary is remaining packet data minus the
            # print(self.IP_header)
            if self.IP_header.protocol == 1:
                # ICMP
                self.inner_protocol = ICMPHeader()
                binary = self.inner_protocol.get_info(binary, endian)
                self.inner_protocol_type = "ICMP"
                # TODO: any logic that gets rid of redundant ICMP packets
                # print("This is a ICMP")
                # print(self.inner_protocol)
                # print(self.inner_protocol.IP_header)
                # print(self.inner_protocol.UDP_header)
            elif self.IP_header.protocol == 17:
                # UDP
                self.inner_protocol = UDPHeader()
                binary = self.inner_protocol.get_info(binary, endian)
                # Now check to see if port is in range
                if (self.inner_protocol.dst_port >= 33434) and (
                    self.inner_protocol.dst_port <= 33625
                ):
                    self.inner_protocol_type = "UDP"
                    # print("This is a valid UDP")
                    # print("IP PROTOCOL:")
                    # print(self.IP_header.protocol)

                else:
                    self.inner_protocol_type = None
                # print(self.inner_protocol)
            elif self.IP_header.protocol == 6:
                # Ip4
                self.inner_protocol = TCPHeader()
                binary = self.inner_protocol.get_info(binary)
                self.inner_protocol_type = "IP"

        else:
            # not a ip4 header so we will set up header and tcp header to None
            self.IP_header = None
            # self.TCP_header = None

        # ip_4 header

    def timestamp_set(self, buffer1, buffer2, orig_time, micro):
        seconds = struct.unpack("I", buffer1)[0]
        if micro:
            microseconds = struct.unpack("<I", buffer2)[0]
            nanoseconds = 0
        else:
            microseconds = 0
            nanoseconds = struct.unpack("<I", buffer2)[0]
        self.timestamp = round(
            (seconds + (microseconds * 0.000001) + (nanoseconds * 0.000000001))
            - orig_time,
            6,
        )
        # print(self.timestamp,self.packet_No)

    def packet_No_set(self):
        Packet.packet_No += 1
        self.packet_No = Packet.packet_No
        if self.packet_No == 1:
            Packet.orig_time = self.timestamp
            self.orig_time = self.timestamp
            self.timestamp = 0

        # print(self.packet_No)

    def get_RTT_value(self, p):
        rtt = p.timestamp - self.timestamp
        self.RTT_value = round(rtt, 8)

    # def get_unique_tuple(self):
    #     return (
    #         [self.IP_header.src_ip, self.TCP_header.src_port],
    #         [self.IP_header.dst_ip, self.TCP_header.dst_port],
    #     )

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)
