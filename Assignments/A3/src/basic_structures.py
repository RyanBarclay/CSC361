import struct

SWAPPED_VALUE = 0xD4C3B2A1
IDENTICAL_VALUE = 0xA1B2C3D4

SIZE_OF_GLOBAL_HEADER = 24
SIZE_OF_PACKET_HEADER = 16
SIZE_OF_ETHERNET_HEADER = 14


def getNextBytes(binary, bytes):
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


class IP_Header:
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
        ip4_header, binary = getNextBytes(binary, self.ip_header_len)

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


class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size = 0
    checksum = 0
    ugp = 0

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size = 0
        self.checksum = 0
        self.ugp = 0

    def src_port_set(self, src):
        self.src_port = src

    def dst_port_set(self, dst):
        self.dst_port = dst

    def seq_num_set(self, seq):
        self.seq_num = seq

    def ack_num_set(self, ack):
        self.ack_num = ack

    def data_offset_set(self, data_offset):
        self.data_offset = data_offset

    def flags_set(self, ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin

    def win_size_set(self, size):
        self.window_size = size

    def get_src_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        port = num1 + num2 + num3 + num4
        self.src_port_set(port)
        # print(self.src_port)
        return None

    def get_dst_port(self, buffer):
        num1 = ((buffer[0] & 240) >> 4) * 16 * 16 * 16
        num2 = (buffer[0] & 15) * 16 * 16
        num3 = ((buffer[1] & 240) >> 4) * 16
        num4 = buffer[1] & 15
        port = num1 + num2 + num3 + num4
        self.dst_port_set(port)
        # print(self.dst_port)
        return None

    def get_seq_num(self, buffer):
        seq = struct.unpack(">I", buffer)[0]
        self.seq_num_set(seq)
        # print(seq)
        return None

    def get_ack_num(self, buffer):
        ack = struct.unpack(">I", buffer)[0]
        self.ack_num_set(ack)
        return None

    def get_flags(self, buffer):
        value = struct.unpack("B", buffer)[0]
        fin = value & 1
        syn = (value & 2) >> 1
        rst = (value & 4) >> 2
        ack = (value & 16) >> 4
        self.flags_set(ack, rst, syn, fin)
        return None

    def get_window_size(self, buffer1, buffer2):
        buffer = buffer2 + buffer1
        size = struct.unpack("H", buffer)[0]
        self.win_size_set(size)
        return None

    def get_data_offset(self, buffer):
        value = struct.unpack("B", buffer)[0]
        length = ((value & 240) >> 4) * 4
        self.data_offset_set(length)
        # print(self.data_offset)
        return None

    def relative_seq_num(self, orig_num):
        if self.seq_num >= orig_num:
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        # print(self.seq_num)

    def relative_ack_num(self, orig_num):
        if self.ack_num >= orig_num:
            relative_ack = self.ack_num - orig_num + 1
            self.ack_num_set(relative_ack)

    def get_info(self, binary):
        # src_port
        self.get_src_port(binary[0:2])

        # dst_port
        self.get_dst_port(binary[2:4])

        # seq_num
        self.get_seq_num(binary[4:8])

        # ack_num
        self.get_ack_num(binary[8:12])

        # data_offset
        self.get_data_offset(binary[12:13])

        # flags
        self.get_flags(binary[13:14])

        # window_size
        self.get_window_size(binary[14:15], binary[15:16])

        # check sum
        # LOL SKIP ME WITH THAT

        # urgent
        # LOL SKIP ME WITH THAT

        # print(self)

        return binary

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)


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
        self.IP_header = IP_Header()
        self.TCP_header = TCP_Header()
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


class Global_Header:
    magic_number = 0  # 4 bytes
    version_major = 0  # 2 bytes
    version_minor = 0  # 2 bytes
    thiszone = 0  # 4 bytes
    sigfigs = 0  # 4 bytes
    snaplen = 0  # 4 bytes
    network = 0  # 4 bytes
    endian = None

    def __init__(self):
        self.magic_number = 0
        self.version_major = 0
        self.version_minor = 0
        self.thiszone = 0
        self.sigfigs = 0
        self.snaplen = 0
        self.network = 0
        self.endian = None

    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    def get_global_header_into(self, binary):

        # Magic number
        self.magic_number = struct.unpack("<I", binary[0:4])[0]

        # Check for swapped or not
        if self.magic_number == SWAPPED_VALUE:
            self.endian = ">"
        elif self.magic_number == IDENTICAL_VALUE:
            self.endian = "<"
        else:
            print("ERROR: magic number is not swapped or identical")

        # Version major
        self.version_major = struct.unpack(self.endian + "H", binary[4:6])[0]

        # Version minor
        self.version_minor = struct.unpack(self.endian + "H", binary[6:8])[0]

        # Thiszone
        self.thiszone = struct.unpack(self.endian + "i", binary[8:12])[0]

        # Sigfigs
        self.sigfigs = struct.unpack(self.endian + "I", binary[12:16])[0]

        # Snaplen
        self.snaplen = struct.unpack(self.endian + "I", binary[16:20])[0]

        # Network
        self.network = struct.unpack(self.endian + "I", binary[20:])[0]


class Connection_detail:

    source_address = None  # str
    destination_address = None  # str
    source_port = 0  # int
    destination_port = 0  # int
    status = []
    # (Only if the connection is complete provide the following information)
    start_time = 0  # int
    end_time = 0  # int
    duration = 0  # int
    packets_src_to_dest = 0  # int
    packets_dest_to_src = 0  # int
    packets_total = 0  # int
    bytes_src_to_dest = 0  # int
    bytes_dest_to_src = 0  # int
    bytes_total = 0  # int

    complete = None  # bool
    received = None  # list
    sent = None  # list
    window_list = None  # list

    connection_num = 0  # int

    def __init__(self):
        self.source_address = None  # done
        self.destination_address = None  # done
        self.source_port = 0  # done
        self.destination_port = 0  # int  # done
        self.status = [0, 0, 0]  # Sx, Fx, Rx
        # Only if the connection is complete provide the following information
        self.start_time = 0  # int  # done
        self.end_time = 0  # int
        self.duration = 0  # int
        self.packets_src_to_dest = 0  # int
        self.packets_dest_to_src = 0  # int
        self.packets_total = 0  # int
        self.bytes_src_to_dest = 0  # int
        self.bytes_dest_to_src = 0  # int
        self.bytes_total = 0  # int

        self.complete = False
        self.received = []
        self.sent = []
        self.window_list = []

        Connection_detail.connection_num += 1
        self.connection_num = Connection_detail.connection_num

    def get_info(self, connection_list):
        # given a list of packets in a connection get all the data needed

        # Get connection data that is dependant on the first packet

        # Get first packet
        first_packet = connection_list[0]
        # print(len(connection_list))
        # Get sub objects
        first_packet_ip4 = first_packet.IP_header
        first_packet_tcp = first_packet.TCP_header

        # source_address
        self.source_address = first_packet_ip4.src_ip

        # destination_port
        self.destination_address = first_packet_ip4.dst_ip

        # ports
        self.source_port = first_packet_tcp.src_port
        self.destination_port = first_packet_tcp.dst_port

        # Init variabes for looping in connections
        final_packet = None

        # iterate through packets in the connection
        for packet in connection_list:

            tcp_header = packet.TCP_header

            # STATUS STUFF
            flags = tcp_header.flags

            # check for status
            if flags["SYN"] == 1:
                if self.status[0] == 0:
                    # find first s1f0 flag set for time
                    # start time
                    self.start_time = round(packet.timestamp, 6)
                self.status[0] += 1

                # count s if flag set

            if flags["RST"] == 1:
                # set r to true if reset is come across
                self.status[2] = 1

            if flags["FIN"] == 1:
                # count f and store last f packet
                final_packet = packet
                self.status[1] += 1
                # set complete or not depending on f flag
                self.complete = True

            # PACKET STUFF

            # find src and dst of the packet
            src = packet.IP_header.src_ip
            dst = packet.IP_header.dst_ip
            # check to see packet going src to dest or vice versa
            if (self.source_address == src) and (self.destination_address == dst):
                # sent packet
                # get bytes for packet and add to correct list
                self.bytes_src_to_dest += packet.get_bytes()
                # append packet to coresponding list
                self.sent.append(packet)
            elif (self.source_address == dst) and (self.destination_address == src):
                # received packet
                # get bytes for packet and add to correct list
                self.bytes_dest_to_src += packet.get_bytes()
                # append packet to coresponding list
                self.received.append(packet)

            # Now we add packet window to list for window sizes
            self.window_list.append(packet.TCP_header.window_size)

        # count src / dst packet count accordingly
        self.packets_dest_to_src = len(self.received)
        self.packets_src_to_dest = len(self.sent)

        # if complete
        if self.complete:

            # Get end time from last packet with f
            self.end_time = final_packet.timestamp
            # set duration
            self.duration = round(self.end_time - self.start_time, 6)

            # count packet total
            self.packets_total = len(connection_list)
            # add bytes total
            self.bytes_total = self.bytes_dest_to_src + self.bytes_src_to_dest
