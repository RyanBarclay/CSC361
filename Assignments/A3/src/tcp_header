import struct

# from basic_structures import get_next_bytes


class TCPHeader:
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
