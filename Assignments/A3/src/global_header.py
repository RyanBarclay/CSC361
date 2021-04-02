import struct

SWAPPED_VALUE = 0xD4C3B2A1
IDENTICAL_VALUE = 0xA1B2C3D4


class GlobalHeader:
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
