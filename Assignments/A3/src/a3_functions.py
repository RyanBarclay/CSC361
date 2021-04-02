import sys


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


def importFile(file):
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
