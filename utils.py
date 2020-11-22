import string
import binascii

def formattedArray(array: [bytes]):
    return b''.join([prependedLen(x, 2) for x in array])

def prependedLen(data: bytes, numBytes=2):
    # Get the length of the data represented in the desired number of bytes
    lengthBytes = bytes([len(data)]).rjust(numBytes, b'\0')
    if len(lengthBytes) > numBytes:
        raise Exception(f"Data length does not fit in {numBytes} bytes")
    return lengthBytes + data

def hexdump(data: bytes) -> str:
    groups = [data[i:i+16] for i in range(0,len(data), 16)]
    lines = []
    for group in groups:
        line = binascii.hexlify(group, ' ').decode('ascii').ljust(51, ' ')
        # Also print the ascii representation
        line += ''.join([chr(b) if chr(b) in string.digits+string.ascii_letters+' ' else '.' for b in group])
        lines += [line]
    return '\n'.join(lines)
