import string
import binascii

def formattedArray(array: [bytes]):
    return b''.join([prependedLen(x, 2) for x in array])

def bytexor(a:bytes, b:bytes):
    return bytes([i ^ j for i, j in zip(a,b)]) 

def binaryToBytes(s: str):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

# reverses each byte in a string of 16 bytes. Used to convert between GCM field representations
def byteReverse(x: int) -> int:
    bytez = x.to_bytes(16, 'big')
    out = []
    for b in bytez:
        out += [int(''.join(reversed(bin(b)[2:].zfill(8))), 2).to_bytes(1, 'big')]
    return int.from_bytes(b''.join(out), 'big')

def prependedLen(data: bytes, numBytes=2):
    # Get the length of the data represented in the desired number of bytes
    lengthBytes = bytes([len(data)]).rjust(numBytes, b'\0')
    if len(lengthBytes) > numBytes:
        raise Exception(f"Data length does not fit in {numBytes} bytes")
    return lengthBytes + data

def hexdump(data: bytes) -> str:
    printable = string.ascii_letters + string.digits + string.punctuation + ' '
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        # 3 byte hex representation of the data index
        bytenum = hex(i)[2:].rjust(6, '0') + '    '
        # The 16 byte line in hex
        line = binascii.hexlify(chunk, ' ').decode('ascii').ljust(51, ' ')
        # The ascii representation of the line
        asciis = ''.join([chr(b) if chr(b) in printable else '.' for b in chunk])
        lines += [bytenum + line + asciis]
    return '\n'.join(lines)
