def formattedArray(array: [bytes]):
    data = b''
    for elem in array:
        data += prependedLength(elem, 2)
    return prependedLength(data, 2)

def prependedLength(data: bytes, numBytes: int):
    # Get the length of the data represented in the desired number of bytes
    lengthBytes = bytes([len(data)]).rjust(numBytes, b'\0')
    if len(lengthBytes) > numBytes:
        raise Exception("Data is too large")
    return lengthBytes + data
