def formattedArray(array: [bytes]):
    return b''.join([prependedLen(x, 2) for x in array])

def prependedLen(data: bytes, numBytes: int=2):
    # Get the length of the data represented in the desired number of bytes
    lengthBytes = bytes([len(data)]).rjust(numBytes, b'\0')
    if len(lengthBytes) > numBytes:
        raise Exception(f"Data length does not fit in {numBytes} bytes")
    return lengthBytes + data

def recvall(socket, length) -> bytes:
    data = b''
    while len(data) < length:
        data += socket.recv(length-len(data))
    return data
