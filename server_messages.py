import io
from utils import hexdump

CHANGE_CIPHER_SPEC = 20 
ALERT              = 21
HANDSHAKE          = 22
APPLICATION_DATA   = 23

TLS_1_2 = b'\x03\x03'


def recvall(socket, length) -> bytes:
    data = b''
    while len(data) < length:
        data += socket.recv(length-len(data))
    return data


def parsePrependedLen(data:io.BytesIO, numBytes=2):
    length = int.from_bytes(data.read(numBytes), "big")
    return data.read(length) if length > 0 else None


class ServerMessage():

    def parseFromStream(self, socket):
        self.rec_header = recvall(socket, 5)
        self.length = int.from_bytes(self.rec_header[3:5], "big")
        self.data = recvall(socket, self.length)
        if self.rec_header[0] != self.content_type:
            print("\nServer Error")
            print(self)
            raise Exception(f"Received wrong content type: {self.rec_header[0]}")
        if self.rec_header[1:3] != TLS_1_2: 
            raise Exception("Received wrong TLS version")
        self._parseData(io.BytesIO(self.data))

    def __repr__(self):
        return hexdump(self.rec_header + self.data)

    def __bytes__(self):
        return self.rec_header + self.data


class ServerHello(ServerMessage):

    content_type = HANDSHAKE

    def _parseData(self, data):
        self.header = data.read(4)
        self.version = data.read(2)
        self.random = data.read(32)
        sessionIdLen = data.read(1)[0]
        self.sessionId = parsePrependedLen(data)
        self.cipherSuite = data.read(2)
        self.compressionMethod = data.read(1)
        self.extensionsLen = int.from_bytes(data.read(2), "big")
        if self.extensionsLen > 0:
            # TODO: Parse extensions
            pass


class ServerCertificate(ServerMessage):

    content_type = HANDSHAKE

    def _parseData(self, data):
        self.header = data.read(4)
        self.certificatesLen = int.from_bytes(data.read(3), "big")
        self.certificates = []
        read_bytes = 0
        while read_bytes < self.certificatesLen:
            cert = parsePrependedLen(data, 3)
            self.certificates.append(cert)
            read_bytes += len(cert) + 3


class ServerKeyExchange(ServerMessage):

    content_type = HANDSHAKE

    def _parseData(self, data):
        self.header = data.read(4)
        self.curveInfo = data.read(1)
        self.curve = data.read(2)
        self.public_key = parsePrependedLen(data, 1)
        self.signatureAlgo = data.read(2)
        self.signature = parsePrependedLen(data)


class ServerDone(ServerMessage):

    content_type = HANDSHAKE

    def _parseData(self, data):
        self.header = data.read(4)


class ServerChangeCipherSpec(ServerMessage):
    
    content_type = CHANGE_CIPHER_SPEC

    def _parseData(self, data):
        self.payload = data.read(1)


class ServerFinished(ServerMessage):

    content_type = HANDSHAKE

    def _parseData(self, data):
        self.nonce = data.read(8)
        self.ciphertext = data.read(32)

class ServerApplicationData(ServerMessage):

    content_type = APPLICATION_DATA

    def _parseData(self, data):
        self.nonce = data.read(8)
        self.ciphertext = data.read(self.length - 8)

