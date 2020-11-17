import io
from utils import recvall, parsePrependedLen


HANDSHAKE_RECORD = b'\x16'
TLS_1_2 = b'\x03\x03'


class ServerMessage():

    def parseFromStream(self, socket):
        rec_header = recvall(socket, 5)
        if rec_header[0:3] != HANDSHAKE_RECORD + TLS_1_2:
            raise Exception("Unexpected record header")
        length = int.from_bytes(rec_header[3:5], "big")
        self.data = recvall(socket, length)
        self._parseData(io.BytesIO(self.data))


class ServerHello(ServerMessage):

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

    def _parseData(self, data):
        self.header = data.read(4)
        self.curveInfo = data.read(1)
        self.curve = data.read(2)
        self.public_key = parsePrependedLen(data, 1)
        self.signatureAlgo = data.read(2)
        self.signature = parsePrependedLen(data)

class ServerDone(ServerMessage):

    def _parseData(self, data):
        self.header = data.read(4)

