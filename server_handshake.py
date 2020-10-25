import io
from utils import recvall


HANDSHAKE_RECORD = b'\x16'
TLS_1_2 = b'\x03\x03'


class ServerHandshakeMessage():

    def parseFromStream(self, socket):
        rec_header = recvall(socket, 5)
        if rec_header[0:3] != HANDSHAKE_RECORD + TLS_1_2:
            raise Exception("Unexpected record header")
        length = int.from_bytes(rec_header[3:5], "big")
        data = recvall(socket, length)
        self._parseData(io.BytesIO(data))


class ServerHello(ServerHandshakeMessage):

    def _parseData(self, data):
        self.header = data.read(4)
        self.version = data.read(2)
        self.random = data.read(32)
        self.sessionIdLen = data.read(1)[0]
        if self.sessionIdLen > 0:
            self.sessionId = data.read(self.sessionIdLen)
        self.cipherSuite = data.read(2)
        self.compressionMethod = data.read(1)
        self.extensionsLen = int.from_bytes(data.read(2), "big")
        if self.extensionsLen > 0:
            # TODO: Parse extensions
            pass


class ServerCertificate(ServerHandshakeMessage):

    def _parseData(self, data):
        self.header = data.read(4)
        self.certificatesLen = int.from_bytes(data.read(3), "big")
        self.certificates = []
        read_bytes = 0
        while read_bytes < self.certificatesLen:
            certLen = int.from_bytes(data.read(3), "big")
            self.certificates.append(data.read(certLen))
            read_bytes += certLen + 3


class ServerKeyExchange(ServerHandshakeMessage):

    def _parseData(self, data):
        self.header = data.read(4)
        

class ServerDone(ServerHandshakeMessage):

    def _parseData(self, data):
        self.header = data.read(4)

