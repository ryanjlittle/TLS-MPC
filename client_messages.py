from extensions import *
from utils import prependedLen



class ClientHello():

    def __init__(self, random=None, hostname=None):
        self.randomness = random if random is not None else bytes(32)
        # Hardcoded for now
        self.extensions = [ServerNameExtension([hostname]), 
                           SupportedGroupsExtension(),
                           RenegotiationExtension()]
        # Hardcoded for now to only support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        self.ciphersuites = [b'\xc0\x2f']
        self.data = self._getData()

    def __bytes__(self):
        # Prepend record header 
        return b'\x16\x03\x01' + prependedLen(self.data)

    def _getData(self) -> bytes:
        data = b''
        # Add client version
        data += b'\x03\x03'
        # Add random bytes
        data += self.randomness
        # Add session id
        data += b'\0'
        # Add ciphersuites
        data += prependedLen(b''.join(self.ciphersuites))
        # Add compression methods (We don't want any)
        data += b'\x01\x00'
        # Add extensions
        data += prependedLen(b''.join([bytes(e) for e in self.extensions]))
        # Prepend handshake header
        data = b'\x01' + prependedLen(data, 3)
        return data

class ClientKeyExchange():

    def __init__(self, public_key: bytes):
        self.public_key = public_key
        self.data = self._getData()

    def __bytes__(self):
        # Prepend record header
        return b'\x16\x03\x03' + prependedLen(self.data)

    def _getData(self) -> bytes:
        data = b''
        # Add public key
        data += prependedLen(self.public_key, 1)
        # Prepend hanshake record
        data = b'\x10' + prependedLen(data, 3)
        return data

class ClientChangeCipherSpec():

    def __init__():
        self.data = self._getData()

    def _getData(self) -> bytes:
        return b'\x01'

    def __bytes__(self):
        # Prepend record header
        return b'\x14\x03\x03' + prependedLen(self.data)
