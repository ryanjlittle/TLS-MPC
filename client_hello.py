from extensions import ServerNameExtension
from utils import prependedLength


class ClientHello():

    def __init__(self, random=None, SNI=None):

        if random:
            self.random = random
        else:
            # TODO: Generate 32 bytes of random data
            pass

        # TODO: Add support for more extensions
        self.extensions = [ServerNameExtension([SNI])]

        # For now this is just TLS_AES_128_GCM_SHA256
        self.ciphersuites = [b'\x13\x01']
        
    def __bytes__(self):

        data = b''

        # Add client version
        data += b'\x03\x03'

        # Add random bytes
        data += self.random

        # Add session id
        data += b'\0'

        # Add ciphersuites
        data += prependedLength(b''.join(self.ciphersuites), 2)

        # Add compression methods (We don't want any)
        data += b'\x01\x00'

        # Add extensions
        data += prependedLength(b''.join([bytes(e) for e in self.extensions]), 2)

        # Prepend handshake header
        data = b'\x01' + prependedLength(data, 3)

        # Prepend record header
        data = b'\x16\x03\x01' + prependedLength(data, 2)
        
        return data

