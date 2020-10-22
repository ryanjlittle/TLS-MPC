from extensions import *
from utils import prependedLen



class ClientHello():

    def __init__(self, random=None, hostname=None):

        if random:
            self.random = random
        else:
            # TODO: Generate 32 bytes of random data
            self.random = b'randomrandomrandomrandomrandomra'
            pass

        self.extensions = [ServerNameExtension([hostname]), 
                           StatusRequestExtension(), 
                           SupportedGroupsExtension(),
                           RenegotiationExtension(),
                           SCTExtension()]

        # Hardcoded for now to only support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        self.ciphersuites = [b'\xc0\x2f']
        
    def __bytes__(self):

        data = b''
        # Add client version
        data += b'\x03\x03'
        # Add random bytes
        data += self.random
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
        # Prepend record header
        data = b'\x16\x03\x01' + prependedLen(data)

        return data

