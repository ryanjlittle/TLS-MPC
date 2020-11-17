from extensions import *
from utils import prependedLen

# Record types
CHANGE_CIPHER_SPEC = b'\x14' 
HANDSHAKE          = b'\x16'
APPLICATION_DATA   = b'\x17'

# TLS versions 
TLS_1_0 = b'\x03\x01'
TLS_1_2 = b'\x03\x03'


class ClientMessage():

    def __init__(self):
        self.data = self._getData()

    def __bytes__(self):
        # Prepend record header
        return self.content_type + self.version + prependedLen(self.data)


class ClientHello(ClientMessage):
    """ 
    https://tools.ietf.org/html/rfc5246#section-7.4.1.2 
    """
    content_type = HANDSHAKE
    version = TLS_1_0 # This is for backwards compatibility 

    def __init__(self, random: bytes, hostname: bytes):
        self.randomness = random
        self.extensions = [ServerNameExtension([hostname]), 
                           SupportedGroupsExtension(),
                           RenegotiationExtension(),
                           SignatureAlgorithmsExtension()]
        # We only support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        self.ciphersuites = [b'\xc0\x2f']
        super().__init__()

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

class ClientKeyExchange(ClientMessage):
    """ 
    https://tools.ietf.org/html/rfc5246#section-7.4.7 
    """
    content_type = HANDSHAKE
    version = TLS_1_2

    def __init__(self, public_key: bytes):
        self.public_key = public_key
        super().__init__()

    def _getData(self) -> bytes:
        data = b''
        # Add public key
        data += prependedLen(self.public_key, 1)
        # Prepend hanshake record
        data = b'\x10' + prependedLen(data, 3)
        return data

class ClientChangeCipherSpec(ClientMessage):
    """
    https://tools.ietf.org/html/rfc5246#section-7.1
    """
    content_type = CHANGE_CIPHER_SPEC
    version = TLS_1_2
    
    def _getData(self) -> bytes:
        return b'\x01'


class ClientFinished(ClientMessage):
    """
    https://tools.ietf.org/html/rfc5246#section-7.4.9
    """
    content_type = HANDSHAKE
    version = TLS_1_2

    # We should have 8 bytes for the nonce (explicit part)
    def __init__(self, explicit_nonce: bytes, ciphertext: bytes):
        self.explicit_nonce = explicit_nonce
        self.ciphertext = ciphertext
        super().__init__()
       
    def _getData(self) -> bytes:
        return self.explicit_nonce + self.ciphertext


class ClientApplicationData(ClientMessage):

    content_type = APPLICATION_DATA
    version = TLS_1_2
    
    def __init__(self, explicit_nonce: bytes, ciphertext: bytes):
        self.explicit_nonce = explicit_nonce
        self.ciphertext = ciphertext
        super().__init__()

    def _getData(self) -> bytes:
        return self.explicit_nonce + self.ciphertext
