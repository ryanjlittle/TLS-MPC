from utils import formattedArray, prependedLen

SERVER_NAME_EXTENSION = b'\x00\x00'
STATUS_REQUEST = b'\x00\x05'
SUPPORTED_GROUPS = b'\x00\x0a'
EC_POINT_FORMATS = b'\x00\x0b'
SIGNATURE_ALGORITHMS = b'\x00\x0d'
RENEGOTIATION_INFO = b'\xff\x01'
SIGNED_CERTIFICATE_TIMESTAMP = b'\x00\x12'
PADDING = b'\x00\x15'

# Signature schemes
RSA_PKCS1_SHA256 = b'\x04\x01'
RSA_PKCS1_SHA384 = b'\x05\x01'
RSA_PKCS1_SHA512 = b'\x06\x01'
ECDSA_SECP256R1_SHA256 = b'\x04\x03'
ECDSA_SECP384R1_SHA384 = b'\x05\x03'
ECDSA_SECP512R1_SHA512 = b'\x06\x03'
RSA_PSS_RSAE_SHA256 = b'\x08\x04'
RSA_PSS_RSAE_SHA384 = b'\x08\x05'
RSA_PSS_RSAE_SHA512 = b'\x08\x06'
ED25519 = b'\x08\x07'
ED448 = b'\x08\x06'
RSA_PSS_PSS_SHA256 = b'\x08\x09'
RSA_PSS_PSS_SHA384 = b'\x08\x0a'
RSA_PSS_PSS_SHA512 = b'\x08\x0b'
RSA_PKCS1_SHA1 = b'\x02\x01'
ECDSA_SHA1 = b'\x08\x0b'


class Extension():

    def __init__(self, extension_type, data):
        self.extension_type = extension_type
        self.data = data
        
    def __bytes__(self):
        return self.extension_type + prependedLen(self.data)


class ServerNameExtension(Extension):

    def __init__(self, hostnames: [str]):
        data = formattedArray(
            [b'\0'  # Byte to indicate entry type is DNS Hostname
            + prependedLen(bytes(hostname, 'ascii', 'strict'))
            for hostname in hostnames])
        super().__init__(SERVER_NAME_EXTENSION, data)
        

class StatusRequestExtension(Extension):

    def __init__(self):
        super().__init__(STATUS_REQUEST, b'\x01\x00\x00\x00\x00')


class SupportedGroupsExtension(Extension):
    
    def __init__(self):
        # Hardcoded now to only support curve 25519.
        data = prependedLen(b'\x00\x1d')
        super().__init__(SUPPORTED_GROUPS, data)


class ECPointFormatExtension(Extension):

    def __init__(self):
        data = prependedLen(b'\x00', 1)
        super().__init__(EC_POINT_FORMATS, data)


class RenegotiationExtension(Extension):

    def __init__(self):
        super().__init__(RENEGOTIATION_INFO, b'\x00')


class SCTExtension(Extension):

    def __init__(self):
        super().__init__(SIGNED_CERTIFICATE_TIMESTAMP, b'')


class SignatureAlgorithmsExtension(Extension):

    def __init__(self, sigAlgos=[] ):
        if not sigAlgos:
            sigAlgos = [RSA_PKCS1_SHA256]
        data = prependedLen(b''.join(sigAlgos))
        super().__init__(SIGNATURE_ALGORITHMS, data)


class PaddingExtension(Extension):

    def __init__(self, dataLen, paddedLen):
        if paddedLen - dataLen < 4:
            raise Exception("Data is too large to be padded")
        data = bytes(paddedLen - dataLen - 4)
        super().__init__(PADDING, data)
