from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client_messages import ClientHandshakeFinished
from utils import prependedLen

# Ciphertexts
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = b'\xc0\x2f'


#CipherSelect = {TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: AES_GCM}

# Is a parent class even useful?
class Cipher():
    def __init__(self, ciphersuite: bytes, key: bytes, 
                 mac_key: bytes, iv: bytes):
        pass




class AES_GCM(Cipher):
    
    def __init__(self, key: bytes, salt: bytes):
        self.aes = AESGCM(key)
        self.salt = salt
        self.sequence_num = 0


    def encrypt(self, data: bytes, additional_data: bytes):
        ciphertext = self.aes.encrypt(self._getNonce(), data, additional_data)
        self.sequence_num += 1
        return ciphertext

    #def createPacket(self, data: bytes):

    def createHandshakeFinishedPacket(self, verify_data: bytes) -> ClientHandshakeFinished:
        additional_data = self.sequence_num.to_bytes(8, byteorder='big') \
                          + b'\x16\x03\x03\x00\x10' 
        implicit_nonce = self._getImplicitNonce()
        # Prepend a handshake header to the data
        payload = b'\x14\x00\x00\x0c' + verify_data
        ciphertext = self.encrypt(payload, additional_data)
        return ClientHandshakeFinished(implicit_nonce, ciphertext)

    def _getImplicitNonce(self):
        return self.sequence_num.to_bytes(8, byteorder='big')

    def _getNonce(self):
        return self.salt + self._getImplicitNonce()
