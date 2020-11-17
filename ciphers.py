from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from client_messages import ClientFinished
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
    
    def __init__(self, key: bytes, implicit_nonce: bytes):
        self.cipher = AESGCM(key)
        self.implicit_nonce = implicit_nonce

    def encrypt(self, explicit_nonce: bytes, data: bytes, additional_data: bytes):
        return self.cipher.encrypt(self.implicit_nonce + explicit_nonce, 
                                   data, additional_data)

    def decrypt(self, explicit_nonce: bytes, data: bytes, additional_data: bytes):
        return self.cipher.decrypt(self.implicit_nonce + explicit_nonce, 
                                   data, additional_data)
