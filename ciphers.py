from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AES_GCM(Cipher):
    """ This class is really just a wrapper for the actual AES GCM
        implementation. It stores the implicit nonce (generated in the key
        calculation) so that you only have to give it the explicit nonce
        when you need to encrypt/decrypt.

        Nonce stuff is defined in https://tools.ietf.org/html/rfc5288.
    """

    def __init__(self, key: bytes, implicit_nonce: bytes):
        self.cipher = AESGCM(key)
        self.implicit_nonce = implicit_nonce

    def encrypt(self, explicit_nonce: bytes, data: bytes, additional_data: bytes):
        return self.cipher.encrypt(self.implicit_nonce + explicit_nonce, 
                                   data, additional_data)

    def decrypt(self, explicit_nonce: bytes, data: bytes, additional_data: bytes):
        return self.cipher.decrypt(self.implicit_nonce + explicit_nonce, 
                                   data, additional_data)
