from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AES_GCM():
    """ This class is really just a wrapper for the actual AES GCM
        implementation. It stores the implicit nonce (generated in the key
        calculation) so that you only have to give it the explicit nonce
        when you need to encrypt/decrypt.

        Nonce stuff is defined in https://tools.ietf.org/html/rfc5288.
    """

    def __init__(self, key: bytes, implicit_nonce: bytes):
        self.key = key
        self.cipher = AESGCM(key)
        self.implicit_nonce = implicit_nonce

    def encrypt(self, explicit_nonce: bytes, data: bytes, additional_data: bytes):
        print("ENCRYPTING...")
        nonce = self.implicit_nonce + explicit_nonce
        print("KEY: ", self.key.hex())
        print("NONCE: ", nonce.hex())
        print("DATA: ", data.hex())
        print("ADDT: ", additional_data.hex())
        return self.cipher.encrypt(nonce, data, additional_data)

    def decrypt(self, explicit_nonce: bytes, data: bytes, additional_data: bytes):
        return self.cipher.decrypt(self.implicit_nonce + explicit_nonce, 
                                   data, additional_data)
