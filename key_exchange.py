from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

class KeyExchange():
    pass


class X25519(KeyExchange):

    def __init__(self, sk: bytes = None):
        # We can specify the private key if we want. This won't be used in TLS,
        # but could be useful for testing 
        if sk:
            self.private_key = x25519.X25519PrivateKey.from_private_bytes(sk)
        else:
            self.private_key = x25519.X25519PrivateKey.generate()

    def privateKey(self):
        return self.private_key.private_bytes(
            encoding=Encoding.Raw, 
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption())

    def publicKey(self):
        return self.private_key.public_key().public_bytes(
            encoding=Encoding.Raw, 
            format=PublicFormat.Raw)

    def exchange(self, server_key=bytes) -> bytes:
        server_pub_key = x25519.X25519PublicKey.from_public_bytes(server_key)
        return self.private_key.exchange(server_pub_key)

