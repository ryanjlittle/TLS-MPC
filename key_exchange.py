from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from crypto_utils import PRF

class KeyExchange():

    # Returns a tuple (master_secret, expanded_master).
    def computeExpandedMasterSecret(self, server_key=bytes, 
                                    client_rand=bytes, 
                                    server_rand=bytes) -> bytes:
        premaster_secret = self.exchange(server_key)
        print(f"premaster_secret: {premaster_secret}\n len: {len(premaster_secret)}")
        master_secret = PRF(secret = premaster_secret, 
                            label = b'master secret', 
                            seed = client_rand + server_rand,
                            num_bytes = 48)
        return (master_secret, 
                PRF(secret = master_secret,
                    label = b'key expansion',
                    seed = server_rand + client_rand,
                    num_bytes = 40))


class X25519(KeyExchange):

    def __init__(self, sk: bytes = None):
        # We can specify the private key if we want.
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


