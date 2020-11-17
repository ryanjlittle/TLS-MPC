import socket
from client_messages import ClientHello, ClientKeyExchange, \
    ClientChangeCipherSpec, ClientFinished
from server_messages import ServerHello, ServerCertificate, \
    ServerKeyExchange, ServerDone, ServerChangeCipherSpec, ServerFinished
from key_exchange import X25519
from ciphers import AES_GCM
from crypto_utils import PRF, sha256


class TlsSession():
    
    def __init__(self, hostname):
        # Initialise a socket for an IPv4, TCP connection
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(hostname)
        self.hostname = hostname
        # TODO: Generate 32 bytes of randomness
        self.client_random = b'randomrandomrandomrandomrandomra'
        self.record = b''

    def connect(self):
        print("Trying to connect...")
        self.socket.connect((self.ip, 44330))
        print(f"Connected to {self.ip}.")
        self._handshake()


    def _handshake(self): 
        hello = ClientHello(random=self.client_random, hostname=self.hostname)
        self.socket.send(bytes(hello))
        self.record += hello.data

        serv_hello = ServerHello()
        serv_hello.parseFromStream(self.socket)
        self.server_random = serv_hello.random
        self.record += serv_hello.data

        serv_cert = ServerCertificate()
        serv_cert.parseFromStream(self.socket)
        self.record += serv_cert.data
        # TODO: Check certificate

        serv_key_ex = ServerKeyExchange()
        serv_key_ex.parseFromStream(self.socket)
        self.server_key = serv_key_ex.public_key
        self.record += serv_key_ex.data
        # TODO: Verify signature 

        serv_done = ServerDone()
        serv_done.parseFromStream(self.socket)
        self.record += serv_done.data

        # TODO: Use the server's ciphersuite to get the right curve for key exchange.
        # For now, we just hardcode X25519 
        self.key_exchange = X25519()

        client_key_ex = ClientKeyExchange(self.key_exchange.publicKey())
        self.socket.send(bytes(client_key_ex))
        self.record += client_key_ex.data
        
        self._calculateKeys()

        client_change_cipher = ClientChangeCipherSpec()
        self.socket.send(bytes(client_change_cipher))


        # TODO: Don't just hardcode this 
        record_hash = self._PRF_HandshakeRecord()
        self.client_seq_num = bytes(8)
        self.server_seq_num = bytes(8)

        encryptor = AES_GCM(self.client_key, self.client_IV)
        
        additional_data = self.client_seq_num + b'\x16\x03\x03\x00\x10' 
        payload = b'\x14\x00\x00\x0c' + record_hash 
        ciphertext = encryptor.encrypt(self.client_seq_num, payload, additional_data)




        client_finished = ClientFinished(self.client_seq_num, ciphertext)

        self.socket.send(bytes(client_finished))

        serv_change_cipher = ServerChangeCipherSpec()
        serv_change_cipher.parseFromStream(self.socket)

        serv_finished = ServerFinished()
        serv_finished.parseFromStream(self.socket)

        decryptor = AES_GCM(self.server_key, self.server_IV)

        additional_data = self.server_seq_num + b'\x16\x03\x03\x00\x10'
        plaintext = decryptor.decrypt(serv_finished.nonce, serv_finished.ciphertext, additional_data)

        print(plaintext)

        #TODO: Verify plaintext is correct

    def send(self, data: bytes):
        pass


    def _calculateKeys(self):
        master_secret, expanded_key = self.key_exchange.computeExpandedMasterSecret(
                self.server_key, self.client_random, self.server_random)
        self.master_secret = master_secret
        # The way we partition the master secret is unique to our ciphersuite.
        self.client_key = expanded_key[:16]
        self.server_key = expanded_key[16:32]
        self.client_IV = expanded_key[32:36]
        self.server_IV = expanded_key[36:40]

    def _PRF_HandshakeRecord(self) -> bytes:
        return PRF(secret = self.master_secret,
                   label = b'client finished',
                   seed = sha256(self.record),
                   num_bytes = 12)

def testSession():
    session = TlsSession("localhost")
    session.connect()
    
if __name__ == "__main__":
    testSession()
    

