import socket
from client_messages import ClientHello, ClientKeyExchange, \
    ClientChangeCipherSpec
from server_handshake import ServerHello, ServerCertificate, \
    ServerKeyExchange, ServerDone
from key_exchange import X25519
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
        self.socket.connect((self.ip, 443))
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
        self.record += serv_key_ex.data
        # TODO: Verify signature 

        serv_done = ServerDone()
        serv_done.parseFromStream(self.socket)
        self.record += serv_done.data

        # TODO: Use the server's ciphersuite to get the right curve for key exchange
        self.key_exchange = X25519()
        self.premaster_key = self.key_exchange.exchange(serv_key_ex.public_key)
        self._calculateKeys()

        client_key_ex = ClientKeyExchange(self.key_exchange.publicKey())
        self.socket.send(bytes(client_key_ex))
        self.record += client_key_ex.data

        client_change_cipher = ClientChangeCipherSpec()
        self.socket.send(bytes(client_change_cipher))
        self.record += client_change_cipher.data

        
        
        res = self.socket.recv(2048)
        print(res)

    def _calculateKeys(self):
        self.mastersecret = PRF(secret = self.premastersecret, 
                                label = b'master secret', 
                                seed = self.client_random + self.server_random,
                                num_bytes = 48)
        # RFC 5246 sec 8.1 says to get rid of the premaster secret after 
        # computing the master secret.
        del a.premastersecret
        expanded_key = PRF(secret = self.mastersecret,
                           label = b'key expansion',
                           seed = self.server_random + self.client_random,
                           num_bytes = 104)
        self.client_MAC_key = expanded_key[:20]
        self.server_MAC_key = expanded_key[20:40]
        self.client_key = expanded_key[40:56]
        self.server_key = expanded_key[56:72]
        self.client_IV = expanded_key[72:88]
        self.server_IV = expanded_key[88:104]

    def _hashHandshakeRecord(self) -> bytes:
        return PRF(secret = self.masterkey,
                   label = b'client finished',
                   seed = sha256(self.record),
                   num_bytes = 12)

def testSession():
    session = TlsSession("wikipedia.org")
    session.connect()
    
if __name__ == "__main__":
    testSession()
    

