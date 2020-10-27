import socket
from client_messages import ClientHello, ClientKeyExchange, \
    ClientChangeCipherSpec
from server_handshake import ServerHello, ServerCertificate, \
    ServerKeyExchange, ServerDone
from key_exchange import X25519


class TlsSession():
    
    def __init__(self, hostname):
        # Initialise a socket for an IPv4, TCP connection
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(hostname)
        self.hostname = hostname
        # TODO: Generate 32 bytes of randomness
        self.randomness = b'randomrandomrandomrandomrandomra'
        self.record = b''

    def connect(self):
        print("Trying to connect...")
        self.socket.connect((self.ip, 443))
        print(f"Connected to {self.ip}.")
        self.handshake()


    def handshake(self): 
        hello = ClientHello(random=self.randomness, hostname=self.hostname)
        self.socket.send(bytes(hello))
        self.record += hello.data

        serv_hello = ServerHello()
        serv_hello.parseFromStream(self.socket)
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

        client_key_ex = ClientKeyExchange(self.key_exchange.publicKey())
        self.socket.send(bytes(client_key_ex))
        self.record += client_key_ex.data

        client_change_cipher = ClientChangeCipherSpec()
        self.socket.send(bytes(client_change_cipher))
        self.record += client_change_cipher.data

        
        res = self.socket.recv(2048)
        print(res)

def testSession():
    session = TlsSession("wikipedia.org")
    session.connect()
    
if __name__ == "__main__":
    testSession()
    

