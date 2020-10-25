import socket
from client_hello import ClientHello
from server_handshake import ServerHello, ServerCertificate

TLS_PORT = 443

class TlsSession():
    
    def __init__(self, hostname):
        # Initialise a socket for an IPv4, TCP connection
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(hostname)
        self.hostname = hostname
        # TODO: Generate 32 bytes of randomness
        self.randomness = b'randomrandomrandomrandomrandomra'

    def connect(self):
        print("Trying to connect...")
        self.socket.connect((self.ip, TLS_PORT))
        print(f"Connected to {self.ip}.")
        self.handshake()


    def handshake(self): 
        hello = ClientHello(random=self.randomness, hostname=self.hostname)
        self.socket.send(bytes(hello))

        serv_hello = ServerHello().parseFromStream(self.socket)
        serv_cert = ServerCertificate().parseFromStream(self.socket)
        # TODO: Check certificate
        serv_key_ex = ServerKeyExchange().parseFromStream(self.socket)
        # TODO: Verify signature 
        serv_done = ServerDone().parseFromStream(self.socket)

        print(serv_cert.__dict__)

        

def testSession():
    session = TlsSession("wikipedia.org")
    session.connect()
    
if __name__ == "__main__":
    testSession()
    

