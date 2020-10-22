import socket
from client_hello import ClientHello

class TlsSession():
    
    def __init__(self, hostname, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(hostname)
        self.hostname = hostname
        self.port = port
        # TODO: Generate 32 bytes of randomness
        self.randomness = b'randomrandomrandomrandomrandomra'

    def connect(self):
        print("Trying to connect...")
        self.socket.connect((self.ip, self.port))
        print(f"Connected to {self.ip} on port {self.port}.")
        self.handshake()


    def handshake(self): 
        hello = ClientHello(random=self.randomness, hostname=self.hostname)
        self.socket.send(bytes(hello))
        response = self.socket.recv(1024)
        print(response)
        

def testSession():
    session = TlsSession("wikipedia.org", 443)
    session.connect()
    
if __name__ == "__main__":
    testSession()
    

