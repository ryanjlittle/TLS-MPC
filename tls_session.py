import socket
from client_messages import ClientHello, ClientKeyExchange, \
    ClientChangeCipherSpec, ClientFinished, ClientApplicationData
from server_messages import ServerHello, ServerCertificate, \
    ServerKeyExchange, ServerDone, ServerChangeCipherSpec, \
    ServerFinished, ServerApplicationData
from key_exchange import X25519
from ciphers import AES_GCM
from crypto_utils import PRF, randomBytes, sha256


class TlsSession():
    
    def __init__(self, hostname, port=443, logging=False):
        self.hostname = hostname
        self.port = port
        self.logging=logging
        # Initialise a socket for an IPv4, TCP connection
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(hostname)
        self.client_random = randomBytes(32)
        self.record = b''
    def connect(self):
        if self.logging:
            print("Trying to connect...")
        self.socket.connect((self.ip, self.port))
        if self.logging:
            print(f"Connected to {self.ip}.")
        self._handshake()

    def _handshake(self): 
        self._sendHello()
        self._recvHello()
        self._recvCertificate()
        self._recvKeyExchange()
        self._recvHelloDone()
        # TODO: Check certificate
        #self._verifyCertificate()
        self._calculateKeys()
        self._sendKeyExchange()
        self._sendFinished()
        self._recvFinished()
    
    def send(self, data: bytes):
        self.client_seq_num = self._incrementSeqNum(self.client_seq_num)
        additional_data = self.client_seq_num + b'\x17\x03\x03' \
                          + len(data).to_bytes(2, byteorder='big')
        ciphertext = self.encryptor.encrypt(self.client_seq_num, 
                                            data, additional_data)
        application_data = ClientApplicationData(self.client_seq_num, 
                                                 ciphertext)
        self.socket.send(bytes(application_data))
        if self.logging:
            print('\nClient Application Data')
            print(application_data)

    def recv_response(self) -> bytes:
        self.server_seq_num = self._incrementSeqNum(self.server_seq_num)
        application_data = ServerApplicationData()
        application_data.parseFromStream(self.socket)
        if self.logging:
            print('\nApplication Data')
            print(application_data)
        # Subtract the length of the auth tag (16 bytes) to get the data length
        data_len = len(application_data.ciphertext)-16 
        additional_data = self.server_seq_num + b'\x17\x03\x03' \
                          + data_len.to_bytes(2, byteorder='big')
        return self.decryptor.decrypt(application_data.nonce, 
                                      application_data.ciphertext, 
                                      additional_data)

    def _sendHello(self):
        hello = ClientHello(random=self.client_random, hostname=self.hostname)
        self.socket.send(bytes(hello))
        if self.logging:
            print('\nClient Hello')
            print(hello)
        self.record += hello.data

    def _recvHello(self):
        serv_hello = ServerHello()
        serv_hello.parseFromStream(self.socket)
        if self.logging:
            print('\nServer Hello')
            print(serv_hello)
        self.server_random = serv_hello.random
        self.record += serv_hello.data

    def _recvCertificate(self):
        serv_cert = ServerCertificate()
        serv_cert.parseFromStream(self.socket)
        if self.logging:
            print('\nServer Certificate')
            print(serv_cert)
        self.record += serv_cert.data

    def _recvKeyExchange(self):
        serv_key_ex = ServerKeyExchange()
        serv_key_ex.parseFromStream(self.socket)
        if self.logging:
            print('\nServer Key Exchange')
            print(serv_key_ex)
        self.server_key = serv_key_ex.public_key
        self.record += serv_key_ex.data

    def _recvHelloDone(self):
        serv_done = ServerDone()
        serv_done.parseFromStream(self.socket)
        if self.logging:
            print('\nServer Hello Done')
            print(serv_done)
        self.record += serv_done.data

    def _sendKeyExchange(self):
        client_key_ex = ClientKeyExchange(self.public_key)
        self.socket.send(bytes(client_key_ex))
        if self.logging:
            print('\nClient Key Exchange')
            print(client_key_ex)
        self.record += client_key_ex.data
        
    def _sendFinished(self):
        client_change_cipher = ClientChangeCipherSpec()
        self.socket.send(bytes(client_change_cipher))
        if self.logging:
            print('\nClient Change Cipher Spec')
            print(client_change_cipher)

        record_hash = self._PRF_HandshakeRecord()
        self.client_seq_num = bytes(8)

        self.encryptor = AES_GCM(self.client_key, self.client_IV)
        additional_data = self.client_seq_num + b'\x16\x03\x03\x00\x10' 
        payload = b'\x14\x00\x00\x0c' + record_hash 
        ciphertext = self.encryptor.encrypt(self.client_seq_num, 
                                            payload, additional_data)
        client_finished = ClientFinished(self.client_seq_num, ciphertext)
        self.socket.send(bytes(client_finished))
        if self.logging:
            print('\nClient Finished')
            print(client_finished)

    def _recvFinished(self):
        serv_change_cipher = ServerChangeCipherSpec()
        serv_change_cipher.parseFromStream(self.socket)
        if self.logging:
            print('\nServer Change Cipher Spec')
            print(serv_change_cipher)

        serv_finished = ServerFinished()
        serv_finished.parseFromStream(self.socket)
        if self.logging:
            print('\nServer Handshake Finished')
            print(serv_finished)
        
        self.server_seq_num = bytes(8)

        self.decryptor = AES_GCM(self.server_key, self.server_IV)
        additional_data = self.server_seq_num + b'\x16\x03\x03\x00\x10'
        plaintext = self.decryptor.decrypt(serv_finished.nonce, 
                                           serv_finished.ciphertext, 
                                           additional_data)
        #TODO: verify that the plaintext matches the hash of the record

    def _incrementSeqNum(self, seq_num: bytes) -> bytes:
        # We can't increment bytes directly in python so we convert to int and back
        inc_seq_num = int.from_bytes(seq_num, byteorder='big') + 1
        return inc_seq_num.to_bytes(8, byteorder='big')

    def _calculateKeys(self):
        key_exchange = X25519()
        self.public_key = key_exchange.publicKey()
        master_secret, expanded_key = key_exchange.computeExpandedMasterSecret(
                self.server_key, self.client_random, self.server_random)
        self.master_secret = master_secret
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
    data = b'GET / HTTP/1.1\r\nHost: www.wikipedia.org\r\nAccept: */*\r\n\r\n'

    session = TlsSession("wikipedia.org", logging=True)
    session.connect()
    session.send(data)
    res = session.recv_response()
    print(res)
    
if __name__ == "__main__":
    testSession()
    

