# overview:
#  set up connecion with Bob
#  set up connection with server
#  send client hello to server
# send copy of client hello to bob
# receive responses from server
# forward those responses to bob
# generate DH public key with bob in MPC
# send key exchange message to server
# send a copy of the message to bob
# etc
import socket
import sys
from random import randbytes
from client_messages import ClientHello, ClientKeyExchange, \
    ClientChangeCipherSpec, ClientFinished, ClientApplicationData
from server_messages import ServerHello, ServerCertificate, \
    ServerKeyExchange, ServerDone, ServerChangeCipherSpec, \
    ServerFinished, ServerApplicationData
from key_exchange import X25519
from ciphers import AES_GCM
from crypto_utils import PRF, randomBytes, sha256
from utils import bytexor
from mpc import MPC


class AliceTlsSession():

    def __init__(self, hostname, serv_port=443, bob_ip="127.0.0.1",  
                 bob_port=12345, logging=False):
        self.hostname = hostname
        self.serv_port = serv_port
        self.bob_ip = bob_ip
        self.bob_port = bob_port
        self.logging = logging
        self.serv_ip = socket.gethostbyname(hostname)
        # TODO: make this shared between Alice and Bob?
        self.client_random = randomBytes(32)
        self.record = b''
        self.mpc = MPC(party=1)

        self.serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self):
        self.connectToBob()
        self.connectToServ()


    def connectToBob(self):
        self.log("Trying to connect to Bob...")
        self.bob_sock.connect((self.bob_ip, self.bob_port))
        self.log(f"Connected to Bob.")

    def connectToServ(self):
        self.log("Trying to connect to server...")
        self.serv_sock.connect((self.serv_ip, self.serv_port))
        self.log(f"Connected to {self.serv_ip}.")

    
    def handshake(self): 
        self.sendHello()
        self.recvHello()
        self.recvCertificate()
        self.recvKeyExchange()
        self.recvHelloDone()
        
        # TODO: Check certificate
        #self.verifyCertificate()
        
        self.calculateKeys()
        self.sendKeyExchange()
        self.sendFinished()
        self.recvFinished()

    
    def send(self, data: bytes):
        chunks = [data[i:i+128] for i in range(0, len(data), 128)]
        for chunk in chunks:
            self.sendChunk(chunk)

    def sendChunk(self, data: bytes):
        self.client_seq_num = self.incrementSeqNum(self.client_seq_num)
        additional_data = self.client_seq_num + b'\x17\x03\x03' \
                          + len(data).to_bytes(2, byteorder='big')
        """
        ciphertext = self.encryptor.encrypt(self.client_seq_num, 
                                            data, additional_data)
        """
        ctxt, tag_share = self.mpc.encryptPubPtxt(self.client_seq_num, data, additional_data)

        # receive tag share from bob
        bob_tag_share = self.bob_sock.recv(16)
        tag = bytexor(tag_share, bob_tag_share)
        ctxt += tag

        application_data = ClientApplicationData(self.client_seq_num, ctxt)

        self.sendToServ(bytes(application_data))
        self.log('\nClient Application Data')
        self.log(application_data)

    def sendPassword(self, password: bytes):
        self.client_seq_num = self.incrementSeqNum(self.client_seq_num)
        additional_data = self.client_seq_num + b'\x17\x03\x03' \
                          + len(password).to_bytes(2, byteorder='big')
        ctxt, tag_share = self.mpc.encryptPassword(self.client_seq_num, password, additional_data)

        # receive tag share from bob
        bob_tag_share = self.bob_sock.recv(16)
        tag = bytexor(tag_share, bob_tag_share)
        ctxt += tag

        application_data = ClientApplicationData(self.client_seq_num, ctxt)

        self.sendToServ(bytes(application_data))
        self.log('\nClient Application Data')
        self.log(application_data)


    def recv_response(self) -> bytes:
        self.server_seq_num = self.incrementSeqNum(self.server_seq_num)
        application_data = ServerApplicationData()
        application_data.parseFromStream(self.serv_sock)
        self.log('\nApplication Data')
        self.log(application_data)
        # Subtract the length of the auth tag (16 bytes) to get the data length
        data_len = len(application_data.ciphertext)-16 
        additional_data = self.server_seq_num + b'\x17\x03\x03' \
                          + data_len.to_bytes(2, byteorder='big')
        return self.decryptor.decrypt(application_data.nonce, 
                                      application_data.ciphertext, 
                                      additional_data)

    def log(self, msg):
        if self.logging:
            print(msg)

    def sendHello(self):
        hello = ClientHello(random=self.client_random, hostname=self.hostname)
        self.sendToServ(bytes(hello))
        self.log('\nClient Hello')
        self.log(hello)
        self.record += hello.data
    
    def recvHello(self):
        serv_hello = ServerHello()
        serv_hello.parseFromStream(self.serv_sock)
        self.log('\nServer Hello')
        self.log(serv_hello)
        self.server_random = serv_hello.random
        self.record += serv_hello.data

    def recvCertificate(self):
        serv_cert = ServerCertificate()
        serv_cert.parseFromStream(self.serv_sock)
        self.log('\nServer Certificate')
        self.log(serv_cert)
        self.record += serv_cert.data

    def recvKeyExchange(self):
        serv_key_ex = ServerKeyExchange()
        serv_key_ex.parseFromStream(self.serv_sock)
        self.log('\nServer Key Exchange')
        self.log(serv_key_ex)
        self.server_key = serv_key_ex.public_key
        self.record += serv_key_ex.data

    def recvHelloDone(self):
        serv_done = ServerDone()
        serv_done.parseFromStream(self.serv_sock)
        self.log('\nServer Hello Done')
        self.log(serv_done)
        self.record += serv_done.data

    def sendKeyExchange(self):
        client_key_ex = ClientKeyExchange(self.public_key)
        self.sendToServ(bytes(client_key_ex))
        self.log('\nClient Key Exchange')
        self.log(client_key_ex)
        self.record += client_key_ex.data
        
    def sendFinished(self):
        client_change_cipher = ClientChangeCipherSpec()
        self.sendToServ(bytes(client_change_cipher))
        self.log('\nClient Change Cipher Spec')
        self.log(client_change_cipher)

        self.record_hash = self.PRF_HandshakeRecord()

        # TODO: this is placeholder, of course needs to be replaced with mpc
        self.sendKeysToBob()


        self.client_seq_num = bytes(8)
        
        self.log("Initiating MPC encryption")
        ctxt, tag_share = self.mpc.encryptClientFinished(self.client_seq_num, self.record_hash)
        self.log("MPC encryption complete")
        
        # receive tag share from bob
        bob_tag_share = self.bob_sock.recv(16)
        tag = bytexor(tag_share, bob_tag_share)
        ctxt += tag

        self.encryptor = AES_GCM(self.client_key, self.client_IV)
        """
        additional_data = self.client_seq_num + b'\x16\x03\x03\x00\x10' 
        payload = b'\x14\x00\x00\x0c' + self.record_hash 
        ciphertext = self.encryptor.encrypt(self.client_seq_num, 
                                            payload, additional_data)
        """
        client_finished = ClientFinished(self.client_seq_num, ctxt)
        self.sendToServ(bytes(client_finished))
        self.log('\nClient Finished')
        self.log(client_finished)

    def recvFinished(self):
        serv_change_cipher = ServerChangeCipherSpec()
        serv_change_cipher.parseFromStream(self.serv_sock)
        self.log('\nServer Change Cipher Spec')
        self.log(serv_change_cipher)

        serv_finished = ServerFinished()
        serv_finished.parseFromStream(self.serv_sock)
        self.log('\nServer Handshake Finished')
        self.log(serv_finished)
        
        self.server_seq_num = bytes(8)

        self.decryptor = AES_GCM(self.server_key, self.server_IV)
        additional_data = self.server_seq_num + b'\x16\x03\x03\x00\x10'
        plaintext = self.decryptor.decrypt(serv_finished.nonce, 
                                           serv_finished.ciphertext, 
                                           additional_data)
        #TODO: verify that the plaintext matches the hash of the record

    def sendKeysToBob(self):
        
        key_mask = randbytes(16)
        self.sendToBob(bytexor(key_mask, self.client_key))
        self.sendToBob(self.record_hash)
        # This shouldn't actually be removed, is meant to be public
        self.sendToBob(self.client_IV)
        self.client_key_share = key_mask

        self.mpc.setKeys(self.client_IV, self.client_key_share)
        self.mpc.precomputeGCM()

    def incrementSeqNum(self, seq_num: bytes) -> bytes:
        # We can't increment bytes directly in python so we convert to int and back
        inc_seq_num = int.from_bytes(seq_num, byteorder='big') + 1
        return inc_seq_num.to_bytes(8, byteorder='big')

    def calculateKeys(self):
        key_exchange = X25519()
        self.public_key = key_exchange.publicKey()
        master_secret, expanded_key = key_exchange.computeExpandedMasterSecret(
                self.server_key, self.client_random, self.server_random)
        self.master_secret = master_secret
        self.client_key = expanded_key[:16]
        self.server_key = expanded_key[16:32]
        self.client_IV = expanded_key[32:36]
        self.server_IV = expanded_key[36:40]


    def PRF_HandshakeRecord(self) -> bytes:
        return PRF(secret = self.master_secret,
                   label = b'client finished',
                   seed = sha256(self.record),
                   num_bytes = 12)

    def sendToServ(self, data: bytes):
        self.serv_sock.send(data)

    def sendToBob(self, data: bytes):
        self.bob_sock.send(data)

