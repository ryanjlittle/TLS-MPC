import sys
import socket
from mpc import MPC

class BobTlsSession():

    def __init__(self, ip="127.0.0.1",  port=12345, logging=False):
        self.ip = ip
        self.port = port
        self.logging = logging
        self.mpc = MPC(party=2)
        self.seq_num=bytes(8)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    def openConnection(self):
        self.socket.bind((self.ip, self.port))
        self.socket.listen()
        self.log("Waiting for Alice's connection...")
        (conn, alice_ip) = self.socket.accept()
        self.log("Connected to Alice.")
        self.conn = conn

    # receive share of key from alice. this is a placeholder to be replaced with mpc
    def getKey(self):
        self.key_share = self.conn.recv(16)
        self.record_hash = self.conn.recv(12)
        self.iv = self.conn.recv(12)

        self.mpc.setKeys(self.iv, self.key_share)
        self.mpc.precomputeGCM()

    def sendFinishedMPC(self):
        self.log("Initiating MPC encryption")
        ctxt, tag_share = self.mpc.encryptClientFinished(self.seq_num, self.record_hash)
        self.conn.send(tag_share)
    
    def send(self, data: bytes):
        chunks = [data[i:i+128] for i in range(0, len(data), 128)]
        for chunk in chunks:
            self.sendChunk(chunk)

    def sendChunk(self, data: bytes):
        self.seq_num = self.incrementSeqNum(self.seq_num)
        additional_data = self.seq_num + b'\x17\x03\x03' \
                          + len(data).to_bytes(2, byteorder='big')
        ctxt, tag = self.mpc.encryptPubPtxt(self.seq_num, data, additional_data)
        self.conn.send(tag)

    def sendPassword(self, password: bytes):
        self.seq_num = self.incrementSeqNum(self.seq_num)
        additional_data = self.seq_num + b'\x17\x03\x03' \
                          + len(password).to_bytes(2, byteorder='big')
        ctxt, tag = self.mpc.encryptPassword(self.seq_num, password, additional_data)
        self.conn.send(tag)


    def incrementSeqNum(self, seq_num: bytes) -> bytes:
        # We can't increment bytes directly in python so we convert to int and back
        inc_seq_num = int.from_bytes(seq_num, byteorder='big') + 1
        return inc_seq_num.to_bytes(8, byteorder='big')

    def log(self, msg):
        if self.logging:
            print(msg)

