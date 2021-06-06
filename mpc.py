import os
from utils import binaryToBytes, byteReverse
from Crypto.Util.number import long_to_bytes, bytes_to_long

ALICE = 1
BOB = 2

class MPC():

    def __init__(self, party: int, port=12346):
        self.port = port
        self.party = party

    def precomputeGCM(self):
        reversed_key_share = byteReverse(int.from_bytes(self.key_share, 'big')).to_bytes(16, 'big')[::-1]
        command = f"./mpc/bin/gcm_share {self.party} {self.port} {reversed_key_share.hex()}"
        print(command)
        os.system(command)
        if self.party == ALICE:
            file = "./alice.out"
        else:
            file = "./bob.out"
        with open(file) as f:
            a = f.readlines()
        self.shares = [byteReverse(int(i, 16)) for i in a]
        os.remove(file)


    def setKeys(self, implicit_nonce: bytes, key_share: bytes):
        self.implicit_nonce = implicit_nonce
        self.key_share = key_share


    def encryptClientFinished(self, seq_num: bytes, record_hash: bytes) -> (bytes, bytes):
        ctr = b'\x00\x00\x00\x02'
        self.key_share = self.key_share
        nonce = self.implicit_nonce + seq_num + ctr # the last 4 bytes are counter for the encryption (NOT the TLS counter)
        msg = b'\x14\x00\x00\x0c' + record_hash
        command = f"./mpc/bin/enc_public {self.party} {self.port} {self.key_share.hex()} {msg.hex()} {nonce.hex()}"
        os.system(command)
        
        if self.party == ALICE:
            file = "./alice.out"
        else:
            file = "./bob.out"
        with open(file) as f:
            a = f.readlines()
        ctxt = bytes.fromhex(a[0])
        os.remove(file)
        
        addt_data = seq_num + b'\x16\x03\x03\x00\x10' 
        tag = self.gcmTag(ctxt, addt_data, nonce[:12])

        return ctxt, tag

    def encryptPubPtxt(self, seq_num: bytes, ptxt: bytes, addt_data: bytes) -> (bytes, bytes):
        ptxt_blocks = [ptxt[i:i+16] for i in range(0, len(ptxt), 16)]
        ctr = 2
        nonce = self.implicit_nonce + seq_num + ctr.to_bytes(4,'big') # the last 4 bytes are counter for the encryption (NOT the TLS counter)
        ctxt = b''
        if self.party == ALICE:
            file = "./alice.out"
        else:
            file = "./bob.out"

        for block in ptxt_blocks:
            ctr_bytes = ctr.to_bytes(4, 'big')
            nonce = self.implicit_nonce + seq_num + ctr_bytes
            command = f"./mpc/bin/enc_public {self.party} {self.port} {self.key_share.hex()} {block.hex()} {nonce.hex()}"
            print(command)
            os.system(command)
            with open(file) as f:
                a = f.readlines()
            ctxt += bytes.fromhex(a[0])
            os.remove(file)
            ctr += 1
        ctxt = ctxt[:len(ptxt)]
        tag = self.gcmTag(ctxt, addt_data, self.implicit_nonce+seq_num)
        return ctxt, tag
       

    def gcmTag(self, ctxt: bytes, addt_data: bytes, nonce: bytes) -> bytes:
        # The additional data is never more than 128 bits in TLS, otherwise we'd need to split it  
        data = addt_data + bytes(-len(addt_data)%16)
        data += ctxt + bytes(-len(ctxt)%16)

        ctxt_blocks = [int.from_bytes(data[i * 16: (i + 1) * 16], "big") for i in range(len(data) // 16)]
        
        #ctxt_blocks = [int.from_bytes(ctxt[i:i+16], 'big') for i in range(0, len(ctxt), 16)]

        len_block = (8 * len(addt_data) << 64) | (8 * len(ctxt))

        blocks = [len_block] + ctxt_blocks[::-1]
        

        tag = 0
        for block, h in zip(blocks, self.shares):
            tag ^= gf_2_128_mul(block, h)

        # don't forget to xor with aes(k, (IV << 32) | 1 )!
        #enc = int("66e94bd4ef8a2c3b884cfa59ca342b2e", 16)
        #tag ^= enc

        ctr = (int.from_bytes(nonce, "big") << 32) | 1

        ctr_hex = (hex(ctr)[2:]).zfill(32)
        command = f"./mpc/bin/public_aes {self.party} {self.port} {self.key_share.hex()} {ctr_hex}"
        #command = f"./mpc/bin/finished_enc {self.party} {self.port} {self.key_share.hex()} {ctr_hex} 00000000000000000000000000000000"
        print(command)
        os.system(command)
        
        if self.party == ALICE:
            file = "./alice.out"
            with open(file) as f:
                a = f.readlines()

            ctr = int(a[0], 16)
            tag ^= ctr
            os.remove(file)
        elif self.party == BOB:
            os.remove("./bob.out")

        return tag.to_bytes(16, "big")

    # password must be 24 characters plus an extra \r\n at then end
    def encryptPassword(self, seq_num: bytes, pwd_share: bytes, addt_data: bytes) -> (bytes, bytes):
        pwd_blocks = [pwd_share[i:i+16] for i in range(0, len(pwd_share), 16)]
        ctr = 2
        nonce = self.implicit_nonce + seq_num + ctr.to_bytes(4,'big') # the last 4 bytes are counter for the encryption (NOT the TLS counter)
        ctxt = b''
        if self.party == ALICE:
            file = "./alice.out"
        else:
            file = "./bob.out"

        for block in pwd_blocks[:2]:
            ctr_bytes = ctr.to_bytes(4, 'big')
            nonce = self.implicit_nonce + seq_num + ctr_bytes
            command = f"./mpc/bin/enc_private {self.party} {self.port} {self.key_share.hex()} {block.hex()} {nonce.hex()}"
            print(command)
            os.system(command)
            with open(file) as f:
                a = f.readlines()
            ctxt += bytes.fromhex(a[0])
            os.remove(file)
            ctr += 1

        ctr_bytes = ctr.to_bytes(4, 'big')
        nonce = self.implicit_nonce + seq_num + ctr_bytes
        command = f"./mpc/bin/enc_public {self.party} {self.port} {self.key_share.hex()} {pwd_blocks[-1].hex()} {nonce.hex()}"
        print(command)
        os.system(command)
        with open(file) as f:
            a = f.readlines()
        ctxt += bytes.fromhex(a[0])
        os.remove(file)

        ctxt = ctxt[:len(pwd_share)]
        tag = self.gcmTag(ctxt, addt_data, self.implicit_nonce+seq_num)
        return ctxt, tag


# copied from github
def gf_2_128_mul(x, y):
    assert x < (1 << 128)
    assert y < (1 << 128)
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)  # branchless
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < 1 << 128
    return res
