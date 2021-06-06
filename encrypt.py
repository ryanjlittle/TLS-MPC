from aes import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from aes_gcm import AES_GCM
import base64

password_share = base64.b64encode(b't^QV6p8dX25J67DC#x@2bBeY') + b'\r\n'
key = bytes.fromhex("2d842a17cdbf5e12aa75f1be7f27d65d")
seq_num = b'\x00\x00\x00\x00\x00\x00\x00\x01'
ptxt = bytes.fromhex("474554202f20485454502f312e310d0a486f73743a207777772e77696b6970656469612e6f72670d0a4163636570743a202a2f2a0d0a0d0a")
email = b'Subject: Test\r\nFrom: <mpcemailtest@gmail.com>\r\nTo: <ryan.jay.little@gmail.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\n\r\nHi!\r\n.\r\n'
email = bytes(129)
ptxt=bytes(56)
iv = bytes.fromhex("20a78d2d")
nonce = iv + seq_num
addt_data = bytes.fromhex("00000000000000011703030038")

#rec_hash = bytes.fromhex("00112233445566778899aabb")
#ptxt = b'\x14\x00\x00\x0c' + rec_hash
#addt_data = seq_num + b'\x16\x03\x03\x00\x10' 

"""
one = b'\x00'*15 + b'\x01'
two = b'\x00'*15 + b'\x02'

ctr = (int.from_bytes(nonce, "big") << 32) | 1
ctr_hex = ctr.to_bytes(16, "big")

#print(ctr_hex.hex())

aes = AES(key)
#ciphertext = aes.encrypt_block(ctr_hex)
ciphertext = aes.encrypt_block(bytes(16))

#print(ciphertext.hex())
"""
aesgcm = AESGCM(key)

ciphertext = aesgcm.encrypt(nonce, email[:129], addt_data)
print(ciphertext.hex())

"""
print("====== Expected: ======")
print("69e18145d856d695de2a2ef144bb77a9")
print("978d1a724a119d578eb82fbccb685243")
"""

"""
aes = AES_GCM(int.from_bytes(key, "big"))
ct, tag = aes.encrypt(int.from_bytes(nonce, "big"), pt, addt_data)
print(ct.hex())
print(hex(tag)[2:])
"""
