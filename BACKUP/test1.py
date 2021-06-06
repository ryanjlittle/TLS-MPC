from mpc import MPC

password_share = bytes(32) + b'\r\n'
#key_share = bytes.fromhex("04a92ed938163775346f98a0979aa3ba")
key_share = b'\x00'*16
iv = bytes.fromhex("20a78d2d")
seq_num = b'\x00\x00\x00\x00\x00\x00\x00\x01'

ptxt = bytes.fromhex("474554202f20485454502f312e310d0a486f73743a207777772e77696b6970656469612e6f72670d0a4163636570743a202a2f2a0d0a0d0a")
email = b'Subject: Test\r\nFrom: <mpcemailtest@gmail.com>\r\nTo: <ryan.jay.little@gmail.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\n\r\nHi!\r\n.\r\n'
email = bytes(129)
ptxt=bytes(56)
addt_data = bytes.fromhex("00000000000000011703030038")
mpc = MPC(1)
mpc.setKeys(iv, key_share)
mpc.precomputeGCM()

#rec_hash = bytes.fromhex("00112233445566778899aabb")
#ptxt = b'\x14\x00\x00\x0c' + rec_hash
#addt_data = seq_num + b'\x16\x03\x03\x00\x10' 

ctxt, tag = mpc.encryptPubPtxt(seq_num, email[:129], addt_data)
#ctxt2, tag = mpc.encryptClientFinished(seq_num, rec_hash)

print((ctxt+tag).hex())
#print("1, client fin:  ", (ctxt2+tag).hex())
