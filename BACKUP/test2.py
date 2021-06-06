from mpc import MPC
import base64

password_share = base64.b64encode(b't^QV6p8dX25J67DC#x@2bBeY') + b'\r\n'
key_share = bytes.fromhex("2d842a17cdbf5e12aa75f1be7f27d65d")
#key_share = b'\xaa'*16
iv = bytes.fromhex("20a78d2d")
seq_num = b'\x00\x00\x00\x00\x00\x00\x00\x01'
#record_hash = b'\x00'*12
ptxt = bytes.fromhex("474554202f20485454502f312e310d0a486f73743a207777772e77696b6970656469612e6f72670d0a4163636570743a202a2f2a0d0a0d0a")
email = b'Subject: Test\r\nFrom: <mpcemailtest@gmail.com>\r\nTo: <ryan.jay.little@gmail.com>\r\nContent-Type: text/plain; charset="UTF-8"\r\n\r\nHi!\r\n.\r\n'
email = bytes(129)
print(len(email))
ptxt=bytes(56)
addt_data = bytes.fromhex("00000000000000011703030038")
mpc = MPC(2)
mpc.setKeys(iv, key_share)
mpc.precomputeGCM()

#rec_hash = bytes.fromhex("00112233445566778899aabb")
#ptxt = b'\x14\x00\x00\x0c' + rec_hash
#addt_data = seq_num + b'\x16\x03\x03\x00\x10' 

#ctxt, tag = mpc.encryptPubPtxt(seq_num, ptxt, addt_data)
ctxt, tag = mpc.encryptPubPtxt(seq_num, email[:129], addt_data)
#ctxt2, tag = mpc.encryptClientFinished(seq_num, rec_hash)

print((ctxt+tag).hex())
#print("2, client fin:  ", (ctxt2+tag).hex())

# expected is b'\xea\xe6\x19~\xe0\x0f> \x9b~\xd3W\xb6\xee&\x95\xbd\x02\ntW7N\x83\x87\xc2\x85\x83\r\xf6\x80~w\xb2V\x9f,a!\xd5I;U\x88\xc3T\xceA-g\r\xfemcr\xb8\xd9\x84[l\x925vi\xc4\x8e?\xf4fL\x06%'
