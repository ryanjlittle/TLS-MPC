from mpc import MPC, gf_2_128_mul
from utils import hexdump, bytexor, byteReverse

alice = MPC(1)
bob = MPC(2)

with open("./mpc/alice_gcm.out") as f:
    a = f.readlines()
alice.shares = [byteReverse(int(i, 16)) for i in a]

with open("./mpc/bob_gcm.out") as f:
    a = f.readlines()
bob.shares = [byteReverse(int(i, 16)) for i in a]

real_shares = [i^j for i,j in zip(alice.shares, bob.shares)]

print("REAL:")
for i in real_shares:
    print(hex(i))


ctxt = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
addt = bytes(16)

len_aad = len(addt)
len_txt = len(ctxt)

# padding
if 0 == len_aad % 16:
    data = addt
else:
    data = aad + b'\x00' * (16 - len_aad % 16)
    
if 0 == len_txt % 16:
    data += ctxt
else:
    data += ctxt + b'\x00' * (16 - len_txt % 16)

print(data)

tag = 0
len_block = ((8 * len_aad) << 64) | (8 * len_txt)
#ctxt_blocks = [bytes_to_long(data[i * 16: (i + 1) * 16]) for i in range(len(data) // 16)]
ctxt_blocks = [int.from_bytes(data[i * 16: (i + 1) * 16], "big") for i in range(len(data) // 16)]
blocks = [len_block] + ctxt_blocks[::-1]

for i, block in enumerate(blocks):
    print("BLOCK: ", block)
    tag ^= gf_2_128_mul(block, real_shares[i])

ctr_enc = int("58e2fccefa7e3061367f1d57a4e7455a", 16)
ghash = tag ^ ctr_enc

print("TAG")
print(hex(ghash))

ctr_enc = bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")

alice_tag = alice.gcm(addt, ctxt)
bob_tag = bob.gcm(addt, ctxt)
print(hexdump(bytexor(bytexor(alice_tag, bob_tag), ctr_enc)))


"""

print("COMPUTED:")
h = real_shares[0]
print(hex(h))
k = h
for i in range(5):
    k = gf_2_128_mul(k, h)
    print(hex(k))

#ctxt = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")
ctxt = bytes(16)
ctr_enc = bytes.fromhex("6697d22bf75134dc11325f9a532cd474")

addt_data = bytes(16)
alice_tag = alice.gcm(addt_data, ctxt)
bob_tag = bob.gcm(addt_data, ctxt)


print(hexdump(bytexor(bytexor(alice_tag, bob_tag), ctr_enc)))
"""
