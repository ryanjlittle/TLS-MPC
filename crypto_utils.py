from cryptography.hazmat.primitives import hashes, hmac
from secrets import token_bytes
from utils import bytexor

""" https://tools.ietf.org/html/rfc5246#section-5 """
def p_hash(secret: bytes, seed: bytes, num_bytes: int) -> bytes:
    hmac_ = hmac.HMAC(secret, hashes.SHA256())
    A = seed
    output = b''
    while len(output) < num_bytes:
        hmac_A = hmac_.copy()
        hmac_P = hmac_.copy()
        hmac_A.update(A)
        A = hmac_A.finalize()
        hmac_P.update(A + seed)
        output += hmac_P.finalize()
    return output[:num_bytes]


""" https://tools.ietf.org/html/rfc5246#section-5 """
def PRF(secret: bytes, label: bytes, seed: bytes, num_bytes: int) -> bytes:
    return p_hash(secret, label + seed, num_bytes)

def randomBytes(numBytes: int) -> bytes:
    return token_bytes(numBytes)

# This exists because I want to hash the records of the handshake in
# tls_session, but I don't want to bring in any crypto imports in the main
# files. Might want to do some refactoring 
def sha256(data: bytes) -> bytes:
    hash_ = hashes.Hash(hashes.SHA256())
    hash_.update(data)
    return hash_.finalize()


def hmac_mine(key: bytes, message: bytes) -> bytes:
    blkwid = 64
    key += bytes(-len(key)%blkwid) # pad key
    print(key, len(key))
    opad = b'\x5c' * blkwid
    ipad = b'\x36' * blkwid
    outer = bytexor(key, opad)
    inner = bytexor(key, ipad)
    return sha256(outer + sha256(inner + message))

def hmac_real(key: bytes, message: bytes) -> bytes:
    hmacc = hmac.HMAC(key, hashes.SHA256())
    hmacc.update(message)
    return hmacc.finalize()
