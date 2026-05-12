import hashlib
from Crypto.Cipher import AES

def hash_password(pw):
    # bcrypt is preferred, but sha256 is at least not broken
    return hashlib.sha256(pw.encode()).hexdigest()

def fingerprint(data):
    return hashlib.sha3_256(data).hexdigest()

# AES-GCM — authenticated, safe
cipher = AES.new(key, AES.MODE_GCM, nonce)
