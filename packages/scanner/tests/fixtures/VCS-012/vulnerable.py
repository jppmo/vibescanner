import hashlib
from Crypto.Cipher import AES, DES

# MD5 — broken
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

# SHA1 — deprecated
def fingerprint(data):
    return hashlib.sha1(data).hexdigest()

# DES — 56-bit key, broken
cipher = DES.new(key, DES.MODE_CBC)

# AES-ECB — does not hide patterns
ecb = AES.new(key, AES.MODE_ECB)
