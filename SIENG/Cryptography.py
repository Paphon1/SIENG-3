from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os, struct

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=200_000)
    return kdf.derive(password.encode())

def encrypt(message: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, message, None)
    # payload = salt(16) + nonce(12) + ciphertext(+tag)
    return salt + nonce + ct

def decrypt(blob: bytes, password: str) -> bytes:
    salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
    key = derive_key(password, salt)
    return AESGCM(key).decrypt(nonce, ct, None)