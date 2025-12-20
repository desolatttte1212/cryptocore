
from ..modes.ctr import CTRMode
import hmac
import hashlib

class AuthenticationError(Exception):
    pass

class EncryptThenMAC:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Master key must be 32 bytes")
        self.enc_key = key[:16]
        self.mac_key = key[16:]

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        ciphertext = CTRMode.ctr_encrypt_bytes(self.enc_key, plaintext)
        tag = hmac.new(self.mac_key, ciphertext + aad, hashlib.sha256).digest()
        return ciphertext + tag

    def decrypt(self, encrypted_data: bytes, aad: bytes = b"") -> bytes:
        if len(encrypted_data) < 32:
            raise ValueError("Data too short")
        ciphertext = encrypted_data[:-32]
        tag_received = encrypted_data[-32:]
        tag_computed = hmac.new(self.mac_key, ciphertext + aad, hashlib.sha256).digest()
        if not hmac.compare_digest(tag_computed, tag_received):
            raise AuthenticationError("MAC verification failed")
        return CTRMode.ctr_decrypt_bytes(self.enc_key, ciphertext)