
import os
import tempfile
from src.modes.gcm import gcm_encrypt, gcm_decrypt

def test_gcm_roundtrip():
    key = os.urandom(16)
    plaintext = b"Secret message for GCM roundtrip test"
    aad = b"associated_data_123"

    ciphertext = gcm_encrypt(key, plaintext, aad)
    decrypted = gcm_decrypt(key, ciphertext, aad)

    assert decrypted == plaintext