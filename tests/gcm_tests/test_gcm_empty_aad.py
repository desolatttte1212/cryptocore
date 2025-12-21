import os
from src.modes.gcm import gcm_encrypt, gcm_decrypt


def test_gcm_empty_aad():
    key = os.urandom(16)
    plaintext = b"Test with empty AAD"

    ciphertext1 = gcm_encrypt(key, plaintext, b"")
    ciphertext2 = gcm_encrypt(key, plaintext, aad=b"")
    ciphertext3 = gcm_encrypt(key, plaintext)

    assert gcm_decrypt(key, ciphertext1, b"") == plaintext
    assert gcm_decrypt(key, ciphertext2, aad=b"") == plaintext
    assert gcm_decrypt(key, ciphertext3) == plaintext