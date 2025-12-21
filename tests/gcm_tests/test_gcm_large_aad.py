import os
from src.modes.gcm import gcm_encrypt, gcm_decrypt


def test_gcm_large_aad():
    key = os.urandom(16)
    plaintext = b"Secret message for large AAD test"

    aad_size = 50 * 1024 * 1024
    aad = b"A" * aad_size

    ciphertext = gcm_encrypt(key, plaintext, aad)

    decrypted = gcm_decrypt(key, ciphertext, aad)
    assert decrypted == plaintext

    wrong_aad = b"B" * aad_size
    try:
        gcm_decrypt(key, ciphertext, wrong_aad)
        assert False, "Decryption should fail with wrong AAD"
    except Exception:
        pass