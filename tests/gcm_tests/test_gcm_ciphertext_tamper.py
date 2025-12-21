import os
import pytest
from src.modes.gcm import gcm_encrypt, gcm_decrypt, AuthenticationError


def test_gcm_ciphertext_tamper():
    key = os.urandom(16)
    plaintext = b"Another secret"
    aad = b""

    ciphertext = gcm_encrypt(key, plaintext, aad)

    # Flip one bit in ciphertext (not in nonce or tag)
    tampered = bytearray(ciphertext)
    if len(tampered) > 28:  # nonce(12) + at least 1 byte + tag(16)
        tampered[12] ^= 0x01  # flip first byte of ciphertext
        with pytest.raises(AuthenticationError):
            gcm_decrypt(key, bytes(tampered), aad)