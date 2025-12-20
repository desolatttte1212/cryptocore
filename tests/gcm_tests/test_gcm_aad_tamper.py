import os
import pytest
from src.modes.gcm import gcm_encrypt, gcm_decrypt, AuthenticationError

def test_gcm_aad_tamper():
    key = os.urandom(16)
    plaintext = b"Secret message"
    aad_correct = b"correct_aad"
    aad_wrong = b"wrong_aad"

    ciphertext = gcm_encrypt(key, plaintext, aad_correct)

    with pytest.raises(AuthenticationError):
        gcm_decrypt(key, ciphertext, aad_wrong)