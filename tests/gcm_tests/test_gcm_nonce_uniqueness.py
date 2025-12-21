import os
from src.modes.gcm import gcm_encrypt

def test_gcm_nonce_uniqueness():
    key = os.urandom(16)
    plaintext = b"x"
    nonces = set()
    for _ in range(1000):
        full_output = gcm_encrypt(key, plaintext)
        nonce = full_output[:12]
        assert nonce not in nonces, "Duplicate nonce detected!"
        nonces.add(nonce)
    assert len(nonces) == 1000