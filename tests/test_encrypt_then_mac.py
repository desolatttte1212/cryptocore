import os
import pytest
from src.aead.encrypt_then_mac import EncryptThenMAC, AuthenticationError

def test_etm_roundtrip():
    key = os.urandom(32)
    pt = b"Secret message for EtM"
    aad = b"associated_data"

    etm = EncryptThenMAC(key)
    ct = etm.encrypt(pt, aad)
    pt2 = etm.decrypt(ct, aad)
    assert pt2 == pt

def test_etm_aad_tamper():
    key = os.urandom(32)
    pt = b"Secret"
    aad1 = b"correct"
    aad2 = b"wrong"

    etm = EncryptThenMAC(key)
    ct = etm.encrypt(pt, aad1)

    with pytest.raises(AuthenticationError):
        etm.decrypt(ct, aad2)

def test_etm_ciphertext_tamper():
    key = os.urandom(32)
    pt = b"Another secret"
    aad = b""

    etm = EncryptThenMAC(key)
    ct = etm.encrypt(pt, aad)

    tampered = bytearray(ct)
    if len(tampered) > 32:
        tampered[0] ^= 1
        with pytest.raises(AuthenticationError):
            etm.decrypt(bytes(tampered), aad)