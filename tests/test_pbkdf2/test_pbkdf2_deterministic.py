# tests/sprint7/test_pbkdf2_deterministic.py
from src.kdf.pbkdf2 import pbkdf2_hmac_sha256

def test_pbkdf2_deterministic():
    """TEST-2: Same inputs → same output"""
    password = b"test_password"
    salt = b"fixed_salt_12345"
    iterations = 10000
    dklen = 32

    key1 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
    key2 = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
    assert key1 == key2