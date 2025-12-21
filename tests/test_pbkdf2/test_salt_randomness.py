
import os
from src.kdf.pbkdf2 import pbkdf2_hmac_sha256


def test_salt_randomness():
    salts = set()
    password = b"test"
    iterations = 1
    dklen = 16

    for _ in range(100):
        salt = os.urandom(16)

        key = pbkdf2_hmac_sha256(password, salt, iterations, dklen)

        salt_hex = salt.hex()

        assert salt_hex not in salts, f"Duplicate salt: {salt_hex}"
        salts.add(salt_hex)

    assert len(salts) == 100