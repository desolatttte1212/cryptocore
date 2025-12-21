
from src.kdf.pbkdf2 import pbkdf2_hmac_sha256

def test_pbkdf2_various_lengths():
    password = b"length_test"
    salt = b"salt"
    iterations = 1000

    for length in [1, 16, 32, 64, 100]:
        key = pbkdf2_hmac_sha256(password, salt, iterations, length)
        assert len(key) == length