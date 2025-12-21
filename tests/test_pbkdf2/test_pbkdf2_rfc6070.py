
from src.kdf.pbkdf2 import pbkdf2_hmac_sha256


def test_pbkdf2_nist_vector():
    password = b"password"
    salt = b"salt"
    iterations = 1
    dklen = 32
    expected = bytes.fromhex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")

    result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
    assert result == expected