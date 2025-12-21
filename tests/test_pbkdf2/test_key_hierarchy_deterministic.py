
from src.kdf.hkdf import derive_key

def test_key_hierarchy_deterministic():
    master = b"master_key_32_bytes_long_12345678"
    context = "encryption"
    length = 32

    key1 = derive_key(master, context, length)
    key2 = derive_key(master, context, length)
    assert key1 == key2