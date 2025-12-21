
from src.kdf.hkdf import derive_key

def test_key_hierarchy_context_separation():
    master = b"master_key_32_bytes_long_12345678"
    length = 32

    key1 = derive_key(master, "encryption", length)
    key2 = derive_key(master, "authentication", length)
    key3 = derive_key(master, "encryption", length)

    assert key1 != key2
    assert key1 == key3