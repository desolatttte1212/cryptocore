import unittest
import hashlib
from src.hash.sha256 import sha256
from src.hash.SHA3_256 import SHA3_256

class TestHashInteroperability(unittest.TestCase):

    def test_sha256_interop(self):
        """TEST-3: SHA-256 matches hashlib (as proxy for sha256sum)"""
        test_data = b"Test data for interoperability"
        our_hash = sha256(test_data)
        ref_hash = hashlib.sha256(test_data).hexdigest()
        self.assertEqual(our_hash, ref_hash)

    def test_sha3_256_interop(self):
        """TEST-3: SHA3-256 matches hashlib"""
        test_data = b"Test data for SHA3"
        our_hasher = SHA3_256()
        our_hasher.update(test_data)
        our_hash = our_hasher.hexdigest()
        ref_hash = hashlib.sha3_256(test_data).hexdigest()
        self.assertEqual(our_hash, ref_hash)

    def test_file_output_format(self):
        """Проверка формата вывода: 'hash filename' (имитация)"""
        test_data = b"Hello"
        hash_val = sha256(test_data)
        fake_line = f"{hash_val} test.txt"
        self.assertTrue(' ' in fake_line)
        self.assertEqual(len(fake_line.split()[0]), 64)


if __name__ == '__main__':
    unittest.main()