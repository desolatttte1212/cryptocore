import unittest
import os
import hashlib
from src.hash.sha256 import SHA256, sha256

class TestLargeFileHashing(unittest.TestCase):

    def test_large_file_chunking(self):
        """TEST-4: Hash large file correctly (simulated with 1 MB)"""
        size_mb = 1
        data = os.urandom(size_mb * 1024 * 1024)

        # Эталонный хеш
        expected = hashlib.sha256(data).hexdigest()

        # Наш хеш через функцию
        result = sha256(data)

        self.assertEqual(result, expected)

    def test_file_larger_than_buffer(self):
        """Файл больше, чем внутренний буфер (64 байта)"""
        data = b"x" * 1000
        expected = hashlib.sha256(data).hexdigest()
        result = sha256(data)
        self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main()