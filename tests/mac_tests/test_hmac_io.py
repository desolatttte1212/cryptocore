import unittest
import os
import tempfile
from src.mac.hmac import HMAC
from src.hash.sha256 import SHA256

class TestHMACKeySizesAndLargeFiles(unittest.TestCase):
    def _safe_cleanup(self, *paths):
        for p in paths:
            if p and os.path.exists(p):
                try:
                    os.unlink(p)
                except:
                    pass

    def test_short_key(self):
        key = bytes.fromhex("a1b2")
        data = b"test"
        hmac = HMAC(key, SHA256)
        result = hmac.hexdigest()
        self.assertEqual(len(result), 64)

    def test_exact_block_size_key(self):
        key = bytes([i % 256 for i in range(64)])
        data = b"test"
        hmac = HMAC(key, SHA256)
        result = hmac.hexdigest()
        self.assertEqual(len(result), 64)

    def test_long_key(self):
        key = b"x" * 100
        data = b"test"
        hmac = HMAC(key, SHA256)
        result = hmac.hexdigest()
        self.assertEqual(len(result), 64)

    def test_large_file(self):
        key = bytes.fromhex("a1b2c3d4" * 4)
        size_mb = 1
        data = os.urandom(size_mb * 1024 * 1024)

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            input_file = f.name

        try:
            hmac_obj = HMAC(key, SHA256)
            hmac_obj.update(data)
            result = hmac_obj.hexdigest()
            self.assertEqual(len(result), 64)
        finally:
            self._safe_cleanup(input_file)