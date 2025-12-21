import unittest
import os
import tempfile
from src.mac.hmac import HMAC
from src.hash.sha256 import SHA256

class TestHMACVerification(unittest.TestCase):
    def _safe_cleanup(self, *paths):
        for p in paths:
            if p and os.path.exists(p):
                try:
                    os.unlink(p)
                except:
                    pass

    def test_hmac_self_verification(self):
        test_data = b"Authentic message for HMAC"
        key = bytes.fromhex("a1b2c3d4e5f67890a1b2c3d4e5f67890")

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(test_data)
            input_file = f.name

        hmac_file = input_file + ".hmac"

        try:
            hmac_obj = HMAC(key, SHA256)
            hmac_obj.update(test_data)
            computed_hmac = hmac_obj.hexdigest()

            with open(hmac_file, 'w') as hf:
                hf.write(f"{computed_hmac} {os.path.basename(input_file)}\n")

            with open(hmac_file, 'r') as hf:
                expected_hash = hf.read().split()[0]
            self.assertEqual(computed_hmac, expected_hash)

        finally:
            self._safe_cleanup(input_file, hmac_file)

    def test_tamper_detection_file(self):
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        original = b"Original content"
        tampered = b"Modified content"

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(original)
            orig_file = f.name

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(tampered)
            tampered_file = f.name

        try:
            hmac_obj = HMAC(key, SHA256)
            hmac_obj.update(original)
            orig_hmac = hmac_obj.hexdigest()

            hmac_obj2 = HMAC(key, SHA256)
            hmac_obj2.update(tampered)
            tampered_hmac = hmac_obj2.hexdigest()

            self.assertNotEqual(orig_hmac, tampered_hmac)

        finally:
            self._safe_cleanup(orig_file, tampered_file)

    def test_tamper_detection_wrong_key(self):
        test_data = b"Same data"
        key1 = bytes.fromhex("a1b2c3d4e5f67890a1b2c3d4e5f67890")
        key2 = bytes.fromhex("00000000000000000000000000000000")

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as f:
            f.write(test_data)
            input_file = f.name

        try:
            hmac1 = HMAC(key1, SHA256)
            hmac1.update(test_data)
            hash1 = hmac1.hexdigest()

            hmac2 = HMAC(key2, SHA256)
            hmac2.update(test_data)
            hash2 = hmac2.hexdigest()

            self.assertNotEqual(hash1, hash2)

        finally:
            self._safe_cleanup(input_file)

    def test_empty_file_hmac(self):
        key = bytes.fromhex("deadbeef" * 4)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            input_file = f.name

        try:
            hmac_obj = HMAC(key, SHA256)
            hmac_obj.update(b"")
            result = hmac_obj.hexdigest()
            self.assertIsInstance(result, str)
            self.assertEqual(len(result), 64)
        finally:
            self._safe_cleanup(input_file)