import unittest
import os
import tempfile
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.modes.ecb import ECBMode
from src.file_io import read_file, write_file


class TestCryptoCore(unittest.TestCase):
    def setUp(self):
        self.key = b'0123456789abcdef'
        self.ecb = ECBMode(self.key)
        self.test_data = b'This is a test message for AES-ECB mode!'

    def test_pad_unpad(self):
        padded = self.ecb.pad(self.test_data)
        unpadded = self.ecb.unpad(padded)
        self.assertEqual(self.test_data, unpadded)

    def test_encrypt_decrypt(self):
        ciphertext = self.ecb.encrypt(self.test_data)
        plaintext = self.ecb.decrypt(ciphertext)
        self.assertEqual(self.test_data, plaintext)

    def test_file_operations(self):
        temp_input = tempfile.NamedTemporaryFile(delete=False, mode='wb')
        temp_input_name = temp_input.name
        temp_input.write(self.test_data)
        temp_input.close()

        temp_output = None
        try:
            data_read = read_file(temp_input_name)
            self.assertEqual(self.test_data, data_read)

            temp_output = temp_input_name + '.out'
            write_file(temp_output, data_read)
            data_written = read_file(temp_output)
            self.assertEqual(self.test_data, data_written)

        finally:
            if os.path.exists(temp_input_name):
                os.unlink(temp_input_name)
            if temp_output and os.path.exists(temp_output):
                os.unlink(temp_output)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            ECBMode(b'shortkey')

    def test_invalid_ciphertext(self):
        with self.assertRaises(ValueError):
            self.ecb.decrypt(b'short')

    def test_ecb_consistency(self):
        ciphertext1 = self.ecb.encrypt(self.test_data)
        ciphertext2 = self.ecb.encrypt(self.test_data)
        self.assertEqual(ciphertext1, ciphertext2)


if __name__ == '__main__':
    unittest.main()