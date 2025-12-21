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
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
            temp_input.write(self.test_data)
            temp_input_name = temp_input.name

        cipher_file = temp_input_name + '.enc'
        decrypted_file = temp_input_name + '.dec'

        try:
            ciphertext = self.ecb.encrypt(temp_input_name)
            write_file(cipher_file, ciphertext)

            plaintext = self.ecb.decrypt(cipher_file)

            self.assertEqual(self.test_data, plaintext)

        finally:
            for file_path in [temp_input_name, cipher_file, decrypted_file]:
                if os.path.exists(file_path):
                    try:
                        os.unlink(file_path)
                    except PermissionError:
                        pass

    def test_file_operations(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
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
            for file_path in [temp_input_name, temp_output]:
                if file_path and os.path.exists(file_path):
                    try:
                        os.unlink(file_path)
                    except PermissionError:
                        pass

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            ECBMode(b'shortkey')

    def test_invalid_ciphertext(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
            temp_input.write(b'short')
            temp_input_name = temp_input.name

        try:
            with self.assertRaises(ValueError):
                self.ecb.decrypt(temp_input_name)
        finally:
            if os.path.exists(temp_input_name):
                try:
                    os.unlink(temp_input_name)
                except PermissionError:
                    pass

    def test_ecb_consistency(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
            temp_input.write(self.test_data)
            temp_input_name = temp_input.name

        cipher_file1 = temp_input_name + '.enc1'
        cipher_file2 = temp_input_name + '.enc2'

        try:
            ciphertext1 = self.ecb.encrypt(temp_input_name)
            write_file(cipher_file1, ciphertext1)

            ciphertext2 = self.ecb.encrypt(temp_input_name)
            write_file(cipher_file2, ciphertext2)

            self.assertEqual(ciphertext1, ciphertext2)

        finally:
            # Cleanup
            for file_path in [temp_input_name, cipher_file1, cipher_file2]:
                if file_path and os.path.exists(file_path):
                    try:
                        os.unlink(file_path)
                    except PermissionError:
                        pass


if __name__ == '__main__':
    unittest.main()