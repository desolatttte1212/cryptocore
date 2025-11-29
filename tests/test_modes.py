import unittest
import os
import tempfile
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.modes.cbc import CBCMode
from src.modes.cfb import CFBMode
from src.modes.ofb import OFBMode
from src.modes.ctr import CTRMode
from src.file_io import write_file, read_file


class TestModes(unittest.TestCase):
    def setUp(self):
        self.key = b'0123456789abcdef' 
        self.test_data = b'This is a test message for AES modes! Exactly 48 bytes.'
        self.long_data = b'X' * 100

    def _safe_cleanup(self, *file_paths):
        for file_path in file_paths:
            if file_path and os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except (PermissionError, OSError):
                    pass

    def test_cbc_encrypt_decrypt(self):
        cbc = CBCMode(self.key)

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
            temp_input.write(self.test_data)
            temp_input_name = temp_input.name

        cipher_file = temp_input_name + '.enc'
        decrypted_file = temp_input_name + '.dec'

        try:
            ciphertext = cbc.encrypt(temp_input_name)
            write_file(cipher_file, ciphertext)

            plaintext = cbc.decrypt(cipher_file)
            self.assertEqual(self.test_data, plaintext)

        finally:
            self._safe_cleanup(temp_input_name, cipher_file, decrypted_file)

    def test_modes_with_provided_iv(self):
        """Test decryption with explicitly provided IV"""
        test_iv = b'11111111222222223333333344444444'

        for mode_class in [CBCMode, CFBMode, OFBMode]:
            cipher = mode_class(self.key)

            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
                temp_input.write(self.test_data)
                temp_input_name = temp_input.name

            cipher_file = temp_input_name + '.enc'
            ciphertext_only_file = temp_input_name + '.cipher_only'

            try:
                full_ciphertext = cipher.encrypt(temp_input_name)
                write_file(cipher_file, full_ciphertext)

                iv_from_file = full_ciphertext[:16]
                ciphertext_only = full_ciphertext[16:]

                write_file(ciphertext_only_file, ciphertext_only)

                plaintext = cipher.decrypt(ciphertext_only_file, iv_from_file)
                self.assertEqual(self.test_data, plaintext)

            finally:
                self._safe_cleanup(temp_input_name, cipher_file, ciphertext_only_file)

    def test_different_data_sizes(self):
        test_cases = [
            b'A',
            b'Hello World!',
            b'X' * 15,
            b'X' * 16,
            b'X' * 17,
            b'X' * 100,
        ]

        for mode_class in [CBCMode, CFBMode, OFBMode, CTRMode]:
            cipher = mode_class(self.key)

            for test_data in test_cases:
                with self.subTest(mode=mode_class.__name__, length=len(test_data)):
                    with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
                        temp_input.write(test_data)
                        temp_input_name = temp_input.name

                    cipher_file = temp_input_name + '.enc'

                    try:
                        ciphertext = cipher.encrypt(temp_input_name)
                        write_file(cipher_file, ciphertext)

                        plaintext = cipher.decrypt(cipher_file)
                        self.assertEqual(test_data, plaintext,
                                         f"Failed for mode {mode_class.__name__} with data length {len(test_data)}")

                    finally:
                        self._safe_cleanup(temp_input_name, cipher_file)

    def test_cfb_encrypt_decrypt(self):
        cfb = CFBMode(self.key)

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
            temp_input.write(self.test_data)
            temp_input_name = temp_input.name

        cipher_file = temp_input_name + '.enc'
        decrypted_file = temp_input_name + '.dec'

        try:
            ciphertext = cfb.encrypt(temp_input_name)
            write_file(cipher_file, ciphertext)

            plaintext = cfb.decrypt(cipher_file)
            self.assertEqual(self.test_data, plaintext)

        finally:
            self._safe_cleanup(temp_input_name, cipher_file, decrypted_file)

    def test_ofb_encrypt_decrypt(self):
        ofb = OFBMode(self.key)

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
            temp_input.write(self.test_data)
            temp_input_name = temp_input.name

        cipher_file = temp_input_name + '.enc'
        decrypted_file = temp_input_name + '.dec'

        try:
            ciphertext = ofb.encrypt(temp_input_name)
            write_file(cipher_file, ciphertext)

            plaintext = ofb.decrypt(cipher_file)
            self.assertEqual(self.test_data, plaintext)

        finally:
            self._safe_cleanup(temp_input_name, cipher_file, decrypted_file)

    def test_ctr_encrypt_decrypt(self):
        ctr = CTRMode(self.key)

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
            temp_input.write(self.test_data)
            temp_input_name = temp_input.name

        cipher_file = temp_input_name + '.enc'
        decrypted_file = temp_input_name + '.dec'

        try:
            ciphertext = ctr.encrypt(temp_input_name)
            write_file(cipher_file, ciphertext)

            plaintext = ctr.decrypt(cipher_file)
            self.assertEqual(self.test_data, plaintext)

        finally:
            self._safe_cleanup(temp_input_name, cipher_file, decrypted_file)

    def test_partial_blocks_stream_modes(self):
        partial_data = b'Short'

        for mode_class in [CFBMode, OFBMode, CTRMode]:
            cipher = mode_class(self.key)

            with tempfile.NamedTemporaryFile(delete=False, mode='wb') as temp_input:
                temp_input.write(partial_data)
                temp_input_name = temp_input.name

            cipher_file = temp_input_name + '.enc'
            decrypted_file = temp_input_name + '.dec'

            try:
                ciphertext = cipher.encrypt(temp_input_name)
                write_file(cipher_file, ciphertext)

                plaintext = cipher.decrypt(cipher_file)
                self.assertEqual(partial_data, plaintext)
                self.assertEqual(len(partial_data), len(plaintext))

            finally:
                self._safe_cleanup(temp_input_name, cipher_file, decrypted_file)


if __name__ == '__main__':
    unittest.main()