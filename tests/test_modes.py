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
        self.key = b'0123456789abcdef'  # 16 bytes key
        self.test_data = b'This is a test message for AES modes!'
        self.long_data = b'X' * 100  # Data longer than one block

    def test_cbc_encrypt_decrypt(self):
        cbc = CBCMode(self.key)

        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            temp_input.write(self.test_data)
            temp_input.flush()

            try:
                # Encrypt
                ciphertext = cbc.encrypt(temp_input.name)

                # Write ciphertext to file
                cipher_file = temp_input.name + '.enc'
                write_file(cipher_file, ciphertext)

                # Decrypt without providing IV (should read from file)
                plaintext = cbc.decrypt(cipher_file)
                self.assertEqual(self.test_data, plaintext)

            finally:
                if os.path.exists(temp_input.name):
                    os.unlink(temp_input.name)
                if os.path.exists(cipher_file):
                    os.unlink(cipher_file)

    def test_cfb_encrypt_decrypt(self):
        cfb = CFBMode(self.key)

        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            temp_input.write(self.test_data)
            temp_input.flush()

            try:
                # Encrypt
                ciphertext = cfb.encrypt(temp_input.name)

                # Write ciphertext to file
                cipher_file = temp_input.name + '.enc'
                write_file(cipher_file, ciphertext)

                # Decrypt without providing IV
                plaintext = cfb.decrypt(cipher_file)
                self.assertEqual(self.test_data, plaintext)

            finally:
                if os.path.exists(temp_input.name):
                    os.unlink(temp_input.name)
                if os.path.exists(cipher_file):
                    os.unlink(cipher_file)

    def test_ofb_encrypt_decrypt(self):
        ofb = OFBMode(self.key)

        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            temp_input.write(self.test_data)
            temp_input.flush()

            try:
                # Encrypt
                ciphertext = ofb.encrypt(temp_input.name)

                # Write ciphertext to file
                cipher_file = temp_input.name + '.enc'
                write_file(cipher_file, ciphertext)

                # Decrypt without providing IV
                plaintext = ofb.decrypt(cipher_file)
                self.assertEqual(self.test_data, plaintext)

            finally:
                if os.path.exists(temp_input.name):
                    os.unlink(temp_input.name)
                if os.path.exists(cipher_file):
                    os.unlink(cipher_file)

    def test_ctr_encrypt_decrypt(self):
        ctr = CTRMode(self.key)

        with tempfile.NamedTemporaryFile(delete=False) as temp_input:
            temp_input.write(self.test_data)
            temp_input.flush()

            try:
                # Encrypt
                ciphertext = ctr.encrypt(temp_input.name)

                # Write ciphertext to file
                cipher_file = temp_input.name + '.enc'
                write_file(cipher_file, ciphertext)

                # Decrypt without providing IV
                plaintext = ctr.decrypt(cipher_file)
                self.assertEqual(self.test_data, plaintext)

            finally:
                if os.path.exists(temp_input.name):
                    os.unlink(temp_input.name)
                if os.path.exists(cipher_file):
                    os.unlink(cipher_file)

    def test_modes_with_provided_iv(self):
        """Test decryption with explicitly provided IV"""
        test_iv = b'1111111122222222'  # 16 bytes

        for mode_class in [CBCMode, CFBMode, OFBMode]:
            cipher = mode_class(self.key)

            with tempfile.NamedTemporaryFile(delete=False) as temp_input:
                temp_input.write(self.test_data)
                temp_input.flush()

                try:
                    # Encrypt
                    ciphertext = cipher.encrypt(temp_input.name)

                    # Extract IV from ciphertext
                    iv_from_file = ciphertext[:16]
                    ciphertext_only = ciphertext[16:]

                    # Write only ciphertext (without IV)
                    cipher_file = temp_input.name + '.enc'
                    write_file(cipher_file, ciphertext_only)

                    # Decrypt with provided IV
                    plaintext = cipher.decrypt(cipher_file, iv_from_file)
                    self.assertEqual(self.test_data, plaintext)

                finally:
                    if os.path.exists(temp_input.name):
                        os.unlink(temp_input.name)
                    if os.path.exists(cipher_file):
                        os.unlink(cipher_file)

    def test_partial_blocks_stream_modes(self):
        """Test that stream modes handle partial blocks correctly"""
        partial_data = b'Short'  # Less than one block

        for mode_class in [CFBMode, OFBMode, CTRMode]:
            cipher = mode_class(self.key)

            with tempfile.NamedTemporaryFile(delete=False) as temp_input:
                temp_input.write(partial_data)
                temp_input.flush()

                try:
                    # Encrypt and decrypt
                    ciphertext = cipher.encrypt(temp_input.name)
                    cipher_file = temp_input.name + '.enc'
                    write_file(cipher_file, ciphertext)

                    plaintext = cipher.decrypt(cipher_file)
                    self.assertEqual(partial_data, plaintext)
                    self.assertEqual(len(partial_data), len(plaintext))

                finally:
                    if os.path.exists(temp_input.name):
                        os.unlink(temp_input.name)
                    if os.path.exists(cipher_file):
                        os.unlink(cipher_file)


if __name__ == '__main__':
    unittest.main()