import unittest
import os
import tempfile
import subprocess

class TestInteroperability(unittest.TestCase):

    def _safe_cleanup(self, *file_paths):
        for file_path in file_paths:
            if file_path and os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except (PermissionError, OSError):
                    pass

    def test_interoperability_cbc(self):
        test_data = b"Test data for interoperability check - AES-CBC"

        fixed_key_hex = "0123456789abcdef0123456789abcdef"

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as input_file:
            input_file.write(test_data)
            input_file_name = input_file.name

        encrypted_file = input_file_name + '.enc'
        decrypted_file = input_file_name + '.dec'

        try:
            result = subprocess.run([
                'cryptocore', '--algorithm', 'aes', '--mode', 'cbc',
                '--encrypt', '--key', fixed_key_hex,
                '--input', input_file_name, '--output', encrypted_file
            ], capture_output=True, text=True, timeout=30)

            self.assertEqual(result.returncode, 0, f"Encryption failed: {result.stderr}")

            result = subprocess.run([
                'cryptocore', '--algorithm', 'aes', '--mode', 'cbc',
                '--decrypt', '--key', fixed_key_hex,
                '--input', encrypted_file, '--output', decrypted_file
            ], capture_output=True, text=True, timeout=30)

            self.assertEqual(result.returncode, 0, f"Decryption failed: {result.stderr}")

            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()

            self.assertEqual(decrypted_data, test_data)

        finally:
            self._safe_cleanup(input_file_name, encrypted_file, decrypted_file)

    def test_interoperability_ctr(self):
        test_data = b"CTR mode interoperability test"

        fixed_key_hex = "0123456789abcdef0123456789abcdef"

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as input_file:
            input_file.write(test_data)
            input_file_name = input_file.name

        encrypted_file = input_file_name + '.enc'
        decrypted_file = input_file_name + '.dec'

        try:
            result = subprocess.run([
                'cryptocore', '--algorithm', 'aes', '--mode', 'ctr',
                '--encrypt', '--key', fixed_key_hex,
                '--input', input_file_name, '--output', encrypted_file
            ], capture_output=True, text=True, timeout=30)

            self.assertEqual(result.returncode, 0)

            result = subprocess.run([
                'cryptocore', '--algorithm', 'aes', '--mode', 'ctr',
                '--decrypt', '--key', fixed_key_hex,
                '--input', encrypted_file, '--output', decrypted_file
            ], capture_output=True, text=True, timeout=30)

            self.assertEqual(result.returncode, 0)

            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()

            self.assertEqual(decrypted_data, test_data)

        finally:
            self._safe_cleanup(input_file_name, encrypted_file, decrypted_file)

if __name__ == '__main__':
    unittest.main()