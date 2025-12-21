import unittest
import os
import tempfile
import subprocess

class TestKeyGeneration(unittest.TestCase):

    def _safe_cleanup(self, *file_paths):
        for file_path in file_paths:
            if file_path and os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except (PermissionError, OSError):
                    pass

    def test_encryption_with_auto_key_generation(self):
        test_data = b"Test data for automatic key generation"

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as input_file:
            input_file.write(test_data)
            input_file_name = input_file.name

        output_file = input_file_name + '.enc'
        decrypted_file = input_file_name + '.dec'

        try:
            result = subprocess.run([
                'cryptocore', 'crypto',
                '--algorithm', 'aes', '--mode', 'cbc',
                '--encrypt', '--input', input_file_name, '--output', output_file
            ], capture_output=True, text=True, timeout=30)

            self.assertEqual(result.returncode, 0, f"Encryption failed: {result.stderr}")

            key_line = [line for line in result.stdout.split('\n') if 'Generated random key:' in line]
            self.assertTrue(key_line, "Key generation message not found")
            key_hex = key_line[0].split(': ')[1].strip()
            self.assertEqual(len(key_hex), 32)

            result = subprocess.run([
                'cryptocore', 'crypto',
                '--algorithm', 'aes', '--mode', 'cbc',
                '--decrypt', '--key', key_hex,
                '--input', output_file, '--output', decrypted_file
            ], capture_output=True, text=True, timeout=30)

            self.assertEqual(result.returncode, 0, f"Decryption failed: {result.stderr}")

            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()
            self.assertEqual(decrypted_data, test_data)

        finally:
            self._safe_cleanup(input_file_name, output_file, decrypted_file)

    def test_decryption_requires_key(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as input_file:
            input_file.write(b"test data")
            input_file_name = input_file.name

        try:
            result = subprocess.run([
                'cryptocore', 'crypto',
                '--algorithm', 'aes', '--mode', 'cbc',
                '--decrypt', '--input', input_file_name
            ], capture_output=True, text=True, timeout=10)

            self.assertNotEqual(result.returncode, 0)
            # Не проверяем stderr — argparse выводит help
        finally:
            self._safe_cleanup(input_file_name)