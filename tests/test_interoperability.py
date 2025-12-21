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

    def _run_interoperability_test(self, mode, test_data):
        fixed_key_hex = "0123456789abcdef0123456789abcdef"

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as input_file:
            input_file.write(test_data)
            input_file_name = input_file.name

        encrypted_file = input_file_name + '.enc'
        decrypted_file = input_file_name + '.dec'

        try:
            # Шифрование — с подкомандой 'crypto'
            result = subprocess.run([
                'cryptocore', 'crypto',
                '--algorithm', 'aes', '--mode', mode,
                '--encrypt', '--key', fixed_key_hex,
                '--input', input_file_name, '--output', encrypted_file
            ], capture_output=True, text=True, timeout=30)

            self.assertEqual(result.returncode, 0, f"[{mode}] Encryption failed: {result.stderr}")

            # Дешифрование
            result = subprocess.run([
                'cryptocore', 'crypto',
                '--algorithm', 'aes', '--mode', mode,
                '--decrypt', '--key', fixed_key_hex,
                '--input', encrypted_file, '--output', decrypted_file
            ], capture_output=True, text=True, timeout=30)

            self.assertEqual(result.returncode, 0, f"[{mode}] Decryption failed: {result.stderr}")

            with open(decrypted_file, 'rb') as f:
                decrypted_data = f.read()
            self.assertEqual(decrypted_data, test_data, f"[{mode}] Data mismatch")

        finally:
            self._safe_cleanup(input_file_name, encrypted_file, decrypted_file)

    def test_interoperability_ecb(self):
        self._run_interoperability_test('ecb', b"ECB test data - 32 bytes exact!!")

    def test_interoperability_cbc(self):
        self._run_interoperability_test('cbc', b"Test data for interoperability check - AES-CBC")

    def test_interoperability_cfb(self):
        self._run_interoperability_test('cfb', b"CFB mode interoperability test with partial blocks")

    def test_interoperability_ofb(self):
        self._run_interoperability_test('ofb', b"OFB stream cipher mode test - any length allowed")

    def test_interoperability_ctr(self):
        self._run_interoperability_test('ctr', b"CTR mode interoperability test - very flexible")

    def test_interoperability_various_lengths(self):
        test_cases = [
            b"A",
            b"Short",
            b"Exactly 16 bytes!!",
            b"X" * 17,
            b"Long data string for testing interoperability."
        ]
        modes = ['ecb', 'cbc', 'cfb', 'ofb', 'ctr']

        for test_data in test_cases:
            for mode in modes:
                with self.subTest(mode=mode, data_length=len(test_data)):
                    self._run_interoperability_test(mode, test_data)