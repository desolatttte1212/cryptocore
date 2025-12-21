import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.csprng import generate_random_bytes, is_weak_key


class TestCSPRNG(unittest.TestCase):

    def test_generate_random_bytes_basic(self):
        for size in [1, 16, 32, 100]:
            with self.subTest(size=size):
                result = generate_random_bytes(size)
                self.assertEqual(len(result), size)
                self.assertIsInstance(result, bytes)

    def test_generate_random_bytes_invalid_size(self):
        with self.assertRaises(ValueError):
            generate_random_bytes(0)

        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_key_uniqueness(self):
        key_set = set()
        num_keys = 1000

        for _ in range(num_keys):
            key = generate_random_bytes(16)
            key_hex = key.hex()

            self.assertNotIn(key_hex, key_set, f"Duplicate key found: {key_hex}")
            key_set.add(key_hex)

        print(f"Successfully generated {len(key_set)} unique keys.")

    def test_randomness_distribution(self):
        total_bits = 0
        total_bytes = 0
        num_samples = 1000

        for _ in range(num_samples):
            random_bytes = generate_random_bytes(16)
            total_bytes += len(random_bytes)

            for byte in random_bytes:
                total_bits += bin(byte).count('1')

        total_bits_count = total_bytes * 8
        ones_ratio = total_bits / total_bits_count

        self.assertGreater(ones_ratio, 0.45)
        self.assertLess(ones_ratio, 0.55)

        print(f"Bit distribution: {ones_ratio:.3f} (should be close to 0.5)")

    def test_weak_key_detection(self):
        zeros_key = bytes(16)
        self.assertTrue(is_weak_key(zeros_key))

        sequential_up = bytes(range(16))
        self.assertTrue(is_weak_key(sequential_up))

        sequential_down = bytes(range(15, -1, -1))
        self.assertTrue(is_weak_key(sequential_down))

        repeated_pattern = b'\x01\x02\x03\x04' * 4
        self.assertTrue(is_weak_key(repeated_pattern))

        strong_key = generate_random_bytes(16)
        self.assertFalse(is_weak_key(strong_key))

    def test_nist_test_data_generation(self):
        total_size = 10_000_000
        test_file = 'nist_test_data.bin'

        try:
            with open(test_file, 'wb') as f:
                bytes_written = 0
                chunk_size = 4096

                while bytes_written < total_size:
                    current_chunk_size = min(chunk_size, total_size - bytes_written)
                    random_chunk = generate_random_bytes(current_chunk_size)
                    f.write(random_chunk)
                    bytes_written += len(random_chunk)

            self.assertTrue(os.path.exists(test_file))
            self.assertEqual(os.path.getsize(test_file), total_size)
            print(f"Generated {bytes_written} bytes for NIST testing in '{test_file}'")

        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)


if __name__ == '__main__':
    unittest.main()