import unittest
from src.hash.sha256 import sha256

class TestAvalancheEffect(unittest.TestCase):
    """TEST-5: Avalanche Effect Test (Should requirement)"""

    def test_avalanche_effect_sha256(self):
        """Изменение одного байта должно изменить ~50% битов хеша."""
        original = b"Hello, world! This is a test for avalanche effect in SHA-256."
        modified = b"Hello, world! This is a test for avalanche effect in SHA-255."

        self.assertNotEqual(original, modified)
        self.assertEqual(len(original), len(modified))

        hash1 = sha256(original)
        hash2 = sha256(modified)

        bin1 = bin(int(hash1, 16))[2:].zfill(256)
        bin2 = bin(int(hash2, 16))[2:].zfill(256)
        diff_bits = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))

        print(f"Avalanche: {diff_bits}/256 bits changed ({diff_bits / 2.56:.1f}%)")

        self.assertGreater(diff_bits, 100)
        self.assertLess(diff_bits, 156)

    def test_single_bit_flip(self):
        """Изменение одного бита (не байта) — через побитовую модификацию."""
        original = bytearray(b"Test avalanche with single bit flip")
        modified = bytearray(original)
        modified[0] ^= 1

        hash1 = sha256(bytes(original))
        hash2 = sha256(bytes(modified))

        bin1 = bin(int(hash1, 16))[2:].zfill(256)
        bin2 = bin(int(hash2, 16))[2:].zfill(256)
        diff_bits = sum(b1 != b2 for b1, b2 in zip(bin1, bin2))

        print(f"Single-bit flip: {diff_bits}/256 bits changed")
        self.assertGreater(diff_bits, 100)


if __name__ == '__main__':
    unittest.main()