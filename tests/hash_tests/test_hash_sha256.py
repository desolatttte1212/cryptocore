import unittest
from src.hash.sha256 import sha256, SHA256

class TestSHA256KnownAnswers(unittest.TestCase):

    def test_nist_test_vectors(self):
        """TEST-1: Known-answer tests from NIST"""
        test_cases = [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        ]

        for input_data, expected_hash in test_cases:
            with self.subTest(input=input_data[:20]):
                result = sha256(input_data)
                self.assertEqual(result, expected_hash)

    def test_empty_file(self):
        """TEST-2: Hash of empty input"""
        result = sha256(b"")
        self.assertEqual(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_chunked_update(self):
        """Проверка, что обновление чанками даёт тот же результат"""
        data = b"a" * 1000
        full_hash = sha256(data)

        hasher = SHA256()
        for i in range(0, len(data), 100):
            hasher.update(data[i:i+100])
        chunked_hash = hasher.hexdigest()

        self.assertEqual(full_hash, chunked_hash)


if __name__ == '__main__':
    unittest.main()