import unittest
from src.mac.hmac import HMAC
from src.hash.sha256 import SHA256  # ← важно: импортируем класс, а не строку


class TestHMACRFC4231(unittest.TestCase):
    """TEST-1: HMAC-SHA256 test vectors from RFC 4231, Section 4.2"""

    def test_rfc4231_test_case_1(self):
        """Key = 0x0b0b0b..., Data = 'Hi There'"""
        key = bytes.fromhex('0b' * 20)
        data = b"Hi There"
        expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        hmac = HMAC(key, SHA256)  # ← передаём класс, не строку
        hmac.update(data)
        result = hmac.hexdigest()
        self.assertEqual(result, expected)

    def test_rfc4231_test_case_2(self):
        """Key = 'Jefe', Data = 'what do ya want for nothing?'"""
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        hmac = HMAC(key, SHA256)
        hmac.update(data)
        result = hmac.hexdigest()
        self.assertEqual(result, expected)

    def test_rfc4231_test_case_3(self):
        """Key = 0xaa*20, Data = 0xdd*50"""
        key = bytes.fromhex('aa' * 20)
        data = bytes.fromhex('dd' * 50)
        expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        hmac = HMAC(key, SHA256)  # ← исправлено: передаём класс
        hmac.update(data)
        result = hmac.hexdigest()
        self.assertEqual(result, expected)

    def test_rfc4231_test_case_4(self):
        """Key = 0x0102..., Data = 0xcd*50"""
        key = bytes.fromhex('0102030405060708090a0b0c0d0e0f10111213141516171819')
        data = bytes.fromhex('cd' * 50)
        expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        hmac = HMAC(key, SHA256)
        hmac.update(data)
        result = hmac.hexdigest()
        self.assertEqual(result, expected)

    def test_empty_key_and_data(self):
        """Edge case: empty key and empty data"""
        key = b""
        data = b""
        # Expected value verified via OpenSSL
        expected = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        hmac = HMAC(key, SHA256)
        hmac.update(data)
        result = hmac.hexdigest()
        self.assertEqual(result, expected)


if __name__ == '__main__':
    unittest.main()