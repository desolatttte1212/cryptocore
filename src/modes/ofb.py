from Crypto.Cipher import AES
from ..csprng import generate_random_bytes
from .base_mode import BaseMode


class OFBMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        from ..file_io import read_file

        plaintext = read_file(input_file)

        iv = generate_random_bytes(16)

        cipher = AES.new(self.key, AES.MODE_ECB)

        keystream = b''
        feedback = iv

        while len(keystream) < len(plaintext):
            encrypted_feedback = cipher.encrypt(feedback)
            keystream += encrypted_feedback
            feedback = encrypted_feedback

        keystream = keystream[:len(plaintext)]

        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        from ..file_io import read_file, read_file_with_iv

        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        cipher = AES.new(self.key, AES.MODE_ECB)

        keystream = b''
        feedback = iv

        while len(keystream) < len(ciphertext):
            encrypted_feedback = cipher.encrypt(feedback)
            keystream += encrypted_feedback
            feedback = encrypted_feedback

        keystream = keystream[:len(ciphertext)]

        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))

        return plaintext