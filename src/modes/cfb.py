from Crypto.Cipher import AES
import os
from .base_mode import BaseMode


class CFBMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        from ..file_io import read_file

        plaintext = read_file(input_file)

        iv = os.urandom(16)

        cipher = AES.new(self.key, AES.MODE_ECB)

        ciphertext = b''
        feedback = iv

        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            encrypted_feedback = cipher.encrypt(feedback)

            cipher_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback[:len(block)]))
            ciphertext += cipher_block

            if len(block) == self.block_size:
                feedback = cipher_block
            else:
                feedback = cipher_block + b'\x00' * (self.block_size - len(block))

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        from ..file_io import read_file, read_file_with_iv

        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        cipher = AES.new(self.key, AES.MODE_ECB)

        plaintext = b''
        feedback = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            encrypted_feedback = cipher.encrypt(feedback)

            plain_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback[:len(block)]))
            plaintext += plain_block

            if len(block) == self.block_size:
                feedback = block
            else:
                feedback = block + b'\x00' * (self.block_size - len(block))

        return plaintext