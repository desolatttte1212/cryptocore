from Crypto.Cipher import AES
import os
from .base_mode import BaseMode


class CBCMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = True

    def encrypt(self, input_file):
        from ..file_io import read_file, write_file

        plaintext = read_file(input_file)

        iv = os.urandom(16)

        padded_plaintext = self.pad(plaintext)

        cipher = AES.new(self.key, AES.MODE_ECB)

        ciphertext = b''
        previous_block = iv

        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]

            xor_block = bytes(a ^ b for a, b in zip(block, previous_block))

            encrypted_block = cipher.encrypt(xor_block)
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        from ..file_io import read_file, read_file_with_iv

        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        cipher = AES.new(self.key, AES.MODE_ECB)

        plaintext = b''
        previous_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            decrypted_block = cipher.decrypt(block)

            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            plaintext += plain_block

        return self.unpad(plaintext)