from Crypto.Cipher import AES
import os
from .base_mode import BaseMode


class CBCMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = True

    def encrypt(self, input_file):
        """Encrypt data using AES-CBC mode"""
        from ..file_io import read_file, write_file

        plaintext = read_file(input_file)

        # Generate random IV
        iv = os.urandom(16)

        # Pad the plaintext
        padded_plaintext = self.pad(plaintext)

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Encrypt block by block with CBC chaining
        ciphertext = b''
        previous_block = iv

        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]

            # XOR with previous ciphertext block (or IV for first block)
            xor_block = bytes(a ^ b for a, b in zip(block, previous_block))

            # Encrypt the XOR result
            encrypted_block = cipher.encrypt(xor_block)
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        """Decrypt data using AES-CBC mode"""
        from ..file_io import read_file, read_file_with_iv

        # Read IV and ciphertext
        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        # Validate ciphertext length
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Decrypt block by block with CBC chaining
        plaintext = b''
        previous_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # Decrypt the block
            decrypted_block = cipher.decrypt(block)

            # XOR with previous ciphertext block (or IV for first block)
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            plaintext += plain_block
            previous_block = block

        # Remove padding
        return self.unpad(plaintext)