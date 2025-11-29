from Crypto.Cipher import AES
import os
from .base_mode import BaseMode


class CFBMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        """Encrypt data using AES-CFB mode"""
        from ..file_io import read_file

        plaintext = read_file(input_file)

        # Generate random IV
        iv = os.urandom(16)

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Encrypt using CFB mode
        ciphertext = b''
        feedback = iv

        # Process data in blocks
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # Encrypt the feedback register
            encrypted_feedback = cipher.encrypt(feedback)

            # XOR with plaintext block (truncate if partial block)
            cipher_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback[:len(block)]))
            ciphertext += cipher_block

            # Update feedback register with ciphertext
            if len(block) == self.block_size:
                feedback = cipher_block
            else:
                # For partial final block, pad with zeros for feedback
                feedback = cipher_block + b'\x00' * (self.block_size - len(block))

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        """Decrypt data using AES-CFB mode"""
        from ..file_io import read_file, read_file_with_iv

        # Read IV and ciphertext
        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Decrypt using CFB mode (same as encryption but with ciphertext)
        plaintext = b''
        feedback = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # Encrypt the feedback register
            encrypted_feedback = cipher.encrypt(feedback)

            # XOR with ciphertext block
            plain_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback[:len(block)]))
            plaintext += plain_block

            # Update feedback register with ciphertext (not plaintext)
            if len(block) == self.block_size:
                feedback = block
            else:
                feedback = block + b'\x00' * (self.block_size - len(block))

        return plaintext