from Crypto.Cipher import AES
from .base_mode import BaseMode


class ECBMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = True

    def encrypt(self, input_file):
        """Encrypt data using AES-ECB mode"""
        from ..file_io import read_file

        plaintext = read_file(input_file)

        # Pad the plaintext
        padded_plaintext = self.pad(plaintext)

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Encrypt block by block
        ciphertext = b''
        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]
            encrypted_block = cipher.encrypt(block)
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self, input_file, provided_iv=None):
        """Decrypt data using AES-ECB mode"""
        from ..file_io import read_file

        ciphertext = read_file(input_file)

        # Validate ciphertext length
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Decrypt block by block
        plaintext = b''
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            decrypted_block = cipher.decrypt(block)
            plaintext += decrypted_block

        # Remove padding
        return self.unpad(plaintext)