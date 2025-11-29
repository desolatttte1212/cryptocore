from Crypto.Cipher import AES
import os
from .base_mode import BaseMode


class OFBMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        """Encrypt data using AES-OFB mode"""
        from ..file_io import read_file

        plaintext = read_file(input_file)

        # Generate random IV
        iv = os.urandom(16)

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Generate keystream using OFB mode
        keystream = b''
        feedback = iv

        # Generate enough keystream for the entire plaintext
        while len(keystream) < len(plaintext):
            encrypted_feedback = cipher.encrypt(feedback)
            keystream += encrypted_feedback
            feedback = encrypted_feedback

        # Truncate keystream to match plaintext length
        keystream = keystream[:len(plaintext)]

        # XOR plaintext with keystream
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        """Decrypt data using AES-OFB mode (same as encryption)"""
        from ..file_io import read_file, read_file_with_iv

        # Read IV and ciphertext
        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        # Create cipher object
        cipher = AES.new(self.key, AES.MODE_ECB)

        # Generate keystream using OFB mode
        keystream = b''
        feedback = iv

        # Generate enough keystream for the entire ciphertext
        while len(keystream) < len(ciphertext):
            encrypted_feedback = cipher.encrypt(feedback)
            keystream += encrypted_feedback
            feedback = encrypted_feedback

        # Truncate keystream to match ciphertext length
        keystream = keystream[:len(ciphertext)]

        # XOR ciphertext with keystream
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))

        return plaintext