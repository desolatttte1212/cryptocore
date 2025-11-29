from Crypto.Cipher import AES
import os
from .base_mode import BaseMode


class CTRMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        from ..file_io import read_file

        plaintext = read_file(input_file)

        nonce = os.urandom(8)
        counter = 0

        cipher = AES.new(self.key, AES.MODE_ECB)

        keystream = b''

        num_blocks = (len(plaintext) + self.block_size - 1) // self.block_size

        for i in range(num_blocks):
            counter_block = nonce + counter.to_bytes(8, 'little')

            keystream_block = cipher.encrypt(counter_block)
            keystream += keystream_block

            counter += 1

        keystream = keystream[:len(plaintext)]

        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))

        return nonce + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        from ..file_io import read_file
        if provided_iv:
            if len(provided_iv) != 16:
                raise ValueError("IV must be 16 bytes for CTR mode")
            nonce = provided_iv[:8]
            ciphertext = read_file(input_file)
        else:
            data = read_file(input_file)
            if len(data) < 8:
                raise ValueError("Input file is too short to contain nonce (minimum 8 bytes required)")
            nonce = data[:8]
            ciphertext = data[8:]

        counter = 0

        cipher = AES.new(self.key, AES.MODE_ECB)

        keystream = b''

        num_blocks = (len(ciphertext) + self.block_size - 1) // self.block_size

        for i in range(num_blocks):
            counter_block = nonce + counter.to_bytes(8, 'little')

            keystream_block = cipher.encrypt(counter_block)
            keystream += keystream_block

            counter += 1

        keystream = keystream[:len(ciphertext)]

        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))

        return plaintext