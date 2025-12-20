import os
from Crypto.Cipher import AES
from ..csprng import generate_random_bytes
from .base_mode import BaseMode

class CTRMode(BaseMode):
    def __init__(self, key):
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        from ..file_io import read_file
        plaintext = read_file(input_file)
        nonce = generate_random_bytes(8)
        counter = 0
        cipher = AES.new(self.key, AES.MODE_ECB)
        keystream = b''
        num_blocks = (len(plaintext) + self.block_size - 1) // self.block_size
        for i in range(num_blocks):
            counter_block = nonce + counter.to_bytes(8, 'little')
            keystream += cipher.encrypt(counter_block)
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
                raise ValueError("Input file is too short...")
            nonce = data[:8]
            ciphertext = data[8:]
        counter = 0
        cipher = AES.new(self.key, AES.MODE_ECB)
        keystream = b''
        num_blocks = (len(ciphertext) + self.block_size - 1) // self.block_size
        for i in range(num_blocks):
            counter_block = nonce + counter.to_bytes(8, 'little')
            keystream += cipher.encrypt(counter_block)
            counter += 1
        keystream = keystream[:len(ciphertext)]
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))

    @staticmethod
    def ctr_encrypt_bytes(key: bytes, plaintext: bytes) -> bytes:
        if not plaintext:
            return b""
        nonce = os.urandom(8)
        cipher = AES.new(key, AES.MODE_ECB)
        keystream = bytearray()
        counter = 0
        block_size = 16
        num_blocks = (len(plaintext) + block_size - 1) // block_size
        for _ in range(num_blocks):
            counter_block = nonce + counter.to_bytes(8, 'little')
            keystream.extend(cipher.encrypt(counter_block))
            counter += 1
        keystream = keystream[:len(plaintext)]
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
        return nonce + ciphertext  # ← nonce в начале

    @staticmethod
    def ctr_decrypt_bytes(key: bytes, data: bytes) -> bytes:
        if not data:
            return b""
        if len(data) < 8:
            raise ValueError("Data too short for CTR nonce")
        nonce = data[:8]
        ciphertext = data[8:]
        cipher = AES.new(key, AES.MODE_ECB)
        keystream = bytearray()
        counter = 0
        block_size = 16
        num_blocks = (len(ciphertext) + block_size - 1) // block_size
        for _ in range(num_blocks):
            counter_block = nonce + counter.to_bytes(8, 'little')
            keystream.extend(cipher.encrypt(counter_block))
            counter += 1
        keystream = keystream[:len(ciphertext)]
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))