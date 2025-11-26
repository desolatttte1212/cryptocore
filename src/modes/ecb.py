from Crypto.Cipher import AES
import struct


class ECBMode:
    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key
        self.block_size = 16

    def pad(self, data):
        padding_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(self, data):
        if len(data) == 0:
            raise ValueError("Cannot unpad empty data")

        padding_length = data[-1]

        if padding_length < 1 or padding_length > self.block_size:
            raise ValueError("Invalid padding")

        if data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid padding")

        return data[:-padding_length]

    def encrypt(self, plaintext):
        padded_plaintext = self.pad(plaintext)

        cipher = AES.new(self.key, AES.MODE_ECB)

        ciphertext = b''
        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]
            encrypted_block = cipher.encrypt(block)
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self, ciphertext):
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        cipher = AES.new(self.key, AES.MODE_ECB)

        plaintext = b''
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            decrypted_block = cipher.decrypt(block)
            plaintext += decrypted_block

        return self.unpad(plaintext)