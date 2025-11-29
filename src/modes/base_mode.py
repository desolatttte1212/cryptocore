from abc import ABC, abstractmethod


class BaseMode(ABC):
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128")
        self.key = key
        self.block_size = 16
        self.requires_padding = True

    def pad(self, data):
        """PKCS#7 padding (only for modes that require padding)"""
        if not self.requires_padding:
            return data

        padding_length = self.block_size - (len(data) % self.block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(self, data):
        """PKCS#7 unpadding (only for modes that require padding)"""
        if not self.requires_padding:
            return data

        if len(data) == 0:
            raise ValueError("Cannot unpad empty data")

        padding_length = data[-1]

        # Validate padding
        if padding_length < 1 or padding_length > self.block_size:
            raise ValueError("Invalid padding")

        if data[-padding_length:] != bytes([padding_length] * padding_length):
            raise ValueError("Invalid padding")

        return data[:-padding_length]

    @abstractmethod
    def encrypt(self, input_file):
        """Encrypt the input file"""
        pass

    @abstractmethod
    def decrypt(self, input_file, provided_iv=None):
        """Decrypt the input file"""
        pass