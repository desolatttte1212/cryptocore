import os
from Crypto.Cipher import AES
from ..csprng import generate_random_bytes
from .base_mode import BaseMode

class CTRMode(BaseMode):
    """
        AES-CTR (Counter) mode implementation.

        Format: [8B nonce][ciphertext]
        Does not require padding (stream cipher mode).

        Security:
            - Requires unique nonce for each encryption with the same key
            - Provides confidentiality but no authentication
            - Allows random access to encrypted data
            - Parallelizable encryption/decryption

        Example:
            ctr = CTRMode(key)
            ct = ctr.encrypt("input.txt")
            pt = ctr.decrypt("input.txt.enc")
        """
    def __init__(self, key):
        """
                Initialize CTR mode with AES key.

                Args:
                    key: 16-byte AES key.
                """
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        """
                Encrypt file using AES-CTR.

                Args:
                    input_file: Path to plaintext file.

                Returns:
                    Encrypted data as bytes: [8B random nonce][ciphertext]

                Security:
                    Nonce is generated using cryptographically secure random number generator.
                    Counter uses little-endian encoding.
                """
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
        """
                Decrypt AES-CTR ciphertext.

                Args:
                    input_file: Path to ciphertext file.
                    provided_iv: 16-byte IV (first 8 bytes used as nonce; optional).

                Returns:
                    Decrypted plaintext as bytes.

                Raises:
                    ValueError: If input data is too short for nonce (<8 bytes).

                Note:
                    CTR does not use padding, so output length matches input length.
                """
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
        """
               Encrypt bytes using AES-CTR (used by Encrypt-then-MAC).

               Args:
                   key: 16-byte AES key.
                   plaintext: Data to encrypt as bytes.

               Returns:
                   Encrypted data as bytes: [8B nonce][ciphertext]

               Security:
                   Nonce is generated using os.urandom (cryptographically secure).
               """
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
        return nonce + ciphertext

    @staticmethod
    def ctr_decrypt_bytes(key: bytes, data: bytes) -> bytes:
        """
                Decrypt AES-CTR ciphertext bytes.

                Args:
                    key: 16-byte AES key.
                    data: Encrypted input: [8B nonce][ciphertext]

                Returns:
                    Decrypted plaintext as bytes.

                Raises:
                    ValueError: If data is too short for nonce (<8 bytes).
                """
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