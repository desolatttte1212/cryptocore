from Crypto.Cipher import AES
from ..csprng import generate_random_bytes
from .base_mode import BaseMode


class CFBMode(BaseMode):
    """
        AES-CFB (Cipher Feedback) mode implementation.

        Format: [16B IV][ciphertext]
        Does not require padding (stream cipher mode).

        Security:
            - Requires unique IV for each encryption with the same key
            - Provides confidentiality but no authentication
            - Self-synchronizing after block errors

        Example:
            cfb = CFBMode(key)
            ct = cfb.encrypt("input.txt")
            pt = cfb.decrypt("input.txt.enc")
        """
    def __init__(self, key):
        """
                Initialize CFB mode with AES key.

                Args:
                    key: 16-byte AES key.
                """
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        """
                Encrypt file using AES-CFB.

                Args:
                    input_file: Path to plaintext file.

                Returns:
                    Encrypted data as bytes: [16B random IV][ciphertext]

                Security:
                    IV is generated using cryptographically secure random number generator.
                """
        from ..file_io import read_file

        plaintext = read_file(input_file)

        iv = generate_random_bytes(16)

        cipher = AES.new(self.key, AES.MODE_ECB)

        ciphertext = b''
        feedback = iv

        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            encrypted_feedback = cipher.encrypt(feedback)

            cipher_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback[:len(block)]))
            ciphertext += cipher_block

            if len(block) == self.block_size:
                feedback = cipher_block
            else:
                feedback = cipher_block + b'\x00' * (self.block_size - len(block))

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        """
                Decrypt AES-CFB ciphertext.

                Args:
                    input_file: Path to ciphertext file.
                    provided_iv: 16-byte IV (optional; if not provided, read from file start).

                Returns:
                    Decrypted plaintext as bytes.

                Note:
                    CFB does not use padding, so output length matches input length.
                """
        from ..file_io import read_file, read_file_with_iv

        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        cipher = AES.new(self.key, AES.MODE_ECB)

        plaintext = b''
        feedback = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            encrypted_feedback = cipher.encrypt(feedback)

            plain_block = bytes(a ^ b for a, b in zip(block, encrypted_feedback[:len(block)]))
            plaintext += plain_block

            if len(block) == self.block_size:
                feedback = block
            else:
                feedback = block + b'\x00' * (self.block_size - len(block))

        return plaintext