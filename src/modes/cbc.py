from Crypto.Cipher import AES
from ..csprng import generate_random_bytes
from .base_mode import BaseMode


class CBCMode(BaseMode):
    """
        AES-CBC (Cipher Block Chaining) mode implementation.

        Format: [16B IV][ciphertext]
        Uses PKCS#7 padding for plaintext.

        Security:
            - Requires unique IV for each encryption with the same key
            - Does not provide authentication (use GCM or Encrypt-then-MAC for AEAD)

        Example:
            cbc = CBCMode(key)
            ct = cbc.encrypt("input.txt")
            pt = cbc.decrypt("input.txt.enc")
        """
    def __init__(self, key):
        """
                Initialize CBC mode with AES key.

                Args:
                    key: 16-byte AES key.
                """
        super().__init__(key)
        self.requires_padding = True

    def encrypt(self, input_file):
        """
               Encrypt file using AES-CBC.

               Args:
                   input_file: Path to plaintext file.

               Returns:
                   Encrypted data as bytes: [16B random IV][padded ciphertext]

               Security:
                   IV is generated using cryptographically secure random number generator.
               """
        from ..file_io import read_file

        plaintext = read_file(input_file)

        iv = generate_random_bytes(16)

        padded_plaintext = self.pad(plaintext)

        cipher = AES.new(self.key, AES.MODE_ECB)

        ciphertext = b''
        previous_block = iv

        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]

            xor_block = bytes(a ^ b for a, b in zip(block, previous_block))

            encrypted_block = cipher.encrypt(xor_block)
            ciphertext += encrypted_block
            previous_block = encrypted_block

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        """
                Decrypt AES-CBC ciphertext.

                Args:
                    input_file: Path to ciphertext file.
                    provided_iv: 16-byte IV (optional; if not provided, read from file start).

                Returns:
                    Decrypted and unpadded plaintext as bytes.

                Raises:
                    ValueError: If ciphertext length is not multiple of block size
                               or padding is invalid.
                """
        from ..file_io import read_file, read_file_with_iv

        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        cipher = AES.new(self.key, AES.MODE_ECB)

        plaintext = b''
        previous_cipher_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            decrypted_block = cipher.decrypt(block)

            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_cipher_block))
            plaintext += plain_block
            previous_cipher_block = block

        return self.unpad(plaintext)