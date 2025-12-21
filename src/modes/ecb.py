from Crypto.Cipher import AES
from .base_mode import BaseMode


class ECBMode(BaseMode):
    """
        AES-ECB (Electronic Codebook) mode implementation.

        Format: [ciphertext]
        Uses PKCS#7 padding for plaintext.

        Security Warning:
            - **ECB is insecure for most applications**
            - Reveals patterns in plaintext
            - Should only be used for testing or encrypting single blocks

        Example:
            ecb = ECBMode(key)
            ct = ecb.encrypt("single_block.txt")  # only if file is exactly 16 bytes
        """
    def __init__(self, key):
        """
                Initialize ECB mode with AES key.

                Args:
                    key: 16-byte AES key.

                Security:
                    ECB mode should not be used for multi-block data or sensitive information.
                """
        super().__init__(key)
        self.requires_padding = True

    def encrypt(self, input_file):
        """
               Encrypt file using AES-ECB.

               Args:
                   input_file: Path to plaintext file.

               Returns:
                   Encrypted data as bytes: [padded ciphertext]

               Security:
                   **WARNING**: ECB reveals plaintext patterns. Use only for testing.
               """
        from ..file_io import read_file

        plaintext = read_file(input_file)

        padded_plaintext = self.pad(plaintext)

        cipher = AES.new(self.key, AES.MODE_ECB)

        ciphertext = b''
        for i in range(0, len(padded_plaintext), self.block_size):
            block = padded_plaintext[i:i + self.block_size]
            encrypted_block = cipher.encrypt(block)
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self, input_file, provided_iv=None):
        """
                Decrypt AES-ECB ciphertext.

                Args:
                    input_file: Path to ciphertext file.
                    provided_iv: Ignored (ECB doesn't use IV).

                Returns:
                    Decrypted and unpadded plaintext as bytes.

                Raises:
                    ValueError: If ciphertext length is not multiple of block size.
                """
        from ..file_io import read_file

        ciphertext = read_file(input_file)
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext length must be multiple of block size")

        cipher = AES.new(self.key, AES.MODE_ECB)

        plaintext = b''
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            decrypted_block = cipher.decrypt(block)
            plaintext += decrypted_block

        return self.unpad(plaintext)