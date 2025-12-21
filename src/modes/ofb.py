from Crypto.Cipher import AES
from ..csprng import generate_random_bytes
from .base_mode import BaseMode


class OFBMode(BaseMode):
    """
        AES-OFB (Output Feedback) mode implementation.

        Format: [16B IV][ciphertext]
        Does not require padding (stream cipher mode).

        Security:
            - Requires unique IV for each encryption with the same key
            - Provides confidentiality but no authentication
            - Errors in transmission do not propagate

        Example:
            ofb = OFBMode(key)
            ct = ofb.encrypt("input.txt")
            pt = ofb.decrypt("input.txt.enc")
        """
    def __init__(self, key):
        """
                Initialize OFB mode with AES key.

                Args:
                    key: 16-byte AES key.
                """
        super().__init__(key)
        self.requires_padding = False

    def encrypt(self, input_file):
        """
                Encrypt file using AES-OFB.

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

        keystream = b''
        feedback = iv

        while len(keystream) < len(plaintext):
            encrypted_feedback = cipher.encrypt(feedback)
            keystream += encrypted_feedback
            feedback = encrypted_feedback

        keystream = keystream[:len(plaintext)]

        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))

        return iv + ciphertext

    def decrypt(self, input_file, provided_iv=None):
        """
                Decrypt AES-OFB ciphertext.

                Args:
                    input_file: Path to ciphertext file.
                    provided_iv: 16-byte IV (optional; if not provided, read from file start).

                Returns:
                    Decrypted plaintext as bytes.

                Note:
                    OFB does not use padding, so output length matches input length.
                """
        from ..file_io import read_file, read_file_with_iv

        if provided_iv:
            iv = provided_iv
            ciphertext = read_file(input_file)
        else:
            iv, ciphertext = read_file_with_iv(input_file)

        cipher = AES.new(self.key, AES.MODE_ECB)

        keystream = b''
        feedback = iv

        while len(keystream) < len(ciphertext):
            encrypted_feedback = cipher.encrypt(feedback)
            keystream += encrypted_feedback
            feedback = encrypted_feedback

        keystream = keystream[:len(ciphertext)]

        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))

        return plaintext