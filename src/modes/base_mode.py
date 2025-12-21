from abc import ABC, abstractmethod


class BaseMode(ABC):
    """
        Abstract base class for all AES block cipher modes.

        Provides common functionality including PKCS#7 padding and key validation.

        Attributes:
            key: 16-byte AES key
            block_size: Block size in bytes (16 for AES)
            requires_padding: Whether the mode requires padding (True for ECB, CBC)

        Example:
            class MyMode(BaseMode):
                 def encrypt(self, input_file):
                     # implementation
        """
    def __init__(self, key):
        """
               Initialize base mode with AES key.

               Args:
                   key: 16-byte AES key.

               Raises:
                   ValueError: If key length is not exactly 16 bytes.

               Note:
                   Only supports AES-128 (16-byte keys).
               """
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128")
        self.key = key
        self.block_size = 16
        self.requires_padding = True

    def pad(self, data):
        """
                Apply PKCS#7 padding to data.

                Args:
                    data: Input data as bytes.

                Returns:
                    Padded data as bytes.

                Note:
                    If padding is not required for this mode, returns data unchanged.
                    For empty input, returns 16 bytes of 0x10 padding.
                """
        if not self.requires_padding:
            return data

        if len(data) == 0:
            return bytes([self.block_size] * self.block_size)

        padding_length = self.block_size - (len(data) % self.block_size)
        if padding_length == 0:
            padding_length = self.block_size

        padding = bytes([padding_length] * padding_length)
        return data + padding

    def unpad(self, data):
        """
                Remove PKCS#7 padding from data.

                Args:
                    data: Padded data as bytes.

                Returns:
                    Unpadded data as bytes.

                Raises:
                    ValueError: If padding is invalid or malformed.

                Note:
                    If padding is not required for this mode, returns data unchanged.
                """
        if not self.requires_padding:
            return data

        if len(data) == 0:
            return data

        if len(data) < 1:
            raise ValueError("Data too short for unpadding")

        padding_length = data[-1]

        if padding_length < 1 or padding_length > self.block_size:
            raise ValueError(f"Invalid padding length: {padding_length}")

        if len(data) < padding_length:
            raise ValueError("Data shorter than padding length")

        expected_padding = bytes([padding_length] * padding_length)
        actual_padding = data[-padding_length:]

        if actual_padding != expected_padding:
            raise ValueError("Invalid padding bytes")

        return data[:-padding_length]

    @abstractmethod
    def encrypt(self, input_file):
        """
                Encrypt a file using this mode.

                Args:
                    input_file: Path to plaintext file.

                Returns:
                    Encrypted data as bytes.

                Raises:
                    FileNotFoundError: If input file does not exist.
                    ValueError: If encryption fails.

                Note:
                    Format varies by mode (e.g., CBC returns [16B IV][ciphertext]).
                """
        pass

    @abstractmethod
    def decrypt(self, input_file, provided_iv=None):
        """
               Decrypt a file using this mode.

               Args:
                   input_file: Path to ciphertext file.
                   provided_iv: Initialization vector (optional, mode-dependent).

               Returns:
                   Decrypted plaintext as bytes.

               Raises:
                   ValueError: If decryption fails or IV is invalid.
                   FileNotFoundError: If input file does not exist.

               Note:
                   For modes that store IV in file (CBC, CFB, OFB), provided_iv is optional.
               """
        pass