
from ..modes.ctr import CTRMode
import hmac
import hashlib

class AuthenticationError(Exception):
    pass
    """
    Raised when message authentication fails (invalid MAC or GCM tag).
    """
class EncryptThenMAC:
    """
        Authenticated encryption using Encrypt-then-MAC construction with AES-CTR + HMAC-SHA256.

        The master key is split into two parts:
        - First 16 bytes: AES key for encryption
        - Last 16 bytes: HMAC key for authentication

        Format: [ciphertext][32-byte HMAC-SHA256 tag]

        Example:
            etm = EncryptThenMAC(os.urandom(32))
            ct = etm.encrypt(b"secret data", aad=b"metadata")
            pt = etm.decrypt(ct, aad=b"metadata")
        """

    def __init__(self, key: bytes):
        """
                Initialize Encrypt-then-MAC with a 32-byte master key.

                Args:
                    key: 32-byte master key (16 bytes for AES, 16 bytes for HMAC).

                Raises:
                    ValueError: If key length is not exactly 32 bytes.

                Example:
                    etm = EncryptThenMAC(bytes.fromhex('a1b2...' * 16))
                """

        if len(key) != 32:
            raise ValueError("Master key must be 32 bytes")
        self.enc_key = key[:16]
        self.mac_key = key[16:]

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        """
                Encrypt and authenticate data using Encrypt-then-MAC.

                Args:
                    plaintext: Data to encrypt (any length).
                    aad: Additional Authenticated Data (not encrypted, but authenticated).

                Returns:
                    Encrypted output as bytes: [ciphertext][32B HMAC-SHA256 tag]

                Example:
                    ct = etm.encrypt(b"message", aad=b"user_id:123")

                Security:
                    - Uses AES-CTR for confidentiality
                    - Uses HMAC-SHA256(ciphertext || AAD) for integrity
                    - Never reuses IV/nonce (handled internally by CTRMode)
                """
        ciphertext = CTRMode.ctr_encrypt_bytes(self.enc_key, plaintext)
        tag = hmac.new(self.mac_key, ciphertext + aad, hashlib.sha256).digest()
        return ciphertext + tag

    def decrypt(self, encrypted_data: bytes, aad: bytes = b"") -> bytes:
        """
               Decrypt and verify authenticated data.

               Args:
                   encrypted_data: Data from `encrypt()` method.
                   aad: Additional Authenticated Data (must match encryption AAD).

               Returns:
                   Decrypted plaintext as bytes.

               Raises:
                   AuthenticationError: If HMAC verification fails (tampered data or wrong AAD).
                   ValueError: If input data is too short (<32 bytes).

               Example:
                   pt = etm.decrypt(ciphertext, aad=b"user_id:123")

               Security:
                   - On authentication failure, no plaintext is returned
                   - Uses constant-time comparison to prevent timing attacks
               """
        if len(encrypted_data) < 32:
            raise ValueError("Data too short")
        ciphertext = encrypted_data[:-32]
        tag_received = encrypted_data[-32:]
        tag_computed = hmac.new(self.mac_key, ciphertext + aad, hashlib.sha256).digest()
        if not hmac.compare_digest(tag_computed, tag_received):
            raise AuthenticationError("MAC verification failed")
        return CTRMode.ctr_decrypt_bytes(self.enc_key, ciphertext)