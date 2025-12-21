import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AuthenticationError(Exception):
    pass


def gcm_encrypt(key, plaintext, aad=b"", nonce=None):
    """
        Encrypt and authenticate data using AES-GCM via the `cryptography` library.

        Args:
            key: 16, 24, or 32-byte AES key.
            plaintext: Data to encrypt (any length).
            aad: Additional Authenticated Data (optional, not encrypted).
            nonce: 12-byte nonce (if None, generated randomly using os.urandom(12)).

        Returns:
            Encrypted output as bytes: [12B nonce][ciphertext][16B authentication tag]

        Example:
            ct = gcm_encrypt(key, b"secret", aad=b"v1.0")
            ct = gcm_encrypt(key, b"secret", nonce=bytes.fromhex('a1b2...'))

        Security:
            - Never reuse the same nonce with the same key
            - Authentication tag ensures integrity of both ciphertext and AAD
            - Uses 16-byte (128-bit) authentication tag for strong security
        """

    if nonce is None:
        nonce = os.urandom(12)

    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, min_tag_length=16),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()

    if aad:
        encryptor.authenticate_additional_data(aad)

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    return nonce + ciphertext + tag


def gcm_decrypt(key, data, aad=b""):
    """
        Decrypt and verify AES-GCM encrypted data.

        Args:
            key: AES key (must match encryption key).
            data: Encrypted input: [12B nonce][ciphertext][16B tag]
            aad: Additional Authenticated Data (must match encryption AAD).

        Returns:
            Decrypted plaintext as bytes.

        Raises:
            AuthenticationError: If tag verification fails (tampered data, wrong key, or wrong AAD).
            ValueError: If input data is too short (<28 bytes).

        Example:
            pt = gcm_decrypt(key, ciphertext, aad=b"v1.0")

        Security:
            - On authentication failure, raises exception without returning partial data
            - Validates nonce, ciphertext, and tag together
        """
    if len(data) < 12 + 16:
        raise ValueError("Файл повреждён или не в формате GCM")

    nonce = data[:12]
    ciphertext = data[12:-16]
    tag = data[-16:]

    try:
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag, min_tag_length=16),
            backend=default_backend()
        )

        decryptor = cipher.decryptor()

        if aad:
            decryptor.authenticate_additional_data(aad)

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    except Exception as e:
        raise AuthenticationError(f"Проверка не прошла: {str(e)}")