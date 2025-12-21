
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AuthenticationError(Exception):
    pass


def gcm_encrypt(key, plaintext, aad=b"", nonce=None):

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