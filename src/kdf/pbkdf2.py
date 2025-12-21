
from typing import Union
from ..mac.hmac import HMAC


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    hmac_obj = HMAC(key)
    hmac_obj.update(msg)
    return hmac_obj.digest()
"""
Compute HMAC-SHA256 using the internal HMAC implementation.

Args:
    key: Secret key as bytes.
    msg: Message to authenticate as bytes.

Returns:
    32-byte HMAC-SHA256 digest.

Example:
    >>> mac = hmac_sha256(b"secret_key", b"message")
"""

def pbkdf2_hmac_sha256(
        password: Union[str, bytes],
        salt: Union[str, bytes],
        iterations: int,
        dklen: int
) -> bytes:
    """
        Derive a cryptographic key using PBKDF2-HMAC-SHA256 (RFC 2898).

        Args:
            password: Input password (string or bytes).
            salt: Cryptographic salt (hex string, raw string, or bytes).
            iterations: Number of PBKDF2 iterations (minimum 1, recommended ≥100000).
            dklen: Desired length of the derived key in bytes.

        Returns:
            Derived key as bytes of exactly `dklen` length.

        Raises:
            ValueError: If `iterations` < 1 or `dklen` < 1.
            ValueError: If salt hex string is invalid.

        Example:
            key = pbkdf2_hmac_sha256("mypassword", "a1b2c3d4", 100000, 32)
            key = pbkdf2_hmac_sha256(b"pass", os.urandom(16), 100000, 32)

        Security:
            Use a cryptographically random salt and at least 100,000 iterations
            to protect against brute-force and rainbow table attacks.
            Salt provided as string is treated as hex if valid, otherwise encoded as UTF-8.
        """
    if isinstance(password, str):
        password = password.encode('utf-8')

    if isinstance(salt, str):
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            salt = salt.encode('utf-8')

    hlen = 32
    blocks_needed = (dklen + hlen - 1) // hlen
    derived_key = b''

    for i in range(1, blocks_needed + 1):
        block = hmac_sha256(password, salt + i.to_bytes(4, 'big'))
        u_prev = block

        for _ in range(2, iterations + 1):
            u_curr = hmac_sha256(password, u_prev)
            block = bytes(a ^ b for a, b in zip(block, u_curr))
            u_prev = u_curr

        derived_key += block

    return derived_key[:dklen]