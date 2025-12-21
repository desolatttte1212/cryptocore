
from typing import Union
from ..mac.hmac import HMAC


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    hmac_obj = HMAC(key)
    hmac_obj.update(msg)
    return hmac_obj.digest()


def pbkdf2_hmac_sha256(
        password: Union[str, bytes],
        salt: Union[str, bytes],
        iterations: int,
        dklen: int
) -> bytes:

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