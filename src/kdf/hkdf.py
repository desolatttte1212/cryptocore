from .pbkdf2 import hmac_sha256

def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:
    if isinstance(context, str):
        context = context.encode('utf-8')
    if length < 1:
        raise ValueError("Length must be >= 1")

    derived = b''
    counter = 1
    while len(derived) < length:
        block = hmac_sha256(master_key, context + counter.to_bytes(4, 'big'))
        derived += block
        counter += 1
    return derived[:length]