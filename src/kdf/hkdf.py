from .pbkdf2 import hmac_sha256

def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:
    """
       Derive a deterministic key from a master key using HMAC-based key derivation.

       Args:
           master_key: Cryptographically random master key (e.g., 32 bytes).
           context: Unique string identifying the key's purpose (e.g., "encryption").
           length: Desired key length in bytes (default: 32, minimum: 1).

       Returns:
           Derived key as bytes of specified `length`.

       Raises:
           ValueError: If `length` < 1.

       Example:
           master = os.urandom(32)
           enc_key = derive_key(master, "encryption", 32)
            auth_key = derive_key(master, "authentication", 32)

       Security:
           - Use unique and immutable context strings to ensure key separation
           - The master key must be secret and generated with a CSPRNG
           - Derived keys are deterministic: same inputs always produce same output
       """
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