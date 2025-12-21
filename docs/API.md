CryptoCore API Documentation
Module: kdf (Key Derivation)
pbkdf2_hmac_sha256(password, salt, iterations, dklen)
Derive a cryptographic key using PBKDF2-HMAC-SHA256 (RFC 2898).

Parameters:

password (Union[str, bytes]): Input password (string or bytes).
salt (Union[str, bytes]): Cryptographic salt (hex string, raw string, or bytes).
iterations (int): Number of PBKDF2 iterations (minimum 1, recommended ≥100000).
dklen (int): Desired length of the derived key in bytes.
Returns:
bytes — Derived key as bytes of exactly dklen length.

Raises:
ValueError — If iterations < 1 or dklen < 1.
ValueError — If salt hex string is invalid.

Security:
Use a cryptographically random salt and at least 100,000 iterations to protect against brute-force and rainbow table attacks. Salt provided as string is treated as hex if valid, otherwise encoded as UTF-8.

hmac_sha256(key, msg)
Compute HMAC-SHA256 using the internal HMAC implementation.

Parameters:

key (bytes): Secret key as bytes.
msg (bytes): Message to authenticate as bytes.
Returns:
bytes — 32-byte HMAC-SHA256 digest.

Security:
This function uses the internal HMAC implementation for compatibility with other components.

derive_key(master_key, context, length=32)
Derive a deterministic key from a master key using HMAC-based key derivation.

Parameters:

master_key (bytes): Cryptographically random master key (e.g., 32 bytes).
context (str): Unique string identifying the key's purpose (e.g., "encryption").
length (int): Desired key length in bytes (default: 32, minimum: 1).
Returns:
bytes — Derived key as bytes of specified length.

Raises:
ValueError — If length < 1.

Security:

Use unique and immutable context strings to ensure key separation
The master key must be secret and generated with a CSPRNG
Derived keys are deterministic: same inputs always produce same output
Module: aead (Authenticated Encryption)
class EncryptThenMAC
Authenticated encryption using Encrypt-then-MAC construction with AES-CTR + HMAC-SHA256.

The master key is split into two parts:

First 16 bytes: AES key for encryption
Last 16 bytes: HMAC key for authentication
Format: [ciphertext][32-byte HMAC-SHA256 tag]

Security:

Uses AES-CTR for confidentiality
Uses HMAC-SHA256(ciphertext || AAD) for integrity
Never reuses IV/nonce (handled internally by CTRMode)
__init__(self, key)
Initialize Encrypt-then-MAC with a 32-byte master key.

Parameters:
key (bytes): 32-byte master key (16 bytes for AES, 16 bytes for HMAC).

Raises:
ValueError — If key length is not exactly 32 bytes.

encrypt(self, plaintext, aad=b"")
Encrypt and authenticate data using Encrypt-then-MAC.

Parameters:

plaintext (bytes): Data to encrypt (any length).
aad (bytes): Additional Authenticated Data (not encrypted, but authenticated).
Returns:
bytes — Encrypted output as bytes: [ciphertext][32B HMAC-SHA256 tag]

Security:

Uses AES-CTR for confidentiality
Uses HMAC-SHA256(ciphertext || AAD) for integrity
Never reuses IV/nonce (handled internally by CTRMode)
decrypt(self, encrypted_data, aad=b"")
Decrypt and verify authenticated data.

Parameters:

encrypted_data (bytes): Data from encrypt() method.
aad (bytes): Additional Authenticated Data (must match encryption AAD).
Returns:
bytes — Decrypted plaintext as bytes.

Raises:
AuthenticationError — If HMAC verification fails (tampered data or wrong AAD).
ValueError — If input data is too short (<32 bytes).

Security:

On authentication failure, no plaintext is returned
Uses constant-time comparison to prevent timing attacks
class AuthenticationError
Raised when message authentication fails (invalid MAC or GCM tag).

Module: modes.gcm
gcm_encrypt(key, plaintext, aad=b"", nonce=None)
Encrypt and authenticate data using AES-GCM via the cryptography library.

Parameters:

key (bytes): 16, 24, or 32-byte AES key.
plaintext (bytes): Data to encrypt (any length).
aad (bytes): Additional Authenticated Data (optional, not encrypted).
nonce (bytes): 12-byte nonce (if None, generated randomly using os.urandom(12)).
Returns:
bytes — Encrypted output as bytes: [12B nonce][ciphertext][16B authentication tag]

Security:

Never reuse the same nonce with the same key
Authentication tag ensures integrity of both ciphertext and AAD
Uses 16-byte (128-bit) authentication tag for strong security
gcm_decrypt(key, data, aad=b"")
Decrypt and verify AES-GCM encrypted data.

Parameters:

key (bytes): AES key (must match encryption key).
data (bytes): Encrypted input: [12B nonce][ciphertext][16B tag]
aad (bytes): Additional Authenticated Data (must match encryption AAD).
Returns:
bytes — Decrypted plaintext as bytes.

Raises:
AuthenticationError — If tag verification fails (tampered data, wrong key, or wrong AAD).
ValueError — If input data is too short (<28 bytes).

Security:

On authentication failure, raises exception without returning partial data
Validates nonce, ciphertext, and tag together
Module: hash (SHA-256)
class SHA256
SHA-256 hash function implementation compliant with NIST FIPS 180-4.

This implementation uses Numba for optimized performance and supports incremental hashing of large data streams.

Security:

Follows NIST FIPS 180-4 standard
Supports streaming input (update() method)
Final state is finalized after digest()
__init__(self)
Initialize SHA256 hasher with default state.

reset(self)
Reset the hasher to its initial state.
This allows reusing the same hasher instance for multiple hashes.

update(self, data)
Update the hash with new data.

Parameters:
data (bytes): Bytes to include in the hash computation.

Raises:
RuntimeError — If the hasher has already been finalized (digest called).

digest(self)
Return the final SHA-256 hash digest.

Returns:
bytes — 32-byte hash digest as bytes.

Note:
After calling digest(), the hasher is finalized and cannot be updated further without calling reset().

hexdigest(self)
Return the final SHA-256 hash as a hexadecimal string.

Returns:
str — 64-character lowercase hex string.

sha256_file(filename, chunk_size=8192)
Compute SHA-256 hash of a file.

Parameters:

filename (str): Path to the file to hash.
chunk_size (int): Read buffer size in bytes (default: 8192).
Returns:
str — SHA-256 hash as 64-character hex string.

Raises:
FileNotFoundError — If the file does not exist.
IOError — If the file cannot be read.

Security:
Uses streaming I/O to handle large files efficiently.

sha256_data(data)
Compute SHA-256 hash of data (string or bytes).

Parameters:
data — Input data as string or bytes.

Returns:
str — SHA-256 hash as 64-character hex string.

Security:
Supports both string and bytes input. Strings are automatically encoded as UTF-8.

Module: mac (HMAC)
class HMAC
HMAC (Keyed-Hash Message Authentication Code) implementation using SHA256.

Implements RFC 2104 with support for incremental updates and secure comparison.

Security:

Uses PKCS#7-style padding for keys longer than block size
Constant-time comparison for verification
Finalized state prevents further updates
__init__(self, key, hash_class=None)
Initialize HMAC with a secret key.

Parameters:

key (bytes): Secret key as bytes or string (UTF-8 encoded).
hash_class — Hash function class (default: SHA256).
Raises:
TypeError — If key is not bytes, bytearray, or string.
ValueError — If hash_class is not supported.

update(self, data)
Update the HMAC with new data.

Parameters:
data (bytes): Bytes to authenticate.

Returns:
HMAC — Self for method chaining.

Raises:
RuntimeError — If HMAC has already been finalized.
TypeError — If data is not bytes, bytearray, or string.

digest(self)
Return the final HMAC digest.

Returns:
bytes — 32-byte HMAC digest as bytes.

Note:
After calling digest(), the HMAC object is finalized and cannot be updated further without creating a new instance.

hexdigest(self)
Return the HMAC as a hexadecimal string.

Returns:
str — 64-character lowercase hex string.

hmac_data(key, data)
Compute HMAC-SHA256 of data and return hex string.

Parameters:

key (bytes): Secret key as bytes or string.
data (bytes): Message to authenticate as bytes or string.
Returns:
str — HMAC-SHA256 as 64-character hex string.

Security:
Uses the internal HMAC implementation for consistency.

hmac_file(key, filename, chunk_size=8096)
Compute HMAC-SHA256 of a file.

Parameters:

key (bytes): Secret key as bytes or string.
filename (str): Path to file to authenticate.
chunk_size (int): Read buffer size in bytes (default: 8096).
Returns:
str — HMAC-SHA256 as 64-character hex string.

Raises:
FileNotFoundError — If file does not exist.
IOError — If file cannot be read.

Security:
Handles large files via chunked reading.

verify_hmac(expected_hmac, computed_hmac)
Securely compare two HMAC values in constant time.

Parameters:

expected_hmac (str): Expected HMAC as hex string.
computed_hmac (str): Computed HMAC as hex string.
Returns:
bool — True if HMACs match, False otherwise.

Security:
Uses constant-time comparison to prevent timing attacks.
Case-insensitive and whitespace-tolerant.

Module: modes (Block Cipher Modes)
class BaseMode
Abstract base class for all AES block cipher modes.

Provides common functionality including PKCS#7 padding and key validation.

Attributes:

key — 16-byte AES key
block_size — Block size in bytes (16 for AES)
requires_padding — Whether the mode requires padding (True for ECB, CBC)
Security:
All modes inherit this base class to ensure consistent behavior.

__init__(self, key)
Initialize base mode with AES key.

Parameters:
key (bytes): 16-byte AES key.

Raises:
ValueError — If key length is not exactly 16 bytes.

pad(self, data)
Apply PKCS#7 padding to data.

Parameters:
data (bytes): Input data as bytes.

Returns:
bytes — Padded data as bytes.

Note:
If padding is not required for this mode, returns data unchanged.
For empty input, returns 16 bytes of 0x10 padding.

unpad(self, data)
Remove PKCS#7 padding from data.

Parameters:
data (bytes): Padded data as bytes.

Returns:
bytes — Unpadded data as bytes.

Raises:
ValueError — If padding is invalid or malformed.

Note:
If padding is not required for this mode, returns data unchanged.

encrypt(self, input_file)
Encrypt a file using this mode.

Parameters:
input_file (str): Path to plaintext file.

Returns:
bytes — Encrypted data as bytes.

Raises:
FileNotFoundError — If input file does not exist.
ValueError — If encryption fails.

decrypt(self, input_file, provided_iv=None)
Decrypt a file using this mode.

Parameters:

input_file (str): Path to ciphertext file.
provided_iv (bytes): Initialization vector (optional, mode-dependent).
Returns:
bytes — Decrypted plaintext as bytes.

Raises:
ValueError — If decryption fails or IV is invalid.
FileNotFoundError — If input file does not exist.

class ECBMode
AES-ECB (Electronic Codebook) mode implementation.

Format: [ciphertext]
Uses PKCS#7 padding for plaintext.

Security Warning:

ECB is insecure for most applications
Reveals patterns in plaintext
Should only be used for testing or encrypting single blocks
__init__(self, key)
Initialize ECB mode with AES key.

Parameters:
key (bytes): 16-byte AES key.

Security:
ECB mode should not be used for multi-block data or sensitive information.

encrypt(self, input_file)
Encrypt file using AES-ECB.

Parameters:
input_file (str): Path to plaintext file.

Returns:
bytes — Encrypted data as bytes: [padded ciphertext]

Security:
WARNING: ECB reveals plaintext patterns. Use only for testing.

decrypt(self, input_file, provided_iv=None)
Decrypt AES-ECB ciphertext.

Parameters:

input_file (str): Path to ciphertext file.
provided_iv (bytes): Ignored (ECB doesn't use IV).
Returns:
bytes — Decrypted and unpadded plaintext as bytes.

Raises:
ValueError — If ciphertext length is not multiple of block size.

class CBCMode
AES-CBC (Cipher Block Chaining) mode implementation.

Format: [16B IV][ciphertext]
Uses PKCS#7 padding for plaintext.

Security:

Requires unique IV for each encryption with the same key
Does not provide authentication (use GCM or Encrypt-then-MAC for AEAD)
__init__(self, key)
Initialize CBC mode with AES key.

Parameters:
key (bytes): 16-byte AES key.

encrypt(self, input_file)
Encrypt file using AES-CBC.

Parameters:
input_file (str): Path to plaintext file.

Returns:
bytes — Encrypted data as bytes: [16B random IV][padded ciphertext]

Security:
IV is generated using cryptographically secure random number generator.

decrypt(self, input_file, provided_iv=None)
Decrypt AES-CBC ciphertext.

Parameters:

input_file (str): Path to ciphertext file.
provided_iv (bytes): 16-byte IV (optional; if not provided, read from file start).
Returns:
bytes — Decrypted and unpadded plaintext as bytes.

Raises:
ValueError — If ciphertext length is not multiple of block size or padding is invalid.

class CFBMode
AES-CFB (Cipher Feedback) mode implementation.

Format: [16B IV][ciphertext]
Does not require padding (stream cipher mode).

Security:

Requires unique IV for each encryption with the same key
Provides confidentiality but no authentication
Self-synchronizing after block errors
__init__(self, key)
Initialize CFB mode with AES key.

Parameters:
key (bytes): 16-byte AES key.

encrypt(self, input_file)
Encrypt file using AES-CFB.

Parameters:
input_file (str): Path to plaintext file.

Returns:
bytes — Encrypted data as bytes: [16B random IV][ciphertext]

Security:
IV is generated using cryptographically secure random number generator.

decrypt(self, input_file, provided_iv=None)
Decrypt AES-CFB ciphertext.

Parameters:

input_file (str): Path to ciphertext file.
provided_iv (bytes): 16-byte IV (optional; if not provided, read from file start).
Returns:
bytes — Decrypted plaintext as bytes.

Note:
CFB does not use padding, so output length matches input length.

class OFBMode
AES-OFB (Output Feedback) mode implementation.

Format: [16B IV][ciphertext]
Does not require padding (stream cipher mode).

Security:

Requires unique IV for each encryption with the same key
Provides confidentiality but no authentication
Errors in transmission do not propagate
__init__(self, key)
Initialize OFB mode with AES key.

Parameters:
key (bytes): 16-byte AES key.

encrypt(self, input_file)
Encrypt file using AES-OFB.

Parameters:
input_file (str): Path to plaintext file.

Returns:
bytes — Encrypted data as bytes: [16B random IV][ciphertext]

Security:
IV is generated using cryptographically secure random number generator.

decrypt(self, input_file, provided_iv=None)
Decrypt AES-OFB ciphertext.

Parameters:

input_file (str): Path to ciphertext file.
provided_iv (bytes): 16-byte IV (optional; if not provided, read from file start).
Returns:
bytes — Decrypted plaintext as bytes.

Note:
OFB does not use padding, so output length matches input length.

class CTRMode
AES-CTR (Counter) mode implementation.

Format: [8B nonce][ciphertext]
Does not require padding (stream cipher mode).

Security:

Requires unique nonce for each encryption with the same key
Provides confidentiality but no authentication
Allows random access to encrypted data
Parallelizable encryption/decryption
__init__(self, key)
Initialize CTR mode with AES key.

Parameters:
key (bytes): 16-byte AES key.

encrypt(self, input_file)
Encrypt file using AES-CTR.

Parameters:
input_file (str): Path to plaintext file.

Returns:
bytes — Encrypted data as bytes: [8B random nonce][ciphertext]

Security:
Nonce is generated using cryptographically secure random number generator.
Counter uses little-endian encoding.

decrypt(self, input_file, provided_iv=None)
Decrypt AES-CTR ciphertext.

Parameters:

input_file (str): Path to ciphertext file.
provided_iv (bytes): 16-byte IV (first 8 bytes used as nonce; optional).
Returns:
bytes — Decrypted plaintext as bytes.

Raises:
ValueError — If input data is too short for nonce (<8 bytes).

Note:
CTR does not use padding, so output length matches input length.

ctr_encrypt_bytes(key, plaintext)
Encrypt bytes using AES-CTR (used by Encrypt-then-MAC).

Parameters:

key (bytes): 16-byte AES key.
plaintext (bytes): Data to encrypt as bytes.
Returns:
bytes — Encrypted data as bytes: [8B nonce][ciphertext]

Security:
Nonce is generated using os.urandom (cryptographically secure).

ctr_decrypt_bytes(key, data)
Decrypt AES-CTR ciphertext bytes.

Parameters:

key (bytes): 16-byte AES key.
data (bytes): Encrypted input: [8B nonce][ciphertext]
Returns:
bytes — Decrypted plaintext as bytes.

Raises:
ValueError — If data is too short for nonce (<8 bytes).