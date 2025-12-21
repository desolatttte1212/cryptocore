import struct

import numpy as np
from numba import jit, uint32, uint8


# Оптимизация работы с использованием jit компиляции
@jit(uint32(uint32, uint32), nopython=True, cache=True)
def _rotr(n, x):
    return (x >> n) | (x << (32 - n))


@jit(uint32(uint32, uint32), nopython=True, cache=True)
def _shr(n, x):
    return x >> n


@jit(uint32(uint32, uint32, uint32), nopython=True, cache=True)
def _ch(x, y, z):
    return (x & y) ^ (~x & z)


@jit(uint32(uint32, uint32, uint32), nopython=True, cache=True)
def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


@jit(uint32(uint32), nopython=True, cache=True)
def _sigma0(x):
    return _rotr(uint32(2), x) ^ _rotr(uint32(13), x) ^ _rotr(uint32(22), x)


@jit(uint32(uint32), nopython=True, cache=True)
def _sigma1(x):
    return _rotr(uint32(6), x) ^ _rotr(uint32(11), x) ^ _rotr(uint32(25), x)


@jit(uint32(uint32), nopython=True, cache=True)
def _sigma0_schedule(x):
    return _rotr(uint32(7), x) ^ _rotr(uint32(18), x) ^ _shr(uint32(3), x)


@jit(uint32(uint32), nopython=True, cache=True)
def _sigma1_schedule(x):
    return _rotr(uint32(17), x) ^ _rotr(uint32(19), x) ^ _shr(uint32(10), x)


@jit(nopython=True, cache=True)
def _process_block_numba(block, h, K):
    w = np.zeros(64, dtype=np.uint32)

    for i in range(16):
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3]

    for i in range(16, 64):
        s0 = _sigma0_schedule(w[i - 15])
        s1 = _sigma1_schedule(w[i - 2])
        w[i] = w[i - 16] + s0 + w[i - 7] + s1

    a, b, c, d, e, f, g, h_val = h

    for i in range(64):
        S1 = _sigma1(e)
        ch = _ch(e, f, g)
        temp1 = h_val + S1 + ch + K[i] + w[i]
        S0 = _sigma0(a)
        maj = _maj(a, b, c)
        temp2 = S0 + maj

        h_val = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2

    h[0] += a
    h[1] += b
    h[2] += c
    h[3] += d
    h[4] += e
    h[5] += f
    h[6] += g
    h[7] += h_val

    return h


class SHA256:
    """
    SHA-256 hash function implementation compliant with NIST FIPS 180-4.

    This implementation uses Numba for optimized performance and supports
    incremental hashing of large data streams.

    Example:
        h = SHA256()
        h.update(b"Hello ")
        h.update(b"World")
        print(h.hexdigest())
"""

    _H0 = np.array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ], dtype=np.uint32)

    _K = np.array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ], dtype=np.uint32)

    def __init__(self):
        self.reset()

    def reset(self):
        """
                Reset the hasher to its initial state.

                This allows reusing the same hasher instance for multiple hashes.
                """
        self.h = self._H0.copy()
        self.buffer = bytearray()
        self.total_length = 0
        self.finalized = False

    def _rotr(self, n, x):
        return _rotr(np.uint32(n), x)

    def _shr(self, n, x):
        return _shr(np.uint32(n), x)

    def _ch(self, x, y, z):
        return _ch(x, y, z)

    def _maj(self, x, y, z):
        return _maj(x, y, z)

    def _sigma0(self, x):
        return _sigma0(x)

    def _sigma1(self, x):
        return _sigma1(x)

    def _sigma0_schedule(self, x):
        return _sigma0_schedule(x)

    def _sigma1_schedule(self, x):
        return _sigma1_schedule(x)

    def _process_block(self, block):
        block_np = np.frombuffer(block[:64], dtype=np.uint8)
        self.h = _process_block_numba(block_np, self.h, self._K)

    def update(self, data):
        """
                Update the hash with new data.

                Args:
                     Bytes to include in the hash computation.

                Raises:
                    RuntimeError: If the hasher has already been finalized (digest called).

                Example:
                    h.update(b"additional data")
                """
        if self.finalized:
            raise RuntimeError("Hash already finalized")

        self.buffer.extend(data)
        self.total_length += len(data)

        while len(self.buffer) >= 64:
            self._process_block(bytes(self.buffer[:64]))
            del self.buffer[:64]

    def _pad_message(self):
        bit_length = self.total_length * 8

        self.buffer.append(0x80)

        while (len(self.buffer) + 8) % 64 != 0:
            self.buffer.append(0x00)

        self.buffer.extend(struct.pack('>Q', bit_length))

    def digest(self):
        """
                Return the final SHA-256 hash digest.

                Returns:
                    32-byte hash digest as bytes.

                Note:
                    After calling digest(), the hasher is finalized and cannot be updated
                    further without calling reset().
                """
        if not self.finalized:

            temp_buffer = self.buffer[:]
            temp_length = self.total_length

            self._pad_message()

            while len(self.buffer) >= 64:
                self._process_block(bytes(self.buffer[:64]))
                del self.buffer[:64]

            self.finalized = True

            self.buffer = temp_buffer
            self.total_length = temp_length

        result = bytearray()
        for val in self.h:
            result.extend(val.item().to_bytes(4, 'big'))
        return bytes(result)

    def hexdigest(self):
        """
                Return the final SHA-256 hash as a hexadecimal string.

                Returns:
                    64-character lowercase hex string.

                Example:
                    print(h.hexdigest())  # 'ba7816bf8f01cfea414140de5dae2223...'
                """

        return self.digest().hex()


def sha256_file(filename, chunk_size=8192):
    """
        Compute SHA-256 hash of a file.

        Args:
            filename: Path to the file to hash.
            chunk_size: Read buffer size in bytes (default: 8192).

        Returns:
            SHA-256 hash as 64-character hex string.

        Raises:
            FileNotFoundError: If the file does not exist.
            IOError: If the file cannot be read.

        Example:
            hash_val = sha256_file("document.pdf")
        """

    sha = SHA256()

    with open(filename, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha.update(chunk)

    return sha.hexdigest()


def sha256_data(data):
    """
        Compute SHA-256 hash of data (string or bytes).

        Args:
            data: Input data as string or bytes.

        Returns:
            SHA-256 hash as 64-character hex string.

        Example:
            hash_val = sha256_data("Hello World")
            hash_val = sha256_data(b"Hello World")
        """

    sha = SHA256()

    if isinstance(data, str):
        data = data.encode('utf-8')

    sha.update(data)
    return sha.hexdigest()

def sha256(data: bytes) -> str:
    """
        Backward-compatible SHA-256 function for testing.

        Args:
            data: Input data as bytes.

        Returns:
            SHA-256 hash as 64-character hex string.

        Note:
            This function is provided for compatibility with existing test suites.
        """
    h = SHA256()
    h.update(data)
    return h.hexdigest()