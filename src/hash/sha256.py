import struct
from .base import HashFunction

class SHA256(HashFunction):

    def __init__(self):
        self.block_size = 64
        self.output_size = 32

        self.h_initial = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]

        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        self.reset()

    def reset(self) -> None:
        self.h = self.h_initial.copy()
        self.message_length = 0
        self.buffer = bytearray()

    def _rotr(self, x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _shr(self, x: int, n: int) -> int:
        return x >> n

    def _ch(self, x: int, y: int, z: int) -> int:
        return (x & y) ^ (~x & z)

    def _maj(self, x: int, y: int, z: int) -> int:
        return (x & y) ^ (x & z) ^ (y & z)

    def _sigma0(self, x: int) -> int:
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)

    def _sigma1(self, x: int) -> int:
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)

    def _gamma0(self, x: int) -> int:
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ self._shr(x, 3)

    def _gamma1(self, x: int) -> int:
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ self._shr(x, 10)

    def _process_block(self, block: bytes) -> None:
        w = [0] * 64

        for i in range(16):
            w[i] = struct.unpack('>I', block[i*4:(i+1)*4])[0]

        for i in range(16, 64):
            s0 = self._gamma0(w[i-15])
            s1 = self._gamma1(w[i-2])
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = self.h

        for i in range(64):
            t1 = (h + self._sigma1(e) + self._ch(e, f, g) + self.k[i] + w[i]) & 0xFFFFFFFF
            t2 = (self._sigma0(a) + self._maj(a, b, c)) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def update(self, data: bytes) -> None:

        self.message_length += len(data)
        self.buffer.extend(data)

        while len(self.buffer) >= self.block_size:
            block = bytes(self.buffer[:self.block_size])
            self._process_block(block)
            self.buffer = self.buffer[self.block_size:]

    def digest(self) -> bytes:
        temp_hasher = SHA256()
        temp_hasher.h = self.h.copy()
        temp_hasher.message_length = self.message_length
        temp_hasher.buffer = self.buffer.copy()

        temp_hasher.buffer.append(0x80)

        while len(temp_hasher.buffer) % 64 != 56:
            temp_hasher.buffer.append(0x00)

        bit_length = temp_hasher.message_length * 8
        temp_hasher.buffer.extend(struct.pack('>Q', bit_length))

        for i in range(0, len(temp_hasher.buffer), 64):
            block = bytes(temp_hasher.buffer[i:i + 64])
            temp_hasher._process_block(block)

        result = b''
        for h_val in temp_hasher.h:
            result += struct.pack('>I', h_val)

        return result

    def hexdigest(self) -> str:
        return self.digest().hex()

def sha256(data: bytes) -> str:
    hasher = SHA256()
    hasher.update(data)
    return hasher.hexdigest()


def sha256_file(file_path: str) -> str:
    hasher = SHA256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()