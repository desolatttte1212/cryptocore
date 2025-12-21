import hashlib

class SHA3_256:
    def __init__(self):
        self._hasher = hashlib.sha3_256()

    def update(self, data):
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        self._hasher.update(data)

    def digest(self):
        return self._hasher.digest()

    def hexdigest(self):
        return self._hasher.hexdigest()

    def hash(self, data):
        hasher = hashlib.sha3_256()
        hasher.update(data)
        return hasher.hexdigest()