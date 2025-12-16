import abc
from typing import BinaryIO


class HashFunction(abc.ABC):

    def __init__(self, block_size: int, output_size: int):

        self.block_size = block_size
        self.output_size = output_size
        self.reset()

    @abc.abstractmethod
    def reset(self) -> None:
        pass

    @abc.abstractmethod
    def update(self, data: bytes) -> None:
        pass

    @abc.abstractmethod
    def digest(self) -> bytes:
        pass

    def hexdigest(self) -> str:
        return self.digest().hex()

    def hash_bytes(self, data: bytes) -> bytes:
        self.reset()
        self.update(data)
        return self.digest()

    def hash_hex(self, data: bytes) -> str:
        return self.hash_bytes(data).hex()

    def hash_file(self, file_path: str) -> str:

        self.reset()

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                self.update(chunk)

        return self.hexdigest()