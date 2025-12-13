from .sha256 import SHA256
from .SHA3_256 import SHA3_256

HASH_ALGORITHMS = {
    'sha256': SHA256,
    'sha3-256': SHA3_256,
    'sha3_256': SHA3_256,
}

def get_hasher(algorithm):
    algo = algorithm.lower()
    if algo not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}. "
                         f"Supported: {', '.join(HASH_ALGORITHMS.keys())}")
    return HASH_ALGORITHMS[algo]()