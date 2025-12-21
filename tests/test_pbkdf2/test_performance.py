import time
from src.kdf.pbkdf2 import pbkdf2_hmac_sha256


def test_pbkdf2_performance():
    password = b"performance_test"
    salt = b"salt"
    dklen = 32

    iterations_list = [10_000, 100_000, 1_000_000]
    times = {}

    for iters in iterations_list:
        start = time.time()
        pbkdf2_hmac_sha256(password, salt, iters, dklen)
        end = time.time()
        times[iters] = end - start
        print(f"Iterations: {iters:>7}, Time: {times[iters]:.3f}s")

    assert times[100_000] > times[10_000]
    assert times[1_000_000] > times[100_000]