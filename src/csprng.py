import os


def generate_random_bytes(num_bytes):
    if num_bytes <= 0:
        raise ValueError("Number of bytes must be positive")

    try:
        return os.urandom(num_bytes)
    except Exception as e:
        raise OSError(f"Failed to generate random bytes: {e}")


def is_weak_key(key_bytes):
    if len(key_bytes) != 16:
        return False

    if all(b == 0 for b in key_bytes):
        return True

    sequential_up = all(key_bytes[i] == key_bytes[i - 1] + 1 for i in range(1, len(key_bytes)))
    sequential_down = all(key_bytes[i] == key_bytes[i - 1] - 1 for i in range(1, len(key_bytes)))

    if sequential_up or sequential_down:
        return True

    if len(key_bytes) >= 4:
        for i in range(0, len(key_bytes) - 4, 4):
            pattern = key_bytes[i:i + 4]
            if key_bytes.count(pattern) > 2:
                return True

    return False