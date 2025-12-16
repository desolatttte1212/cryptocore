import os


def read_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            return file.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"Input file not found: {file_path}")
    except PermissionError:
        raise PermissionError(f"Permission denied reading file: {file_path}")
    except Exception as e:
        raise IOError(f"Error reading file {file_path}: {e}")


def write_file(file_path, data):
    try:
        os.makedirs(os.path.dirname(file_path) if os.path.dirname(file_path) else '.',
                    exist_ok=True)

        with open(file_path, 'wb') as file:
            file.write(data)
    except PermissionError:
        raise PermissionError(f"Permission denied writing to file: {file_path}")
    except Exception as e:
        raise IOError(f"Error writing to file {file_path}: {e}")


def read_file_with_iv(file_path):
    data = read_file(file_path)
    if len(data) < 16:
        raise ValueError("Input file is too short to contain IV (minimum 16 bytes required)")

    iv = data[:16]
    ciphertext = data[16:]
    return iv, ciphertext