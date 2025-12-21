
import os
import tempfile
from src.file_io import read_file, write_file, read_file_with_iv


def test_file_io():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"test data")
        tmp_path = tmp.name

    try:
        data = read_file(tmp_path)
        assert data == b"test data"

        out_path = tmp_path + ".out"
        write_file(out_path, b"output")
        assert read_file(out_path) == b"output"

        with open(tmp_path, "wb") as f:
            f.write(b"IV12345678901234" + b"ciphertext")
        iv, ct = read_file_with_iv(tmp_path)
        assert iv == b"IV12345678901234"
        assert ct == b"ciphertext"

    finally:
        for f in [tmp_path, tmp_path + ".out"]:
            if os.path.exists(f):
                os.remove(f)