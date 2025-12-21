# tests/unit/test_main.py
from src import __main__

def test_main_import():
    assert hasattr(__main__, 'main')