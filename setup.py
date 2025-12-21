# setup.py
from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="0.5.0",
    packages=find_packages(),
    package_dir={"": "."},  # ← корень = текущая директория
    install_requires=[
        'pycryptodome>=3.20.0',
        'numba>=0.50.0',
        'numpy>=1.19.0'
    ],
    entry_points={
        'console_scripts': [
            'cryptocore=src.cli_parser:main',
        ],
    },
    python_requires='>=3.6',
)