from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'pycryptodome>=3.20.0',
    ],
    entry_points={
        'console_scripts': [
            'cryptocore=src.cli_parser:main',
        ],
    },
    python_requires='>=3.6',
)