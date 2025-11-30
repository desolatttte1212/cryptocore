import argparse
import sys
import os
import warnings
from .file_io import read_file, write_file
from .csprng import generate_random_bytes, is_weak_key
from .modes.ecb import ECBMode
from .modes.cbc import CBCMode
from .modes.cfb import CFBMode
from .modes.ofb import OFBMode
from .modes.ctr import CTRMode


def parse_arguments():
    parser = argparse.ArgumentParser(description='CryptoCore - AES Encryption Tool')

    parser.add_argument('--algorithm', required=True, choices=['aes'],
                        help='Cipher algorithm (currently only aes supported)')
    parser.add_argument('--mode', required=True, choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                        help='Mode of operation')

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--encrypt', action='store_true',
                              help='Perform encryption')
    action_group.add_argument('--decrypt', action='store_true',
                              help='Perform decryption')

    parser.add_argument('--key',
                        help='Encryption key as hexadecimal string (16 bytes for AES-128). Optional for encryption.')
    parser.add_argument('--input', required=True,
                        help='Input file path')
    parser.add_argument('--output',
                        help='Output file path (default: derived from input)')
    parser.add_argument('--iv',
                        help='Initialization vector as hexadecimal string (16 bytes, for decryption only)')

    return parser.parse_args()


def validate_key(key_hex):
    try:
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != 16:
            raise ValueError("AES-128 requires exactly 16 bytes (32 hex characters)")
        return key_bytes
    except ValueError as e:
        raise ValueError(f"Invalid key format: {e}")


def validate_iv(iv_hex):
    try:
        iv_bytes = bytes.fromhex(iv_hex)
        if len(iv_bytes) != 16:
            raise ValueError("IV must be exactly 16 bytes (32 hex characters)")
        return iv_bytes
    except ValueError as e:
        raise ValueError(f"Invalid IV format: {e}")


def derive_output_filename(input_file, operation):
    base_name = os.path.basename(input_file)
    if operation == 'encrypt':
        return f"{input_file}.enc"
    else:
        if input_file.endswith('.enc'):
            return input_file[:-4] + '.dec'
        else:
            return f"{input_file}.dec"


def get_mode_class(mode_name):
    modes = {
        'ecb': ECBMode,
        'cbc': CBCMode,
        'cfb': CFBMode,
        'ofb': OFBMode,
        'ctr': CTRMode
    }
    return modes.get(mode_name)


def main():
    try:
        args = parse_arguments()

        if args.encrypt and not args.key:
            key_bytes = generate_random_bytes(16)
            key_hex = key_bytes.hex()
            print(f"[INFO] Generated random key: {key_hex}")
        elif args.key:
            key_bytes = validate_key(args.key)

            if is_weak_key(key_bytes):
                warnings.warn(
                    "Warning: The provided key appears to be weak. "
                    "Consider using a randomly generated key for better security.",
                    UserWarning
                )
        else:
            raise ValueError("The --key argument is required for decryption operations")

        iv_bytes = None
        if args.iv:
            if args.encrypt:
                warnings.warn("IV is ignored during encryption. Using randomly generated IV.", UserWarning)
            else:
                iv_bytes = validate_iv(args.iv)

        operation = 'encrypt' if args.encrypt else 'decrypt'

        output_file = args.output or derive_output_filename(args.input, operation)

        mode_class = get_mode_class(args.mode)
        if not mode_class:
            raise ValueError(f"Unsupported mode: {args.mode}")

        cipher = mode_class(key_bytes)

        if args.encrypt:
            output_data = cipher.encrypt(args.input)
        else:
            output_data = cipher.decrypt(args.input, iv_bytes)

        write_file(output_file, output_data)

        print(f"Operation completed successfully: {args.input} -> {output_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()