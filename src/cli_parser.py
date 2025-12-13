import argparse
import sys
import os
import warnings
from .file_io import read_file, write_file
from .csprng import is_weak_key
from .modes.ecb import ECBMode
from .modes.cbc import CBCMode
from .modes.cfb import CFBMode
from .modes.ofb import OFBMode
from .modes.ctr import CTRMode
from .hash import get_hasher


def get_mode_class(mode_name):
    modes = {
        'ecb': ECBMode,
        'cbc': CBCMode,
        'cfb': CFBMode,
        'ofb': OFBMode,
        'ctr': CTRMode
    }
    return modes.get(mode_name)


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


def run_hash_command(args):
    try:
        hasher = get_hasher(args.algorithm)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.input, 'rb') as f:
            chunk_size = 8192
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        hash_value = hasher.hexdigest()
        output_line = f"{hash_value} {args.input}"

        if args.output:
            try:
                with open(args.output, 'w') as out_f:
                    out_f.write(output_line + '\n')
            except Exception as e:
                print(f"Error writing to output file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(output_line)

    except FileNotFoundError:
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def run_crypto_command(args):
    try:
        if args.encrypt and not args.key:
            from .csprng import generate_random_bytes
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
        if args.decrypt and args.iv:
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


def main():
    parser = argparse.ArgumentParser(
        description='CryptoCore - AES Encryption & Hashing Tool',
        prog='cryptocore'
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    dgst_parser = subparsers.add_parser('dgst', help='Compute message digest (hash)')
    dgst_parser.add_argument('--algorithm', required=True,
                             choices=['sha256', 'sha3_256'],
                             help='Hash algorithm to use')
    dgst_parser.add_argument('--input', required=True,
                             help='Input file to hash')
    dgst_parser.add_argument('--output',
                             help='Output file to write hash (optional)')

    crypto_parser = subparsers.add_parser('crypto', help='AES encryption/decryption')
    crypto_parser.add_argument('--algorithm', required=True, choices=['aes'],
                               help='Cipher algorithm (currently only aes supported)')
    crypto_parser.add_argument('--mode', required=True,
                               choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'],
                               help='Mode of operation')

    action_group = crypto_parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--encrypt', action='store_true', help='Perform encryption')
    action_group.add_argument('--decrypt', action='store_true', help='Perform decryption')

    crypto_parser.add_argument('--key', help='Encryption key as hex string (16 bytes for AES-128)')
    crypto_parser.add_argument('--input', required=True, help='Input file path')
    crypto_parser.add_argument('--output', help='Output file path')
    crypto_parser.add_argument('--iv', help='Initialization vector as hex string (for decryption only)')

    args, unknown = parser.parse_known_args()

    if args.command == 'dgst':
        run_hash_command(args)
    elif args.command == 'crypto':
        run_crypto_command(args)
    else:
        old_parser = argparse.ArgumentParser(description='CryptoCore - AES Encryption Tool')
        old_parser.add_argument('--algorithm', required=True, choices=['aes'])
        old_parser.add_argument('--mode', required=True, choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr'])
        action_group = old_parser.add_mutually_exclusive_group(required=True)
        action_group.add_argument('--encrypt', action='store_true')
        action_group.add_argument('--decrypt', action='store_true')
        old_parser.add_argument('--key')
        old_parser.add_argument('--input', required=True)
        old_parser.add_argument('--output')
        old_parser.add_argument('--iv')
        old_args = old_parser.parse_args()
        old_args.command = 'crypto'
        run_crypto_command(old_args)


if __name__ == "__main__":
    main()