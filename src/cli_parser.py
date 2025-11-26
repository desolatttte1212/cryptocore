import argparse
import sys
import os
from .file_io import read_file, write_file
from .modes.ecb import ECBMode


def parse_arguments():
    parser = argparse.ArgumentParser(description='CryptoCore - AES Encryption Tool')

    parser.add_argument('--algorithm', required=True, choices=['aes'],
                        help='Cipher algorithm (currently only aes supported)')
    parser.add_argument('--mode', required=True, choices=['ecb'],
                        help='Mode of operation (currently only ecb supported)')

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--encrypt', action='store_true',
                              help='Perform encryption')
    action_group.add_argument('--decrypt', action='store_true',
                              help='Perform decryption')

    parser.add_argument('--key', required=True,
                        help='Encryption key as hexadecimal string (16 bytes for AES-128)')
    parser.add_argument('--input', required=True,
                        help='Input file path')
    parser.add_argument('--output',
                        help='Output file path (default: derived from input)')

    return parser.parse_args()


def validate_key(key_hex):
    try:
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != 16:
            raise ValueError("AES-128 requires exactly 16 bytes (32 hex characters)")
        return key_bytes
    except ValueError as e:
        raise ValueError(f"Invalid key format: {e}")


def derive_output_filename(input_file, operation):
    base_name = os.path.basename(input_file)
    if operation == 'encrypt':
        return f"{input_file}.enc"
    else:  # decrypt
        if input_file.endswith('.enc'):
            return input_file[:-4] + '.dec'
        else:
            return f"{input_file}.dec"


def main():
    try:
        args = parse_arguments()

        key_bytes = validate_key(args.key)

        operation = 'encrypt' if args.encrypt else 'decrypt'

        output_file = args.output or derive_output_filename(args.input, operation)

        input_data = read_file(args.input)

        if args.algorithm == 'aes' and args.mode == 'ecb':
            ecb = ECBMode(key_bytes)
            if args.encrypt:
                output_data = ecb.encrypt(input_data)
            else:
                output_data = ecb.decrypt(input_data)
        else:
            raise ValueError(f"Unsupported algorithm/mode combination: {args.algorithm}/{args.mode}")

        write_file(output_file, output_data)

        print(f"Operation completed successfully: {args.input} -> {output_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()