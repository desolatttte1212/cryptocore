import argparse
import sys
import os
import warnings
from .file_io import read_file
from .csprng import is_weak_key, generate_random_bytes
from .modes.ecb import ECBMode
from .modes.cbc import CBCMode
from .modes.cfb import CFBMode
from .modes.ofb import OFBMode
from .modes.ctr import CTRMode
from .modes.gcm import gcm_encrypt, gcm_decrypt, AuthenticationError


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
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24, or 32 bytes")
        return key_bytes
    except ValueError as e:
        raise ValueError(f"Invalid key format: {e}")


def validate_iv(iv_hex):
    try:
        iv_bytes = bytes.fromhex(iv_hex)
        if len(iv_bytes) != 16:
            raise ValueError("IV must be exactly 16 bytes")
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
    if args.hmac and args.cmac:
        print("Error: --hmac and --cmac cannot be used together", file=sys.stderr)
        sys.exit(1)

    if args.hmac:
        if not args.key:
            print("Error: --key is required when using --hmac", file=sys.stderr)
            sys.exit(1)
        if args.algorithm != 'sha256':
            print("Error: HMAC is only supported with --algorithm sha256", file=sys.stderr)
            sys.exit(1)
        try:
            key_bytes = bytes.fromhex(args.key)
        except ValueError:
            print("Error: --key must be a valid hexadecimal string", file=sys.stderr)
            sys.exit(1)
        from .mac.hmac import HMAC
        hmac_obj = HMAC(key_bytes, 'sha256')
        hash_value = hmac_obj.compute_file(args.input)
        output_line = f"{hash_value} {args.input}"

    elif args.cmac:
        if not args.key:
            print("Error: --key is required when using --cmac", file=sys.stderr)
            sys.exit(1)
        if args.algorithm != 'aes':
            print("Error: --cmac requires --algorithm aes", file=sys.stderr)
            sys.exit(1)
        try:
            key_bytes = bytes.fromhex(args.key)
        except ValueError:
            print("Error: --key must be a valid hexadecimal string", file=sys.stderr)
            sys.exit(1)
        if len(key_bytes) != 16:
            print("Error: AES-CMAC requires a 16-byte key", file=sys.stderr)
            sys.exit(1)
        from .mac.cmac import AES_CMAC
        cmac_obj = AES_CMAC(key_bytes)
        hash_value = cmac_obj.compute_file(args.input)
        output_line = f"{hash_value} {args.input}"

    else:
        if args.key:
            print("Error: --key can only be used with --hmac or --cmac", file=sys.stderr)
            sys.exit(1)
        if args.verify:
            print("Error: --verify can only be used with --hmac or --cmac", file=sys.stderr)
            sys.exit(1)

        hasher = get_hasher(args.algorithm)
        with open(args.input, 'rb') as f:
            chunk_size = 8192
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        hash_value = hasher.hexdigest()
        output_line = f"{hash_value} {args.input}"

    if args.verify:
        try:
            with open(args.verify, 'r') as vf:
                expected_line = vf.read().strip()
            expected_hash = expected_line.split()[0]
            if expected_hash.lower() == hash_value.lower():
                print("[OK] Verification successful")
                sys.exit(0)
            else:
                print("[ERROR] Verification failed", file=sys.stderr)
                sys.exit(1)
        except Exception as e:
            print(f"Error reading verification file: {e}", file=sys.stderr)
            sys.exit(1)

    if args.output:
        try:
            with open(args.output, 'w') as out_f:
                out_f.write(output_line + '\n')
        except Exception as e:
            print(f"Error writing to output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output_line)


def run_crypto_command(args):
    try:
        key_bytes = None
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

        operation = 'encrypt' if args.encrypt else 'decrypt'
        output_file = args.output or derive_output_filename(args.input, operation)

        if args.mode == 'gcm':
            aad = bytes.fromhex(args.aad) if args.aad else b""
            if args.encrypt:
                plaintext = read_file(args.input)
                encrypted_data = gcm_encrypt(key_bytes, plaintext, aad)
                write_file(output_file, encrypted_data)
                print(f"[SUCCESS] Encryption completed: {args.input} -> {output_file}")
            else:
                encrypted_data = read_file(args.input)
                try:
                    plaintext = gcm_decrypt(key_bytes, encrypted_data, aad)
                    write_file(output_file, plaintext)
                    print("[SUCCESS] Decryption completed successfully")
                except AuthenticationError as e:
                    print(f"[ERROR] Authentication failed: {str(e)}", file=sys.stderr)
                    if os.path.exists(output_file):
                        os.remove(output_file)
                    sys.exit(1)
                except Exception as e:
                    print(f"[ERROR] Decryption failed: {e}", file=sys.stderr)
                    if os.path.exists(output_file):
                        os.remove(output_file)
                    sys.exit(1)
            return

        mode_class = get_mode_class(args.mode)
        if not mode_class:
            raise ValueError(f"Unsupported mode: {args.mode}")

        cipher = mode_class(key_bytes)

        if args.encrypt:
            output_data = cipher.encrypt(args.input)
            write_file(output_file, output_data)
            print(f"[SUCCESS] Encryption completed: {args.input} -> {output_file}")
        else:
            iv_bytes = None
            if args.iv:
                iv_bytes = validate_iv(args.iv)
            plaintext = cipher.decrypt(args.input, provided_iv=iv_bytes)
            write_file(output_file, plaintext)
            print(f"[SUCCESS] Decryption completed: {args.input} -> {output_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def run_derive_command(args):
    try:
        from .kdf.pbkdf2 import pbkdf2_hmac_sha256
        import os

        password = args.password.encode('utf-8')
        salt = bytes.fromhex(args.salt) if args.salt else os.urandom(16)
        key = pbkdf2_hmac_sha256(password, salt, args.iterations, args.length)

        output_line = f"{key.hex()} {salt.hex()}"

        if args.output:
            with open(args.output, 'wb') as f:
                f.write(key)
            print(f"[SUCCESS] Derived key written to {args.output}")
        else:
            print(output_line)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='CryptoCore - AES Encryption, Hashing, HMAC, CMAC, AEAD, and Key Derivation',
        prog='cryptocore'
    )
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # === Subcommand: dgst ===
    dgst_parser = subparsers.add_parser('dgst', help='Compute message digest (hash, HMAC, or CMAC)')
    dgst_parser.add_argument('--algorithm', required=True,
                             choices=['sha256', 'sha3-256', 'sha3_256', 'aes'],
                             help='Hash or cipher algorithm to use')
    dgst_parser.add_argument('--input', required=True, help='Input file to process')
    dgst_parser.add_argument('--output', help='Output file to write result')
    dgst_parser.add_argument('--hmac', action='store_true', help='Use HMAC')
    dgst_parser.add_argument('--cmac', action='store_true', help='Use AES-CMAC')
    dgst_parser.add_argument('--key', help='Key for HMAC or CMAC (hex string)')
    dgst_parser.add_argument('--verify', help='Verify against expected hash/MAC file')

    # === Subcommand: crypto ===
    crypto_parser = subparsers.add_parser('crypto', help='AES encryption/decryption')
    crypto_parser.add_argument('--algorithm', required=True, choices=['aes'], help='Cipher algorithm')
    crypto_parser.add_argument('--mode', required=True,
                               choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm'],
                               help='Mode of operation')
    action_group = crypto_parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('--encrypt', action='store_true', help='Perform encryption')
    action_group.add_argument('--decrypt', action='store_true', help='Perform decryption')
    crypto_parser.add_argument('--key', help='Encryption key as hex string')
    crypto_parser.add_argument('--input', required=True, help='Input file path')
    crypto_parser.add_argument('--output', help='Output file path')
    crypto_parser.add_argument('--iv', help='IV as hex string (optional for decryption)')
    crypto_parser.add_argument('--aad', help='Additional Authenticated Data (hex, for GCM only)')

    # === Subcommand: derive (Sprint 7) ===
    derive_parser = subparsers.add_parser('derive', help='Derive cryptographic key from password')
    derive_parser.add_argument('--password', required=True, help='Password string')
    derive_parser.add_argument('--salt', help='Salt as hexadecimal string (16 random bytes if omitted)')
    derive_parser.add_argument('--iterations', type=int, default=100000,
                               help='PBKDF2 iteration count (default: 100000)')
    derive_parser.add_argument('--length', type=int, default=32,
                               help='Desired key length in bytes (default: 32)')
    derive_parser.add_argument('--algorithm', choices=['pbkdf2'], default='pbkdf2',
                               help='KDF algorithm (currently only pbkdf2)')
    derive_parser.add_argument('--output', help='Write raw key to file (optional)')

    args = parser.parse_args()

    if args.command == 'dgst':
        run_hash_command(args)
    elif args.command == 'crypto':
        run_crypto_command(args)
    elif args.command == 'derive':
        run_derive_command(args)


def write_file(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def get_hasher(algorithm):
    from .hash import get_hasher as _get_hasher
    return _get_hasher(algorithm)


if __name__ == "__main__":
    main()