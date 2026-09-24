"""Command-line entry point for filemgr.

Planned commands (see README.md):
    init              create a new key vault, set the master password
    encrypt <file>    encrypt a file
    decrypt <file>    decrypt a file
    verify <file>     check a ciphertext's auth tag without decrypting fully
    list              list files this tool has encrypted
    change-password   re-wrap the DEK under a new master password

Design constraint (see docs/DESIGN.md, threat A3): the master password
must never be accepted as a plain CLI argument. Always prompt via
getpass so it doesn't land in shell history or `ps` output.
"""

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="filemgr")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="create a new key vault")

    encrypt_p = subparsers.add_parser("encrypt", help="encrypt a file")
    encrypt_p.add_argument("file")
    encrypt_p.add_argument("-o", "--output")

    decrypt_p = subparsers.add_parser("decrypt", help="decrypt a file")
    decrypt_p.add_argument("file")
    decrypt_p.add_argument("-o", "--output")

    verify_p = subparsers.add_parser("verify", help="verify a ciphertext file")
    verify_p.add_argument("file")

    subparsers.add_parser("list", help="list encrypted files")
    subparsers.add_parser("change-password", help="rotate the master password")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    # TODO (Checkpoint 2): dispatch to key_manager / crypto_engine / file_io
    raise NotImplementedError(f"'{args.command}' not implemented yet — Checkpoint 1 is design-only")


if __name__ == "__main__":
    main()
