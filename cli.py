#!/usr/bin/env python3
"""filemgr - encrypt/decrypt files under one master password."""
import argparse
import getpass
import os
import sys

import crypto_engine as ce
import file_io as fio
import key_manager as km


def get_password(confirm=False) -> str:
    # FILEMGR_PASSWORD is for scripted tests only (less secure).
    env = os.environ.get("FILEMGR_PASSWORD")
    if env:
        return env
    pw = getpass.getpass("Master password: ")
    if confirm and pw != getpass.getpass("Confirm password: "):
        raise km.AuthError("Passwords do not match.")
    return pw


def cmd_init(args):
    km.init_vault(get_password(confirm=True))
    print(f"Vault created at {km.vault_path()}")
    print("WARNING: if you lose the master password, your data cannot be recovered.")


def cmd_encrypt(args):
    src = fio.check_input(args.file)
    out = fio.check_output(args.output or str(src) + ".enc", src, args.force)
    dek = km.unlock_vault(get_password())
    prefix = fio.random_prefix()

    def write(dst):
        with open(src, "rb") as f:
            ce.encrypt_stream(dek, f, dst, prefix)
    fio.atomic_write(out, write)
    print(f"Encrypted -> {out}")


def cmd_decrypt(args):
    src = fio.check_input(args.file)
    default = str(src)[:-4] if src.suffix == ".enc" else str(src) + ".dec"
    out = fio.check_output(args.output or default, src, args.force)
    dek = km.unlock_vault(get_password())

    def write(dst):
        with open(src, "rb") as f:
            ce.decrypt_stream(dek, f, dst)
    fio.atomic_write(out, write)
    print(f"Decrypted -> {out}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="filemgr", description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create the vault and set master password").set_defaults(fn=cmd_init)
    for name, fn in (("encrypt", cmd_encrypt), ("decrypt", cmd_decrypt)):
        p = sub.add_parser(name, help=f"{name} a file")
        p.add_argument("file")
        p.add_argument("-o", "--output", help="output path")
        p.add_argument("-f", "--force", action="store_true", help="overwrite existing output")
        p.set_defaults(fn=fn)
    args = ap.parse_args(argv)
    try:
        args.fn(args)
    except (km.AuthError, fio.PathError, ce.DecryptError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
