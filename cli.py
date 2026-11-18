#!/usr/bin/env python3
"""filemgr - per-user encrypted file manager (encrypt, decrypt, secure delete)."""
import argparse
import getpass
import os
import sys
from contextlib import contextmanager
from pathlib import Path

import audit
import crypto_engine as ce
import file_io as fio
import key_manager as km
import secure_mem
from errors import AccessDenied, AuthError, DecryptError, FilemgrError


def get_password(confirm=False) -> str:
    # FILEMGR_PASSWORD is for scripted tests only (less secure). There is
    # deliberately no --password option, so the password never shows up in
    # the process list or shell history.
    env = os.environ.get("FILEMGR_PASSWORD")
    if env:
        return env
    pw = getpass.getpass("Master password: ")
    if confirm and pw != getpass.getpass("Confirm password: "):
        raise AuthError("Passwords do not match.", "confirmation mismatch")
    return pw


@contextmanager
def session(user):
    """Authenticate, hand out the DEK, and always wipe it afterwards."""
    dek = km.unlock_vault(user, get_password())
    audit.event("auth_ok", user=user)
    try:
        yield dek
    finally:
        secure_mem.wipe(dek)


def not_foreign(path: Path, user: str) -> None:
    """Refuse to touch an existing filemgr file that belongs to someone else."""
    if not path.exists():
        return
    try:
        owner = ce.read_owner(path)
    except DecryptError:
        return                      # not a filemgr file, so it has no owner
    except OSError:
        raise AccessDenied("Access denied.", "cannot inspect existing file") from None
    ce.check_owner(owner, user)


def cmd_init(args, user):
    km.init_vault(user, get_password(confirm=True))
    audit.event("account_created", user=user)
    print(f"Account '{user}' created.")
    print("WARNING: if you lose the master password, your data cannot be recovered.")


def cmd_encrypt(args, user):
    src = fio.check_input(args.file)
    out = fio.check_output(args.output or str(src) + ".enc", src, args.force)
    with session(user) as dek:
        not_foreign(src, user)
        not_foreign(out, user)
        prefix = fio.random_prefix()

        def write(dst):
            with open(src, "rb") as f:
                ce.encrypt_stream(dek, user, f, dst, prefix)
        fio.atomic_write(out, write)
    audit.event("encrypt_ok", user=user, file=src.name, output=out.name)
    print(f"Encrypted -> {out}")
    if args.shred_original:
        fio.secure_delete(src)
        audit.event("shred_ok", user=user, file=src.name)
        print("Original file securely deleted.")


def cmd_decrypt(args, user):
    src = fio.check_input(args.file)
    default = str(src)[:-4] if src.suffix == ".enc" else str(src) + ".dec"
    out = fio.check_output(args.output or default, src, args.force)
    with session(user) as dek:
        ce.check_owner(ce.read_owner(src), user)
        not_foreign(out, user)

        def write(dst):
            with open(src, "rb") as f:
                ce.decrypt_stream(dek, user, f, dst)
        fio.atomic_write(out, write)
    audit.event("decrypt_ok", user=user, file=src.name, output=out.name)
    print(f"Decrypted -> {out}")


def cmd_delete(args, user):
    src = fio.check_input(args.file)
    with session(user):
        ce.check_owner(ce.read_owner(src), user)
        if not args.yes and input(f"Permanently delete {src.name}? [y/N] ").strip().lower() != "y":
            print("Cancelled.")
            return
        fio.secure_delete(src)
    audit.event("delete_ok", user=user, file=src.name)
    print("File securely deleted.")


def build_parser():
    ap = argparse.ArgumentParser(prog="filemgr", description=__doc__)
    ap.add_argument("-u", "--user", help="user name (or set FILEMGR_USER)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create an account and set its master password"
                   ).set_defaults(fn=cmd_init)
    for name, fn in (("encrypt", cmd_encrypt), ("decrypt", cmd_decrypt)):
        p = sub.add_parser(name, help=f"{name} a file")
        p.add_argument("file")
        p.add_argument("-o", "--output", help="output path")
        p.add_argument("-f", "--force", action="store_true", help="overwrite existing output")
        if name == "encrypt":
            p.add_argument("--shred-original", action="store_true",
                           help="securely delete the plaintext after encrypting")
        p.set_defaults(fn=fn)
    d = sub.add_parser("delete", help="securely delete one of your encrypted files")
    d.add_argument("file")
    d.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    d.set_defaults(fn=cmd_delete)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    secure_mem.disable_core_dumps()
    user = None
    try:
        audit.setup()
        user = km.validate_username(args.user or os.environ.get("FILEMGR_USER") or "")
        args.fn(args, user)
        return 0
    except FilemgrError as e:
        audit.event(f"{args.command}_failed", "WARNING", user=user,
                    category=e.category, reason=e.detail)
        print(f"Error: {e.public}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception as e:
        # Only the exception type is logged: messages can contain paths or data.
        audit.event(f"{args.command}_failed", "ERROR", user=user,
                    category="internal", reason=type(e).__name__)
        print("Error: an internal error occurred.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
