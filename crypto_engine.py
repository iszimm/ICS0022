"""Chunked AES-256-GCM.

File layout:  magic(5) | nonce prefix(8) | owner length(1) | owner | chunks

Each chunk has its own nonce (random prefix + counter). The AAD of every chunk
holds the owner name and a flag marking the last chunk, so truncation and
changes to the owner field are detected."""
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from errors import AccessDenied, DecryptError

MAGIC = b"FMGR\x02"
PREFIX_LEN = 8
CHUNK = 64 * 1024
TAG = 16
MAX_CHUNKS = 2**32 - 1


def header_len(owner: str) -> int:
    return len(MAGIC) + PREFIX_LEN + 1 + len(owner)


def _nonce(prefix: bytes, i: int) -> bytes:
    return prefix + struct.pack(">I", i)


def _aad(owner: bytes, last: bool) -> bytes:
    return owner + (b"\x01" if last else b"\x00")


def read_header(src):
    """Return (nonce prefix, owner name) or raise DecryptError."""
    fixed = src.read(len(MAGIC) + PREFIX_LEN + 1)
    if len(fixed) != len(MAGIC) + PREFIX_LEN + 1 or not fixed.startswith(MAGIC):
        raise DecryptError("Not a filemgr encrypted file.", "bad header")
    prefix = fixed[len(MAGIC):len(MAGIC) + PREFIX_LEN]
    n = fixed[-1]
    raw = src.read(n)
    if not 3 <= n <= 32 or len(raw) != n:
        raise DecryptError("Not a filemgr encrypted file.", "bad owner field")
    try:
        return prefix, raw.decode("ascii")
    except UnicodeDecodeError:
        raise DecryptError("Not a filemgr encrypted file.", "bad owner field") from None


def read_owner(path) -> str:
    with open(path, "rb") as f:
        return read_header(f)[1]


def check_owner(owner: str, user: str) -> None:
    if owner != user:
        raise AccessDenied("Access denied.", f"file owned by {owner!r}, requested by {user!r}")


def encrypt_stream(dek, owner: str, src, dst, prefix: bytes) -> None:
    aes = AESGCM(dek)
    ob = owner.encode("ascii")
    dst.write(MAGIC + prefix + bytes([len(ob)]) + ob)
    cur = src.read(CHUNK)
    i = 0
    while True:
        nxt = src.read(CHUNK)
        last = not nxt
        dst.write(aes.encrypt(_nonce(prefix, i), cur, _aad(ob, last)))
        if last:
            break
        cur, i = nxt, i + 1
        if i > MAX_CHUNKS:
            raise ValueError("File too large.")


def decrypt_stream(dek, user: str, src, dst) -> None:
    prefix, owner = read_header(src)
    check_owner(owner, user)          # enforced here too, not only in the CLI
    aes = AESGCM(dek)
    ob = owner.encode("ascii")
    cur = src.read(CHUNK + TAG)
    i = 0
    try:
        while True:
            nxt = src.read(CHUNK + TAG)
            last = not nxt
            dst.write(aes.decrypt(_nonce(prefix, i), cur, _aad(ob, last)))
            if last:
                break
            cur, i = nxt, i + 1
            if i > MAX_CHUNKS:
                raise DecryptError("Decryption failed.", "too many chunks")
    except InvalidTag:
        raise DecryptError("Decryption failed: wrong key or the file was modified.",
                           "authentication tag mismatch") from None
