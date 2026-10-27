"""Chunked AES-256-GCM. Each chunk has its own nonce (random prefix + counter);
the AAD marks the final chunk so truncation is detected."""
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"FMGR\x01"
CHUNK = 64 * 1024
TAG = 16
MAX_CHUNKS = 2**32 - 1


class DecryptError(Exception):
    pass


def _nonce(prefix: bytes, i: int) -> bytes:
    return prefix + struct.pack(">I", i)


def encrypt_stream(dek: bytes, src, dst, prefix: bytes) -> None:
    aes = AESGCM(dek)
    dst.write(MAGIC + prefix)
    cur = src.read(CHUNK)
    i = 0
    while True:
        nxt = src.read(CHUNK)
        last = not nxt
        dst.write(aes.encrypt(_nonce(prefix, i), cur, b"\x01" if last else b"\x00"))
        if last:
            break
        cur, i = nxt, i + 1
        if i > MAX_CHUNKS:
            raise ValueError("File too large.")


def decrypt_stream(dek: bytes, src, dst) -> None:
    aes = AESGCM(dek)
    header = src.read(len(MAGIC) + 8)
    if len(header) != len(MAGIC) + 8 or not header.startswith(MAGIC):
        raise DecryptError("Not a filemgr encrypted file.")
    prefix = header[len(MAGIC):]
    cur = src.read(CHUNK + TAG)
    i = 0
    try:
        while True:
            nxt = src.read(CHUNK + TAG)
            last = not nxt
            dst.write(aes.decrypt(_nonce(prefix, i), cur, b"\x01" if last else b"\x00"))
            if last:
                break
            cur, i = nxt, i + 1
    except InvalidTag:
        raise DecryptError("Authentication failed: wrong key or file was tampered with.") from None
