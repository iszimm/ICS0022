"""Path validation, atomic file writing and secure deletion."""
import os
import secrets
import tempfile
from pathlib import Path

import key_manager
from errors import PathError

MAX_PATH = 4096


def root_dir() -> Path:
    """Files may only be read or written inside this directory (default: cwd)."""
    return Path(os.environ.get("FILEMGR_ROOT") or os.getcwd()).resolve()


def _resolve(path: str) -> Path:
    if (not isinstance(path, str) or not path or len(path) > MAX_PATH
            or any(ord(c) < 32 or ord(c) == 127 for c in path)):
        raise PathError("Invalid path.", "empty, too long or contains control characters")
    p = Path(path)
    if p.is_symlink():
        raise PathError("Refusing to use a symbolic link.", f"symlink: {path!r}")
    r = p.resolve()
    # Checked before existence so the error does not reveal what is outside the root.
    if not r.is_relative_to(root_dir()) or r.is_relative_to(key_manager.home_dir().resolve()):
        raise PathError("Path is not allowed.", f"outside root or inside vault dir: {path!r}")
    return r


def check_input(path: str) -> Path:
    p = _resolve(path)
    if not p.exists():
        raise PathError("File not found.", f"missing: {path!r}")
    if not p.is_file():
        raise PathError("Not a regular file.", f"not a file: {path!r}")
    if not os.access(p, os.R_OK):
        raise PathError("Cannot read file.", f"unreadable: {path!r}")
    return p


def check_output(path: str, src: Path, force: bool) -> Path:
    p = _resolve(path)
    if p == src:
        raise PathError("Output must differ from input.", "output equals input")
    if not p.parent.is_dir():
        raise PathError("Output directory does not exist.", f"no parent dir: {path!r}")
    if p.exists():
        if not p.is_file():
            raise PathError("Output is not a regular file.", f"output not a file: {path!r}")
        if not force:
            raise PathError("Output already exists (use --force to overwrite).",
                            f"exists: {path!r}")
    return p


def secure_delete(path: Path, passes: int = 3) -> None:
    """Overwrite the file with random data, flush to disk, then unlink.
    This is best effort: SSD wear levelling and copy-on-write or journaling
    file systems may keep old copies of the blocks."""
    fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        size = os.fstat(fd).st_size
        for _ in range(passes):
            os.lseek(fd, 0, os.SEEK_SET)
            left = size
            while left > 0:
                left -= os.write(fd, os.urandom(min(left, 1 << 20)))
            os.fsync(fd)
    finally:
        os.close(fd)
    os.unlink(path)


def atomic_write(dest: Path, writer) -> None:
    """Call writer(fileobj) on a private temp file in the same dir, fsync, then rename.
    If anything fails the temp file (which may hold partial plaintext) is wiped."""
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".filemgr-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            writer(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            try:
                secure_delete(Path(tmp), passes=1)
            except OSError:
                os.unlink(tmp)
        raise


def random_prefix() -> bytes:
    return secrets.token_bytes(8)
