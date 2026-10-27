"""Path validation and atomic file writing."""
import os
import secrets
import tempfile
from pathlib import Path


class PathError(Exception):
    pass


def check_input(path: str) -> Path:
    if not path or "\x00" in path:
        raise PathError("Invalid path.")
    p = Path(path).expanduser()
    if p.is_symlink():
        raise PathError(f"Refusing to follow symlink: {path}")
    p = p.resolve()
    if not p.exists():
        raise PathError(f"File not found: {path}")
    if not p.is_file():
        raise PathError(f"Not a regular file: {path}")
    if not os.access(p, os.R_OK):
        raise PathError(f"Cannot read: {path}")
    return p


def check_output(path: str, src: Path, force: bool) -> Path:
    if "\x00" in path:
        raise PathError("Invalid path.")
    p = Path(path).expanduser()
    if p.is_symlink():
        raise PathError(f"Refusing to write through symlink: {path}")
    p = p.resolve()
    if p == src:
        raise PathError("Output must differ from input.")
    if not p.parent.is_dir():
        raise PathError(f"Output directory does not exist: {p.parent}")
    if p.exists() and not force:
        raise PathError(f"{p} already exists (use --force to overwrite).")
    return p


def atomic_write(dest: Path, writer) -> None:
    """Call writer(fileobj) on a temp file in the same dir, fsync, then rename."""
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".filemgr-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            writer(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def random_prefix() -> bytes:
    return secrets.token_bytes(8)
