"""Filesystem I/O helpers.

Responsibilities (see docs/DESIGN.md section 3.1):
- Resolve/canonicalize and validate paths (threat F2: path traversal).
- Refuse to follow symlinks on output paths (threat F6).
- Write output atomically: temp file in the same directory, fsync,
  then os.replace() over the destination (threat F3).
"""

# TODO (Checkpoint 2):
# - def safe_resolve_path(path: str) -> Path
# - def atomic_write(destination: Path, data_iter) -> None
