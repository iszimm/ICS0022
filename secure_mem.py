"""Best-effort handling of key material in memory.

Python cannot promise that no other copy of a secret exists, but keys are kept
in mutable bytearrays, locked in RAM when the OS allows it, and zeroed as soon
as they are no longer needed. Core dumps are switched off so a crash does not
write keys to disk."""
import ctypes
import sys

try:
    import resource
except ImportError:  # Windows
    resource = None

_libc = None
if sys.platform != "win32":
    try:
        _libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        _libc = None


def _addr(buf: bytearray) -> int:
    return ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))


def protect(buf: bytearray) -> bool:
    """Try to keep buf out of swap with mlock. Returns False if not possible."""
    if _libc is None or not buf:
        return False
    try:
        return _libc.mlock(ctypes.c_void_p(_addr(buf)), ctypes.c_size_t(len(buf))) == 0
    except Exception:
        return False


def wipe(buf) -> None:
    """Overwrite a bytearray with zeros (and unlock it). Ignores None/bytes."""
    if not isinstance(buf, bytearray) or not buf:
        return
    ctypes.memset(_addr(buf), 0, len(buf))
    if _libc is not None:
        try:
            _libc.munlock(ctypes.c_void_p(_addr(buf)), ctypes.c_size_t(len(buf)))
        except Exception:
            pass


def disable_core_dumps() -> None:
    if resource is not None:
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError):
            pass
