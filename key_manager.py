"""Master password -> KEK (Argon2id) -> wraps/unwraps a random DEK.
Each user has a separate vault file, bound to that user name."""
import json
import os
import re
import secrets
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import secure_mem
from errors import AuthError, InputError

MIN_PASSWORD_LEN = 12
MAX_PASSWORD_LEN = 256
KDF_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}  # 64 MiB
USER_RE = re.compile(r"[a-z][a-z0-9_]{2,31}")
AUTH_MSG = "Authentication failed."


def validate_username(name: str) -> str:
    if not USER_RE.fullmatch(name or ""):
        raise InputError(
            "Invalid user name (3-32 chars: lowercase letters, digits, underscore; "
            "must start with a letter).", f"bad user name: {(name or '')[:40]!r}")
    return name


def home_dir() -> Path:
    return Path(os.environ.get("FILEMGR_HOME") or Path.home() / ".filemgr")


def vault_path(user: str) -> Path:
    # user has already been validated, so it cannot contain separators or dots
    return home_dir() / "users" / user / "vault.key"


def _aad(user: str) -> bytes:
    return b"filemgr-vault-v2:" + user.encode()


def _params_ok(p) -> bool:
    try:
        return (1 <= p["time_cost"] <= 10
                and 8192 <= p["memory_cost"] <= 262144
                and 1 <= p["parallelism"] <= 16)
    except (KeyError, TypeError):
        return False


def _derive_kek(password: str, salt: bytes, p: dict) -> bytearray:
    raw = hash_secret_raw(
        password.encode(), salt,
        time_cost=p["time_cost"], memory_cost=p["memory_cost"],
        parallelism=p["parallelism"], hash_len=32, type=Type.ID,
    )
    return bytearray(raw)


def init_vault(user: str, password: str) -> None:
    validate_username(user)
    if not (MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN):
        raise InputError(f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.",
                         "password length rejected")
    path = vault_path(user)
    if path.exists():
        raise InputError("Could not create the account.", "user already exists")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    kek = _derive_kek(password, salt, KDF_PARAMS)
    dek = bytearray(AESGCM.generate_key(bit_length=256))
    try:
        wrapped = AESGCM(kek).encrypt(nonce, bytes(dek), _aad(user))
        for d in (home_dir(), home_dir() / "users", path.parent):
            d.mkdir(mode=0o700, exist_ok=True)
        data = {"version": 2, "salt": salt.hex(), "kdf": KDF_PARAMS,
                "nonce": nonce.hex(), "wrapped_dek": wrapped.hex()}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
    finally:
        secure_mem.wipe(kek)
        secure_mem.wipe(dek)


def unlock_vault(user: str, password: str) -> bytearray:
    """Return the DEK as a bytearray; the caller must wipe it.
    The GCM tag on the wrapped key acts as the password check. Every failure
    gives the same message so callers cannot tell a wrong password from an
    unknown user or a damaged vault."""
    validate_username(user)
    path = vault_path(user)
    kek = None
    try:
        if len(password) > MAX_PASSWORD_LEN:
            raise AuthError(AUTH_MSG, "password too long")
        if not path.exists():
            # same amount of work as a real attempt, so timing does not reveal valid users
            secure_mem.wipe(_derive_kek(password, bytes(16), KDF_PARAMS))
            raise AuthError(AUTH_MSG, "unknown user")
        d = json.loads(path.read_text())
        if not _params_ok(d["kdf"]):
            raise AuthError(AUTH_MSG, "vault kdf parameters out of range")
        kek = _derive_kek(password, bytes.fromhex(d["salt"]), d["kdf"])
        dek = bytearray(AESGCM(kek).decrypt(
            bytes.fromhex(d["nonce"]), bytes.fromhex(d["wrapped_dek"]), _aad(user)))
        secure_mem.protect(dek)
        return dek
    except InvalidTag:
        raise AuthError(AUTH_MSG, "wrong password or vault tampered") from None
    except (KeyError, ValueError, TypeError, OSError):
        raise AuthError(AUTH_MSG, "vault unreadable or corrupted") from None
    finally:
        secure_mem.wipe(kek)
