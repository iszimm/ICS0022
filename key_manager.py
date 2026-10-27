"""Master password -> KEK (Argon2id) -> wraps/unwraps the random DEK."""
import json
import os
import secrets
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MIN_PASSWORD_LEN = 12
KDF_PARAMS = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}  # 64 MiB


class AuthError(Exception):
    pass


def vault_path() -> Path:
    home = Path(os.environ.get("FILEMGR_HOME", Path.home() / ".filemgr"))
    return home / "vault.key"


def _derive_kek(password: str, salt: bytes, p: dict) -> bytes:
    return hash_secret_raw(
        password.encode(), salt,
        time_cost=p["time_cost"], memory_cost=p["memory_cost"],
        parallelism=p["parallelism"], hash_len=32, type=Type.ID,
    )


def init_vault(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    path = vault_path()
    if path.exists():
        raise AuthError(f"Vault already exists at {path}.")
    salt = secrets.token_bytes(16)
    kek = _derive_kek(password, salt, KDF_PARAMS)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(kek).encrypt(nonce, dek, b"filemgr-vault-v1")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"version": 1, "salt": salt.hex(), "kdf": KDF_PARAMS,
            "nonce": nonce.hex(), "wrapped_dek": wrapped.hex()}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)


def unlock_vault(password: str) -> bytes:
    """Return the DEK. Unwrapping only succeeds with the right password
    (the GCM tag acts as the password verifier)."""
    path = vault_path()
    if not path.exists():
        raise AuthError("No vault found. Run 'init' first.")
    try:
        d = json.loads(path.read_text())
        kek = _derive_kek(password, bytes.fromhex(d["salt"]), d["kdf"])
        return AESGCM(kek).decrypt(
            bytes.fromhex(d["nonce"]), bytes.fromhex(d["wrapped_dek"]),
            b"filemgr-vault-v1")
    except InvalidTag:
        raise AuthError("Wrong master password.") from None
    except (KeyError, ValueError):
        raise AuthError("Vault file is corrupted.") from None
