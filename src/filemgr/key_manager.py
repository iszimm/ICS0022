"""Auth / KDF / key management.

Responsibilities (see docs/DESIGN.md sections 2.1, 3.2, 3.3):
- Derive a Key-Encryption-Key (KEK) from the master password using
  Argon2id, with a per-vault random salt.
- Generate a random Data-Encryption-Key (DEK) at `init` time.
- Wrap (encrypt) the DEK with the KEK for storage, and unwrap it in
  memory when a command needs to encrypt/decrypt a file.
- Store/load the vault file: {salt, KDF params, wrapped DEK, password verifier}.
- Verify a supplied master password against the stored verifier using
  a constant-time comparison.

Nothing here should ever write the master password or the unwrapped
KEK/DEK to disk or to a log.
"""

# TODO (Checkpoint 2):
# - def derive_kek(password: bytes, salt: bytes, params) -> bytes
# - def generate_dek() -> bytes
# - def wrap_dek(dek: bytes, kek: bytes) -> bytes
# - def unwrap_dek(wrapped: bytes, kek: bytes) -> bytes
# - def create_vault(path, password) -> None
# - def load_vault(path, password) -> bytes  # returns unwrapped DEK
