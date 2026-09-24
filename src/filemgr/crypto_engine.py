"""AES-256-GCM file encryption/decryption.

Responsibilities (see docs/DESIGN.md sections 3.1, 3.3):
- Encrypt file contents with AES-256-GCM using the unwrapped DEK.
- Generate a fresh random 96-bit nonce per encryption call (threat K5:
  never reuse a nonce under the same key).
- Produce/consume a file header of {salt, nonce, tag} alongside the
  ciphertext payload.
- Stream data in fixed-size chunks rather than loading whole files into
  memory (threat F4).
- Fail closed on authentication tag mismatch (threat F1) — never emit
  partially-decrypted output.
"""

# TODO (Checkpoint 2):
# - def encrypt_stream(dek: bytes, infile, outfile) -> None
# - def decrypt_stream(dek: bytes, infile, outfile) -> None
