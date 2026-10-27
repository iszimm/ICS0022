# Checkpoint 2 — Progress Note

**Done**
- CLI with `init`, `encrypt`, `decrypt` and file path arguments (argparse).
- Encryption/decryption with `cryptography` AES-256-GCM, streamed in 64 KiB chunks;
  per-chunk nonce and a final-chunk flag detect tampering and truncation (F1, F4, K5).
- Authentication: Argon2id derives a KEK from the master password; the random DEK is
  stored wrapped in `vault.key`. A wrong password fails the GCM tag check, so the vault
  only unlocks on success (A1, K1). Min 12-char password (A2). Prompt via getpass (A3, K6).
- Input validation: rejects missing/non-regular files, null bytes, symlinks, same
  input/output, nonexistent output dir, and overwriting without `--force` (F2, F6).
- Atomic writes: temp file + fsync + rename (F3). Tests in `test_filemgr.py`.

**Deviation from DESIGN.md:** no separate password verifier; the AES-GCM tag on the
wrapped DEK serves as the verifier (simpler, same security).

**Next (Checkpoint 3):** change-password, constant-time/lockout hardening, secure
delete option, more edge-case tests.
