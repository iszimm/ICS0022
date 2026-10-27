# filemgr — encrypted file manager (ICS0022)

Encrypts/decrypts files under one master password.
AES-256-GCM (chunked, streamed) + Argon2id key derivation + wrapped random DEK.

## Setup (clean machine, Python 3.11+)
```bash
git clone https://github.com/iszimm/ICS0022 && cd ICS0022
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
```bash
python cli.py init                      # create vault, choose master password (min 12 chars)
python cli.py encrypt secret.txt        # -> secret.txt.enc
python cli.py decrypt secret.txt.enc    # -> secret.txt
python cli.py encrypt a.txt -o out.enc --force
```
The password is always prompted (no echo), never passed as an argument.
The vault lives in `~/.filemgr/vault.key` (override with `FILEMGR_HOME`).
For scripts/tests only, `FILEMGR_PASSWORD` can supply the password (less secure).

## Tests
```bash
pip install pytest && pytest -q
```

## Layout
`cli.py` CLI · `key_manager.py` Argon2id/KEK/DEK/auth · `crypto_engine.py` AES-GCM · `file_io.py` path checks + atomic write · `docs/DESIGN.md` threat model
