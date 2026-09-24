# File Manager

A command-line tool for encrypting and decrypting individual files under
a single master password, using authenticated encryption (AES-256-GCM)
and a password-hardening key derivation function (Argon2id).

## Project scope

- Encrypt/decrypt individual files on the local filesystem.
- One master password per vault, used to protect a randomly generated
  Data-Encryption-Key (DEK); the master password itself is never stored.


## Planned commands

| Command | Description |
|---|---|
| `filemgr init` | Create a new key vault; prompts for and sets the master password |
| `filemgr encrypt <file> [-o OUTPUT]` | Encrypt a file, prompts for the master password |
| `filemgr decrypt <file> [-o OUTPUT]` | Decrypt a file, prompts for the master password |
| `filemgr verify <file>` | Check a ciphertext file's authentication tag without writing plaintext |
| `filemgr list` | List files this tool has a record of encrypting |
| `filemgr change-password` | Re-wrap the DEK under a new master password |

> module skeleton only.

## Repository layout

```
file-manager/
├── docs/
│   └── DESIGN.md        # architecture, threat model, library choices
├── src/filemgr/
│   ├── cli.py            # command-line entry point
│   ├── key_manager.py     # KDF, KEK/DEK wrapping, vault file handling
│   ├── crypto_engine.py   # AES-256-GCM encrypt/decrypt
│   └── file_io.py         # streaming reads/writes, atomic file replace
├── tests/
├── requirements.txt
└── README.md
```

## Build & run

Requires Python 3.11+.

```bash
# clone and enter the repo
git clone <this-repo-url>
cd file-manager

# create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# run the CLI (once implemented)
python -m filemgr.cli --help
```

## Status

Checkpoint 1 (this commit): architecture, threat model, language/library
choice, and repo skeleton. No cryptographic code is implemented yet —
see `docs/DESIGN.md` for what's coming at Checkpoint 2.
