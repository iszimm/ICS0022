"""Structured audit log: one JSON object per line in <home>/filemgr.log.

Callers never pass secrets. As a second layer, any field whose name looks
sensitive, and any bytes value, is replaced with [redacted] before writing."""
import json
import logging
import os
from datetime import datetime, timezone

import key_manager

log = logging.getLogger("filemgr")
log.propagate = False
log.addHandler(logging.NullHandler())

SENSITIVE = ("pass", "secret", "key", "dek", "kek", "token", "salt", "nonce", "wrapped")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.fromtimestamp(record.created, timezone.utc)
        entry = {"ts": ts.isoformat(timespec="seconds"),
                 "level": record.levelname,
                 "event": record.getMessage()}
        entry.update(getattr(record, "fields", {}))
        # ensure_ascii escapes control characters, so input cannot forge log lines
        return json.dumps(entry, ensure_ascii=True)


def setup() -> None:
    home = key_manager.home_dir()
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = home / "filemgr.log"
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
    for h in list(log.handlers):
        log.removeHandler(h)
        h.close()
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(JsonFormatter())
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def _clean(name, value):
    if any(s in name.lower() for s in SENSITIVE) or isinstance(value, (bytes, bytearray)):
        return "[redacted]"
    if isinstance(value, str):
        return value[:200]
    return value


def event(name: str, level: str = "INFO", **fields) -> None:
    safe = {k: _clean(k, v) for k, v in fields.items()}
    log.log(getattr(logging, level), name, extra={"fields": safe})
