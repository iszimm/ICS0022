import json
import os
import re
from pathlib import Path

import pytest

import audit
import cli
import crypto_engine as ce
import file_io as fio
import key_manager as km
import secure_mem

PW = "correct horse battery"
PW2 = "another long password"
HERE = Path(__file__).parent


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("FILEMGR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("FILEMGR_PASSWORD", PW)
    monkeypatch.setenv("FILEMGR_USER", "alice")
    monkeypatch.delenv("FILEMGR_ROOT", raising=False)
    monkeypatch.chdir(tmp_path)
    # cheap Argon2 settings so the suite runs fast (one test checks the real ones)
    monkeypatch.setattr(km, "KDF_PARAMS", {"time_cost": 1, "memory_cost": 8192, "parallelism": 1})


def login_as(monkeypatch, user, pw):
    monkeypatch.setenv("FILEMGR_USER", user)
    monkeypatch.setenv("FILEMGR_PASSWORD", pw)


def log_text(tmp_path):
    return (tmp_path / "home" / "filemgr.log").read_text()


def log_events(tmp_path):
    return [json.loads(line) for line in log_text(tmp_path).splitlines()]


def two_users(tmp_path, monkeypatch):
    """alice owns a.enc; bobby is a second registered user."""
    (tmp_path / "a").write_bytes(b"alice secret data")
    assert cli.main(["init"]) == 0
    assert cli.main(["encrypt", "a"]) == 0
    login_as(monkeypatch, "bobby", PW2)
    assert cli.main(["init"]) == 0
    return (tmp_path / "a.enc").read_bytes()


# ---------- encryption and decryption correctness ----------

def test_roundtrip_multi_chunk(tmp_path):
    data = os.urandom(200_000)
    (tmp_path / "a.bin").write_bytes(data)
    assert cli.main(["init"]) == 0
    assert cli.main(["encrypt", "a.bin"]) == 0
    assert (tmp_path / "a.bin.enc").read_bytes() != data
    assert cli.main(["decrypt", "a.bin.enc", "-o", "b.bin"]) == 0
    assert (tmp_path / "b.bin").read_bytes() == data


def test_empty_file(tmp_path):
    (tmp_path / "e").write_bytes(b"")
    cli.main(["init"]); cli.main(["encrypt", "e"])
    assert cli.main(["decrypt", "e.enc", "-o", "e2"]) == 0
    assert (tmp_path / "e2").read_bytes() == b""


def test_exact_chunk_boundary(tmp_path):
    data = os.urandom(ce.CHUNK * 2)
    (tmp_path / "a").write_bytes(data)
    cli.main(["init"]); cli.main(["encrypt", "a"])
    assert cli.main(["decrypt", "a.enc", "-o", "b"]) == 0
    assert (tmp_path / "b").read_bytes() == data


def test_same_input_gives_different_ciphertext(tmp_path):
    (tmp_path / "a").write_bytes(b"same data")
    cli.main(["init"]); cli.main(["encrypt", "a"])
    first = (tmp_path / "a.enc").read_bytes()
    cli.main(["encrypt", "a", "-f"])
    assert (tmp_path / "a.enc").read_bytes() != first


def test_plaintext_not_visible_in_ciphertext(tmp_path):
    (tmp_path / "a").write_bytes(b"VERY-RECOGNISABLE-TEXT" * 50)
    cli.main(["init"]); cli.main(["encrypt", "a"])
    assert b"RECOGNISABLE" not in (tmp_path / "a.enc").read_bytes()


def test_tamper_and_truncate(tmp_path):
    (tmp_path / "a").write_bytes(os.urandom(150_000))
    cli.main(["init"]); cli.main(["encrypt", "a"])
    raw = (tmp_path / "a.enc").read_bytes()
    h = ce.header_len("alice")
    pos = h + 20
    (tmp_path / "t.enc").write_bytes(raw[:pos] + bytes([raw[pos] ^ 1]) + raw[pos + 1:])
    assert cli.main(["decrypt", "t.enc", "-o", "t"]) == 1
    (tmp_path / "c.enc").write_bytes(raw[:h + ce.CHUNK + ce.TAG])      # drop last chunks
    assert cli.main(["decrypt", "c.enc", "-o", "c"]) == 1
    (tmp_path / "h.enc").write_bytes(raw[:h])                          # header only
    assert cli.main(["decrypt", "h.enc", "-o", "h"]) == 1
    (tmp_path / "x.enc").write_bytes(raw + b"extra")                   # appended bytes
    assert cli.main(["decrypt", "x.enc", "-o", "x"]) == 1
    for name in "tchx":
        assert not (tmp_path / name).exists()
    assert not list(tmp_path.glob(".filemgr-*"))                       # no temp leftovers


def test_not_an_encrypted_file(tmp_path):
    (tmp_path / "plain").write_text("hello")
    cli.main(["init"])
    assert cli.main(["decrypt", "plain", "-o", "out"]) == 1
    assert not (tmp_path / "out").exists()


# ---------- secure deletion ----------

def test_delete_overwrites_then_removes(tmp_path, monkeypatch):
    (tmp_path / "a").write_bytes(b"A" * 5000)
    cli.main(["init"]); cli.main(["encrypt", "a"])
    original = (tmp_path / "a.enc").read_bytes()
    seen = []
    real_unlink = os.unlink

    def spy(p, *a, **k):
        if str(p).endswith("a.enc"):
            seen.append(Path(p).read_bytes())   # what is on disk right before unlink
        return real_unlink(p, *a, **k)
    monkeypatch.setattr(os, "unlink", spy)
    assert cli.main(["delete", "a.enc", "-y"]) == 0
    assert not (tmp_path / "a.enc").exists()
    assert len(seen) == 1 and len(seen[0]) == len(original) and seen[0] != original


def test_delete_asks_for_confirmation(tmp_path, monkeypatch):
    (tmp_path / "a").write_text("x")
    cli.main(["init"]); cli.main(["encrypt", "a"])
    monkeypatch.setattr("builtins.input", lambda _: "n")
    assert cli.main(["delete", "a.enc"]) == 0
    assert (tmp_path / "a.enc").exists()


def test_delete_refuses_plain_files(tmp_path):
    (tmp_path / "plain").write_text("keep me")
    cli.main(["init"])
    assert cli.main(["delete", "plain", "-y"]) == 1
    assert (tmp_path / "plain").read_text() == "keep me"


def test_shred_original_after_encrypt(tmp_path):
    (tmp_path / "a").write_bytes(b"to be shredded")
    cli.main(["init"])
    assert cli.main(["encrypt", "a", "--shred-original"]) == 0
    assert not (tmp_path / "a").exists()
    assert cli.main(["decrypt", "a.enc", "-o", "back"]) == 0
    assert (tmp_path / "back").read_bytes() == b"to be shredded"


def test_failed_decrypt_wipes_partial_output(tmp_path, monkeypatch):
    (tmp_path / "a").write_bytes(os.urandom(150_000))
    cli.main(["init"]); cli.main(["encrypt", "a"])
    raw = (tmp_path / "a.enc").read_bytes()
    (tmp_path / "t.enc").write_bytes(raw[:ce.header_len("alice") + ce.CHUNK + ce.TAG])
    wiped = []
    real = fio.secure_delete
    monkeypatch.setattr(fio, "secure_delete", lambda p, passes=3: (wiped.append(str(p)), real(p, passes)))
    assert cli.main(["decrypt", "t.enc", "-o", "t"]) == 1
    assert len(wiped) == 1 and ".filemgr-" in wiped[0]


# ---------- authentication failure paths ----------

def test_wrong_password(tmp_path, monkeypatch, capsys):
    (tmp_path / "a").write_text("x")
    cli.main(["init"])
    monkeypatch.setenv("FILEMGR_PASSWORD", "wrong wrong wrong")
    capsys.readouterr()
    assert cli.main(["encrypt", "a"]) == 1
    assert capsys.readouterr().err.strip() == "Error: Authentication failed."
    assert not (tmp_path / "a.enc").exists()


def test_unknown_user_looks_like_wrong_password(tmp_path, monkeypatch, capsys):
    cli.main(["init"])
    (tmp_path / "a").write_text("x")
    monkeypatch.setenv("FILEMGR_PASSWORD", "wrong wrong wrong")
    capsys.readouterr()
    cli.main(["encrypt", "a"])
    wrong_pw = capsys.readouterr().err
    monkeypatch.setenv("FILEMGR_USER", "nobody")
    cli.main(["encrypt", "a"])
    assert capsys.readouterr().err == wrong_pw


def test_short_and_long_password(monkeypatch):
    monkeypatch.setenv("FILEMGR_PASSWORD", "short")
    assert cli.main(["init"]) == 1
    monkeypatch.setenv("FILEMGR_PASSWORD", "x" * 300)
    assert cli.main(["init"]) == 1
    assert not km.vault_path("alice").exists()


def test_duplicate_account():
    assert cli.main(["init"]) == 0
    assert cli.main(["init"]) == 1


def test_password_confirmation_mismatch(monkeypatch):
    monkeypatch.delenv("FILEMGR_PASSWORD")
    answers = iter(["first password long", "second password long"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(answers))
    assert cli.main(["init"]) == 1
    assert not km.vault_path("alice").exists()


def test_corrupted_vault(tmp_path, capsys):
    (tmp_path / "a").write_text("x")
    cli.main(["init"])
    km.vault_path("alice").write_text("{not json")
    capsys.readouterr()
    assert cli.main(["encrypt", "a"]) == 1
    assert capsys.readouterr().err.strip() == "Error: Authentication failed."


def test_vault_cannot_be_copied_to_another_user(monkeypatch):
    cli.main(["init"])
    other = km.vault_path("mallory")
    other.parent.mkdir(parents=True)
    other.write_bytes(km.vault_path("alice").read_bytes())
    login_as(monkeypatch, "mallory", PW)
    with pytest.raises(km.AuthError):
        km.unlock_vault("mallory", PW)


def test_vault_with_huge_kdf_params_rejected():
    cli.main(["init"])
    p = km.vault_path("alice")
    d = json.loads(p.read_text())
    d["kdf"]["memory_cost"] = 2**30
    p.write_text(json.dumps(d))
    with pytest.raises(km.AuthError):
        km.unlock_vault("alice", PW)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_private_file_permissions(tmp_path):
    (tmp_path / "a").write_text("x")
    cli.main(["init"]); cli.main(["encrypt", "a"])
    assert oct(km.vault_path("alice").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "a.enc").stat().st_mode & 0o777) == "0o600"
    assert oct((tmp_path / "home" / "filemgr.log").stat().st_mode & 0o777) == "0o600"


def test_real_kdf_parameters_are_strong():
    import importlib.util
    spec = importlib.util.spec_from_file_location("km_fresh", HERE / "key_manager.py")
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    assert fresh.KDF_PARAMS["memory_cost"] >= 65536 and fresh.KDF_PARAMS["time_cost"] >= 3
    assert fresh._params_ok(fresh.KDF_PARAMS)


# ---------- input validation ----------

def test_validation(tmp_path):
    cli.main(["init"])
    assert cli.main(["encrypt", "missing"]) == 1
    (tmp_path / "a").write_text("x")
    cli.main(["encrypt", "a"])
    assert cli.main(["encrypt", "a"]) == 1          # no overwrite
    assert cli.main(["encrypt", "a", "-f"]) == 0
    os.symlink("a", "link")
    assert cli.main(["encrypt", "link"]) == 1


def test_output_validation(tmp_path):
    (tmp_path / "a").write_text("x")
    (tmp_path / "adir").mkdir()
    cli.main(["init"])
    assert cli.main(["encrypt", "a", "-o", "a"]) == 1             # same as input
    assert cli.main(["encrypt", "a", "-o", "adir", "-f"]) == 1    # output is a directory
    assert cli.main(["encrypt", "a", "-o", "nodir/out"]) == 1     # parent missing
    assert cli.main(["encrypt", "adir"]) == 1                     # input is a directory


def test_path_traversal_blocked(tmp_path, monkeypatch, capsys):
    work = tmp_path / "work"
    work.mkdir()
    (tmp_path / "outside.txt").write_text("not yours")
    monkeypatch.chdir(work)
    cli.main(["init"])
    (work / "ok").write_text("x")
    for args in (["encrypt", "../outside.txt"],
                 ["encrypt", str(tmp_path / "outside.txt")],
                 ["encrypt", "ok", "-o", "../stolen.enc"],
                 ["decrypt", "../outside.txt"],
                 ["delete", "../outside.txt", "-y"],
                 ["encrypt", "/etc/passwd"]):
        assert cli.main(args) == 1, args
    assert not (tmp_path / "stolen.enc").exists()
    assert (tmp_path / "outside.txt").read_text() == "not yours"
    # the message must not reveal whether a file outside the root exists
    capsys.readouterr()
    cli.main(["encrypt", "../outside.txt"]); a = capsys.readouterr().err
    cli.main(["encrypt", "../does-not-exist"]); b = capsys.readouterr().err
    assert a == b


def test_symlinked_directory_cannot_escape_root(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "f").write_text("x")
    monkeypatch.chdir(work)
    os.symlink(tmp_path / "outside", work / "d")
    cli.main(["init"])
    assert cli.main(["encrypt", "d/f"]) == 1


def test_vault_directory_is_off_limits(tmp_path):
    cli.main(["init"])
    vault = os.path.relpath(km.vault_path("alice"), tmp_path)
    assert cli.main(["encrypt", vault, "--shred-original"]) == 1
    assert cli.main(["delete", vault, "-y"]) == 1
    assert km.vault_path("alice").exists()


@pytest.mark.parametrize("bad", ["", "a\nb", "x" * 5000, "a\x1b[31mb", "a\x7fb"])
def test_bad_path_strings(bad):
    with pytest.raises(fio.PathError):
        fio.check_input(bad)


def test_nul_byte_in_path():
    with pytest.raises(fio.PathError):
        fio.check_input("a\x00b")


@pytest.mark.parametrize("name", ["a; touch pwned", "$(touch pwned)", "`touch pwned`",
                                  "a && touch pwned", "-rf", "a|b", "it's \"quoted\""])
def test_command_injection_in_filenames(tmp_path, name):
    (tmp_path / name).write_text("data")
    cli.main(["init"])
    assert cli.main(["encrypt", "--", name]) == 0
    assert cli.main(["decrypt", "-o", "out", "--", name + ".enc"]) == 0
    assert (tmp_path / "out").read_text() == "data"
    assert not (tmp_path / "pwned").exists()


def test_no_shell_or_dynamic_code_in_source():
    banned = re.compile(r"subprocess|os\.system|os\.popen|shell\s*=\s*True|\beval\(|\bexec\(|pickle")
    for f in HERE.glob("*.py"):
        if f.name == Path(__file__).name:
            continue
        assert not banned.search(f.read_text()), f.name


@pytest.mark.parametrize("user", ["", "ab", "../evil", "a/b", "ALICE", "bob smith",
                                  "x" * 40, "a\nb", "alice;rm", "1alice", "al.ice"])
def test_bad_user_names(tmp_path, monkeypatch, user):
    monkeypatch.setenv("FILEMGR_USER", user)
    assert cli.main(["init"]) == 1
    assert not (tmp_path / "home" / "users").exists()
    assert not (tmp_path.parent / "evil").exists()


def test_user_option_overrides_env(tmp_path):
    assert cli.main(["--user", "carol", "init"]) == 0
    assert km.vault_path("carol").exists()


def test_password_not_accepted_on_command_line():
    with pytest.raises(SystemExit):
        cli.main(["--password", "x", "init"])


# ---------- per-user access control ----------

def test_other_user_cannot_decrypt(tmp_path, monkeypatch):
    two_users(tmp_path, monkeypatch)
    assert cli.main(["decrypt", "a.enc", "-o", "stolen"]) == 1
    assert not (tmp_path / "stolen").exists()
    assert any(e.get("category") == "access" and e.get("user") == "bobby"
               for e in log_events(tmp_path))


def test_other_user_cannot_delete(tmp_path, monkeypatch):
    two_users(tmp_path, monkeypatch)
    assert cli.main(["delete", "a.enc", "-y"]) == 1
    assert (tmp_path / "a.enc").exists()


def test_other_user_cannot_overwrite_or_shred(tmp_path, monkeypatch):
    raw = two_users(tmp_path, monkeypatch)
    (tmp_path / "mine").write_text("bobby's file")
    assert cli.main(["encrypt", "mine", "-o", "a.enc", "-f"]) == 1
    assert cli.main(["encrypt", "a.enc", "--shred-original"]) == 1
    assert (tmp_path / "a.enc").read_bytes() == raw


def test_editing_owner_field_does_not_grant_access(tmp_path, monkeypatch):
    raw = two_users(tmp_path, monkeypatch)
    forged = raw[:14] + b"bobby" + raw[19:]            # alice -> bobby, same length
    (tmp_path / "forged.enc").write_bytes(forged)
    assert cli.main(["decrypt", "forged.enc", "-o", "out"]) == 1
    assert not (tmp_path / "out").exists()


def test_owner_still_has_access(tmp_path, monkeypatch):
    two_users(tmp_path, monkeypatch)
    login_as(monkeypatch, "alice", PW)
    assert cli.main(["decrypt", "a.enc", "-o", "out"]) == 0
    assert (tmp_path / "out").read_bytes() == b"alice secret data"


def test_engine_enforces_owner_directly():
    import io
    dek = bytearray(os.urandom(32))
    out = io.BytesIO()
    ce.encrypt_stream(dek, "alice", io.BytesIO(b"hi"), out, os.urandom(8))
    with pytest.raises(ce.AccessDenied):
        ce.decrypt_stream(dek, "bobby", io.BytesIO(out.getvalue()), io.BytesIO())


# ---------- logging and error messages ----------

def test_log_is_structured_json(tmp_path):
    (tmp_path / "a").write_text("x")
    cli.main(["init"]); cli.main(["encrypt", "a"]); cli.main(["decrypt", "a.enc", "-o", "b"])
    events = log_events(tmp_path)
    names = [e["event"] for e in events]
    assert names == ["account_created", "auth_ok", "encrypt_ok", "auth_ok", "decrypt_ok"]
    assert all({"ts", "level", "event"} <= set(e) for e in events)
    assert events[2]["file"] == "a" and events[2]["user"] == "alice"


def test_failures_are_logged(tmp_path, monkeypatch):
    (tmp_path / "a").write_text("x")
    cli.main(["init"])
    monkeypatch.setenv("FILEMGR_PASSWORD", "wrong wrong wrong")
    cli.main(["encrypt", "a"])
    last = log_events(tmp_path)[-1]
    assert last["event"] == "encrypt_failed" and last["category"] == "auth"
    assert last["level"] == "WARNING"


def test_no_secret_ever_reaches_the_log(tmp_path, monkeypatch):
    (tmp_path / "a").write_bytes(os.urandom(100_000))
    cli.main(["init"]); cli.main(["encrypt", "a"]); cli.main(["decrypt", "a.enc", "-o", "b"])
    monkeypatch.setenv("FILEMGR_PASSWORD", "wrong wrong wrong")
    cli.main(["encrypt", "a", "-f"])                           # failed login
    login_as(monkeypatch, "bobby", PW2)
    cli.main(["init"]); cli.main(["decrypt", "a.enc", "-o", "c"])   # access denied
    login_as(monkeypatch, "alice", PW)
    dek = km.unlock_vault("alice", PW)
    vault = json.loads(km.vault_path("alice").read_text())
    text = log_text(tmp_path)
    secrets_ = [PW, PW2, "wrong wrong wrong", bytes(dek).hex(), vault["wrapped_dek"],
                vault["salt"], vault["nonce"]]
    for s in secrets_:
        assert s not in text
    secure_mem.wipe(dek)


def test_logger_redacts_sensitive_fields(tmp_path):
    audit.setup()
    audit.event("probe", password="hunter2hunter2", dek=b"\x01\x02", note=bytearray(b"zz"),
                file="ok.txt")
    last = log_events(tmp_path)[-1]
    assert last["password"] == "[redacted]" and last["dek"] == "[redacted]"
    assert last["note"] == "[redacted]" and last["file"] == "ok.txt"
    assert "hunter2" not in log_text(tmp_path)


def test_log_lines_cannot_be_forged(tmp_path):
    odd = 'x","event":"fake'                                  # quote characters in a file name
    (tmp_path / odd).write_text("x")
    cli.main(["init"]); cli.main(["encrypt", "--", odd])
    events = log_events(tmp_path)                             # every line still valid JSON
    assert [e["event"] for e in events].count("fake") == 0


def test_unexpected_errors_are_generic(tmp_path, monkeypatch, capsys):
    (tmp_path / "a").write_text("x")
    cli.main(["init"])

    def boom(*a, **k):
        raise RuntimeError("secret-internal-detail /srv/app/internals.py")
    monkeypatch.setattr(fio, "atomic_write", boom)
    capsys.readouterr()
    assert cli.main(["encrypt", "a"]) == 1
    err = capsys.readouterr().err
    assert err.strip() == "Error: an internal error occurred."
    last = log_events(tmp_path)[-1]
    assert last["reason"] == "RuntimeError" and "secret-internal" not in log_text(tmp_path)


def test_error_messages_do_not_leak_paths(tmp_path, monkeypatch, capsys):
    (tmp_path / "a").write_text("x")
    cli.main(["init"])
    capsys.readouterr()
    cli.main(["init"])
    cli.main(["encrypt", "missing"])
    cli.main(["encrypt", "../x"])
    cli.main(["encrypt", "a", "-o", "nodir/out"])
    cli.main(["decrypt", "a"])
    monkeypatch.setenv("FILEMGR_PASSWORD", "wrong wrong wrong")
    cli.main(["encrypt", "a"])
    err = capsys.readouterr().err
    assert str(tmp_path) not in err and "home" not in err and "Traceback" not in err


# ---------- secure memory handling ----------

def test_wipe_zeroes_buffer():
    buf = bytearray(os.urandom(32))
    secure_mem.wipe(buf)
    assert buf == bytearray(32)
    secure_mem.wipe(None)               # must not raise
    secure_mem.wipe(b"immutable")


def test_unlock_returns_mutable_buffer():
    cli.main(["init"])
    dek = km.unlock_vault("alice", PW)
    assert isinstance(dek, bytearray) and len(dek) == 32 and any(dek)
    secure_mem.wipe(dek)


def _capture_deks(monkeypatch):
    captured = []
    real = km.unlock_vault

    def spy(u, p):
        d = real(u, p)
        captured.append(d)
        return d
    monkeypatch.setattr(km, "unlock_vault", spy)
    return captured


def test_key_wiped_after_success(tmp_path, monkeypatch):
    (tmp_path / "a").write_text("x")
    cli.main(["init"])
    captured = _capture_deks(monkeypatch)
    assert cli.main(["encrypt", "a"]) == 0
    assert len(captured) == 1 and captured[0] == bytearray(32)


def test_key_wiped_after_failure(tmp_path, monkeypatch):
    (tmp_path / "a").write_bytes(os.urandom(100_000))
    cli.main(["init"]); cli.main(["encrypt", "a"])
    raw = bytearray((tmp_path / "a.enc").read_bytes())
    raw[ce.header_len("alice") + 5] ^= 1
    (tmp_path / "t.enc").write_bytes(raw)
    captured = _capture_deks(monkeypatch)
    assert cli.main(["decrypt", "t.enc", "-o", "t"]) == 1
    assert len(captured) == 1 and captured[0] == bytearray(32)


@pytest.mark.skipif(os.name != "posix", reason="needs resource module")
def test_core_dumps_disabled():
    import resource
    cli.main(["init"])
    assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
