import os
import pytest
import cli

PW = "correct horse battery"


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("FILEMGR_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("FILEMGR_PASSWORD", PW)
    monkeypatch.chdir(tmp_path)


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


def test_wrong_password(tmp_path, monkeypatch):
    (tmp_path / "a").write_text("x")
    cli.main(["init"])
    monkeypatch.setenv("FILEMGR_PASSWORD", "wrong wrong wrong")
    assert cli.main(["encrypt", "a"]) == 1


def test_tamper_and_truncate(tmp_path):
    (tmp_path / "a").write_bytes(os.urandom(150_000))
    cli.main(["init"]); cli.main(["encrypt", "a"])
    raw = (tmp_path / "a.enc").read_bytes()
    (tmp_path / "t.enc").write_bytes(raw[:20] + bytes([raw[20] ^ 1]) + raw[21:])
    assert cli.main(["decrypt", "t.enc", "-o", "t"]) == 1
    (tmp_path / "c.enc").write_bytes(raw[:13 + 65536 + 16])  # drop last chunk
    assert cli.main(["decrypt", "c.enc", "-o", "c"]) == 1
    assert not (tmp_path / "t").exists()


def test_validation(tmp_path):
    cli.main(["init"])
    assert cli.main(["encrypt", "missing"]) == 1
    (tmp_path / "a").write_text("x")
    cli.main(["encrypt", "a"])
    assert cli.main(["encrypt", "a"]) == 1          # no overwrite
    assert cli.main(["encrypt", "a", "-f"]) == 0
    os.symlink("a", "link")
    assert cli.main(["encrypt", "link"]) == 1


def test_short_password(monkeypatch):
    monkeypatch.setenv("FILEMGR_PASSWORD", "short")
    assert cli.main(["init"]) == 1
