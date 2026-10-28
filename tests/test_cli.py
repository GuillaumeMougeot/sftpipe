"""End to end: the sftpipe CLI against paramiko, OpenSSH's sftp-server, and a real sshd reached through ssh."""

import csv
import os

import pytest
from conftest import put_file

from sftpipe import sha1_64k_local
from sftpipe.cli import main

TREE = {"t/a.mp4": 3 * 65536 + 1, "t/b/c.mp4": 10, "t/b/d/e.txt": 0, "t/b/d/f.bin": 70 * 65536}


@pytest.fixture
def tree(remote):
    for rel, size in TREE.items():
        put_file(remote.root, rel, os.urandom(size))
    return remote


def rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def test_ls(tree, tmp_path):
    out = tmp_path / "ls.csv"
    assert tree.cli("-n", "3", "ls", "-r", "t", "t/a.mp4", "-o", out) == 0
    got = rows(out)
    assert {(r["path"], int(r["size"])) for r in got if r["dir"] == "0"} == set(TREE.items())
    assert {r["path"] for r in got if r["dir"] == "1"} == {"t/b", "t/b/d"}
    assert len(got) == len(TREE) + 3  # + 2 directories + t/a.mp4 given as an argument too


def test_hash_resumes(tree, tmp_path):
    out = tmp_path / "h.csv"
    assert tree.cli("-n", "3", "hash", "-r", "t", "-o", out) == 0
    first = rows(out)
    assert [r["path"] for r in first] == sorted(TREE)
    assert all(r["sha1_64k"] == sha1_64k_local(tree.root / r["path"]) for r in first)
    out.write_text("".join(out.read_text().splitlines(keepends=True)[:-1]))  # lose the last row
    (tmp_path / "list").write_text("t/b/c.mp4\nt/missing\n")
    assert tree.cli("hash", "-r", "t", "--from", tmp_path / "list", "-o", out) == 1  # t/missing fails
    second = rows(out)
    assert [r for r in second if r["path"] in TREE] == first and second[-1]["path"] == "t/missing"


def test_get_mirrors_and_resumes(tree, tmp_path):
    dest = tmp_path / "down"
    assert tree.cli("-n", "3", "get", "-r", "--verify", "t", dest) == 0
    for rel in TREE:
        assert (dest / rel).read_bytes() == (tree.root / rel).read_bytes()
    os.utime(dest / "t/a.mp4", (0, 0))  # unchanged size: a rerun leaves it alone
    assert tree.cli("get", "-r", "t", dest) == 0 and (dest / "t/a.mp4").stat().st_mtime == 0
    assert tree.cli("get", "t", dest) == 1  # a directory without -r
    assert not list(dest.rglob("*.part"))


def test_put_mirrors_and_keeps_existing(tree, tmp_path):
    src = tmp_path / "up"
    for rel, size in TREE.items():
        put_file(src, rel, os.urandom(size))
    assert tree.cli("-n", "3", "put", "-r", "--verify", src / "t", "u") == 0
    for rel in TREE:
        assert (tree.root / "u" / rel).read_bytes() == (src / rel).read_bytes()
    (tree.root / "u/t/b/d/f.bin").unlink()  # an interrupted run: a rerun uploads only what is missing
    (tree.root / "u/t/a.mp4").write_bytes(b"x" * TREE["t/a.mp4"])  # same size: skipped, not compared
    assert tree.cli("put", "-r", src / "t", "u") == 0
    assert (tree.root / "u/t/b/d/f.bin").read_bytes() == (src / "t/b/d/f.bin").read_bytes()
    assert (tree.root / "u/t/a.mp4").read_bytes() == b"x" * TREE["t/a.mp4"]
    (src / "t/b/c.mp4").write_bytes(b"new")
    assert tree.cli("put", "-r", src / "t", "u") == 1  # exists with another size: kept
    assert (tree.root / "u/t/b/c.mp4").read_bytes() != b"new"
    assert tree.cli("put", "-r", "--overwrite", src / "t", "u") == 0
    assert (tree.root / "u/t/b/c.mp4").read_bytes() == b"new"
    assert tree.cli("put", src / "t", "u") == 1  # a directory without -r
    assert not list((tree.root / "u").rglob("*.part"))


def test_mv_never_replaces(tree, tmp_path):
    (tmp_path / "list").write_text("t/b/d/f.bin\nt/b/x/f.bin\n")
    put_file(tree.root, "t/b/x/f.bin", b"other")
    put_file(tree.root, "t/y/z", b"")
    put_file(tree.root, "m/c.mp4", b"keep")
    f_bin = (tree.root / "t/b/d/f.bin").read_bytes()
    assert tree.cli("mv", "--from", tmp_path / "list", "t/a.mp4", "t/b/c.mp4", "t/y/", "m") == 1
    assert (tree.root / "m/a.mp4").stat().st_size == TREE["t/a.mp4"] and not (tree.root / "t/a.mp4").exists()
    assert (tree.root / "m/y/z").exists() and not (tree.root / "t/y").exists()
    assert (tree.root / "m/c.mp4").read_bytes() == b"keep" and (tree.root / "t/b/c.mp4").exists()  # target exists
    assert (tree.root / "m/f.bin").read_bytes() == f_bin and (tree.root / "t/b/x/f.bin").exists()  # same target


def test_ls_failed_connection_prints_nothing(capsys):
    assert main(["--cmd", "false", "ls", "t"]) == 1
    assert capsys.readouterr().out == ""


def test_probe(remote):
    assert remote.cli("-n", "2", "probe") == 0


def test_usage_errors(capsys):
    with pytest.raises(SystemExit) as e:
        main(["ls", "x"])
    assert e.value.code == 2 and "--host" in capsys.readouterr().err
