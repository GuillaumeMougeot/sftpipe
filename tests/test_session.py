"""Session and Pool against real servers over stdio: paramiko (ERDA stand-in) and OpenSSH's sftp-server."""

import asyncio
import os
import shlex
import sys

import pytest
from conftest import Remote, fake_cmd, put_file

from sftpipe import BLOCK, Pool, Session, SFTPError, core, sha1_64k_local

SIZES = [0, 1, BLOCK - 1, BLOCK, BLOCK + 1, 5 * BLOCK + 7]


def go(remote: Remote, coro_fn):  # type: ignore[no-untyped-def]
    async def body():  # type: ignore[no-untyped-def]
        async with Session(remote.cmd) as s:
            return await coro_fn(s)

    return asyncio.run(body())


@pytest.mark.parametrize("size", SIZES)
def test_hash_matches_local(stdio, size, monkeypatch):
    monkeypatch.setattr(core, "SEG", 2 * BLOCK)  # several check-file requests per file
    f = put_file(stdio.root, "f", os.urandom(size))

    async def both(s):
        return [await s.sha1_64k("f", server) for server in (None, False)]

    for attrs, h in go(stdio, both):
        assert (attrs.size, h) == (size, sha1_64k_local(f))


def test_check_file_only_where_offered(stdio):
    put_file(stdio.root, "f", b"x")
    offered = go(stdio, lambda s: asyncio.sleep(0, "check-file" in s.ext))
    assert offered == (stdio.kind == "fake")
    if not offered:
        with pytest.raises(SFTPError) as e:
            go(stdio, lambda s: s.sha1_64k("f", server=True))
        assert e.value.errno == 8  # unsupported


def test_listdir_pipelined(stdio):
    for i in range(300):  # paramiko sends 16 names per READDIR: > 16 rounds of pipelined requests
        put_file(stdio.root, f"d/{i}", b"")
    assert sorted(int(n) for n, _ in go(stdio, lambda s: s.listdir("d"))) == list(range(300))


@pytest.mark.parametrize("size", [0, 70 * BLOCK + 3])  # 70 blocks: more than one window of requests
def test_put_get_roundtrip(stdio, tmp_path, size):
    up, down = put_file(tmp_path, "up", os.urandom(size)), tmp_path / "down"

    async def roundtrip(s):
        await s.put(str(up), "f")
        return await s.get("f", str(down))

    attrs = go(stdio, roundtrip)
    assert down.read_bytes() == up.read_bytes() and attrs.size == size
    assert int(down.stat().st_mtime) == attrs.mtime and not (tmp_path / "down.part").exists()


def test_put_refuses_existing_unless_overwrite(stdio, tmp_path):
    put_file(stdio.root, "f", b"old")
    up = put_file(tmp_path, "up", b"new")
    with pytest.raises(SFTPError):
        go(stdio, lambda s: s.put(str(up), "f"))
    go(stdio, lambda s: s.put(str(up), "f", overwrite=True))
    assert (stdio.root / "f").read_bytes() == b"new"


def test_dirs_rename_remove_errors(stdio):
    put_file(stdio.root, "a", b"1")

    async def ops(s):
        await s.makedirs("x/y/z")
        await s.makedirs("x/y/z")  # idempotent
        await s.rename("a", "x/b")
        with pytest.raises(SFTPError):  # paramiko fails at open, OpenSSH at our is_dir check
            await s.sha1_64k("x")
        await s.remove("x/b")
        with pytest.raises(SFTPError) as e:
            await s.stat("x/b")
        return e.value.errno

    assert go(stdio, ops) == 2  # no such file
    assert (stdio.root / "x/y/z").is_dir() and not (stdio.root / "a").exists()


def test_rejected_after_version(tmp_path, monkeypatch):
    """MiG (ERDA) answers VERSION and only then refuses sessions over its cap: that must count as a failed login."""
    monkeypatch.setenv("SFTPIPE_FAKE_REJECT", "1")
    with pytest.raises(ConnectionError, match="Too many open sessions"):
        go(Remote("fake", tmp_path, ["--cmd", shlex.join(fake_cmd(tmp_path))]), lambda s: s.stat("."))


def test_pool_logs_in_once_when_login_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("SFTPIPE_FAKE_REJECT", "1")
    attempts = tmp_path / "attempts"
    cmd = ["sh", "-c", f"echo >> {attempts}; exec {shlex.join(fake_cmd(tmp_path))}"]

    async def nothing(s, it, push):
        pass

    with pytest.raises(ConnectionError):
        asyncio.run(Pool(cmd, sessions=8).run(range(10), nothing))
    assert attempts.read_text() == "\n"


def test_pool_retries_on_session_loss_and_walks(tmp_path, monkeypatch):
    monkeypatch.setenv("SFTPIPE_FAKE_DIE", str(tmp_path / "died"))
    files = {f"t/{i % 7}/{i}": os.urandom(i) for i in range(60)}
    for rel, data in files.items():
        put_file(tmp_path / "srv", rel, data)
    pool, hashes = Pool(fake_cmd(tmp_path / "srv"), sessions=3), {}

    async def fn(s, path, push):
        hashes[path] = (await s.sha1_64k(path))[1]

    async def main():
        walked = await pool.walk(["t"])
        await pool.run([p for p, _ in walked], fn)
        return walked

    walked = asyncio.run(main())
    assert sorted(p for p, _ in walked) == sorted(files) and (tmp_path / "died").exists()
    assert hashes == {p: sha1_64k_local(tmp_path / "srv" / p) for p in files}


def test_failing_command_reports_stderr():
    with pytest.raises(ConnectionError, match="denied"):
        asyncio.run(Session([sys.executable, "-c", "import sys; sys.exit('denied')"]).__aenter__())


def test_concurrent_makedirs(stdio):
    async def race(s):
        await asyncio.gather(*(s.makedirs("a/b/c") for _ in range(8)))  # all find a/b missing, all create it

    go(stdio, race)
    assert (stdio.root / "a/b/c").is_dir()
    put_file(stdio.root, "f", b"")
    with pytest.raises(SFTPError):
        go(stdio, lambda s: s.makedirs("f/g"))  # a file in the way still fails
