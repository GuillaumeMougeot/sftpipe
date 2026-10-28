"""sftpipe: fast parallel SFTP over OpenSSH. Connection settings come from options, SFTPIPE_* environment variables
or ~/.ssh/config. See `sftpipe COMMAND -h`."""

import argparse
import asyncio
import contextlib
import csv
import os
import posixpath
import shlex
import sys
import time
from collections.abc import Awaitable, Callable, Iterable, Iterator
from pathlib import Path
from typing import IO, Any

from .core import Pool, Push, Session, SFTPError, log, sha1_64k_local, ssh_argv

HASH_COLS = ["path", "size", "mtime", "sha1_64k", "error"]
Fn = Callable[[Session, Any, Push], Awaitable[object]]


class Progress:
    """Counts files, bytes and errors; logs them every 10 s and at the end."""

    def __init__(self) -> None:
        self.n = self.bytes = self.errors = self.skipped = 0
        self.t0 = time.monotonic()

    def add(self, nbytes: int) -> None:
        self.n, self.bytes = self.n + 1, self.bytes + nbytes

    def error(self, path: str, e: OSError) -> None:
        self.errors += 1
        log(f"{path}: {e.strerror}")

    def __str__(self) -> str:
        mb, dt = self.bytes / 1e6, time.monotonic() - self.t0
        skipped = f", {self.skipped} skipped" if self.skipped else ""
        return f"{self.n} files, {mb / 1e3:.2f} GB, {mb / dt:.0f} MB/s{skipped}, {self.errors} errors"

    async def run(self, pool: Pool, items: Iterable[Any], fn: Fn) -> int:
        """pool.run with progress logs; exit code 1 if any item failed."""

        async def tick() -> None:
            while True:
                await asyncio.sleep(10)
                log(self)

        ticker = asyncio.create_task(tick())
        try:
            await pool.run(items, fn)
        finally:
            ticker.cancel()
        log(self)
        return int(self.errors > 0)


@contextlib.contextmanager
def output(path: str | None, mode: str) -> Iterator[IO[Any]]:
    if path is None:
        yield sys.stdout
    else:
        with open(path, mode, newline="") as f:
            yield f


def all_paths(a: argparse.Namespace) -> list[str]:
    """PATHS then the lines of --from, deduplicated."""
    more = Path(a.from_file).read_text().splitlines() if a.from_file else []
    return [p for p in dict.fromkeys([*a.paths, *more]) if p]


def read_rows(path: str) -> list[dict[str, str]]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


async def probe(a: argparse.Namespace, cmd: list[str]) -> int:
    """Log in and print the server's SFTP extensions, then open --sessions sessions one by one, stopping at the first
    refusal. Stay under the server's session cap: a refused session can count as a failed login."""
    async with Session(cmd) as s:
        hashing = "server-side hashing available" if "check-file" in s.ext else "no server-side hashing"
        log(f"extensions: {s.ext}; {hashing}")
    sessions: list[Session] = []
    try:
        while len(sessions) < a.sessions:
            sessions.append(await Session(cmd).__aenter__())
        log(f"{len(sessions)} sessions open")
        return 0
    except ConnectionError as e:
        log(f"session {len(sessions) + 1} refused: {e}")
        return 1
    finally:
        await asyncio.gather(*(s.aclose() for s in sessions))


async def ls(a: argparse.Namespace, cmd: list[str]) -> int:
    """CSV path,size,mtime,dir of the given paths: directories are listed, with -r recursively."""
    prog = Progress()
    with output(a.out, "w") as f:
        w, header = csv.writer(f), [["path", "size", "mtime", "dir"]]

        async def fn(s: Session, item: tuple[str, bool], push: Push) -> None:
            if header:  # only once connected
                w.writerow(header.pop())
            path, listed = item
            try:
                if not listed and not (at := await s.stat(path)).is_dir:
                    w.writerow([path, at.size, at.mtime, 0])
                    prog.add(at.size)
                    return
                for name, at in await s.listdir(path):
                    w.writerow([p := posixpath.join(path, name), at.size, at.mtime, int(at.is_dir)])
                    prog.add(0 if at.is_dir else at.size)
                    if at.is_dir and a.recursive:
                        push((p, True))
            except SFTPError as e:
                prog.error(path, e)

        return await prog.run(Pool(cmd, a.sessions), [(p, False) for p in a.paths], fn)


async def hash_files(a: argparse.Namespace, cmd: list[str]) -> int:
    """CSV path,size,mtime,sha1_64k,error; server-side when the server offers check-file. With --out, rows are
    appended as they come, a rerun skips hashed paths, and the file is sorted at the end."""
    old = os.path.exists(a.out) if a.out else False
    done = {r["path"] for r in read_rows(a.out) if r["sha1_64k"]} if old else set()
    prog = Progress()
    with output(a.out, "a") as f:
        w = csv.writer(f)
        if not old:
            w.writerow(HASH_COLS)

        async def fn(s: Session, item: tuple[str, Any], push: Push) -> None:
            path, at = item
            try:
                if at is None and a.recursive:
                    at = await s.stat(path)
                if at is not None and at.is_dir:
                    for name, child in await s.listdir(path):
                        p = posixpath.join(path, name)
                        if child.is_dir or p not in done:
                            push((p, child))
                    return
                at, h = await s.sha1_64k(path)
                w.writerow([path, at.size, at.mtime, h, ""])
                prog.add(at.size)
            except SFTPError as e:
                w.writerow([path, "", "", "", e.strerror])
                prog.error(path, e)
            f.flush()

        items = [(p, None) for p in all_paths(a) if p not in done]
        code = await prog.run(Pool(cmd, a.sessions), items, fn)
    if a.out:
        rows = {r["path"]: r for r in read_rows(a.out)}  # the last row of a path wins
        with open(a.out, "w", newline="") as f:
            dw = csv.DictWriter(f, HASH_COLS)
            dw.writeheader()
            dw.writerows(rows[p] for p in sorted(rows))
    return code


async def get(a: argparse.Namespace, cmd: list[str]) -> int:
    """Download REMOTE files into LOCALDIR, directories with -r. Local files of the remote size are skipped, so a
    rerun resumes; --verify compares hashes after each transfer."""
    os.makedirs(a.dest, exist_ok=True)
    prog = Progress()

    async def fn(s: Session, item: tuple[str, str, Any], push: Push) -> None:
        remote, local, at = item
        try:
            at = at or await s.stat(remote)
            if at.is_dir:
                if not a.recursive:
                    raise SFTPError(4, "is a directory, use -r")
                os.makedirs(local, exist_ok=True)
                for name, child in await s.listdir(remote):
                    push((posixpath.join(remote, name), os.path.join(local, name), child))
            elif not (os.path.isfile(local) and os.path.getsize(local) == at.size):
                await s.get(remote, local)
                if a.verify and (await s.sha1_64k(remote))[1] != await asyncio.to_thread(sha1_64k_local, local):
                    os.remove(local)
                    raise SFTPError(4, "hash mismatch, local copy removed")
                prog.add(at.size)
        except ConnectionError:
            raise
        except OSError as e:  # SFTPError or local disk trouble
            prog.error(remote, e)

    items = [(r, os.path.join(a.dest, posixpath.basename(r.rstrip("/"))), None) for r in a.paths]
    return await prog.run(Pool(cmd, a.sessions), items, fn)


async def put(a: argparse.Namespace, cmd: list[str]) -> int:
    """Upload LOCAL files into REMOTEDIR, directories with -r. Each remote directory is listed once: files already
    there with the local size are skipped, so a rerun resumes; other existing files are kept unless --overwrite.
    Files are written to NAME.part and renamed when complete; --verify compares hashes after each transfer."""
    prog = Progress()

    async def fn(s: Session, job: tuple[str, str | tuple[str, ...]], push: Push) -> None:
        remote, local = job
        try:
            if isinstance(local, tuple):  # a directory: create it, list it, queue what is missing
                await s.makedirs(remote)
                have = {n: at.size for n, at in await s.listdir(remote) if not at.is_dir}
                for p in local:
                    r = posixpath.join(remote, n := os.path.basename(os.path.normpath(p)))
                    if os.path.isdir(p) and not a.recursive:
                        prog.error(p, SFTPError(4, "is a directory, use -r"))
                    elif os.path.isdir(p):
                        push((r, tuple(os.path.join(p, c) for c in os.listdir(p))))
                    elif n not in have or a.overwrite:
                        push((r, p))
                    elif have[n] == os.path.getsize(p):
                        prog.skipped += 1
                    else:
                        prog.error(r, SFTPError(4, "exists with another size, use --overwrite"))
                return
            await s.put(local, remote, a.overwrite)
            if a.verify and (await s.sha1_64k(remote))[1] != await asyncio.to_thread(sha1_64k_local, local):
                await s.remove(remote)
                raise SFTPError(4, "hash mismatch, remote copy removed")
            prog.add(os.path.getsize(local))
        except ConnectionError:
            raise
        except OSError as e:  # SFTPError or local file trouble
            prog.error(remote, e)

    return await prog.run(Pool(cmd, a.sessions), [(a.dest, tuple(a.paths))], fn)


async def mv(a: argparse.Namespace, cmd: list[str]) -> int:
    """Move REMOTE files or directories into REMOTEDIR, server-side. Never replaces an existing target (some servers'
    rename would), nor moves two sources onto one name."""
    prog, todo = Progress(), dict[str, str]()
    for p in all_paths(a):
        dst = posixpath.join(a.dest, posixpath.basename(p.rstrip("/")))
        if dst in todo:
            prog.error(p, SFTPError(4, f"same target as {todo[dst]}"))
        else:
            todo[dst] = p
    async with Session(cmd) as s:
        await s.makedirs(a.dest)

    async def fn(s: Session, dst: str, push: Push) -> None:
        try:
            if await s.exists(dst):
                raise SFTPError(4, f"{dst} exists")
            await s.rename(todo[dst], dst)
            prog.add(0)
        except SFTPError as e:
            prog.error(todo[dst], e)

    return await prog.run(Pool(cmd, a.sessions), todo, fn)


COMMANDS = {"probe": probe, "ls": ls, "hash": hash_files, "get": get, "put": put, "mv": mv}


def main(argv: list[str] | None = None) -> int:
    env = os.environ.get
    p = argparse.ArgumentParser(prog="sftpipe", description=__doc__)
    p.add_argument("-H", "--host", default=env("SFTPIPE_HOST"), help="SSH host or ~/.ssh/config alias")
    p.add_argument("-P", "--port", type=int, default=env("SFTPIPE_PORT"))
    p.add_argument("-u", "--user", default=env("SFTPIPE_USER"))
    p.add_argument("-i", "--key", default=env("SFTPIPE_KEY"), help="SSH private key")
    p.add_argument("-n", "--sessions", type=int, default=int(env("SFTPIPE_SESSIONS") or 8),
                   help="parallel sessions (default 8); stay under the server's per-user cap")  # fmt: skip
    p.add_argument("--ssh-opt", action="append", default=[], metavar="OPT", help="extra ssh -o option, repeatable")
    p.add_argument("--cmd", help="command speaking SFTP on stdin/stdout, instead of ssh")
    sub = p.add_subparsers(dest="command", required=True)
    for name, fn in COMMANDS.items():
        doc = fn.__doc__ or ""
        s = sub.add_parser(name, help=doc.split(". ")[0], description=doc)
        if name == "probe":
            continue
        if name != "mv":
            s.add_argument("-r", "--recursive", action="store_true")
        if name in ("ls", "hash"):
            s.add_argument("paths", nargs="+" if name == "ls" else "*")
            s.add_argument("-o", "--out", help="CSV file, default stdout")
        else:
            s.add_argument("paths", nargs="*" if name == "mv" else "+", metavar="LOCAL" if name == "put" else "REMOTE")
            s.add_argument("dest", metavar="LOCALDIR" if name == "get" else "REMOTEDIR")
        if name in ("get", "put"):
            s.add_argument("--verify", action="store_true", help="compare hashes after each transfer")
        if name in ("hash", "mv"):
            s.add_argument("--from", dest="from_file", metavar="FILE", help="more paths, one per line")
        if name == "put":
            s.add_argument("--overwrite", action="store_true", help="replace existing remote files")
    a = p.parse_args(argv)
    if not (a.host or a.cmd):
        p.error("give --host (or SFTPIPE_HOST) or --cmd")
    cmd = shlex.split(a.cmd) if a.cmd else ssh_argv(a.host, a.port, a.user, a.key, a.ssh_opt)
    try:
        return asyncio.run(COMMANDS[a.command](a, cmd))
    except ConnectionError as e:
        log(f"connection failed: {e}")
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
