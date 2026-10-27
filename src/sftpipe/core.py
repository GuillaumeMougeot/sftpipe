"""Pipelined SFTP v3 over any SFTP-on-stdio command, by default OpenSSH (`ssh -s HOST sftp`)."""

import asyncio
import hashlib
import os
import posixpath
import stat
import struct
import sys
import time
from asyncio.subprocess import PIPE, Process
from collections.abc import AsyncIterator, Awaitable, Callable, Hashable, Iterable, Sequence
from typing import NamedTuple, Self

# paramiko's check-file does `offset += count`: blocks > 64 KiB hash wrong ranges and spin forever at EOF on the
# server. 64 KiB blocks are read in one chunk, which is exact. SEG caps digests per reply (server concat is O(n^2)).
BLOCK, SEG, DEPTH = 1 << 16, 1 << 26, 64  # DEPTH: requests in flight per transfer
INIT, VERSION, OPEN, CLOSE, READ, WRITE, FSTAT, OPENDIR, READDIR = 1, 2, 3, 4, 5, 6, 8, 11, 12
REMOVE, MKDIR, STAT, RENAME = 13, 14, 17, 18
STATUS, HANDLE, DATA, NAME, ATTRS, EXTENDED, EXTENDED_REPLY = 101, 102, 103, 104, 105, 200, 201
EOF, NO_SUCH_FILE = 1, 2
WRITE_NEW, WRITE_TRUNC = 0x02 | 0x08 | 0x20, 0x02 | 0x08 | 0x10  # WRITE CREAT, then EXCL or TRUNC


def log(*msg: object) -> None:
    print(time.strftime("%H:%M:%S"), *msg, file=sys.stderr, flush=True)


def ssh_argv(host: str, port: int | None = None, user: str | None = None, key: str | None = None,
             options: Sequence[str] = ()) -> list[str]:  # fmt: skip
    """OpenSSH command opening an SFTP subsystem. Never prompts: failed logins can lock accounts (ERDA: 5 in 2 min)."""
    argv = ["ssh", "-Txa", "-oBatchMode=yes", "-oServerAliveInterval=15", "-oLogLevel=ERROR"]
    argv += [f"-o{o}" for o in options]
    if port:
        argv += ["-p", str(port)]
    if user:
        argv += ["-l", user]
    if key:
        argv += ["-i", key, "-oIdentitiesOnly=yes"]
    return [*argv, "-s", host, "sftp"]


def sha1_64k_local(path: str | os.PathLike[str]) -> str:
    """Local twin of Session.sha1_64k: SHA-1 of the concatenated SHA-1 digests of consecutive 64 KiB blocks."""
    out = hashlib.sha1()
    with open(path, "rb") as f:
        while b := f.read(BLOCK):
            out.update(hashlib.sha1(b).digest())
    return out.hexdigest()


class SFTPError(OSError):
    """Non-OK SFTP status; errno is the SFTP code (1 EOF, 2 no such file, 3 permission denied, 8 unsupported)."""


class Attrs(NamedTuple):
    size: int
    mtime: int | None
    mode: int

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)


def _s(x: str | bytes) -> bytes:
    if isinstance(x, str):
        x = x.encode("utf-8", "surrogateescape")
    return struct.pack(">I", len(x)) + x


class Buf:
    """Reader over one SFTP packet body."""

    def __init__(self, data: bytes):
        self.d, self.i = data, 0

    def u32(self) -> int:
        self.i += 4
        return int(struct.unpack_from(">I", self.d, self.i - 4)[0])

    def u64(self) -> int:
        self.i += 8
        return int(struct.unpack_from(">Q", self.d, self.i - 8)[0])

    def bytes(self) -> bytes:
        n = self.u32()
        self.i += n
        return self.d[self.i - n : self.i]

    def str(self) -> str:
        return self.bytes().decode("utf-8", "surrogateescape")

    def attrs(self) -> Attrs:
        f = self.u32()
        size = self.u64() if f & 1 else 0
        self.i += 8 if f & 2 else 0  # uid, gid
        mode = self.u32() if f & 4 else 0
        mtime = (self.u32(), self.u32())[1] if f & 8 else None
        for _ in range(2 * self.u32() if f & 0x80000000 else 0):
            self.bytes()
        return Attrs(size, mtime, mode)


class Session:
    """One SFTP session over a subprocess (`async with Session(argv) as s`). Any number of requests may be in flight."""

    proc: Process
    ext: dict[str, str]

    def __init__(self, argv: Sequence[str]):
        self.argv, self.ids = list(argv), 0
        self.pending: dict[int, asyncio.Future[tuple[int, Buf]]] = {}
        self.closed: ConnectionError | None = None

    async def __aenter__(self) -> Self:
        self.proc = await asyncio.create_subprocess_exec(*self.argv, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        try:
            self._stdin.write(struct.pack(">IBI", 5, INIT, 3))
            t, b = await self._packet()
            if t != VERSION:
                raise ConnectionError(f"expected SFTP VERSION, got packet type {t}")
            b.u32()
            self.ext = {}
            while b.i < len(b.d):
                name, data = b.str(), b.str()  # not ext[b.str()] = b.str(): the right side is evaluated first
                self.ext[name] = data
            self.reader = asyncio.create_task(self._read_loop())
            await self.stat(".")  # paramiko replies VERSION before servers like MiG (ERDA) may reject the session
        except BaseException as e:  # cancellation included: never leave a half-open session behind
            await self.aclose()
            if isinstance(e, ConnectionError) or not isinstance(e, (EOFError, OSError)):
                raise
            raise ConnectionError(await self._stderr() or repr(e)) from None
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close stdin so the server ends the session cleanly (servers may count open sessions toward a cap)."""
        self._stdin.close()
        try:
            await asyncio.wait_for(self.proc.wait(), 10)
        except TimeoutError:
            self.proc.kill()

    @property
    def _stdin(self) -> asyncio.StreamWriter:
        assert self.proc.stdin
        return self.proc.stdin

    async def _stderr(self) -> str:
        assert self.proc.stderr
        try:
            return (await asyncio.wait_for(self.proc.stderr.read(), 5)).decode(errors="replace").strip()
        except TimeoutError:
            return ""

    async def _packet(self) -> tuple[int, Buf]:
        assert self.proc.stdout
        n, t = struct.unpack(">IB", await self.proc.stdout.readexactly(5))
        return t, Buf(await self.proc.stdout.readexactly(n - 1))

    async def _read_loop(self) -> None:
        try:
            while True:
                t, b = await self._packet()
                f = self.pending.pop(b.u32(), None)
                if f and not f.done():
                    f.set_result((t, b))
        except (EOFError, OSError) as e:
            self.closed = ConnectionError(f"SFTP session ended: {await self._stderr() or repr(e)}")
            for f in self.pending.values():
                if not f.done():
                    f.set_exception(self.closed)

    async def request(self, t: int, *fields: bytes) -> tuple[int, Buf]:
        """Send one request; returns the reply's (type, body after the request id)."""
        if self.closed:
            raise self.closed
        self.ids = i = (self.ids + 1) & 0xFFFFFFFF
        body = b"".join(fields)
        f: asyncio.Future[tuple[int, Buf]] = asyncio.get_running_loop().create_future()
        self.pending[i] = f
        self._stdin.write(struct.pack(">IBI", len(body) + 5, t, i) + body)
        await self._stdin.drain()
        return await f

    async def call(self, t: int, *fields: bytes, want: int = STATUS) -> Buf:
        """Request expecting a reply of type `want`; a non-OK STATUS raises SFTPError."""
        rt, b = await self.request(t, *fields)
        if rt == STATUS and ((code := b.u32()) or want != STATUS):
            raise SFTPError(code, b.str())
        if rt not in (want, STATUS):
            raise SFTPError(4, f"unexpected reply type {rt}")
        return b

    async def open(self, path: str, flags: int = 1) -> bytes:
        return (await self.call(OPEN, _s(path), struct.pack(">II", flags, 0), want=HANDLE)).bytes()

    async def close(self, handle: bytes) -> None:
        await self.call(CLOSE, _s(handle))

    async def stat(self, path: str) -> Attrs:
        return (await self.call(STAT, _s(path), want=ATTRS)).attrs()

    async def fstat(self, handle: bytes) -> Attrs:
        return (await self.call(FSTAT, _s(handle), want=ATTRS)).attrs()

    async def remove(self, path: str) -> None:
        await self.call(REMOVE, _s(path))

    async def rename(self, old: str, new: str) -> None:
        """Beware: servers differ when `new` exists (OpenSSH refuses, MiG/ERDA overwrites)."""
        await self.call(RENAME, _s(old), _s(new))

    async def mkdir(self, path: str) -> None:
        await self.call(MKDIR, _s(path), struct.pack(">I", 0))

    async def makedirs(self, path: str) -> None:
        """mkdir -p; tolerates concurrent creators."""
        if path in ("", "/", "."):
            return
        try:
            await self.mkdir(path)
        except SFTPError:
            try:
                if (await self.stat(path)).is_dir:
                    return
            except SFTPError:
                pass
            await self.makedirs(posixpath.dirname(path))
            await self.mkdir(path)

    async def listdir(self, path: str) -> list[tuple[str, Attrs]]:
        """(name, attrs) of entries but . and .. READDIRs are pipelined: paramiko returns only 16 names per call."""
        handle, out = (await self.call(OPENDIR, _s(path), want=HANDLE)).bytes(), []
        try:
            while True:
                for t, b in await asyncio.gather(*(self.request(READDIR, _s(handle)) for _ in range(16))):
                    if t == NAME:
                        for _ in range(b.u32()):
                            name, _long = b.str(), b.bytes()
                            out.append((name, b.attrs()))
                    elif (code := b.u32()) == EOF:
                        return [e for e in out if e[0] not in (".", "..")]
                    else:
                        raise SFTPError(code, b.str())
        finally:
            await self.close(handle)

    async def read(self, handle: bytes, offset: int, n: int) -> bytes:
        """Exactly n bytes at offset (servers may answer short reads). Hitting EOF raises SFTPError(1)."""
        data = b""
        while len(data) < n:
            args = _s(handle), struct.pack(">QI", offset + len(data), n - len(data))
            data += (await self.call(READ, *args, want=DATA)).bytes()
        return data

    async def _each(
        self, handle: bytes, size: int, step: int, part: Callable[[bytes, int, int], Awaitable[bytes]]
    ) -> AsyncIterator[bytes]:
        """part(handle, offset, n) over [0, size) in step-sized pieces, in order, DEPTH requests in flight."""
        for o in range(0, size, DEPTH * step):
            ends = range(o, min(o + DEPTH * step, size), step)
            for r in await asyncio.gather(*(part(handle, b, min(step, size - b)) for b in ends)):
                yield r

    async def get(self, remote: str, local: str) -> Attrs:
        """Download a file through LOCAL.part, then rename it and copy the remote mtime."""
        handle = await self.open(remote)
        try:
            a = await self.fstat(handle)
            with open(f"{local}.part", "wb") as f:
                async for data in self._each(handle, a.size, BLOCK, self.read):
                    f.write(data)
        finally:
            await self.close(handle)
        os.replace(f"{local}.part", local)
        if a.mtime is not None:
            os.utime(local, (a.mtime, a.mtime))
        return a

    async def put(self, local: str, remote: str, overwrite: bool = False) -> None:
        """Upload a file, DEPTH writes of 64 KiB in flight. Refuses to replace an existing file unless overwrite."""
        handle = await self.open(remote, WRITE_TRUNC if overwrite else WRITE_NEW)
        try:
            with open(local, "rb") as f:
                while chunks := [(f.tell() - len(b), b) for _ in range(DEPTH) if (b := f.read(BLOCK))]:
                    writes = (self.call(WRITE, _s(handle), struct.pack(">Q", o), _s(b)) for o, b in chunks)
                    await asyncio.gather(*writes)
        finally:
            await self.close(handle)

    async def sha1_64k(self, path: str, server: bool | None = None) -> tuple[Attrs, str]:
        """(attrs, hex SHA-1 of the concatenated SHA-1 digests of consecutive 64 KiB blocks).

        Hashed server-side via `check-file` when offered (or `server=True`), else downloaded: same result."""
        handle = await self.open(path)
        try:
            a = await self.fstat(handle)
            if a.is_dir:
                raise SFTPError(4, "is a directory")
            if "check-file" in self.ext if server is None else server:
                parts = [d async for d in self._each(handle, a.size, SEG, self._check_file)]
            else:
                parts = [hashlib.sha1(d).digest() async for d in self._each(handle, a.size, BLOCK, self.read)]
        finally:
            await self.close(handle)
        return a, hashlib.sha1(b"".join(parts)).hexdigest()

    async def _check_file(self, handle: bytes, start: int, length: int) -> bytes:
        args = _s("check-file"), _s(handle), _s("sha1"), struct.pack(">QQI", start, length, BLOCK)
        b = await self.call(EXTENDED, *args, want=EXTENDED_REPLY)
        b.str(), b.str()  # "check-file", algorithm
        if len(digests := b.d[b.i :]) != -(-length // BLOCK) * 20:
            raise SFTPError(4, f"check-file: {len(digests)} digest bytes for {length} bytes")
        return digests


Push = Callable[[Hashable], None]


class Pool:
    """Runs work over `sessions` SFTP sessions with `per` tasks each. Logins are serialized; if the first fails, no
    other is tried; later failures back off >= 30 s (ERDA locks a user out after 5 failed logins in 2 minutes)."""

    def __init__(self, argv: Sequence[str], sessions: int = 8, per: int = 4):
        self.argv, self.sessions, self.per = list(argv), sessions, per
        self.lock, self.up, self.fails = asyncio.Lock(), False, 0
        self.error: ConnectionError | None = None

    async def connect(self) -> Session:
        async with self.lock:
            while True:
                if self.error:
                    raise self.error
                try:
                    s = await Session(self.argv).__aenter__()
                except ConnectionError as e:
                    if not self.up:  # first login failed: misconfiguration, do not hammer
                        self.error = e
                        raise
                    self.fails += 1
                    log(f"login failed ({e}), retry in {(delay := min(300, 15 << self.fails))} s")
                    await asyncio.sleep(delay)
                else:
                    self.up, self.fails = True, 0
                    return s

    async def run(self, items: Iterable[Hashable], fn: Callable[[Session, Hashable, Push], Awaitable[object]]) -> None:
        """Await fn(session, item, push) for every item; push(item) queues more work. fn must handle SFTPError
        itself; items in flight on a session that dies are retried on a fresh one."""
        q: asyncio.Queue[Hashable] = asyncio.Queue()
        for it in items:
            q.put_nowait(it)

        async def worker(s: Session) -> None:
            while True:
                it = await q.get()
                try:
                    await fn(s, it, q.put_nowait)
                except BaseException:
                    q.put_nowait(it)
                    raise
                finally:
                    q.task_done()

        async def group() -> None:
            while True:
                s = await self.connect()
                try:
                    async with asyncio.TaskGroup() as tg:
                        for _ in range(self.per):
                            tg.create_task(worker(s))
                except* ConnectionError as eg:
                    log(f"session lost: {eg.exceptions[0]}")
                finally:
                    await s.aclose()
                await asyncio.sleep(5)  # no reconnect storm if sessions keep dying

        tasks = [asyncio.create_task(group()) for _ in range(self.sessions)]
        tasks.append(asyncio.create_task(q.join()))
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                t.result()  # a group only ends on error
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def walk(self, roots: Iterable[str]) -> list[tuple[str, Attrs]]:
        """(path, attrs) of every file below roots, listing directories in parallel; listing errors are logged."""
        files: list[tuple[str, Attrs]] = []

        async def fn(s: Session, d: Hashable, push: Push) -> None:
            assert isinstance(d, str)
            try:
                for name, a in await s.listdir(d):
                    if a.is_dir:
                        push(posixpath.join(d, name))
                    else:
                        files.append((posixpath.join(d, name), a))
            except SFTPError as e:
                log(f"{d}: {e.strerror}")

        await self.run(roots, fn)
        return files
