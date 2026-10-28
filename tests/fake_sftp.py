"""Test server: paramiko's SFTP server on stdin/stdout rooted at argv[1], as MiG (e.g. ERDA) runs it behind OpenSSH.

It keeps paramiko's quirks (16 names per READDIR, check-file buggy above 64 KiB blocks) and MiG's (rename
overwrites). Hooks: env SFTPIPE_FAKE_REJECT rejects sessions after VERSION, as MiG does over its session cap;
env SFTPIPE_FAKE_DIE=FILE makes the first process to create FILE exit at its 3rd open (session loss).
"""

import os
import shutil
import sys
from collections.abc import Callable
from typing import Any

from paramiko import SFTP_OK, SFTPAttributes, SFTPHandle, SFTPServer, SFTPServerInterface


def sftp_errors(fn: Callable[..., Any]) -> Callable[..., Any]:
    def wrap(*args: Any) -> Any:
        try:
            return fn(*args)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)

    return wrap


class Handle(SFTPHandle):
    def stat(self) -> SFTPAttributes:
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))


class FS(SFTPServerInterface):
    root, opens = ".", 0

    def session_started(self) -> None:
        if os.environ.get("SFTPIPE_FAKE_REJECT"):
            raise PermissionError("Too many open sessions")

    def real(self, path: str) -> str:
        return os.path.join(self.root, path.lstrip("/"))

    @sftp_errors
    def list_folder(self, path: str) -> list[SFTPAttributes]:
        d = self.real(path)
        return [SFTPAttributes.from_stat(os.stat(os.path.join(d, n)), n) for n in os.listdir(d)]

    @sftp_errors
    def stat(self, path: str) -> SFTPAttributes:
        return SFTPAttributes.from_stat(os.stat(self.real(path)))

    @sftp_errors
    def lstat(self, path: str) -> SFTPAttributes:  # list_folder follows links, lstat does not
        return SFTPAttributes.from_stat(os.lstat(self.real(path)))

    @sftp_errors
    def open(self, path: str, flags: int, attr: SFTPAttributes) -> SFTPHandle:
        FS.opens += 1
        if FS.opens == 3 and (marker := os.environ.get("SFTPIPE_FAKE_DIE")):
            try:
                os.close(os.open(marker, os.O_CREAT | os.O_EXCL))
                os._exit(1)
            except FileExistsError:
                pass
        h = Handle(flags)
        h.readfile = h.writefile = os.fdopen(os.open(self.real(path), flags, 0o644), "r+b" if flags & 3 else "rb")
        return h

    @sftp_errors
    def remove(self, path: str) -> int:
        os.remove(self.real(path))
        return SFTP_OK

    @sftp_errors
    def rename(self, old: str, new: str) -> int:
        shutil.move(self.real(old), self.real(new))  # like MiG: replaces an existing file
        return SFTP_OK

    @sftp_errors
    def mkdir(self, path: str, attr: SFTPAttributes) -> int:
        os.mkdir(self.real(path))
        return SFTP_OK

    @sftp_errors
    def rmdir(self, path: str) -> int:
        os.rmdir(self.real(path))
        return SFTP_OK


class Stdio:
    """The channel and transport duck type paramiko's SFTPServer needs."""

    def recv(self, n: int) -> bytes:
        return os.read(0, n)

    def send(self, data: bytes) -> int:
        return os.write(1, data)

    def get_transport(self) -> "Stdio":
        return self

    def get_log_channel(self) -> str:
        return "fake_sftp"

    def get_hexdump(self) -> bool:
        return False

    def get_name(self) -> str:
        return "stdio"


def main() -> None:
    FS.root = sys.argv[1] if len(sys.argv) > 1 else "."
    chan = Stdio()
    SFTPServer(chan, "sftp", server=None, sftp_si=FS).start_subsystem("sftp", chan, chan)


if __name__ == "__main__":
    main()
