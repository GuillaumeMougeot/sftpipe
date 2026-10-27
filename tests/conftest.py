import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from sftpipe.cli import main

OPENSSH_SFTP = shutil.which("sftp-server", path="/usr/lib/openssh:/usr/lib:/usr/libexec:/usr/libexec/openssh")
SSHD = shutil.which("sshd", path="/usr/sbin:/usr/bin")


def fake_cmd(root: Path) -> list[str]:
    return [sys.executable, "-m", "sftpipe.fake", str(root)]


class Remote:
    """A server for tests: `root` is the local directory it serves, `args` the sftpipe connection options."""

    def __init__(self, kind: str, root: Path, args: list[str]):
        self.kind, self.root, self.args = kind, root, args

    @property
    def cmd(self) -> list[str]:
        return shlex.split(self.args[1])

    def cli(self, *args: object) -> int:
        """Run sftpipe: in-process for stdio servers, as a real subprocess (through ssh) for sshd."""
        argv = [*self.args, *map(str, args)]
        if self.kind == "sshd":
            return subprocess.run([sys.executable, "-m", "sftpipe", *argv], timeout=120).returncode
        return main(argv)


def stdio_remote(kind: str, root: Path) -> Remote:
    root.mkdir(exist_ok=True)
    if kind == "openssh":
        if not OPENSSH_SFTP:
            pytest.skip("no OpenSSH sftp-server")
        return Remote(kind, root, ["--cmd", shlex.join([OPENSSH_SFTP, "-d", str(root)])])
    return Remote(kind, root, ["--cmd", shlex.join(fake_cmd(root))])


@pytest.fixture(params=["fake", "openssh"])
def stdio(request: pytest.FixtureRequest, tmp_path: Path) -> Remote:
    """paramiko (the ERDA stand-in) and OpenSSH's sftp-server, both spoken to over stdin/stdout."""
    return stdio_remote(request.param, tmp_path / "srv")


@pytest.fixture
def sshd(tmp_path: Path) -> Iterator[Remote]:
    """A real unprivileged sshd on localhost whose SFTP subsystem is sftpipe.fake: OpenSSH in front of paramiko,
    like ERDA. sftpipe reaches it through the ssh client, as in production."""
    if not SSHD:
        pytest.skip("no sshd")
    d, root = tmp_path / "sshd", tmp_path / "srv"
    d.mkdir()
    root.mkdir()
    for key in ("host", "client"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", d / key], check=True)
    (d / "authorized_keys").write_text((d / "client.pub").read_text())
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    config = f"""Port {port}
ListenAddress 127.0.0.1
HostKey {d}/host
AuthorizedKeysFile {d}/authorized_keys
PidFile {d}/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
Subsystem sftp {shlex.join(fake_cmd(root))}
"""
    (d / "sshd_config").write_text(config)
    opts = ["StrictHostKeyChecking=no", f"UserKnownHostsFile={d}/known_hosts"]
    args = ["-H", "127.0.0.1", "-P", str(port), "-i", str(d / "client"), *[f"--ssh-opt={o}" for o in opts]]
    with open(d / "log", "w") as log, subprocess.Popen([SSHD, "-D", "-e", "-f", d / "sshd_config"], stderr=log) as proc:
        deadline = time.monotonic() + 10
        while not port_open(port):
            assert time.monotonic() < deadline and proc.poll() is None, (d / "log").read_text()
            time.sleep(0.05)
        yield Remote("sshd", root, args)
        proc.terminate()


def port_open(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


@pytest.fixture(params=["fake", "openssh", "sshd"])
def remote(request: pytest.FixtureRequest, tmp_path: Path) -> Remote:
    if request.param == "sshd":
        return request.getfixturevalue("sshd")
    return stdio_remote(request.param, tmp_path / "srv")


def put_file(root: Path, rel: str, data: bytes) -> Path:
    (p := root / rel).parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


@pytest.fixture(autouse=True)
def _no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never pick up a real server from the environment."""
    for k in list(os.environ):
        if k.startswith("SFTPIPE_"):
            monkeypatch.delenv(k)
