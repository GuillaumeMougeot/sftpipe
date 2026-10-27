"""Unit tests: wire encoding, attribute parsing, ssh command, local hash. No server."""

import hashlib
import os
import stat
import struct

from sftpipe import BLOCK, sha1_64k_local, ssh_argv
from sftpipe.core import Attrs, Buf, _s


def test_string_roundtrip_keeps_undecodable_names():
    name = b"caf\xe9.mp4".decode("utf-8", "surrogateescape")  # latin-1 byte on a UTF-8 server
    assert Buf(_s(name) + _s("é")).str() == name


def test_attrs_with_every_flag():
    data = struct.pack(">IQIII", 0x8000000F, 123, 1000, 1000, stat.S_IFDIR | 0o755)
    data += struct.pack(">II", 1, 2) + struct.pack(">I", 1) + _s("k") + _s("v") + b"rest"
    b = Buf(data)
    assert b.attrs() == Attrs(123, 2, stat.S_IFDIR | 0o755)
    assert b.d[b.i :] == b"rest"  # extended pairs consumed
    assert Attrs(0, None, stat.S_IFDIR).is_dir and not Attrs(0, None, stat.S_IFREG).is_dir


def test_attrs_with_no_flag():
    assert Buf(struct.pack(">I", 0)).attrs() == Attrs(0, None, 0)


def test_ssh_argv():
    assert ssh_argv("h")[-3:] == ["-s", "h", "sftp"]
    full = ssh_argv("h", 2222, "me@x.dk", "/k", ["ProxyJump=j"])
    for opt in (["-p", "2222"], ["-l", "me@x.dk"], ["-i", "/k"]):
        assert full[full.index(opt[0]) + 1] == opt[1]
    assert "-oIdentitiesOnly=yes" in full and "-oProxyJump=j" in full and "-oBatchMode=yes" in full


def test_sha1_64k_local(tmp_path):
    data = os.urandom(2 * BLOCK + 5)
    (f := tmp_path / "f").write_bytes(data)
    parts = (data[i : i + BLOCK] for i in range(0, len(data), BLOCK))
    assert sha1_64k_local(f) == hashlib.sha1(b"".join(hashlib.sha1(p).digest() for p in parts)).hexdigest()
    (f := tmp_path / "e").write_bytes(b"")
    assert sha1_64k_local(f) == hashlib.sha1(b"").hexdigest()
