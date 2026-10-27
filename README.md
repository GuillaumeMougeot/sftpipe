# sftpipe

[![CI](https://github.com/GuillaumeMougeot/sftpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/GuillaumeMougeot/sftpipe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)

Fast parallel SFTP for Python, built on OpenSSH: list, hash, download and upload many files over several pipelined SFTP sessions. On paramiko-based servers such as [ERDA](https://erda.au.dk) (MiG), files are hashed server-side, without downloading them.

On AU ERDA, from a host with a 1 Gbit link, sftpipe hashed 813 GB (96k videos) in 11 minutes: 1.26 GB/s. Downloading them would cap at ~0.11 GB/s on that link.

## Why it is fast
- OpenSSH does the SSH work: C crypto, plus your keys, agent and `~/.ssh/config`. sftpipe speaks SFTP v3 over its stdin and stdout.
- Requests are pipelined: up to 64 reads or writes in flight per session, instead of one round trip each.
- Several sessions run in parallel, each over its own SSH connection.
- Servers offering the `check-file` extension (paramiko-based ones) hash files themselves.

## Install
```bash
uv tool install git+https://github.com/GuillaumeMougeot/sftpipe   # the sftpipe command
uv add git+https://github.com/GuillaumeMougeot/sftpipe            # the library, in a project
```
Needs Python 3.12+ and the OpenSSH client; no Python dependencies.

## CLI
```bash
export SFTPIPE_HOST=io.erda.au.dk SFTPIPE_PORT=2222 SFTPIPE_USER=you@au.dk SFTPIPE_KEY=~/.ssh/id_ed25519
export SFTPIPE_SESSIONS=15                # ERDA allows 16 per user

sftpipe probe                             # log in, show server extensions, open the sessions
sftpipe ls -r data -o files.csv           # path,size,mtime,dir
sftpipe hash -r data -o hashes.csv        # path,size,mtime,sha1_64k,error; rerun to resume
sftpipe get -r data ./local               # skips local files already of the right size
sftpipe put -r ./results project          # never overwrites unless --overwrite
```
Options also take a `~/.ssh/config` alias (`sftpipe -H erda ...`); `--verify` compares hashes after each transfer. Failed files are reported on stderr and set exit code 1. See `sftpipe COMMAND -h`.

## Library
```python
import asyncio
from sftpipe import Pool, Session, ssh_argv

cmd = ssh_argv("io.erda.au.dk", 2222, "you@au.dk", "/home/you/.ssh/id_ed25519")


async def main():
    async with Session(cmd) as s:
        attrs, digest = await s.sha1_64k("data/video.mp4")
        await s.get("data/video.mp4", "video.mp4")

    pool = Pool(cmd, sessions=15)
    files = await pool.walk(["data"])  # [(path, Attrs)], directories listed in parallel

    async def show(s, path, push):  # push(item) queues more work
        print(path, (await s.sha1_64k(path))[1])

    await pool.run([p for p, _ in files], show)  # an item on a session that dies is retried


asyncio.run(main())
```
`Session` also has `stat`, `isdir`, `listdir`, `put`, `mkdir`, `makedirs`, `rename`, `remove`, `open`, `read` and `close`. Server errors raise `SFTPError` (`errno` is the SFTP status code); a lost session raises `ConnectionError`.

## The hash
`sha1_64k` is the SHA-1 of the concatenated SHA-1 digests of consecutive 64 KiB blocks. That is what `check-file` returns, so it is computed server-side when offered, else by streaming the file; both give the same value. For local files: `sftpipe.sha1_64k_local(path)`.

## ERDA and other MiG sites
- Register your public key under Setup > SFTP > Public Keys; your username is listed under Login Details.
- AU ERDA allows 16 SFTP sessions per user and locks you out after 5 failed logins within 2 minutes. A session refused over the cap counts as a failed login, and MiG refuses it only after the SSH login succeeded.
- So sftpipe logs in one session at a time, checks each new session with a request, stops after a first failed login, and waits 30 s or more between later retries. Never run `probe -n` above the cap.
- On MiG, `rename` overwrites an existing destination (OpenSSH refuses).

## Design notes
- paramiko's `check-file` hashes wrong ranges for blocks over 64 KiB and can loop forever at end of file (`offset += count`). sftpipe only asks for 64 KiB blocks with exact lengths, 64 MiB per request, since the server joins digests in quadratic time.
- paramiko returns 16 names per READDIR, so sftpipe sends 16 READDIRs at once.
- Downloads are written to `FILE.part` and renamed when complete.
- Not yet: splitting one large file over several sessions, resuming partial files, SFTP versions above 3.

## Development
```bash
uv sync
uv run pytest      # unit; sessions vs paramiko and OpenSSH sftp-server; end to end through a local sshd
uv run ruff check . && uv run ruff format --check . && uv run mypy src
uv run pre-commit install
```
Tests that need OpenSSH's `sftp-server` or `sshd` are skipped when they are missing. `sftpipe.fake` (extra `fake`, needs paramiko) is a fake ERDA for your own tests: `sftpipe --cmd "python -m sftpipe.fake ROOT" ls .`

## License
[MIT](LICENSE)
