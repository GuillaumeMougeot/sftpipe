# sftpipe

[![CI](https://github.com/GuillaumeMougeot/sftpipe/actions/workflows/ci.yml/badge.svg)](https://github.com/GuillaumeMougeot/sftpipe/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)

Fast parallel SFTP for Python, built on the OpenSSH client: list, hash, download and upload many files over several pipelined SFTP sessions, from the command line or as an asyncio library. Servers offering the `check-file` extension hash files themselves, so only digests cross the network.

## Why it is fast
- OpenSSH does the SSH work: C crypto, plus your keys, agent and `~/.ssh/config`. sftpipe speaks SFTP v3 over its stdin and stdout.
- Requests are pipelined: up to 64 reads or writes in flight per session, instead of one round trip each.
- Several sessions run in parallel, each over its own SSH connection.
- With `check-file`, hashing runs on the server: 14 sessions hashed 4.5 TB at 1.35 GB/s from a host whose 1 Gbit link caps downloads at 0.11 GB/s.

## Install
```bash
uv tool install git+https://github.com/GuillaumeMougeot/sftpipe   # the sftpipe command
uv add git+https://github.com/GuillaumeMougeot/sftpipe            # the library, in a project
```
Needs Python 3.12+ and the OpenSSH client; no Python dependencies.

## CLI
```bash
export SFTPIPE_HOST=sftp.example.org SFTPIPE_USER=me SFTPIPE_KEY=~/.ssh/id_ed25519

sftpipe probe                         # log in, show server extensions, open the sessions
sftpipe ls -r data -o files.csv       # path,size,mtime,dir
sftpipe hash -r data -o hashes.csv    # path,size,mtime,sha1_64k,error; rerun to resume
sftpipe get -r data ./local           # skips local files already of the right size
sftpipe put -r ./results project      # skips remote files already of the right size; never overwrites unless --overwrite

# on the server
sftpipe cp -r data backup             # copy; resumes like put
sftpipe mv --from moves.txt flat      # move into a directory, or rename one path; never replaces a target
sftpipe rm -r old                     # contents in parallel, then directories; links removed, not followed
sftpipe mkdir a/b c                   # with parents
```
Connection options `-H`, `-P`, `-u`, `-i`, `-n` (sessions, default 8) and `--ssh-opt` also read `SFTPIPE_HOST`, `SFTPIPE_PORT`, `SFTPIPE_USER`, `SFTPIPE_KEY` and `SFTPIPE_SESSIONS`; the host can be a `~/.ssh/config` alias. For password logins, set `SFTPIPE_PASSWORD` (or `--password`): ssh reads it through `SSH_ASKPASS`, one try per login, and never accepts an unknown host key. `--verify` compares hashes after each transfer. Failed files are reported on stderr and set exit code 1. See `sftpipe COMMAND -h`.

## Library
```python
import asyncio

from sftpipe import Pool, Session, ssh_argv

cmd = ssh_argv("sftp.example.org", user="me", key="/home/me/.ssh/id_ed25519")


async def main():
    async with Session(cmd) as s:
        attrs, digest = await s.sha1_64k("data/a.bin")
        await s.get("data/a.bin", "a.bin")

    pool = Pool(cmd, sessions=8)
    files = await pool.walk(["data"])  # [(path, Attrs)], directories listed in parallel

    async def show(s, path, push):  # push(item) queues more work
        print(path, (await s.sha1_64k(path))[1])

    await pool.run([p for p, _ in files], show)  # an item on a session that dies is retried


asyncio.run(main())
```
`Session` also has `stat`, `lstat`, `exists`, `isdir`, `listdir`, `put`, `copy`, `mkdir`, `makedirs`, `rmdir`, `rename`, `remove`, `open`, `read` and `close`. Server errors raise `SFTPError` (`errno` is the SFTP status code); a lost session raises `ConnectionError`.

## The hash
`sha1_64k` is the SHA-1 of the concatenated SHA-1 digests of consecutive 64 KiB blocks. That is what `check-file` returns, so it is computed server-side when offered, else by streaming the file; both give the same value. For local files: `sftpipe.sha1_64k_local(path)`.

## Session caps and login lockouts
Some servers cap sessions per user and lock accounts after a few failed logins. MiG-based ones, such as ERDA, even count a session refused over the cap as a failed login, refused only after the SSH login succeeded. So sftpipe logs in one session at a time, checks each new session with a request, stops after a first failed login, and waits 30 s or more between later retries. Keep `-n` under the cap, `probe` included.

## Design notes
- paramiko's `check-file` hashes wrong ranges for blocks over 64 KiB and can loop forever at end of file (`offset += count`). sftpipe only asks for 64 KiB blocks with exact lengths, 64 MiB per request, since the server joins digests in quadratic time.
- paramiko returns 16 names per READDIR, so sftpipe sends 16 READDIRs at once.
- Transfers and copies are written to `FILE.part` and renamed when complete, so a file of the right size is a whole file.
- SFTP v3 has no copy: `copy` uses the `copy-data` extension when offered (OpenSSH 9+), keeping the data on the server; otherwise it reads and writes through the client, at network speed.
- `rename` onto an existing file fails on OpenSSH but replaces it on MiG.
- Not yet: splitting one large file over several sessions, resuming partial files, SFTP versions above 3.

## Development
```bash
uv sync
uv run pytest      # unit, then against OpenSSH's sftp-server, a paramiko server and a throwaway local sshd
uv run ruff check . && uv run ruff format --check . && uv run mypy src
uv run pre-commit install   # optional: the same checks on each commit
```
Tests needing OpenSSH's `sftp-server` or `sshd` are skipped when they are missing.

## License
[MIT](LICENSE)
