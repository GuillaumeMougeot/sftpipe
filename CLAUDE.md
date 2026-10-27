# sftpipe: agent notes

Fast parallel SFTP over OpenSSH, library + CLI. Born in vid-dedup (gitlab.au.dk ecos/hoyelab/wildcam/vid-dedup) to hash ~250k AU ERDA videos server-side. Public repo: keep it generic, never commit credentials, hosts' user names or data.

## Rules
- Succinct docs and code; optimize runtime and line count, not dev time. README is the documentation.
- Before pushing: `uv run pytest` (warnings are errors), `uv run ruff check . && uv run ruff format .`, `uv run mypy src` (strict). Keep CI green.
- Tests never reach real servers: stdio fakes and a local unprivileged sshd only.
- Never probe a real server's session cap by exceeding it.

## Layout
- `core.py`: Session (SFTP v3 over a subprocess, pipelined), Pool (sessions x workers, login-safe, retries), sha1_64k.
- `cli.py`: probe, ls, hash, get, put. `fake.py`: paramiko server on stdio, the ERDA stand-in; test hooks via env.
- `tests/`: test_core (unit), test_session (Session, Pool vs paramiko and OpenSSH sftp-server), test_cli (end to end, also through sshd).

## Invariants (learned on AU ERDA, 2026-10)
- check-file: 64 KiB blocks, exact lengths (paramiko bug: larger blocks hash wrong ranges, loop forever at EOF); 64 MiB per request.
- MiG sends VERSION before its session checks: a session counts as open only after a reply (`stat(".")`).
- Refused sessions are failed logins; 5 in 2 min locks the user. Logins serialized; first failure aborts; backoff >= 30 s.
- Any setup failure or cancellation must close the ssh process: leaked sessions count toward the cap.
- MiG rename overwrites, OpenSSH refuses. paramiko READDIR returns 16 names: pipeline 16 requests.
- Python: `d[f()] = g()` evaluates g() first.
