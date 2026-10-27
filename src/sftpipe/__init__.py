"""Fast parallel SFTP over OpenSSH: pipelined multi-session transfers, listings and server-side hashing."""

from importlib.metadata import version

from .core import BLOCK, Attrs, Pool, Session, SFTPError, sha1_64k_local, ssh_argv

__version__ = version("sftpipe")
__all__ = ["BLOCK", "Attrs", "Pool", "SFTPError", "Session", "__version__", "sha1_64k_local", "ssh_argv"]
