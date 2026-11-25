"""Proxmox rotation module: the root password or the SSH key of an account changes over SSH.

Built on the shared base in ssh.py. Two modes, one class each:
- ProxmoxPasswordRotator: the vault item login holds the password; `chpasswd` runs on the node as
  that account (value on stdin); verify logs in with the new password and checks the old is refused.
- ProxmoxKeyRotator: the item password holds an OpenSSH private key (ed25519, no passphrase); the new
  public key replaces the account authorized_keys (one managed key per account), verify logs in with
  the new key and checks the old key is refused.
A failed step puts the old value back (node first, then the vault item). Private keys touch disk only
as 0600 files in a private temp directory removed right after the ssh call.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Callable

from vw_server.client import VwError

from .ssh import NO_CONFIG, SshPasswordRotator, target

DEFAULT_USER = "root"
INSTALL_KEY_CMD = "umask 077; mkdir -p ~/.ssh && cat > ~/.ssh/authorized_keys"


def _write_key(path: str, private: str) -> None:
    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fh:
        fh.write(private if private.endswith("\n") else private + "\n")


def new_key() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "k")
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path], check=True,
                       capture_output=True)
        with open(path) as fh:
            return fh.read()


def public_key(private: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "k")
        _write_key(path, private)
        try:
            proc = subprocess.run(["ssh-keygen", "-y", "-f", path], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise VwError("cannot read the private key") from None
    if proc.returncode != 0 or not proc.stdout.strip():
        raise VwError("cannot read the private key")
    return proc.stdout.strip()


class PrivateKeyTransport:
    """ssh with a private key given as text; the `password` argument carries the key."""

    def __init__(self, timeout: int = 60, options: list[str] | None = None):
        self.timeout = timeout
        self.options = options or [*NO_CONFIG, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                   "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
                                   "-o", "ConnectTimeout=15"]

    def run(self, host: str, user: str, password: str, command: str, stdin: str = "") -> int | None:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "k")
                _write_key(path, password)
                name, port = target(host)
                argv = ["ssh", *self.options, *port, "-i", path, f"{user}@{name}", command]
                proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return None if proc.returncode == 255 else proc.returncode


class ProxmoxPasswordRotator(SshPasswordRotator):
    def __init__(self, items: set[str], host: str, write_item: Callable[[dict, str], None], **kw):
        kw.setdefault("name", "proxmox")
        super().__init__(items, host, write_item, **kw)

    def _user(self, item: dict) -> str:
        return (item.get("login") or {}).get("username") or DEFAULT_USER


class ProxmoxKeyRotator(ProxmoxPasswordRotator):
    def __init__(self, items: set[str], host: str, write_item: Callable[[dict, str], None],
                 transport=None, pubkey: Callable[[str], str] = public_key,
                 generate: Callable[[], str] = new_key, **kw):
        kw.setdefault("name", "proxmox-key")
        super().__init__(items, host, write_item, transport=transport or PrivateKeyTransport(),
                         change_cmd=INSTALL_KEY_CMD, generate=generate, **kw)
        self._pubkey = pubkey

    def _set(self, user: str, current: str, target: str) -> bool:
        return self._ssh.run(self.host, user, current, self.change_cmd, self._pubkey(target) + "\n") == 0
