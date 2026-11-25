"""Shared SSH rotation helper: change a password on a host, prove the new one, roll back on failure.

Steps of one rotation: log in with
the old secret and set the new one (the new value goes to the stdin of the remote command), log in
with the new one, check that the old one no longer works, write the new value to the vault item.
A failed step puts the old value back (host first, then the vault item). The old secret is dead
after a verified change, so revoke_old has nothing to do. Values travel only through memory, the
environment of the local ssh process and stdin; errors carry no command output.
"""

from __future__ import annotations

import os
import secrets
import subprocess
from collections.abc import Callable
from typing import Protocol

from vw_server.client import VwError

from .rotation import Issued, PartialDistribution

HOST = "host"
VAULT_ITEM = "vault item"
DEFAULT_CHANGE_CMD = "chpasswd"  # reads "user:password" lines from stdin
CHECK_CMD = "true"


class Transport(Protocol):
    def run(self, host: str, user: str, password: str, command: str, stdin: str = "") -> int | None:
        """Run `command` on `host` logged in with `password`; return the exit code, or None when
        the login itself was refused or the host is unreachable."""


def target(host: str) -> tuple[str, list[str]]:
    """`host` or `host:port` (an IPv6 address goes in brackets: `[::1]:2222`) → host and `-p`."""
    if host.startswith("["):
        addr, _, rest = host[1:].partition("]")
        return addr, (["-p", rest[1:]] if rest.startswith(":") and rest[1:].isdigit() else [])
    name, sep, port = host.rpartition(":")
    if sep and port.isdigit() and ":" not in name:
        return name, ["-p", port]
    return host, []


# The user's ~/.ssh/config is not read: its Match/ProxyJump/IdentityAgent rules belong to the
# owner's interactive ssh and once turned a password check into a connection that never reached
# the login. Host keys still come from ~/.ssh/known_hosts.
NO_CONFIG = ["-F", "/dev/null"]


class SshTransport:
    """ssh through sshpass: the password goes by the environment, never by argv."""

    def __init__(self, timeout: int = 60, options: list[str] | None = None):
        self.timeout = timeout
        self.options = options or [*NO_CONFIG, "-o", "StrictHostKeyChecking=yes", "-o", "PubkeyAuthentication=no",
                                   "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=15"]

    def run(self, host: str, user: str, password: str, command: str, stdin: str = "") -> int | None:
        name, port = target(host)
        argv = ["sshpass", "-e", "ssh", *self.options, *port, f"{user}@{name}", command]
        try:
            proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=self.timeout,
                                  env={**os.environ, "SSHPASS": password})
        except (OSError, subprocess.TimeoutExpired):
            return None
        # ssh reports a refused login and an unreachable host with 255; sshpass a wrong password with 5
        return None if proc.returncode in (5, 255) else proc.returncode


def new_password() -> str:
    return secrets.token_urlsafe(24)


class SshPasswordRotator:
    """Rotates the password of an account on one host over SSH.

    `items` are vault item names; the item login holds the account password and its username
    is the account on the host. `change_cmd` runs as that account with `stdin_template` on
    stdin (chpasswd style by default; set another template for tools like Pi-hole).
    """

    def __init__(self, items: set[str], host: str, write_item: Callable[[dict, str], None],
                 transport: Transport | None = None, change_cmd: str = DEFAULT_CHANGE_CMD,
                 stdin_template: str = "{user}:{password}\n",
                 generate: Callable[[], str] = new_password, name: str = "ssh"):
        self.items = set(items)
        self.host = host
        self._write_item = write_item
        self._ssh = transport or SshTransport()
        self.change_cmd = change_cmd
        self.stdin_template = stdin_template
        self._generate = generate
        self.name = name

    def matches(self, item: dict) -> bool:
        return item.get("type") == 1 and item.get("name") in self.items and not item.get("deletedDate")

    def _user(self, item: dict) -> str:
        user = (item.get("login") or {}).get("username") or ""
        if not user:
            raise VwError("the item has no username")
        return user

    def _can_login(self, user: str, password: str) -> bool:
        return self._ssh.run(self.host, user, password, CHECK_CMD) == 0

    def _set(self, user: str, current: str, target: str) -> bool:
        stdin = self.stdin_template.format(user=user, password=target)
        return self._ssh.run(self.host, user, current, self.change_cmd, stdin) == 0

    # --- module steps ---------------------------------------------------------------

    def issue(self, item: dict) -> Issued:
        user, old = self._user(item), (item.get("login") or {}).get("password") or ""
        if not self._can_login(user, old):
            raise VwError("the current password does not log in")
        value = self._generate()
        if not value or value == old:
            raise VwError("no new password generated")
        return Issued(ref=user, value=value)

    def distribute(self, item: dict, new: Issued) -> list[str]:
        user, old = self._user(item), item["login"]["password"]
        if not self._set(user, old, new.value):
            raise PartialDistribution("the password change failed on the host", [HOST])
        try:
            self._write_item(item, new.value)
        except Exception as exc:
            msg = str(exc) if isinstance(exc, VwError) else type(exc).__name__
            raise PartialDistribution(f"writing the vault item failed: {msg}", [HOST, VAULT_ITEM]) from None
        return [HOST, VAULT_ITEM]

    def verify(self, item: dict, new: Issued) -> bool:
        user, old = self._user(item), item["login"]["password"]
        return self._can_login(user, new.value) and not self._can_login(user, old)

    def revoke_old(self, item: dict, new: Issued) -> None:
        """Nothing to do: the old password was replaced and verify saw it dead."""

    def rollback(self, item: dict, new: Issued, done: list[str]) -> None:
        user, old = self._user(item), item["login"]["password"]
        errors = []
        if HOST in done and not self._can_login(user, old):
            # the host holds the new value (if the change never landed, old still logs in)
            if not (self._set(user, new.value, old) and self._can_login(user, old)):
                errors.append(HOST)
        if VAULT_ITEM in done:
            try:
                self._write_item(item, old)
            except Exception:
                errors.append(VAULT_ITEM)
        if errors:
            raise VwError("rollback failed for: " + ", ".join(errors))
