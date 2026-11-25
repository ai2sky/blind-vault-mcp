"""Pi-hole rotation module: the web password changes over SSH, login is checked through the API.

Built on the shared base in ssh.py. The vault item holds
the Pi-hole web password. The daemon sets the new one with `pihole setpassword` on the Pi-hole host
(an admin account with key login; the value goes to stdin, never argv), then signs in to the
Pi-hole API with the new password and checks that the old one is refused, then the vault item gets
the new value. A failed step puts the old password back (host first, then the vault item).
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable

import httpx

from .ssh import SshPasswordRotator

DEFAULT_CHANGE_CMD = "pihole setpassword"  # Pi-hole v6 asks for the password and its repeat on stdin
STDIN_TEMPLATE = "{password}\n{password}\n"
DEFAULT_USER = "admin"  # item without a username


class KeyTransport:
    """ssh with key login (BatchMode); the password argument is ignored, so one admin account serves."""

    def __init__(self, admin: str = "root", timeout: int = 60, options: list[str] | None = None):
        self.admin, self.timeout = admin, timeout
        self.options = options or ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                                   "-o", "ConnectTimeout=15"]

    def run(self, host: str, user: str, password: str, command: str, stdin: str = "") -> int | None:
        argv = ["ssh", *self.options, f"{self.admin}@{host}", command]
        try:
            proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=self.timeout,
                                  env=dict(os.environ))
        except (OSError, subprocess.TimeoutExpired):
            return None
        return None if proc.returncode == 255 else proc.returncode


class PiHoleRotator(SshPasswordRotator):
    def __init__(self, items: set[str], host: str, write_item: Callable[[dict, str], None],
                 url: str = "", transport=None, http: httpx.Client | None = None, admin: str = "root",
                 change_cmd: str = DEFAULT_CHANGE_CMD, **kw):
        super().__init__(items, host, write_item, transport=transport or KeyTransport(admin),
                         change_cmd=change_cmd, stdin_template=STDIN_TEMPLATE, name="pihole", **kw)
        self._api = (url or f"http://{host}").rstrip("/") + "/api/auth"
        self._http = http or httpx.Client(timeout=30)

    def _user(self, item: dict) -> str:
        return (item.get("login") or {}).get("username") or DEFAULT_USER

    def _can_login(self, user: str, password: str) -> bool:
        """True when the Pi-hole API accepts the password; the session is closed right away."""
        try:
            resp = self._http.post(self._api, json={"password": password})
            if resp.status_code != 200:
                return False
            session = (resp.json() or {}).get("session") or {}
            if not session.get("valid"):
                return False
            if session.get("sid"):
                try:
                    self._http.delete(self._api, headers={"sid": session["sid"]})
                except httpx.HTTPError:
                    pass
            return True
        except (httpx.HTTPError, ValueError, AttributeError):
            return False
