"""MikroTik rotation module: the RouterOS user password changes over SSH.

Built on the shared base in ssh.py. The vault item login holds the account password and its
username is the RouterOS user. The daemon logs in with the old password, runs the RouterOS
`user set` command for that account, and then, BEFORE the vault item is written, logs in with the
new password. RouterOS exits 0 even when the command was rejected, so the exit code proves nothing:
only a real login with the new password does. If that login fails the old password is put back and
checked (`rollback`), and the vault keeps the old value. Losing access to a router is critical, so
a value that cannot be quoted safely is never used.
RouterOS has no stdin for this command: the value travels in the ssh command line (visible to
local processes for the moment of the call); generated values are URL-safe characters only.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from vw_server.client import VwError

from .ssh import HOST, VAULT_ITEM, Issued, PartialDistribution, SshPasswordRotator

SET_CMD = '/user set [find name="{user}"] password="{password}"'
_SAFE = re.compile(r"[A-Za-z0-9._@+=,:/-]+")


class MikroTikRotator(SshPasswordRotator):
    def __init__(self, items: set[str], host: str, write_item: Callable[[dict, str], None], **kw):
        kw.setdefault("name", "mikrotik")
        super().__init__(items, host, write_item, **kw)

    def _user(self, item: dict) -> str:
        user = super()._user(item)
        if not _SAFE.fullmatch(user):
            raise VwError("the username has characters that cannot be quoted safely")
        return user

    def _set(self, user: str, current: str, target: str) -> bool:
        # the current value is only sent as the login secret, never quoted into the command
        if not _SAFE.fullmatch(target):
            return False
        return self._ssh.run(self.host, user, current, SET_CMD.format(user=user, password=target)) == 0

    def issue(self, item: dict) -> Issued:
        new = super().issue(item)
        if not _SAFE.fullmatch(new.value):
            raise VwError("the new password has characters that cannot be quoted safely")
        return new

    def distribute(self, item: dict, new: Issued) -> list[str]:
        user, old = self._user(item), item["login"]["password"]
        if not self._set(user, old, new.value):
            raise PartialDistribution("the password change failed on the router", [HOST])
        if not self._can_login(user, new.value):
            # the router did not take the new value: undo and prove the old one works, then stop
            try:
                self.rollback(item, new, [HOST])
            except VwError:
                raise PartialDistribution("the new password does not log in and the rollback "
                                          "could not be confirmed", [HOST]) from None
            raise PartialDistribution("the new password does not log in; the old one was kept", [])
        try:
            self._write_item(item, new.value)
        except Exception as exc:
            msg = str(exc) if isinstance(exc, VwError) else type(exc).__name__
            raise PartialDistribution(f"writing the vault item failed: {msg}", [HOST, VAULT_ITEM]) from None
        return [HOST, VAULT_ITEM]
