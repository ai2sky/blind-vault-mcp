"""Backup rotation module: the password of a restic or borg repository changes over SSH.

Built on the shared base in ssh.py. The vault item password is the repository password; the repository
lives on (or is reached from) the backup host, where the daemon logs in with a key (an admin account).
Steps: open the repository with the old password, change the password (old and new go to the stdin of
the remote shell, never argv), open the repository with the NEW password, and only then write the
vault item. A backup that cannot be opened with the new value is never recorded: the old password is
put back on the repository and checked (`rollback`), and the vault keeps the old value. The repository
comes from the item field `repo` or from the module default; the tool is `restic` or `borg`.
Opening the repository (`restic cat config`, `borg info`) is the check; it does not restore data.
"""

from __future__ import annotations

import shlex
from collections.abc import Callable

from vw_server.client import VwError

from .pihole import KeyTransport
from .ssh import HOST, VAULT_ITEM, Issued, PartialDistribution, SshPasswordRotator

DEFAULT_USER = "backup"  # item without a username
REPO_FIELD = "repo"
_READ_OLD = "IFS= read -r OLD; "
_READ_BOTH = _READ_OLD + "IFS= read -r NEW; "
# the vars are plain shell variables, exported only into the one tool process
COMMANDS = {
    "restic": {
        "open": _READ_OLD + 'RESTIC_PASSWORD="$OLD" restic -r {repo} cat config >/dev/null',
        "change": _READ_BOTH + 'printf "%s\\n" "$NEW" | RESTIC_PASSWORD="$OLD" '
                  "restic -r {repo} key passwd --new-password-file /dev/stdin",
    },
    "borg": {
        "open": _READ_OLD + 'BORG_PASSPHRASE="$OLD" borg info {repo} >/dev/null',
        "change": _READ_BOTH + 'BORG_PASSPHRASE="$OLD" BORG_NEW_PASSPHRASE="$NEW" '
                  "borg key change-passphrase {repo}",
    },
}


class BackupRotator(SshPasswordRotator):
    def __init__(self, items: set[str], host: str, write_item: Callable[[dict, str], None],
                 tool: str = "restic", repo: str = "", admin: str = "root", transport=None, **kw):
        if tool not in COMMANDS:
            raise VwError(f"unknown backup tool: {tool}")
        kw.setdefault("name", "backup")
        super().__init__(items, host, write_item, transport=transport or KeyTransport(admin), **kw)
        self.tool, self.repo = tool, repo

    def _user(self, item: dict) -> str:
        return (item.get("login") or {}).get("username") or DEFAULT_USER

    def _repo(self, item: dict) -> str:
        for field in item.get("fields") or []:
            if field.get("name") == REPO_FIELD and field.get("value"):
                return field["value"]
        if not self.repo:
            raise VwError("the item has no repository and no default is set")
        return self.repo

    def _cmd(self, item: dict, kind: str) -> str:
        return COMMANDS[self.tool][kind].format(repo=shlex.quote(self._repo(item)))

    @staticmethod
    def _line_safe(*values: str) -> None:
        if any(not v or "\n" in v or "\r" in v for v in values):
            raise VwError("the password cannot be passed on one line")

    def _open(self, item: dict, password: str) -> bool:
        self._line_safe(password)
        return self._ssh.run(self.host, self._user(item), password, self._cmd(item, "open"),
                             password + "\n") == 0

    def _change(self, item: dict, current: str, target: str) -> bool:
        self._line_safe(current, target)
        return self._ssh.run(self.host, self._user(item), current, self._cmd(item, "change"),
                             f"{current}\n{target}\n") == 0

    # the base steps take a user; here the item is needed to find the repository, so they are redone

    def issue(self, item: dict) -> Issued:
        old = (item.get("login") or {}).get("password") or ""
        if not self._open(item, old):
            raise VwError("the current password does not open the backup")
        value = self._generate()
        if not value or value == old:
            raise VwError("no new password generated")
        self._line_safe(value)
        return Issued(ref=self._repo(item), value=value)

    def distribute(self, item: dict, new: Issued) -> list[str]:
        old = item["login"]["password"]
        if not self._change(item, old, new.value):
            raise PartialDistribution("the password change failed on the repository", [HOST])
        if not self._open(item, new.value):
            # the repository does not open with the new value: restore the old one and prove it
            try:
                self.rollback(item, new, [HOST])
            except VwError:
                raise PartialDistribution("the backup does not open with the new password and the "
                                          "rollback could not be confirmed", [HOST]) from None
            raise PartialDistribution("the backup does not open with the new password; "
                                      "the old one was kept", [])
        try:
            self._write_item(item, new.value)
        except Exception as exc:
            msg = str(exc) if isinstance(exc, VwError) else type(exc).__name__
            raise PartialDistribution(f"writing the vault item failed: {msg}", [HOST, VAULT_ITEM]) from None
        return [HOST, VAULT_ITEM]

    def verify(self, item: dict, new: Issued) -> bool:
        return self._open(item, new.value) and not self._open(item, item["login"]["password"])

    def rollback(self, item: dict, new: Issued, done: list[str]) -> None:
        old = item["login"]["password"]
        errors = []
        if HOST in done and not self._open(item, old):
            if not (self._change(item, new.value, old) and self._open(item, old)):
                errors.append(HOST)
        if VAULT_ITEM in done:
            try:
                self._write_item(item, old)
            except Exception:
                errors.append(VAULT_ITEM)
        if errors:
            raise VwError("rollback failed for: " + ", ".join(errors))
