import pytest

from vw_server.client import VwError
from vw_vault.backup import BackupRotator
from vw_vault.rotation import PartialDistribution

OLD, NEW = "old-secret", "new-secret"


class FakeHost:
    """The backup host: `open` succeeds with the repository password; `change` swaps it.
    `broken_change` makes the new password not open (the change silently went wrong)."""

    def __init__(self, broken_change=False):
        self.secret, self.broken, self.calls = OLD, broken_change, []

    def run(self, host, user, password, command, stdin=""):
        self.calls.append((command, stdin))
        lines = stdin.split("\n")
        if lines[0] != self.secret:
            return 1
        if "key passwd" in command or "change-passphrase" in command:
            if not self.broken:
                self.secret = lines[1]
        return 0


def item(**extra):
    return {"id": "i1", "type": 1, "name": "bk", "login": {"password": OLD}, **extra}


def make(host, written, tool="restic", write=None):
    return BackupRotator({"bk"}, "bk.lan", write or (lambda it, v: written.append(v)), tool=tool,
                         repo="repo dir", transport=host, generate=lambda: NEW)


@pytest.mark.parametrize("tool", ["restic", "borg"])
def test_new_password_opens_backup_then_written(tool):
    host, written = FakeHost(), []
    rot = make(host, written, tool)
    new = rot.issue(item())
    rot.distribute(item(), new)
    assert rot.verify(item(), new)
    assert written == [NEW] and host.secret == NEW
    assert all(OLD not in c and NEW not in c for c, _ in host.calls)  # values only on stdin
    assert "'repo dir'" in host.calls[0][0]


def test_repo_from_item_field():
    host = FakeHost()
    rot = make(host, [])
    rot.issue(item(fields=[{"name": "repo", "value": "sftp:x:r"}]))
    assert "sftp:x:r" in host.calls[0][0]


def test_wrong_current_password_stops_early():
    host = FakeHost()
    host.secret = "other"
    with pytest.raises(VwError):
        make(host, []).issue(item())


def test_backup_not_opening_keeps_old_value():
    host, written = FakeHost(broken_change=True), []
    rot = make(host, written)
    with pytest.raises(PartialDistribution) as exc:
        rot.distribute(item(), rot.issue(item()))
    assert written == [] and exc.value.done == []


def test_unconfirmed_rollback_reported():
    host, written = FakeHost(), []
    rot = make(host, written)
    new = rot.issue(item())
    host.secret = "somebody-else"  # neither old nor new opens the backup
    with pytest.raises(PartialDistribution) as exc:
        rot.distribute(item(), new)
    assert written == [] and exc.value.done == ["host"]


def test_vault_write_failure_rolls_back_host():
    host = FakeHost()

    def boom(it, v):
        if v == NEW:
            raise RuntimeError("x")
    rot = make(host, [], write=boom)
    new = rot.issue(item())
    with pytest.raises(PartialDistribution) as exc:
        rot.distribute(item(), new)
    rot.rollback(item(), new, exc.value.done)
    assert host.secret == OLD


def test_unknown_tool_and_newline_rejected():
    with pytest.raises(VwError):
        BackupRotator({"bk"}, "h", lambda *a: None, tool="tar")
    with pytest.raises(VwError):
        make(FakeHost(), []).issue(item() | {"login": {"password": "a\nb"}})
