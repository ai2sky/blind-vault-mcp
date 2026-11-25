import pytest

from vw_server import backup
from vw_server.client import VwError


def test_unset_command_fails(monkeypatch):
    monkeypatch.delenv("VW_BACKUP_CMD", raising=False)
    with pytest.raises(VwError, match="not set"):
        backup.run_backup()


def test_last_stdout_line_is_the_id(monkeypatch):
    monkeypatch.setenv("VW_BACKUP_CMD", "sh -c 'echo working; echo vw-2026-10-26.tar'")
    assert backup.run_backup() == "vw-2026-10-26.tar"


@pytest.mark.parametrize("cmd", ["false", "true", "no-such-backup-cmd"])
def test_failure_or_no_id_fails(monkeypatch, cmd):
    monkeypatch.setenv("VW_BACKUP_CMD", cmd)
    with pytest.raises(VwError):
        backup.run_backup()
