import pytest

from vw_server.client import VwError
from vw_vault.mikrotik import MikroTikRotator
from vw_vault.rotation import PartialDistribution

OLD, NEW = "old-secret", "new-secret"


class FakeRouter:
    """RouterOS: a rejected command still exits 0; `ignore_set` leaves the password unchanged."""

    def __init__(self, ignore_set=False, fail_rollback=False):
        self.secret, self.ignore_set, self.fail_rollback, self.commands = OLD, ignore_set, fail_rollback, []

    def run(self, host, user, password, command, stdin=""):
        if password != self.secret:
            return None
        self.commands.append(command)
        if command == "true":
            return 0
        value = command.split('password="')[1].rstrip('"')
        if self.ignore_set or (self.fail_rollback and value == OLD):
            return 0
        self.secret = value
        return 0


def item():
    return {"id": "i1", "type": 1, "name": "rb", "login": {"username": "admin", "password": OLD}}


def make(router, written, generate=lambda: NEW, write=None):
    return MikroTikRotator({"rb"}, "rb.lan", write or (lambda it, v: written.append(v)),
                           transport=router, generate=generate)


def test_new_works_old_refused_written():
    router, written = FakeRouter(), []
    rot = make(router, written)
    new = rot.issue(item())
    rot.distribute(item(), new)
    assert rot.verify(item(), new)
    assert written == [NEW] and router.secret == NEW
    assert any('find name="admin"' in c for c in router.commands)


def test_rejected_change_is_caught_by_login_and_vault_untouched():
    router, written = FakeRouter(ignore_set=True), []
    rot = make(router, written)
    with pytest.raises(PartialDistribution) as exc:
        rot.distribute(item(), rot.issue(item()))
    assert written == [] and router.secret == OLD and exc.value.done == []


def test_unconfirmed_rollback_is_reported():
    router, written = FakeRouter(), []
    rot = make(router, written)
    new = rot.issue(item())
    router.secret = "somebody-else"  # neither old nor new logs in
    with pytest.raises(PartialDistribution):
        rot.distribute(item(), new)
    assert written == []


def test_vault_write_failure_rolls_back_router():
    router = FakeRouter()

    def write(it, v):
        raise VwError("vault down")

    rot = make(router, [], write=write)
    new = rot.issue(item())
    with pytest.raises(PartialDistribution):
        rot.distribute(item(), new)
    assert router.secret == NEW
    rot.rollback(item(), new, ["host"])
    assert router.secret == OLD


def test_unsafe_value_refused():
    rot = make(FakeRouter(), [], generate=lambda: 'bad"; /system reset-configuration')
    with pytest.raises(VwError):
        rot.issue(item())
