import pytest

from vw_server.client import VwError
from vw_vault.proxmox import ProxmoxKeyRotator, ProxmoxPasswordRotator
from vw_vault.rotation import PartialDistribution

OLD, NEW = "old-secret", "new-secret"
MODES = [(ProxmoxPasswordRotator, {}), (ProxmoxKeyRotator, {"pubkey": lambda k: "pub:" + k})]


class FakeNode:
    """One account on a node: `secrets` is the set of values that log in."""

    def __init__(self, refuse_change=False):
        self.secrets, self.refuse_change, self.users = {OLD}, refuse_change, []

    def run(self, host, user, password, command, stdin=""):
        self.users.append(user)
        if password not in self.secrets:
            return None
        if command == "true":
            return 0
        if self.refuse_change:
            return 1
        # password mode stdin is "user:value", key mode is the "pub:<private>" stand-in
        line = stdin.strip()
        self.secrets = {line.split(":", 1)[1]}
        return 0


def item():
    return {"id": "i1", "type": 1, "name": "pve", "login": {"password": OLD}}


@pytest.mark.parametrize("cls,kw", MODES)
def test_new_works_old_refused_written(cls, kw):
    node, written = FakeNode(), []
    rot = cls({"pve"}, "pve.example.internal", lambda it, v: written.append(v), transport=node, generate=lambda: NEW, **kw)
    assert rot.matches(item())
    new = rot.issue(item())
    rot.distribute(item(), new)
    assert rot.verify(item(), new)
    assert written == [NEW] and node.secrets == {NEW}
    assert set(node.users) == {"root"}


@pytest.mark.parametrize("cls,kw", MODES)
def test_failed_change_keeps_old(cls, kw):
    node, written = FakeNode(refuse_change=True), []
    rot = cls({"pve"}, "pve.example.internal", lambda it, v: written.append(v), transport=node, generate=lambda: NEW, **kw)
    with pytest.raises(PartialDistribution):
        rot.distribute(item(), rot.issue(item()))
    assert written == [] and node.secrets == {OLD}


@pytest.mark.parametrize("cls,kw", MODES)
def test_vault_write_failure_rolls_back_host(cls, kw):
    node, written = FakeNode(), []

    def write(it, v):
        if v == NEW:
            raise VwError("vault down")
        written.append(v)

    rot = cls({"pve"}, "pve.example.internal", write, transport=node, generate=lambda: NEW, **kw)
    new = rot.issue(item())
    with pytest.raises(PartialDistribution) as exc:
        rot.distribute(item(), new)
    assert node.secrets == {NEW}
    rot.rollback(item(), new, ["host"])
    assert node.secrets == {OLD}
