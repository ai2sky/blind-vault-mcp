import json

import pytest

from vw_server.client import VwError
from vw_vault.daemon import dispatch
from vw_vault.rotation import Issued

from test_vw_vault import login, make, state  # noqa: F401  (state is a fixture)

NEW = "n3w-secret-value-xyz"


class FakeRotator:
    """A dummy rotation module: records the steps, can fail at a chosen one."""

    name = "dummy"

    def __init__(self, fail=None, prefix="dummy"):
        self.fail, self.prefix, self.steps = fail, prefix, []

    def matches(self, item):
        return item["name"].startswith(self.prefix)

    def _step(self, name):
        self.steps.append(name)
        if self.fail == name:
            raise VwError(f"{name} broke")

    def issue(self, item):
        self._step("issue")
        return Issued(ref="new1", value=NEW)

    def distribute(self, item, new):
        self._step("distribute")
        return ["vault.yml", "repo-secret"]

    def verify(self, item, new):
        self.steps.append("verify")
        return self.fail != "verify"

    def revoke_old(self, item, new):
        self._step("revoke_old")

    def rollback(self, item, new, done):
        self.steps.append(f"rollback:{','.join(done)}")


def rotating(state, rot):
    eng, _ = make([login("a", "dummy-a", "example.com", pw="pw-a-distinct-0001")], state)
    eng.rotators = [rot]
    return eng


def test_rotate_runs_steps_in_order_and_clears_list(state):
    rot = FakeRotator()
    eng = rotating(state, rot)
    eng.mark_rotation(["a"], "leak")
    res = eng.rotate_all()
    assert rot.steps == ["issue", "distribute", "verify", "revoke_old"]
    assert res["rotated"] == 1 and res["results"][0]["consumers"] == ["vault.yml", "repo-secret"]
    assert "a" not in eng.rotation()
    assert NEW not in json.dumps(res) + (state / "journal.log").read_text()


@pytest.mark.parametrize("fail", ["distribute", "verify"])
def test_rotate_rolls_back_and_keeps_old_secret(state, fail):
    rot = FakeRotator(fail=fail)
    eng = rotating(state, rot)
    eng.mark_rotation(["a"], "leak")
    r = eng.rotate_all()["results"][0]
    assert "revoke_old" not in rot.steps
    assert rot.steps[-1].startswith("rollback:")
    assert not r["ok"] and r["rolled_back"] and r["stage"] == fail
    assert any("rotation failed" in x for x in eng.rotation()["a"]["reasons"])


def test_rotate_issue_failure_needs_no_rollback(state):
    rot = FakeRotator(fail="issue")
    eng = rotating(state, rot)
    assert not eng.rotate(["a"])["results"][0]["ok"]
    assert rot.steps == ["issue"]


def test_rotate_revoke_failure_reports_old_alive(state):
    eng = rotating(state, FakeRotator(fail="revoke_old"))
    eng.mark_rotation(["a"], "leak")
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["old_alive"] and "a" in eng.rotation()


def test_rotate_without_module_and_unexpected_error_text(state):
    eng = rotating(state, FakeRotator(prefix="other"))
    assert eng.rotate(["a"])["results"][0]["error"] == "no rotation module for the item"

    class Leaky(FakeRotator):
        def distribute(self, item, new):
            raise RuntimeError(new.value)

    r = rotating(state, Leaky()).rotate(["a"])["results"][0]
    assert r["error"] == "RuntimeError" and NEW not in json.dumps(r)


def test_rotate_needs_backup(state):
    eng = rotating(state, FakeRotator())
    eng.backup_cmd = "false"
    with pytest.raises(VwError):
        eng.rotate(["a"])


def test_dispatch_rotate_all(state):
    eng = rotating(state, FakeRotator())
    eng.mark_rotation(["a"], "leak")
    assert dispatch(eng, "rotate_all", {})["rotated"] == 1
