import json
import logging

import pytest

from vw_server import audit, server
from vw_server.client import VwError

SECRET = "s3cr3t-VALUE-9f2"


class FakeManager:
    calls: list[tuple] = []
    fail = False

    def _do(self, *call):
        if self.fail:
            raise VwError("boom")
        self.calls.append(call)

    def list_collections(self):
        return ["agents", "google"]

    def list_collection_names(self, collection):
        return ["A", "B"]

    def create_collection(self, collection):
        self._do("create", collection)
        return True

    def grant_reader(self, collection, account):
        self._do("grant", collection, account)
        return True

    existing = False

    def secret_exists(self, collection, name):
        return self.existing

    def set_collection_secret(self, collection, name, value):
        self._do("set", collection, name, value)
        return True

    def delete_secret(self, collection, name):
        self._do("delete", collection, name)
        return True


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    FakeManager.calls = []
    FakeManager.fail = False
    FakeManager.existing = False
    monkeypatch.setattr(server, "_manager", FakeManager)
    monkeypatch.setattr(server, "_delete_hook", server.deny_deletes)
    monkeypatch.setattr(server, "_prompt_hook", server.no_prompt)
    monkeypatch.setenv("VW_AUDIT_LOG", str(tmp_path / "audit.log"))
    sent = []
    monkeypatch.setattr(audit, "notify", sent.append)
    return {"sent": sent, "log": tmp_path / "audit.log"}


def journal(env):
    return [json.loads(line) for line in env["log"].read_text().splitlines()]


async def test_lists(env):
    assert await server.list_collections() == ["agents", "google"]
    assert await server.list_items("agents") == ["A", "B"]


async def test_create_and_grant_are_journaled_and_notified(env):
    assert "created" in await server.create_collection("agents")
    assert "can read" in await server.grant_reader("agents", "r@example.com")
    assert FakeManager.calls == [("create", "agents"), ("grant", "agents", "r@example.com")]
    assert [e["action"] for e in journal(env)][0] == "create_collection"
    assert len(env["sent"]) == 2


async def test_generate_writes_without_leaking(env, caplog):
    with caplog.at_level(logging.DEBUG):
        result = await server.set_secret("agents", "TOKEN", generate=True)
    (_, collection, name, value), = FakeManager.calls
    assert (collection, name) == ("agents", "TOKEN") and len(value) >= 32
    everything = result + caplog.text + env["log"].read_text() + "".join(env["sent"])
    assert value not in everything
    assert len(env["sent"]) == 1 and "TOKEN" in env["sent"][0]


async def test_from_file_writes_without_leaking(env, tmp_path):
    f = tmp_path / "v"
    f.write_text(SECRET + "\n")
    result = await server.set_secret("agents", "FILE_KEY", from_file=str(f))
    assert FakeManager.calls == [("set", "agents", "FILE_KEY", SECRET)]
    assert SECRET not in result + env["log"].read_text() + "".join(env["sent"])


async def test_prompt_uses_hook(env):
    async def hook(collection, name):
        return SECRET

    server.set_prompt_hook(hook)
    result = await server.set_secret("agents", "ASKED", prompt=True)
    assert FakeManager.calls == [("set", "agents", "ASKED", SECRET)]
    assert SECRET not in result


async def test_prompt_without_channel_writes_nothing(env):
    assert "Not written" in await server.set_secret("agents", "ASKED", prompt=True)
    assert FakeManager.calls == []


@pytest.mark.parametrize("kwargs", [{}, {"generate": True, "prompt": True}, {"from_file": "/x", "generate": True}])
async def test_exactly_one_source(env, kwargs):
    with pytest.raises(ValueError, match="exactly one"):
        await server.set_secret("agents", "K", **kwargs)


async def test_bad_name_and_missing_file(env):
    with pytest.raises(ValueError):
        await server.set_secret("agents", "a-b", generate=True)
    with pytest.raises(ValueError, match="Not written"):
        await server.set_secret("agents", "K", from_file="/nonexistent/file")
    assert FakeManager.calls == []


async def test_delete_needs_owner_confirmation(env):
    assert "not given" in await server.delete_secret("agents", "K")
    assert FakeManager.calls == []
    assert journal(env)[-1]["outcome"] == "refused"

    async def yes(request):
        return True

    server.set_delete_hook(yes)
    assert "deleted" in await server.delete_secret("agents", "K")
    assert FakeManager.calls == [("delete", "agents", "K")]


async def test_failure_is_journaled_and_reported(env):
    FakeManager.fail = True
    with pytest.raises(ValueError, match="boom"):
        await server.set_secret("agents", "K", generate=True)
    assert journal(env)[-1]["outcome"] == "failed"


async def test_notification_failure_does_not_undo_action(env, monkeypatch):
    def broken(text):
        raise RuntimeError("down")

    monkeypatch.setattr(audit, "notify", broken)
    result = await server.set_secret("agents", "K", generate=True)
    assert "created" in result and "notification failed" in result
    assert len(FakeManager.calls) == 1


def fake_backup(monkeypatch, result="snap-42"):
    runs = []

    def run():
        runs.append(1)
        if result is None:
            raise VwError("backup command failed with code 1")
        return result

    monkeypatch.setattr(server.backup, "run_backup", run)
    return runs


async def yes(request):
    return True


async def test_overwrite_backs_up_and_journals_the_id(env, monkeypatch):
    runs = fake_backup(monkeypatch)
    FakeManager.existing = True
    await server.set_secret("agents", "K", generate=True)
    assert len(runs) == 1
    assert journal(env)[-1]["backup"] == "snap-42"
    assert "snap-42" in env["sent"][-1]
    info = await server.restore_info("agents", "K")
    assert "snap-42" in info and "vw-put" in info


async def test_new_secret_takes_no_backup(env, monkeypatch):
    runs = fake_backup(monkeypatch)
    await server.set_secret("agents", "K", generate=True)
    assert runs == [] and "backup" not in journal(env)[-1]
    assert "No backup" in await server.restore_info("agents", "K")


async def test_failed_backup_stops_overwrite_and_delete(env, monkeypatch):
    fake_backup(monkeypatch, None)
    FakeManager.existing = True
    with pytest.raises(ValueError, match="Not changed"):
        await server.set_secret("agents", "K", generate=True)
    monkeypatch.setattr(server, "_delete_hook", yes)
    with pytest.raises(ValueError, match="Not changed"):
        await server.delete_secret("agents", "K")
    assert FakeManager.calls == []
    assert [e["outcome"] for e in journal(env)] == ["refused: backup failed"] * 2


async def test_delete_backs_up_existing(env, monkeypatch):
    runs = fake_backup(monkeypatch)
    monkeypatch.setattr(server, "_delete_hook", yes)
    FakeManager.existing = True
    await server.delete_secret("agents", "K")
    assert len(runs) == 1 and journal(env)[-1]["backup"] == "snap-42"
