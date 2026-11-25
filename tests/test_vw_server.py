import logging

import pytest

from vw_server import server
from vw_server.client import VwError

SECRET = "s3cr3t-VALUE-9f2"


class FakeClient:
    names = ["A", "B"]
    set_calls: list[tuple[str, str]] = []
    fail = False

    def list_names(self):
        return list(self.names)

    def set_secret(self, name, value):
        if self.fail:
            raise VwError("boom")
        self.set_calls.append((name, value))


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    FakeClient.set_calls = []
    FakeClient.fail = False
    monkeypatch.setattr(server, "VwClient", FakeClient)
    monkeypatch.setattr(server, "_approval_hook", server.deny_all)
    return FakeClient


async def test_default_hook_denies(fake):
    result = await server.vw_set("NEW", SECRET)
    assert "not given" in result
    assert fake.set_calls == []


async def test_approved_writes_once_without_leaking(fake, caplog):
    requests = []

    async def hook(request):
        requests.append(request)
        return True

    server.set_approval_hook(hook)
    with caplog.at_level(logging.DEBUG):
        result = await server.vw_set("NEW", SECRET)
    assert fake.set_calls == [("NEW", SECRET)]
    assert SECRET not in result
    assert SECRET not in caplog.text
    assert not requests[0].overwrite
    assert SECRET not in repr(requests[0]) + server.describe(requests[0])


async def test_overwrite_flag(fake):
    seen = []

    async def hook(request):
        seen.append(request)
        return False

    server.set_approval_hook(hook)
    await server.vw_set("A", SECRET)
    assert seen[0].overwrite
    assert "overwrite" in server.describe(seen[0])


@pytest.mark.parametrize("name", ["", "a b", "x" * 65, "a/b", "a\n", "a.b", "a-b", "1abc"])
async def test_bad_name_rejected(fake, name):
    seen = []

    async def hook(request):
        seen.append(request)
        return True

    server.set_approval_hook(hook)
    with pytest.raises(ValueError):
        await server.vw_set(name, SECRET)
    assert seen == []
    assert fake.set_calls == []


async def test_client_error_is_message(fake):
    async def yes(request):
        return True

    server.set_approval_hook(yes)
    fake.fail = True
    result = await server.vw_set("NEW", SECRET)
    assert "boom" in result and SECRET not in result


async def test_list_returns_names(fake):
    assert await server.vw_list() == ["A", "B"]
