import asyncio
import json
import shutil
import tempfile

import pytest

from vw_server import approve, audit, owner_approval as oa, server as vw

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def sandbox(monkeypatch):
    """Sockets in a short temp dir, the notification captured, the real hooks restored after.

    Not tmp_path: a Unix socket path is limited to ~107 bytes, and tmp_path plus
    blind-vault-approve-<uid>/<pid>-<hex>.sock goes over it on runners with a long
    pytest base dir; ask_owner then fails closed and every test sees no request.
    """
    runtime = tempfile.mkdtemp(prefix="oa-", dir="/tmp")
    monkeypatch.setenv("XDG_RUNTIME_DIR", runtime)
    monkeypatch.delenv(oa.MODE_ENV, raising=False)
    sent = []
    monkeypatch.setattr(audit, "notify", sent.append)
    yield sent
    vw.set_approval_hook(vw.deny_all)
    vw.set_delete_hook(vw.deny_deletes)
    shutil.rmtree(runtime, ignore_errors=True)


def code_of(sent):
    return sent[0].split("Code: ")[1].split()[0]


async def wait_for_socket():
    for _ in range(100):
        found = await approve._pending()
        if found:
            return found[0][0]
        await asyncio.sleep(0.02)
    raise AssertionError("no pending request")


async def test_the_right_code_approves_once(sandbox):
    task = asyncio.create_task(oa.ask_owner("vw_set: add new secret 'X'"))
    path = await wait_for_socket()
    assert (await approve._talk(path, "info"))["summary"] == "vw_set: add new secret 'X'"
    reply = await approve._talk(path, f"code {code_of(sandbox)}")
    assert reply["result"] == "approved"
    assert await task is True
    assert not path.exists()


async def test_the_code_comes_first_so_a_long_summary_cannot_push_it_out(sandbox):
    task = asyncio.create_task(oa.ask_owner("telegram_send_as_me: " + "long text " * 200))
    path = await wait_for_socket()
    assert sandbox[0].startswith("Code: ")
    assert sandbox[0].index("Code: ") < sandbox[0].index("Approval needed")
    await approve._talk(path, "deny")
    assert await task is False


async def test_the_code_is_in_the_notification_and_nowhere_the_agent_can_read(sandbox):
    task = asyncio.create_task(oa.ask_owner("vw_set: x"))
    path = await wait_for_socket()
    info = await approve._talk(path, "info")
    assert code_of(sandbox) not in json.dumps(info)
    await approve._talk(path, "deny")
    assert await task is False


async def test_three_wrong_codes_refuse(sandbox):
    task = asyncio.create_task(oa.ask_owner("vw_set: x"))
    path = await wait_for_socket()
    wrong = "000000" if code_of(sandbox) != "000000" else "111111"
    assert (await approve._talk(path, f"code {wrong}"))["result"] == "wrong"
    assert (await approve._talk(path, f"code {wrong}"))["result"] == "wrong"
    assert (await approve._talk(path, f"code {wrong}"))["result"] == "closed"
    assert await task is False


async def test_a_deny_refuses(sandbox):
    task = asyncio.create_task(oa.ask_owner("vw_set: x"))
    path = await wait_for_socket()
    await approve._talk(path, "deny")
    assert await task is False


async def test_timeout_refuses(sandbox, monkeypatch):
    monkeypatch.setattr(oa, "_ttl", lambda: 0.05)
    assert await oa.ask_owner("vw_set: x") is False


async def test_without_a_notification_channel_nothing_is_approved(monkeypatch):
    def broken(text):
        raise RuntimeError("VW_NOTIFY_URL is not set")
    monkeypatch.setattr(audit, "notify", broken)
    assert await oa.ask_owner("vw_set: x") is False
    assert not list(oa.socket_dir().glob("*.sock"))


async def test_one_approval_is_one_call(sandbox):
    task = asyncio.create_task(oa.ask_owner("vw_set: x"))
    path = await wait_for_socket()
    await approve._talk(path, f"code {code_of(sandbox)}")
    assert await task is True
    sandbox.clear()
    task = asyncio.create_task(oa.ask_owner("vw_set: x"))
    path = await wait_for_socket()
    assert code_of(sandbox)  # a fresh code for the next call
    await approve._talk(path, "deny")
    assert await task is False


async def test_install_replaces_the_deny_hooks(sandbox):
    oa.install_vw()
    assert vw._approval_hook is not vw.deny_all and vw._delete_hook is not vw.deny_deletes
    task = asyncio.create_task(vw._approval_hook(vw.ApprovalRequest("TOKEN", False, "my-app", "telegram_create_bot")))
    path = await wait_for_socket()
    summary = (await approve._talk(path, "info"))["summary"]
    assert "telegram_create_bot" in summary and "my-app" in summary and "TOKEN" in summary
    await approve._talk(path, "deny")
    assert await task is False


async def test_deny_mode_keeps_the_default_hooks(monkeypatch):
    monkeypatch.setenv(oa.MODE_ENV, "deny")
    oa.install_vw()
    assert vw._approval_hook is vw.deny_all


async def test_elicitation_with_a_wrong_code_does_not_approve(sandbox):
    class Result:
        action = "accept"

        class data:
            code = "not-the-code"

    class Ctx:
        async def elicit(self, message, schema):
            return Result

    class App:
        def get_context(self):
            return Ctx()

    task = asyncio.create_task(oa.ask_owner("vw_set: x", App()))
    path = await wait_for_socket()
    await asyncio.sleep(0.1)
    assert not task.done()  # the agent's guesses neither approve nor refuse
    await approve._talk(path, "deny")
    assert await task is False


async def test_elicitation_with_the_right_code_approves(sandbox):
    holder = {}

    class Ctx:
        async def elicit(self, message, schema):
            for _ in range(100):
                if sandbox:
                    break
                await asyncio.sleep(0.01)

            class Data:
                code = code_of(sandbox)

            class Result:
                action = "accept"
                data = Data
            return Result

    class App:
        def get_context(self):
            return Ctx()

    assert await oa.ask_owner("vw_set: x", App()) is True
