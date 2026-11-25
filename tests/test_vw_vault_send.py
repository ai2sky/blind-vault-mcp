"""vault_send, vault_send_list, vault_send_delete and openrouter_keys: fakes only, no network."""

import datetime
import json

import httpx
import pytest
from vw_server.client import VwError

from vw_vault.daemon import dispatch
from vw_vault.engine import Engine
from vw_vault.openrouter import OpenRouterRotator

from test_vw_vault import FakeBw, login, state  # noqa: F401  (state is a fixture)

SECRET = "Sup3r-Secret-Value-for-Alice-0042"
NOTE_SECRET = "-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\n-----END PRIVATE KEY-----\n"  # gitleaks:allow (fake test value)
FIELD_SECRET = "custom-field-secret-value-77"
ACCESS_PW = "open-sesame-from-chat"
KEY = "K3yK3yK3yK3yK3yK3yK3yK"  # the decryption key inside a Send URL


class SendBw(FakeBw):
    """FakeBw that also keeps Sends the way `bw send ...` shows them."""

    def __init__(self, items):
        super().__init__(items)
        self.sends = {}
        self.requests = {}  # what bw was asked to create, by Send id
        self.server = "https://127.0.0.1:18443"

    def _json(self, args):
        if args[:2] == ["send", "list"]:
            # bw lists every Send with its access URL, key included
            return [{**s, "accessUrl": f"{self.server}/#/send/{s['id']}/{KEY}"} for s in self.sends.values()]
        return super()._json(args)

    def _run(self, args, stdin=None, extra_env=None):
        if args[:2] == ["send", "create"]:
            self.calls.append(args)
            body = json.loads(stdin)
            send = {**body, "id": f"send-{len(self.sends) + 1}", "accessCount": 0,
                    "password": "hashed" if body.get("password") else None}
            self.sends[send["id"]] = send
            self.requests[send["id"]] = body
            return json.dumps({**send, "accessUrl": f"{self.server}/#/send/{send['id']}/{KEY}"})
        if args[:2] == ["send", "delete"]:
            self.calls.append(args)
            self.sends.pop(args[2])
            return ""
        return super()._run(args, stdin, extra_env)


def make_send(state, **kw):
    items = [
        login("a", "ALICE_OPENROUTER_KEY", "openrouter.ai", pw=SECRET),
        {"id": "n", "type": 2, "name": "GitHub App key", "notes": NOTE_SECRET, "organizationId": None,
         "deletedDate": None, "fields": [{"name": "APP_TOKEN", "value": FIELD_SECRET, "type": 1}]},
    ]
    bw = SendBw(items)
    return Engine(bw, backup_cmd="false", **kw), bw  # a backup would fail: a Send must not need one


def logs(state):
    return (state / "journal.log").read_text()


def test_send_creates_a_hidden_text_send_and_returns_no_value(state):
    eng, bw = make_send(state, public_url="https://vault.example")
    out = eng.send("a", max_views=2, expires_hours=48, password=ACCESS_PW, note="for Alice")
    body = bw.requests["send-1"]
    assert body["type"] == 0 and body["text"] == {"text": SECRET, "hidden": True}
    assert body["maxAccessCount"] == 2 and body["password"] == ACCESS_PW and body["notes"] == "for Alice"
    assert body["deletionDate"] == body["expirationDate"] and body["disabled"] is False
    soon = datetime.datetime.strptime(body["deletionDate"], "%Y-%m-%dT%H:%M:%S.000Z").replace(
        tzinfo=datetime.timezone.utc)
    delta = soon - datetime.datetime.now(datetime.timezone.utc)
    assert datetime.timedelta(hours=47, minutes=59) < delta <= datetime.timedelta(hours=48)
    assert "ALICE_OPENROUTER_KEY" in body["name"] and SECRET not in body["name"]
    assert out["send"] == "send-1" and out["max_views"] == 2 and out["password"] is True
    assert out["expires"] == body["deletionDate"]
    # the loopback origin bw built is replaced by the public one; the path with the key stays
    assert out["url"] == f"https://vault.example/#/send/send-1/{KEY}"
    for text in (json.dumps(out), logs(state)):
        assert SECRET not in text and ACCESS_PW not in text
    # the URL carries the key: it is in the tool result only, never in the journal
    assert KEY not in logs(state) and "#/send/" not in logs(state)
    assert json.loads(logs(state).splitlines()[-1])["action"] == "send"


def test_send_without_public_url_keeps_what_bw_built(state):
    eng, _ = make_send(state)
    assert eng.send("a")["url"] == f"https://127.0.0.1:18443/#/send/send-1/{KEY}"


def test_send_defaults_and_no_access_password(state):
    eng, bw = make_send(state)
    out = eng.send("a")
    assert out["max_views"] == 1 and out["password"] is False
    assert bw.requests["send-1"]["password"] is None and bw.requests["send-1"]["maxAccessCount"] == 1


def test_send_field_selection(state):
    eng, bw = make_send(state)
    eng.send("a", field="password")
    eng.send("n", field="notes")
    eng.send("n", field="APP_TOKEN")
    texts = [s["text"]["text"] for s in bw.requests.values()]
    assert texts == [SECRET, NOTE_SECRET, FIELD_SECRET]
    assert "(notes)" in bw.sends["send-2"]["name"] and "(APP_TOKEN)" in bw.sends["send-3"]["name"]
    for text in (logs(state), *(s["name"] for s in bw.sends.values())):
        assert not any(v in text for v in (SECRET, NOTE_SECRET, FIELD_SECRET))


@pytest.mark.parametrize("kw", [{"max_views": 6}, {"max_views": 0}, {"max_views": True}, {"expires_hours": 169},
                                {"expires_hours": 0}, {"expires_hours": 24.5}, {"password": ""}])
def test_send_refuses_out_of_range_requests(state, kw):
    eng, bw = make_send(state)
    with pytest.raises(VwError):
        eng.send("a", **kw)
    assert bw.sends == {}


def test_send_limits_are_the_documented_maxima(state):
    eng, bw = make_send(state)
    eng.send("a", max_views=5, expires_hours=168)
    assert bw.sends["send-1"]["maxAccessCount"] == 5


def test_send_refuses_missing_item_field_and_trashed_item(state):
    eng, bw = make_send(state)
    for args in (("nope",), ("a", "notes"), ("a", "NO_SUCH_FIELD"), ("n", "password")):
        with pytest.raises(VwError):
            eng.send(*args)
    eng.items["a"]["deletedDate"] = "now"
    with pytest.raises(VwError):
        eng.send("a")
    assert bw.sends == {}


def test_send_bw_failure_carries_no_value(state):
    eng, bw = make_send(state)

    def boom(args, stdin=None, extra_env=None):
        bw.last_stderr = f"Error: could not store {SECRET}"
        raise VwError("bw send exited with code 1")

    bw._run = boom
    with pytest.raises(VwError) as err:
        eng.send("a")
    assert SECRET not in str(err.value)


def test_send_list_has_metadata_and_no_urls(state):
    eng, bw = make_send(state)
    eng.send("a", password=ACCESS_PW)
    eng.send("n", field="notes")
    bw.sends["send-2"]["disabled"] = True
    bw.sends["send-2"]["accessCount"] = 1
    rows = eng.send_list()["sends"]
    assert [r["id"] for r in rows] == ["send-1", "send-2"]
    assert rows[0]["password"] is True and rows[1]["password"] is False
    assert rows[1]["disabled"] is True and rows[1]["views"] == 1 and rows[0]["max_views"] == 1
    assert rows[0]["expires"] and set(rows[0]) == {"id", "name", "expires", "deletes", "views", "max_views",
                                                   "disabled", "password"}
    dump = json.dumps(rows)
    assert KEY not in dump and "#/send/" not in dump and ACCESS_PW not in dump and SECRET not in dump


def test_send_delete_removes_and_journals(state):
    eng, bw = make_send(state)
    eng.send("a")
    assert eng.send_delete("send-1") == {"deleted": "send-1"}
    assert bw.sends == {} and ["send", "delete", "send-1"] in bw.calls
    assert json.loads(logs(state).splitlines()[-1]) == {**json.loads(logs(state).splitlines()[-1]),
                                                        "action": "send-delete", "send": "send-1"}


@pytest.mark.parametrize("bad", ["no-such-send", "--help", "", "a b", "../x"])
def test_send_delete_refuses_unknown_and_odd_ids(state, bad):
    eng, bw = make_send(state)
    eng.send("a")
    with pytest.raises(VwError):
        eng.send_delete(bad)
    assert list(bw.sends) == ["send-1"]


def test_dispatch_routes_the_send_commands(state):
    eng, bw = make_send(state)
    out = dispatch(eng, "send", {"id": "a", "field": "password", "expires_hours": 12, "max_views": 3,
                                 "note": "x"})
    assert out["max_views"] == 3 and bw.requests["send-1"]["notes"] == "x"
    assert len(dispatch(eng, "send_list", {})["sends"]) == 1
    with pytest.raises(VwError):
        dispatch(eng, "send", {"id": "a", "max_views": 9})
    assert dispatch(eng, "send_delete", {"id": "send-1"}) == {"deleted": "send-1"}


# --- openrouter_keys ------------------------------------------------------------------

MASTER = "sk-or-v1-master-provisioning-0001"
LABEL = "sk-or-v1-abc...xyz"
FULL_HASH = "9f8e7d6c5b4a39281716151413121110"


def openrouter_engine(state, rows, status=200):
    seen = []

    def api(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.headers["authorization"]))
        if status != 200:
            return httpx.Response(status, json={})
        page = rows if request.url.params["offset"] == "0" else []
        return httpx.Response(200, json={"data": page})

    eng, bw = make_send(state)
    eng.items["m"] = login("m", "OPENROUTER_PROVISIONING_KEY", "openrouter.ai", pw=MASTER)
    rot = OpenRouterRotator({"OPENROUTER_API_KEY"}, lambda: eng.master_value("OPENROUTER_PROVISIONING_KEY"),
                            eng.write_password, http=httpx.Client(transport=httpx.MockTransport(api)))
    eng.rotators = [rot]
    return eng, seen


def test_openrouter_keys_lists_metadata_without_key_text(state):
    rows = [{"name": "OPENROUTER_API_KEY", "hash": FULL_HASH, "label": LABEL, "limit": 50, "usage": 1.5,
             "disabled": False, "created_at": "2026-11-18T09:00:00Z", "updated_at": "2026-11-18T09:00:00Z"},
            {"name": "legacy", "hash": "aaaa1111bbbb2222", "label": LABEL, "limit": None, "usage": 12.25,
             "disabled": True, "created_at": "2025-03-01T10:00:00Z", "updated_at": None}]
    eng, seen = openrouter_engine(state, rows)
    out = dispatch(eng, "openrouter_keys", {})["keys"]
    assert [k["name"] for k in out] == ["legacy", "OPENROUTER_API_KEY"]  # oldest first
    assert out[0] == {"name": "legacy", "hash_prefix": "aaaa1111", "created": "2025-03-01T10:00:00Z",
                      "updated": None, "disabled": True, "limit": None, "usage": 12.25}
    assert out[1]["hash_prefix"] == FULL_HASH[:8] and out[1]["limit"] == 50
    dump = json.dumps(out)
    assert FULL_HASH not in dump and LABEL not in dump and MASTER not in dump
    assert all(auth == f"Bearer {MASTER}" for _, _, auth in seen) and all(m == "GET" for m, _, _ in seen)


def test_openrouter_keys_error_and_off_module(state):
    eng, _ = openrouter_engine(state, [], status=403)
    with pytest.raises(VwError) as err:
        eng.openrouter_keys()
    assert MASTER not in str(err.value) and "403" in str(err.value)
    eng.rotators = []
    with pytest.raises(VwError):
        eng.openrouter_keys()
