import json

import httpx
import pytest

from vw_vault.openrouter import CommandConsumer, OpenRouterRotator

from test_vw_vault import login, make, state  # noqa: F401  (state is a fixture)

MASTER = "sk-or-v1-master-provisioning-0001"
OLD = "sk-or-v1-old-key-value-000000002"
NEW = "sk-or-v1-new-key-value-000000003"


class FakeOpenRouter:
    """The slice of the OpenRouter keys API the module uses."""

    def __init__(self, fail_verify=False):
        self.keys = {"h-old": {"hash": "h-old", "name": "OPENROUTER_API_KEY", "limit": 50}}
        self.valid = {OLD: "h-old"}
        self.fail_verify = fail_verify
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers["authorization"].removeprefix("Bearer ")
        path = request.url.path.removeprefix("/api/v1")
        self.calls.append((request.method, path))
        if path == "/key":
            ok = auth in self.valid and not (self.fail_verify and auth == NEW)
            return httpx.Response(200 if ok else 401, json={})
        assert auth == MASTER
        if request.method == "GET":
            rows = list(self.keys.values()) if request.url.params["offset"] == "0" else []
            return httpx.Response(200, json={"data": rows})
        if request.method == "POST":
            body = json.loads(request.content)
            self.keys["h-new"] = {"hash": "h-new", **body}
            self.valid[NEW] = "h-new"
            return httpx.Response(200, json={"data": {"hash": "h-new"}, "key": NEW})
        h = path.rsplit("/", 1)[1]
        self.keys.pop(h)
        self.valid = {v: k for v, k in self.valid.items() if k != h}
        return httpx.Response(200, json={})


def setup(state, api, consumers=()):
    eng, bw = make([login("a", "OPENROUTER_API_KEY", "openrouter.ai", pw=OLD)], state)
    rot = OpenRouterRotator({"OPENROUTER_API_KEY"}, lambda: MASTER, eng.write_password, list(consumers),
                            http=httpx.Client(transport=httpx.MockTransport(api)))
    eng.rotators = [rot]
    return eng, bw


def test_rotation_replaces_key_and_kills_the_old_one(state, tmp_path):
    api = FakeOpenRouter()
    out = tmp_path / "consumer.txt"
    eng, bw = setup(state, api, [CommandConsumer("host", f"tee {out}")])
    eng.mark_rotation(["a"], "leak")
    res = eng.rotate(["a"])
    assert res["rotated"] == 1 and res["results"][0]["consumers"] == ["vault item", "host"]
    assert bw.items["a"]["login"]["password"] == NEW and out.read_text() == NEW
    assert api.keys["h-new"]["limit"] == 50 and "h-old" not in api.keys
    assert OLD not in api.valid and "a" not in eng.rotation()
    assert NEW not in json.dumps(res) + (state / "journal.log").read_text()


def test_failed_verify_rolls_back(state, tmp_path):
    api = FakeOpenRouter(fail_verify=True)
    out = tmp_path / "consumer.txt"
    eng, bw = setup(state, api, [CommandConsumer("host", f"tee {out}")])
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["rolled_back"] and r["stage"] == "verify"
    assert bw.items["a"]["login"]["password"] == OLD and out.read_text() == OLD
    assert list(api.keys) == ["h-old"] and OLD in api.valid


def test_failed_consumer_rolls_back_including_itself(state):
    api = FakeOpenRouter()
    eng, bw = setup(state, api, [CommandConsumer("bad", "false")])
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "distribute"
    assert r["rolled_back"] is False and r["rollback_error"] == "rollback incomplete: bad"  # it fails again
    assert r["consumers"] == ["vault item", "bad"] and bw.items["a"]["login"]["password"] == OLD
    assert "h-new" not in api.keys


def test_old_key_still_alive_is_reported(state):
    api = FakeOpenRouter()
    eng, _ = setup(state, api)
    api.keys["h-old"]["name"] = "other"  # the old key is not found by name, so it is not deleted
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["old_alive"] and "still works" in r["error"]


def test_unreachable_api_changes_nothing(state):
    def boom(request):
        raise httpx.ConnectError("secret detail")

    eng, bw = setup(state, boom)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "issue" and "secret detail" not in json.dumps(r)
    assert bw.items["a"]["login"]["password"] == OLD


def test_matches_only_named_live_logins(state):
    rot = OpenRouterRotator({"X"}, lambda: "", lambda i, v: None)
    assert rot.matches({"type": 1, "name": "X"})
    assert not rot.matches({"type": 2, "name": "X"})
    assert not rot.matches({"type": 1, "name": "X", "deletedDate": "now"})
    assert not rot.matches({"type": 1, "name": "Y"})


def test_master_value_needs_exactly_one_login(state):
    eng, _ = make([login("m", "OPENROUTER_PROVISIONING_KEY", "openrouter.ai", pw=MASTER)], state)
    assert eng.master_value("OPENROUTER_PROVISIONING_KEY") == MASTER
    with pytest.raises(Exception, match="found 0"):
        eng.master_value("nope")


def test_consumer_limited_to_items_skips_other_keys(state, tmp_path):
    """A person's own key goes only to that person's consumer, the shared consumers never see it."""
    api = FakeOpenRouter()
    mine, other = tmp_path / "mine.txt", tmp_path / "other.txt"
    eng, bw = setup(state, api, [CommandConsumer("mine", f"tee {mine}", items=["OPENROUTER_API_KEY"]),
                                 CommandConsumer("other", f"tee {other}", items=["ALICE_OPENROUTER_API_KEY"]),
                                 CommandConsumer("everyone", f"tee {tmp_path / 'all.txt'}")])
    eng.mark_rotation(["a"], "leak")
    res = eng.rotate(["a"])
    assert res["results"][0]["consumers"] == ["vault item", "mine", "everyone"]
    assert mine.read_text() == NEW and not other.exists() and (tmp_path / "all.txt").read_text() == NEW


def test_load_consumers_reads_items(tmp_path):
    from vw_vault.openrouter import load_consumers
    f = tmp_path / "c.json"
    f.write_text(json.dumps([{"name": "a", "cmd": "true", "items": ["X"]}, {"name": "b", "cmd": "true"}]))
    a, b = load_consumers(str(f))
    assert a.serves({"name": "X"}) and not a.serves({"name": "Y"}) and b.serves({"name": "Y"})
