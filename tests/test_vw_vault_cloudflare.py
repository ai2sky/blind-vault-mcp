import json

import httpx
import pytest

from vw_vault.cloudflare import CloudflareRotator
from vw_vault.openrouter import CommandConsumer

from test_vw_vault import login, make, state  # noqa: F401  (state is a fixture)

MASTER = "cf-master-token-api-tokens-edit-0001"
OLD = "cf-old-token-value-000000000000002"
NEW = "cf-new-token-value-000000000000003"
POLICIES = [{"effect": "allow", "resources": {"com.cloudflare.api.account.zone.z1": "*"},
             "permission_groups": [{"id": "pg1"}]}]


class FakeCloudflare:
    """The slice of the Cloudflare user tokens API the module uses."""

    def __init__(self, fail_verify=False):
        self.tokens = {"t-old": {"id": "t-old", "name": "CF_DNS", "status": "active", "policies": POLICIES,
                                 "expires_on": "2027-01-01T00:00:00Z", "issued_on": "2026-01-01"}}
        self.valid = {OLD: "t-old", MASTER: "t-master"}
        self.fail_verify = fail_verify

    def __call__(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers["authorization"].removeprefix("Bearer ")
        path = request.url.path.removeprefix("/client/v4")
        if path == "/user/tokens/verify":
            tid = self.valid.get(auth)
            if not tid or (self.fail_verify and auth == NEW):
                return httpx.Response(401, json={"success": False})
            return httpx.Response(200, json={"result": {"id": tid, "status": "active"}})
        assert auth == MASTER
        if request.method == "POST":
            body = json.loads(request.content)
            assert "id" not in body and "issued_on" not in body
            self.tokens["t-new"] = {"id": "t-new", **body}
            self.valid[NEW] = "t-new"
            return httpx.Response(200, json={"result": {"id": "t-new", "value": NEW}})
        tid = path.rsplit("/", 1)[1]
        if request.method == "GET":
            return httpx.Response(200, json={"result": self.tokens[tid]})
        self.tokens.pop(tid)
        self.valid = {v: k for v, k in self.valid.items() if k != tid}
        return httpx.Response(200, json={"result": {"id": tid}})


def setup(state, api, consumers=()):
    eng, bw = make([login("a", "CF_DNS", "cloudflare.com", pw=OLD)], state)
    rot = CloudflareRotator({"CF_DNS"}, lambda: MASTER, eng.write_password, list(consumers),
                            http=httpx.Client(transport=httpx.MockTransport(api)))
    eng.rotators = [rot]
    return eng, bw


def test_rotation_replaces_token_and_kills_the_old_one(state, tmp_path):
    api = FakeCloudflare()
    out = tmp_path / "consumer.txt"
    eng, bw = setup(state, api, [CommandConsumer("host", f"tee {out}")])
    eng.mark_rotation(["a"], "leak")
    res = eng.rotate(["a"])
    assert res["rotated"] == 1 and res["results"][0]["consumers"] == ["vault item", "host"]
    assert bw.items["a"]["login"]["password"] == NEW and out.read_text() == NEW
    assert api.tokens["t-new"]["policies"] == POLICIES and api.tokens["t-new"]["name"] == "CF_DNS"
    assert "t-old" not in api.tokens and OLD not in api.valid and "a" not in eng.rotation()
    assert NEW not in json.dumps(res) + (state / "journal.log").read_text()


def test_failed_verify_rolls_back(state, tmp_path):
    api = FakeCloudflare(fail_verify=True)
    out = tmp_path / "consumer.txt"
    eng, bw = setup(state, api, [CommandConsumer("host", f"tee {out}")])
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["rolled_back"] and r["stage"] == "verify"
    assert bw.items["a"]["login"]["password"] == OLD and out.read_text() == OLD
    assert list(api.tokens) == ["t-old"] and OLD in api.valid


def test_failed_consumer_rolls_back_including_itself(state):
    api = FakeCloudflare()
    eng, bw = setup(state, api, [CommandConsumer("bad", "false")])
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "distribute"
    assert r["rolled_back"] is False and r["rollback_error"] == "rollback incomplete: bad"  # it fails again
    assert r["consumers"] == ["vault item", "bad"] and bw.items["a"]["login"]["password"] == OLD
    assert list(api.tokens) == ["t-old"]


def test_dead_current_token_is_not_rotated(state):
    api = FakeCloudflare()
    api.valid.pop(OLD)
    eng, bw = setup(state, api)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "issue" and "not active" in r["error"]
    assert list(api.tokens) == ["t-old"] and bw.items["a"]["login"]["password"] == OLD
