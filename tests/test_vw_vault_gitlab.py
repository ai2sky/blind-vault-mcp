import datetime
import json

import httpx

from vw_vault.gitlab import GitLabRotator
from vw_vault.openrouter import CommandConsumer

from test_vw_vault import login, make, state  # noqa: F401  (state is a fixture)

OLD = "glpat-old-token-value-0000000002"  # gitleaks:allow (fake test value)
NEW = "glpat-new-token-value-0000000003"  # gitleaks:allow (fake test value)
TODAY = datetime.date(2026, 10, 27)


class FakeGitLab:
    """The slice of the GitLab personal access token API the module uses."""

    def __init__(self, fail_verify=False, scopes=("api",)):
        self.valid = {OLD: {"id": 7, "active": True, "revoked": False, "scopes": list(scopes),
                            "created_at": "2026-01-01T10:00:00.000Z", "expires_at": "2026-04-11"}}
        self.fail_verify = fail_verify
        self.rotate_params = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        token = request.headers["private-token"]
        path = request.url.path.removeprefix("/api/v4")
        record = self.valid.get(token)
        if record is None or (self.fail_verify and token == NEW):
            return httpx.Response(401, json={"message": "401 Unauthorized"})
        if request.method == "GET" and path == "/personal_access_tokens/self":
            return httpx.Response(200, json=record)
        assert request.method == "POST" and path == "/personal_access_tokens/self/rotate"
        self.rotate_params = dict(request.url.params)
        self.valid.pop(token)
        self.valid[NEW] = {**record, "id": 8}
        return httpx.Response(200, json={"id": 8, "token": NEW, "expires_at": self.rotate_params.get("expires_at")})


def setup(state, api, consumers=()):
    eng, bw = make([login("a", "GITLAB_TOKEN", "gitlab.com", pw=OLD)], state)
    rot = GitLabRotator({"GITLAB_TOKEN"}, eng.write_password, list(consumers),
                        http=httpx.Client(transport=httpx.MockTransport(api)), today=lambda: TODAY)
    eng.rotators = [rot]
    return eng, bw


def test_rotation_replaces_token_and_kills_the_old_one(state, tmp_path):
    api = FakeGitLab()
    out = tmp_path / "consumer.txt"
    eng, bw = setup(state, api, [CommandConsumer("host", f"tee {out}")])
    eng.mark_rotation(["a"], "leak")
    res = eng.rotate(["a"])
    assert res["rotated"] == 1 and res["results"][0]["consumers"] == ["vault item", "host"]
    assert bw.items["a"]["login"]["password"] == NEW and out.read_text() == NEW
    assert OLD not in api.valid and NEW in api.valid and "a" not in eng.rotation()
    assert api.rotate_params == {"expires_at": "2027-02-04"}  # the old lifetime of 100 days, from today
    assert NEW not in json.dumps(res) + (state / "journal.log").read_text()


def test_failed_verify_keeps_the_new_value_in_place(state, tmp_path):
    api = FakeGitLab(fail_verify=True)
    out = tmp_path / "consumer.txt"
    eng, bw = setup(state, api, [CommandConsumer("host", f"tee {out}")])
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "verify" and r["rolled_back"]
    # the old token is gone for good, so the vault keeps the new one
    assert bw.items["a"]["login"]["password"] == NEW and out.read_text() == NEW


def test_failed_consumer_is_reported(state):
    api = FakeGitLab()
    eng, bw = setup(state, api, [CommandConsumer("bad", "false")])
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "distribute"
    assert r["rolled_back"] is False and "bad" in r["rollback_error"]
    assert bw.items["a"]["login"]["password"] == NEW


def test_dead_or_scopeless_token_is_not_rotated(state):
    api = FakeGitLab()
    api.valid.pop(OLD)
    eng, bw = setup(state, api)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "issue" and "not active" in r["error"]
    api = FakeGitLab(scopes=("read_api",))
    eng, bw = setup(state, api)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and "scope" in r["error"] and OLD in api.valid
    assert bw.items["a"]["login"]["password"] == OLD
