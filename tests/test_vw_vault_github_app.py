import json
import logging

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from vw_vault.github_app import GitHubAppRotator
from vw_vault.openrouter import CommandConsumer

from test_vw_vault import login, make, state  # noqa: F401  (state is a fixture)

TOKEN = "ghs_installationtoken0000000000000000001"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PEM = KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption()).decode()


class FakeGitHub:
    def __init__(self, fail_verify=False):
        self.fail_verify = fail_verify
        self.calls = []
        self.claims = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        auth = request.headers["authorization"].removeprefix("Bearer ")
        path = request.url.path
        self.calls.append((request.method, path))
        if path == "/app/installations":
            self.claims = jwt.decode(auth, KEY.public_key(), algorithms=["RS256"])
            return httpx.Response(200, json=[{"id": 77}])
        if path == "/app/installations/77/access_tokens":
            return httpx.Response(201, json={"token": TOKEN, "expires_at": "2026-10-27T13:00:00Z"})
        assert auth == TOKEN
        if path == "/installation/repositories":
            return httpx.Response(401 if self.fail_verify else 200, json={})
        return httpx.Response(204)  # DELETE /installation/token


def setup(state, api, consumers=()):
    eng, bw = make([login("a", "GITHUB_APP_KEY", "github.com", user="12345", pw=PEM)], state)
    eng.rotators = [GitHubAppRotator({"GITHUB_APP_KEY"}, list(consumers),
                                     http=httpx.Client(transport=httpx.MockTransport(api)))]
    return eng, bw


def test_token_is_issued_and_handed_to_the_consumer_only(state, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    api = FakeGitHub()
    out = tmp_path / "consumer.txt"
    eng, _ = setup(state, api, [CommandConsumer("host", f"tee {out}")])
    res = eng.rotate(["a"])
    assert res["rotated"] == 1 and res["results"][0]["consumers"] == ["host"]
    assert out.read_text() == TOKEN
    assert api.claims["iss"] == "12345"
    assert ("DELETE", "/installation/token") not in api.calls
    seen = json.dumps(res) + caplog.text + (state / "journal.jsonl").read_text() if (
        state / "journal.jsonl").exists() else json.dumps(res) + caplog.text
    for p in state.rglob("*"):
        if p.is_file() and p != out:
            seen += p.read_text(errors="ignore")
    assert TOKEN not in seen and PEM not in seen


def test_failed_verify_revokes_the_new_token(state, tmp_path):
    api = FakeGitHub(fail_verify=True)
    eng, _ = setup(state, api)
    res = eng.rotate(["a"])
    r = res["results"][0]
    assert res["failed"] == 1 and r["stage"] == "verify" and r["rolled_back"] is True
    assert ("DELETE", "/installation/token") in api.calls
    assert TOKEN not in json.dumps(res)


def test_secure_note_key_and_status(state):
    class Api(FakeGitHub):
        def __call__(self, request):
            if request.url.path == "/app":
                return httpx.Response(200, json={"slug": "example-automation"})
            if request.url.path == "/app/installations":
                self.claims = jwt.decode(request.headers["authorization"].removeprefix("Bearer "),
                                         KEY.public_key(), algorithms=["RS256"])
                return httpx.Response(200, json=[{"id": 77, "account": {"login": "example-org"},
                                                  "repository_selection": "selected", "permissions": {"contents": "write"}}])
            if request.url.path == "/installation/repositories":
                return httpx.Response(200, json={"repositories": [{"full_name": "example-org/infra"}]})
            return super().__call__(request)

    api = Api()
    note = {"id": "n", "type": 2, "name": "GitHub App example-automation", "notes": PEM,
            "fields": [{"name": "APP_ID", "value": "5506432", "type": 0}], "revisionDate": "2026-10-28T00:00:00Z"}
    rot = GitHubAppRotator({note["name"]}, http=httpx.Client(transport=httpx.MockTransport(api)))
    assert rot.matches(note)
    out = rot.status(note)
    assert api.claims["iss"] == "5506432"
    assert out["installations"][0]["repositories"] == ["example-org/infra"]
    assert ("DELETE", "/installation/token") in api.calls
    assert TOKEN not in json.dumps(out) and "PRIVATE KEY" not in json.dumps(out)


def test_one_scoped_token_per_consumer_account(state, tmp_path):
    from vw_vault.github_app import GitHubConsumer

    minted = []

    class Api(FakeGitHub):
        def __call__(self, request):
            path = request.url.path
            self.calls.append((request.method, path))
            if path == "/app/installations":
                return httpx.Response(200, json=[{"id": 1, "account": {"login": "example-org"}},
                                                 {"id": 2, "account": {"login": "acme"}}])
            if path.endswith("/access_tokens"):
                tok = f"ghs_tok{path.split('/')[3]}_{len(minted)}"
                minted.append((path.split("/")[3], json.loads(request.content or b"{}"), tok))
                return httpx.Response(201, json={"token": tok})
            if path == "/installation/repositories":
                return httpx.Response(200, json={})
            return httpx.Response(204)

    api = Api()
    a, b = tmp_path / "a", tmp_path / "b"
    consumers = [GitHubConsumer("infra", f"tee {a}", "example-org", ["example-org/infra"],
                                {"contents": "write"}),
                 GitHubConsumer("myapp", f"tee {b}", "acme")]
    eng, _ = make([login("k", "GITHUB_APP_KEY", "github.com", user="12345", pw=PEM)], state)
    eng.rotators = [GitHubAppRotator({"GITHUB_APP_KEY"}, consumers,
                                     http=httpx.Client(transport=httpx.MockTransport(api)))]
    res = eng.rotate(["k"])
    assert res["rotated"] == 1
    assert [m[0] for m in minted] == ["1", "2"]
    assert minted[0][1] == {"repositories": ["infra"], "permissions": {"contents": "write"}}
    assert a.read_text() == minted[0][2] and b.read_text() == minted[1][2]


def test_unknown_account_revokes_what_was_minted(state, tmp_path):
    from vw_vault.github_app import GitHubConsumer

    class Api(FakeGitHub):
        def __call__(self, request):
            self.calls.append((request.method, request.url.path))
            if request.url.path == "/app/installations":
                return httpx.Response(200, json=[{"id": 1, "account": {"login": "example-org"}}])
            if request.url.path.endswith("/access_tokens"):
                return httpx.Response(201, json={"token": "ghs_x"})
            return httpx.Response(204)

    api = Api()
    consumers = [GitHubConsumer("ok", f"tee {tmp_path / 'a'}", "example-org"),
                 GitHubConsumer("bad", f"tee {tmp_path / 'b'}", "nobody")]
    eng, _ = make([login("k", "GITHUB_APP_KEY", "github.com", user="12345", pw=PEM)], state)
    eng.rotators = [GitHubAppRotator({"GITHUB_APP_KEY"}, consumers,
                                     http=httpx.Client(transport=httpx.MockTransport(api)))]
    res = eng.rotate(["k"])
    assert res["rotated"] == 0
    assert ("DELETE", "/installation/token") in api.calls
    assert not (tmp_path / "a").exists()
