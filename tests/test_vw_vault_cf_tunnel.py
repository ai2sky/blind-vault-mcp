import base64
import json
import logging

import httpx
import pytest

from vw_server.client import VwError
from vw_vault import cf_tunnel
from vw_vault.cf_tunnel import CloudflareTunnelRotator, decode_token, load_entries, parse_entry

from test_vw_vault import login, make, state  # noqa: F401  (state is a fixture)

MASTER = "cf-master-tunnel-edit-token-0001"
ACCOUNT, TUNNEL = "acc-1", "tun-1"
OLD_SECRET = base64.b64encode(b"o" * 32).decode()
NEW_SECRET = base64.b64encode(b"n" * 32).decode()
COLLECTIONS = {"c1": "infra"}


def token(secret, account=ACCOUNT, tunnel=TUNNEL):
    return base64.b64encode(json.dumps({"a": account, "t": tunnel, "s": secret}).encode()).decode()


OLD, NEW = token(OLD_SECRET), token(NEW_SECRET)


class FakeTunnelApi:
    """The slice of the tunnels API the module uses, plus a cloudflared that runs on the token file."""

    def __init__(self, tmp_path, ignore_patch=False, patch_status=200, new_token_refused=False, hostname_ok=True):
        self.secret = OLD_SECRET
        self.ignore_patch, self.patch_status = ignore_patch, patch_status
        self.new_token_refused, self.hostname_ok = new_token_refused, hostname_ok
        self.token_file, self.restart_log = tmp_path / "cloudflared-token.txt", tmp_path / "restarts.txt"
        self.token_file.write_text(OLD)
        self.calls: list[tuple[str, str]] = []
        self.patches: list[str] = []

    def restarts(self) -> int:
        return self.restart_log.read_text().count("r") if self.restart_log.exists() else 0

    def connectors(self):
        n = self.restarts()
        running = self.token_file.read_text()
        live = n == 0 or (running == token(self.secret) and not (self.new_token_refused and running == NEW))
        return [{"id": f"c{n}", "conns": [{"is_pending_reconnect": not live}]}]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "hostname.test":
            return httpx.Response(200 if self.hostname_ok else 502)
        assert request.headers["authorization"] == f"Bearer {MASTER}"
        path = request.url.path.removeprefix(f"/client/v4/accounts/{ACCOUNT}/cfd_tunnel/")
        self.calls.append((request.method, path))
        if path != TUNNEL and not path.startswith(TUNNEL + "/"):
            return httpx.Response(404)
        suffix = path.removeprefix(TUNNEL)
        if request.method == "PATCH":
            body = json.loads(request.content)
            self.patches.append(body["tunnel_secret"])
            if self.patch_status != 200:
                return httpx.Response(self.patch_status)
            if not self.ignore_patch:
                self.secret = body["tunnel_secret"]
            return httpx.Response(200, json={"result": {"id": TUNNEL}})
        if suffix == "/token":
            return httpx.Response(200, json={"result": token(self.secret)})
        if suffix == "/connections":
            return httpx.Response(200, json={"result": self.connectors()})
        return httpx.Response(200, json={"result": {"id": TUNNEL, "name": "home"}})


def entry(tmp_path, **over):
    raw = {"item": "CLOUDFLARED_TUNNEL_TOKEN", "collection": "infra", "account_id": ACCOUNT, "tunnel_id": TUNNEL,
           "consumers": [{"name": "cloudflared-env", "cmd": f"tee {tmp_path / 'cloudflared-token.txt'}"}],
           "restart": f'sh -c "echo r >> {tmp_path / "restarts.txt"}"', "check_retries": 2, "check_delay": 0,
           "owner_consent": True}
    raw.update(over)
    return raw


def setup(state, tmp_path, raw=None, write_item=None, collections=("c1",), pw=OLD, **api_kw):
    eng, bw = make([login("a", "CLOUDFLARED_TUNNEL_TOKEN", "cloudflare.com", pw=pw,
                          collectionIds=list(collections))], state)
    api = FakeTunnelApi(tmp_path, **api_kw)
    write = write_item(eng.write_password) if write_item else eng.write_password
    rot = CloudflareTunnelRotator([parse_entry(raw or entry(tmp_path))], lambda: MASTER, write, lambda: COLLECTIONS,
                                  http=httpx.Client(transport=httpx.MockTransport(api)),
                                  secret=lambda: NEW_SECRET, sleep=lambda s: None)
    eng.rotators = [rot]
    return eng, bw, api


def edits(bw):
    return [c for c in bw.calls if c[:2] == ["edit", "item"]]


def test_rotation_issues_a_token_and_checks_the_connection(state, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    eng, bw, api = setup(state, tmp_path)
    res = eng.rotate(["a"])
    r = res["results"][0]
    assert r["ok"] and r["module"] == "cloudflare-tunnel"
    assert r["consumers"] == ["vault item", "cloudflared-env", "restart"]
    assert api.patches == [NEW_SECRET] and api.restarts() == 1
    assert bw.items["a"]["login"]["password"] == NEW and api.token_file.read_text() == NEW
    for text in (json.dumps(res), (state / "journal.log").read_text(), caplog.text):
        for value in (OLD, NEW, OLD_SECRET, NEW_SECRET, MASTER):
            assert value not in text


def test_without_consent_nothing_is_called(state, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    raw = entry(tmp_path)
    del raw["owner_consent"]
    eng, bw, api = setup(state, tmp_path, raw)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "issue" and r["module"] == "cloudflare-tunnel"
    assert "explicit consent" in r["error"] and "owner_consent" in r["error"]
    assert api.calls == [] and api.patches == [] and edits(bw) == [] and api.restarts() == 0
    assert bw.items["a"]["login"]["password"] == OLD
    assert "explicit consent" in eng.rotation()["a"]["reasons"][-1]
    # the reason is written, the values are not
    for text in (json.dumps(eng.rotation()), (state / "journal.log").read_text(), caplog.text):
        for value in (OLD, MASTER):
            assert value not in text
    # an explicit false is the same as no flag
    eng, bw, api = setup(state, tmp_path, entry(tmp_path, owner_consent=False))
    assert not eng.rotate(["a"])["results"][0]["ok"] and api.calls == []


def test_failed_connection_puts_the_old_token_back(state, tmp_path):
    eng, bw, api = setup(state, tmp_path, new_token_refused=True)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "verify" and r["rolled_back"] is True
    assert api.patches == [NEW_SECRET, OLD_SECRET] and api.secret == OLD_SECRET
    assert bw.items["a"]["login"]["password"] == OLD and api.token_file.read_text() == OLD
    assert api.restarts() == 2  # cloudflared was restarted on the old token and connected again
    assert "a" in eng.rotation()
    assert NEW not in json.dumps(r) + (state / "journal.log").read_text()


def test_a_connector_that_was_already_there_is_not_proof(state, tmp_path):
    # a restart that does nothing leaves the old connector alive: that must not pass as a connection
    eng, bw, api = setup(state, tmp_path, entry(tmp_path, restart="true"))
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "verify"
    assert bw.items["a"]["login"]["password"] == OLD and api.secret == OLD_SECRET


def test_hostname_check_is_part_of_the_verdict(state, tmp_path):
    raw = entry(tmp_path, check_url="http://hostname.test/alive")
    eng, bw, api = setup(state, tmp_path, raw, hostname_ok=False)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "verify" and bw.items["a"]["login"]["password"] == OLD
    eng, bw, api = setup(state, tmp_path, raw)
    assert eng.rotate(["a"])["results"][0]["ok"]


def test_a_token_without_the_new_secret_is_not_written(state, tmp_path):
    eng, bw, api = setup(state, tmp_path, ignore_patch=True)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "issue" and "does not carry the new secret" in r["error"]
    assert "old secret was put back" in r["error"]
    assert edits(bw) == [] and api.restarts() == 0 and api.token_file.read_text() == OLD
    assert api.patches == [NEW_SECRET, OLD_SECRET]


def test_refused_secret_change_leaves_everything(state, tmp_path):
    eng, bw, api = setup(state, tmp_path, patch_status=403)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "issue" and "old token is intact" in r["error"]
    assert edits(bw) == [] and api.restarts() == 0


def test_a_token_of_another_tunnel_is_refused_before_any_change(state, tmp_path):
    for pw in (token(OLD_SECRET, tunnel="other"), token(OLD_SECRET, account="other"), "not-a-token"):
        eng, bw, api = setup(state, tmp_path, pw=pw)
        r = eng.rotate(["a"])["results"][0]
        assert not r["ok"] and r["stage"] == "issue" and "configured tunnel" in r["error"]
        assert api.calls == [] and edits(bw) == []


def test_failed_vault_write_gives_the_secret_back_without_a_restart(state, tmp_path):
    def flaky(real):
        calls = []

        def write(item, value):
            calls.append(value)
            if len(calls) == 1:
                raise VwError("vault write failed")
            real(item, value)
        return write

    eng, bw, api = setup(state, tmp_path, write_item=flaky)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "distribute" and r["consumers"] == ["vault item"]
    assert api.patches == [NEW_SECRET, OLD_SECRET] and api.restarts() == 0
    assert bw.items["a"]["login"]["password"] == OLD and api.token_file.read_text() == OLD


def test_item_in_another_collection_is_not_matched(state, tmp_path):
    eng, bw, api = setup(state, tmp_path, collections=("c9",))
    assert not eng.rotators[0].matches(bw.items["a"])
    assert eng.rotate(["a"])["results"][0]["stage"] == "match" and api.calls == []


def test_token_decoding():
    assert decode_token(OLD) == {"a": ACCOUNT, "t": TUNNEL, "s": OLD_SECRET}
    assert decode_token(OLD.rstrip("=")) == decode_token(OLD)
    for bad in ("", "***", base64.b64encode(b"[1]").decode(), base64.b64encode(b'{"a": "x"}').decode()):
        assert decode_token(bad) is None


def test_config(tmp_path, state):
    for bad in ({"restart": None}, {"token": OLD}, {"check_url": "ftp://x"}, {"owner_consent": "true"}):
        with pytest.raises(VwError) as err:
            parse_entry({k: v for k, v in entry(tmp_path, **bad).items() if v is not None})
        assert OLD not in str(err.value)
    path = tmp_path / "tunnels.json"
    with pytest.raises(VwError, match="cannot be read"):
        load_entries(str(path))
    path.write_text(json.dumps([entry(tmp_path), entry(tmp_path)]))
    with pytest.raises(VwError, match="twice"):
        load_entries(str(path))
    # nothing without a setting; the consent flag is not defaulted on
    eng, _ = make([], state)
    assert cf_tunnel.from_settings({}, eng) is None
    raw = entry(tmp_path)
    del raw["owner_consent"]
    path.write_text(json.dumps([raw]))
    rot = cf_tunnel.from_settings({"VW_VAULT_CF_TUNNELS": str(path)}, eng)
    assert isinstance(rot, CloudflareTunnelRotator) and rot.entries[0].consent_given is False
