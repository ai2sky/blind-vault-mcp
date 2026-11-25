import json

import pytest

from vw_server.client import VwError
from vw_vault import checks, dedupe, engine as engine_mod
from vw_vault.daemon import dispatch
from vw_vault.engine import Engine
from vw_vault.inventory import REDACTED, Fingerprinter, LeakGuard, describe

PW = "Pa55-word-for-github!"
TOKEN = "ghp_" + "A" * 36
TG = "123456789:" + "B" * 35


def login(id, name, host, user="user-zz9", pw=PW, rev="2025-01-01T00:00:00Z", **extra):
    return {"id": id, "type": 1, "name": name, "folderId": None, "organizationId": None,
            "revisionDate": rev, "creationDate": rev, "deletedDate": None,
            "login": {"username": user, "password": pw, "uris": [{"uri": f"https://{host}/login?t=x"}]},
            **extra}


class FakeBw:
    """In-memory stand-in for VwClient: records calls, never prints."""

    timeout = 60

    def __init__(self, items):
        self.items = {i["id"]: i for i in items}
        self.calls = []

    def _json(self, args):
        if args[:2] == ["list", "items"]:
            if "--archived" in args:
                return [i for i in self.items.values() if i.get("arch")]
            trash = "--trash" in args
            return [i for i in self.items.values() if bool(i.get("deletedDate")) == trash and not i.get("arch")]
        if args[:2] == ["list", "folders"]:
            return [{"id": "f1", "name": "Dev"}]
        if args[:2] == ["list", "org-collections"]:
            return [{"id": c, "name": n} for c, n in getattr(self, "colls", {}).items()]
        return []

    def _encode(self, obj):
        return json.dumps(obj)

    def _run(self, args, stdin=None, extra_env=None):
        self.calls.append(args)
        if args[:2] == ["edit", "item"]:
            new = json.loads(stdin)
            if new.get("fields") is None and "fields" in new:
                new["fields"] = self.items[args[2]].get("fields")  # like bw: a null keeps the old fields
            self.items[args[2]] = new
        elif args[:2] == ["delete", "item"]:
            self.items[args[2]]["deletedDate"] = "now"
        elif args[:2] == ["restore", "item"]:
            self.items[args[2]]["deletedDate"] = None
        elif args[:2] == ["create", "folder"]:
            return json.dumps({"id": "f-new"})
        elif args[:2] == ["create", "org-collection"]:
            self.colls = {**getattr(self, "colls", {}), "c-new": json.loads(stdin)["name"]}
            return json.dumps({"id": "c-new"})
        elif args[:2] == ["create", "item"]:
            new = {**json.loads(stdin), "id": f"copy{len(self.items)}"}
            self.items[new["id"]] = new
            return json.dumps(new)
        return ""


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(engine_mod, "STATE_DIR", tmp_path)
    return tmp_path


def make(items, state, backup="true"):
    bw = FakeBw(items)
    return Engine(bw, backup_cmd=backup), bw


def test_inventory_has_no_values(state):
    items = [login("1", "GitHub", "github.com", fields=[{"name": "API", "value": TOKEN, "type": 1}],
                   notes=f"bot={TG}"),
             {"id": "2", "type": 2, "name": "note", "notes": "TOKEN: " + TOKEN}]
    eng, _ = make(items, state)
    text = json.dumps([eng.summary(), eng.inventory(), eng.dedupe_plan()])
    for value in (PW, TOKEN, TG, "user-zz9", "t=x"):
        assert value not in text
    assert "github-classic" in text
    assert eng.export_inventory()
    assert PW not in (state / "inventory.jsonl").read_text()


def test_value_in_name_is_redacted_and_marked(state):
    eng, _ = make([login("1", f"github {PW}", "github.com")], state)
    assert eng.meta["1"]["name"] == REDACTED
    assert "1" in eng.rotation()


def test_guard_withholds_response(state):
    eng, _ = make([login("1", "GitHub", "github.com")], state)
    assert eng.guard_response(json.dumps({"x": f"leak {PW}"})) == REDACTED
    assert eng.guard_response(json.dumps({"x": "nothing here"})) is None
    assert "1" in eng.rotation()


def test_dedupe_merges_and_trashes_older(state):
    old = login("old", "github", "github.com", rev="2020-01-01T00:00:00Z",
                notes="recovery codes", fields=[{"name": "pin", "value": "1234", "type": 1}])
    old["login"]["uris"].append({"uri": "https://gist.github.com"})
    new = login("new", "GitHub", "github.com", rev="2026-01-01T00:00:00Z")
    other = login("x", "GitLab", "gitlab.com", pw="different-password-1")
    eng, bw = make([old, new, other], state)
    plan = eng.dedupe_plan()
    assert plan["exact_groups"] == 1 and plan["to_trash"] == 1
    assert plan["exact_sample"][0]["keep"]["id"] == "new"
    eng._apply_groups(eng._plans["exact"], lambda *a: None)
    kept = bw.items["new"]
    assert bw.items["old"]["deletedDate"]
    assert {u["uri"] for u in kept["login"]["uris"]} >= {"https://gist.github.com"}
    assert "recovery codes" in kept["notes"]
    assert any(f["name"] == "pin" for f in kept["fields"])
    assert not bw.items["x"]["deletedDate"]
    assert "merged from «github»" in kept["notes"]


def test_dedupe_skips_attachments_and_conflicting_totp(state):
    a = login("a", "s", "site.com", rev="2026-01-01T00:00:00Z")
    b = login("b", "s", "site.com", attachments=[{"id": "x"}])
    with pytest.raises(dedupe.Skip):
        dedupe.merge([a, b])
    c = login("c", "s", "site.com")
    a["login"]["totp"], c["login"]["totp"] = "AAA", "BBB"
    with pytest.raises(dedupe.Skip):
        dedupe.merge([a, c])


def test_keeper_prefers_owner_folder(state):
    imp = login("imp", "s", "site.com", rev="2026-09-07T00:00:00Z", folderId="fi")
    own = login("own", "s", "site.com", rev="2024-01-01T00:00:00Z", folderId="fh")
    bw = FakeBw([imp, own])
    bw._json_orig = bw._json
    bw._json = lambda a: [{"id": "fi", "name": "Import - Chrome"}, {"id": "fh", "name": "Homelab"}] \
        if a[:2] == ["list", "folders"] else bw._json_orig(a)
    eng = Engine(bw, backup_cmd="true")
    assert eng.dedupe_plan()["exact_sample"][0]["keep"]["id"] == "own"


def test_bulk_trash_via_api(state, monkeypatch):
    calls = []

    class Resp:
        def __init__(self, data=None):
            self._data = data or {}

        def raise_for_status(self):
            pass

        def json(self):
            return self._data

    monkeypatch.setattr(engine_mod.httpx, "post", lambda *a, **k: Resp({"access_token": "t"}))
    monkeypatch.setattr(engine_mod.httpx, "put", lambda url, json, **k: calls.append(json["ids"]) or Resp())
    items = [login(str(i), "s", "site.com") for i in range(5)]
    bw = FakeBw(items)
    bw._cfg = type("C", (), {"server_url": "https://vault.example"})()
    eng = Engine(bw, backup_cmd="true", api_key=("user.x", "secret"))
    eng.dedupe_plan()
    result = eng._apply_groups(eng._plans["exact"], lambda *a: None)
    assert result["trashed"] == 4 and len(calls) == 1 and len(calls[0]) == 4
    assert ["sync"] in bw.calls and not any(c[:2] == ["delete", "item"] for c in bw.calls)


def test_similar_groups_need_owner(state):
    eng, _ = make([login("1", "a", "bank.com", pw="first-password-1"),
                   login("2", "a", "bank.com", pw="second-password-2")], state)
    plan = eng.dedupe_plan()
    assert plan["exact_groups"] == 0 and plan["similar_groups"] == 1
    assert PW not in json.dumps(plan)


def test_changes_need_backup(state):
    eng, _ = make([login("1", "a", "a.com")], state, backup="")
    with pytest.raises(VwError):
        eng.trash(["1"], "test")
    eng, _ = make([login("1", "a", "a.com")], state, backup="false")
    with pytest.raises(VwError):
        eng.trash(["1"], "test")


def test_trash_restore_move_journal(state):
    eng, bw = make([login("1", "a", "a.com")], state)
    assert eng.trash(["1"], "dead site")["trashed"] == 1
    assert eng.restore(["1"])["restored"] == 1
    assert eng.move(["1"], "Old")["moved"] == 1
    assert bw.items["1"]["folderId"] == "f-new"
    journal = (state / "journal.log").read_text()
    assert "dead site" in journal and PW not in journal


def test_set_uri(state):
    eng, bw = make([login("1", "a", "old.example.com")], state)
    eng.set_uri("1", "old.example.com", "https://new.example.com/signin")
    assert bw.items["1"]["login"]["uris"][0]["uri"] == "https://new.example.com/signin"


def test_leak_scan_finds_values_in_files(tmp_path):
    (tmp_path / "t.jsonl").write_text(json.dumps({"text": f"here {TOKEN} and {PW}"}) + "\n")
    (tmp_path / "clean.txt").write_text("nothing\n")
    items = [login("1", "a", "a.com", fields=[{"name": "t", "value": TOKEN, "type": 1}]),
             login("2", "b", "b.com", pw="never-written-anywhere")]
    found = checks.leak_scan(items, [str(tmp_path)])
    assert set(found["items"]) == {"1"}
    assert str(tmp_path / "t.jsonl") in found["items"]["1"]
    assert PW not in json.dumps(found) and TOKEN not in json.dumps(found)


def test_twofa_from_directory():
    directory = [["GitHub", {"domain": "github.com", "tfa": ["totp", "u2f"]}]]
    items = [login("1", "a", "gist.github.com"), login("2", "b", "nowhere.example")]
    rows = checks.twofa(items, directory)
    assert [r["id"] for r in rows] == ["1"] and rows[0]["methods"] == ["totp", "u2f"]


def test_dispatch_rejects_unknown(state):
    eng, _ = make([], state)
    with pytest.raises(VwError):
        dispatch(eng, "get_value", {})


def test_fingerprints_are_keyed():
    a, b = Fingerprinter(b"k1"), Fingerprinter(b"k2")
    assert a(PW) == a(PW) and a(PW) != b(PW)
    guard = LeakGuard([])
    meta = describe(login("1", "n", "h.com"), a, guard, {}, {}, {})
    assert meta["password_fp"] == a(PW) and meta["uris"] == ["https://h.com/login"]


def test_socket_round_trip_and_guard(state, tmp_path, monkeypatch):
    import threading

    from vw_vault import daemon

    sock = tmp_path / "s.sock"
    monkeypatch.setenv("VW_VAULT_SOCKET", str(sock))
    eng, _ = make([login("1", "GitHub", "github.com")], state)
    server = daemon.Daemon(sock, eng, idle=3600)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert oct(sock.stat().st_mode & 0o777) == "0o600"
        resp = daemon.call("summary")
        assert resp["ok"] and resp["result"]["items"] == 1
        # a value smuggled into a reason is withheld on the way out
        resp = daemon.call("rotation_mark", {"ids": ["1"], "reason": f"oops {PW}"})
        assert not resp["ok"] and "refused" in resp["error"]
        assert PW not in (state / "rotation.json").read_text()
        assert "1" in eng.rotation()
        assert daemon.call("nope")["ok"] is False
    finally:
        server.shutdown()


def test_text_fields_and_domains_are_not_guarded(state):
    passkey = login("1", "KeePassXC passkey", "webauthn.example.org",
                    fields=[{"name": "KPEX_PASSKEY_RELYING_PARTY", "value": "github.com", "type": 0},
                            {"name": "email", "value": "someone@example.org", "type": 0}],
                    notes="url: https://accounts.example.org/login\napi_key: Zx81-qPw7_Lm2Rt9vB3n")  # gitleaks:allow (fake test value)
    named = login("2", "github.com", "github.com", pw="other-Secret-77")
    eng, _ = make([passkey, named], state)
    assert eng.meta["2"]["name"] == "github.com"
    assert "2" not in eng.rotation()
    assert "Zx81-qPw7_Lm2Rt9vB3n" in eng.guard.values  # a random note value still counts


def test_leak_scan_skips_domains_but_finds_note_tokens(tmp_path):
    (tmp_path / "t.txt").write_text("visit github.com and use Zx81-qPw7_Lm2Rt9vB3n\n")
    item = login("1", "a", "a.com", pw="never-written-anywhere",
                 fields=[{"name": "rp", "value": "github.com", "type": 0}],
                 notes="api_key: Zx81-qPw7_Lm2Rt9vB3n")  # gitleaks:allow (fake test value)
    found = checks.leak_scan([item], [str(tmp_path)])
    assert list(found["items"]) == ["1"]


def _folders(bw, mapping):
    orig = bw._json
    bw._json = lambda a: [{"id": k, "name": v} for k, v in mapping.items()] if a[:2] == ["list", "folders"] else orig(a)


def test_owner_items_are_never_trashed(state):
    oct_a = login("oct", "s", "site.com", folderId="fo")
    home = login("home", "s", "site.com", folderId="fh")
    imp = login("imp", "s", "site.com", folderId="fi", rev="2027-01-01T00:00:00Z")
    bw = FakeBw([oct_a, home, imp])
    _folders(bw, {"fo": "OCT", "fh": "Homelab", "fi": "Import - Chrome"})
    eng = Engine(bw, backup_cmd="true")
    eng.dedupe_plan()
    groups = eng._plans["exact"]
    assert len(groups) == 1 and groups[0][1:] == ["imp"] and groups[0][0] in ("oct", "home")


def test_archived_owner_item_keeps_and_is_not_trashed(state):
    arch = login("arch", "s", "site.com", folderId="fo", arch=True, notes="work note")
    imp = login("imp", "s", "site.com", folderId="fi")
    imp2 = login("imp2", "s", "site.com", folderId="fi", arch=True)
    bw = FakeBw([arch, imp, imp2])
    _folders(bw, {"fo": "OCT", "fi": "Import - Chrome"})
    eng = Engine(bw, backup_cmd="true")
    assert eng.meta["arch"]["archived"]
    eng.dedupe_plan()
    assert eng._plans["exact"] == [["arch", "imp"]]
    plan = eng.collections_plan()
    assert plan["folders"][0]["folder"] == "OCT" and plan["folders"][0]["archived"] == 1
    assert eng.unarchive(["arch"])["unarchived"] == 1
    assert ["restore", "item", "arch"] in bw.calls


def test_keepassxc_passkey_converts(state):
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from vw_vault import passkeys

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    cid = base64.urlsafe_b64encode(b"\x01" * 32).decode().rstrip("=")
    item = {"id": "pk", "type": 1, "name": "GitHub (Passkey)", "login": {"username": "me"},
            "fields": [{"name": "KPEX_PASSKEY_PRIVATE_KEY_PEM", "value": pem, "type": 1},
                       {"name": "KPEX_PASSKEY_CREDENTIAL_ID", "value": cid, "type": 0},
                       {"name": "KPEX_PASSKEY_RELYING_PARTY", "value": "github.com", "type": 0},
                       {"name": "KPEX_PASSKEY_USER_HANDLE", "value": "dXNlcg", "type": 0}]}
    eng, bw = make([item], state)
    out = eng.convert_passkeys(["pk"])
    assert out["converted"] == 1 and pem not in json.dumps(out)
    cred = bw.items["pk"]["login"]["fido2Credentials"][0]
    assert cred["rpId"] == "github.com" and cred["credentialId"].startswith("b64.")
    assert cred["keyAlgorithm"] == "ECDSA" and cred["keyCurve"] == "P-256"
    assert bw.items["pk"]["login"]["uris"][0]["uri"] == "https://github.com"
    with pytest.raises(passkeys.NotConvertible):
        passkeys.converted(bw.items["pk"])
    assert eng.drop_kpex_fields(["pk"])["cleaned"] == 1
    assert not any(f["name"].startswith("KPEX_") for f in bw.items["pk"]["fields"] or [])
    assert bw.items["pk"]["login"]["fido2Credentials"]


def test_lan_proxy_passes_https_to_plain_http(tmp_path):
    import http.server
    import ssl
    import threading
    import urllib.request

    from vw_vault.lanproxy import LanProxy

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"x" * 300000
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    up = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    proxy = LanProxy(f"http://127.0.0.1:{up.server_address[1]}", 0, tmp_path)
    proxy.url = f"https://127.0.0.1:{proxy.sock.getsockname()[1]}"
    proxy.start()
    ctx = ssl.create_default_context(cafile=str(proxy.cert))
    with urllib.request.urlopen(proxy.url + "/alive", context=ctx, timeout=10) as r:
        assert r.status == 200 and len(r.read()) == 300000
    assert not (tmp_path / "loopback.key").exists()
    up.shutdown()


def test_copy_to_other_org_checks_fingerprint(state):
    item = login("u", "UTILITIES_VAULT_PASSWORD", "x.com", organizationId="work", collectionIds=["cu"])
    bw = FakeBw([item])
    orig = bw._json
    bw._json = lambda a: [{"id": "work", "name": "acme"}, {"id": "home", "name": "personal"}] \
        if a[:2] == ["list", "organizations"] else orig(a)
    eng = Engine(bw, backup_cmd="true")
    out = eng.copy_to(["u"], "keys", "personal")
    assert len(out["copied"]) == 1 and not out["failed"]
    copy = bw.items[out["copied"][0]["copy"]]
    assert copy["organizationId"] == "home" and copy["collectionIds"] == ["c-new"]
    assert not bw.items["u"].get("deletedDate")  # the original stays until trashed on purpose
    assert PW not in json.dumps(out)


def test_compare_keyring_returns_verdict_only(state, monkeypatch):
    import subprocess as sp

    eng, _ = make([login("1", "a", "a.com")], state)
    monkeypatch.setattr(engine_mod.subprocess, "run",
                        lambda args, **k: sp.CompletedProcess(args, 0, PW + "\n", ""))
    out = eng.compare_keyring("1", {"service": "x", "key": "y"})
    assert out == {"match": True, "field": "login.password"} and PW not in json.dumps(out)
    monkeypatch.setattr(engine_mod.subprocess, "run",
                        lambda args, **k: sp.CompletedProcess(args, 0, "other\n", ""))
    assert eng.compare_keyring("1", {"service": "x"})["match"] is False


def test_to_collection_copies_checks_and_trashes(state):
    a = login("a", "router", "10.0.0.1", folderId="fh")
    b = login("b", "with file", "x.com", folderId="fh", attachments=[{"id": "f"}])
    bw = FakeBw([a, b])
    orig = bw._json
    bw._json = lambda x: [{"id": "home", "name": "personal"}] if x[:2] == ["list", "organizations"] else orig(x)
    eng = Engine(bw, backup_cmd="true")
    out = eng.to_collection(["a", "b"], "infra", "personal")
    assert out["moved"] == 1 and out["failed"][0]["id"] == "b"
    assert bw.items["a"]["deletedDate"] and not bw.items["b"].get("deletedDate")
    copies = [i for i in bw.items.values() if i.get("organizationId") == "home"]
    assert len(copies) == 1 and copies[0]["collectionIds"] == ["c-new"]
    # the second call finds the collection by name instead of creating another
    eng.to_collection([], "infra", "personal")
    assert sum(1 for c in bw.calls if c[:2] == ["create", "org-collection"]) == 1


def test_delete_folders_keeps_items(state):
    eng, bw = make([login("1", "a", "a.com", folderId="f1")], state)
    assert eng.folders_plan()["folders"] == [{"name": "Dev", "items": 1}]
    assert eng.delete_folders(["Dev", "nope"])["deleted"] == ["Dev"]
    assert ["delete", "folder", "f1"] in bw.calls and not bw.items["1"].get("deletedDate")


def test_move_collection_item_into_folder_via_api(state, monkeypatch):
    calls = []

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"access_token": "t"}

    monkeypatch.setattr(engine_mod.httpx, "post", lambda *a, **k: Resp())
    monkeypatch.setattr(engine_mod.httpx, "put", lambda url, json, **k: calls.append((url, json)) or Resp())
    org_item = login("o", "MYAPP_X", "x.com", organizationId="home", collectionIds=["c1"])
    bw = FakeBw([org_item])
    bw._cfg = type("C", (), {"server_url": "https://vault.example"})()
    eng = Engine(bw, backup_cmd="true", api_key=("user.x", "secret"))
    eng.mark_rotation(["o"], "leak")
    assert eng.move(["o"], "Утечки")["moved"] == 1
    assert calls[0][0].endswith("/api/ciphers/o/partial") and calls[0][1]["folderId"] == "f-new"
    assert bw.items["o"]["collectionIds"] == ["c1"]


def test_rename_changes_only_the_name(state):
    item = login("1", "UTILITIES_ADDC_USER", "addc.ae", user="me@example.com", pw="s3cret-pw",
                 fields=[{"name": "note", "value": "keep", "type": 0}],
                 organizationId="home", collectionIds=["c1"])
    eng, bw = make([item], state)
    out = eng.rename("1", "UTILITIES_ADDC_LOGIN")
    assert out == {"renamed": "1", "old": "UTILITIES_ADDC_USER", "new": "UTILITIES_ADDC_LOGIN"}
    saved = bw.items["1"]
    assert saved["name"] == "UTILITIES_ADDC_LOGIN"
    assert saved["login"]["username"] == "me@example.com" and saved["login"]["password"] == "s3cret-pw"
    assert saved["fields"] == [{"name": "note", "value": "keep", "type": 0}]
    assert saved["collectionIds"] == ["c1"] and saved["organizationId"] == "home"
    assert "s3cret-pw" not in json.dumps(out)
    assert eng.items["1"]["name"] == "UTILITIES_ADDC_LOGIN"


def test_rename_refuses_bad_requests(state):
    a = login("1", "A", "a.com", organizationId="home", collectionIds=["c1"])
    same = login("2", "B", "b.com", organizationId="home", collectionIds=["c1"])
    other_coll = login("3", "C", "c.com", organizationId="home", collectionIds=["c2"])
    personal = login("4", "P", "p.com")
    personal2 = login("6", "Q", "q.com")
    dead = login("5", "D", "d.com", organizationId="home", collectionIds=["c1"], deletedDate="2025-02-01T00:00:00Z")
    eng, bw = make([a, same, other_coll, personal, personal2, dead], state)
    with pytest.raises(VwError, match="empty"):
        eng.rename("1", "   ")
    with pytest.raises(VwError, match="no such item"):
        eng.rename("nope", "X")
    with pytest.raises(VwError, match="already has this name"):
        eng.rename("1", "A")
    with pytest.raises(VwError, match="same collection"):
        eng.rename("1", "B")
    with pytest.raises(VwError, match="personal"):
        eng.rename("4", "Q")
    assert eng.rename("1", "C")["new"] == "C"  # same name in another collection is fine
    assert eng.rename("1", "D")["new"] == "D"  # a trashed item does not count
    assert bw.items["1"]["name"] == "D"


def test_copy_inherits_rotation(state):
    a = login("a", "r", "10.0.0.1")
    bw = FakeBw([a])
    orig = bw._json
    bw._json = lambda x: [{"id": "home", "name": "personal"}] if x[:2] == ["list", "organizations"] else orig(x)
    eng = Engine(bw, backup_cmd="true")
    eng.mark_rotation(["a"], "leak in transcript")
    eng.to_collection(["a"], "infra", "personal")
    copy = next(i for i in bw.items.values() if i.get("organizationId") == "home")
    assert eng.rotation()[copy["id"]]["reasons"] == ["leak in transcript"]


def test_drop_field_and_set_from_ansible_vault(state, monkeypatch, tmp_path):
    import subprocess as sp

    item = login("1", "openrouter", "openrouter.ai",
                 fields=[{"name": "OpenRouter API key", "value": "sk-or-dead-0000000000", "type": 0}])
    eng, bw = make([item], state)
    assert eng.drop_field("1", "OpenRouter API key") == {"dropped": "OpenRouter API key"}
    assert not bw.items["1"]["fields"]
    with pytest.raises(VwError):
        eng.drop_field("1", "nope")
    vault = tmp_path / "vault.yml"
    vault.write_text("encrypted")
    real_run = sp.run

    def fake_run(args, **k):
        if args[:2] == ["ansible-vault", "view"]:
            return sp.CompletedProcess(args, 0, "vault_github_bot_token: github_pat_NEWVALUE123\n", "")
        return real_run(args, **k)

    monkeypatch.setattr(engine_mod.subprocess, "run", fake_run)
    out = eng.set_from_ansible_vault("1", str(vault), "vault_github_bot_token")
    assert bw.items["1"]["login"]["password"] == "github_pat_NEWVALUE123"
    assert "NEWVALUE" not in json.dumps(out) and out["password_fp_before"] != out["password_fp_after"]


def test_export_to_ansible_vault(state, monkeypatch, tmp_path):
    import subprocess as sp

    store = {"plain": "vault_other: \"x\"\n"}
    real = sp.run

    def fake_run(args, **k):
        if args[:2] == ["ansible-vault", "view"]:
            return sp.CompletedProcess(args, 0, store["plain"], "")
        if args[:2] == ["ansible-vault", "encrypt"]:
            store["plain"] = k["input"]
            return sp.CompletedProcess(args, 0, "$ANSIBLE_VAULT;1.1;AES256\nabc\n", "")
        return real(args, **k)

    monkeypatch.setattr(engine_mod.subprocess, "run", fake_run)
    pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"  # gitleaks:allow (fake test value)
    note = {"id": "n", "type": 2, "name": "GitHub App infra-runtime", "notes": pem,
            "fields": [{"name": "APP_ID", "value": "5569100", "type": 0}]}
    eng, _ = make([note], state)
    vault = tmp_path / "vault.yml"
    vault.write_text("$ANSIBLE_VAULT;1.1;AES256\nold\n")
    out = eng.export_to_ansible_vault("n", str(vault), "vault_github_app_infra_runtime_key", "notes")
    assert out["action"] == "added" and "BEGIN" not in json.dumps(out)
    from ruamel.yaml import YAML
    data = YAML(typ="safe").load(store["plain"])
    assert data["vault_github_app_infra_runtime_key"] == pem and data["vault_other"] == "x"
    assert eng.export_to_ansible_vault("n", str(vault), "vault_app_id", "APP_ID")["action"] == "added"
    with pytest.raises(VwError):
        eng.export_to_ansible_vault("n", str(vault), "Bad-Name", "notes")


def test_write_password_twice_uses_the_latest_revision(state):
    """A rollback writes the item a second time; it must carry the revision the first write made,
    as Vaultwarden refuses a stale one (seen in practice)."""
    eng, bw = make([login("a", "pve.example.internal", "pve.example.internal")], state)
    snapshot = dict(eng.items["a"])
    real_run = bw._run

    def strict_run(args, stdin=None, extra_env=None):
        if args[:2] == ["edit", "item"]:
            sent = json.loads(stdin)
            if sent.get("revisionDate") != bw.items[args[2]].get("revisionDate"):
                raise VwError("The cipher is out of date")
            out = real_run(args, stdin, extra_env)
            bw.items[args[2]]["revisionDate"] = (sent.get("revisionDate") or "") + "+1"
            return json.dumps(bw.items[args[2]])
        return real_run(args, stdin, extra_env)

    bw._run = strict_run
    eng.write_password(snapshot, "new-value-1")
    eng.write_password(snapshot, "old-value-back")  # the rollback holds the old snapshot
    assert bw.items["a"]["login"]["password"] == "old-value-back"
