import base64
import dataclasses
import json
import fcntl
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

from vw_server.client import VwClient, VwConfig, VwError, load_config

SECRET = "s3cr3t-VALUE-9f2"

# Fake bw: records argv, env and stdin into calls.jsonl next to itself and keeps
# the "vault" in state.json. When a "fail" file exists, create/edit echo their
# stdin to stderr and exit non-zero, to prove stderr is not forwarded.
FAKE = f"""#!{sys.executable}
import base64, json, os, sys
a = sys.argv[1:]
d = os.path.dirname(os.path.abspath(__file__))
stdin = "" if sys.stdin.isatty() else sys.stdin.read()
with open(os.path.join(d, "calls.jsonl"), "a") as f:
    f.write(json.dumps({{"argv": a, "env": dict(os.environ), "stdin": stdin}}) + "\\n")
sp = os.path.join(d, "state.json")
st = json.load(open(sp)) if os.path.exists(sp) else {{"items": []}}
if os.path.exists(os.path.join(d, "fail")) and a[0] in ("create", "edit"):
    sys.stderr.write("boom " + base64.b64decode(stdin).decode())
    sys.exit(3)
if os.path.exists(os.path.join(d, "loggedin")) and a[0] in ("config", "login"):
    sys.exit(1)
if os.path.exists(os.path.join(d, "strict")):
    # like the real bw: an unlock replaces the session of whoever unlocked before in this data
    # dir, and a list with a replaced session prints nothing and exits 0
    import time
    cur = os.path.join(d, "session")
    if a[0] == "unlock":
        open(cur, "w").write("S%d" % os.getpid())
        time.sleep(0.05)
        print("S%d" % os.getpid())
        sys.exit()
    if a[0] == "list":
        time.sleep(0.05)
        if os.environ.get("BW_SESSION") != open(cur).read():
            sys.exit()
if a[0] == "unlock":
    print("SESSION")
elif a[:2] == ["list", "folders"]:
    print(json.dumps([{{"id": "f1", "name": "other"}}, {{"id": "f2", "name": "agents"}}]))
elif a[:2] == ["list", "org-collections"]:
    print(json.dumps([{{"id": "c1", "name": "other"}}, {{"id": "c2", "name": "shared"}}] + st.get("colls", [])))
elif a[:2] == ["list", "org-members"]:
    print(json.dumps([{{"id": "m1", "email": "reader@example.com", "status": 2}}] + st.get("members", [])))
elif a[:2] == ["confirm", "org-member"]:
    for m in st.get("members", []):
        if m["id"] == a[2]:
            m["status"] = 2
    json.dump(st, open(sp, "w"))
elif a[:2] == ["get", "org-collection"]:
    print(json.dumps({{"id": a[2], "name": "shared", "groups": [], "users": st.get("users", [])}}))
elif a[:2] == ["edit", "org-collection"]:
    st["users"] = json.loads(base64.b64decode(stdin))["users"]
    json.dump(st, open(sp, "w"))
elif a[:2] == ["create", "org-collection"]:
    st.setdefault("colls", []).append({{"id": "cn", "name": json.loads(base64.b64decode(stdin))["name"]}})
    json.dump(st, open(sp, "w"))
elif a[:2] == ["delete", "item"]:
    st["items"] = [i for i in st["items"] if i["id"] != a[2]]
    json.dump(st, open(sp, "w"))
elif a[:3] == ["list", "items", "--organizationid"]:
    # like the real bw: --collectionid next to --organizationid is ignored
    print(json.dumps([i for i in st["items"] if i.get("organizationId") or i.get("collectionIds")]))
elif a[:2] == ["list", "items"]:
    print(json.dumps([i for i in st["items"] if i.get("folderId") == a[3]]))
elif a[0] == "encode":
    print(base64.b64encode(stdin.encode()).decode())
elif a[:2] in (["create", "item"], ["edit", "item"]):
    item = json.loads(base64.b64decode(stdin))
    if a[0] == "create":
        item["id"] = "i%d" % len(st["items"])
        st["items"].append(item)
    else:
        st["items"] = [item if i["id"] == a[2] else i for i in st["items"]]
    json.dump(st, open(sp, "w"))
"""


@pytest.fixture
def cfg(tmp_path):
    fake = tmp_path / "bw"
    fake.write_text(FAKE)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    (tmp_path / "cs").write_text("client-secret")
    (tmp_path / "mp").write_text("master-pass")
    return VwConfig("https://vw.example", "user.1", tmp_path / "cs", tmp_path / "mp",
                        "agents", str(fake))


def calls(cfg):
    log = Path(cfg.bw).parent / "calls.jsonl"
    return [json.loads(line) for line in log.read_text().splitlines()]


def seed(cfg, items):
    (Path(cfg.bw).parent / "state.json").write_text(json.dumps({"items": items}))


def test_list_names_has_no_values(cfg):
    seed(cfg, [{"id": "1", "name": "B", "notes": SECRET, "folderId": "f2"},
               {"id": "2", "name": "A", "notes": SECRET, "folderId": "f2"},
               {"id": "3", "name": "Hidden", "notes": SECRET, "folderId": "f1"}])
    names = VwClient(cfg).list_names()
    assert names == ["A", "B"]
    assert SECRET not in json.dumps(names)


def test_set_secret_create_then_update_keeps_value_out_of_argv(cfg):
    c = VwClient(cfg)
    assert c.set_secret("TOKEN", SECRET) is True
    assert c.set_secret("TOKEN", SECRET + "2") is False
    assert c.list_names() == ["TOKEN"]
    log = calls(cfg)
    assert all(SECRET not in " ".join(call["argv"]) for call in log)
    assert all(SECRET not in json.dumps(call["env"]) for call in log)
    assert any(SECRET in base64.b64decode(x["stdin"]).decode()
               for x in log if x["argv"][0] in ("create", "edit"))
    # The parent environment is not inherited (the interpreter may add its own LC_* vars).
    assert all("VW_URL" not in x["env"] and "PYTHONPATH" not in x["env"] for x in log)
    assert {k for x in log for k in x["env"] if k.startswith("BW_")} == {
        "BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET"}


def test_bw_failure_does_not_leak_value(cfg):
    (Path(cfg.bw).parent / "fail").write_text("")
    with pytest.raises(VwError) as e:
        VwClient(cfg).set_secret("TOKEN", SECRET)
    assert SECRET not in str(e.value)


def test_name_rule_uses_fullmatch(cfg):
    for bad in ("ABC\n", "A\n", "x" * 65):
        with pytest.raises(VwError, match="invalid secret name"):
            VwClient(cfg).set_secret(bad, "x")
    for good in ("ABC_1", "x" * 64):
        assert VwClient(cfg).set_secret(good, "x") in (True, False)


def test_invalid_name_and_missing_folder(cfg):
    for bad in ("bad name", "a.b", "1abc", "x" * 65):
        with pytest.raises(VwError):
            VwClient(cfg).set_secret(bad, "x")
    with pytest.raises(VwError, match="folder"):
        VwClient(dataclasses.replace(cfg, folder="nope")).list_names()


def test_already_logged_in_bw_is_tolerated(cfg):
    (Path(cfg.bw).parent / "loggedin").write_text("")
    c = VwClient(cfg)
    assert c.set_secret("TOKEN", SECRET) is True
    assert c.list_names() == ["TOKEN"]
    assert ["config", "server", cfg.server_url] in [x["argv"] for x in calls(cfg)]


def test_load_config_requires_url():
    with pytest.raises(VwError, match="VW_URL"):
        load_config({"VW_CLIENT_ID": "x"})


def test_load_config_defaults():
    c = load_config({"VW_URL": "u", "VW_CLIENT_ID": "i",
                     "VW_CLIENT_SECRET_FILE": "/a", "VW_MASTER_PASSWORD_FILE": "/b"})
    assert c.folder == "agents" and c.client_secret_file == Path("/a")


def test_folder_mode_bw_arguments(cfg):
    VwClient(cfg).set_secret("TOKEN", SECRET)
    argvs = [x["argv"] for x in calls(cfg)]
    assert ["list", "folders"] in argvs
    assert ["list", "items", "--folderid", "f2"] in argvs
    assert not any("--organizationid" in a for a in argvs)
    stored = json.loads((Path(cfg.bw).parent / "state.json").read_text())["items"][0]
    assert stored["folderId"] == "f2" and "collectionIds" not in stored


@pytest.fixture
def ccfg(cfg):
    return dataclasses.replace(cfg, organization_id="org1", collection="shared")


def test_collection_mode_bw_arguments_and_item(ccfg):
    c = VwClient(ccfg)
    assert c.set_secret("TOKEN", SECRET) is True
    assert c.set_secret("TOKEN", SECRET + "2") is False
    assert c.list_names() == ["TOKEN"]
    log = calls(ccfg)
    argvs = [x["argv"] for x in log]
    assert ["list", "org-collections", "--organizationid", "org1"] in argvs
    assert ["list", "items", "--organizationid", "org1", "--collectionid", "c2"] in argvs
    assert ["list", "folders"] not in argvs
    assert not any("--folderid" in a for a in argvs)
    items = json.loads((Path(ccfg.bw).parent / "state.json").read_text())["items"]
    assert len(items) == 1
    assert items[0]["organizationId"] == "org1" and items[0]["collectionIds"] == ["c2"]
    assert "folderId" not in items[0]
    assert all(SECRET not in " ".join(x["argv"]) for x in log)
    assert all(SECRET not in json.dumps(x["env"]) for x in log)


def test_collection_mode_missing_collection(ccfg):
    with pytest.raises(VwError, match="collection"):
        VwClient(dataclasses.replace(ccfg, collection="nope")).list_names()


def test_collection_failure_does_not_leak_value(ccfg):
    (Path(ccfg.bw).parent / "fail").write_text("")
    with pytest.raises(VwError) as e:
        VwClient(ccfg).set_secret("TOKEN", SECRET)
    assert SECRET not in str(e.value)


def test_load_config_collection_vars():
    base = {"VW_URL": "u", "VW_CLIENT_ID": "i",
            "VW_CLIENT_SECRET_FILE": "/a", "VW_MASTER_PASSWORD_FILE": "/b"}
    assert not load_config(base).use_collection
    c = load_config({**base, "VW_ORGANIZATION_ID": "o", "VW_COLLECTION": "shared"})
    assert c.use_collection and c.organization_id == "o" and c.collection == "shared"
    with pytest.raises(VwError, match="together"):
        load_config({**base, "VW_ORGANIZATION_ID": "o"})
    assert load_config({**base, "VW_ORGANIZATION_ID": "o"}, allow_org_only=True).organization_id == "o"


def test_login_item_format_keeps_value_out_of_argv(ccfg):
    c = VwClient(ccfg)
    assert c.set_collection_secret("shared", "API_KEY", SECRET) is True
    assert c.set_collection_secret("shared", "API_KEY", SECRET + "2") is False
    log = calls(ccfg)
    assert all(SECRET not in " ".join(x["argv"]) for x in log)
    items = json.loads((Path(ccfg.bw).parent / "state.json").read_text())["items"]
    assert len(items) == 1
    assert items[0]["type"] == 1 and items[0]["name"] == "API_KEY"
    assert items[0]["login"]["password"] == SECRET + "2" and "notes" not in items[0]
    assert items[0]["collectionIds"] == ["c2"]


def test_collections_create_list_and_names(ccfg):
    c = VwClient(ccfg)
    assert c.create_collection("fresh") is True
    assert c.create_collection("fresh") is False
    assert c.list_collections() == ["fresh", "other", "shared"]
    c.set_collection_secret("shared", "K", SECRET)
    assert c.list_collection_names("shared") == ["K"]
    with pytest.raises(VwError):
        c.create_collection("bad;name")


def test_org_operations_need_organization(cfg):
    with pytest.raises(VwError, match="ORGANIZATION"):
        VwClient(cfg).list_collections()


def test_grant_reader_is_idempotent_and_read_only(ccfg):
    c = VwClient(ccfg)
    assert c.grant_reader("shared", "Reader@example.com") is True
    assert c.grant_reader("shared", "reader@example.com") is False
    users = json.loads((Path(ccfg.bw).parent / "state.json").read_text())["users"]
    assert users == [{"id": "m1", "readOnly": True, "hidePasswords": False}]
    with pytest.raises(VwError, match="member"):
        c.grant_reader("shared", "m9")


def test_grant_reader_invites_and_confirms_a_new_account(ccfg, monkeypatch):
    sp = Path(ccfg.bw).parent / "state.json"
    sent = []

    def api(self, method, path, body):
        sent.append((method, path, body))
        st = json.loads(sp.read_text()) if sp.exists() else {"items": []}
        st["members"] = [{"id": "m2", "email": body["emails"][0], "status": 1}]
        st["users"] = [{"id": "m2", "readOnly": True, "hidePasswords": False}]
        sp.write_text(json.dumps(st))

    monkeypatch.setattr(VwClient, "_api", api)
    c = VwClient(ccfg)
    assert c.grant_reader("shared", "new@example.com") is True
    assert sent == [("POST", "/api/organizations/org1/users/invite", {
        "emails": ["new@example.com"], "type": 2, "accessAll": False, "groups": [],
        "collections": [{"id": "c2", "readOnly": True, "hidePasswords": False, "manage": False}]})]
    assert ["confirm", "org-member", "m2", "--organizationid", "org1"] in [x["argv"] for x in calls(ccfg)]
    assert json.loads(sp.read_text())["members"][0]["status"] == 2
    assert c.grant_reader("shared", "new@example.com") is False
    assert len(sent) == 1


def test_grant_reader_refuses_an_unaccepted_invitation(ccfg, monkeypatch):
    sp = Path(ccfg.bw).parent / "state.json"
    sp.write_text(json.dumps({"items": [], "members": [{"id": "m3", "email": "x@example.com", "status": 0}]}))
    with pytest.raises(VwError, match="accepted"):
        VwClient(ccfg).grant_reader("shared", "x@example.com")


def test_delete_secret(ccfg):
    c = VwClient(ccfg)
    c.set_collection_secret("shared", "K", SECRET)
    assert c.delete_secret("shared", "K") is True
    assert c.delete_secret("shared", "K") is False
    assert c.list_collection_names("shared") == []


def test_keyring_credentials_replace_files(cfg, monkeypatch):
    kcfg = dataclasses.replace(cfg, client_secret="kc-secret", master_password="kc-master",
                               client_secret_file=Path("/nope"), master_password_file=Path("/nope"))
    VwClient(kcfg).list_names()
    log = calls(kcfg)
    unlock = next(x for x in log if x["argv"][0] == "unlock")
    assert unlock["argv"][1] == "--passwordenv" and "kc-master" not in " ".join(unlock["argv"])
    login = next(x for x in log if x["argv"][0] == "login")
    assert login["env"]["BW_CLIENTSECRET"] == "kc-secret"


def test_load_config_from_keyring(monkeypatch):
    from vw_server import client
    vals = {"client_id": "user.k", "client_secret": "ks", "master_password": "km"}
    monkeypatch.setattr(client, "keyring_get", vals.get)
    monkeypatch.setattr(client.os, "environ", {"VW_URL": "u"})
    c = load_config()
    assert (c.client_id, c.client_secret, c.master_password) == ("user.k", "ks", "km")


def test_unlock_syncs_the_local_vault(cfg):
    VwClient(cfg).list_names()
    argv = [c["argv"] for c in calls(cfg)]
    assert argv.index(["sync"]) == next(i for i, a in enumerate(argv) if a[0] == "unlock") + 1


def test_bw_runs_with_its_own_data_dir(cfg, tmp_path):
    """A personal `bw login` in the same HOME must not get in the way of the account's."""
    own = dataclasses.replace(cfg, bw_data_dir=str(tmp_path / "bw-data"))
    VwClient(own).list_names()
    envs = {c["env"].get("BITWARDENCLI_APPDATA_DIR") for c in calls(own)}
    assert envs == {str(tmp_path / "bw-data")} and (tmp_path / "bw-data").is_dir()


def test_load_config_gives_each_account_a_data_dir(monkeypatch):
    base = {"VW_URL": "https://vw", "VW_CLIENT_ID": "user.a",
            "VW_CLIENT_SECRET_FILE": "/x", "VW_MASTER_PASSWORD_FILE": "/y"}
    a = load_config(base).bw_data_dir
    b = load_config({**base, "VW_CLIENT_ID": "user.b"}).bw_data_dir
    assert a != b and "/.local/state/vw/bw-" in a
    assert load_config({**base, "VW_BW_DATA_DIR": "/d"}).bw_data_dir == "/d"


def test_a_write_never_touches_a_same_named_item_of_another_collection(ccfg):
    """bw lists the whole organization even with --collectionid: the production MYAPP_SECRET_KEY must not
    be overwritten when the pre-prod one is written."""
    seed(ccfg, [{"id": "9", "name": "MYAPP_SECRET_KEY", "type": 1, "login": {"password": "prod"},
                 "organizationId": "o", "collectionIds": ["c1"]}])
    client = VwClient(ccfg)
    assert client.list_names() == []
    assert client.set_secret("MYAPP_SECRET_KEY", SECRET, as_login=True) is True  # created, not edited
    assert not any(c["argv"][:2] == ["edit", "item"] for c in calls(ccfg))


def test_screen_stderr_repeats_a_known_reason():
    from vw_server.client import screen_stderr

    assert screen_stderr("You do not have permission to edit this.") == \
        "You do not have permission to edit this."
    assert screen_stderr("noise\nCollection not found.") == "Collection not found."


def test_screen_stderr_drops_anything_shaped_like_an_item():
    from vw_server.client import screen_stderr

    assert screen_stderr('{"login": {"password": "s3cret"}} not found') == ""
    assert screen_stderr("password=s3cret not found") == ""


def test_screen_stderr_drops_a_long_or_unknown_line():
    from vw_server.client import screen_stderr

    assert screen_stderr("x" * 200 + " not found") == ""
    assert screen_stderr("Something unexpected happened") == ""
    assert screen_stderr("") == ""


def test_screen_stderr_names_a_node_error_class_only():
    from vw_server.client import screen_stderr

    assert screen_stderr("FetchError: request to https://vw/api/sync failed, reason: socket hang up\n"
                         "    at ClientRequest.<anonymous>") == "FetchError"
    assert screen_stderr('boom {"login": {"password": "s3cret"}}\nTypeError: x') == "TypeError"
    assert screen_stderr("s3cretError: not a class bw throws") == ""


def strict(cfg, tmp_path):
    """A config whose fake bw behaves like the real one when two processes share its data dir."""
    (Path(cfg.bw).parent / "strict").write_text("")
    seed(cfg, [{"id": "1", "name": "A", "notes": SECRET, "folderId": "f2"}])
    return dataclasses.replace(cfg, bw_data_dir=str(tmp_path / "bw-data"))


def test_a_replaced_session_is_named_in_the_error(cfg, tmp_path):
    client = VwClient(strict(cfg, tmp_path))
    client._unlock()
    (Path(cfg.bw).parent / "session").write_text("another process")
    with pytest.raises(VwError, match="returned nothing: its session is no longer valid"):
        client._items("f2")


def test_clients_sharing_a_data_dir_take_turns(cfg, tmp_path):
    """2026-11-02: `vw-rm` failed with «bw list returned invalid JSON» while another process
    unlocked the same account's data dir; operations now hold the dir one at a time."""
    own = strict(cfg, tmp_path)
    results, errors = [], []

    def work():
        try:
            results.append(VwClient(own).list_names())
        except VwError as exc:
            errors.append(str(exc))

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == [] and results == [["A"]] * 4


def test_an_operation_releases_the_dir_and_drops_its_session(cfg, tmp_path):
    own = strict(cfg, tmp_path)
    client = VwClient(own)
    assert client.list_names() == ["A"]
    assert client._session is None
    with open(Path(own.bw_data_dir) / "vw.lock") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert client.list_names() == ["A"]  # unlocks again


def test_a_session_unlocked_outside_an_operation_is_kept(cfg, tmp_path):
    client = VwClient(strict(cfg, tmp_path))
    client._unlock()
    assert client.list_names() == ["A"] and client._session


def test_a_busy_data_dir_is_reported(cfg, tmp_path, monkeypatch):
    import vw_server.client as vw_client

    own = strict(cfg, tmp_path)
    monkeypatch.setattr(vw_client, "LOCK_WAIT", 0.3)
    Path(own.bw_data_dir).mkdir()
    with open(Path(own.bw_data_dir) / "vw.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with pytest.raises(VwError, match="bw data dir is busy"):
            VwClient(own).list_names()


class FakeMsvcrt:
    """msvcrt.locking as Windows does it: a second lock on a held region raises OSError."""
    LK_NBLCK, LK_UNLCK = 2, 0

    def __init__(self):
        self.held = set()

    def locking(self, fd, mode, nbytes):
        key = os.fstat(fd).st_ino
        if mode == self.LK_UNLCK:
            self.held.discard(key)
        elif key in self.held:
            raise OSError(13, "Permission denied")
        else:
            self.held.add(key)


def test_the_lock_works_without_fcntl(tmp_path, monkeypatch):
    import vw_server.client as vw_client

    fake = FakeMsvcrt()
    monkeypatch.setattr(vw_client, "fcntl", None)
    monkeypatch.setattr(vw_client, "msvcrt", fake, raising=False)
    monkeypatch.setattr(vw_client, "LOCK_WAIT", 0.3)
    first = vw_client.DataDirLock(str(tmp_path / "bw"))
    first.acquire()
    with pytest.raises(VwError, match="bw data dir is busy"):
        vw_client.DataDirLock(str(tmp_path / "bw")).acquire()
    first.release()
    second = vw_client.DataDirLock(str(tmp_path / "bw"))
    second.acquire()  # released: free again
    second.release()
    assert fake.held == set()


def test_a_login_write_replaces_an_existing_note_with_a_login(cfg):
    """Older writers stored bot tokens as notes; readers take only a Login's password. Vaultwarden keeps an item's type on edit, so a Login is created and the note
    is deleted after it."""
    seed(cfg, [{"id": "7", "name": "TELEGRAM_BOT_TOKEN_X_BOT", "type": 2, "secureNote": {"type": 0},
                "notes": "old", "folderId": "f2"}])
    assert VwClient(cfg).set_secret("TELEGRAM_BOT_TOKEN_X_BOT", SECRET, as_login=True) is False
    log = calls(cfg)
    create = [n for n, x in enumerate(log) if x["argv"][:2] == ["create", "item"]]
    delete = [n for n, x in enumerate(log) if x["argv"][:3] == ["delete", "item", "7"]]
    assert create and delete and create[-1] < delete[-1]
    item = json.loads(base64.b64decode(log[create[-1]]["stdin"]).decode())
    assert item["type"] == 1 and item["login"]["password"] == SECRET and not item.get("notes")
    assert not any(x["argv"][:2] == ["edit", "item"] for x in log)
