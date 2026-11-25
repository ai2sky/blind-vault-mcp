import json

import pytest

from vw_server import audit, put

SECRET = "s3cr3t-VALUE-9f2"


class FakeClient:
    writes: list[tuple] = []

    def __init__(self, cfg):
        pass

    def set_collection_secret(self, collection, name, value):
        self.writes.append((collection, name, value))
        return True


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    FakeClient.writes = []
    monkeypatch.setattr(put, "VwClient", FakeClient)
    monkeypatch.setattr(put, "load_config", lambda allow_org_only: None)
    monkeypatch.setattr(put, "ENV_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("VW_AUDIT_LOG", str(tmp_path / "audit.log"))
    sent = []
    monkeypatch.setattr(audit, "notify", sent.append)
    return {"sent": sent, "log": tmp_path / "audit.log"}


def test_typed_value_twice_is_written_and_never_printed(monkeypatch, capsys, env):
    monkeypatch.setattr(put.getpass, "getpass", lambda prompt: SECRET)
    put.main(["interview-preps", "CLAUDE_CODE_OAUTH_TOKEN"])
    assert FakeClient.writes == [("interview-preps", "CLAUDE_CODE_OAUTH_TOKEN", SECRET)]
    out = capsys.readouterr()
    assert SECRET not in out.out + out.err and "created" in out.out
    entry = json.loads(env["log"].read_text())
    assert entry["action"] == "set_secret (typed, vw-put)" and SECRET not in env["log"].read_text()
    assert env["sent"] and SECRET not in env["sent"][0]


def test_two_different_values_are_refused(monkeypatch):
    answers = iter([SECRET, "other"])
    monkeypatch.setattr(put.getpass, "getpass", lambda prompt: next(answers))
    with pytest.raises(SystemExit, match="differ"):
        put.main(["c", "NAME"])
    assert FakeClient.writes == []


def test_file_and_generated_values(tmp_path):
    f = tmp_path / "creds.json"
    f.write_text(SECRET + "\n")
    put.main(["google", "GOOGLE_CREDS", "--file", str(f)])
    put.main(["c", "SESSION_KEY", "--generate"])
    assert FakeClient.writes[0] == ("google", "GOOGLE_CREDS", SECRET)
    assert len(FakeClient.writes[1][2]) >= 40


def test_bad_name_is_refused():
    with pytest.raises(SystemExit, match="not written"):
        put.main(["c", "bad name!", "--generate"])
