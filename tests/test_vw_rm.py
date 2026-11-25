import pytest

from vw_server import rm


class FakeClient:
    def __init__(self, deleted=True, raises=None):
        self.calls = []
        self._deleted, self._raises = deleted, raises

    def delete_secret(self, collection, name):
        self.calls.append((collection, name))
        if self._raises:
            raise self._raises
        return self._deleted


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(rm, "load_env_file", lambda *a, **kw: None)
    monkeypatch.setattr(rm, "load_config", lambda **kw: object())
    monkeypatch.setattr(rm.audit, "record", lambda *a, **kw: "")


def test_yes_deletes_without_asking(monkeypatch, capsys):
    client = FakeClient()
    monkeypatch.setattr(rm, "VwClient", lambda cfg: client)
    monkeypatch.setattr(rm, "confirm", lambda *a: pytest.fail("must not ask"))
    rm.main(["demo-app", "ZZ_PROBE", "--yes"])
    assert client.calls == [("demo-app", "ZZ_PROBE")]
    assert "deleted" in capsys.readouterr().out


def test_a_wrong_confirmation_keeps_the_secret(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(rm, "VwClient", lambda cfg: client)
    monkeypatch.setattr("builtins.input", lambda *a: "wrong name")
    with pytest.raises(SystemExit) as exc:
        rm.main(["demo-app", "ZZ_PROBE"])
    assert client.calls == [] and "did not match" in str(exc.value)


def test_the_typed_name_must_match(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(rm, "VwClient", lambda cfg: client)
    monkeypatch.setattr("builtins.input", lambda *a: "ZZ_PROBE")
    rm.main(["demo-app", "ZZ_PROBE"])
    assert client.calls == [("demo-app", "ZZ_PROBE")]


def test_a_missing_secret_is_said_plainly(monkeypatch, capsys):
    monkeypatch.setattr(rm, "VwClient", lambda cfg: FakeClient(deleted=False))
    rm.main(["demo-app", "ZZ_NOPE", "--yes"])
    assert "no such secret" in capsys.readouterr().out


def test_a_bad_name_never_reaches_the_vault(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(rm, "VwClient", lambda cfg: client)
    with pytest.raises(SystemExit):
        rm.main(["demo-app", "not a variable name", "--yes"])
    assert client.calls == []
