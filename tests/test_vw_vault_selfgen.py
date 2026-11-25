import json
import logging

import httpx
import pytest

from vw_server.client import VwError
from vw_vault import selfgen
from vw_vault.rotation import Issued
from vw_vault.selfgen import SelfGeneratedRotator, load_entries, parse_entry

from test_vw_vault import login, make, state  # noqa: F401  (state is a fixture)

OLD = "Old0ValueOfTheSecret0000000000000"
NEW = "Nw7Qx2LmZp9RtV4cYb8KdHs3FgJa6EuX"
COLLECTIONS = {"c1": "myapp", "c2": "other"}


class FakeApp:
    """The consumer's health endpoint: counts calls, answers 200 unless told otherwise."""

    def __init__(self, healthy=True):
        self.healthy, self.calls = healthy, 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200 if self.healthy else 503)


def fixed(value=NEW):
    return lambda length, alphabet: value


def entry(tmp_path, **over):
    raw = {"name": "MYAPP_ADMIN_TOKEN", "collection": "myapp", "length": 32,
           "consumers": [{"name": "env-file", "cmd": f"tee {tmp_path / 'consumer.txt'}"}],
           "restart": f'sh -c "echo r >> {tmp_path / "restarts.txt"}"', "check_url": "http://app.test/api/health",
           "check_retries": 2, "check_delay": 0}
    raw.update(over)
    return raw


def setup(state, tmp_path, raw=None, app=None, value=NEW, name="MYAPP_ADMIN_TOKEN", collections=("c1",)):
    eng, bw = make([login("a", name, "myapp.test", pw=OLD, collectionIds=list(collections))], state)
    app = app or FakeApp()
    rot = SelfGeneratedRotator([parse_entry(raw or entry(tmp_path))], eng.write_password, lambda: COLLECTIONS,
                               http=httpx.Client(transport=httpx.MockTransport(app)), generator=fixed(value),
                               sleep=lambda s: None)
    eng.rotators = [rot]
    return eng, bw, app


def edits(bw):
    return [c for c in bw.calls if c[:2] == ["edit", "item"]]


def test_rotation_writes_restarts_and_checks(state, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    eng, bw, app = setup(state, tmp_path)
    eng.mark_rotation(["a"], "scheduled")
    res = eng.rotate(["a"])
    r = res["results"][0]
    assert r["ok"] and r["module"] == "self-generated" and r["consumers"] == ["vault item", "env-file", "restart"]
    assert bw.items["a"]["login"]["password"] == NEW and (tmp_path / "consumer.txt").read_text() == NEW
    assert (tmp_path / "restarts.txt").read_text().count("r") == 1 and app.calls == 1
    assert "a" not in eng.rotation()
    # no value in an answer, the journal or a log
    for text in (json.dumps(res), (state / "journal.log").read_text(), caplog.text):
        assert NEW not in text and OLD not in text


def test_failed_check_keeps_the_old_value(state, tmp_path):
    eng, bw, app = setup(state, tmp_path, app=FakeApp(healthy=False))
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "verify" and r["error"] == "verification failed"
    # the rollback restarted the consumer again and looked again; the second look failed too
    assert r["rolled_back"] is False and r["rollback_error"] == "rollback incomplete: check after rollback"
    assert bw.items["a"]["login"]["password"] == OLD and (tmp_path / "consumer.txt").read_text() == OLD
    assert (tmp_path / "restarts.txt").read_text().count("r") == 2
    assert "a" in eng.rotation() and "verify" in eng.rotation()["a"]["reasons"][-1]
    assert NEW not in json.dumps(r) + (state / "journal.log").read_text()


def test_check_that_passes_only_with_the_new_value_rolls_back_cleanly(state, tmp_path):
    # the app is healthy on the old value and not on the new one
    marker = tmp_path / "consumer.txt"

    def app(request):
        return httpx.Response(200 if marker.read_text() == OLD else 503)

    marker.write_text(OLD)
    eng, bw, _ = setup(state, tmp_path, app=app)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["rolled_back"] is True and "rollback_error" not in r
    assert bw.items["a"]["login"]["password"] == OLD and marker.read_text() == OLD


@pytest.mark.parametrize("bad", ["short", OLD, "Nw7Qx2LmZp9RtV4cYb8KdHs3FgJa6E!X", "a" * 32])
def test_new_value_is_judged_before_any_write(state, tmp_path, bad):
    eng, bw, app = setup(state, tmp_path, value=bad)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "issue" and "before any write" in r["error"]
    assert edits(bw) == [] and not (tmp_path / "consumer.txt").exists() and not (tmp_path / "restarts.txt").exists()
    assert bw.items["a"]["login"]["password"] == OLD and app.calls == 0


def test_precheck_command_runs_before_any_write(state, tmp_path):
    eng, bw, app = setup(state, tmp_path, entry(tmp_path, precheck_cmd="false"))
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "issue"
    assert edits(bw) == [] and not (tmp_path / "consumer.txt").exists()
    eng, bw, app = setup(state, tmp_path, entry(tmp_path, precheck_cmd="true"))
    assert eng.rotate(["a"])["results"][0]["ok"]


def test_failed_consumer_rolls_back_including_itself(state, tmp_path):
    raw = entry(tmp_path, consumers=[{"name": "bad", "cmd": "false"}])
    eng, bw, app = setup(state, tmp_path, raw)
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "distribute" and r["consumers"] == ["vault item", "bad"]
    assert r["rollback_error"] == "rollback incomplete: bad"  # it fails again, and is named
    assert bw.items["a"]["login"]["password"] == OLD and not (tmp_path / "restarts.txt").exists()


def test_failed_restart_rolls_back_and_restarts_again(state, tmp_path):
    flag = tmp_path / "second-run"
    # fails on the first call, succeeds on the second
    cmd = f'sh -c "test -e {flag} || {{ touch {flag}; exit 1; }}; echo r >> {tmp_path / "restarts.txt"}"'
    eng, bw, app = setup(state, tmp_path, entry(tmp_path, restart=cmd))
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "distribute" and r["error"] == "restart failed"
    assert r["consumers"][-1] == "restart" and r["rolled_back"] is True
    assert bw.items["a"]["login"]["password"] == OLD and (tmp_path / "consumer.txt").read_text() == OLD
    assert (tmp_path / "restarts.txt").read_text().count("r") == 1


# --- owner consent ----------------------------------------------------------------------

@pytest.fixture
def consent_list(monkeypatch):
    """A deployment that lists its session signing key as consent-only."""
    monkeypatch.setattr(selfgen, "OWNER_CONSENT_ONLY", frozenset({"MYAPP_SECRET_KEY"}))


def test_a_listed_key_is_not_rotated_without_the_flag(state, tmp_path, caplog, consent_list):
    caplog.set_level(logging.DEBUG)
    eng, bw, app = setup(state, tmp_path, name="MYAPP_SECRET_KEY",
                         raw=entry(tmp_path, name="MYAPP_SECRET_KEY"))
    res = eng.rotate(["a"])
    r = res["results"][0]
    assert not r["ok"] and r["stage"] == "issue" and r["module"] == "self-generated"
    assert "explicit consent" in r["error"] and "owner_consent" in r["error"]
    # nothing was touched
    assert edits(bw) == [] and bw.items["a"]["login"]["password"] == OLD
    assert not (tmp_path / "consumer.txt").exists() and not (tmp_path / "restarts.txt").exists() and app.calls == 0
    # the reason is written where the owner looks: the rotation list and the journal
    assert "explicit consent" in eng.rotation()["a"]["reasons"][-1]
    assert "explicit consent" in (state / "journal.log").read_text()
    # the reason is written, the values are not
    for text in (json.dumps(res), (state / "journal.log").read_text(), caplog.text):
        assert OLD not in text and NEW not in text


def test_a_listed_key_rotates_with_the_flag(state, tmp_path, consent_list):
    raw = entry(tmp_path, name="MYAPP_SECRET_KEY", owner_consent=True)
    eng, bw, app = setup(state, tmp_path, name="MYAPP_SECRET_KEY", raw=raw)
    assert eng.rotate(["a"])["results"][0]["ok"] and bw.items["a"]["login"]["password"] == NEW


def test_the_built_in_list_cannot_be_switched_off_by_the_file(state, tmp_path, consent_list):
    for spelling in ("MYAPP_SECRET_KEY", "myapp_secret_key"):
        raw = entry(tmp_path, name=spelling, requires_consent=False)
        eng, bw, _ = setup(state, tmp_path, name=spelling, raw=raw)
        r = eng.rotate(["a"])["results"][0]
        assert not r["ok"] and "explicit consent" in r["error"] and edits(bw) == []


def test_any_entry_can_ask_for_consent(state, tmp_path):
    eng, bw, _ = setup(state, tmp_path, raw=entry(tmp_path, requires_consent=True))
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and "explicit consent" in r["error"] and edits(bw) == []
    eng, bw, _ = setup(state, tmp_path, raw=entry(tmp_path, requires_consent=True, owner_consent=True))
    assert eng.rotate(["a"])["results"][0]["ok"]


def test_consent_is_a_real_boolean(tmp_path):
    for flag in ("true", 1, "yes"):
        with pytest.raises(VwError, match="owner_consent is true or false"):
            parse_entry(entry(tmp_path, name="MYAPP_SECRET_KEY", owner_consent=flag))


# --- matching and config ----------------------------------------------------------------

def test_an_item_in_another_collection_is_not_touched(state, tmp_path):
    eng, bw, _ = setup(state, tmp_path, collections=("c2",))
    assert not eng.rotators[0].matches(bw.items["a"])
    r = eng.rotate(["a"])["results"][0]
    assert not r["ok"] and r["stage"] == "match" and edits(bw) == []
    eng, bw, _ = setup(state, tmp_path, collections=())  # a personal item
    assert not eng.rotators[0].matches(bw.items["a"])


def test_config_needs_a_check(tmp_path):
    raw = entry(tmp_path)
    del raw["check_url"]
    with pytest.raises(VwError, match="a check is required"):
        parse_entry(raw)
    parse_entry({**raw, "check_cmd": "true"})


def test_config_refuses_a_value_and_never_echoes_it(tmp_path):
    with pytest.raises(VwError) as err:
        parse_entry(entry(tmp_path, value=NEW))
    assert "value" in str(err.value) and NEW not in str(err.value)
    for bad in ({"alphabet": "emoji"}, {"length": 8}, {"length": True}, {"check_url": "ftp://x"},
                {"consumers": [{"name": "restart", "cmd": "true"}]}, {"restart": "'"}):
        with pytest.raises(VwError):
            parse_entry(entry(tmp_path, **bad))
    with pytest.raises(VwError, match="missing"):
        parse_entry({"name": "X"})


def test_config_file(tmp_path):
    path = tmp_path / "selfgen.json"
    with pytest.raises(VwError, match="cannot be read"):
        load_entries(str(path))
    path.write_text('{"a": 1}')
    with pytest.raises(VwError, match="list of objects"):
        load_entries(str(path))
    path.write_text(json.dumps([entry(tmp_path), entry(tmp_path)]))
    with pytest.raises(VwError, match="twice"):
        load_entries(str(path))
    path.write_text(json.dumps([entry(tmp_path), entry(tmp_path, collection="other")]))
    assert [e.collection for e in load_entries(str(path))] == ["myapp", "other"]


def test_nothing_is_rotated_without_a_config(state, tmp_path):
    eng, _ = make([], state)
    assert selfgen.from_settings({}, eng) is None
    assert selfgen.from_settings({"VW_VAULT_SELFGEN_CONFIG": ""}, eng) is None
    path = tmp_path / "selfgen.json"
    path.write_text(json.dumps([entry(tmp_path)]))
    rot = selfgen.from_settings({"VW_VAULT_SELFGEN_CONFIG": str(path)}, eng)
    assert isinstance(rot, SelfGeneratedRotator) and [e.name for e in rot.entries] == ["MYAPP_ADMIN_TOKEN"]


def test_generated_values_follow_the_entry(tmp_path):
    for alphabet in selfgen.ALPHABETS:
        value = selfgen.generate(40, alphabet)
        assert len(value) == 40 and set(value) <= set(selfgen.ALPHABETS[alphabet])
    assert selfgen.generate(48, "alnum") != selfgen.generate(48, "alnum")


def test_issued_value_stays_out_of_repr():
    assert NEW not in repr(Issued(ref="r1", value=NEW))


def test_failed_rotation_leaks_no_value_to_logs_or_answers(state, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    eng, bw, app = setup(state, tmp_path, app=FakeApp(healthy=False))
    res = eng.rotate(["a"])
    assert bw.items["a"]["login"]["password"] == OLD
    for text in (json.dumps(res), (state / "journal.log").read_text(), caplog.text):
        assert NEW not in text and OLD not in text
