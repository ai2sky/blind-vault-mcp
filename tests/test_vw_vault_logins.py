"""Login checks on a fake browser: no real site, no real browser, no real password."""

import datetime
import json

import pytest

from vw_server.client import VwError
from vw_vault import logins
from vw_vault.daemon import dispatch
from vw_vault.engine import Engine
from vw_vault.inventory import Fingerprinter
from vw_vault.logins import LoginChecks, Session

CANARY = "Canary-Pa55-9f3k2-never-leak"
USER = "owner-zz9@example.test"

TOML = """
[[site]]
name = "pihole"
item = "PIHOLE_PASSWORD"
origin = "https://pihole.lan"
login_path = "/admin/login"
fields = { user = "", password = "input[type=password]" }
ok = { url_not_contains = "/login" }
bad = { text_any = ["Wrong password"] }

[[site]]
name = "forum"
item = "FORUM"
origin = "https://forum.example.test"
login_path = "/login"
fields = { user = "input[name=user]", password = "input[type=password]" }
ok = { url_not_contains = "/login" }
bad = { text_any = ["Invalid credentials"] }
min_interval_days = 5
"""


class FakeSession(Session):
    """A scripted login page. `behaviour` decides what the page shows after submit."""

    instances: list = []

    def __init__(self, host, behaviour="works", **page):
        self.host, self.behaviour, self.page = host, behaviour, page
        self.blocked, self.filled, self.closed, self._url = False, {}, False, ""
        self._submitted = False
        FakeSession.instances.append(self)

    def goto(self, url):
        if self.page.get("raise_on_goto"):
            raise RuntimeError(f"goto failed while holding {CANARY}")
        self._url = self.page.get("redirect") or url

    def url(self):
        if self._submitted and self.behaviour == "works":
            return "https://" + self.host + "/admin/"
        return self._url

    def status(self):
        return 429 if self._submitted and self.behaviour == "429" else 200

    def has(self, selector):
        if selector in logins.TWOFA_SELECTORS:
            return self.page.get("twofa", False) or (self._submitted and self.behaviour == "2fa")
        if selector in logins.CAPTCHA_SELECTORS:
            return self.page.get("captcha", False)
        return selector in ("input[type=password]", "input[name=user]")

    def fill(self, selector, value):
        if self.behaviour == "fill-error":
            raise RuntimeError(f"locator.fill: Timeout while filling {value!r}")
        self.filled[selector] = value

    def submit(self, selector):
        self._submitted = True

    def text(self):
        if not self._submitted:
            return "Sign in"
        return {"wrong": "Wrong password", "rejected": "Invalid credentials", "weird": "Welcome to nothing",
                "locked": "Your account is locked"}.get(self.behaviour, "Dashboard")

    def close(self):
        self.closed = True


class FakeEngine:
    _fp = Fingerprinter(b"k" * 32)

    def __init__(self):
        self.journal = []

    def _journal(self, action, **fields):
        self.journal.append({"action": action, **fields})


def items(pihole_uri="https://pihole.lan/admin", forum_uri="https://forum.example.test/login"):
    def login(id, name, uri, user=""):
        return {"id": id, "type": 1, "name": name, "deletedDate": None,
                "login": {"username": user, "password": CANARY, "uris": [{"uri": uri}]}}
    return [login("i1", "PIHOLE_PASSWORD", pihole_uri), login("i2", "FORUM", forum_uri, USER)]


class Clock:
    def __init__(self):
        self.t = datetime.datetime(2026, 11, 10, tzinfo=datetime.timezone.utc)

    def __call__(self):
        return self.t


def make(tmp_path, behaviour="works", sites=None, clock=None, sleeps=None, **page):
    FakeSession.instances = []
    eng = FakeEngine()
    mod = LoginChecks(sites or logins.parse_config(TOML), tmp_path / "state.json", eng._fp,
                      driver=lambda host: FakeSession(host, behaviour, **page), journal=eng._journal,
                      sleep=(sleeps.append if sleeps is not None else lambda s: None),
                      now=clock or Clock(), jitter=lambda: 0)
    return mod, eng


def everything(*parts):
    return json.dumps(parts, default=str)


def only(sites, name):
    return [s for s in sites if s.name == name]


# --- off by default ---------------------------------------------------------------------------


def test_off_without_allow_list(tmp_path, monkeypatch):
    conf = {"VW_VAULT_LOGIN_CHECKS_FILE": str(tmp_path / "none.toml")}
    module, why = logins.setup(conf, FakeEngine(), state_dir=tmp_path)
    assert module is None and "no allow list" in why


def test_off_without_extra(tmp_path, monkeypatch):
    path = tmp_path / "login-checks.toml"
    path.write_text(TOML)
    monkeypatch.setattr(logins, "playwright_installed", lambda: False)
    module, why = logins.setup({"VW_VAULT_LOGIN_CHECKS_FILE": str(path)}, FakeEngine(), state_dir=tmp_path)
    assert module is None and "extra not installed" in why


def test_off_by_env_switch(tmp_path):
    path = tmp_path / "login-checks.toml"
    path.write_text(TOML)
    module, why = logins.setup({"VW_VAULT_LOGIN_CHECKS_FILE": str(path), "VW_VAULT_LOGIN_CHECKS": "0"},
                               FakeEngine(), state_dir=tmp_path, driver=lambda h: None)
    assert module is None and "VW_VAULT_LOGIN_CHECKS=0" in why


def test_unconfirmed_list_stays_off_and_confirmed_hash_is_remembered(tmp_path):
    path = tmp_path / "login-checks.toml"
    path.write_text(TOML)
    conf, said = {"VW_VAULT_LOGIN_CHECKS_FILE": str(path)}, []
    driver = lambda h: None  # noqa: E731
    module, why = logins.setup(conf, FakeEngine(), state_dir=tmp_path, ask=lambda q: "n", say=said.append,
                               driver=driver)
    assert module is None and "not confirmed" in why
    assert any("pihole" in line for line in said)
    module, _ = logins.setup(conf, FakeEngine(), state_dir=tmp_path, ask=lambda q: "y", say=said.append,
                             driver=driver)
    assert module is not None
    # same file: no question the second time; a changed file asks again
    module, _ = logins.setup(conf, FakeEngine(), state_dir=tmp_path, ask=lambda q: pytest.fail("asked"),
                             say=said.append, driver=driver)
    assert module is not None
    path.write_text(TOML + "\n# changed\n[[site]]\nname='x'\nitem='X'\norigin='https://x.example.test'\nbad={text_any=['no']}\n")
    module, why = logins.setup(conf, FakeEngine(), state_dir=tmp_path, ask=lambda q: "n", say=said.append,
                               driver=driver)
    assert module is None


def test_engine_off_reports_and_opens_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr("vw_vault.engine.STATE_DIR", tmp_path)

    class Bw:
        timeout = 1

        def _json(self, args):
            return []

    engine = Engine(Bw())
    with pytest.raises(VwError, match="login checks are off"):
        dispatch(engine, "check_logins", {})
    # the agent route: refused with a hint, whatever is enabled
    engine.login_checks = object()
    with pytest.raises(VwError, match="only by the owner"):
        dispatch(engine, "check", {"name": "logins"})


def test_daemon_refuses_a_run_without_the_owner_proof(tmp_path, monkeypatch):
    monkeypatch.setattr("vw_vault.engine.STATE_DIR", tmp_path)

    class Bw:
        timeout = 1

        def _json(self, args):
            return []

    engine = Engine(Bw())
    engine.login_checks, _ = make(tmp_path / "m", "works")
    for args in ({}, {"dry_run": True}, {"proof": ""}, {"proof": "guess"}):
        with pytest.raises(VwError, match="check phrase"):
            dispatch(engine, "check_logins", args)  # what a raw socket request reaches
    engine.set_owner_phrase("owner phrase")
    with pytest.raises(VwError, match="check phrase"):
        dispatch(engine, "check_logins", {"proof": "guess"})
    assert engine.job == {} or engine.job.get("state") != "running"
    assert dispatch(engine, "check_logins", {"proof": "owner phrase", "dry_run": True})["state"] == "running"


def test_call_subcommand_refuses_check_logins(monkeypatch):
    from vw_vault import daemon

    def boom(*a, **k):
        raise AssertionError("daemon must not be called")

    monkeypatch.setattr(daemon, "call", boom)
    monkeypatch.setattr("sys.argv", ["vw-vault", "call", "check_logins", "{}"])
    with pytest.raises(SystemExit, match="vw-vault check logins"):
        daemon.main()


async def test_mcp_tool_refuses_without_asking_the_daemon(monkeypatch):
    from vw_vault import server

    async def boom(*a, **k):
        raise AssertionError("daemon must not be called")

    monkeypatch.setattr(server, "_call", boom)
    out = await server.vault_check("logins")
    assert "vw-vault check logins" in out


# --- config, allow list and deny list ----------------------------------------------------------


def test_config_needs_profile_https_and_clamps_limits():
    with pytest.raises(logins.LoginCheckError):
        logins.parse_config('[[site]]\nname="a"\nitem="A"\norigin="http://a.example.test"\nbad={text_any=["x"]}\n')
    with pytest.raises(logins.LoginCheckError, match="no profile"):
        logins.parse_config('[[site]]\nname="a"\nitem="A"\norigin="https://a.example.test"\n')
    sites = logins.parse_config(TOML.replace("min_interval_days = 5", "min_interval_days = 1"))
    assert [s.min_interval_days for s in sites] == [30, 30]  # limits can only get stricter


@pytest.mark.parametrize("host", ["www.sberbank.ru", "gmail.com", "accounts.google.com", "paypal.com",
                                  "login.microsoftonline.com", "my-bank.example.test", "mail.ru",
                                  "www.gosuslugi.ru", "namecheap.com", "vault.example.com"])
def test_deny_list_wins_over_the_file(tmp_path, host):
    site = logins.Site(name="x", item="FORUM", origin=f"https://{host}", ok={"url_not_contains": "/login"})
    mod, _ = make(tmp_path, sites=[site])
    mod.vault_host = "vault.example.com"
    rows = mod.run(items(forum_uri=f"https://{host}/"))
    assert rows[0]["status"] == "refused" and "deny list" in rows[0]["reason"]
    assert FakeSession.instances == []


def test_item_must_be_named_and_host_must_match_exactly(tmp_path):
    mod, _ = make(tmp_path)
    rows = mod.run(items(pihole_uri="https://pihole.lan.evil.test/admin", forum_uri="https://forum.example.test.evil/"))
    assert [r["status"] for r in rows] == ["refused", "refused"]
    assert FakeSession.instances == []
    # an extra look-alike URI on the item is enough to refuse
    extra = items()
    extra[0]["login"]["uris"].append({"uri": "https://pihole-lan.evil.test"})
    assert mod.run(extra[:1])[0]["status"] == "refused"
    # an item not in the file is never touched: only the listed sites are tried
    other = items() + [{"id": "i3", "type": 1, "name": "OTHER", "login": {"password": "x" * 20,
                                                                         "uris": [{"uri": "https://pihole.lan"}]}}]
    mod.run(other)
    assert all(s.host in ("pihole.lan", "forum.example.test") for s in FakeSession.instances)


def test_redirect_to_another_host_is_refused_before_typing(tmp_path):
    mod, _ = make(tmp_path, redirect="https://evil.test/login")
    row = mod.run(items(), progress=lambda d, t: None)[0]
    assert row["status"] == "refused"
    assert all(s.filled == {} for s in FakeSession.instances)
    assert mod.state()["pihole"]["paused"]


# --- statuses ---------------------------------------------------------------------------------


@pytest.mark.parametrize("behaviour,status", [("works", "works"), ("wrong", "wrong_password"),
                                              ("weird", "unknown"), ("2fa", "needs_human"),
                                              ("locked", "needs_human"), ("429", "rejected")])
def test_statuses_for_the_lan_site(tmp_path, behaviour, status):
    mod, _ = make(tmp_path, behaviour)
    rows = mod.run(items())
    assert rows[0]["status"] == status
    assert FakeSession.instances[0].filled == {"input[type=password]": CANARY}
    assert FakeSession.instances[0].closed


def test_wrong_password_is_a_note_not_a_rotation(tmp_path):
    mod, _ = make(tmp_path, "wrong")
    row = mod.run(items())[0]
    assert row["look_at"] is True
    assert "paused" not in row  # it worked never before: no breaker, only a note


def test_wrong_password_after_works_pauses_the_site(tmp_path):
    mod, _ = make(tmp_path, "works")
    mod.run(items())
    clock = mod.now
    clock.t += datetime.timedelta(days=31)
    mod.driver = lambda host: FakeSession(host, "wrong")
    assert mod.run(items())[0]["paused"] is True
    clock.t += datetime.timedelta(days=60)
    assert mod.run(items())[0]["status"] == "skipped"  # paused until the owner clears the state file


def test_site_with_user_that_hides_which_part_is_wrong_is_rejected(tmp_path):
    mod, _ = make(tmp_path, "rejected", sites=only(logins.parse_config(TOML), "forum"))
    row = mod.run(items())[0]
    assert row["status"] == "rejected"
    assert FakeSession.instances[0].filled == {"input[name=user]": USER, "input[type=password]": CANARY}


def test_account_missing_only_when_site_says_so(tmp_path):
    cfg = TOML.replace('bad = { text_any = ["Invalid credentials"] }',
                       'bad = { text_any = ["Invalid credentials"] }\nmissing = { text_any = ["Invalid credentials"] }\n'
                       "distinguishes_account = true")
    mod, _ = make(tmp_path, "rejected", sites=only(logins.parse_config(cfg), "forum"))
    assert mod.run(items())[0]["status"] == "account_missing"


# --- 2FA and captchas ---------------------------------------------------------------------------


@pytest.mark.parametrize("page", [{"twofa": True}, {"captcha": True}])
def test_2fa_or_captcha_stops_before_typing(tmp_path, page):
    mod, _ = make(tmp_path, **page)
    row = mod.run(items())[0]
    assert row["status"] == "needs_human"
    assert all(s.filled == {} for s in FakeSession.instances)
    assert mod.state()["pihole"]["paused"]


def test_2fa_after_the_password_is_needs_human_and_totp_is_never_typed(tmp_path):
    totp_item = items()
    totp_item[0]["login"]["totp"] = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
    mod, _ = make(tmp_path, "2fa")
    row = mod.run(totp_item)[0]
    assert row["status"] == "needs_human"  # never "works", even though the password was accepted
    assert list(FakeSession.instances[0].filled.values()) == [CANARY]
    assert "JBSWY3DPEHPK3PXP" not in everything(row, FakeSession.instances[0].filled)


# --- limits ----------------------------------------------------------------------------------


def test_one_attempt_and_thirty_days(tmp_path):
    mod, _ = make(tmp_path)
    assert mod.run(items())[0]["status"] == "works"
    assert len(FakeSession.instances) == 2  # both sites tried once
    again = mod.run(items())
    assert [r["status"] for r in again] == ["skipped", "skipped"]
    assert len(FakeSession.instances) == 2
    mod.now.t += datetime.timedelta(days=29)
    assert mod.run(items())[0]["status"] == "skipped"
    mod.now.t += datetime.timedelta(days=2)
    assert mod.run(items())[0]["status"] == "works"


def test_failure_is_not_retried_and_counts_as_an_attempt(tmp_path):
    mod, _ = make(tmp_path, "fill-error")
    assert mod.run(items())[0]["status"] == "error"
    assert len(FakeSession.instances) == 2  # one session per site, no retries
    assert mod.run(items())[0]["status"] == "skipped"  # typed once: the interval applies


def test_pause_between_sites_and_run_limit(tmp_path):
    sleeps = []
    many = []
    for n in range(7):
        many.append(logins.Site(name=f"s{n}", item=f"ITEM{n}", origin=f"https://s{n}.example.test",
                                ok={"url_not_contains": "/login"}))
    its = [{"id": f"i{n}", "type": 1, "name": f"ITEM{n}", "login": {"password": CANARY, "username": "u",
            "uris": [{"uri": f"https://s{n}.example.test"}]}} for n in range(7)]
    mod, _ = make(tmp_path, sites=many, sleeps=sleeps)
    rows = mod.run(its)
    assert [r["status"] for r in rows].count("works") == 5
    assert [r["reason"] for r in rows[5:]] == ["run limit", "run limit"]
    assert sleeps == [60] * 4


# --- dry run -----------------------------------------------------------------------------------


def test_dry_run_submits_nothing_and_does_not_start_the_interval(tmp_path):
    mod, eng = make(tmp_path)
    rows = mod.run(items(), dry_run=True)
    assert [r["status"] for r in rows] == ["form_found", "form_found"]
    assert all(s.filled == {} and not s._submitted for s in FakeSession.instances)
    assert "last_checked" not in json.dumps(mod.state())
    assert mod.run(items())[0]["status"] == "works"  # a real run is still allowed afterwards


# --- the value never leaves --------------------------------------------------------------------


@pytest.mark.parametrize("behaviour,page", [("works", {}), ("wrong", {}), ("2fa", {}), ("fill-error", {}),
                                            ("works", {"raise_on_goto": True}), ("works", {"twofa": True}),
                                            ("works", {"redirect": "https://evil.test/"})])
def test_password_never_reaches_rows_journal_state_or_files(tmp_path, behaviour, page):
    mod, eng = make(tmp_path, behaviour, **page)
    rows = mod.run(items())
    blob = everything(rows, eng.journal, mod.state(), [p.read_text() for p in tmp_path.rglob("*") if p.is_file()])
    assert CANARY not in blob and USER not in blob
    assert all("Traceback" not in json.dumps(r) for r in rows)


def test_error_keeps_only_the_exception_type(tmp_path):
    mod, _ = make(tmp_path, raise_on_goto=True)
    row = mod.run(items())[0]
    assert row["status"] == "error" and row["reason"] == "RuntimeError"


def test_result_has_only_a_fingerprint(tmp_path):
    mod, _ = make(tmp_path)
    row = mod.run(items())[0]
    assert len(row["fingerprint"]) == 10 and CANARY not in row["fingerprint"]


def test_engine_job_saves_status_rows_without_values(tmp_path, monkeypatch):
    monkeypatch.setattr("vw_vault.engine.STATE_DIR", tmp_path)
    live = items()

    class Bw:
        timeout = 1

        def _json(self, args):
            return live if args[:2] == ["list", "items"] and len(args) == 2 else []

    engine = Engine(Bw())
    engine.login_checks, _ = make(tmp_path / "m", "wrong")
    engine.set_owner_phrase("owner phrase")
    out = engine.check_logins(proof="owner phrase")
    assert out["state"] == "running"
    import time
    for _ in range(100):
        if engine.job.get("state") != "running":
            break
        time.sleep(0.05)
    result = engine.job["result"]
    assert result["statuses"] == {"wrong_password": 1, "unknown": 1} and result["look_at"] == ["pihole"]
    assert CANARY not in json.dumps(engine.job) + (tmp_path / "check-logins.json").read_text()
    assert engine.guard_response(json.dumps(engine.job)) is None  # no vault value in the job either
