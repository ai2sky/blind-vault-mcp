"""Opt-in login checks: does the site still accept the password of a vault item?

Design note: docs/vault.md, "Login checks". Off by default. The module exists only when the
optional extra (Playwright) is installed, the owner's allow list `~/.config/vw/login-checks.toml`
exists and the owner confirmed its hash at `vw-vault unlock`. Only the owner starts a run, in their
own terminal (`vw-vault check logins`); an agent gets a refusal.

The password is typed into the one form of one allowed site and goes nowhere else: results carry a
status and an HMAC fingerprint, errors are reduced to the exception type, and the browser layer
(`Session`) never hands page text, screenshots or traces to the code that stores anything.
2FA, captchas and "unusual activity" pages stop the check as `needs_human`; no TOTP is ever typed.
"""

from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import os
import random
import shutil
import tempfile
import time
import tomllib
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_PATH = Path("~/.config/vw/login-checks.toml")
DEFAULT_INTERVAL_DAYS = 30
MAX_SITES_PER_RUN = 5
SITE_PAUSE_SECONDS = 60
JITTER_SECONDS = 15
STATUSES = ("works", "wrong_password", "account_missing", "rejected", "needs_human", "unknown",
            "refused", "skipped", "error", "form_found")

# Never allowed, whatever the file says: a lockout there costs more than the knowledge is worth.
DENY_DOMAINS = {
    "payments": ["paypal.com", "stripe.com", "wise.com", "revolut.com", "qiwi.com", "yoomoney.ru",
                 "visa.com", "mastercard.com", "payoneer.com", "skrill.com", "webmoney.ru"],
    "banks": ["sberbank.ru", "sber.ru", "tinkoff.ru", "tbank.ru", "vtb.ru", "alfabank.ru", "raiffeisen.ru",
              "gazprombank.ru", "psbank.ru", "chase.com", "wellsfargo.com", "bankofamerica.com", "hsbc.com"],
    "government": ["gosuslugi.ru", "nalog.ru", "mos.ru", "pfr.gov.ru", "gov.uk", "login.gov", "usps.com"],
    "mail": ["gmail.com", "mail.ru", "yandex.ru", "ya.ru", "outlook.com", "live.com", "hotmail.com",
             "yahoo.com", "proton.me", "protonmail.com", "fastmail.com", "icloud.com", "zoho.com", "gmx.com"],
    "identity": ["accounts.google.com", "google.com", "apple.com", "microsoftonline.com", "microsoft.com",
                 "id.yandex.ru", "passport.yandex.ru", "okta.com", "auth0.com"],
    "registrars": ["namecheap.com", "godaddy.com", "reg.ru", "nic.ru", "name.com", "gandi.net",
                   "porkbun.com", "hover.com", "ru-center.ru"],
    "vault": ["bitwarden.com", "bitwarden.eu", "vaultwarden.org"],
}
DENY_WORDS = {"bank": "banks", "gosuslugi": "government", "paypal": "payments"}  # inside any host label

TWOFA_SELECTORS = ["input[autocomplete=one-time-code]", "input[name=otp]", "input[name=totp]",
                   "input[name=twofactor]", "input[name=code][inputmode=numeric]"]
CAPTCHA_SELECTORS = ["iframe[src*=recaptcha]", "iframe[src*=hcaptcha]", "iframe[src*=turnstile]",
                     "script[src*=recaptcha]", "script[src*=hcaptcha]", "script[src*=turnstile]",
                     "[data-sitekey]"]
HUMAN_TEXT = ["verify it's you", "verify it’s you", "unusual activity", "unusual sign-in",
              "verification code", "check your email", "not a robot", "accept the terms"]
LOCK_TEXT = ["account is locked", "account has been locked", "too many attempts", "too many failed",
             "temporarily blocked", "temporarily locked", "unusual activity"]


class LoginCheckError(Exception):
    """A config or setup problem; the message never carries a vault value."""


def host_name(uri: str | None) -> str | None:
    """Exact host of a URI (lowercase, no suffix games, no www stripping)."""
    if not uri:
        return None
    try:
        return (urllib.parse.urlsplit(uri if "://" in uri else "https://" + uri).hostname or "").lower() or None
    except ValueError:
        return None


def denied(host: str, vault_host: str = "") -> str | None:
    """The deny-list category of a host, or None."""
    host = (host or "").lower().rstrip(".")
    if vault_host and host == vault_host.lower():
        return "vault"
    for category, domains in DENY_DOMAINS.items():
        if any(host == d or host.endswith("." + d) for d in domains):
            return category
    for label in host.split("."):
        for word, category in DENY_WORDS.items():
            if word in label:
                return category
    return None


@dataclass
class Site:
    name: str
    item: str
    origin: str
    login_path: str = "/"
    user: str = ""
    password: str = "input[type=password]"
    ok: dict = field(default_factory=dict)
    bad: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    distinguishes_account: bool = False
    min_interval_days: int = DEFAULT_INTERVAL_DAYS

    @property
    def host(self) -> str:
        return host_name(self.origin) or ""

    @property
    def login_url(self) -> str:
        return self.origin.rstrip("/") + "/" + self.login_path.lstrip("/")


def parse_config(text: str) -> list[Site]:
    """The allow list. Limits can only be made stricter than the defaults, never weaker."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise LoginCheckError("login-checks.toml is not valid TOML") from exc
    sites, seen = [], set()
    for raw in data.get("site", []):
        try:
            fields = raw.get("fields") or {}
            site = Site(
                name=str(raw["name"]), item=str(raw["item"]), origin=str(raw["origin"]).rstrip("/"),
                login_path=str(raw.get("login_path") or "/"), user=str(fields.get("user") or ""),
                password=str(fields.get("password") or "input[type=password]"),
                ok=dict(raw.get("ok") or {}), bad=[str(t) for t in (raw.get("bad") or {}).get("text_any", [])],
                missing=[str(t) for t in (raw.get("missing") or {}).get("text_any", [])],
                distinguishes_account=bool(raw.get("distinguishes_account", False)),
                min_interval_days=max(DEFAULT_INTERVAL_DAYS, int(raw.get("min_interval_days", DEFAULT_INTERVAL_DAYS))))
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise LoginCheckError(f"bad [[site]] entry: {type(exc).__name__}") from exc
        parts = urllib.parse.urlsplit(site.origin)
        if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/"):
            raise LoginCheckError(f"site {site.name}: origin must be https://host without a path")
        if not site.ok and not site.bad:
            raise LoginCheckError(f"site {site.name}: no profile (ok/bad markers), nothing is guessed")
        if site.name in seen:
            raise LoginCheckError(f"site {site.name} is listed twice")
        seen.add(site.name)
        sites.append(site)
    return sites


def describe_sites(sites: list[Site], vault_host: str = "") -> list[str]:
    lines = []
    for s in sites:
        category = denied(s.host, vault_host)
        lines.append(f"  {s.name}: item {s.item} at {s.origin}{s.login_path}"
                     + (f"  [DENIED: {category}, will never run]" if category else ""))
    return lines


# --- the browser layer -----------------------------------------------------------------------


class Session:
    """What the check needs from a browser. Page text exists only to be matched, never stored."""

    blocked: bool = False  # a request to another host was aborted

    def goto(self, url: str) -> None: ...
    def url(self) -> str: ...
    def status(self) -> int | None: ...  # HTTP status of the last page load
    def has(self, selector: str) -> bool: ...
    def fill(self, selector: str, value: str) -> None: ...
    def submit(self, selector: str) -> None: ...  # press Enter in the field, wait for the page to settle
    def text(self) -> str: ...
    def close(self) -> None: ...


Driver = Callable[[str], Session]  # allowed host -> a fresh session


def playwright_installed() -> bool:
    return importlib.util.find_spec("playwright") is not None


class PlaywrightSession(Session):
    """Chromium through Playwright: a fresh context in a private temp directory, nothing recorded."""

    def __init__(self, host: str):
        from playwright.sync_api import sync_playwright
        base = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
        self._dir = tempfile.mkdtemp(prefix="vw-login-", dir=base)
        os.chmod(self._dir, 0o700)
        self._host, self.blocked, self._status = host, False, None
        self._pw = sync_playwright().start()
        try:
            self._browser = self._pw.chromium.launch(
                headless=True, args=["--disable-crash-reporter", "--disable-breakpad", "--disable-extensions"],
                downloads_path=self._dir)
            self._ctx = self._browser.new_context(accept_downloads=False, service_workers="block",
                                                  ignore_https_errors=False)
            self._ctx.route("**/*", self._route)
            self._page = self._ctx.new_page()
            self._page.on("response", self._on_response)
        except BaseException:
            self.close()
            raise

    def _route(self, route) -> None:
        if (host_name(route.request.url) or "") == self._host:
            route.continue_()
        else:
            self.blocked = True
            route.abort()

    def _on_response(self, response) -> None:
        if response.request.is_navigation_request() and response.frame == self._page.main_frame:
            self._status = response.status

    def goto(self, url: str) -> None:
        self._page.goto(url, wait_until="load", timeout=30000)

    def url(self) -> str:
        return self._page.url

    def status(self) -> int | None:
        return self._status

    def has(self, selector: str) -> bool:
        return self._page.locator(selector).count() > 0

    def fill(self, selector: str, value: str) -> None:
        self._page.fill(selector, value, timeout=10000)

    def submit(self, selector: str) -> None:
        self._page.press(selector, "Enter", timeout=10000)
        try:
            self._page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass

    def text(self) -> str:
        return self._page.inner_text("body", timeout=5000)

    def close(self) -> None:
        for step in (lambda: self._ctx.close(), lambda: self._browser.close(), lambda: self._pw.stop()):
            try:
                step()
            except Exception:
                pass
        shutil.rmtree(self._dir, ignore_errors=True)


# --- the check ------------------------------------------------------------------------------


class LoginChecks:
    def __init__(self, sites: list[Site], state_file: Path, fingerprint: Callable[[str], str | None],
                 driver: Driver = PlaywrightSession, journal: Callable[..., None] | None = None,
                 vault_host: str = "", sleep: Callable[[float], None] = time.sleep,
                 now: Callable[[], datetime.datetime] | None = None, jitter: Callable[[], float] | None = None,
                 config_hash: str = ""):
        self.sites, self.state_file, self.fingerprint, self.driver = sites, Path(state_file), fingerprint, driver
        self._journal = journal or (lambda *a, **k: None)
        self.vault_host, self.sleep, self.config_hash = vault_host, sleep, config_hash
        self.now = now or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self.jitter = jitter or (lambda: random.uniform(0, JITTER_SECONDS))

    # state: per site, last check time, last status, pause reason; no values
    def state(self) -> dict:
        try:
            return json.loads(self.state_file.read_text())
        except (OSError, ValueError):
            return {}

    def _update(self, name: str, **fields) -> None:
        data = self.state()
        data.setdefault(name, {}).update(fields)
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(data, indent=1))
        os.chmod(self.state_file, 0o600)

    def run(self, items: list[dict], dry_run: bool = False,
            progress: Callable[[int, int], None] = lambda d, t: None) -> list[dict]:
        rows, attempts = [], 0
        for done, site in enumerate(self.sites):
            progress(done, len(self.sites))
            if attempts >= MAX_SITES_PER_RUN:
                rows.append(self._row(site, "skipped", reason="run limit"))
                continue
            row = self._pre_checks(site, items)
            if row is None:
                if attempts:
                    self.sleep(SITE_PAUSE_SECONDS + self.jitter())
                attempts += 1
                row = self._attempt(site, self._item(site, items), dry_run)
            rows.append(row)
            self._journal("login-check", site=site.name, status=row["status"], dry_run=dry_run)
        progress(len(self.sites), len(self.sites))
        return rows

    def _row(self, site: Site, status: str, **extra) -> dict:
        return {"site": site.name, "item": site.item, "host": site.host, "status": status,
                "time": self.now().isoformat(timespec="seconds"), **extra}

    def _item(self, site: Site, items: list[dict]) -> dict | None:
        found = [i for i in items if i.get("type") == 1 and not i.get("deletedDate") and i.get("name") == site.item]
        return found[0] if len(found) == 1 else None

    def _pre_checks(self, site: Site, items: list[dict]) -> dict | None:
        """A refusal or skip row, or None when the site may be tried."""
        category = denied(site.host, self.vault_host)
        if category:
            return self._row(site, "refused", reason=f"deny list: {category}")
        item = self._item(site, items)
        if item is None:
            return self._row(site, "refused", reason="item not found by exact name (or ambiguous)")
        hosts = [host_name(u.get("uri")) for u in (item.get("login") or {}).get("uris") or []]
        hosts = [h for h in hosts if h]
        if not hosts or any(h != site.host for h in hosts):
            return self._row(site, "refused", reason="item URI host differs from the allowed origin")
        if not (item.get("login") or {}).get("password"):
            return self._row(site, "skipped", reason="item has no password")
        entry = self.state().get(site.name) or {}
        if entry.get("paused"):
            return self._row(site, "skipped", reason=f"paused: {entry['paused']}")
        last = entry.get("last_checked")
        if last:
            age = self.now() - datetime.datetime.fromisoformat(last)
            if age < datetime.timedelta(days=site.min_interval_days):
                return self._row(site, "skipped", reason=f"checked {age.days} days ago, interval "
                                                       f"{site.min_interval_days}")
        return None

    def _attempt(self, site: Site, item: dict, dry_run: bool) -> dict:
        login = item["login"]
        typed = False
        session = None
        try:
            session = self.driver(site.host)
            session.goto(site.login_url)
            verdict = self._guard(site, session)
            if verdict:
                return self._finish(site, verdict[0], reason=verdict[1])
            if dry_run:
                fields = [s for s in (site.user, site.password) if s]
                found = all(session.has(s) for s in fields)
                return self._row(site, "form_found" if found else "unknown", dry_run=True)
            if not session.has(site.password) or (site.user and not session.has(site.user)):
                return self._finish(site, "unknown", reason="form fields not found")
            typed = True  # from here on the attempt counts, even when the library fails midway
            if site.user:
                session.fill(site.user, login.get("username") or "")
            session.fill(site.password, login["password"])
            session.submit(site.password)
            status, reason = self._classify(site, session)
            fp = self.fingerprint(f"{login.get('username') or ''}\n{login['password']}")
            return self._finish(site, status, reason=reason, typed=True, fingerprint=fp)
        except Exception as exc:  # automation errors can quote call details: keep only the type
            return self._finish(site, "error", reason=type(exc).__name__, typed=typed)
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass

    def _guard(self, site: Site, session: Session) -> tuple[str, str] | None:
        """Stops before anything is typed: wrong place, 2FA, captcha, human-only pages."""
        parts = urllib.parse.urlsplit(session.url())
        if session.blocked or parts.scheme != "https" or (parts.hostname or "").lower() != site.host:
            return "refused", "redirect or request to another host"
        return self._human(session)

    def _human(self, session: Session) -> tuple[str, str] | None:
        if any(session.has(s) for s in TWOFA_SELECTORS):
            return "needs_human", "2FA prompt"
        if any(session.has(s) for s in CAPTCHA_SELECTORS):
            return "needs_human", "captcha"
        text = session.text().lower()
        if any(t in text for t in HUMAN_TEXT) and not session.has("input[type=password]"):
            return "needs_human", "verification page"
        return None

    def _classify(self, site: Site, session: Session) -> tuple[str, str]:
        parts = urllib.parse.urlsplit(session.url())
        if session.blocked or (parts.hostname or "").lower() != site.host:
            return "refused", "request to another host after typing"
        if session.status() in (403, 429):
            return "rejected", f"http {session.status()}"
        text = session.text().lower()
        if any(t in text for t in LOCK_TEXT):
            return "needs_human", "lock or unusual-activity text"
        human = self._human(session)
        if human:
            return human
        if any(t.lower() in text for t in site.bad):
            if not site.user:
                return "wrong_password", ""
            if site.distinguishes_account:
                if any(t.lower() in text for t in site.missing):
                    return "account_missing", ""
                return "wrong_password", ""
            return "rejected", "site does not say which part is wrong"
        if site.ok and self._ok(site, session):
            return "works", ""
        return "unknown", "no marker matched"

    def _ok(self, site: Site, session: Session) -> bool:
        url = session.url()
        ok = site.ok
        if "url_not_contains" in ok and str(ok["url_not_contains"]) in url:
            return False
        if "url_contains" in ok and str(ok["url_contains"]) not in url:
            return False
        if "selector" in ok and not session.has(str(ok["selector"])):
            return False
        return True

    def _finish(self, site: Site, status: str, reason: str = "", typed: bool = False, **extra) -> dict:
        """Record the result; the circuit breaker pauses the site on anything suspicious."""
        entry = self.state().get(site.name) or {}
        fields: dict = {"last_status": status}
        if typed:
            fields["last_checked"] = self.now().isoformat(timespec="seconds")
        pause = None
        if status in ("needs_human", "rejected") or (status == "wrong_password" and entry.get("last_status") == "works"):
            pause = f"{status}" + (f" ({reason})" if reason else "")
        elif status == "refused" and "another host" in reason:
            pause = f"{status} ({reason})"
        if pause:
            fields["paused"] = pause
        self._update(site.name, **fields)
        extra = {k: v for k, v in extra.items() if v not in (None, "")}
        row = self._row(site, status, **({"reason": reason} if reason else {}), **extra)
        if status == "wrong_password":
            row["look_at"] = True  # a note for the owner, never the rotation list
        if pause:
            row["paused"] = True
        return row


# --- setup at unlock -------------------------------------------------------------------------


def setup(conf: dict[str, str], engine, vault_host: str = "", ask: Callable[[str], str] = input,
          say: Callable[[str], None] = print, state_dir: Path | None = None,
          driver: Driver | None = None) -> tuple[LoginChecks | None, str]:
    """(module, "") when enabled, else (None, why it is off). Opens no browser."""
    if conf.get("VW_VAULT_LOGIN_CHECKS", "").strip() == "0":
        return None, "login checks are off: VW_VAULT_LOGIN_CHECKS=0"
    path = Path(conf.get("VW_VAULT_LOGIN_CHECKS_FILE") or CONFIG_PATH).expanduser()
    if not path.is_file():
        return None, f"login checks are off: no allow list at {path}"
    if driver is None and not playwright_installed():
        return None, "login checks are off: extra not installed (uv sync --extra login-checks; playwright install chromium)"
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        sites = parse_config(raw.decode())
    except (LoginCheckError, UnicodeDecodeError) as exc:
        return None, f"login checks are off: {exc}"
    state_dir = state_dir or engine_state_dir()
    confirmed = state_dir / "login-checks-confirmed.json"
    try:
        known = json.loads(confirmed.read_text()).get("hash")
    except (OSError, ValueError):
        known = None
    say(f"login checks: {len(sites)} site(s), allow list hash {digest[:16]}")
    if known != digest:
        for line in describe_sites(sites, vault_host):
            say(line)
        if ask("The allow list is new or changed. Allow these login checks? [y/N]: ").strip().lower() != "y":
            return None, "login checks are off: the allow list was not confirmed at unlock"
        state_dir.mkdir(parents=True, exist_ok=True)
        confirmed.write_text(json.dumps({"hash": digest}))
        os.chmod(confirmed, 0o600)
    kw = {"driver": driver} if driver else {}
    return LoginChecks(sites, state_dir / "login-checks-state.json", engine._fp, journal=engine._journal,
                       vault_host=vault_host, config_hash=digest, **kw), ""


def engine_state_dir() -> Path:
    from .engine import STATE_DIR
    return STATE_DIR
