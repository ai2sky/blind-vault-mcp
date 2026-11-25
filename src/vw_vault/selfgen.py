"""Rotation module for secrets an application invents itself (a session key, an admin token ...).

There is no issuer to ask for a new value, so the daemon makes one. Steps: generate a value and
check it **before anything is written** (shape, differs from the old one, an optional check
command), write it to the vault item (the collection the consumer reads at startup) and to the
other consumers, restart the consumer, then check that it runs on the new value. A failed
distribute, restart or check puts the old value back everywhere, restarts the consumer again
and checks it again; the vault item keeps the old value. Nothing at an issuer needs revoking.

What is rotated and how comes from a JSON file the daemon is pointed at
(`VW_VAULT_SELFGEN_CONFIG`), never from code: no secret is listed by default. Some secrets only
rotate with the owner's explicit consent (`owner_consent: true` on their entry): a change of
an application's session signing key logs every user out. Without the flag the module refuses and says why.

The file holds names and commands, never values. Values travel only through memory, stdin of
commands and the vault write; errors are our own sentences, never a command's output.
"""

from __future__ import annotations

import dataclasses
import json
import secrets
import shlex
import string
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

import httpx
from vw_server.client import VwError

from .openrouter import VAULT_ITEM, CommandConsumer
from .rotation import Issued, PartialDistribution

RESTART = "restart"
# secrets whose rotation has a cost the owner has to accept; the config cannot lift this
OWNER_CONSENT_ONLY: frozenset[str] = frozenset()  # names that always need consent; extend per deployment
ALPHABETS = {
    "alnum": string.ascii_letters + string.digits,
    "hex": string.hexdigits[:16],
    "urlsafe": string.ascii_letters + string.digits + "-_",
}
MIN_LENGTH, MAX_LENGTH, DEFAULT_LENGTH = 32, 256, 48
ENTRY_KEYS = {"name", "collection", "length", "alphabet", "consumers", "restart", "check_url", "check_cmd",
              "precheck_cmd", "check_retries", "check_delay", "requires_consent", "owner_consent"}
REQUIRED_KEYS = {"name", "collection"}


# --- helpers shared with the tunnel module ---------------------------------------------

def load_json_list(path: str, what: str) -> list[dict]:
    try:
        data = json.loads(Path(path).expanduser().read_text())
    except (OSError, ValueError):
        raise VwError(f"{what}: the file cannot be read as JSON") from None
    if not isinstance(data, list) or not all(isinstance(e, dict) for e in data):
        raise VwError(f"{what}: expected a JSON list of objects")
    return data


def check_keys(entry: dict, allowed: set[str], required: set[str], what: str) -> None:
    """A strict key set: a stray key (a `value`, a `password`) is refused, never ignored."""
    extra = set(entry) - allowed
    if extra:
        # key names only; a value never appears in a message
        raise VwError(f"{what}: unknown keys {sorted(extra)}; the config holds names and commands, not secrets")
    missing = {k for k in required if not entry.get(k)}
    if missing:
        raise VwError(f"{what}: missing {sorted(missing)}")


def parse_consumers(raw, what: str) -> list[CommandConsumer]:
    out: list[CommandConsumer] = []
    for c in raw or []:
        if not isinstance(c, dict) or not c.get("name") or not c.get("cmd") or set(c) - {"name", "cmd"}:
            raise VwError(f"{what}: a consumer is {{name, cmd}}")
        if c["name"] in (VAULT_ITEM, RESTART) or c["name"] in {x.name for x in out}:
            raise VwError(f"{what}: consumer name {c['name']!r} is reserved or repeated")
        out.append(CommandConsumer(str(c["name"]), str(c["cmd"])))
    return out


def parse_int(entry: dict, key: str, default: int, low: int, high: int, what: str) -> int:
    value = entry.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise VwError(f"{what}: {key} must be a number from {low} to {high}")
    return value


class Command:
    """A command without a value on stdin (a restart); the output is never read into a message."""

    def __init__(self, what: str, cmd: str, timeout: int = 120):
        try:
            self.argv = shlex.split(cmd)
        except ValueError:
            raise VwError(f"{what}: the command cannot be parsed") from None
        if not self.argv:
            raise VwError(f"{what}: the command is empty")
        self.what, self.timeout = what, timeout

    def run(self, value: str | None = None) -> bool:
        try:
            proc = subprocess.run(self.argv, input=value, capture_output=True, text=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0


def poll(fn: Callable[[], bool], retries: int, delay: float, sleep: Callable[[float], None]) -> bool:
    """fn until it is true, `retries` tries, `delay` seconds apart (a restarted service needs a moment)."""
    for attempt in range(int(retries)):
        if fn():
            return True
        if attempt < retries - 1:
            sleep(delay)
    return False


def http_ok(http: httpx.Client, url: str) -> bool:
    try:
        return 200 <= http.get(url, follow_redirects=False).status_code < 300
    except httpx.HTTPError:
        return False


def check_url_ok(url: str, what: str) -> str:
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise VwError(f"{what}: check_url must be an http(s) URL")
    return url


def in_collection(item: dict, collection: str, names: Callable[[], dict]) -> bool:
    known = names()
    return collection in {known.get(c) for c in item.get("collectionIds") or []}


# --- the module ---------------------------------------------------------------------------

@dataclasses.dataclass
class Entry:
    name: str
    collection: str
    length: int
    alphabet: str
    consumers: list
    restart: Command | None
    check_url: str
    check: Command | None
    precheck: Command | None
    retries: int
    delay: float
    consent_needed: bool
    consent_given: bool


def parse_entry(raw: dict) -> Entry:
    what = f"self-generated secret {raw.get('name') or '?'}"
    check_keys(raw, ENTRY_KEYS, REQUIRED_KEYS, what)
    name = str(raw["name"])
    alphabet = raw.get("alphabet", "alnum")
    if alphabet not in ALPHABETS:
        raise VwError(f"{what}: alphabet is one of {sorted(ALPHABETS)}")
    for flag in ("requires_consent", "owner_consent"):
        if flag in raw and not isinstance(raw[flag], bool):
            raise VwError(f"{what}: {flag} is true or false")
    check_url = check_url_ok(raw["check_url"], what) if raw.get("check_url") else ""
    check = Command(what, raw["check_cmd"]) if raw.get("check_cmd") else None
    if not check_url and not check:
        raise VwError(f"{what}: a check is required (check_url or check_cmd): no rotation without a way to verify")
    return Entry(
        name=name, collection=str(raw["collection"]),
        length=parse_int(raw, "length", DEFAULT_LENGTH, MIN_LENGTH, MAX_LENGTH, what), alphabet=alphabet,
        consumers=parse_consumers(raw.get("consumers"), what),
        restart=Command(what, raw["restart"]) if raw.get("restart") else None,
        check_url=check_url, check=check,
        precheck=Command(what, raw["precheck_cmd"]) if raw.get("precheck_cmd") else None,
        retries=parse_int(raw, "check_retries", 5, 1, 60, what), delay=parse_int(raw, "check_delay", 3, 0, 300, what),
        # the built-in list cannot be turned off from the file
        consent_needed=name.strip().upper() in OWNER_CONSENT_ONLY or raw.get("requires_consent", False),
        consent_given=raw.get("owner_consent") is True,
    )


def load_entries(path: str) -> list[Entry]:
    entries = [parse_entry(e) for e in load_json_list(path, "self-generated secrets config")]
    keys = [(e.name, e.collection) for e in entries]
    if len(set(keys)) != len(keys):
        raise VwError("self-generated secrets config: a name is listed twice for one collection")
    return entries


def generate(length: int, alphabet: str) -> str:
    return "".join(secrets.choice(ALPHABETS[alphabet]) for _ in range(length))


class SelfGeneratedRotator:
    name = "self-generated"

    def __init__(self, entries: list[Entry], write_item: Callable[[dict, str], None],
                 collection_names: Callable[[], dict], http: httpx.Client | None = None,
                 generator: Callable[[int, str], str] = generate, sleep: Callable[[float], None] = time.sleep):
        self.entries = list(entries)
        self._write_item = write_item  # (item, value): the vault item keeps the working value
        self._collection_names = collection_names  # id -> name of the collections the daemon knows
        self._http = http or httpx.Client(timeout=15)
        self._generate = generator
        self._sleep = sleep

    def _entry(self, item: dict) -> Entry | None:
        for entry in self.entries:
            if item.get("name") == entry.name and in_collection(item, entry.collection, self._collection_names):
                return entry
        return None

    def matches(self, item: dict) -> bool:
        return item.get("type") == 1 and not item.get("deletedDate") and self._entry(item) is not None

    # --- checks -----------------------------------------------------------------------

    def _check(self, entry: Entry, value: str) -> bool:
        def once() -> bool:
            if entry.check_url and not http_ok(self._http, entry.check_url):
                return False
            return entry.check.run(value) if entry.check else True
        return poll(once, entry.retries, entry.delay, self._sleep)

    def _acceptable(self, entry: Entry, value: str, old: str) -> bool:
        """The new value is judged here, before the first write."""
        return (isinstance(value, str) and len(value) == entry.length and value != old
                and set(value) <= set(ALPHABETS[entry.alphabet]) and len(set(value)) >= 8
                and (entry.precheck is None or entry.precheck.run(value)))

    # --- module steps -----------------------------------------------------------------

    def issue(self, item: dict) -> Issued:
        entry = self._entry(item)
        if entry is None:
            raise VwError("the item is not in the self-generated config")
        if entry.consent_needed and not entry.consent_given:
            # nothing has been generated or touched yet
            raise VwError(
                f"{entry.name} is rotated only with the owner's explicit consent: changing it has a cost "
                f"(e.g. a new session signing key signs every user out); set owner_consent to true on its entry in the "
                f"self-generated config to allow it")
        value = self._generate(entry.length, entry.alphabet)
        if not self._acceptable(entry, value, item["login"]["password"]):
            raise VwError("the generated value was rejected before any write; the old value stays")
        return Issued(ref=secrets.token_hex(4), value=value)

    def distribute(self, item: dict, new: Issued) -> list[str]:
        entry = self._entry(item)
        done: list[str] = []
        # a failed step may be half done: it stays in `done`, so the rollback restores it as well
        try:
            done.append(VAULT_ITEM)
            self._write_item(item, new.value)
            for consumer in entry.consumers:
                done.append(consumer.name)
                consumer.put(new.value)
            if entry.restart:
                done.append(RESTART)
                if not entry.restart.run():
                    raise VwError("restart failed")
        except VwError as exc:
            raise PartialDistribution(str(exc), done) from None
        return done

    def verify(self, item: dict, new: Issued) -> bool:
        return self._check(self._entry(item), new.value)

    def revoke_old(self, item: dict, new: Issued) -> None:
        """Nothing to revoke: the value was never registered anywhere but in the consumers."""

    def rollback(self, item: dict, new: Issued, done: list[str]) -> None:
        entry = self._entry(item)
        old = item["login"]["password"]
        failed: list[str] = []
        for name in reversed(done):
            if name == RESTART:
                continue
            try:
                if name == VAULT_ITEM:
                    self._write_item(item, old)
                else:
                    next(c for c in entry.consumers if c.name == name).put(old)
            except Exception:
                failed.append(name)
        if RESTART in done:
            # the consumer may be running on the new value: restart it on the old one and look
            if not entry.restart.run():
                failed.append(RESTART)
            elif not self._check(entry, old):
                failed.append("check after rollback")
        if failed:
            raise VwError("rollback incomplete: " + ", ".join(failed))


def from_settings(conf: dict, engine) -> SelfGeneratedRotator | None:
    """The module when the daemon is pointed at a config; with no setting nothing is rotated."""
    path = conf.get("VW_VAULT_SELFGEN_CONFIG")
    if not path:
        return None
    return SelfGeneratedRotator(load_entries(path), engine.write_password, lambda: engine.collections)
