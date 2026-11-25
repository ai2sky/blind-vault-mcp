"""Cloudflare tunnel token rotation: a new tunnel secret through the tunnels API, cloudflared checked.

The item holds the token of a remotely managed tunnel (base64 of {a: account, t: tunnel, s: secret}).
Steps: read the old token (its secret is the way back), set a new tunnel secret through the API,
fetch the token and check it **before it is written anywhere** (same account and tunnel, carries
the new secret, differs from the old one), write it to the vault item and the consumers, restart
cloudflared, and check that a new connector of the tunnel is connected (and, if set, that a public
hostname answers). A failure puts the old secret back at Cloudflare, the old token back in every
place, restarts cloudflared and looks again.

Rotating invalidates the old token and the restart drops the tunnel for a moment, and the vault
itself may be served through it (vault.example.com): so this module only runs with the owner's explicit
consent (`owner_consent: true` on the entry); without it, it refuses before any call and says why.
The vault item is written first, while the tunnel still carries the daemon; point the daemon at
`VW_VAULT_LAN_URL` when the vault is reached through this very tunnel.

Configured by a JSON file (`VW_VAULT_CF_TUNNELS`), names and commands only, nothing by default.
Values travel only through memory, stdin of consumer commands and the vault write; errors carry
no response bodies and no token content. Tested on mocks only.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import secrets
import time
from collections.abc import Callable

import httpx
from vw_server.client import VwError

from .openrouter import VAULT_ITEM
from .rotation import Issued, PartialDistribution
from .selfgen import (RESTART, Command, check_keys, check_url_ok, http_ok, in_collection, load_json_list, parse_consumers,
                      parse_int, poll)

API = "https://api.cloudflare.com/client/v4"
MASTER_NAME = "CLOUDFLARE_TUNNEL_EDIT"  # an API token with Cloudflare Tunnel: Edit
ENTRY_KEYS = {"item", "collection", "account_id", "tunnel_id", "consumers", "restart", "check_url",
              "check_retries", "check_delay", "owner_consent"}
REQUIRED_KEYS = {"item", "collection", "account_id", "tunnel_id", "restart"}


@dataclasses.dataclass
class TunnelEntry:
    item: str
    collection: str
    account_id: str
    tunnel_id: str
    consumers: list
    restart: Command
    check_url: str
    retries: int
    delay: float
    consent_given: bool


def parse_entry(raw: dict) -> TunnelEntry:
    what = f"cloudflare tunnel {raw.get('item') or '?'}"
    check_keys(raw, ENTRY_KEYS, REQUIRED_KEYS, what)
    if "owner_consent" in raw and not isinstance(raw["owner_consent"], bool):
        raise VwError(f"{what}: owner_consent is true or false")
    return TunnelEntry(
        item=str(raw["item"]), collection=str(raw["collection"]), account_id=str(raw["account_id"]),
        tunnel_id=str(raw["tunnel_id"]), consumers=parse_consumers(raw.get("consumers"), what),
        restart=Command(what, raw["restart"]),
        check_url=check_url_ok(raw["check_url"], what) if raw.get("check_url") else "",
        retries=parse_int(raw, "check_retries", 10, 1, 60, what), delay=parse_int(raw, "check_delay", 3, 0, 300, what),
        consent_given=raw.get("owner_consent") is True)


def load_entries(path: str) -> list[TunnelEntry]:
    entries = [parse_entry(e) for e in load_json_list(path, "cloudflare tunnels config")]
    keys = [(e.item, e.collection) for e in entries]
    if len(set(keys)) != len(keys):
        raise VwError("cloudflare tunnels config: an item is listed twice for one collection")
    return entries


def decode_token(value: str) -> dict | None:
    """{a, t, s} of a tunnel token, or None when it is not one (never echoed anywhere)."""
    try:
        data = json.loads(base64.b64decode(value + "=" * (-len(value) % 4), validate=True))
    except (binascii.Error, ValueError, TypeError):
        return None
    if isinstance(data, dict) and all(isinstance(data.get(k), str) and data[k] for k in ("a", "t", "s")):
        return data
    return None


def new_secret() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


class CloudflareTunnelRotator:
    name = "cloudflare-tunnel"

    def __init__(self, entries: list[TunnelEntry], master: Callable[[], str],
                 write_item: Callable[[dict, str], None], collection_names: Callable[[], dict],
                 http: httpx.Client | None = None, secret: Callable[[], str] = new_secret,
                 sleep: Callable[[float], None] = time.sleep):
        self.entries = list(entries)
        self._master = master  # the API token with Tunnel: Edit, read inside the daemon
        self._write_item = write_item
        self._collection_names = collection_names
        self._http = http or httpx.Client(timeout=30)
        self._secret = secret
        self._sleep = sleep
        self._seen: dict[str, set[str]] = {}  # per rotation: connector ids that must not count as new

    def _entry(self, item: dict) -> TunnelEntry | None:
        for entry in self.entries:
            if item.get("name") == entry.item and in_collection(item, entry.collection, self._collection_names):
                return entry
        return None

    def matches(self, item: dict) -> bool:
        return item.get("type") == 1 and not item.get("deletedDate") and self._entry(item) is not None

    # --- Cloudflare API ---------------------------------------------------------------

    def _call(self, entry: TunnelEntry, method: str, suffix: str = "", **kw) -> httpx.Response:
        url = f"{API}/accounts/{entry.account_id}/cfd_tunnel/{entry.tunnel_id}{suffix}"
        try:
            return self._http.request(method, url, headers={"Authorization": f"Bearer {self._master()}"}, **kw)
        except httpx.HTTPError:
            raise VwError("Cloudflare is unreachable") from None

    def _set_secret(self, entry: TunnelEntry, secret: str) -> bool:
        try:
            return self._call(entry, "PATCH", json={"tunnel_secret": secret}).status_code == 200
        except VwError:
            return False

    def _token(self, entry: TunnelEntry) -> str:
        resp = self._call(entry, "GET", "/token")
        if resp.status_code != 200:
            raise VwError(f"reading the tunnel token failed (HTTP {resp.status_code})")
        try:
            result = resp.json().get("result")
        except ValueError:
            result = None
        if not isinstance(result, str) or not result:
            raise VwError("Cloudflare returned no tunnel token")
        return result

    def _connectors(self, entry: TunnelEntry) -> dict[str, bool]:
        """Connector id -> whether it holds a live connection of the tunnel."""
        resp = self._call(entry, "GET", "/connections")
        if resp.status_code != 200:
            raise VwError(f"reading the tunnel connections failed (HTTP {resp.status_code})")
        try:
            rows = resp.json().get("result") or []
        except ValueError:
            rows = []
        return {str(r["id"]): any(not c.get("is_pending_reconnect") for c in r.get("conns") or [])
                for r in rows if isinstance(r, dict) and r.get("id")}

    def _connected(self, entry: TunnelEntry, ref: str) -> bool:
        """A connector that did not exist before the restart is connected (and the hostname answers)."""
        def once() -> bool:
            try:
                rows = self._connectors(entry)
            except VwError:
                return False
            fresh = {i for i, live in rows.items() if live and i not in self._seen[ref]}
            self._seen[ref] |= set(rows)
            if not fresh:
                return False
            return not entry.check_url or http_ok(self._http, entry.check_url)
        return poll(once, entry.retries, entry.delay, self._sleep)

    # --- module steps -----------------------------------------------------------------

    def issue(self, item: dict) -> Issued:
        entry = self._entry(item)
        if entry is None:
            raise VwError("the item is not in the tunnels config")
        if not entry.consent_given:
            # no call has been made and nothing is generated
            raise VwError(
                f"tunnel token {entry.item} is rotated only with the owner's explicit consent: the old token "
                f"stops working and restarting cloudflared drops the tunnel (and the vault with it, if it is served through the tunnel); set "
                f"owner_consent to true on its entry in the tunnels config to allow it")
        old = decode_token(item["login"]["password"])
        if not old or old["a"] != entry.account_id or old["t"] != entry.tunnel_id:
            raise VwError("the item does not hold a token of the configured tunnel")
        resp = self._call(entry, "GET")
        if resp.status_code != 200:
            raise VwError(f"reading the tunnel failed (HTTP {resp.status_code})")
        secret = self._secret()
        if not self._set_secret(entry, secret):
            raise VwError("setting a new tunnel secret failed; the old token is intact")
        try:
            value = self._token(entry)
            fresh = decode_token(value)
            if not (fresh and fresh["a"] == entry.account_id and fresh["t"] == entry.tunnel_id
                    and fresh["s"] == secret and fresh["s"] != old["s"] and value != item["login"]["password"]):
                raise VwError("Cloudflare returned a token that does not carry the new secret")
        except VwError as exc:
            # the secret is already changed and nothing is written yet: give the old one back here
            back = self._set_secret(entry, old["s"])
            raise VwError(f"{exc}; " + ("the old secret was put back" if back else
                                        "the OLD SECRET COULD NOT BE PUT BACK, restore it by hand")) from None
        return Issued(ref=secrets.token_hex(4), value=value)

    def distribute(self, item: dict, new: Issued) -> list[str]:
        entry = self._entry(item)
        done: list[str] = []
        try:
            # the vault goes first: it may be reached through this tunnel, which is still up
            done.append(VAULT_ITEM)
            self._write_item(item, new.value)
            for consumer in entry.consumers:
                done.append(consumer.name)
                consumer.put(new.value)
            self._seen[new.ref] = set(self._connectors(entry))
            done.append(RESTART)
            if not entry.restart.run():
                raise VwError("restart failed")
        except VwError as exc:
            raise PartialDistribution(str(exc), done) from None
        return done

    def verify(self, item: dict, new: Issued) -> bool:
        return self._connected(self._entry(item), new.ref)

    def revoke_old(self, item: dict, new: Issued) -> None:
        """The old token died when the secret changed; only the bookkeeping is left."""
        self._seen.pop(new.ref, None)

    def rollback(self, item: dict, new: Issued, done: list[str]) -> None:
        entry = self._entry(item)
        old_value = item["login"]["password"]
        failed: list[str] = []
        # first make the old token valid again, then put it back where it is read
        if not self._set_secret(entry, decode_token(old_value)["s"]):
            failed.append("old tunnel secret")
        for name in reversed(done):
            if name == RESTART:
                continue
            try:
                if name == VAULT_ITEM:
                    self._write_item(item, old_value)
                else:
                    next(c for c in entry.consumers if c.name == name).put(old_value)
            except Exception:
                failed.append(name)
        if RESTART in done:
            self._seen.setdefault(new.ref, set())
            if not entry.restart.run():
                failed.append(RESTART)
            elif not self._connected(entry, new.ref):
                failed.append("connection after rollback")
        self._seen.pop(new.ref, None)
        if failed:
            raise VwError("rollback incomplete: " + ", ".join(failed))


def from_settings(conf: dict, engine) -> CloudflareTunnelRotator | None:
    path = conf.get("VW_VAULT_CF_TUNNELS")
    if not path:
        return None
    master = conf.get("VW_VAULT_CF_TUNNELS_MASTER") or MASTER_NAME
    return CloudflareTunnelRotator(load_entries(path), lambda: engine.master_value(master),
                                   engine.write_password, lambda: engine.collections)
