"""Cloudflare rotation module: a token with API Tokens: Edit replaces an API token with a copy.

The manager token (the master) sits in the vault; the rotated item holds another Cloudflare API
token. Steps: find the old token id by verifying its value, create a new token with the same
name, policies, condition and expiry, write it to the vault item and to the consumers, check it
with the token verify call, delete the old token and check that the old value is dead. A new
token is created instead of rolled in place, because a roll kills the old value at once and
leaves no way back. Values travel only through memory, stdin of consumer commands and the
vault write; errors carry no response bodies.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
from vw_server.client import VwError

from .openrouter import VAULT_ITEM
from .rotation import Issued, PartialDistribution

API = "https://api.cloudflare.com/client/v4"
MASTER_NAME = "CLOUDFLARE_API_TOKENS_EDIT"
# fields of a token that a create call takes; the rest (id, issued_on, status ...) is server-set
COPIED = ("name", "policies", "condition", "not_before", "expires_on")


class CloudflareRotator:
    name = "cloudflare"

    def __init__(self, items: set[str], master: Callable[[], str], write_item: Callable[[dict, str], None],
                 consumers: list | None = None, http: httpx.Client | None = None):
        self.items = set(items)
        self._master = master  # the API Tokens: Edit token, read inside the daemon
        self._write_item = write_item  # (item, value): the vault item keeps the working token
        self.consumers = list(consumers or [])
        self._http = http or httpx.Client(timeout=30)

    def matches(self, item: dict) -> bool:
        return item.get("type") == 1 and item.get("name") in self.items and not item.get("deletedDate")

    # --- Cloudflare API -------------------------------------------------------------

    def _call(self, method: str, path: str, token: str, **kw) -> httpx.Response:
        try:
            return self._http.request(method, API + path, headers={"Authorization": f"Bearer {token}"}, **kw)
        except httpx.HTTPError:
            raise VwError("Cloudflare is unreachable") from None

    def _verify(self, value: str) -> dict | None:
        """The verify result of a token value, or None when it is not active."""
        resp = self._call("GET", "/user/tokens/verify", value)
        if resp.status_code != 200:
            return None
        try:
            result = resp.json().get("result") or {}
        except ValueError:
            return None
        return result if result.get("status") == "active" and result.get("id") else None

    # --- module steps ---------------------------------------------------------------

    def issue(self, item: dict) -> Issued:
        old = self._verify(item["login"]["password"])
        if not old:
            raise VwError("the current token is not active")
        resp = self._call("GET", f"/user/tokens/{old['id']}", self._master())
        if resp.status_code != 200:
            raise VwError(f"reading the token failed (HTTP {resp.status_code})")
        current = resp.json().get("result") or {}
        body = {k: current[k] for k in COPIED if current.get(k) is not None}
        body["name"] = current.get("name") or item["name"]
        resp = self._call("POST", "/user/tokens", self._master(), json=body)
        if resp.status_code not in (200, 201):
            raise VwError(f"creating the token failed (HTTP {resp.status_code})")
        result = resp.json().get("result") or {}
        ref, value = result.get("id"), result.get("value")
        if not ref or not value:
            raise VwError("Cloudflare returned no token")
        # the old id rides along in the ref so that revoke_old needs no second lookup
        return Issued(ref=f"{ref}:{old['id']}", value=value)

    def distribute(self, item: dict, new: Issued) -> list[str]:
        done: list[str] = []
        # a failed step may be half done: it stays in `done`, so the rollback restores it as well
        try:
            done.append(VAULT_ITEM)
            self._write_item(item, new.value)
            for consumer in self.consumers:
                if not consumer.serves(item):
                    continue
                done.append(consumer.name)
                consumer.put(new.value)
        except VwError as exc:
            raise PartialDistribution(str(exc), done) from None
        return done

    def verify(self, item: dict, new: Issued) -> bool:
        result = self._verify(new.value)
        return bool(result) and result["id"] == new.ref.split(":")[0]

    def revoke_old(self, item: dict, new: Issued) -> None:
        resp = self._call("DELETE", f"/user/tokens/{new.ref.split(':')[1]}", self._master())
        if resp.status_code not in (200, 204):
            raise VwError(f"deleting the old token failed (HTTP {resp.status_code})")
        if self._verify(item["login"]["password"]):
            raise VwError("the old token still works")

    def rollback(self, item: dict, new: Issued, done: list[str]) -> None:
        old = item["login"]["password"]
        failed: list[str] = []
        for name in reversed(done):
            try:
                if name == VAULT_ITEM:
                    self._write_item(item, old)
                else:
                    next(c for c in self.consumers if c.name == name).put(old)
            except Exception:
                failed.append(name)
        resp = self._call("DELETE", f"/user/tokens/{new.ref.split(':')[0]}", self._master())
        if resp.status_code not in (200, 204):
            failed.append("new token")
        if failed:
            raise VwError("rollback incomplete: " + ", ".join(failed))
