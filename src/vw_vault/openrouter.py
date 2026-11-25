"""OpenRouter rotation module: the provisioning key creates a new API key, the old one is deleted.

The provisioning key (the master) sits in the vault; the rotated item holds an API key named
like the item at OpenRouter. Steps: create a key under the same name (and limit), write it to
the vault item and to the consumers, check it against OpenRouter, delete the old key and check
that the old value is dead. Values travel only through memory, stdin of consumer commands and
the vault write; errors carry no response bodies.
"""

from __future__ import annotations

import json
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path

import httpx
from vw_server.client import VwError

from .rotation import Issued, PartialDistribution

API = "https://openrouter.ai/api/v1"
MASTER_NAME = "OPENROUTER_PROVISIONING_KEY"
VAULT_ITEM = "vault item"


class CommandConsumer:
    """A consumer fed by a command: the value goes to its stdin (rollback runs it with the old one).

    `items` limits it to the vault items of those names; without it the consumer gets every item
    its module rotates. One module often rotates several keys with different consumers (a shared
    key and a person's own key), and a key must never reach a consumer that is not its own."""

    def __init__(self, name: str, cmd: str, timeout: int = 60, items: list[str] | None = None):
        self.name, self.cmd, self.timeout = name, shlex.split(cmd), timeout
        self.items = set(items) if items else None

    def serves(self, item: dict) -> bool:
        return self.items is None or item.get("name") in self.items

    def put(self, value: str) -> None:
        try:
            proc = subprocess.run(self.cmd, input=value, capture_output=True, text=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired):
            raise VwError(f"consumer {self.name} did not run") from None
        if proc.returncode != 0:
            raise VwError(f"consumer {self.name} failed")


def load_consumers(path: str) -> list[CommandConsumer]:
    """A JSON list of {"name": ..., "cmd": ..., "items": [...] (optional: only these item names)}."""
    data = json.loads(Path(path).expanduser().read_text())
    return [CommandConsumer(str(c["name"]), str(c["cmd"]), items=[str(i) for i in c.get("items") or []])
            for c in data]


class OpenRouterRotator:
    name = "openrouter"

    def __init__(self, items: set[str], master: Callable[[], str], write_item: Callable[[dict, str], None],
                 consumers: list | None = None, http: httpx.Client | None = None):
        self.items = set(items)
        self._master = master  # the provisioning key, read inside the daemon
        self._write_item = write_item  # (item, value): the vault item keeps the working key
        self.consumers = list(consumers or [])
        self._http = http or httpx.Client(timeout=30)

    def matches(self, item: dict) -> bool:
        return item.get("type") == 1 and item.get("name") in self.items and not item.get("deletedDate")

    # --- OpenRouter API -------------------------------------------------------------

    def _call(self, method: str, path: str, key: str, **kw) -> httpx.Response:
        try:
            return self._http.request(method, API + path, headers={"Authorization": f"Bearer {key}"}, **kw)
        except httpx.HTTPError:
            raise VwError("OpenRouter is unreachable") from None

    def _listing(self) -> list[dict]:
        rows: list[dict] = []
        while True:
            resp = self._call("GET", "/keys", self._master(), params={"offset": len(rows)})
            if resp.status_code != 200:
                raise VwError(f"listing keys failed (HTTP {resp.status_code})")
            page = resp.json().get("data") or []
            rows += page
            if not page:
                return rows

    def key_rows(self) -> list[dict]:
        """The account's keys without any key text: OpenRouter's masked `label` is left out too.
        The hash is cut to a prefix, enough to tell keys apart (and to find one in the dashboard
        by name, creation date and usage)."""
        return sorted(({"name": k.get("name"), "hash_prefix": str(k.get("hash") or "")[:8],
                        "created": k.get("created_at"), "updated": k.get("updated_at"),
                        "disabled": bool(k.get("disabled")), "limit": k.get("limit"), "usage": k.get("usage")}
                       for k in self._listing()), key=lambda r: (r["created"] or "", r["name"] or ""))

    def _alive(self, value: str) -> bool:
        return self._call("GET", "/key", value).status_code == 200

    # --- module steps ---------------------------------------------------------------

    def issue(self, item: dict) -> Issued:
        old = [k for k in self._listing() if k.get("name") == item["name"]]
        body: dict = {"name": item["name"]}
        if old and old[0].get("limit") is not None:
            body["limit"] = old[0]["limit"]
        resp = self._call("POST", "/keys", self._master(), json=body)
        if resp.status_code not in (200, 201):
            raise VwError(f"creating the key failed (HTTP {resp.status_code})")
        data = resp.json()
        ref, value = (data.get("data") or {}).get("hash"), data.get("key")
        if not ref or not value:
            raise VwError("OpenRouter returned no key")
        return Issued(ref=ref, value=value)

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
        return self._alive(new.value)

    def revoke_old(self, item: dict, new: Issued) -> None:
        for key in self._listing():
            if key.get("name") == item["name"] and key.get("hash") != new.ref:
                resp = self._call("DELETE", f"/keys/{key['hash']}", self._master())
                if resp.status_code not in (200, 204):
                    raise VwError(f"deleting the old key failed (HTTP {resp.status_code})")
        if self._alive(item["login"]["password"]):
            raise VwError("the old key still works")

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
        resp = self._call("DELETE", f"/keys/{new.ref}", self._master())
        if resp.status_code not in (200, 204):
            failed.append("new key")
        if failed:
            raise VwError("rollback incomplete: " + ", ".join(failed))
