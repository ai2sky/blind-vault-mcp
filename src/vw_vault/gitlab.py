"""GitLab rotation module: a personal access token rotates itself through the API.

The item holds a GitLab PAT. Steps: read the token (id, expiry), call the self-rotate endpoint,
write the new value to the vault item and the consumers, check it with the token self call,
check that the old value is dead. GitLab revokes the old token inside the rotate call, so there
is no way back to it: a failed distribute or verify writes the new value again to every place
and keeps the new token alive. Values travel only through memory, stdin of consumer commands
and the vault write; errors carry no response bodies.
"""

from __future__ import annotations

import datetime
from collections.abc import Callable

import httpx
from vw_server.client import VwError

from .openrouter import VAULT_ITEM
from .rotation import Issued, PartialDistribution

DEFAULT_URL = "https://gitlab.com"
MAX_DAYS = 365  # the GitLab limit for a token lifetime
SELF = "/personal_access_tokens/self"


class GitLabRotator:
    name = "gitlab"

    def __init__(self, items: set[str], write_item: Callable[[dict, str], None], consumers: list | None = None,
                 url: str = DEFAULT_URL, http: httpx.Client | None = None,
                 today: Callable[[], datetime.date] = datetime.date.today):
        self.items = set(items)
        self._write_item = write_item  # (item, value): the vault item keeps the working token
        self.consumers = list(consumers or [])
        self._api = (url or DEFAULT_URL).rstrip("/") + "/api/v4"
        self._http = http or httpx.Client(timeout=30)
        self._today = today

    def matches(self, item: dict) -> bool:
        return item.get("type") == 1 and item.get("name") in self.items and not item.get("deletedDate")

    # --- GitLab API -----------------------------------------------------------------

    def _call(self, method: str, path: str, token: str, **kw) -> httpx.Response:
        try:
            return self._http.request(method, self._api + path, headers={"PRIVATE-TOKEN": token}, **kw)
        except httpx.HTTPError:
            raise VwError("GitLab is unreachable") from None

    def _self(self, value: str) -> dict | None:
        """The token record of a token value, or None when it is not active."""
        resp = self._call("GET", SELF, value)
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except ValueError:
            return None
        if not isinstance(data, dict) or not data.get("active") or data.get("revoked") or not data.get("id"):
            return None
        return data

    def _lifetime(self, current: dict) -> int | None:
        """Days the new token lives: the lifetime of the old one, capped; None keeps GitLab's default."""
        try:
            end = datetime.date.fromisoformat(current["expires_at"])
            start = datetime.date.fromisoformat(current["created_at"][:10])
        except (KeyError, TypeError, ValueError):
            return None
        return max(1, min((end - start).days, MAX_DAYS))

    # --- module steps ---------------------------------------------------------------

    def issue(self, item: dict) -> Issued:
        old_value = item["login"]["password"]
        current = self._self(old_value)
        if not current:
            raise VwError("the current token is not active")
        if not {"api", "self_rotate"} & set(current.get("scopes") or []):
            raise VwError("the token has no api or self_rotate scope")
        params = {}
        days = self._lifetime(current)
        if days:
            params["expires_at"] = (self._today() + datetime.timedelta(days=days)).isoformat()
        resp = self._call("POST", SELF + "/rotate", old_value, params=params)
        if resp.status_code not in (200, 201):
            raise VwError(f"rotating the token failed (HTTP {resp.status_code})")
        try:
            data = resp.json()
        except ValueError:
            data = {}
        ref, value = data.get("id"), data.get("token")
        if not ref or not value:
            # the old token is gone and the new value is lost: say it plainly
            raise VwError("GitLab returned no token after the rotate; the old token is revoked")
        return Issued(ref=str(ref), value=value)

    def distribute(self, item: dict, new: Issued) -> list[str]:
        done: list[str] = []
        # a failed step may be half done: it stays in `done`
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
        current = self._self(new.value)
        return bool(current) and str(current["id"]) == new.ref

    def revoke_old(self, item: dict, new: Issued) -> None:
        # GitLab revoked the old token in the rotate call; only the check is left
        if self._self(item["login"]["password"]):
            raise VwError("the old token still works")

    def rollback(self, item: dict, new: Issued, done: list[str]) -> None:
        """The old token is already revoked: make sure every place holds the new, live value."""
        failed: list[str] = []
        for consumer in [None, *self.consumers]:
            try:
                if consumer is None:
                    self._write_item(item, new.value)
                else:
                    consumer.put(new.value)
            except Exception:
                failed.append(VAULT_ITEM if consumer is None else consumer.name)
        if failed:
            raise VwError("old token already revoked, the new one is not stored in: " + ", ".join(failed))
