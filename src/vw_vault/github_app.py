"""GitHub App module: the app key from the vault issues installation tokens that live an hour.

The vault item (a login in the personal vault) keeps the app's private key (PEM) as its password and
the app id as its username. Steps: sign a short JWT with the key, ask GitHub for an installation
token, hand it to the consumers (stdin of their commands), check it against the API. The item is
never rewritten, and an old token is not revoked: it expires within the hour on its own.
Values travel only through memory and consumer stdin; errors carry no response bodies.
"""

from __future__ import annotations

import time

import httpx
import jwt
from vw_server.client import VwError

from .openrouter import CommandConsumer
from .rotation import Issued, PartialDistribution

API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


class GitHubAppRotator:
    name = "github-app"

    def __init__(self, items: set[str], consumers: list[CommandConsumer] | None = None,
                 installation: str = "", http: httpx.Client | None = None):
        self.items = set(items)
        self.consumers = list(consumers or [])
        self.installation = installation  # empty: the app's only installation
        self._http = http or httpx.Client(timeout=30)

    def matches(self, item: dict) -> bool:
        return item.get("type") in (1, 2) and item.get("name") in self.items and not item.get("deletedDate")

    @staticmethod
    def credentials(item: dict) -> tuple[str, str]:
        """(app id, PEM) from a login (username, password) or a secure note (field APP_ID, notes):
        a PEM pasted into a note keeps its line breaks, a password field may not."""
        login = item.get("login") or {}
        fields = {f.get("name"): f.get("value") for f in item.get("fields") or []}
        app_id = str(login.get("username") or fields.get("APP_ID") or "").strip()
        pem = login.get("password") or item.get("notes") or ""
        if "BEGIN" not in pem:
            pem = ""
        return app_id, pem.strip() + "\n" if pem else ""

    def _call(self, method: str, path: str, token: str, **kw) -> httpx.Response:
        try:
            return self._http.request(method, API + path, headers={**HEADERS, "Authorization": f"Bearer {token}"},
                                      **kw)
        except httpx.HTTPError:
            raise VwError("GitHub is unreachable") from None

    def _app_jwt(self, item: dict) -> str:
        app_id, pem = self.credentials(item)
        if not app_id or not pem:
            raise VwError("the item needs the app id (username or field APP_ID) and the private key "
                          "(password or the note)")
        now = int(time.time())
        try:
            return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": str(app_id)}, pem, algorithm="RS256")
        except Exception:
            raise VwError("the app private key is not usable") from None

    def _installation(self, app_jwt: str) -> str:
        if self.installation:
            return self.installation
        resp = self._call("GET", "/app/installations", app_jwt)
        if resp.status_code != 200:
            raise VwError(f"listing installations failed (HTTP {resp.status_code})")
        rows = resp.json()
        if len(rows) != 1:
            raise VwError(f"expected one installation, found {len(rows)}: set VW_VAULT_GITHUB_APP_INSTALLATION")
        return str(rows[0]["id"])

    def status(self, item: dict) -> dict:
        """The app, its installations and the repositories each one reaches. A token is issued per
        installation for the listing and revoked right after; nothing is handed to consumers."""
        app_jwt = self._app_jwt(item)
        app = self._call("GET", "/app", app_jwt)
        if app.status_code != 200:
            raise VwError(f"the app key is not accepted (HTTP {app.status_code})")
        rows = self._call("GET", "/app/installations", app_jwt)
        if rows.status_code != 200:
            raise VwError(f"listing installations failed (HTTP {rows.status_code})")
        out = []
        for inst in rows.json():
            tok = self._call("POST", f"/app/installations/{inst['id']}/access_tokens", app_jwt)
            if tok.status_code != 201:
                out.append({"installation": inst["id"], "account": (inst.get("account") or {}).get("login"),
                            "error": f"HTTP {tok.status_code}"})
                continue
            token = tok.json()["token"]
            repos = self._call("GET", "/installation/repositories", token, params={"per_page": 100})
            names = [r["full_name"] for r in repos.json().get("repositories", [])] if repos.status_code == 200 else []
            self._call("DELETE", "/installation/token", token)
            out.append({"installation": inst["id"], "account": (inst.get("account") or {}).get("login"),
                        "repository_selection": inst.get("repository_selection"), "repositories": names,
                        "permissions": inst.get("permissions")})
        return {"app": app.json().get("slug"), "installations": out}

    # --- module steps ---------------------------------------------------------------

    def _installations(self, app_jwt: str) -> dict[str, str]:
        """account login (lower case) -> installation id."""
        resp = self._call("GET", "/app/installations", app_jwt)
        if resp.status_code != 200:
            raise VwError(f"listing installations failed (HTTP {resp.status_code})")
        return {str((row.get("account") or {}).get("login", "")).lower(): str(row["id"]) for row in resp.json()}

    def _mint(self, app_jwt: str, installation: str, consumer=None) -> str:
        body = {}
        if getattr(consumer, "repositories", None):
            body["repositories"] = [r.split("/")[-1] for r in consumer.repositories]
        if getattr(consumer, "permissions", None):
            body["permissions"] = dict(consumer.permissions)
        resp = self._call("POST", f"/app/installations/{installation}/access_tokens", app_jwt,
                          **({"json": body} if body else {}))
        if resp.status_code != 201:
            raise VwError(f"issuing the token failed (HTTP {resp.status_code})")
        token = resp.json().get("token")
        if not token:
            raise VwError("GitHub returned no token")
        return token

    def issue(self, item: dict) -> Issued:
        """One token per consumer, from the installation of its account and narrowed to its
        repositories and permissions when it names them; without such consumers, one token from
        the configured (or the only) installation, as before. Tokens stay in daemon memory."""
        app_jwt = self._app_jwt(item)
        self._minted: list[tuple[object, str]] = []
        scoped = [c for c in self.consumers if getattr(c, "account", "")]
        if not scoped:
            token = self._mint(app_jwt, self._installation(app_jwt))
            self._minted = [(None, token)]
            return Issued(ref="1 token", value=token)
        installs = self._installations(app_jwt)
        try:
            for consumer in self.consumers:
                account = (getattr(consumer, "account", "") or "").lower()
                if account not in installs:
                    raise VwError(f"consumer {consumer.name}: the app is not installed on {account or '(no account)'}")
                self._minted.append((consumer, self._mint(app_jwt, installs[account], consumer)))
        except VwError:
            self._revoke_minted()
            raise
        return Issued(ref=f"{len(self._minted)} tokens", value="")

    def _revoke_minted(self) -> None:
        for _, token in getattr(self, "_minted", []):
            self._call("DELETE", "/installation/token", token)
        self._minted = []

    def distribute(self, item: dict, new: Issued) -> list[str]:
        done: list[str] = []
        own = {id(c): t for c, t in getattr(self, "_minted", []) if c is not None}
        try:
            for consumer in self.consumers:
                done.append(consumer.name)  # a failed consumer may be half done: it stays listed
                consumer.put(own.get(id(consumer), new.value))
        except VwError as exc:
            raise PartialDistribution(str(exc), done) from None
        return done

    def verify(self, item: dict, new: Issued) -> bool:
        tokens = [t for _, t in getattr(self, "_minted", [])] or [new.value]
        return all(self._call("GET", "/installation/repositories", t, params={"per_page": 1}).status_code == 200
                   for t in tokens)

    def revoke_old(self, item: dict, new: Issued) -> None:
        """Nothing to do: the previous token expires within the hour."""

    def rollback(self, item: dict, new: Issued, done: list[str]) -> None:
        # the previous tokens are unknown here (and valid until they expire); only the new ones are killed
        tokens = [t for _, t in getattr(self, "_minted", [])] or [new.value]
        failed = [t for t in tokens if self._call("DELETE", "/installation/token", t).status_code != 204]
        self._minted = []
        if failed:
            raise VwError(f"rollback incomplete: {len(failed)} new token(s)")


class GitHubConsumer:
    """A consumer of app tokens: a command fed on stdin, the installation account it needs and,
    optionally, the repositories and permissions its token is narrowed to."""

    def __init__(self, name: str, cmd: str, account: str = "", repositories: list | None = None,
                 permissions: dict | None = None):
        from .openrouter import CommandConsumer
        self._cmd = CommandConsumer(name, cmd)
        self.name, self.account = name, account
        self.repositories, self.permissions = list(repositories or []), dict(permissions or {})

    def put(self, value: str) -> None:
        self._cmd.put(value)


def load_github_consumers(path: str) -> list[GitHubConsumer]:
    """JSON list of {name, cmd, account?, repositories?, permissions?}."""
    import json
    from pathlib import Path
    data = json.loads(Path(path).expanduser().read_text())
    return [GitHubConsumer(str(c["name"]), str(c["cmd"]), str(c.get("account", "")),
                           c.get("repositories"), c.get("permissions")) for c in data]
