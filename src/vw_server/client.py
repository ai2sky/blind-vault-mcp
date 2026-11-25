"""Write-only wrapper around the Bitwarden CLI (bw) for Vaultwarden.

Only the names of items in the whitelist folder (or, when an organization
collection is configured, in that collection) are ever listed. Values are
passed to bw through stdin (bw encode, then create/edit) and never appear in
argv, return values or error messages. There is deliberately no function that
exposes a value.
"""

import dataclasses
import functools
import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .useragent import USER_AGENT

try:
    import fcntl
except ImportError:  # Windows: no fcntl, the lock goes through msvcrt
    fcntl = None
    import msvcrt


def _lock_nowait(fd: int) -> None:
    """Take an exclusive lock on fd or raise BlockingIOError if another process holds it."""
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # the first byte stands for the whole file
    except OSError:
        raise BlockingIOError("vw.lock is held") from None


def _unlock(fd: int) -> None:
    """Closing drops a flock; on Windows unlock first so the region is freed at once."""
    if fcntl is None:
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    os.close(fd)

NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
COLLECTION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
MAX_VALUE_LEN =16384
BW_TIMEOUT = 60
DEFAULT_FOLDER = "agents"
SECURE_NOTE = 2  # Bitwarden item type for a secure note
LOGIN = 1  # Bitwarden item type for a login
KEYRING_SERVICE = "vw-manager"  # default keyring service of the manager account; VW_KEYRING_SERVICE overrides
MEMBER_USER = 2  # organization role «User»
MEMBER_INVITED, MEMBER_ACCEPTED = 0, 1  # organization member status; 2 is confirmed
LOCK_FILE = "vw.lock"  # in the bw data dir
LOCK_WAIT = 2 * BW_TIMEOUT  # seconds to wait for another process using the same data dir


# Reasons bw gives that are safe to repeat: short, fixed phrases that cannot carry an item's
# contents. Anything else is dropped, because `bw create` and `bw encode` echo the item on error.
SAFE_REASONS = (
    "not found",
    "you do not have permission",
    "you are not logged in",
    "vault is locked",
    "invalid master password",
    "more than one result",
    "could not connect",
    "rate limit",
    "unauthorized",
    "forbidden",
    "session key",
    "premium",
)
MAX_REASON_LEN = 120
# Node error classes bw dies with ("FetchError: request to ... failed"): when a line starts with
# one, its name alone is repeated, never the rest of the line.
ERROR_CLASSES = ("FetchError", "TypeError", "SyntaxError", "RangeError", "ReferenceError", "Error")
ERROR_CLASS_RE = re.compile(r"^(%s)(?::|$)" % "|".join(ERROR_CLASSES))


def screen_stderr(text: str) -> str:
    """The reason bw gave, if repeating it cannot leak a secret; otherwise nothing.

    Only a short last line matching a known phrase passes, and anything shaped like JSON
    or a key=value pair is dropped whatever it says. Failing that, the name of a Node
    error class that starts a line is given on its own.
    """
    lines = [line.strip() for line in (text or "").strip().splitlines() if line.strip()]
    if lines:
        line = lines[-1]
        if len(line) <= MAX_REASON_LEN and not any(c in line for c in '{}"='):
            low = line.lower()
            if any(reason in low for reason in SAFE_REASONS):
                return line
    for line in reversed(lines):
        match = ERROR_CLASS_RE.match(line)
        if match:
            return match.group(1)
    return ""


class VwError(Exception):
    """vw failure. Messages never contain secret values."""


@dataclass(frozen=True)
class VwConfig:
    server_url: str
    client_id: str
    client_secret_file: Path
    master_password_file: Path
    folder: str = DEFAULT_FOLDER
    bw: str = "bw"
    organization_id: str = ""
    collection: str = ""
    client_secret: str = ""  # from the keyring; takes the place of the file
    master_password: str = ""  # from the keyring; takes the place of the file
    # bw's own data directory for this account: never the user's (a personal `bw login` in the same
    # HOME would make the account's login fail and its unlock use the wrong vault)
    bw_data_dir: str = ""

    @property
    def use_collection(self) -> bool:
        return bool(self.organization_id and self.collection)

    def validate(self) -> None:
        for label, path, inline in (("client secret", self.client_secret_file, self.client_secret),
                                    ("master password", self.master_password_file, self.master_password)):
            if not inline and not path.is_file():
                raise VwError(f"{label} file not found")


def keyring_service() -> str:
    """The keyring service of the manager account, read at call time (after prime_environment)."""
    return os.environ.get("VW_KEYRING_SERVICE", "").strip() or KEYRING_SERVICE


def keyring_get(key: str) -> str:
    """One credential of the manager account from the OS keyring ("" if absent)."""
    try:
        import keyring
        return keyring.get_password(keyring_service(), key) or ""
    except Exception:
        return ""


ENV_FILE = "~/.config/vw/env"


def settings_from_file(env: dict[str, str]) -> dict[str, str]:
    """The VW_* settings of `~/.config/vw/env` under `env`, which wins. As `vw-put` reads them."""
    path = Path(env.get("VW_ENV_FILE", "") or ENV_FILE).expanduser()
    from_file: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                from_file[key.strip().removeprefix("export ").strip()] = value.strip().strip("'\"")
    return {**from_file, **env}


def prime_environment(env: dict[str, str] | None = None) -> None:
    """Put the VW_* settings of `~/.config/vw/env` into the process environment.

    `load_config` reads the service account from the keyring only when it is given no
    environment of its own, so callers that want the keyring must go through here first.
    """
    for key, value in settings_from_file(dict(os.environ if env is None else env)).items():
        if key.startswith("VW_"):
            os.environ.setdefault(key, value)


def read_collection(collection: str, env: dict[str, str] | None = None) -> dict[str, str]:
    """Every secret of a collection as name -> value.

    The VW_* settings come from the environment and `~/.config/vw/env`; the service account's own
    credentials from the keyring, which `load_config` reads only for the process environment, so
    they are put there first. Values are the Logins' passwords, where the writers put them.
    """
    import dataclasses

    prime_environment(env)
    config = dataclasses.replace(load_config(allow_org_only=True), collection=collection)
    return VwClient(config).read_values()


def load_config(env: dict[str, str] | None = None, allow_org_only: bool = False) -> VwConfig:
    """Read the configuration from the environment.

    Secrets are given as file paths. When the client id, client secret file or
    master password file is not set, the manager's keyring entries client_id,
    client_secret and master_password are used instead (only when env is the
    process environment). allow_org_only lets VW_ORGANIZATION_ID stand
    without VW_COLLECTION (the collection is then chosen per call).
    """
    use_keyring = env is None
    env = os.environ if env is None else env

    def need(var: str) -> str:
        value = env.get(var, "").strip()
        if not value:
            raise VwError(f"{var} is not set")
        return value

    organization_id = env.get("VW_ORGANIZATION_ID", "").strip()
    collection = env.get("VW_COLLECTION", "").strip()
    if bool(organization_id) != bool(collection) and not (allow_org_only and organization_id):
        raise VwError("VW_ORGANIZATION_ID and VW_COLLECTION must be set together")

    server_url = need("VW_URL")
    secret_file = env.get("VW_CLIENT_SECRET_FILE", "").strip()
    password_file = env.get("VW_MASTER_PASSWORD_FILE", "").strip()
    client_id = env.get("VW_CLIENT_ID", "").strip() or (keyring_get("client_id") if use_keyring else "")
    client_secret = "" if secret_file or not use_keyring else keyring_get("client_secret")
    master_password = "" if password_file or not use_keyring else keyring_get("master_password")
    if not client_id:
        raise VwError("VW_CLIENT_ID is not set")
    if not (secret_file or client_secret):
        raise VwError("VW_CLIENT_SECRET_FILE is not set")
    if not (password_file or master_password):
        raise VwError("VW_MASTER_PASSWORD_FILE is not set")

    return VwConfig(
        server_url=server_url,
        client_id=client_id,
        client_secret_file=Path(secret_file),
        master_password_file=Path(password_file),
        client_secret=client_secret,
        master_password=master_password,
        folder=env.get("VW_FOLDER", "").strip() or DEFAULT_FOLDER,
        bw_data_dir=env.get("VW_BW_DATA_DIR", "").strip() or os.path.expanduser(
            f"~/.local/state/vw/bw-{hashlib.sha256(client_id.encode()).hexdigest()[:12]}"),
        organization_id=organization_id,
        collection=collection,
    )


class DataDirLock:
    """One operation at a time on a bw data dir, across processes (flock on vw.lock).

    bw keeps its session and its copy of the vault in data.json there. Another process's
    login, unlock or sync in the same dir replaces what this one's BW_SESSION refers to: its
    next call prints nothing with exit code 0 or fails (2026-11-02: `vw-rm` gave «bw list
    returned invalid JSON» while another process listed the same collection). Reentrant: the
    clients of `_in_collection` share their parent's lock.
    """

    def __init__(self, data_dir: str):
        self._dir = data_dir
        self._fd: int | None = None
        self.depth = 0

    def acquire(self) -> None:
        if self.depth == 0 and self._dir:
            path = Path(self._dir)
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(path / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
            deadline = time.monotonic() + LOCK_WAIT
            while True:
                try:
                    _lock_nowait(fd)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        os.close(fd)
                        raise VwError(f"bw data dir is busy: another vw process has held it for {LOCK_WAIT} s") from None
                    time.sleep(0.2)
            self._fd = fd
        self.depth += 1

    def release(self) -> None:
        self.depth -= 1
        if self.depth == 0 and self._fd is not None:
            _unlock(self._fd)
            self._fd = None


def exclusive(method):
    """A client operation: holds the data dir from unlock to its end.

    The session it unlocked is dropped at the end, because another process may unlock in the
    same dir as soon as the lock is released. A session unlocked outside any operation (a
    caller of `_unlock`) is kept, as before.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        outer = self._lock.depth == 0
        own_session = self._session is None
        self._lock.acquire()
        try:
            return method(self, *args, **kwargs)
        finally:
            self._lock.release()
            if outer and own_session:
                self._session = None
    return wrapper


class VwClient:
    # seconds per bw call; a personal vault with thousands of items needs more (vw-vault)
    timeout = BW_TIMEOUT

    def __init__(self, config: VwConfig | None = None):
        self._cfg = config or load_config()
        self._session: str | None = None
        self._lock = DataDirLock(self._cfg.bw_data_dir)

    def _run(self, args: list[str], stdin: str | None = None,
             extra_env: dict[str, str] | None = None) -> str:
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG") if k in os.environ}
        if self._session:
            env["BW_SESSION"] = self._session
        if self._cfg.bw_data_dir:
            data = Path(self._cfg.bw_data_dir)
            data.mkdir(mode=0o700, parents=True, exist_ok=True)
            env["BITWARDENCLI_APPDATA_DIR"] = str(data)
        env.update(extra_env or {})
        try:
            # Without input, stdin must not be inherited: under MCP stdio it is
            # the protocol pipe.
            proc = subprocess.run(
                [self._cfg.bw, *args], input=stdin,
                stdin=None if stdin is not None else subprocess.DEVNULL,
                capture_output=True, text=True, timeout=self.timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise VwError(f"bw failed to run: {type(exc).__name__}") from None
        if proc.returncode != 0:
            # stdout/stderr are not forwarded: they could echo secret content. The tail of
            # stderr is kept on the client for callers that screen it first (vw-vault).
            self.last_stderr = (proc.stderr or "")[-300:]
            reason = screen_stderr(self.last_stderr)
            raise VwError(f"bw {args[0]} exited with code {proc.returncode}"
                          + (f": {reason}" if reason else ""))
        return proc.stdout

    def _json(self, args: list[str]):
        out = self._run(args)
        if not out.strip():
            # what bw does when its session was replaced by another process in the same data dir
            raise VwError(f"bw {args[0]} returned nothing: its session is no longer valid "
                          "(another bw process using the same data dir?)")
        try:
            return json.loads(out)
        except ValueError:
            raise VwError(f"bw {args[0]} returned invalid JSON") from None

    def _unlock(self) -> None:
        if self._session:
            return
        self._cfg.validate()
        secret = self._cfg.client_secret or self._cfg.client_secret_file.read_text().strip()
        # An already logged-in bw refuses both calls (the session persists in
        # HOME between processes) and exits non-zero; unlock below then decides
        # whether the session is usable.
        try:
            self._run(["config", "server", self._cfg.server_url])
            self._run(["login", "--apikey"], extra_env={
                "BW_CLIENTID": self._cfg.client_id, "BW_CLIENTSECRET": secret})
        except VwError:
            pass
        if self._cfg.master_password:
            session = self._run(["unlock", "--passwordenv", "BW_MASTER_PASSWORD", "--raw"],
                                extra_env={"BW_MASTER_PASSWORD": self._cfg.master_password}).strip()
        else:
            session = self._run(["unlock", "--passwordfile",
                                 str(self._cfg.master_password_file), "--raw"]).strip()
        if not session:
            raise VwError("bw unlock returned no session")
        self._session = session
        # bw answers from its local copy of the vault, refreshed only at login: an account whose
        # data dir outlives one run (a runner, the manager) would otherwise read stale items
        self._run(["sync"])

    def _folder_id(self) -> str:
        folders = self._json(["list", "folders"])
        for f in folders if isinstance(folders, list) else []:
            if isinstance(f, dict) and f.get("name") == self._cfg.folder and f.get("id"):
                return str(f["id"])
        raise VwError("whitelist folder not found")

    def _collection_id(self) -> str:
        collections = self._json(["list", "org-collections",
                                  "--organizationid", self._cfg.organization_id])
        for c in collections if isinstance(collections, list) else []:
            if isinstance(c, dict) and c.get("name") == self._cfg.collection and c.get("id"):
                return str(c["id"])
        raise VwError("organization collection not found")

    def _items(self, scope_id: str) -> list[dict]:
        if self._cfg.use_collection:
            args = ["list", "items", "--organizationid", self._cfg.organization_id,
                    "--collectionid", scope_id]
        else:
            args = ["list", "items", "--folderid", scope_id]
        items = self._json(args)
        if not isinstance(items, list):
            raise VwError("unexpected bw item list")
        items = [i for i in items if isinstance(i, dict)]
        if self._cfg.use_collection:
            # bw ignores --collectionid next to --organizationid and lists the whole organization:
            # without this a write would find and overwrite a same-named item of another collection
            items = [i for i in items if scope_id in (i.get("collectionIds") or [])]
        return items

    def _scope_id(self) -> str:
        return self._collection_id() if self._cfg.use_collection else self._folder_id()

    @property
    def collection(self) -> str:
        """The collection this client writes to ("" in the legacy folder mode)."""
        return self._cfg.collection if self._cfg.use_collection else ""

    @exclusive
    def list_names(self) -> list[str]:
        """Names of the items in the whitelist folder or collection. Never values."""
        self._unlock()
        return sorted(str(i["name"]) for i in self._items(self._scope_id()) if "name" in i)

    @exclusive
    def set_secret(self, name: str, value: str, as_login: bool = False) -> bool:
        """Write an item. Returns True if created, False if an existing one was updated.

        as_login stores a Login whose name is the variable name and whose
        password is the value (what `vw-env` readers expect); otherwise a secure note.
        """
        if not NAME_RE.fullmatch(name):
            raise VwError("invalid secret name")
        if not isinstance(value, str) or not value or len(value) > MAX_VALUE_LEN:
            raise VwError("invalid secret value")
        self._unlock()
        scope_id = self._scope_id()
        existing = next((i for i in self._items(scope_id) if i.get("name") == name), None)
        if existing:
            item = dict(existing)
        else:
            if as_login:
                item = {"type": LOGIN, "name": name, "login": {}}
            else:
                item = {"type": SECURE_NOTE, "name": name, "secureNote": {"type": 0}}
            if self._cfg.use_collection:
                item["organizationId"] = self._cfg.organization_id
                item["collectionIds"] = [scope_id]
            else:
                item["folderId"] = scope_id
        replace_note = bool(existing) and as_login and existing.get("type") != LOGIN
        if replace_note:
            # A note written before the reader wanted a Login (readers that take only a
            # Login's password). Vaultwarden keeps an item's type on edit, so a new Login is created
            # and the note goes to the trash afterwards: the value is never without a copy.
            item = {"type": LOGIN, "name": name, "login": {}}
            if self._cfg.use_collection:
                item["organizationId"] = self._cfg.organization_id
                item["collectionIds"] = [scope_id]
            else:
                item["folderId"] = scope_id
        if as_login:
            item["login"] = {**(item.get("login") or {}), "password": value}
        else:
            item["notes"] = value
        encoded = self._run(["encode"], stdin=json.dumps(item)).strip()
        if not encoded:
            raise VwError("bw encode returned nothing")
        if replace_note:
            self._run(["create", "item"], stdin=encoded)
            self._run(["delete", "item", str(existing["id"])])
            return False
        if existing:
            self._run(["edit", "item", str(existing["id"])], stdin=encoded)
            return False
        self._run(["create", "item"], stdin=encoded)
        return True

    # Organization-level operations. They need VW_ORGANIZATION_ID; the
    # collection is passed per call. None of them returns a value.

    def _org(self) -> str:
        if not self._cfg.organization_id:
            raise VwError("VW_ORGANIZATION_ID is not set")
        return self._cfg.organization_id

    def _in_collection(self, collection: str) -> "VwClient":
        """A client for a collection of the same organization, sharing the unlocked session."""
        self._org()
        self._unlock()
        other = VwClient(dataclasses.replace(self._cfg, collection=collection))
        other._session = self._session
        other._lock = self._lock
        return other

    def _encode(self, obj: dict) -> str:
        encoded = self._run(["encode"], stdin=json.dumps(obj)).strip()
        if not encoded:
            raise VwError("bw encode returned nothing")
        return encoded

    @exclusive
    def list_collections(self) -> list[str]:
        self._unlock()
        found = self._json(["list", "org-collections", "--organizationid", self._org()])
        return sorted(str(c["name"]) for c in found if isinstance(c, dict) and "name" in c)

    @exclusive
    def list_collection_names(self, collection: str) -> list[str]:
        return self._in_collection(collection).list_names()

    @exclusive
    def create_collection(self, collection: str) -> bool:
        """Create a collection. Returns False if it already exists."""
        if not COLLECTION_RE.match(collection):
            raise VwError("invalid collection name")
        if collection in self.list_collections():
            return False
        encoded = self._encode({"organizationId": self._org(), "name": collection,
                                "groups": [], "users": []})
        self._run(["create", "org-collection", "--organizationid", self._org()], stdin=encoded)
        return True

    def _member(self, org: str, account: str) -> dict | None:
        members = self._json(["list", "org-members", "--organizationid", org])
        return next((m for m in members if isinstance(m, dict) and m.get("id")
                     and account.lower() in (str(m.get("email", "")).lower(), str(m["id"]))), None)

    def _api(self, method: str, path: str, body: dict) -> None:
        """A Vaultwarden API call bw has no command for, as this account (its API key)."""
        url = self._cfg.server_url.rstrip("/")
        secret = self._cfg.client_secret or self._cfg.client_secret_file.read_text().strip()
        try:
            token = httpx.post(f"{url}/identity/connect/token", timeout=BW_TIMEOUT,
                               headers={"User-Agent": USER_AGENT}, data={
                "grant_type": "client_credentials", "scope": "api",
                "client_id": self._cfg.client_id, "client_secret": secret,
                "device_type": "25", "device_name": "vw",
                "device_identifier": hashlib.sha256(self._cfg.client_id.encode()).hexdigest()[:32],
            })
            token.raise_for_status()
            resp = httpx.request(method, f"{url}{path}", json=body, timeout=BW_TIMEOUT,
                                 headers={"Authorization": f"Bearer {token.json()['access_token']}",
                                          "User-Agent": USER_AGENT})
            resp.raise_for_status()
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            # the response text is not forwarded: the token request carries the key
            raise VwError(f"Vaultwarden API {path.rsplit('/', 1)[-1]} failed: {type(exc).__name__}") from None

    @exclusive
    def grant_reader(self, collection: str, account: str) -> bool:
        """Give an account read access to a collection. False if already granted.

        An account that is not in the organization yet is invited with that access and
        confirmed: without SMTP Vaultwarden accepts the invitation of an existing account
        itself, so nobody has to click through the web vault.
        """
        org = self._org()
        coll_id = self._in_collection(collection)._collection_id()
        member = self._member(org, account)
        invited = member is None
        if invited:
            if "@" not in account:
                raise VwError("account is not a member of the organization")
            self._api("POST", f"/api/organizations/{org}/users/invite", {
                "emails": [account], "type": MEMBER_USER, "accessAll": False, "groups": [],
                "collections": [{"id": coll_id, "readOnly": True, "hidePasswords": False, "manage": False}]})
            member = self._member(org, account)
            if member is None:
                raise VwError("invited account is not listed in the organization")
        if member.get("status") == MEMBER_INVITED:
            raise VwError("account has not accepted the invitation (no such Vaultwarden account?)")
        if member.get("status") == MEMBER_ACCEPTED:
            self._run(["confirm", "org-member", str(member["id"]), "--organizationid", org])
        current = self._json(["get", "org-collection", coll_id, "--organizationid", org])
        if not isinstance(current, dict):
            raise VwError("unexpected bw collection")
        users = [u for u in current.get("users") or [] if isinstance(u, dict)]
        if any(u.get("id") == member["id"] for u in users):
            return invited
        users.append({"id": member["id"], "readOnly": True, "hidePasswords": False})
        update = {"organizationId": org, "name": current.get("name", collection),
                  "groups": current.get("groups") or [], "users": users}
        self._run(["edit", "org-collection", coll_id, "--organizationid", org],
                  stdin=self._encode(update))
        return True

    @exclusive
    def set_collection_secret(self, collection: str, name: str, value: str) -> bool:
        """Write a Login (name = variable name, password = value) into a collection."""
        return self._in_collection(collection).set_secret(name, value, as_login=True)

    @exclusive
    def secret_exists(self, collection: str, name: str) -> bool:
        """True if the collection already holds an item with this name."""
        client = self._in_collection(collection)
        return any(i.get("name") == name for i in client._items(client._scope_id()))

    @exclusive
    def delete_secret(self, collection: str, name: str) -> bool:
        """Delete a named item from a collection. False if there is none."""
        client = self._in_collection(collection)
        existing = next((i for i in client._items(client._scope_id()) if i.get("name") == name), None)
        if not existing:
            return False
        self._run(["delete", "item", str(existing["id"])])
        return True

    @exclusive
    def read_values(self) -> dict[str, str]:
        """Variable values of the configured collection or folder (vw-env only).

        A Login gives its password, a secure note its notes. Items whose name is
        not a valid variable name or that carry no value are skipped. This is not
        reachable from any MCP tool.
        """
        self._unlock()
        values: dict[str, str] = {}
        for item in self._items(self._scope_id()):
            name = str(item.get("name", ""))
            value = (item.get("login") or {}).get("password") or item.get("notes") or ""
            if NAME_RE.fullmatch(name) and isinstance(value, str) and value:
                values[name] = value
        return values
