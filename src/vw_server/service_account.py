"""vw-service-account: the Vaultwarden account an application reads its own secrets with.

    vw-service-account create <name>   # create the account, keys into vault.yml
    vw-service-account create <name> --invited
                                       # the same, for an account grant_reader already invited
    vw-service-account check  <name>   # log in as the service, list the variables it sees
    vw-service-account rotate <name>   # issue a new API key
    vw-service-account import <name> "<item>" <vault_variable>
                                       # an item's password from the collection into vault.yml

An application reads its secrets itself: it logs in to Vaultwarden as its own account
`svc-<name>@<domain>`, which has read access to one collection of the organization and nothing
else. This command creates that account and writes its keys into an Ansible Vault file, so the
first step of the arrangement is not a hand-made account in the web vault.

It writes `vault_<name>_bw_email`, `_bw_password`, `_bw_clientid` and `_bw_clientsecret` — the
names the playbooks expect. The Vaultwarden admin token (needed by `create` only) comes from
`VW_ADMIN_TOKEN`, or from `vault_vaultwarden_admin_token` / `vault_vaultwarden_admin_token_raw`
in the same file. With `create <name> --invited` no admin token is needed: the account is taken
to be invited already, through the vw MCP tool `grant_reader` below.

Access to the collection is granted separately and also not by hand: the vw MCP tool
`grant_reader(collection, "svc-<name>@<domain>")` invites the account to the organization with
read-only access and confirms the invitation itself.

Configuration, from the environment or `~/.config/vw/env`:

- `VW_SERVICE_VAULT_FILE` (or `--vault-file`): the Ansible Vault file to write the keys into.
- `VW_SERVICE_REPO` (or `--repo`): the directory `ansible-vault` runs in, the one holding the
  `ansible.cfg` that knows the vault password. Found by walking up from the vault file when unset.
- `VW_ORG_DOMAIN` (required): the mail domain of the service accounts.
- `VW_ADMIN_URL`, else `VW_URL`: the Vaultwarden API and admin interface.
- `VW_BW_URL`, else `VW_URL`: the URL for the `bw` CLI, which insists on HTTPS (`check`, `import`).

Needs `ansible-vault` and `cryptography`; `check` and `import` also need the `bw` CLI.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ruamel.yaml import YAML, YAMLError

from .put import load_env_file
from .useragent import USER_AGENT

KDF_ITERATIONS = 600_000
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
VAULT_VAR_RE = re.compile(r"^vault_[a-z0-9_]+$")
ADMIN_TOKEN_KEYS = ("vault_vaultwarden_admin_token", "vault_vaultwarden_admin_token_raw")


class ServiceAccountError(Exception):
    """Failure of this command. Messages never contain a password or a key."""


@dataclass(frozen=True)
class Config:
    vault_file: Path
    repo: Path
    org_domain: str
    url: str
    bw_url: str
    ansible_vault: str = "ansible-vault"


def find_repo(vault_file: Path) -> Path:
    """The nearest directory above the vault file that holds an ansible.cfg.

    That is where ansible-vault must run: the config there says how to get the vault password.
    """
    for directory in vault_file.resolve().parents:
        if (directory / "ansible.cfg").is_file():
            return directory
    raise ServiceAccountError(
        f"no ansible.cfg above {vault_file}: pass --repo or set VW_SERVICE_REPO")


def load_config(vault_file: str | None = None, repo: str | None = None,
                environ: dict[str, str] | None = None) -> Config:
    env = os.environ if environ is None else environ
    path = vault_file or env.get("VW_SERVICE_VAULT_FILE")
    if not path:
        raise ServiceAccountError("no vault file: pass --vault-file or set VW_SERVICE_VAULT_FILE")
    url = (env.get("VW_ADMIN_URL") or env.get("VW_URL") or "").rstrip("/")
    if not url:
        raise ServiceAccountError("no Vaultwarden URL: set VW_ADMIN_URL or VW_URL")
    domain = env.get("VW_ORG_DOMAIN")
    if not domain:
        raise ServiceAccountError(
            "no mail domain for service accounts: set VW_ORG_DOMAIN (~/.config/vw/env)")
    chosen_repo = repo or env.get("VW_SERVICE_REPO")
    return Config(
        vault_file=Path(path).expanduser(),
        repo=Path(chosen_repo).expanduser() if chosen_repo else find_repo(Path(path).expanduser()),
        org_domain=domain,
        url=url,
        bw_url=(env.get("VW_BW_URL") or env.get("VW_URL") or url).rstrip("/"),
    )


# --- Ansible Vault: read and write without printing the contents --------------


class VaultFile:
    """The flat `vault_*` variables of one Ansible Vault file.

    This one can read a value back: rotate, check and import log in
    as the account whose password it wrote. It is a command the owner runs, not an MCP tool, so
    no value is ever handed to an agent.
    """

    def __init__(self, config: Config):
        self._cfg = config

    def _run(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run([self._cfg.ansible_vault, *args], cwd=self._cfg.repo,
                              capture_output=True, text=True)

    def read(self) -> str:
        # A new service has no vault.yml yet: empty text, and `set` creates the file. That way
        # create needs no file made by hand for the four variables it writes itself.
        if not self._cfg.vault_file.exists():
            return ""
        proc = self._run(["view", str(self._cfg.vault_file)])
        if proc.returncode != 0:
            raise ServiceAccountError(f"ansible-vault view: {proc.stderr.strip()}")
        return proc.stdout

    @staticmethod
    def get(text: str, key: str) -> str | None:
        try:
            data = YAML(typ="safe").load(text) or {}
        except YAMLError:
            raise ServiceAccountError("vault content is not valid YAML") from None
        value = data.get(key)
        return str(value) if value else None

    def set(self, values: dict[str, str]) -> None:
        """Update or add flat variables (decrypt -> edit -> encrypt -> shred)."""
        text = self.read()
        for key, value in values.items():
            line = f"{key}: {json.dumps(value)}"
            pattern = re.compile(rf"^{re.escape(key)}:.*$", re.M)
            if pattern.search(text):
                text = pattern.sub(lambda _: line, text)
            else:
                text = text.rstrip("\n") + "\n" + line + "\n"

        tmpdir = Path(os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir())
        fd, tmp = tempfile.mkstemp(prefix="vault-", suffix=".yml", dir=tmpdir)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(text)
            proc = self._run(["encrypt", tmp, "--output", str(self._cfg.vault_file)])
            if proc.returncode != 0:
                raise ServiceAccountError(f"ansible-vault encrypt: {proc.stderr.strip()}")
        finally:
            subprocess.run(["shred", "-u", tmp], check=False)

    def check_writable(self) -> None:
        """Check that the vault file can be written BEFORE the account is created.

        `create` generates a master password, registers the account and issues a key, and only
        then writes all of it. If that write fails (no keyring, no password), the account is left
        in Vaultwarden with a password that lived in this process only — nothing can recover it,
        it can only be deleted through the admin interface and made again.
        """
        proc = self._run(["encrypt_string", "probe", "--name", "probe"])
        if proc.returncode != 0:
            err = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "unknown"
            raise ServiceAccountError(
                f"the vault file cannot be written, no account was created: {err}\n"
                f"Check the Ansible Vault password in {self._cfg.repo}.\n"
                "Empty with 'The given address is empty' — the shell cannot reach the keyring:\n"
                "  export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus")


# --- Bitwarden crypto (PBKDF2, EncString type 2) ------------------------------


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def master_key(password: str, email: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), email.lower().encode(), KDF_ITERATIONS, 32)


def master_password_hash(mkey: bytes, password: str) -> str:
    return b64(hashlib.pbkdf2_hmac("sha256", mkey, password.encode(), 1, 32))


def stretch(mkey: bytes) -> tuple[bytes, bytes]:
    # HKDF-Expand with a single block: T(1) = HMAC(prk, info || 0x01)
    enc = hmac.new(mkey, b"enc\x01", hashlib.sha256).digest()
    mac = hmac.new(mkey, b"mac\x01", hashlib.sha256).digest()
    return enc, mac


def enc_string(plain: bytes, enc_key: bytes, mac_key: bytes) -> str:
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def registration_payload(email: str, password: str) -> dict:
    mkey = master_key(password, email)
    s_enc, s_mac = stretch(mkey)
    user_key = secrets.token_bytes(64)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_der = private.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public_der = private.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {
        "email": email,
        "name": email.split("@")[0],
        "masterPasswordHash": master_password_hash(mkey, password),
        "masterPasswordHint": None,
        "key": enc_string(user_key, s_enc, s_mac),
        "kdf": 0,
        "kdfIterations": KDF_ITERATIONS,
        "keys": {
            "publicKey": b64(public_der),
            "encryptedPrivateKey": enc_string(private_der, user_key[:32], user_key[32:]),
        },
    }


def register(cfg: Config, email: str, password: str) -> None:
    """Register an invited account, on old and new Vaultwarden alike.

    Older servers take one POST /identity/accounts/register. Newer ones (seen on 2026.6.0) answer
    it with 404 and register in two steps: send-verification-email, then register/finish with the
    token. Without SMTP the server returns that token in the response body instead of mailing it.
    """
    payload = registration_payload(email, password)
    try:
        http(cfg, "POST", "/identity/accounts/register", json_body=payload)
        return
    except ServiceAccountError as e:
        if "HTTP 404" not in str(e):
            raise
    token = http(cfg, "POST", "/identity/accounts/register/send-verification-email",
                 json_body={"email": email, "name": payload["name"],
                            "receiveMarketingEmails": False})
    if not isinstance(token, str) or not token:
        raise ServiceAccountError(
            "register/send-verification-email returned no token: the server mails it (SMTP is "
            "on), so this account cannot be registered without that e-mail")
    http(cfg, "POST", "/identity/accounts/register/finish", json_body={
        "email": email,
        "emailVerificationToken": token,
        "masterPasswordHash": payload["masterPasswordHash"],
        "masterPasswordHint": None,
        "userSymmetricKey": payload["key"],
        "userAsymmetricKeys": payload["keys"],
        "kdf": payload["kdf"],
        "kdfIterations": payload["kdfIterations"],
    })


# --- HTTP ---------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_no_redirect = urllib.request.build_opener(_NoRedirect)


def http(cfg: Config, method: str, path: str, *, json_body=None, form=None,
         headers=None, raw=False):
    data = None
    hdrs = {"Accept": "application/json", "User-Agent": USER_AGENT, **(headers or {})}
    if json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(cfg.url + path, data=data, headers=hdrs, method=method)
    opener = _no_redirect.open if raw else urllib.request.urlopen
    try:
        with opener(req, timeout=30) as resp:
            body = resp.read().decode()
            if raw:
                return resp, body
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as e:
        if raw and 300 <= e.code < 400:
            # The redirect after signing in to /admin: the cookie is in the response headers
            return e, ""
        detail = e.read().decode(errors="replace")[:300]
        raise ServiceAccountError(f"{method} {path}: HTTP {e.code} {detail}") from None


def admin_invite(cfg: Config, admin_token: str, email: str) -> None:
    # The admin cookie is set with the Secure flag when the domain is https, so send it by hand
    resp, _ = http(cfg, "POST", "/admin", form={"token": admin_token}, raw=True)
    cookies = [c.split(";", 1)[0] for c in resp.headers.get_all("Set-Cookie") or []]
    admin_cookie = next((c for c in cookies if c.startswith("VW_ADMIN=")), None)
    if not admin_cookie:
        raise ServiceAccountError("could not sign in to /admin: wrong admin token?")
    users = http(cfg, "GET", "/admin/users", headers={"Cookie": admin_cookie})
    if any(u.get("email", "").lower() == email for u in users):
        raise ServiceAccountError(
            f"{email} already exists in Vaultwarden (for a new key: rotate)")
    http(cfg, "POST", "/admin/invite", json_body={"email": email},
         headers={"Cookie": admin_cookie})


def login(cfg: Config, email: str, pw_hash: str) -> str:
    token = http(
        cfg, "POST", "/identity/connect/token",
        form={
            "grant_type": "password",
            "username": email,
            "password": pw_hash,
            "scope": "api offline_access",
            "client_id": "cli",
            "deviceType": "8",
            "deviceIdentifier": str(uuid.uuid4()),
            "deviceName": "vw-service-account",
        },
        headers={"Auth-Email": base64.urlsafe_b64encode(email.encode()).decode().rstrip("=")},
    )
    return token["access_token"]


def api_key(cfg: Config, email: str, password: str) -> tuple[str, str]:
    pw_hash = master_password_hash(master_key(password, email), password)
    auth = {"Authorization": f"Bearer {login(cfg, email, pw_hash)}"}
    profile = http(cfg, "GET", "/api/accounts/profile", headers=auth)
    key = http(cfg, "POST", "/api/accounts/api-key",
               json_body={"masterPasswordHash": pw_hash}, headers=auth)
    return f"user.{profile['id']}", key["apiKey"]


# --- Commands -----------------------------------------------------------------


def prefix(name: str) -> str:
    return f"vault_{name}_bw"


def collection_of(name: str) -> str:
    return name.replace("_", "-")


def cmd_create(cfg: Config, name: str, invited: bool = False) -> None:
    """Create the account. With `invited`, it was already invited by vw MCP grant_reader.

    The invitation is what lets an account register while self-registration is closed, and the
    admin interface is only one way to send it. Where the vault file holds the admin token as a
    hash rather than raw, POST /admin answers 401 and the only way through is grant_reader first.
    """
    vault = VaultFile(cfg)
    vault.check_writable()
    text = vault.read()
    if vault.get(text, f"{prefix(name)}_password"):
        raise ServiceAccountError(
            f"{prefix(name)}_password is already in the vault file (for a new key: rotate)")
    admin_token = None
    if not invited:
        admin_token = os.environ.get("VW_ADMIN_TOKEN") or next(
            (v for v in (vault.get(text, k) for k in ADMIN_TOKEN_KEYS) if v), None)
        if not admin_token:
            raise ServiceAccountError(
                "a Vaultwarden admin token is needed: VW_ADMIN_TOKEN or "
                f"{ADMIN_TOKEN_KEYS[0]} in the vault file (raw, not a hash); "
                "or vw MCP grant_reader first, then create <name> --invited")

    collection = collection_of(name)
    email = f"svc-{collection}@{cfg.org_domain}"
    password = secrets.token_urlsafe(32)

    if invited:
        print(f"-> skipping the admin interface: {email} is already invited")
    else:
        print(f"-> inviting {email} through the admin interface at {cfg.url}")
        admin_invite(cfg, admin_token, email)
    print("-> registering the account")
    register(cfg, email, password)
    print("-> issuing an API key")
    client_id, client_secret = api_key(cfg, email, password)

    vault.set({
        f"{prefix(name)}_email": email,
        f"{prefix(name)}_password": password,
        f"{prefix(name)}_clientid": client_id,
        f"{prefix(name)}_clientsecret": client_secret,
    })
    print(f"OK {email} created, keys written to {cfg.vault_file}")
    print(
        "\nNext, and not by hand:\n"
        f'  1. The collection "{collection}" — vw MCP: create_collection, if it is not there yet\n'
        f'  2. Read-only access — vw MCP: grant_reader("{collection}", "{email}")\n'
        "     (it invites the account to the organization and confirms the invitation)\n"
        f"  3. Secrets into the collection — vw-put, then check: vw-service-account check {name}"
    )


def cmd_rotate(cfg: Config, name: str) -> None:
    vault = VaultFile(cfg)
    text = vault.read()
    email = vault.get(text, f"{prefix(name)}_email")
    password = vault.get(text, f"{prefix(name)}_password")
    if not (email and password):
        raise ServiceAccountError(
            f"no {prefix(name)}_email/_password in the vault file (run create first)")
    # Vaultwarden issues a new key through rotate-api-key
    pw_hash = master_password_hash(master_key(password, email), password)
    auth = {"Authorization": f"Bearer {login(cfg, email, pw_hash)}"}
    profile = http(cfg, "GET", "/api/accounts/profile", headers=auth)
    key = http(cfg, "POST", "/api/accounts/rotate-api-key",
               json_body={"masterPasswordHash": pw_hash}, headers=auth)
    vault.set({
        f"{prefix(name)}_clientid": f"user.{profile['id']}",
        f"{prefix(name)}_clientsecret": key["apiKey"],
    })
    print(f"OK a new API key for {email} is in {cfg.vault_file}; "
          "roll it out with the playbook that reads these variables")


def collection_items(cfg: Config, name: str) -> list[dict]:
    """Log in to bw as the service and return the items of its collection."""
    bw = shutil.which("bw")
    if not bw:
        raise ServiceAccountError("the bw CLI is needed")
    vault = VaultFile(cfg)
    text = vault.read()
    creds = {
        "BW_CLIENTID": vault.get(text, f"{prefix(name)}_clientid"),
        "BW_CLIENTSECRET": vault.get(text, f"{prefix(name)}_clientsecret"),
        "BW_PASSWORD": vault.get(text, f"{prefix(name)}_password"),
    }
    if not all(creds.values()):
        raise ServiceAccountError(
            f"no {prefix(name)}_* in the vault file (run create first)")

    appdata = tempfile.mkdtemp(prefix="vw-svc-")
    env = {"PATH": os.environ["PATH"], "HOME": appdata,
           "BITWARDENCLI_APPDATA_DIR": appdata, **creds}

    def run(*args: str, session: str | None = None) -> str:
        cmd = [bw, *args, "--nointeraction"] + (["--session", session] if session else [])
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            raise ServiceAccountError(
                f"bw {args[0]}: {proc.stderr.strip() or proc.stdout.strip()}")
        return proc.stdout.strip()

    try:
        run("config", "server", cfg.bw_url)
        run("login", "--apikey")
        session = run("unlock", "--passwordenv", "BW_PASSWORD", "--raw")
        run("sync", session=session)
        all_cols = json.loads(run("list", "collections", session=session))
        collection = collection_of(name)
        cols = [c for c in all_cols if c["name"] == collection]
        if not cols:
            orgs = [o["name"] for o in json.loads(run("list", "organizations", session=session))]
            raise ServiceAccountError(
                f'the service does not see the collection "{collection}".\n'
                f"  its organizations: {orgs or 'none (invite it and confirm)'}\n"
                f"  collections it reaches: "
                f"{[c['name'] for c in all_cols] or 'none (grant access to the collection)'}")
        items = json.loads(run("list", "items", "--collectionid", cols[0]["id"], session=session))
        run("logout")
        return items
    finally:
        shutil.rmtree(appdata, ignore_errors=True)


def cmd_check(cfg: Config, name: str) -> None:
    items = collection_items(cfg, name)
    env_re = re.compile(r"^[A-Z][A-Z0-9_]*$")
    names = set()
    for item in items:
        if env_re.match(item.get("name", "")) and (item.get("login") or {}).get("password"):
            names.add(item["name"])
        names.update(f["name"] for f in item.get("fields") or []
                     if env_re.match(f.get("name") or ""))
    print(f'OK signing in as the service works, collection "{collection_of(name)}": '
          f"{len(items)} items")
    for n in sorted(names):
        print(f"  {n}")
    if not names:
        print("  (no variables: an item or field name must be SHAPED_LIKE_THIS)")


def cmd_import(cfg: Config, name: str, item_name: str, var: str) -> None:
    """An item's password from the collection into a vault variable (deploy secrets, not the app's)."""
    if not VAULT_VAR_RE.match(var):
        raise ServiceAccountError("the vault variable must look like vault_<what>_<name>")
    matches = [i for i in collection_items(cfg, name) if i.get("name") == item_name]
    if len(matches) != 1:
        raise ServiceAccountError(
            f'items named "{item_name}" in collection "{collection_of(name)}": '
            f"{len(matches)}, exactly one is needed")
    value = (matches[0].get("login") or {}).get("password")
    if not value:
        raise ServiceAccountError(f'the item "{item_name}" has an empty password field')
    VaultFile(cfg).set({var: value})
    print(f'OK "{item_name}" -> {var} in {cfg.vault_file}')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vw-service-account",
        description="The Vaultwarden account an application reads its own secrets with.")
    parser.add_argument("--vault-file", help="Ansible Vault file to write the keys into")
    parser.add_argument("--repo", help="directory ansible-vault runs in (holds ansible.cfg)")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, help_text in (("create", "create the account and write its keys"),
                               ("check", "log in as the service and list the variables"),
                               ("rotate", "issue a new API key")):
        p = sub.add_parser(command, help=help_text)
        p.add_argument("name")
        if command == "create":
            p.add_argument("--invited", action="store_true",
                           help="the account is already invited (vw MCP grant_reader): "
                                "no admin token, no invitation through the admin interface")
    p = sub.add_parser("import", help="an item's password into a vault variable")
    p.add_argument("name")
    p.add_argument("item")
    p.add_argument("variable")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    load_env_file()
    try:
        if not NAME_RE.match(args.name):
            raise ServiceAccountError("service name: lowercase letters, digits and _")
        cfg = load_config(args.vault_file, args.repo)
        if args.command == "import":
            cmd_import(cfg, args.name, args.item, args.variable)
        elif args.command == "create":
            cmd_create(cfg, args.name, args.invited)
        else:
            {"check": cmd_check, "rotate": cmd_rotate}[args.command](cfg, args.name)
    except ServiceAccountError as exc:
        sys.exit(f"vw-service-account: {exc}")


if __name__ == "__main__":
    main()
