"""Item metadata without values.

Everything here turns decrypted bw items into records that are safe to show an
agent: names, types, folders, cleaned URIs, which fields are filled, dates and
fingerprints. A fingerprint is HMAC-SHA256 under a key that lives only in the
daemon process, so equal values look equal inside one unlock but a fingerprint
cannot be brute-forced back into a password.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import urllib.parse

TYPES = {1: "login", 2: "note", 3: "card", 4: "identity", 5: "ssh-key"}
FIELD_TYPES = {0: "text", 1: "hidden", 2: "bool", 3: "linked"}
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]*")
SLUG_NAME = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
# Kind of secret by prefix; the value itself never leaves the daemon
TOKEN_KINDS = [
    ("github_pat_", "github-fine-grained"),
    ("ghp_", "github-classic"),
    ("gho_", "github-oauth"),
    ("ghs_", "github-app"),
    ("glpat-", "gitlab-pat"),
    ("sk-ant-api", "anthropic-api"),
    ("sk-ant-oat", "anthropic-oauth"),
    ("sk-or-", "openrouter"),
    ("sk-proj-", "openai"),
    ("sk-", "openai-like"),
    ("xoxb-", "slack-bot"),
    ("xoxp-", "slack-user"),
    ("AKIA", "aws-access-key"),
    ("eyJ", "jwt"),
    ("-----BEGIN", "pem"),
]
TELEGRAM_TOKEN = re.compile(r"\d{6,12}:[A-Za-z0-9_-]{30,}")
REDACTED = "<redacted: contains a secret>"


class Fingerprinter:
    def __init__(self, key: bytes):
        self._key = key

    def __call__(self, value) -> str | None:
        if value is None or value == "":
            return None
        return hmac.new(self._key, str(value).encode(), hashlib.sha256).hexdigest()[:10]


def token_kind(value) -> str | None:
    if not isinstance(value, str):
        return None
    for prefix, kind in TOKEN_KINDS:
        if value.startswith(prefix):
            return kind
    if TELEGRAM_TOKEN.fullmatch(value):
        return "telegram-bot"
    return None


def clean_uri(uri: str | None) -> str | None:
    """URI without userinfo, query and fragment: tokens hide there."""
    if not uri:
        return None
    parts = urllib.parse.urlsplit(uri)
    if not parts.scheme or not parts.netloc:
        return uri.split("?", 1)[0].split("#", 1)[0]
    try:
        port = f":{parts.port}" if parts.port else ""
    except ValueError:
        port = ""
    return f"{parts.scheme}://{parts.hostname or ''}{port}{parts.path}"


def host_of(uri: str | None) -> str | None:
    if not uri:
        return None
    parts = urllib.parse.urlsplit(uri if "://" in uri else "https://" + uri)
    try:
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    return (host[4:] if host.startswith("www.") else host) or None


def secret_values(item: dict) -> list[tuple[str, str]]:
    """(where, value) for every secret-bearing field of an item. Daemon memory only."""
    out: list[tuple[str, str]] = []
    login = item.get("login") or {}
    for key in ("password", "totp"):
        if login.get(key):
            out.append((f"login.{key}", login[key]))
    for f in item.get("fields") or []:
        if f.get("value") and f.get("type") in (0, 1):
            kind = "field" if f.get("type") == 1 else "text"  # hidden fields are secret by intent
            out.append((f"{kind}:{f.get('name')}", f["value"]))
    if item.get("notes"):
        out.append(("notes", item["notes"]))
        # KEY=value / key: value lines in a note are compared one by one too
        for line in item["notes"].splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*[:=]\s*(.+?)\s*$", line)
            if m:
                out.append((f"notes:{m.group(1)}", m.group(2).strip("'\"")))
    card = item.get("card") or {}
    for key in ("number", "code"):
        if card.get(key):
            out.append((f"card.{key}", card[key]))
    ssh = item.get("sshKey") or {}
    if ssh.get("privateKey"):
        out.append(("ssh.privateKey", ssh["privateKey"]))
    for old in item.get("passwordHistory") or []:
        if old.get("password"):
            out.append(("passwordHistory", old["password"]))
    return out


NOT_SECRET = re.compile(
    r"(https?://\S+|[\w.+-]+@[\w-]+(\.[\w-]+)+|([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?|\d{1,3}(\.\d{1,3}){3}(:\d+)?)",
    re.I)


def looks_secret(where: str, value) -> bool:
    """Is this value a secret worth guarding and searching for?

    Passwords, TOTP, hidden fields, cards, SSH keys and old passwords always are. Text
    fields and KEY=value lines of notes hold domains, e-mails and user handles too, so
    only a recognised token or a random-looking string counts there.
    """
    if not isinstance(value, str) or not value:
        return False
    if not where.startswith(("text:", "notes")):
        return True
    v = value.strip()
    if token_kind(v):
        return True
    if len(v) < 16 or " " in v or NOT_SECRET.fullmatch(v):
        return False
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    return classes >= 3


def content_fp(item: dict, fp: Fingerprinter) -> str:
    """One fingerprint of everything secret in an item (for non-login duplicates)."""
    payload = {
        "type": item.get("type"),
        "login": {k: (item.get("login") or {}).get(k) for k in ("username", "password", "totp")},
        "notes": item.get("notes"),
        "fields": sorted((f.get("name") or "", f.get("value") or "") for f in item.get("fields") or []),
        "card": item.get("card"),
        "identity": item.get("identity"),
        "sshKey": item.get("sshKey"),
    }
    return fp(json.dumps(payload, sort_keys=True, ensure_ascii=False)) or ""


class LeakGuard:
    """Catches a secret value sitting in a field that is shown (name, URI, field name).

    Such text is replaced by REDACTED and the item is reported, so the caller can
    put it on the rotation list.
    """

    MIN_LEN = 8
    PLAIN = re.compile(r"[a-z]{1,12}|[0-9]{1,12}")
    SPLIT = re.compile(r"[\s/?=&:#,;|\"'()\[\]{}<>]+")

    def __init__(self, items: list[dict]):
        self.values: set[str] = set()
        for item in items:
            for where, value in secret_values(item):
                # a lone word or number would match ordinary text (weak, but not a leak signal)
                if (looks_secret(where, value) and len(value) >= self.MIN_LEN
                        and not self.PLAIN.fullmatch(value)):
                    self.values.add(value)
        self.hits: dict[str, str] = {}  # item id -> where

    def clean(self, text: str | None, item: dict, where: str) -> str | None:
        if not text:
            return text
        own = [v for w, v in secret_values(item) if looks_secret(w, v) and len(v) >= self.MIN_LEN]
        if text in self.values or any(v in text for v in own) or any(
                tok in self.values for tok in self.SPLIT.split(text) if len(tok) >= self.MIN_LEN):
            self.hits[item["id"]] = where
            return REDACTED
        return text


def describe(item: dict, fp: Fingerprinter, guard: LeakGuard, folders: dict, collections: dict,
             orgs: dict) -> dict:
    login = item.get("login") or {}
    uris = [guard.clean(clean_uri(u.get("uri")), item, "uri") for u in login.get("uris") or [] if u.get("uri")]
    name = guard.clean(item.get("name"), item, "name")
    values = secret_values(item)
    return {
        "id": item["id"],
        "name": name,
        "type": TYPES.get(item.get("type"), str(item.get("type"))),
        "org": orgs.get(item.get("organizationId")),
        "collections": [collections.get(c, c) for c in item.get("collectionIds") or []],
        "folder": folders.get(item.get("folderId")),
        "favorite": bool(item.get("favorite")),
        "deleted": item.get("deletedDate") is not None,
        "uris": [u for u in uris if u],
        "hosts": sorted({h for u in uris if u and u != REDACTED and (h := host_of(u))}),
        "username_fp": fp(login.get("username")),
        "password_fp": fp(login.get("password")),
        "password_len": len(login["password"]) if login.get("password") else 0,
        "has_totp": bool(login.get("totp")),
        "has_passkey": bool(login.get("fido2Credentials")),
        # passkey metadata only (rpId, algorithm, dates); the key itself stays in the daemon
        "passkeys": [{k: c.get(k) for k in ("rpId", "keyAlgorithm", "keyCurve", "discoverable", "creationDate")}
                     for c in login.get("fido2Credentials") or []],
        "keepassxc_passkey": any((f.get("name") or "").startswith("KPEX_PASSKEY_") for f in item.get("fields") or []),
        "archived": bool(item.get("_archived")),
        "has_notes": bool(item.get("notes")),
        "fields": [{"name": guard.clean(f.get("name"), item, "field name"),
                    "type": FIELD_TYPES.get(f.get("type")),
                    "fp": fp(f.get("value")) if f.get("type") in (0, 1) else None}
                   for f in item.get("fields") or []],
        "attachments": len(item.get("attachments") or []),
        "password_history": len(item.get("passwordHistory") or []),
        "token_kinds": sorted({k for _, v in values if (k := token_kind(v))}),
        "name_style": ("env" if ENV_NAME.fullmatch(item.get("name") or "")
                       else "slug" if SLUG_NAME.fullmatch(item.get("name") or "") else "free"),
        "content_fp": content_fp(item, fp),
        "created": item.get("creationDate"),
        "revised": item.get("revisionDate"),
        "password_revised": login.get("passwordRevisionDate"),
    }
