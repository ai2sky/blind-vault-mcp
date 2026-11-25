"""KeePassXC passkeys (custom fields KPEX_PASSKEY_*) to Bitwarden fido2Credentials.

KeePassXC exports a passkey as plain custom fields; Bitwarden only uses
login.fido2Credentials, so such passkeys do nothing there. The private key is in
the fields, so the passkey can be rebuilt in Bitwarden's format, inside the daemon.
"""

from __future__ import annotations

import base64
import datetime
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

PREFIX = "KPEX_PASSKEY_"


class NotConvertible(Exception):
    """The item holds no usable KeePassXC passkey; the message says why."""


def _b64url_decode(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def kpex_fields(item: dict) -> dict[str, str]:
    return {f["name"][len(PREFIX):]: f.get("value") or "" for f in item.get("fields") or []
            if (f.get("name") or "").startswith(PREFIX)}


def credential(item: dict) -> dict:
    """A Bitwarden fido2Credential built from the item's KPEX fields. Raises NotConvertible."""
    kp = kpex_fields(item)
    for need in ("PRIVATE_KEY_PEM", "CREDENTIAL_ID", "RELYING_PARTY"):
        if not kp.get(need):
            raise NotConvertible(f"field {PREFIX}{need} is missing")
    try:
        key = serialization.load_pem_private_key(kp["PRIVATE_KEY_PEM"].encode(), password=None)
    except (ValueError, TypeError):
        raise NotConvertible("private key is not a readable PEM") from None
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise NotConvertible("only ECDSA P-256 passkeys are supported by Bitwarden")
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    raw_id = _b64url_decode(kp["CREDENTIAL_ID"])
    # Bitwarden keeps a 16-byte id as a GUID and any other length as "b64.<base64url>"
    cred_id = str(uuid.UUID(bytes=raw_id)) if len(raw_id) == 16 else "b64." + _b64url(raw_id)
    username = kp.get("USERNAME") or (item.get("login") or {}).get("username") or ""
    return {
        "credentialId": cred_id,
        "keyType": "public-key",
        "keyAlgorithm": "ECDSA",
        "keyCurve": "P-256",
        "keyValue": _b64url(der),
        "rpId": kp["RELYING_PARTY"],
        "rpName": kp["RELYING_PARTY"],
        "userHandle": kp.get("USER_HANDLE") or None,
        "userName": username,
        "userDisplayName": username,
        "counter": "0",
        "discoverable": "true",
        "creationDate": item.get("creationDate") or datetime.datetime.now(datetime.UTC).isoformat(),
    }


def converted(item: dict) -> dict:
    """The item with the passkey added to login.fido2Credentials (KPEX fields kept as they are)."""
    cred = credential(item)
    login = dict(item.get("login") or {})
    existing = login.get("fido2Credentials") or []
    if any(c.get("credentialId") == cred["credentialId"] for c in existing):
        raise NotConvertible("the passkey is already in Bitwarden format")
    login["fido2Credentials"] = [*existing, cred]
    if not login.get("uris"):
        login["uris"] = [{"uri": f"https://{cred['rpId']}", "match": None}]
    if not login.get("username") and cred["userName"]:
        login["username"] = cred["userName"]
    return {**item, "type": 1, "login": login}
