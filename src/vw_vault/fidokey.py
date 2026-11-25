"""Unlock with a FIDO2 security key instead of typing the master password.

The master password is encrypted on disk with a key that only a registered
security key gives out, through the WebAuthn PRF (hmac-secret) extension, and
only after the owner's PIN and a touch. Each registered key keeps its own copy
of the ciphertext, so any one of them unlocks. Nobody, an agent included, can
decrypt the file without the physical key, its PIN and a touch.

File: ~/.local/state/vw/vault/fido-unlock.json (mode 0600), entries of
{credential_id, salt, nonce, ciphertext, label}. Typing the password still works.
"""

from __future__ import annotations

import getpass
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RP_ID = "vw-vault.local"
ORIGIN = f"https://{RP_ID}"
INFO = b"vw-vault master password v1"


class FidoError(Exception):
    """No key, a wrong PIN, a timeout or a broken file; the message says which."""


def _b64(data: bytes) -> str:
    from fido2.utils import websafe_encode
    return websafe_encode(data)


def _unb64(text: str) -> bytes:
    from fido2.utils import websafe_decode
    return websafe_decode(text)


class _Prompt:
    """PIN by getpass, touch by a line on the terminal."""

    def __init__(self, label: str):
        self.label = label

    def prompt_up(self) -> None:
        print(f"touch the security key ({self.label}) ...", flush=True)

    def request_pin(self, permissions, rp_id) -> str:
        return getpass.getpass(f"PIN of the security key ({self.label}): ")

    def request_uv(self, permissions, rp_id) -> bool:
        return True


def _devices() -> list:
    from fido2.hid import CtapHidDevice
    found = list(CtapHidDevice.list_devices())
    try:
        from fido2.pcsc import CtapPcscDevice  # NFC over a smart card reader, if pyscard is there
        found += list(CtapPcscDevice.list_devices())
    except Exception:
        pass
    return found


def _client(device):
    from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction

    label = getattr(getattr(device, "descriptor", None), "product_name", None) or "key"

    class Interaction(_Prompt, UserInteraction):
        pass

    # a local, non-web relying party: the origin check is ours to waive
    collector = DefaultClientDataCollector(ORIGIN, verify=lambda rp_id, origin: rp_id == RP_ID)
    return Fido2Client(device, client_data_collector=collector, user_interaction=Interaction(label)), label


def _aead_key(prf_output: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(prf_output)


def _prf(client, credential_id: bytes, salt: bytes) -> bytes:
    from fido2.webauthn import (PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions,
                                PublicKeyCredentialType, UserVerificationRequirement)
    result = client.get_assertion(PublicKeyCredentialRequestOptions(
        challenge=secrets.token_bytes(32), rp_id=RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=credential_id)],
        user_verification=UserVerificationRequirement.REQUIRED,
        extensions={"prf": {"eval": {"first": salt}}},
    )).get_response(0)
    prf = (result.client_extension_results or {}).get("prf") or {}
    first = (prf.get("results") or {}).get("first")
    if not first:
        raise FidoError("the key gave no PRF output (no hmac-secret support?)")
    return first if isinstance(first, bytes) else _unb64(first)


def enroll(path: Path, password: str) -> str:
    """Register the connected key and store the password encrypted for it. Returns its label."""
    from fido2.webauthn import (AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions,
                                PublicKeyCredentialParameters, PublicKeyCredentialRpEntity,
                                PublicKeyCredentialType, PublicKeyCredentialUserEntity,
                                ResidentKeyRequirement, UserVerificationRequirement)
    devices = _devices()
    if not devices:
        raise FidoError("no security key found: plug it in (or hold it to the NFC reader)")
    client, label = _client(devices[0])
    try:
        made = client.make_credential(PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id=RP_ID, name="vw-vault"),
            user=PublicKeyCredentialUserEntity(id=secrets.token_bytes(16), name="vw-vault"),
            challenge=secrets.token_bytes(32),
            pub_key_cred_params=[PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7)],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.REQUIRED),
            extensions={"prf": {}},
        ))
        cred_id = made.raw_id
        salt = secrets.token_bytes(32)
        key = _aead_key(_prf(client, cred_id, salt))
    except FidoError:
        raise
    except Exception as exc:  # PIN errors, timeouts, unsupported keys
        raise FidoError(f"the key refused: {type(exc).__name__}") from None
    nonce = secrets.token_bytes(12)
    entry = {"credential_id": _b64(cred_id), "salt": _b64(salt), "nonce": _b64(nonce),
             "ciphertext": _b64(AESGCM(key).encrypt(nonce, password.encode(), INFO)), "label": label}
    entries = [e for e in load(path) if e.get("credential_id") != entry["credential_id"]] + [entry]
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_suffix(".tmp")
    tmp.touch(mode=0o600)
    tmp.write_text(json.dumps(entries, indent=1))
    os.replace(tmp, path)
    return label


def load(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def unlock_password(path: Path) -> str:
    """The master password, decrypted with whichever registered key is connected.

    One assertion lists every registered credential with its own PRF salt, so the owner
    gives the PIN and a touch once, whichever key it is."""
    from fido2.webauthn import (PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions,
                                PublicKeyCredentialType, UserVerificationRequirement)
    entries = load(path)
    if not entries:
        raise FidoError("no key is registered (vw-vault unlock --enroll)")
    devices = _devices()
    if not devices:
        raise FidoError("no security key found: plug it in")
    by_id = {entry["credential_id"]: entry for entry in entries}
    last = "no registered key answered"
    for device in devices:
        client, label = _client(device)
        try:
            response = client.get_assertion(PublicKeyCredentialRequestOptions(
                challenge=secrets.token_bytes(32), rp_id=RP_ID,
                allow_credentials=[PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY,
                                                                 id=_unb64(c)) for c in by_id],
                user_verification=UserVerificationRequirement.REQUIRED,
                extensions={"prf": {"evalByCredential": {c: {"first": _unb64(e["salt"])}
                                                         for c, e in by_id.items()}}},
            )).get_response(0)
            entry = by_id[_b64(response.raw_id)]
            prf = (response.client_extension_results or {}).get("prf") or {}
            first = (prf.get("results") or {}).get("first")
            if not first:
                raise FidoError("the key gave no PRF output")
            key = _aead_key(first if isinstance(first, bytes) else _unb64(first))
            return AESGCM(key).decrypt(_unb64(entry["nonce"]), _unb64(entry["ciphertext"]), INFO).decode()
        except FidoError as exc:
            last = f"{label}: {exc}"
        except Exception as exc:  # not a registered key, a wrong PIN, a timeout
            last = f"{label}: {type(exc).__name__}"
    raise FidoError(last)
