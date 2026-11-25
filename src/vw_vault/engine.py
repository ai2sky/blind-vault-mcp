"""The engine: an unlocked personal vault held in the daemon process.

Every public method returns data without values. Mutations go through bw
(edit, soft delete to the trash, restore), each is journaled, and a batch is
refused unless the backup command (VW_VAULT_BACKUP_CMD) succeeds first.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import re
import os
import secrets
import shlex
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path

import httpx
from vw_server.client import VwClient, VwError

from . import checks, dedupe, passkeys
from .rotation import run_module
from .inventory import REDACTED, Fingerprinter, LeakGuard, clean_uri, describe, host_of, secret_values

STATE_DIR = Path(os.environ.get("VW_VAULT_STATE_DIR") or "~/.local/state/vw/vault").expanduser()
BACKUP_MAX_AGE = 15 * 60  # a backup older than this does not count for the next batch


LOGINS_PROOF_REFUSAL = ("the logins check needs the owner's check phrase, typed in their own terminal: "
                        "run `vw-vault check logins`")
LOGINS_AGENT_REFUSAL = ("the logins check is started only by the owner, in their own terminal: "
                        "`vw-vault check logins` (add --dry-run to submit nothing); it is off unless enabled at unlock")


def _now() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


class Engine:
    def __init__(self, client: VwClient, backup_cmd: str = "", api_key: tuple[str, str] | None = None,
                 lan_url: str = "", rotators: list | None = None, public_url: str = ""):
        self._bw = client
        # the server's public origin, for Send links when bw builds them on the loopback proxy
        self.public_url = public_url
        self.rotators = list(rotators or [])
        # opt-in login checks (logins.py); None until the owner enabled them at unlock
        self._owner_proof: tuple[bytes, bytes] | None = None
        self.login_checks = None
        self.login_checks_off = "login checks are off: not set up at unlock"
        # the API key lets the trash take hundreds of items per request; bw needs ~9 s per item
        self._api_key = api_key
        self._lan_url = lan_url
        self._lock = threading.RLock()
        self._fp = Fingerprinter(secrets.token_bytes(32))
        self.backup_cmd = backup_cmd
        self.backup_at = 0.0
        self.job: dict = {"name": None}
        self._plans: dict[str, list[list[str]]] = {}
        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.rotation_file = STATE_DIR / "rotation.json"
        self.journal_file = STATE_DIR / "journal.log"
        self.load()

    # --- state ------------------------------------------------------------------

    def load(self) -> None:
        with self._lock:
            live = self._bw._json(["list", "items"])
            trash = self._bw._json(["list", "items", "--trash"])
            # bw lists archived items only on request; the engine marks them itself
            archived = self._bw._json(["list", "items", "--archived"])
            for item in archived:
                if isinstance(item, dict):
                    item["_archived"] = True
            self.items = {i["id"]: i for i in live + trash + archived if isinstance(i, dict) and i.get("id")}
            self.folders = {f["id"]: f["name"] for f in self._bw._json(["list", "folders"]) if f.get("id")}
            self.orgs = {o["id"]: o["name"] for o in self._bw._json(["list", "organizations"])}
            self.collections = {c["id"]: c["name"] for c in self._bw._json(["list", "collections"])}
            # guard verdicts are recomputed on every load: drop the old ones first
            data = self.rotation()
            for item_id in [i for i, e in data.items()
                            if all(r.startswith("a value sits in the item") for r in e["reasons"])]:
                del data[item_id]
            self._write_rotation(data)
            self.guard = LeakGuard(list(self.items.values()))
            self.meta = {i: describe(raw, self._fp, self.guard, self.folders, self.collections, self.orgs)
                         for i, raw in self.items.items()}
            for item_id, where in self.guard.hits.items():
                self.mark_rotation([item_id], f"a value sits in the item {where}")
            self.loaded_at = _now()

    def _journal(self, action: str, **fields) -> None:
        with self.journal_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"time": _now(), "action": action, **fields}, ensure_ascii=False) + "\n")

    def _short(self, item_id: str) -> dict:
        m = self.meta.get(item_id) or {}
        return {"id": item_id, "name": m.get("name"), "type": m.get("type"), "folder": m.get("folder"),
                "hosts": m.get("hosts"), "revised": (m.get("revised") or "")[:10], "deleted": m.get("deleted")}

    # --- reading ----------------------------------------------------------------

    def summary(self) -> dict:
        live = [m for m in self.meta.values() if not m["deleted"]]
        return {
            "loaded_at": self.loaded_at,
            "items": len(live), "trash": len(self.meta) - len(live),
            "by_type": dict(Counter(m["type"] for m in live).most_common()),
            "personal": sum(1 for m in live if not m["org"]),
            "organization": sum(1 for m in live if m["org"]),
            "folders": dict(Counter(m["folder"] or "(none)" for m in live if not m["org"]).most_common()),
            "collections": dict(Counter(c for m in live for c in m["collections"]).most_common()),
            "with_totp": sum(m["has_totp"] for m in live),
            "with_passkey": sum(m["has_passkey"] for m in live),
            "logins_without_password": sum(1 for m in live if m["type"] == "login" and not m["password_fp"]),
            "logins_without_uri": sum(1 for m in live if m["type"] == "login" and not m["uris"]),
            "rotation": len(self.rotation()),
        }

    def inventory(self, query: str = "", include_deleted: bool = False, offset: int = 0, limit: int = 100) -> dict:
        q = query.lower()
        rows = [m for m in self.meta.values() if (include_deleted or not m["deleted"]) and (
            not q or q in (m["name"] or "").lower() or any(q in h for h in m["hosts"])
            or q in (m["folder"] or "").lower() or q == m["id"] or q in m["token_kinds"])]
        rows.sort(key=lambda m: ((m["name"] or "").lower(), m["revised"] or ""))
        return {"total": len(rows), "offset": offset, "items": rows[offset:offset + limit]}

    def export_inventory(self) -> str:
        """Write the whole inventory (no values) to a JSONL file and return its path."""
        path = STATE_DIR / "inventory.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for m in self.meta.values():
                f.write(json.dumps(m, ensure_ascii=False) + "\n")
        os.chmod(path, 0o600)
        return str(path)

    # --- rotation list ------------------------------------------------------------

    def rotation(self) -> dict:
        try:
            return json.loads(self.rotation_file.read_text())
        except (OSError, ValueError):
            return {}

    def _carry_rotation(self, old: str, new: str) -> None:
        """A copy inherits the rotation reasons of its original."""
        entry = self.rotation().get(old)
        for reason in (entry or {}).get("reasons", []):
            self.mark_rotation([new], reason)

    def _write_rotation(self, data: dict) -> None:
        self.rotation_file.write_text(json.dumps(data, ensure_ascii=False, indent=1))
        os.chmod(self.rotation_file, 0o600)

    def mark_rotation(self, ids: list[str], reason: str) -> int:
        with self._lock:
            data = self.rotation()
            n = 0
            for item_id in ids:
                entry = data.setdefault(item_id, {"name": (self.meta.get(item_id) or {}).get("name") if hasattr(self, "meta") else None,
                                                  "since": _now(), "reasons": []})
                if reason not in entry["reasons"]:
                    entry["reasons"].append(reason)
                    n += 1
            self._write_rotation(data)
            if n:
                self._journal("rotation-mark", ids=ids, reason=reason)
            return n

    def clear_rotation(self, ids: list[str], reason: str) -> int:
        with self._lock:
            data = self.rotation()
            gone = [i for i in ids if data.pop(i, None) is not None]
            self._write_rotation(data)
            self._journal("rotation-clear", ids=gone, reason=reason)
            return len(gone)

    def rotate(self, ids: list[str]) -> dict:
        """Run the rotation module of each item: issue, distribute, verify, revoke the old one.

        A failed step rolls the item back and keeps it on the rotation list with the reason;
        a success takes it off. Needs the unlocked vault (the daemon only exists unlocked).
        """
        with self._lock:
            self._require_backup()
            results = []
            for item_id in ids:
                item = self.items.get(item_id)
                module = next((m for m in self.rotators if item and m.matches(item)), None)
                if not module:
                    res = {"ok": False, "stage": "match", "error": "no rotation module for the item"}
                else:
                    res = run_module(module, item)
                res["id"] = item_id
                self._journal("rotate", **res)
                if res["ok"]:
                    self.clear_rotation([item_id], f"rotated by {res['module']}")
                else:
                    self.mark_rotation([item_id], f"rotation failed at {res['stage']}: {res.get('error')}")
                results.append(res)
            self.load()
            return {"rotated": sum(r["ok"] for r in results), "failed": sum(not r["ok"] for r in results),
                    "results": results}

    def master_value(self, name: str) -> str:
        """The password of the one live login called `name` (for rotation modules; stays inside)."""
        found = [i for i in self.items.values() if i.get("name") == name and i.get("type") == 1
                 and not i.get("deletedDate")]
        if len(found) != 1:
            raise VwError(f"expected one login named {name}, found {len(found)}")
        return (found[0].get("login") or {}).get("password") or ""

    def write_password(self, item: dict, value: str) -> None:
        """Set the password of a login (rotation modules; rotate already checked the backup).

        It edits the latest known version of the item, not the snapshot the caller holds: a
        rotation writes the item, then a failed check writes the old value back, and Vaultwarden
        refuses the second edit when it carries the first one's stale revision date (seen on
        2026-11-18: "rollback failed for: vault item"). The edited item replaces the cached one."""
        with self._lock:
            base = self.items.get(item["id"]) or item
            new = {k: v for k, v in base.items() if not k.startswith("_")}
            new["login"] = {**(base.get("login") or {}), "password": value}
            out = self._bw._run(["edit", "item", item["id"]], stdin=self._bw._encode(new))
            try:
                fresh = json.loads(out) if out else None
            except ValueError:
                fresh = None
            self.items[item["id"]] = {**base, **fresh} if isinstance(fresh, dict) else new

    def rotate_all(self) -> dict:
        """Rotate every item on the rotation list (the leaks list)."""
        return self.rotate(list(self.rotation()))

    # --- backup -------------------------------------------------------------------

    def backup(self) -> dict:
        if not self.backup_cmd:
            raise VwError("VW_VAULT_BACKUP_CMD is not set: no change without a backup")
        proc = subprocess.run(shlex.split(self.backup_cmd), capture_output=True, text=True, timeout=1800)
        ok = proc.returncode == 0
        self._journal("backup", ok=ok, code=proc.returncode)
        if not ok:
            raise VwError(f"backup command failed with code {proc.returncode}")
        self.backup_at = time.time()
        return {"backup": "ok", "at": _now()}

    def _require_backup(self) -> None:
        if time.time() - self.backup_at > BACKUP_MAX_AGE:
            self.backup()

    # --- duplicates -----------------------------------------------------------------

    def dedupe_plan(self) -> dict:
        with self._lock:
            groups = dedupe.exact_groups(list(self.items.values()), self._fp, self._curated(), protect=True)
            plan, skipped = [], []
            for g in groups:
                ids = [i["id"] for i in g]
                try:
                    dedupe.merge(g)
                    plan.append(ids)
                except dedupe.Skip as why:
                    skipped.append({"reason": str(why), "items": [self._short(i) for i in ids]})
            self._plans["exact"] = plan
            similar = dedupe.similar_groups(list(self.items.values()), self._fp, self._curated())
            self._plans["similar"] = [[i["id"] for i in g] for g in similar]
            return {
                "exact_groups": len(plan), "to_trash": sum(len(g) - 1 for g in plan),
                "exact_sample": [{"keep": self._short(g[0]), "trash": [self._short(i) for i in g[1:]]} for g in plan[:20]],
                "skipped": skipped,
                "similar_groups": len(similar),
                "similar": [{"group": n, "items": [{**self._short(i["id"]),
                                                    "password_fp": self.meta[i["id"]]["password_fp"]} for i in g]}
                            for n, g in enumerate(similar)],
            }

    def dedupe_apply(self, limit: int = 0) -> dict:
        """Merge every planned exact group (or the first `limit`): edit the keeper, trash the rest."""
        plan = self._plans.get("exact")
        if plan is None:
            raise VwError("run dedupe_plan first")
        todo = plan[:limit] if limit else plan
        return self._run_job("dedupe", lambda progress: self._apply_groups(todo, progress))

    def _curated(self) -> frozenset:
        """Folders the owner keeps, as opposed to the dumps of an import."""
        imports = ("Import - ", "Imported ", "KeePassXC-Browser ")
        return frozenset(fid for fid, name in self.folders.items() if not name.startswith(imports))

    def _api_auth(self) -> tuple[str, dict]:
        """Base URL and bearer header for a Vaultwarden API call as the owner (API key)."""
        if not self._api_key:
            raise VwError("no API key in the daemon")
        # the LAN address when set: the public one may be a slow tunnel
        url = (os.environ.get("VW_VAULT_LAN_URL") or self._lan_url or self._bw._cfg.server_url).rstrip("/")
        client_id, secret = self._api_key
        try:
            token = httpx.post(f"{url}/identity/connect/token", timeout=60, data={
                "grant_type": "client_credentials", "scope": "api", "client_id": client_id,
                "client_secret": secret, "device_type": "25", "device_name": "vw-vault",
                "device_identifier": hashlib.sha256(client_id.encode()).hexdigest()[:32]})
            token.raise_for_status()
            return url, {"Authorization": f"Bearer {token.json()['access_token']}"}
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            # response text is not forwarded: the token request carries the key
            raise VwError(f"API login failed: {type(exc).__name__}") from None

    def _sync(self) -> None:
        try:
            timeout, self._bw.timeout = self._bw.timeout, 180
            try:
                self._bw._run(["sync"])
            finally:
                self._bw.timeout = timeout
        except VwError:
            self._journal("sync-failed")

    def _soft_delete(self, ids: list[str]) -> None:
        """Move items to the trash: one API request per 200 items, or bw item by item."""
        if not ids:
            return
        if self._api_key:
            url, auth = self._api_auth()
            try:
                for i in range(0, len(ids), 200):
                    httpx.put(f"{url}/api/ciphers/delete", json={"ids": ids[i:i + 200]},
                              headers=auth, timeout=120).raise_for_status()
            except httpx.HTTPError as exc:
                raise VwError(f"trash via API failed: {type(exc).__name__}") from None
            self._journal("trash-api", ids=list(ids))
            self._sync()  # the server already has them in the trash; bw catches up here or on load
        else:
            for item_id in ids:
                self._bw._run(["delete", "item", item_id])
        for item_id in ids:
            self.items[item_id]["deletedDate"] = _now()
            self.meta[item_id]["deleted"] = True

    def _apply_groups(self, groups: list[list[str]], progress) -> dict:
        self._require_backup()
        merged = trashed = 0
        failed, pending = [], []

        def flush() -> None:
            nonlocal trashed
            self._soft_delete(pending)
            self._journal("trash", ids=list(pending), reason="duplicate")
            trashed += len(pending)
            pending.clear()

        for n, ids in enumerate(groups, 1):
            with self._lock:
                group = [self.items[i] for i in ids if i in self.items and not self.items[i].get("deletedDate")]
                if len(group) < 2:
                    continue
                try:
                    keeper = dedupe.merge(group)
                    if dedupe.changed(group[0], keeper):
                        self._bw._run(["edit", "item", keeper["id"]], stdin=self._bw._encode(keeper))
                        self.items[keeper["id"]] = keeper
                    # the rest goes to the trash only after its keeper holds the merged data
                    pending.extend(o["id"] for o in group[1:])
                    merged += 1
                    self._journal("dedupe", keep=keeper["id"], trashed=[o["id"] for o in group[1:]])
                    if len(pending) >= 200:
                        flush()
                except (VwError, dedupe.Skip) as exc:
                    failed.append({"keep": ids[0], "error": str(exc)})
                    self._journal("dedupe-failed", keep=ids[0], error=str(exc))
            progress(n, len(groups))
        with self._lock:
            flush()
        self.load()
        return {"merged_groups": merged, "trashed": trashed, "failed": failed}

    # --- direct edits by id -------------------------------------------------------------

    def trash(self, ids: list[str], reason: str) -> dict:
        with self._lock:
            self._require_backup()
            done = [i for i in ids if i in self.items and not self.items[i].get("deletedDate")]
            self._soft_delete(done)
            self._journal("trash", ids=done, reason=reason)
            return {"trashed": len(done)}

    def restore(self, ids: list[str]) -> dict:
        with self._lock:
            done = []
            for item_id in ids:
                item = self.items.get(item_id)
                if item and item.get("deletedDate"):
                    self._bw._run(["restore", "item", item_id])
                    item["deletedDate"] = None
                    self.meta[item_id]["deleted"] = False
                    done.append(item_id)
            self._journal("restore", ids=done)
            return {"restored": len(done)}

    def unarchive(self, ids: list[str]) -> dict:
        """Take items out of the archive (bw restore works on archive and trash)."""
        with self._lock:
            self._require_backup()
            done = []
            for item_id in ids:
                item = self.items.get(item_id)
                if item and item.get("_archived"):
                    self._bw._run(["restore", "item", item_id])
                    item.pop("_archived", None)
                    self.meta[item_id]["archived"] = False
                    done.append(item_id)
            self._journal("unarchive", ids=done)
            return {"unarchived": len(done)}

    def convert_passkeys(self, ids: list[str]) -> dict:
        """Rebuild KeePassXC passkeys (KPEX_PASSKEY_* fields) as Bitwarden passkeys."""
        with self._lock:
            self._require_backup()
            done, skipped = [], []
            for item_id in ids:
                item = self.items.get(item_id)
                if not item:
                    continue
                try:
                    new = passkeys.converted(item)
                except passkeys.NotConvertible as why:
                    skipped.append({"id": item_id, "reason": str(why)})
                    continue
                payload = {k: v for k, v in new.items() if not k.startswith("_")}
                self._bw._run(["edit", "item", item_id], stdin=self._bw._encode(payload))
                self.items[item_id] = new
                done.append(item_id)
            self._journal("passkey-convert", ids=done, skipped=len(skipped))
            self.load()
            return {"converted": len(done), "skipped": skipped,
                    "passkeys": [self.meta[i]["passkeys"] for i in done]}

    def _collection_id(self, org: str, collection: str) -> str:
        """Id of the organization's collection by name, from the server's list (bw's local
        cache does not know a collection created a moment ago); created when missing."""
        found = self._bw._json(["list", "org-collections", "--organizationid", org])
        match = sorted(c["id"] for c in found if isinstance(c, dict) and c.get("name") == collection)
        if match:
            self.collections.setdefault(match[0], collection)
            return match[0]
        created = json.loads(self._bw._run(["create", "org-collection", "--organizationid", org],
                                           stdin=self._bw._encode({"organizationId": org, "name": collection,
                                                                   "groups": [], "users": []})))
        self.collections[created["id"]] = collection
        self._journal("collection-create", name=collection, organization=self.orgs.get(org))
        return created["id"]

    def dedupe_collections(self, organization: str) -> dict:
        """Delete empty collections whose name another collection of the organization also has."""
        with self._lock:
            self._require_backup()
            org = self._org(organization)
            found = [c for c in self._bw._json(["list", "org-collections", "--organizationid", org])
                     if isinstance(c, dict) and c.get("id")]
            used = {c for i in self.items.values() if not i.get("deletedDate") for c in i.get("collectionIds") or []}
            removed = []
            for name in {c["name"] for c in found}:
                same = sorted((c for c in found if c["name"] == name), key=lambda c: c["id"] in used, reverse=True)
                for extra in same[1:]:
                    if extra["id"] not in used:
                        self._bw._run(["delete", "org-collection", extra["id"], "--organizationid", org])
                        removed.append({"id": extra["id"], "name": name})
            self._journal("collections-dedupe", organization=self.orgs.get(org), removed=removed)
            return {"removed": removed}

    def _bw_error(self, exc: VwError) -> str:
        """bw's own error line, unless it carries a vault value."""
        tail = (getattr(self._bw, "last_stderr", "") or "").strip().splitlines()
        line = tail[-1][:200] if tail else ""
        if line and self.guard_response(line) is None:
            return f"{exc}: {line}"
        return str(exc)

    def _org(self, organization: str) -> str:
        org = next((o for o, n in self.orgs.items() if organization in (o, n)), None)
        if not org:
            raise VwError("no such organization")
        return org

    COPY_KEYS = ("type", "name", "notes", "login", "secureNote", "card", "identity", "sshKey",
                 "fields", "reprompt", "favorite", "passwordHistory")

    def _copy(self, item: dict, org: str, coll: str) -> dict:
        """Create a copy of item in the collection and check it by fingerprint. Raises VwError."""
        if item.get("attachments"):
            raise VwError("has attachments: move it in the web vault")
        new = {k: item[k] for k in self.COPY_KEYS if k in item}
        new.update(organizationId=org, collectionIds=[coll], folderId=None)
        try:
            created = json.loads(self._bw._run(["create", "item"], stdin=self._bw._encode(new)))
        except VwError as exc:
            raise VwError(self._bw_error(exc)) from None
        except ValueError:
            raise VwError("bw create returned no item") from None
        if dedupe.content_fp(created, self._fp) != dedupe.content_fp(item, self._fp):
            raise VwError(f"copy {created.get('id')} differs from the original")
        return created

    def copy_to(self, ids: list[str], collection: str, organization: str) -> dict:
        """Copy items into a collection, each checked by fingerprint. The originals stay."""
        with self._lock:
            self._require_backup()
            org = self._org(organization)
            coll = self._collection_id(org, collection)
            done, failed = [], []
            for item_id in ids:
                item = self.items.get(item_id)
                if not item or item.get("deletedDate"):
                    continue
                try:
                    done.append({"id": item_id, "copy": self._copy(item, org, coll)["id"]})
                    self._carry_rotation(item_id, done[-1]["copy"])
                except VwError as exc:
                    failed.append({"id": item_id, "error": str(exc)})
            self._journal("copy", ids=[d["id"] for d in done], collection=collection,
                          organization=self.orgs.get(org), failed=len(failed))
            self.load()
            return {"copied": done, "failed": failed}

    def compare_keyring(self, item_id: str, attributes: dict[str, str]) -> dict:
        """Does the item's value equal a keyring secret? Both are read inside the daemon; only
        the verdict leaves. No value comes from the caller, so this is no guessing oracle."""
        item = self.items.get(item_id)
        if not item:
            raise VwError("no such item")
        if not attributes or not all(isinstance(k, str) and isinstance(v, str) for k, v in attributes.items()):
            raise VwError("keyring attributes must be strings")
        args = ["secret-tool", "lookup"]
        for k, v in attributes.items():
            args += [k, v]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise VwError("secret-tool failed to run") from None
        if proc.returncode != 0 or not proc.stdout:
            raise VwError("no such keyring entry")
        stored = proc.stdout.rstrip("\n")
        candidates = {"login.password": (item.get("login") or {}).get("password"), "notes": item.get("notes")}
        match = next((where for where, v in candidates.items() if isinstance(v, str) and v.strip() == stored.strip()), None)
        self._journal("compare-keyring", id=item_id, attributes=attributes, match=bool(match))
        return {"match": bool(match), "field": match}

    def drop_kpex_fields(self, ids: list[str]) -> dict:
        """Remove KeePassXC passkey fields (KPEX_PASSKEY_*) from items whose passkey is already
        in Bitwarden's format; items without a Bitwarden passkey keep them."""
        with self._lock:
            self._require_backup()
            done, skipped = [], []
            for item_id in ids:
                item = self.items.get(item_id)
                if not item or not passkeys.kpex_fields(item):
                    continue
                if not (item.get("login") or {}).get("fido2Credentials"):
                    skipped.append({"id": item_id, "reason": "no Bitwarden passkey yet: convert first"})
                    continue
                fields = [f for f in item.get("fields") or []
                          if not (f.get("name") or "").startswith(passkeys.PREFIX)]
                new = {k: v for k, v in item.items() if not k.startswith("_")}
                new["fields"] = fields  # [] clears; bw edit ignores a null and keeps the old fields
                self._bw._run(["edit", "item", item_id], stdin=self._bw._encode(new))
                done.append(item_id)
            self.load()
            still = [i for i in done if passkeys.kpex_fields(self.items[i])]
            done = [i for i in done if i not in still]
            skipped += [{"id": i, "reason": "bw kept the fields"} for i in still]
            self._journal("kpex-drop", ids=done, skipped=len(skipped))
            return {"cleaned": len(done), "skipped": skipped}

    def drop_field(self, item_id: str, field: str) -> dict:
        """Remove a custom field by name (e.g. a dead token kept next to a live one)."""
        with self._lock:
            self._require_backup()
            item = self.items.get(item_id)
            if not item:
                raise VwError("no such item")
            fields = item.get("fields") or []
            kept = [f for f in fields if f.get("name") != field]
            if len(kept) == len(fields):
                raise VwError("no such field on the item")
            new = {k: v for k, v in item.items() if not k.startswith("_")}
            new["fields"] = kept  # [] clears; bw edit ignores a null and keeps the old fields
            self._bw._run(["edit", "item", item_id], stdin=self._bw._encode(new))
            self.load()
            if any(f.get("name") == field for f in self.items[item_id].get("fields") or []):
                raise VwError("bw kept the field: nothing changed")
            self._journal("field-drop", id=item_id, field=field)
            return {"dropped": field}

    def set_from_ansible_vault(self, item_id: str, vault_file: str, variable: str) -> dict:
        """Put an Ansible Vault variable into the item's password. The value is read and written
        inside the daemon; only the fingerprints before and after are returned."""
        with self._lock:
            self._require_backup()
            item = self.items.get(item_id)
            if not item or item.get("type") != 1:
                raise VwError("no such login")
            path = Path(vault_file).expanduser()
            if not path.is_file():
                raise VwError("no such vault file")
            top = subprocess.run(["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
                                 capture_output=True, text=True).stdout.strip() or str(path.parent)
            proc = subprocess.run(["ansible-vault", "view", str(path)], cwd=top, capture_output=True, text=True)
            if proc.returncode != 0:
                raise VwError("ansible-vault view failed (no vault password?)")
            from ruamel.yaml import YAML
            value = (YAML(typ="safe").load(proc.stdout) or {}).get(variable)
            if not isinstance(value, str) or not value:
                raise VwError("no such variable, or not a string")
            before = self._fp((item.get("login") or {}).get("password"))
            new = {k: v for k, v in item.items() if not k.startswith("_")}
            new["login"] = {**(item.get("login") or {}), "password": value}
            self._bw._run(["edit", "item", item_id], stdin=self._bw._encode(new))
            self._journal("set-from-ansible-vault", id=item_id, vault=str(path), variable=variable)
            del value
            self.load()
            return {"updated": item_id, "password_fp_before": before,
                    "password_fp_after": self.meta[item_id]["password_fp"]}

    def export_to_ansible_vault(self, item_id: str, vault_file: str, variable: str, field: str = "password") -> dict:
        """Write an item's value (password, notes or a custom field by name) into a variable of an
        encrypted Ansible Vault file: view, replace or append the line, encrypt, write. The value
        stays in the daemon and the ansible-vault pipes; only fingerprints come back."""
        import json as _json
        with self._lock:
            item = self.items.get(item_id)
            if not item:
                raise VwError("no such item")
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,99}", variable):
                raise VwError("variable must be lower_snake_case")
            fields = {f.get("name"): f.get("value") for f in item.get("fields") or []}
            value = {"password": (item.get("login") or {}).get("password"), "notes": item.get("notes")}.get(
                field, fields.get(field))
            if not isinstance(value, str) or not value:
                raise VwError("the item has no value in that field")
            path = Path(vault_file).expanduser()
            if not path.is_file():
                raise VwError("no such vault file")
            top = subprocess.run(["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
                                 capture_output=True, text=True).stdout.strip() or str(path.parent)
            view = subprocess.run(["ansible-vault", "view", str(path)], cwd=top, capture_output=True, text=True)
            if view.returncode != 0:
                raise VwError("ansible-vault view failed (no vault password?)")
            lines = view.stdout.splitlines()
            line = f"{variable}: {_json.dumps(value)}"
            idx = next((i for i, l in enumerate(lines) if l.startswith(f"{variable}:")), None)
            before = None
            if idx is None:
                lines.append(line)
            else:
                from ruamel.yaml import YAML
                before = self._fp((YAML(typ="safe").load(view.stdout) or {}).get(variable))
                lines[idx] = line
            plain = "\n".join(lines) + "\n"
            from ruamel.yaml import YAML
            if (YAML(typ="safe").load(plain) or {}).get(variable) != value:
                raise VwError("the edited vault would not read back the value; nothing written")
            enc = subprocess.run(["ansible-vault", "encrypt", "--output", "-", "-"], cwd=top, input=plain,
                                 capture_output=True, text=True)
            if enc.returncode != 0 or not enc.stdout.startswith("$ANSIBLE_VAULT"):
                raise VwError("ansible-vault encrypt failed; vault left as is")
            path.write_text(enc.stdout)
            self._journal("export-to-ansible-vault", id=item_id, vault=str(path), variable=variable, field=field)
            after = self._fp(value)
            del value, plain
            return {"variable": variable, "action": "added" if idx is None else "replaced",
                    "fp_before": before, "fp_after": after}

    # --- Sends: hand a value to a person ----------------------------------------------

    SEND_MAX_VIEWS = 5
    SEND_MAX_HOURS = 168

    @staticmethod
    def _item_value(item: dict, field: str):
        """The item's password, notes or a custom field by name (None when it has none)."""
        fields = {f.get("name"): f.get("value") for f in item.get("fields") or []}
        return {"password": (item.get("login") or {}).get("password"), "notes": item.get("notes")}.get(
            field, fields.get(field))

    def _send_url(self, url: str) -> str:
        """The access URL as the recipient can open it. Behind the loopback proxy bw builds the
        link on 127.0.0.1; the public origin replaces it, the path with the key stays."""
        head, sep, tail = url.partition("#/send/")
        if self.public_url and sep:
            return f"{self.public_url.rstrip('/')}/#/send/{tail}"
        return url

    def send(self, item_id: str, field: str = "password", expires_hours: int = 24, max_views: int = 1,
             password: str | None = None, note: str = "") -> dict:
        """Create a text Send (hidden) from an item's value for a person who has no access to the
        vault. The value goes to bw on stdin and nowhere else; the result and the journal never
        carry it. The URL holds the decryption key after `#`: it is returned to the caller and
        not journaled. A Send is not a vault item, so no backup is needed."""
        if isinstance(max_views, bool) or not isinstance(max_views, int) or not 1 <= max_views <= self.SEND_MAX_VIEWS:
            raise VwError(f"max_views must be 1 to {self.SEND_MAX_VIEWS}")
        if isinstance(expires_hours, bool) or not isinstance(expires_hours, int) \
                or not 1 <= expires_hours <= self.SEND_MAX_HOURS:
            raise VwError(f"expires_hours must be 1 to {self.SEND_MAX_HOURS}")
        if password is not None and not (isinstance(password, str) and password):
            raise VwError("the access password is empty")
        with self._lock:
            item = self.items.get(item_id)
            if not item or item.get("deletedDate"):
                raise VwError("no such item")
            value = self._item_value(item, field)
            if not isinstance(value, str) or not value:
                raise VwError("the item has no value in that field")
            when = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=expires_hours)
                    ).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            name = f"{self.meta[item_id]['name'] or 'item'} ({field}), by vw-vault {_now()[:16]}"
            body = {"name": name, "notes": note or None, "type": 0, "text": {"text": value, "hidden": True},
                    "file": None, "maxAccessCount": max_views, "deletionDate": when, "expirationDate": when,
                    "password": password, "emails": None, "disabled": False, "hideEmail": False}
            try:
                created = json.loads(self._bw._run(["send", "create"], stdin=self._bw._encode(body)))
                url, send_id = self._send_url(created["accessUrl"]), created["id"]
            except VwError as exc:
                raise VwError(self._bw_error(exc)) from None
            except (ValueError, KeyError, TypeError):
                raise VwError("bw send create returned no Send") from None
            finally:
                del value, body
            self._journal("send", id=item_id, field=field, send=send_id, expires=when, max_views=max_views,
                          password=bool(password))
            return {"send": send_id, "url": url, "expires": when, "max_views": max_views,
                    "password": bool(password)}

    def send_list(self) -> dict:
        """The owner's Sends: metadata only. bw also lists each URL with its key; it is dropped here."""
        rows = [{"id": s.get("id"), "name": s.get("name"), "expires": s.get("expirationDate"),
                 "deletes": s.get("deletionDate"), "views": s.get("accessCount"),
                 "max_views": s.get("maxAccessCount"), "disabled": bool(s.get("disabled")),
                 "password": bool(s.get("password"))}
                for s in self._bw._json(["send", "list"]) if isinstance(s, dict)]
        return {"sends": rows}

    def send_delete(self, send_id: str) -> dict:
        """Delete a Send so its link stops working. Only a Send the account really has."""
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,63}", send_id or ""):
            raise VwError("bad Send id")
        with self._lock:
            if send_id not in {s["id"] for s in self.send_list()["sends"]}:
                raise VwError("no such Send")
            try:
                self._bw._run(["send", "delete", send_id])
            except VwError as exc:
                raise VwError(self._bw_error(exc)) from None
            self._journal("send-delete", send=send_id)
            return {"deleted": send_id}

    def openrouter_keys(self) -> dict:
        """The account's OpenRouter keys (name, hash prefix, dates, limit, usage; never a key)."""
        module = next((r for r in self.rotators if hasattr(r, "key_rows")), None)
        if module is None:
            raise VwError("the OpenRouter module is off: set VW_VAULT_OPENROUTER_ITEMS at unlock")
        return {"keys": module.key_rows()}

    def collections_plan(self) -> dict:
        """Owner folders (not imports) and what a collection per folder would hold."""
        curated = self._curated()
        rows = []
        for fid in sorted(curated, key=lambda f: self.folders[f]):
            members = [m for i, m in self.meta.items() if self.items[i].get("folderId") == fid
                       and not m["deleted"] and not m["org"]]
            if members:
                rows.append({"folder": self.folders[fid], "items": len(members),
                             "archived": sum(1 for m in members if m.get("archived")),
                             "names": sorted(m["name"] or "" for m in members)})
        orgs = [{"id": o, "name": n} for o, n in self.orgs.items()]
        return {"organizations": orgs, "existing_collections": sorted(set(self.collections.values())),
                "folders": rows}

    def to_collection(self, ids: list[str], collection: str, organization: str) -> dict:
        """Move personal items into an organization collection (created if missing): a copy
        checked by fingerprint, then the original to the trash. bw move fails on this server."""
        with self._lock:
            self._require_backup()
            org = self._org(organization)
            coll = self._collection_id(org, collection)
            moved, failed, originals = [], [], []
            for item_id in ids:
                item = self.items.get(item_id)
                if not item or item.get("organizationId") or item.get("deletedDate") or item.get("_archived"):
                    continue
                try:
                    copy = self._copy(item, org, coll)
                except VwError as exc:
                    failed.append({"id": item_id, "name": self.meta[item_id]["name"], "error": str(exc)})
                    continue
                moved.append({"id": item_id, "copy": copy["id"]})
                originals.append(item_id)
                self._carry_rotation(item_id, copy["id"])
            self._soft_delete(originals)
            self._journal("to-collection", moved=moved, collection=collection,
                          organization=self.orgs.get(org), failed=len(failed))
            self.load()
            return {"moved": len(moved), "failed": failed}

    def folders_plan(self) -> dict:
        """Personal folders with the number of live personal items in each."""
        counts = {fid: 0 for fid in self.folders}
        for item in self.items.values():
            if not item.get("deletedDate") and item.get("folderId") in counts:
                counts[item["folderId"]] += 1
        return {"folders": sorted(({"name": self.folders[f], "items": n} for f, n in counts.items()),
                                  key=lambda r: r["name"])}

    def delete_folders(self, names: list[str]) -> dict:
        """Delete personal folders by name. Their items stay, without a folder (Bitwarden's rule)."""
        with self._lock:
            self._require_backup()
            done = []
            for fid, name in list(self.folders.items()):
                if name in names:
                    self._bw._run(["delete", "folder", fid])
                    del self.folders[fid]
                    done.append(name)
            self._journal("folders-delete", names=done)
            self.load()
            return {"deleted": done}

    def _folder_id(self, name: str) -> str | None:
        if not name:
            return None
        for fid, fname in self.folders.items():
            if fname == name:
                return fid
        created = json.loads(self._bw._run(["create", "folder"], stdin=self._bw._encode({"name": name})))
        self.folders[created["id"]] = name
        self._journal("folder-create", name=name)
        return created["id"]

    def move(self, ids: list[str], folder: str) -> dict:
        """Put items into a personal folder. Folders are per user, so an item in a collection keeps
        its collection and shows in the folder too (no copy). Uses the API's partial update."""
        with self._lock:
            self._require_backup()
            fid = self._folder_id(folder)
            todo = [i for i in ids if i in self.items and self.items[i].get("folderId") != fid]
            if self._api_key:
                url, auth = self._api_auth()
                try:
                    for item_id in todo:
                        httpx.put(f"{url}/api/ciphers/{item_id}/partial", headers=auth, timeout=60,
                                  json={"folderId": fid, "favorite": bool(self.items[item_id].get("favorite"))}
                                  ).raise_for_status()
                except httpx.HTTPError as exc:
                    raise VwError(f"folder change via API failed: {type(exc).__name__}") from None
                self._sync()
            else:
                todo = [i for i in todo if not self.items[i].get("organizationId")]
                for item_id in todo:
                    self._bw._run(["edit", "item", item_id],
                                  stdin=self._bw._encode({**self.items[item_id], "folderId": fid}))
            for item_id in todo:
                self.items[item_id]["folderId"] = fid
                self.meta[item_id]["folder"] = folder or None
            self._journal("move", ids=todo, folder=folder)
            return {"moved": len(todo)}

    def set_uri(self, item_id: str, old: str, new: str) -> dict:
        """Replace one URI of a login (old matched by host or full cleaned URI). URIs are not secret."""
        with self._lock:
            self._require_backup()
            item = self.items.get(item_id)
            if not item or item.get("type") != 1:
                raise VwError("no such login")
            uris = list((item.get("login") or {}).get("uris") or [])
            hit = next((u for u in uris if old in (clean_uri(u.get("uri")), host_of(u.get("uri")))), None)
            if hit is None:
                raise VwError("old URI not found on the item")
            hit["uri"] = new
            item = {**item, "login": {**item["login"], "uris": uris}}
            self._bw._run(["edit", "item", item_id], stdin=self._bw._encode(item))
            self.items[item_id] = item
            self.meta[item_id] = describe(item, self._fp, self.guard, self.folders, self.collections, self.orgs)
            self._journal("set-uri", id=item_id, old=old, new=new)
            return {"updated": item_id}

    def rename(self, item_id: str, new_name: str) -> dict:
        """Rename an item. Nothing else on it changes: login, password, fields and URIs stay as
        they are, and no value is read or returned. Refused when another live item of the same
        organization shares a collection (or both are personal) and already has the name, since
        consumers that map item names to variables could not tell the two apart."""
        new_name = (new_name or "").strip()
        if not new_name:
            raise VwError("the new name is empty")
        with self._lock:
            self._require_backup()
            item = self.items.get(item_id)
            if not item:
                raise VwError("no such item")
            old_name = item.get("name")
            if old_name == new_name:
                raise VwError("the item already has this name")
            mine = set(item.get("collectionIds") or [])
            for other in self.items.values():
                if other["id"] == item_id or other.get("deletedDate") or other.get("name") != new_name:
                    continue
                if other.get("organizationId") != item.get("organizationId"):
                    continue
                if not mine and not (other.get("collectionIds") or []):
                    raise VwError("another personal item already has this name")
                if mine & set(other.get("collectionIds") or []):
                    raise VwError("another item of the same collection already has this name")
            item = {**item, "name": new_name}
            self._bw._run(["edit", "item", item_id], stdin=self._bw._encode(item))
            self.items[item_id] = item
            self.meta[item_id] = describe(item, self._fp, self.guard, self.folders, self.collections, self.orgs)
            self._journal("rename", id=item_id, old=old_name, new=new_name)
            return {"renamed": item_id, "old": old_name, "new": new_name}

    # --- checks -------------------------------------------------------------------------

    def _save(self, name: str, data) -> str:
        path = STATE_DIR / f"check-{name}.json"
        path.write_text(json.dumps({"at": _now(), "result": data}, ensure_ascii=False, indent=1))
        os.chmod(path, 0o600)
        return str(path)

    def check(self, name: str, paths: list[str] | None = None) -> dict:
        items = [i for i in self.items.values() if not i.get("deletedDate")]
        if name == "leaks":
            def run(progress):
                found = checks.leak_scan(items, paths)
                ids = list(found["items"])
                for item_id, files in found["items"].items():
                    self.mark_rotation([item_id], f"value found in local files ({len(files)})")
                rows = [{**self._short(i), "files": found["items"][i]} for i in ids]
                return {"items": len(rows), "scanned": found["scanned"], "file": self._save("leaks", rows)}
        elif name == "hibp":
            def run(progress):
                res = checks.hibp(items, progress)
                if res.ranges and len(res.unchecked) == res.ranges:
                    raise VwError("hibp: every range lookup failed, nothing was checked (network or api.pwnedpasswords.com down?)")
                for item_id, n in res.hits.items():
                    self.mark_rotation([item_id], f"password seen in breaches ({n})")
                rows = sorted(({**self._short(i), "pwned": n} for i, n in res.hits.items()), key=lambda r: -r["pwned"])
                not_checked = [self._short(i) for i in sorted(res.unchecked_ids)]
                out = {"items": len(rows), "ranges": res.ranges, "not_checked": len(not_checked),
                       "not_checked_ranges": len(res.unchecked)}
                out["file"] = self._save("hibp", {"pwned": rows, "not_checked": not_checked})
                return out
        elif name == "urls":
            def run(progress):
                verdicts = checks.urls(items, progress)
                by_state = Counter(v["state"] for v in verdicts.values())
                moved = sum(1 for v in verdicts.values() if v.get("moved"))
                return {"hosts": len(verdicts), "states": dict(by_state), "moved": moved,
                        "file": self._save("urls", verdicts)}
        elif name == "tokens":
            def run(progress):
                rows = [{**self._short(r["id"]), **{k: v for k, v in r.items() if k != "id"}}
                        for r in checks.tokens(items, progress)]
                return {"tokens": len(rows), "alive": sum(1 for r in rows if r.get("alive")),
                        "dead": sum(1 for r in rows if r.get("alive") is False), "file": self._save("tokens", rows)}
        elif name == "twofa":
            def run(progress):
                rows = [{**self._short(r["id"]), **{k: v for k, v in r.items() if k != "id"}}
                        for r in checks.twofa(items)]
                return {"items": len(rows), "file": self._save("twofa", rows)}
        elif name == "logins":
            raise VwError(LOGINS_AGENT_REFUSAL)
        else:
            raise VwError("unknown check: leaks, hibp, urls, tokens, twofa")
        return self._run_job(f"check-{name}", run)

    def set_owner_phrase(self, phrase: str) -> None:
        """The phrase the owner types for each run; only a salted scrypt hash stays in memory."""
        salt = os.urandom(16)
        self._owner_proof = (salt, hashlib.scrypt(phrase.encode(), salt=salt, n=2**14, r=8, p=1))

    def _owner_proof_ok(self, proof: str) -> bool:
        if not self._owner_proof or not proof:
            return False
        salt, digest = self._owner_proof
        return hmac.compare_digest(hashlib.scrypt(proof.encode(), salt=salt, n=2**14, r=8, p=1), digest)

    def check_logins(self, dry_run: bool = False, proof: str = "") -> dict:
        """The owner's own run (vw-vault check logins). Off: says why and opens nothing.

        The socket has no caller identity, so the run needs the phrase the owner set at unlock."""
        module = self.login_checks
        if module is None:
            raise VwError(self.login_checks_off)
        if not self._owner_proof_ok(proof):
            raise VwError(LOGINS_PROOF_REFUSAL)

        def run(progress):
            rows = module.run(list(self.items.values()), dry_run=dry_run, progress=progress)
            by_status = Counter(r["status"] for r in rows)
            return {"sites": len(rows), "statuses": dict(by_status), "dry_run": dry_run,
                    "look_at": [r["site"] for r in rows if r.get("look_at")],
                    "file": self._save("logins", rows)}
        return self._run_job("check-logins", run)

    # --- background jobs ------------------------------------------------------------------

    def _run_job(self, name: str, fn) -> dict:
        if self.job.get("state") == "running":
            raise VwError(f"job {self.job['name']} is still running")
        self.job = {"name": name, "state": "running", "started": _now(), "done": 0, "total": 0}

        def progress(done: int, total: int) -> None:
            self.job.update(done=done, total=total)

        def target():
            try:
                self.job.update(state="done", result=fn(progress), finished=_now())
            except Exception as exc:  # the job reports, the daemon lives on
                msg = str(exc) if isinstance(exc, VwError) else type(exc).__name__
                self.job.update(state="failed", error=msg, finished=_now())

        threading.Thread(target=target, daemon=True).start()
        return {"job": name, "state": "running"}

    def job_status(self) -> dict:
        return dict(self.job)

    def busy(self) -> bool:
        return self.job.get("state") == "running"

    def guard_response(self, text: str) -> str | None:
        """Last line of defence: a response that carries a vault value is withheld."""
        tokens = {t for t in LeakGuard.SPLIT.split(text) if len(t) >= LeakGuard.MIN_LEN}
        hits = tokens & self.guard.values
        if not hits:
            return None
        ids = [i for i, raw in self.items.items() if any(v in hits for _, v in secret_values(raw))]
        self.mark_rotation(ids, "value reached a response of the engine (withheld)")
        return REDACTED
