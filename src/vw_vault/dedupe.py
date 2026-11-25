"""Duplicate detection and merging, done on decrypted items inside the daemon.

Exact duplicates: logins with the same site(s), username and password, or any
other item whose whole secret content is equal. The newest item is kept; URIs,
custom fields, TOTP, notes and password history of the others are merged into
it and the others go to the trash (restorable).

Similar items (same site and username, different passwords) are only reported:
which password is right is the owner's call.
"""

from __future__ import annotations

import copy
from collections import defaultdict

from .inventory import Fingerprinter, content_fp, host_of  # noqa: F401 (content_fp re-exported)


class Skip(Exception):
    """A group that must not be merged automatically; the message says why."""


def _hosts(item: dict) -> tuple[str, ...]:
    uris = (item.get("login") or {}).get("uris") or []
    return tuple(sorted({h for u in uris if (h := host_of(u.get("uri")))}))


def _site(item: dict) -> set[str]:
    return set(_hosts(item)) or {"name:" + (item.get("name") or "").strip().lower()}


def _components(items: list[dict]) -> list[list[dict]]:
    """Items linked when they share a host (or, without URIs, a name)."""
    parent = list(range(len(items)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: dict[str, int] = {}
    for n, item in enumerate(items):
        for site in _site(item):
            if site in owner:
                parent[find(n)] = find(owner[site])
            else:
                owner[site] = n
    groups: dict[int, list[dict]] = defaultdict(list)
    for n, item in enumerate(items):
        groups[find(n)].append(item)
    return list(groups.values())


def _newest_first(items: list[dict], prefer: frozenset = frozenset()) -> list[dict]:
    """Keeper first: an item in a folder the owner keeps (prefer) beats an import copy, then the newest."""
    return sorted(items, key=lambda i: (i.get("folderId") in prefer, i.get("revisionDate") or "",
                                        i.get("creationDate") or ""), reverse=True)


def _eligible(item: dict) -> bool:
    return not item.get("deletedDate") and not item.get("organizationId")  # trash and org items stay


def _protect(group: list[dict], prefer: frozenset) -> list[list[dict]]:
    """Never trash an owner's item: one owner item keeps the import copies; owner items in
    different owner folders stay side by side (their import copies go to the first)."""
    owned = [i for i in group if i.get("folderId") in prefer]
    copies = [i for i in group if i.get("folderId") not in prefer]
    if not owned:
        return [group]
    if not copies:
        return []
    return [[owned[0], *copies]]


def exact_groups(items: list[dict], fp: Fingerprinter, prefer: frozenset = frozenset(),
                 protect: bool = False) -> list[list[dict]]:
    """Logins with the same username and password on an overlapping site; other items with equal content.

    With protect, items in owner folders (prefer) are never in the trashed part of a group.
    Archived items are considered (they may be the owner's copy) but never trashed."""
    buckets: dict[tuple, list[dict]] = defaultdict(list)
    for item in filter(_eligible, items):
        login = item.get("login") or {}
        if item.get("type") == 1 and login.get("password"):
            buckets[("login", fp(login.get("username")), fp(login["password"]))].append(item)
        else:
            buckets[("other", item.get("type"), (item.get("name") or "").strip().lower(),
                     content_fp(item, fp))].append(item)
    out = []
    for key, bucket in buckets.items():
        parts = _components(bucket) if key[0] == "login" else [bucket]
        for g in parts:
            if len(g) < 2:
                continue
            g = _newest_first(g, prefer)
            pieces = _protect(g, prefer) if protect else [g]
            for piece in pieces:
                # an archived item may keep the group, but is never put in the trash
                piece = [piece[0], *[i for i in piece[1:] if not i.get("_archived")]]
                if len(piece) > 1:
                    out.append(piece)
    return out


def similar_groups(items: list[dict], fp: Fingerprinter, prefer: frozenset = frozenset()) -> list[list[dict]]:
    """Same site and username, more than one distinct password."""
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for item in items:
        login = item.get("login") or {}
        if not _eligible(item) or item.get("type") != 1:
            continue
        if login.get("password") and (site := _hosts(item)):
            groups[(site, fp(login.get("username")))].append(item)
    out = []
    for g in groups.values():
        if len({(i.get("login") or {}).get("password") for i in g}) > 1:
            out.append(_newest_first(g, prefer))
    return out


def merge(group: list[dict]) -> dict:
    """The keeper (group[0]) with everything worth keeping from the others. Raises Skip."""
    keeper = copy.deepcopy(group[0])
    others = group[1:]
    for other in others:
        if other.get("attachments"):
            raise Skip("a duplicate has attachments")
        if (other.get("login") or {}).get("fido2Credentials") and not (keeper.get("login") or {}).get("fido2Credentials"):
            raise Skip("a duplicate holds a passkey the kept item lacks")
    login = keeper.get("login")
    if login is not None:
        uris = list(login.get("uris") or [])
        seen = {u.get("uri") for u in uris}
        totps = {o_login.get("totp") for o in group if (o_login := o.get("login") or {}).get("totp")}
        if len(totps) > 1:
            raise Skip("duplicates carry different TOTP secrets")
        for other in others:
            o_login = other.get("login") or {}
            for u in o_login.get("uris") or []:
                if u.get("uri") and u["uri"] not in seen:
                    uris.append(u)
                    seen.add(u["uri"])
            if not login.get("totp") and o_login.get("totp"):
                login["totp"] = o_login["totp"]
        login["uris"] = uris

    fields = list(keeper.get("fields") or [])
    seen_fields = {(f.get("name"), f.get("value"), f.get("type")) for f in fields}
    for other in others:
        for f in other.get("fields") or []:
            key = (f.get("name"), f.get("value"), f.get("type"))
            if key not in seen_fields:
                fields.append(f)
                seen_fields.add(key)
    keeper["fields"] = fields or keeper.get("fields")

    notes = [keeper.get("notes")] if keeper.get("notes") else []
    names = {(keeper.get("name") or "").strip().lower()}
    for other in others:
        text = other.get("notes")
        name = (other.get("name") or "").strip()
        header = f"--- merged from «{name}» ({(other.get('revisionDate') or '')[:10]}) ---"
        if text and text not in notes:
            notes.append(f"{header}\n{text}")
        elif name.lower() not in names:
            notes.append(header)  # keep a differing name findable, e.g. two routers with one password
        names.add(name.lower())
    keeper["notes"] = "\n\n".join(notes) if notes else keeper.get("notes")

    history = list(keeper.get("passwordHistory") or [])
    seen_pw = {h.get("password") for h in history} | {(login or {}).get("password")}
    for other in others:
        for h in other.get("passwordHistory") or []:
            if h.get("password") not in seen_pw:
                history.append(h)
                seen_pw.add(h.get("password"))
    keeper["passwordHistory"] = sorted(history, key=lambda h: h.get("lastUsedDate") or "", reverse=True) or keeper.get("passwordHistory")

    keeper["favorite"] = any(bool(i.get("favorite")) for i in group) or keeper.get("favorite")
    if not keeper.get("folderId"):
        keeper["folderId"] = next((i["folderId"] for i in others if i.get("folderId")), None)
    keeper["reprompt"] = max(int(i.get("reprompt") or 0) for i in group)
    return keeper


def changed(before: dict, after: dict) -> bool:
    keys = ("login", "fields", "notes", "passwordHistory", "favorite", "folderId", "reprompt")
    return any(before.get(k) != after.get(k) for k in keys)
