"""vw-vault MCP server: the agent's view of the owner's unlocked personal vault.

Every tool is a request to the vw-vault daemon. No tool returns a value: only names,
cleaned URIs, which fields are filled, dates and fingerprints valid for one unlock.
Changes go to the trash (restorable), are journaled, and need a fresh backup.
"""

from __future__ import annotations

import asyncio
import json

from mcp.server.fastmcp import FastMCP

from . import daemon
from .engine import LOGINS_AGENT_REFUSAL as LOGINS_REFUSAL

mcp = FastMCP("vw-vault")

LOCKED = ("The vault is locked. Ask the owner to run in their own terminal: "
          "vw-vault unlock")


async def _call(cmd: str, **args) -> str:
    try:
        resp = await asyncio.to_thread(daemon.call, cmd, {k: v for k, v in args.items() if v is not None})
    except OSError:
        return LOCKED
    if not resp.get("ok"):
        return f"Error: {resp.get('error')}"
    return json.dumps(resp["result"], ensure_ascii=False)


@mcp.tool()
async def github_app_status(id: str) -> str:
    """The GitHub App of a key item: its installations and the repositories each reaches (no token is kept)."""
    return await _call("github_app_status", id=id)


@mcp.tool()
async def vault_export_to_ansible_vault(id: str, vault_file: str, variable: str, field: str = "password") -> str:
    """Write an item's password, notes or named field into an Ansible Vault variable; fingerprints only."""
    return await _call("export_to_ansible_vault", id=id, vault_file=vault_file, variable=variable, field=field)


@mcp.tool()
async def vault_send(id: str, field: str = "password", expires_hours: int = 24, max_views: int = 1,
                     password: str | None = None, note: str = "") -> str:
    """Share an item's value with a person as a Bitwarden Send (hidden text link). `field` is
    password, notes or a custom field name; the link dies after `expires_hours` (max 168) or
    `max_views` views (max 5); `password` is an optional access password to tell the person
    another way. Returns the access URL (it holds the key: hand it over, do not log it), the Send
    id, expiry and max views. The value itself never comes back."""
    return await _call("send", id=id, field=field, expires_hours=expires_hours, max_views=max_views,
                       password=password, note=note)


@mcp.tool()
async def vault_send_list() -> str:
    """The owner's Sends: id, name, expiry, views so far, view limit, disabled. No links."""
    return await _call("send_list")


@mcp.tool()
async def vault_send_delete(id: str) -> str:
    """Delete a Send by its id: its link stops working at once."""
    return await _call("send_delete", id=id)


@mcp.tool()
async def openrouter_keys() -> str:
    """The OpenRouter API keys of the account (via the provisioning key): name, hash prefix,
    created, disabled, limit, usage. No key values. Answers "which key is the old one"."""
    return await _call("openrouter_keys")


@mcp.tool()
async def vault_status() -> str:
    """Is the personal vault unlocked; the running job."""
    return await _call("status")


@mcp.tool()
async def vault_summary() -> str:
    """Counts by type, folder and collection; TOTP, passkeys, rotation list size."""
    return await _call("summary")


@mcp.tool()
async def vault_inventory(query: str = "", include_deleted: bool = False, offset: int = 0, limit: int = 100) -> str:
    """Items matching a name, host, folder, id or token kind, without values."""
    return await _call("inventory", query=query, include_deleted=include_deleted, offset=offset, limit=limit)


@mcp.tool()
async def vault_export_inventory() -> str:
    """Write the whole inventory (no values) to a local JSONL file; returns its path."""
    return await _call("export_inventory")


@mcp.tool()
async def vault_reload() -> str:
    """Re-read the vault (after the owner changed something in a client)."""
    return await _call("reload")


@mcp.tool()
async def vault_backup() -> str:
    """Run the backup command now (changes run it themselves when the last one is older than 15 min)."""
    return await _call("backup")


@mcp.tool()
async def dedupe_plan() -> str:
    """Exact duplicate groups to merge, groups skipped and why, and similar groups (same site
    and username, different passwords) that need the owner's decision."""
    return await _call("dedupe_plan")


@mcp.tool()
async def dedupe_apply(limit: int = 0) -> str:
    """Merge the planned exact duplicates (all, or the first `limit` groups) in the background:
    the newest item keeps URIs, fields, TOTP, notes and history of the rest, which go to the trash."""
    return await _call("dedupe_apply", limit=limit)


@mcp.tool()
async def vault_trash(ids: list[str], reason: str) -> str:
    """Move items to the trash (restorable). Use after the owner agreed."""
    return await _call("trash", ids=ids, reason=reason)


@mcp.tool()
async def vault_restore(ids: list[str]) -> str:
    """Restore items from the trash."""
    return await _call("restore", ids=ids)


@mcp.tool()
async def vault_move(ids: list[str], folder: str) -> str:
    """Move personal items into a folder (created if missing; empty name = no folder)."""
    return await _call("move", ids=ids, folder=folder)


@mcp.tool()
async def vault_set_uri(id: str, old: str, new: str) -> str:
    """Replace one URI of a login; `old` is its host or cleaned URI. URIs are not secret."""
    return await _call("set_uri", id=id, old=old, new=new)


@mcp.tool()
async def vault_rename(id: str, name: str) -> str:
    """Rename an item by id. Only the name changes; the login, password and fields stay untouched and no value is returned."""
    return await _call("rename", id=id, name=name)


@mcp.tool()
async def vault_convert_passkeys(ids: list[str]) -> str:
    """Rebuild KeePassXC passkeys (KPEX_PASSKEY_* fields) as Bitwarden passkeys; the fields stay."""
    return await _call("convert_passkeys", ids=ids)


@mcp.tool()
async def vault_compare_keyring(id: str, attributes: dict[str, str]) -> str:
    """Whether an item's password or note equals a keyring secret (secret-tool attributes); verdict only."""
    return await _call("compare_keyring", id=id, attributes=attributes)


@mcp.tool()
async def folders_plan() -> str:
    """Personal folders with their item counts."""
    return await _call("folders_plan")


@mcp.tool()
async def vault_delete_folders(names: list[str]) -> str:
    """Delete personal folders by name; their items stay, without a folder."""
    return await _call("delete_folders", names=names)


@mcp.tool()
async def vault_dedupe_collections(organization: str) -> str:
    """Delete empty collections that share a name with another collection of the organization."""
    return await _call("dedupe_collections", organization=organization)


@mcp.tool()
async def vault_copy_to(ids: list[str], collection: str, organization: str) -> str:
    """Copy items into a collection of an organization, checked by fingerprint; originals stay."""
    return await _call("copy_to", ids=ids, collection=collection, organization=organization)


@mcp.tool()
async def vault_drop_field(id: str, field: str) -> str:
    """Remove a custom field of an item by name (e.g. a dead token kept next to a live one)."""
    return await _call("drop_field", id=id, field=field)


@mcp.tool()
async def vault_set_from_ansible_vault(id: str, vault_file: str, variable: str) -> str:
    """Put an Ansible Vault variable into a login's password, inside the daemon; returns fingerprints only."""
    return await _call("set_from_ansible_vault", id=id, vault_file=vault_file, variable=variable)


@mcp.tool()
async def vault_drop_kpex_fields(ids: list[str]) -> str:
    """Remove KeePassXC passkey fields from items whose passkey is already in Bitwarden's format."""
    return await _call("drop_kpex_fields", ids=ids)


@mcp.tool()
async def vault_unarchive(ids: list[str]) -> str:
    """Take items out of the archive."""
    return await _call("unarchive", ids=ids)


@mcp.tool()
async def collections_plan() -> str:
    """Owner folders (not imports) with their items, as candidates for one collection each."""
    return await _call("collections_plan")


@mcp.tool()
async def vault_to_collection(ids: list[str], collection: str, organization: str) -> str:
    """Move personal items into an organization collection (created if missing). After the owner agreed."""
    return await _call("to_collection", ids=ids, collection=collection, organization=organization)


@mcp.tool()
async def vault_check(name: str, paths: list[str] | None = None) -> str:
    """Start a check in the background: leaks (values in local files such as agent transcripts),
    hibp (breached passwords, k-anonymity), urls (site alive, moved), tokens (API tokens alive),
    twofa (site offers 2FA, item has none). Leaks and breaches go on the rotation list.
    "logins" is not available here: only the owner starts it in their terminal (vw-vault check logins)."""
    if name == "logins":
        return f"Error: {LOGINS_REFUSAL}"
    return await _call("check", name=name, paths=paths)


@mcp.tool()
async def vault_job() -> str:
    """Progress or result of the background job; results point to a JSON file without values."""
    return await _call("job_status")


@mcp.tool()
async def rotation_list() -> str:
    """Items to rotate, with reasons."""
    return await _call("rotation_list")


@mcp.tool()
async def rotation_mark(ids: list[str], reason: str) -> str:
    """Put items on the rotation list (e.g. a value was shown somewhere)."""
    return await _call("rotation_mark", ids=ids, reason=reason)


@mcp.tool()
async def rotation_clear(ids: list[str], reason: str = "rotated") -> str:
    """Take items off the rotation list once the owner rotated them."""
    return await _call("rotation_clear", ids=ids, reason=reason)


@mcp.tool()
async def rotate(ids: list[str]) -> str:
    """Rotate the items with their rotation modules (issue, distribute, verify, revoke the old
    secret; rolled back on a failed check). Values stay in the daemon."""
    return await _call("rotate", ids=ids)


@mcp.tool()
async def rotate_all() -> str:
    """Rotate everything on the rotation list (the leaks list)."""
    return await _call("rotate_all")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
