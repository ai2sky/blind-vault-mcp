"""vw MCP server: vw_set (owner approval required), vw_list (names only)
and the organization collection tools (list_collections, list_items, create_collection,
grant_reader, set_secret, delete_secret)."""

import asyncio
import os
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import audit, backup
from .client import VwClient, VwError, load_config

mcp = FastMCP("vw")

NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


@dataclass(frozen=True)
class ApprovalRequest:
    """What the owner is asked to approve. Never contains the value."""
    name: str
    overwrite: bool
    collection: str = ""
    tool: str = "vw_set"
    summary: str = ""  # a ready prompt for tools that approve something other than a secret write


ApprovalHook = Callable[[ApprovalRequest], Awaitable[bool]]


async def deny_all(request: ApprovalRequest) -> bool:
    """Default hook: nobody can approve yet, so vw_set never writes.

    MCP elicitation is answered by the client, i.e. the agent itself, so it is
    not owner approval. A hook backed by the owner's button is installed via
    set_approval_hook().
    """
    return False


_approval_hook: ApprovalHook = deny_all


def set_approval_hook(hook: ApprovalHook) -> None:
    global _approval_hook
    _approval_hook = hook


def describe(request: ApprovalRequest) -> str:
    """Prompt text for the owner's approval button."""
    if request.summary:
        return request.summary
    action = "overwrite existing" if request.overwrite else "add new"
    where = f" in collection '{request.collection}'" if request.collection else ""
    return f"{request.tool}: {action} secret '{request.name}'{where}"


def _check_name(name: str) -> None:
    if not NAME_RE.fullmatch(name):
        raise ValueError("invalid secret name: start with a letter or _, then letters, digits or _, up to 64 characters")


@mcp.tool()
async def vw_set(name: str, value: str) -> str:
    """Write a secret into vw. Needs owner approval. Never returns the value."""
    _check_name(name)
    client = VwClient()
    try:
        exists = name in await asyncio.to_thread(client.list_names)
        try:
            approved = await _approval_hook(ApprovalRequest(name, exists)) is True
        except Exception:
            approved = False
        if not approved:
            return "Not written: owner approval was not given."
        await asyncio.to_thread(client.set_secret, name, value)
    except VwError as exc:
        return f"Not written: vw error: {exc}"
    return f"Secret '{name}' written."


@mcp.tool()
async def vw_list() -> list[str]:
    """List secret names stored in vw (never values)."""
    try:
        return await asyncio.to_thread(VwClient().list_names)
    except VwError as exc:
        raise ValueError(f"vw error: {exc}") from None


# Manager tools: organization collections. Writes need no per-call approval but
# are journaled and notified; the value never passes through the model.

MAX_FILE_BYTES = 16384
GENERATED_BYTES = 32


@dataclass(frozen=True)
class DeleteRequest:
    """What the owner is asked to confirm for a deletion."""
    collection: str
    name: str


DeleteHook = Callable[[DeleteRequest], Awaitable[bool]]
PromptHook = Callable[[str, str], Awaitable[str | None]]


async def deny_deletes(request: DeleteRequest) -> bool:
    """Default hook: deleting is never confirmed until the owner's button is installed."""
    return False


async def no_prompt(collection: str, name: str) -> str | None:
    """Default hook: no out-of-band channel to ask the owner for a value."""
    return None


_delete_hook: DeleteHook = deny_deletes
_prompt_hook: PromptHook = no_prompt


def set_delete_hook(hook: DeleteHook) -> None:
    global _delete_hook
    _delete_hook = hook


def set_prompt_hook(hook: PromptHook) -> None:
    """The hook asks the owner (not the agent) for a value and returns it, or None."""
    global _prompt_hook
    _prompt_hook = hook


def _manager() -> VwClient:
    try:
        return VwClient(load_config(allow_org_only=True))
    except VwError as exc:
        raise ValueError(f"vw error: {exc}") from None


async def _managed(action: str, collection: str, name: str, call):
    """Run a client call in a thread, journal and notify, return a value-free message."""
    try:
        result = await asyncio.to_thread(call)
    except VwError as exc:
        warn = await asyncio.to_thread(audit.record, action, collection, name, "failed")
        raise ValueError(f"vw error: {exc}.{warn}") from None
    return result


async def _backup_before(action: str, collection: str, name: str, client: VwClient) -> str:
    """Back up when the secret exists (something would be lost); return the copy id or "".

    Any failure stops the operation: nothing is changed without a backup.
    """
    try:
        exists = await asyncio.to_thread(client.secret_exists, collection, name)
        if not exists:
            return ""
        return await asyncio.to_thread(backup.run_backup)
    except VwError as exc:
        warn = await asyncio.to_thread(audit.record, action, collection, name, "refused: backup failed")
        raise ValueError(f"Not changed: {exc}.{warn}") from None


@mcp.tool()
async def list_collections() -> list[str]:
    """List the organization's collection names."""
    client = _manager()
    return await _managed("list_collections", "", "", client.list_collections)


@mcp.tool()
async def list_items(collection: str) -> list[str]:
    """List secret names in a collection (never values)."""
    client = _manager()
    return await _managed("list_items", collection, "",
                          lambda: client.list_collection_names(collection))


@mcp.tool()
async def create_collection(collection: str) -> str:
    """Create a collection in the organization."""
    client = _manager()
    created = await _managed("create_collection", collection, "",
                             lambda: client.create_collection(collection))
    warn = await asyncio.to_thread(audit.record, "create_collection", collection, "",
                                   "created" if created else "exists")
    return (f"Collection '{collection}' created." if created
            else f"Collection '{collection}' already exists.") + warn


@mcp.tool()
async def grant_reader(collection: str, account: str) -> str:
    """Give an account (email) read access to a collection, inviting it into the organization if needed."""
    client = _manager()
    granted = await _managed("grant_reader", collection, "",
                             lambda: client.grant_reader(collection, account))
    warn = await asyncio.to_thread(audit.record, f"grant_reader {account}", collection, "",
                                   "granted" if granted else "already granted")
    return (f"'{account}' can read '{collection}'." if granted
            else f"'{account}' already could read '{collection}'.") + warn


def _read_value_file(path: str) -> str:
    p = Path(path).expanduser()
    if not p.is_file():
        raise ValueError("file not found")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("file is too large")
    return p.read_text(encoding="utf-8").rstrip("\r\n")


@mcp.tool()
async def set_secret(collection: str, name: str, from_file: str = "",
                     generate: bool = False, prompt: bool = False) -> str:
    """Write a secret into a collection as a Login (name and password).

    Give exactly one source: from_file (path to a file holding the value),
    generate (random value) or prompt (the owner is asked for the value outside
    the chat). The value never appears in the arguments or in the output.
    """
    _check_name(name)
    if bool(from_file) + generate + prompt != 1:
        raise ValueError("give exactly one of from_file, generate, prompt")
    if from_file:
        try:
            value = await asyncio.to_thread(_read_value_file, from_file)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            reason = exc if isinstance(exc, ValueError) else "cannot read file"
            raise ValueError(f"Not written: {reason}") from None
        source = "file"
    elif generate:
        value = secrets.token_urlsafe(GENERATED_BYTES)
        source = "generated"
    else:
        try:
            value = await _prompt_hook(collection, name) or ""
        except Exception:
            value = ""
        source = "prompt"
    if not value:
        return "Not written: no value was provided."
    client = _manager()
    copy = await _backup_before(f"set_secret ({source})", collection, name, client)
    created = await _managed("set_secret", collection, name,
                             lambda: client.set_collection_secret(collection, name, value))
    warn = await asyncio.to_thread(audit.record, f"set_secret ({source})", collection, name,
                                   "created" if created else "updated", copy)
    return f"Secret '{name}' {'created' if created else 'updated'} in '{collection}'.{warn}"


@mcp.tool()
async def delete_secret(collection: str, name: str) -> str:
    """Delete a secret from a collection. Needs the owner's confirmation."""
    _check_name(name)
    try:
        confirmed = await _delete_hook(DeleteRequest(collection, name)) is True
    except Exception:
        confirmed = False
    if not confirmed:
        warn = await asyncio.to_thread(audit.record, "delete_secret", collection, name, "refused")
        return "Not deleted: owner confirmation was not given." + warn
    client = _manager()
    copy = await _backup_before("delete_secret", collection, name, client)
    deleted = await _managed("delete_secret", collection, name,
                             lambda: client.delete_secret(collection, name))
    warn = await asyncio.to_thread(audit.record, "delete_secret", collection, name,
                                   "deleted" if deleted else "not found", copy)
    return (f"Secret '{name}' deleted from '{collection}'." if deleted
            else f"No secret '{name}' in '{collection}'.") + warn


@mcp.tool()
async def restore_info(collection: str, name: str) -> str:
    """Show the backups taken before this secret was overwritten or deleted, and how to roll back.

    Reads the audit journal only; no value is shown or restored by this tool.
    """
    _check_name(name)
    entries = await asyncio.to_thread(audit.backups_for, collection, name)
    if not entries:
        return f"No backup recorded for '{name}' in '{collection}'."
    lines = [f"{e['time']}  {e['action']}  backup: {e['backup']}" for e in entries]
    return "\n".join(lines + [backup.restore_steps(entries[0]["backup"], collection, name)])


def main() -> None:
    """Serve over stdio by default; VW_TRANSPORT=streamable-http serves HTTP.

    There is no authentication: bind VW_HOST to the agents' interface only
    and restrict the port with a firewall.
    """
    from .owner_approval import install_vw

    install_vw(mcp)
    transport = os.environ.get("VW_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run()
        return
    if transport != "streamable-http":
        raise SystemExit("VW_TRANSPORT must be stdio or streamable-http")
    host = os.environ.get("VW_HOST")
    if not host:
        raise SystemExit("VW_HOST is required for streamable-http")
    mcp.settings.host = host
    mcp.settings.port = int(os.environ.get("VW_PORT", "8765"))
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
