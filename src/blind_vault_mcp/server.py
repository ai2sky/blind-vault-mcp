"""blind-vault-mcp: one MCP server for an agent that manages Vaultwarden secrets blind.

Three toolsets, chosen with VW_TOOLSETS (comma-separated; default "secrets"):

  secrets  organization collections for services and CI: create a collection, grant a
           service account read access, write a generated or owner-supplied secret, list
           names, delete with the owner's out-of-band approval. (vw_server.server)
  vault    the owner's personal vault through the vw-vault daemon the owner unlocked in their
           own terminal: inventory, duplicates, leak and breach checks, rotation. (vw_vault.server)
  send     vault_send and friends: hand a value to a person as a one-time Bitwarden Send link.
           Off by default because the link itself reaches the agent.

"all" turns on every toolset. No tool in any toolset returns a secret value, and no tool
takes one as an argument: values come from a file, a generator, the owner's terminal or the
daemon's memory.
"""

from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP

from vw_server import server as shared
from vw_vault import server as personal

DEFAULT_TOOLSETS = ("secrets",)
SEND_TOOLS = frozenset({"vault_send", "vault_send_list", "vault_send_delete"})
# The folder mode of the first vw server: vw_set takes the value as an argument, so it would
# put the secret through the chat. It stays in vw-server for old setups, not here.
LEGACY_TOOLS = frozenset({"vw_set", "vw_list"})

INSTRUCTIONS = """\
You manage secrets in Vaultwarden without ever seeing a value. No tool returns one.
- To store a value only the user has, ask them to run `vw-put <collection> <NAME>` in their own
  terminal. Never ask them to paste a secret into the chat.
- To create a new secret, call set_secret with generate=true.
- Deleting asks the owner for a code delivered outside this chat; you cannot answer it yourself.
- If a vault tool says the vault is locked, ask the user to run `vw-vault unlock`.
"""


def parse_toolsets(raw: str | None) -> tuple[str, ...]:
    """The toolsets named in VW_TOOLSETS, in a fixed order; a typo is an error, not silence."""
    names = [n.strip().lower() for n in (raw or "").split(",") if n.strip()]
    if not names:
        return DEFAULT_TOOLSETS
    if "all" in names:
        return ("secrets", "vault", "send")
    unknown = sorted(set(names) - {"secrets", "vault", "send"})
    if unknown:
        raise SystemExit(f"VW_TOOLSETS: unknown toolset(s) {', '.join(unknown)}; "
                         "use secrets, vault, send or all")
    return tuple(t for t in ("secrets", "vault", "send") if t in names)


def selected_tools(toolsets: tuple[str, ...]) -> list:
    """The Tool objects of the chosen toolsets, taken from the two underlying servers."""
    tools = []
    if "secrets" in toolsets:
        tools += [t for t in shared.mcp._tool_manager.list_tools() if t.name not in LEGACY_TOOLS]
    vault_tools = personal.mcp._tool_manager.list_tools()
    if "vault" in toolsets:
        tools += [t for t in vault_tools if t.name not in SEND_TOOLS]
    if "send" in toolsets:
        tools += [t for t in vault_tools if t.name in SEND_TOOLS]
    return tools


def build(toolsets: tuple[str, ...]) -> FastMCP:
    app = FastMCP("blind-vault", instructions=INSTRUCTIONS)
    for tool in selected_tools(toolsets):
        app.add_tool(tool.fn, name=tool.name, description=tool.description, annotations=tool.annotations)
    return app


def main() -> None:
    """Serve over stdio by default; VW_TRANSPORT=streamable-http serves HTTP on VW_HOST:VW_PORT.

    HTTP has no authentication of its own: bind VW_HOST to a private interface only.
    """
    from vw_server.client import prime_environment
    from vw_server.owner_approval import install_vw

    prime_environment()  # VW_* settings from ~/.config/vw/env, under the process environment
    app = build(parse_toolsets(os.environ.get("VW_TOOLSETS")))
    install_vw(app)  # delete_secret asks the owner through this server's own elicitation form
    transport = os.environ.get("VW_TRANSPORT", "stdio")
    if transport == "stdio":
        app.run()
        return
    if transport != "streamable-http":
        raise SystemExit("VW_TRANSPORT must be stdio or streamable-http")
    host = os.environ.get("VW_HOST")
    if not host:
        raise SystemExit("VW_HOST is required for streamable-http")
    app.settings.host = host
    app.settings.port = int(os.environ.get("VW_PORT", "8765"))
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
