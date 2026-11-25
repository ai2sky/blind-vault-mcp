"""The User-Agent every HTTP client here sends to Vaultwarden.

Cloudflare in front of the vault answers Error 1010 (403) to the default `Python-urllib/3.x`
signature, on `/admin` and on `/identity/accounts/register`. A named agent is not blocked.
"""

from __future__ import annotations

from importlib import metadata


def _version() -> str:
    try:
        return metadata.version("blind-vault-mcp")
    except metadata.PackageNotFoundError:  # run from a source tree that was never installed
        return "dev"


USER_AGENT = f"blind-vault-mcp/{_version()}"
