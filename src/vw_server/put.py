"""vw-put: the owner writes one secret into a collection from their own terminal.

    vw-put COLLECTION NAME              # hidden prompt, asked twice
    vw-put COLLECTION NAME --file PATH  # the value is the file's content
    vw-put COLLECTION NAME --generate   # a random value

It writes as the manager account (keyring service VW_KEYRING_SERVICE) like the vw MCP tools, journals the
action and notifies the owner; the value is never printed. For values only the owner holds (a
`claude setup-token`, a bot token): the agent asks the owner to run this, the value never passes
through the chat. Settings come from the environment or ~/.config/vw/env (KEY=VALUE lines):
VW_URL, VW_ORGANIZATION_ID, VW_NOTIFY_URL.
"""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

from . import audit
from .client import VwClient, VwError, load_config
from .server import GENERATED_BYTES, _check_name, _read_value_file

ENV_FILE = "~/.config/vw/env"


def load_env_file(path: str = ENV_FILE) -> None:
    """KEY=VALUE lines into the environment; variables already set win."""
    p = Path(path).expanduser()
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())


def read_value(args: argparse.Namespace) -> tuple[str, str]:
    if args.file:
        return _read_value_file(args.file), "file"
    if args.generate:
        return secrets.token_urlsafe(GENERATED_BYTES), "generated"
    first = getpass.getpass(f"{args.name} (hidden): ")
    if getpass.getpass("again: ") != first:
        raise ValueError("the two values differ")
    return first, "typed"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="vw-put", description=__doc__.split("\n\n")[0])
    parser.add_argument("collection")
    parser.add_argument("name")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--file", help="read the value from this file")
    source.add_argument("--generate", action="store_true", help="generate a random value")
    args = parser.parse_args(argv)
    load_env_file()
    try:
        _check_name(args.name)
        value, how = read_value(args)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        sys.exit(f"vw-put: not written: {exc if isinstance(exc, ValueError) else 'cannot read file'}")
    if not value:
        sys.exit("vw-put: not written: empty value")
    action = f"set_secret ({how}, vw-put)"
    try:
        created = VwClient(load_config(allow_org_only=True)).set_collection_secret(
            args.collection, args.name, value)
    except VwError as exc:
        warn = audit.record(action, args.collection, args.name, "failed")
        sys.exit(f"vw-put: not written: {exc}.{warn}")
    warn = audit.record(action, args.collection, args.name, "created" if created else "updated")
    print(f"{args.name} {'created' if created else 'updated'} in '{args.collection}'.{warn}")


if __name__ == "__main__":
    main()
