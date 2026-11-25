"""vw-rm: the owner deletes one secret from a collection, from their own terminal.

    vw-rm COLLECTION NAME          # asks for the name again before deleting
    vw-rm COLLECTION NAME --yes    # for a script that already asked

The pair of `vw-put`. It writes as the manager account, journals the action and notifies
the owner. Deleting is not undone by anything here, so the name is typed twice by default.
"""

from __future__ import annotations

import argparse
import sys

from . import audit
from .client import VwClient, VwError, load_config
from .put import load_env_file
from .server import _check_name


def confirm(collection: str, name: str) -> bool:
    print(f"Deleting secret {name} from collection {collection}. This cannot be undone.")
    try:
        return input("Type the secret name again to confirm: ").strip() == name
    except EOFError:
        return False


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="vw-rm", description=__doc__.split("\n\n")[0])
    parser.add_argument("collection")
    parser.add_argument("name")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation")
    args = parser.parse_args(argv)
    load_env_file()
    try:
        _check_name(args.name)
    except ValueError as exc:
        sys.exit(f"vw-rm: not deleted: {exc}")
    if not args.yes and not confirm(args.collection, args.name):
        sys.exit("vw-rm: not deleted: the name did not match")
    try:
        deleted = VwClient(load_config(allow_org_only=True)).delete_secret(
            args.collection, args.name)
    except VwError as exc:
        warn = audit.record("delete_secret (vw-rm)", args.collection, args.name, "failed")
        sys.exit(f"vw-rm: not deleted: {exc}.{warn}")
    if not deleted:
        print(f"{args.name}: no such secret in '{args.collection}'.")
        return
    warn = audit.record("delete_secret (vw-rm)", args.collection, args.name, "deleted")
    print(f"{args.name} deleted from '{args.collection}'.{warn}")


if __name__ == "__main__":
    main()
