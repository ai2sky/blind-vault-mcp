"""vw-approve: the owner's side of an approval, run in a terminal of their own.

A write or deploy tool waits for an approval. The owner gets its description and a six-digit
code through the notification channel; this command lists what is waiting, shows it and takes the code. It never
sees the code anywhere else, so an agent that runs it learns nothing it can use.

    vw-approve            # the only pending request
    vw-approve --deny     # refuse it
"""

import argparse
import asyncio
import getpass
import json
import sys
from pathlib import Path

from .owner_approval import socket_dir


async def _talk(path: Path, line: str) -> dict:
    reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path)), 5)
    writer.write((line + "\n").encode())
    await writer.drain()
    reply = json.loads((await asyncio.wait_for(reader.readline(), 5)).decode())
    writer.close()
    return reply


async def _pending() -> list[tuple[Path, str]]:
    """The live requests: a stale socket of a dead server refuses the connection and is dropped."""
    found = []
    for path in sorted(socket_dir().glob("*.sock")):
        try:
            found.append((path, (await _talk(path, "info"))["summary"]))
        except (OSError, asyncio.TimeoutError, ValueError, KeyError):
            path.unlink(missing_ok=True)
    return found


async def _run(deny: bool) -> int:
    pending = await _pending()
    if not pending:
        print("Nothing is waiting for approval.")
        return 1
    if len(pending) > 1:
        for number, (_, summary) in enumerate(pending, 1):
            print(f"{number}. {summary}")
        try:
            path = pending[int(input("Which one? ")) - 1][0]
        except (ValueError, IndexError):
            print("No such request.")
            return 1
        summary = dict((p, s) for p, s in pending)[path]
    else:
        path, summary = pending[0]
    print(summary)
    if deny:
        await _talk(path, "deny")
        print("Refused.")
        return 0
    for _ in range(3):
        code = getpass.getpass("Code from the notification (empty to refuse): ").strip()
        if not code:
            await _talk(path, "deny")
            print("Refused.")
            return 0
        reply = await _talk(path, f"code {code}")
        if reply.get("result") == "approved":
            print("Approved: this one call goes ahead.")
            return 0
        if reply.get("result") == "closed":
            print("The request is closed (too many wrong codes, a timeout, or already decided).")
            return 1
        print("Wrong code.")
    return 1


def main() -> None:
    parser = argparse.ArgumentParser(description="Answer a pending owner approval of an MCP tool")
    parser.add_argument("--deny", action="store_true", help="refuse instead of entering a code")
    args = parser.parse_args()
    try:
        sys.exit(asyncio.run(_run(args.deny)))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
