"""Journal and owner notifications for vw manager actions.

Every manager action is appended to a JSON-lines journal and sent to the owner
as a notification through a webhook. Records carry the action, the collection, the
secret name and the outcome, never a value. A change that lost data also
carries the identifier of the backup taken before it.
"""

import json
import os
import time
from pathlib import Path

import httpx

from .client import keyring_get, keyring_service, settings_from_file

NOTIFY_TIMEOUT = 10
DEFAULT_LOG = "~/.local/state/vw/audit.log"


def journal_path() -> Path:
    return Path(os.environ.get("VW_AUDIT_LOG") or DEFAULT_LOG).expanduser()


def write_journal(entry: dict) -> None:
    path = journal_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def notify(text: str) -> None:
    """Send a notification. VW_NOTIFY_URL is any endpoint taking JSON {"text": ...}
    (a Slack or Mattermost incoming webhook, or a bridge to a messenger).

    The bearer token is the file VW_NOTIFY_TOKEN_FILE, or else the
    manager's keyring entry notify_token. Raises on any failure.
    """
    settings = settings_from_file(dict(os.environ))  # the process env, then ~/.config/vw/env
    url = settings.get("VW_NOTIFY_URL", "").strip()
    if not url:
        raise RuntimeError("VW_NOTIFY_URL is not set")
    token_file = settings.get("VW_NOTIFY_TOKEN_FILE", "").strip()
    token = Path(token_file).read_text().strip() if token_file else keyring_get("notify_token")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    httpx.post(url, json={"text": text, "source": keyring_service()},
               headers=headers, timeout=NOTIFY_TIMEOUT).raise_for_status()


def backups_for(collection: str, name: str, limit: int = 5) -> list[dict]:
    """The latest journal entries with a backup id for this secret, newest first."""
    try:
        lines = journal_path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    found = []
    for line in reversed(lines):
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("backup") and e.get("collection") == collection and e.get("name") == name:
            found.append(e)
            if len(found) == limit:
                break
    return found


def record(action: str, collection: str = "", name: str = "", outcome: str = "ok",
           backup: str = "") -> str:
    """Journal an action and notify the owner.

    Returns "" or a warning to append to the tool output. A failed journal or
    notification never undoes the action.
    """
    entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "action": action,
             "collection": collection, "name": name, "outcome": outcome}
    if backup:
        entry["backup"] = backup
    warnings = []
    try:
        write_journal(entry)
    except OSError:
        warnings.append("journal write failed")
    target = " ".join(f"{label} '{v}'" for label, v in (("collection", collection), ("secret", name)) if v)
    try:
        suffix = f", backup {backup}" if backup else ""
        notify(f"vw: {action} {target} ({outcome}{suffix})".replace("  ", " "))
    except Exception:
        warnings.append("owner notification failed")
    return f" Warning: {', '.join(warnings)}." if warnings else ""
