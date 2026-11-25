"""Backup before a change that loses data (overwrite or delete of a secret).

VW_BACKUP_CMD is a command that makes a Vaultwarden backup and prints the
copy's identifier (a file name, a snapshot or volume id) as the last line of
stdout, e.g. `ssh -o BatchMode=yes root@vault-host backup-vaultwarden`. The
identifier goes to the audit journal next to the action, so a rollback has a
concrete copy to start from. No identifier, a failure or an unset command all
mean no backup, and the caller must not change anything.
"""

import os
import shlex
import subprocess

from .client import VwError

BACKUP_TIMEOUT = 1800
MAX_ID_LEN = 200
RESTORE_STEPS = (
    "Restore: 1) bring up the copy '{id}' on a scratch Vaultwarden (never over the live one); "
    "2) open the item '{name}' in collection '{collection}' there and copy its value; "
    "3) the owner writes it back with vw-put. Test a restore of the copy once before you need it."
)


def run_backup() -> str:
    """Run VW_BACKUP_CMD and return the copy identifier. Raises VwError on any failure."""
    cmd = os.environ.get("VW_BACKUP_CMD", "").strip()
    if not cmd:
        raise VwError("VW_BACKUP_CMD is not set: no overwrite or delete without a backup")
    try:
        proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=BACKUP_TIMEOUT)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise VwError("backup command could not run") from None
    if proc.returncode != 0:
        raise VwError(f"backup command failed with code {proc.returncode}")
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    backup_id = lines[-1] if lines else ""
    if not backup_id or len(backup_id) > MAX_ID_LEN:
        raise VwError("backup command printed no usable copy identifier")
    return backup_id


def restore_steps(backup_id: str, collection: str, name: str) -> str:
    return RESTORE_STEPS.format(id=backup_id, name=name, collection=collection)
