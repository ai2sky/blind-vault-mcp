"""Rotation modules: issue a new secret, spread it to the consumers, verify, revoke the old one.

A module owns one kind of secret (a GitHub token, a service password ...). The engine
drives the steps and keeps the order and the rollback; the value lives only inside the
module and the daemon and never reaches a result, the journal or an error message.
"""

from __future__ import annotations

import dataclasses
from typing import Protocol

from vw_server.client import VwError


@dataclasses.dataclass
class Issued:
    """A freshly issued secret. The value stays out of repr, so a log line cannot carry it."""

    ref: str  # opaque handle of the new secret at the issuer (token id, key id ...)
    value: str = dataclasses.field(repr=False, default="")


class RotationModule(Protocol):
    name: str

    def matches(self, item: dict) -> bool:
        """Whether this module rotates the vault item (raw bw item, stays inside the daemon)."""

    def issue(self, item: dict) -> Issued:
        """Create the new secret; the old one stays valid."""

    def distribute(self, item: dict, new: Issued) -> list[str]:
        """Put the new value where it is used (vault.yml, GitHub repo secrets, collections,
        hosts); return the names of the consumers updated, in the order done."""

    def verify(self, item: dict, new: Issued) -> bool:
        """Whether the consumers work with the new secret."""

    def revoke_old(self, item: dict, new: Issued) -> None:
        """Revoke the old secret; runs only after a successful verify."""

    def rollback(self, item: dict, new: Issued, done: list[str]) -> None:
        """Undo a failed rotation: put the old value back on the consumers in `done`,
        revoke the new secret. The old secret is still valid at this point."""


class PartialDistribution(VwError):
    """distribute failed after touching some consumers; `done` lists them (the failed one too)."""

    def __init__(self, message: str, done: list[str]):
        super().__init__(message)
        self.done = done


def _reason(exc: Exception) -> str:
    # only our own messages are written by us; anything else may quote a value
    return str(exc) if isinstance(exc, VwError) else type(exc).__name__


def run_module(module: RotationModule, item: dict) -> dict:
    """One rotation: issue, distribute, verify, revoke_old.

    A failure before revoke_old rolls back and leaves the old secret valid. A failure of
    revoke_old keeps the new secret in place (the consumers already use it) and reports
    the old one as still alive.
    """
    out: dict = {"module": module.name, "ok": False, "stage": "issue", "consumers": []}
    new: Issued | None = None
    done: list[str] = []
    try:
        new = module.issue(item)
        out["stage"] = "distribute"
        done = list(module.distribute(item, new))
        out["consumers"] = done
        out["stage"] = "verify"
        if not module.verify(item, new):
            raise VwError("verification failed")
    except Exception as exc:
        out["error"] = _reason(exc)
        if isinstance(exc, PartialDistribution):
            done = out["consumers"] = exc.done
        if new is not None:
            try:
                module.rollback(item, new, done)
                out["rolled_back"] = True
            except Exception as back:
                out["rolled_back"] = False
                out["rollback_error"] = _reason(back)
        return out
    out["stage"] = "revoke_old"
    try:
        module.revoke_old(item, new)
    except Exception as exc:
        out["error"] = _reason(exc)
        out["old_alive"] = True
        return out
    out["ok"], out["stage"] = True, "done"
    return out
