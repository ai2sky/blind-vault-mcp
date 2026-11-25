"""Owner approval outside the chat, for the tools that write or deploy.

The vw hooks default to "deny". `install_vw` here replaces them with a
challenge the agent cannot answer:

1. The server makes a six-digit code and keeps it in its own memory only.
2. It sends the owner a message with what is about to happen and the code, through the
   notification webhook (`VW_NOTIFY_URL`), a channel the agent has no tool to read.
3. The owner gives the code back where the agent does not see it: `vw-approve` in a terminal
   of their own, or the form the MCP client shows for the question (elicitation).
4. A right code approves exactly this one call; three wrong ones, the timeout, a missing
   notification channel or any error is a refusal.

The agent can start a request (by calling the tool) but cannot finish it: it never learns the
code, because the code is never in a tool result, a log, a file or the socket's answers.
"""

import asyncio
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path

from . import audit

CODE_DIGITS = 6
MAX_ATTEMPTS = 3
DEFAULT_TTL = 300  # seconds the owner has to answer
MODE_ENV = "MCP_APPROVAL"  # "owner" (default) or "deny"
TTL_ENV = "MCP_APPROVAL_TTL"


def socket_dir() -> Path:
    """Where pending requests listen: owner-only, under the runtime dir."""
    base = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    return Path(base) / f"blind-vault-approve-{os.getuid()}"


def _ttl() -> int:
    try:
        return max(10, int(os.environ.get(TTL_ENV, "") or DEFAULT_TTL))
    except ValueError:
        return DEFAULT_TTL


def _new_code() -> str:
    return f"{secrets.randbelow(10 ** CODE_DIGITS):0{CODE_DIGITS}d}"


class Challenge:
    """One pending request: its summary, its code and the attempts left."""

    def __init__(self, summary: str):
        self.summary = summary
        self.code = _new_code()
        self.attempts = MAX_ATTEMPTS
        self.denied = False
        self.done: asyncio.Future[bool] = asyncio.get_running_loop().create_future()

    def matches(self, given: str) -> bool:
        return hmac.compare_digest(given.strip().encode(), self.code.encode())

    def answer(self, given: str) -> str:
        """Check a code from the owner; returns "approved", "wrong" or "closed"."""
        if self.done.done():
            return "closed"
        if self.matches(given):
            self.done.set_result(True)
            return "approved"
        self.attempts -= 1
        if self.attempts <= 0:
            self.done.set_result(False)
            return "closed"
        return "wrong"

    def deny(self) -> None:
        if not self.done.done():
            self.denied = True
            self.done.set_result(False)


async def _serve(challenge: Challenge, path: Path) -> asyncio.AbstractServer:
    """A Unix socket `vw-approve` talks to: info, code <digits>, deny. Never sends the code."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = (await asyncio.wait_for(reader.readline(), 10)).decode().strip()
            verb, _, arg = line.partition(" ")
            if verb == "info":
                reply = {"summary": challenge.summary, "attempts": challenge.attempts}
            elif verb == "code":
                reply = {"result": challenge.answer(arg), "attempts": challenge.attempts}
            elif verb == "deny":
                challenge.deny()
                reply = {"result": "denied"}
            else:
                reply = {"error": "unknown request"}
            writer.write((json.dumps(reply) + "\n").encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.unlink(missing_ok=True)
    server = await asyncio.start_unix_server(handle, path=str(path))
    os.chmod(path, 0o600)
    return server


async def _elicit(challenge: Challenge, app) -> None:
    """Also ask through the client's own form, if it shows one. The answer is only a code
    attempt: an agent that answers it does not know the code. It has its own attempt budget and
    never refuses the request: a decline or a failure just leaves the terminal as the channel."""
    try:
        from pydantic import BaseModel

        class Code(BaseModel):
            code: str

        ctx = app.get_context()
        for _ in range(MAX_ATTEMPTS):
            if challenge.done.done():
                return
            result = await ctx.elicit(
                f"{challenge.summary}\nEnter the code from your notification, or cancel and use "
                "`vw-approve` in a terminal.", Code)
            if result.action != "accept":
                return
            if challenge.matches(result.data.code):
                if not challenge.done.done():
                    challenge.done.set_result(True)
                return
    except Exception:
        return


async def ask_owner(summary: str, app=None) -> bool:
    """Ask the owner out of band. True only for a right code in time; never raises."""
    challenge = None
    server = None
    path = None
    try:
        challenge = Challenge(summary)
        path = socket_dir() / f"{os.getpid()}-{secrets.token_hex(4)}.sock"
        server = await _serve(challenge, path)
        # The code goes first: the notification channel cuts a long message at about 1000
        # characters, and a long summary (a chat message) used to push the code off the end.
        text = (f"Code: {challenge.code}\nApproval needed: {summary}\n"
                "Give the code to `vw-approve` in your terminal (or to the form in the chat) to "
                "allow this one call; ignore this message to refuse.")
        try:
            await asyncio.to_thread(audit.notify, text)
        except Exception:
            return False  # no channel to the owner, so no approval
        elicit = asyncio.create_task(_elicit(challenge, app)) if app is not None else None
        try:
            return await asyncio.wait_for(asyncio.shield(challenge.done), _ttl()) is True
        except asyncio.TimeoutError:
            return False
        finally:
            if elicit is not None:
                elicit.cancel()
    except Exception:
        return False
    finally:
        if challenge is not None and not challenge.done.done():
            challenge.done.set_result(False)
        if server is not None:
            server.close()
        if path is not None:
            path.unlink(missing_ok=True)


def enabled() -> bool:
    return (os.environ.get(MODE_ENV, "owner").strip().lower() or "owner") != "deny"


def install_vw(app=None) -> None:
    """Owner approval for vw_set and delete_secret.

    `app` is the FastMCP instance of the running server, for the in-chat form."""
    if not enabled():
        return
    from . import server as vw

    async def approve(request: vw.ApprovalRequest) -> bool:
        return await ask_owner(vw.describe(request), app)

    async def confirm_delete(request: vw.DeleteRequest) -> bool:
        return await ask_owner(
            f"delete_secret: delete '{request.name}' from collection '{request.collection}'", app)

    vw.set_approval_hook(approve)
    vw.set_delete_hook(confirm_delete)

