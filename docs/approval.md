# Owner approval outside the chat

A tool that deletes a secret needs the owner's yes. The client's own prompt is not that yes: in
a desktop client the agent and the owner share one chat, and an MCP elicitation is answered by
the client, which the agent drives. So the yes comes from a channel the agent cannot read.

**Contents**

- [How it works](#how-it-works)
- [Why the agent cannot approve itself](#why-the-agent-cannot-approve-itself)
- [Setup](#setup)
- [If an approval does not arrive](#if-an-approval-does-not-arrive)
- [Where it is installed](#where-it-is-installed)

## How it works

1. The agent calls a tool that needs approval: `delete_secret`, or `vw_set` in the older
   `vw-server`. The call **blocks** inside the server.
2. The server makes a six-digit code and keeps it in its own memory: never in a tool result, a
   log, a file, or an answer of the local socket.
3. It sends the owner a message through the notification webhook (`VW_NOTIFY_URL`, see
   [Journal and notifications](overview.md#journal-and-notifications)): the code first, then
   what is about to happen and in which collection. The code is the first line because some
   channels cut a long message at about 1000 characters, and a code at the end could be cut off.
4. The owner gives the code back, where the agent does not see it. Either:
   - in a terminal of their own: `vw-approve` (the code is typed hidden; `--deny` refuses at
     once; with several requests waiting it lists them and asks which one), or
   - in the form the client shows for the question (MCP elicitation), if the client shows one.
     Declining the form does not refuse the request; the terminal stays open as the channel.
5. A right code lets this one call go ahead. Three wrong codes, five minutes
   (`MCP_APPROVAL_TTL` seconds), no notification channel, or any error refuses. The next call
   gets a new code.

The message names the action, so the owner approves what will actually run. Values never appear
in it.

`vw-approve` finds waiting requests through owner-only Unix sockets in
`$XDG_RUNTIME_DIR/blind-vault-approve-<uid>/`. A socket answers only three requests: `info` (the
summary and the attempts left), `code <digits>` and `deny`. It never sends the code.

## Why the agent cannot approve itself

- It starts a request but never learns the code: the code is in the server's memory and the
  owner's notification channel only. Guessing is three tries in a million, and each request
  pings the owner.
- `vw-approve` and the elicitation form are only places to *enter* a code. An agent that runs
  `vw-approve` or answers the form has nothing to enter. A refusal (`--deny`, an empty code) is
  the only thing it can do there, which is harmless.
- The server, not a tool argument, decides: the hooks are installed in the server's `main()`,
  no parameter skips them, and only `True` counts (fail closed). Code that uses the library
  without `main()` gets the default hooks, which deny everything.

Residual risk, stated plainly: the agent and the owner are one Unix user. An agent that got
hold of the notification channel itself (for example a messenger session token stored in a
collection it can export with `vw-env`) could read the code, and one that attached a debugger
to the server could read its memory. That is a deliberate attack, not a mistake or a prompt
injection; keep `vw-env` and `gdb`/`ptrace` behind the client's permission rules (do not allow
them for agents), and do not store the credentials of the notification channel where the agent
can read them.

## Setup

Nothing beyond the notification settings: `VW_NOTIFY_URL` (in `~/.config/vw/env` or the
server's environment) and, if the endpoint needs one, a token from the file
`VW_NOTIFY_TOKEN_FILE` or the keyring entry `notify_token` of the manager account (service
`VW_KEYRING_SERVICE`, default `vw-manager`). Without a way to notify the owner nothing is
approved: the tool says the owner's approval or confirmation was not given.

`MCP_APPROVAL=deny` refuses every approval without asking. The default is `owner`.
`MCP_APPROVAL_TTL` sets the seconds the owner has to answer (default 300, at least 10).

## If an approval does not arrive

| Symptom | Cause and fix |
|---|---|
| "Not deleted: owner confirmation was not given" at once | The notification failed. Check `VW_NOTIFY_URL`, the token, and that the endpoint answers 2xx to a POST of `{"text": "..."}` |
| The message came, `vw-approve` says "Nothing is waiting for approval" | The five minutes passed, or the server was restarted (it holds the request). Call the tool again |
| "The request is closed" | Three wrong codes, a timeout, or a refusal: call the tool again for a fresh code |
| Several requests at once | `vw-approve` lists them; the code in a message belongs to the request it describes |
| The refusal came after five minutes, the owner saw no form | The client did not show the elicitation form. Open a terminal with `vw-approve` **before** the tool is called and type the code from the latest "Code: ..." message there |

## Where it is installed

`vw_server.owner_approval.install_vw` replaces the default deny-all hooks in `main()` of
`blind-vault-mcp` and `vw-server`. The code and its tests:
[`src/vw_server/owner_approval.py`](../src/vw_server/owner_approval.py),
[`src/vw_server/approve.py`](../src/vw_server/approve.py),
[`tests/test_owner_approval.py`](../tests/test_owner_approval.py).
