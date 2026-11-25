# blind-vault-mcp

An MCP server that lets an AI agent manage secrets in [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
(or Bitwarden) **without ever seeing a secret value**.

The agent can create a collection for a new service, generate a database password into it, give
the service's CI account read access, find the keys that leaked into old transcripts, and rotate
them. It never reads a password, a token or a key. The values never enter the model's context,
the chat transcript or the provider's logs.

## Why

Agents like Claude Code now do real infrastructure work, and that work involves secrets. The
usual options are poor:

- **Paste the secret into the chat.** It stays in the transcript, the provider's logs and
  whatever the agent writes next.
- **Give the agent a password-manager MCP.** Most Bitwarden/Vaultwarden MCP servers, the official
  one included, return passwords, TOTP codes or share links to the model. That makes the agent a
  reader of the whole vault, so one prompt injection can exfiltrate it.
- **Do it by hand.** Then the agent stops being useful exactly where infrastructure work starts.

blind-vault-mcp takes a fourth route: the agent gets the ability to act on secrets, but never the
values that make the action possible.

## How it works

```
 agent (Claude Code, …)                 owner
    │  names, ids, statuses only           │  vw-put / vw-vault unlock / vw-approve
    ▼                                      ▼  (own terminal, never the chat)
 ┌──────────────────────┐   values   ┌──────────────┐        ┌─────────────┐
 │  blind-vault-mcp     │──stdin────▶│   bw CLI     │──API──▶│ Vaultwarden │
 │  (MCP server, stdio) │            └──────────────┘        └─────────────┘
 └─────────┬────────────┘
           │ "approve delete X? code 418302"
           ▼
   notification webhook ──▶ owner's phone (a channel the agent cannot read)
```

The contract, enforced by the code and by tests:

- **No value out.** No tool returns a secret value: listings return names, inventories return
  cleaned URLs, which fields are filled and per-unlock fingerprints.
- **No value in.** No tool takes a value as an argument. A value comes from a file path, from the
  generator (`generate=true`), from the owner's own terminal (`vw-put`), or stays
  inside the vault daemon's memory during a rotation. [A test](tests/test_blind_vault_server.py)
  fails if any tool grows a `value`, `password`, `token` or similar parameter.
- **Out-of-band approval.** Destructive calls such as deleting a secret wait for a six-digit code
  sent to the owner through a webhook. The owner types it into `vw-approve` in their own terminal.
  The agent can start the request but cannot finish it: the code is never in a tool result, a log
  or a file.
- **Nothing lost.** Every overwrite or delete is preceded by a backup (`VW_BACKUP_CMD`) and fails
  if the backup fails. Every action goes to a JSON-lines journal and to the owner's notifications.
- **Values never in argv.** Values reach `bw` through stdin (`bw encode`), never the command line,
  so they don't show up in `ps` or shell history.

## Toolsets

One server, three toolsets, chosen with `VW_TOOLSETS` (default `secrets`):

| Toolset | For | Tools |
|---|---|---|
| `secrets` | Secrets of services and CI in organization collections, one collection per repository or service | `list_collections`, `list_items`, `create_collection`, `grant_reader`, `set_secret`, `delete_secret`, `restore_info` |
| `vault` | The owner's personal vault, through a daemon the owner unlocks in their own terminal | inventory and search, exact-duplicate merge, leak check (values found in local files such as agent transcripts), breach check (HIBP k-anonymity), dead-URL and dead-token checks, missing-2FA check, trash/restore/move/rename, KeePassXC passkey import, rotation |
| `send` | Handing a value to a person as a one-time Bitwarden Send | `vault_send`, `vault_send_list`, `vault_send_delete` |

`send` is off by default: the Send link itself reaches the agent, which is the one exception to
"no value out". Turn it on only if you accept that trade-off.

**Rotation modules** (vault toolset, each off until configured): OpenRouter keys, Cloudflare API
tokens, Cloudflare tunnel tokens, GitLab tokens, GitHub App installation tokens, Pi-hole,
Proxmox and MikroTik passwords or keys, backup repository passwords, and application-generated
secrets (session keys, admin tokens). A rotation issues the new secret, distributes it to its
consumers, checks that they work, revokes the old one, and puts everything back if a check fails.

## Who it is for

- People who self-host Vaultwarden and let agents run their homelab or side projects.
- Small teams that keep CI and service secrets in a Bitwarden organization and want an agent to
  set up new services end to end.
- Anyone who wants an agent to clean up a large personal vault (duplicates, leaked and breached
  passwords, dead logins) without handing it the vault.

## Requirements

- Linux (macOS should work but is untested), Python 3.11+, [uv](https://docs.astral.sh/uv/).
- The [Bitwarden CLI](https://bitwarden.com/help/cli/) `bw` on `PATH`.
- A Vaultwarden or Bitwarden server with an organization, and a dedicated **manager account** in
  it (an owner or admin of the organization) for the `secrets` toolset.

## Install

```bash
uv tool install git+https://github.com/ai2sky/blind-vault-mcp
```

This puts `blind-vault-mcp` and the `vw-*` commands on your `PATH`.

## Configure

Settings come from the process environment or from `~/.config/vw/env` (`KEY=VALUE` lines):

```bash
mkdir -p ~/.config/vw
cat > ~/.config/vw/env <<'EOF'
VW_URL=https://vault.example.com
VW_ORGANIZATION_ID=<organization uuid>
EOF
```

The manager account's credentials live in the OS keyring (service `vw-manager`), never in a
file next to the code. Each command asks for the value with a hidden prompt:

```bash
uv tool run --from keyring keyring set vw-manager client_id        # user.xxxxxxxx-…
uv tool run --from keyring keyring set vw-manager client_secret
uv tool run --from keyring keyring set vw-manager master_password
```

On a headless host use `VW_CLIENT_ID`, `VW_CLIENT_SECRET_FILE` and `VW_MASTER_PASSWORD_FILE`
instead (files readable only by the server's user).

For approvals and notifications, point `VW_NOTIFY_URL` at any endpoint that accepts JSON
`{"text": "..."}`: a Slack or Mattermost incoming webhook, or a small bridge to your messenger.
An optional bearer token goes in `VW_NOTIFY_TOKEN_FILE` or the keyring entry `notify_token`.
Without it, tools that need approval refuse instead of waiting.

## Use with Claude Code

```bash
claude mcp add --scope user blind-vault -e VW_TOOLSETS=secrets -- blind-vault-mcp
```

Start a new session and ask for what you need:

> Set up secrets for the new `billing-api` service: a collection, a generated `DB_PASSWORD`,
> and read access for `svc-billing-api@example.com`. I'll enter the Stripe key myself.

The agent calls `create_collection("billing-api")`, `set_secret("billing-api", "DB_PASSWORD",
generate=true)` and `grant_reader("billing-api", "svc-billing-api@example.com")`. For the Stripe
key it asks you to run, in your own terminal:

```bash
vw-put billing-api STRIPE_SECRET_KEY
```

On the host or in CI, the service reads its collection into the environment with its own
read-only account (`VW_COLLECTION=billing-api` plus that account's `VW_*` settings in a `0600`
file). That is a command, not an MCP tool, so the agent still cannot call it:

```bash
eval "$(vw-env --env-file /etc/billing-api/vw.env)"
```

### The personal vault

```bash
vw-vault unlock          # once, in your own terminal: API key + master password or a FIDO2 key
claude mcp add --scope user blind-vault -e VW_TOOLSETS=secrets,vault -- blind-vault-mcp
```

> Find duplicate logins and any password that appears in my old agent transcripts under
> ~/.claude/projects, and put the leaked ones on the rotation list.

The daemon holds the unlocked vault in memory, serves a `0600` Unix socket, and locks itself
after `VW_VAULT_IDLE` seconds idle. Changes go to the trash (restorable), are journaled, and need
a fresh backup.

## Commands

| Command | What it does |
|---|---|
| `blind-vault-mcp` | The MCP server (stdio; `VW_TRANSPORT=streamable-http` for HTTP on a private interface) |
| `vw-put <collection> <NAME>` | The owner writes one secret: hidden prompt, `--file` or `--generate` |
| `vw-rm <collection> <NAME>` | The owner deletes one secret, typing the name again to confirm |
| `vw-env` | Reads a whole collection into the environment on a host or in CI (masked under GitHub Actions) |
| `vw-approve` | The owner's side of an approval: shows what is waiting and takes the code |
| `vw-service-account` | Creates the read-only Vaultwarden account a service uses for its own collection |
| `vw-vault` | The personal-vault daemon: `unlock`, `lock`, `status`, `unlock --enroll` for a security key |

## Configuration reference

| Variable | Meaning |
|---|---|
| `VW_URL` | Vaultwarden URL (required) |
| `VW_ORGANIZATION_ID` | The organization the `secrets` toolset manages |
| `VW_TOOLSETS` | `secrets` (default), `vault`, `send`, comma-separated, or `all` |
| `VW_KEYRING_SERVICE` | Keyring service of the manager account (default `vw-manager`) |
| `VW_CLIENT_ID`, `VW_CLIENT_SECRET_FILE`, `VW_MASTER_PASSWORD_FILE` | Manager credentials from files instead of the keyring |
| `VW_NOTIFY_URL`, `VW_NOTIFY_TOKEN_FILE` | Notification and approval webhook |
| `MCP_APPROVAL` | `owner` (default) or `deny` to refuse every approval-gated call |
| `MCP_APPROVAL_TTL` | Seconds the owner has to answer (default 300) |
| `VW_BACKUP_CMD` | Command that backs up the vault before an overwrite or delete |
| `VW_AUDIT_LOG` | Journal path (default `~/.local/state/vw/audit.log`) |
| `VW_VAULT_IDLE`, `VW_VAULT_BACKUP_CMD` | Personal-vault daemon: idle lock, backup before a batch |
| `VW_VAULT_*_ITEMS`, `VW_VAULT_*_CONSUMERS` | Rotation modules: which items, where the new value goes |
| `VW_TRANSPORT`, `VW_HOST`, `VW_PORT` | HTTP transport (no auth of its own: bind to a private interface) |

Details: [overview](docs/overview.md), [approval](docs/approval.md),
[manager account and collections](docs/manager.md), [service accounts](docs/service-account.md),
[personal vault and rotation](docs/vault.md).

## Security model and limits

blind-vault-mcp keeps values away from **the model**: its context, the transcript, the provider
and any tool output a prompt injection could steer. It does not protect against a hostile local
user. Whoever runs as the same OS user can read the keyring, the `bw` data directory and the
daemon's socket. Run the agent and the server as a user you trust, and keep the manager account
separate from your personal one.

What it does not claim:

- A value can still be read by commands the agent runs in a shell (`vw-env`, `bw get`). If the
  agent has an unrestricted shell on the same user, block those commands with your agent's
  permission rules (in Claude Code, `permissions.deny`).
- The `send` toolset hands the agent a one-time link to a value; it is off by default for that
  reason.
- The HTTP transport has no authentication of its own.

## Development

```bash
uv sync
uv run pytest -q
```

CI runs the tests on Python 3.11–3.13 and scans the whole history with
[gitleaks](https://github.com/gitleaks/gitleaks). Test fixtures that look like secrets are marked
line by line with `gitleaks:allow`.

## License

[MIT](LICENSE)
