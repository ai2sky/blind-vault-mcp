# blind-vault-mcp: secrets in Vaultwarden that the agent never sees

An AI agent can create, file, grant and delete secrets in Vaultwarden, and tidy the owner's
personal vault, without a single value ever reaching the model. No tool returns a value and no
tool takes one as an argument: values come from a file the server reads, a generator, the
owner's own terminal or the memory of a daemon the owner unlocked.

**Contents**

- [Threat model](#threat-model)
- [Commands](#commands)
- [Install and connect to Claude Code](#install-and-connect-to-claude-code)
- [Toolsets](#toolsets)
- [The secrets toolset: organization collections](#the-secrets-toolset-organization-collections)
- [Backup before data is lost](#backup-before-data-is-lost)
- [Journal and notifications](#journal-and-notifications)
- [Configuration](#configuration)
- [vw-put: the owner writes a secret from their own terminal](#vw-put-the-owner-writes-a-secret-from-their-own-terminal)
- [vw-rm: the owner deletes a secret from their own terminal](#vw-rm-the-owner-deletes-a-secret-from-their-own-terminal)
- [vw-env: read a collection in CI and on hosts](#vw-env-read-a-collection-in-ci-and-on-hosts)
- [vw-service-account: the account a service reads its own secrets with](#vw-service-account-the-account-a-service-reads-its-own-secrets-with)
- [vw-vault: tidy the owner's personal vault without seeing it](#vw-vault-tidy-the-owners-personal-vault-without-seeing-it)
- [The older single-purpose servers](#the-older-single-purpose-servers)

Other pages:

- [Owner approval outside the chat](approval.md)
- [The manager account and collections](manager.md)
- [vw-service-account](service-account.md)
- [vw-vault: the personal vault](vault.md)

## Threat model

The agent is trusted to *manage* secrets, not to *know* them. Whatever reaches the model can end
up in a transcript, a log, a prompt injection's exfiltration or a provider's retention, so the
design keeps values on the other side of the tool boundary:

- Tools return names, counts, dates, cleaned URIs and HMAC fingerprints, never a value.
- A value enters only from a file path the server reads, a random generator, the owner's hidden
  prompt in their own terminal (`vw-put`), or the vw-vault daemon's memory.
- Values reach `bw` on stdin, never in argv; error messages from `bw` are reduced to a short list
  of known phrases, because `bw create` and `bw encode` echo the item on error.
- Destructive actions need the owner's yes through a channel the agent cannot read
  ([approval](approval.md)), and a backup taken right before them.
- Every change is journaled and the owner is notified.

What it does not protect against: the agent runs as the same Unix user as the owner. A process
that deliberately reads another process's memory or the owner's notification channel can get
around it. Keep debuggers (`gdb`, `ptrace`) and `vw-env` behind the client's permission rules;
see [Why the agent cannot approve itself](approval.md#why-the-agent-cannot-approve-itself).

## Commands

| Command | Who runs it | What it is |
|---|---|---|
| `blind-vault-mcp` | the MCP client | The MCP server. Toolsets are chosen with `VW_TOOLSETS` |
| `vw-put` | the owner | Write one secret into a collection from a hidden prompt, a file or a generator |
| `vw-rm` | the owner | Delete one secret from a collection |
| `vw-approve` | the owner | Enter the approval code for a waiting tool call |
| `vw-env` | CI, hosts | Export a collection as environment variables with a read-only account |
| `vw-service-account` | the owner | Create the Vaultwarden account an application reads its collection with |
| `vw-vault` | the owner | Unlock the personal vault into a daemon; lock it; run login checks |
| `vw-server`, `vw-vault-server` | the MCP client | The older single-purpose servers, see [below](#the-older-single-purpose-servers) |

The [`bw` CLI](https://bitwarden.com/help/cli/) must be installed on the host: the server,
`vw-put`, `vw-rm`, `vw-env`, `vw-vault` and `vw-service-account check`/`import` all work through
it.

## Install and connect to Claude Code

```bash
uv tool install git+https://github.com/ai2sky/blind-vault-mcp
```

This puts every command above on the `PATH`. Without installing, run one with
`uvx --from git+https://github.com/ai2sky/blind-vault-mcp <command>`.

Put the settings in `~/.config/vw/env` (`KEY=VALUE` lines, see [Configuration](#configuration))
or pass them with `-e`, then add the server for all projects:

```bash
claude mcp add --scope user blind-vault \
  -e VW_URL=https://vault.example.com -e VW_ORGANIZATION_ID=<org-id> \
  -e VW_NOTIFY_URL=https://hooks.example.com/<your-webhook> \
  -- blind-vault-mcp
```

The manager account's credentials come from the OS keyring (see [manager.md](manager.md)), so
they appear in neither the command nor the client's config.

## Toolsets

`VW_TOOLSETS` is a comma-separated list; the default is `secrets`. An unknown name stops the
server at start.

| Toolset | Tools | Needs |
|---|---|---|
| `secrets` | Organization collections for services and CI: list, create, grant read access, write, delete, restore info | The manager account |
| `vault` | The owner's personal vault through the vw-vault daemon: inventory, duplicates, checks, rotation | `vw-vault unlock` in the owner's terminal |
| `send` | `vault_send`, `vault_send_list`, `vault_send_delete`: hand a value to a person as a one-time Bitwarden Send link | The daemon, as `vault` |
| `all` | All three | |

`send` is off unless named, because the Send link carries the decryption key and the link itself
reaches the agent. See [vault.md](vault.md#tools).

## The secrets toolset: organization collections

The tools work on collections of one organization (`VW_ORGANIZATION_ID` is required; the
collection is passed in each call).

| Tool | Confirmation | Description |
|------|--------------|-------------|
| `list_collections()` | None | Collection names of the organization. |
| `list_items(collection)` | None | Secret names in a collection, never values. |
| `create_collection(collection)` | None | Creates a collection. |
| `grant_reader(collection, account)` | None | Gives an account (email) read access to a collection. An account that is not in the organization yet is invited with that access and confirmed (Vaultwarden without SMTP accepts the invitation of an existing account itself), so nothing is done in the web vault. |
| `set_secret(collection, name, from_file \| generate \| prompt)` | None | Writes a Login: the variable name as the item name, the value in `password`. |
| `delete_secret(collection, name)` | Owner approval ([how](approval.md)) | Deletes a secret. |
| `restore_info(collection, name)` | None | Backups recorded before this secret was overwritten or deleted, and the rollback steps. Reads the journal only. |

`name` must start with a letter or underscore and contain only letters, digits and underscores,
up to 64 characters. Names with `.` or `-` or a leading digit are rejected. Collection names are
letters, digits, space, `_`, `.` and `-`, up to 64 characters, and are matched exactly.

Where the value of `set_secret` comes from (exactly one):

- `from_file`: a path the server reads (up to 16 KiB; a trailing newline is dropped).
- `generate`: 32 random bytes, URL-safe base64.
- `prompt`: the server asks the owner outside the chat through a hook
  (`vw_server.server.set_prompt_hook`). The shipped servers install no such hook, so `prompt`
  writes nothing ("no value was provided"). For a value only the owner holds, use
  [`vw-put`](#vw-put-the-owner-writes-a-secret-from-their-own-terminal).

## Backup before data is lost

`set_secret` over an existing name and `delete_secret` of an existing secret first run
`VW_BACKUP_CMD`, for example `ssh -o BatchMode=yes root@backup-host backup-vaultwarden`. The
last line of its stdout must be the copy's identifier (a file name or snapshot id); it is
written to the journal and the notification next to the action. Creating a new secret takes no
backup. If the command is unset, fails or prints no identifier, nothing is changed and the
refusal is journaled.

Rollback, as `restore_info` prints it: bring the copy up on a scratch Vaultwarden (never over
the live one), copy the value out there, have the owner write it back with `vw-put`. Try a
restore once, before you need it.

`vw-put` and `vw-rm` are the owner's own commands and take no backup.

## Journal and notifications

Every write, collection creation, access grant and deletion (including refused or failed ones)
is appended to the journal (JSON lines, `VW_AUDIT_LOG`, default `~/.local/state/vw/audit.log`)
and sent to the owner as a notification. Records carry the action, the collection, the name, the
outcome and the backup id, never a value. Reads (`list_*`) are not journaled.

The notification is a POST of `{"text": ..., "source": ...}` to `VW_NOTIFY_URL`: any endpoint
that takes JSON with a `text` field, such as a Slack or Mattermost incoming webhook or a small
bridge to a messenger. If a token is configured it is sent as `Authorization: Bearer <token>`;
it comes from the file `VW_NOTIFY_TOKEN_FILE`, or else the keyring entry `notify_token` of the
manager account. A failed notification does not undo the action; it adds a warning to the tool
output. The same channel carries the [approval](approval.md) codes, so it must be one the agent
cannot read: the owner's phone, not a chat the agent has a tool for.

## Configuration

`blind-vault-mcp`, `vw-put`, `vw-rm` and `vw-service-account` read `~/.config/vw/env`
(`KEY=VALUE` lines); a variable already set in the environment wins.

The manager account (the account the tools sign in as, see [manager.md](manager.md)):

- `VW_URL` (required): URL of the Vaultwarden server. There is no default.
- `VW_ORGANIZATION_ID` (required for the collection tools): id of the organization.
- `VW_CLIENT_ID`, `VW_CLIENT_SECRET_FILE`, `VW_MASTER_PASSWORD_FILE`: the account's API key
  client id and the paths of files holding the client secret and the master password. Any of
  them that is unset is taken from the OS keyring: service `VW_KEYRING_SERVICE` (default
  `vw-manager`), entries `client_id`, `client_secret`, `master_password`.
- `VW_BW_DATA_DIR` (optional): bw's data directory for this account, default
  `~/.local/state/vw/bw-<hash of the client id>`. It is never the user's own, so a personal
  `bw login` in the same home does not get in the way.
- `VW_COLLECTION` (optional): a fixed collection for `vw-env` and the older `vw_set`/`vw_list`.
  Set it together with `VW_ORGANIZATION_ID`.
- `VW_FOLDER` (optional, default `agents`): the personal folder `vw-env` and `vw_set`/`vw_list`
  use when no collection is set.

Safety and notifications:

- `VW_BACKUP_CMD`: see [Backup before data is lost](#backup-before-data-is-lost).
- `VW_AUDIT_LOG`, `VW_NOTIFY_URL`, `VW_NOTIFY_TOKEN_FILE`: see
  [Journal and notifications](#journal-and-notifications).
- `MCP_APPROVAL`, `MCP_APPROVAL_TTL`: see [approval.md](approval.md#setup).

Server:

- `VW_TOOLSETS`: see [Toolsets](#toolsets).
- `VW_TRANSPORT` (optional): `stdio` (default) or `streamable-http`.
- `VW_HOST`: bind address, required for `streamable-http`. There is no authentication: bind to a
  private interface only and restrict the port with a firewall.
- `VW_PORT` (optional): port for `streamable-http`, default `8765`.

### One bw data directory, one operation at a time

The MCP server, `vw-put`, `vw-rm` and any script using the same account share one bw data
directory, and bw keeps its session there: an unlock by one process voids the session of
another, whose next call then prints nothing ("bw list returned invalid JSON", "bw create exited
with code 1"). So every operation holds `vw.lock` in that directory with `flock`
(`msvcrt.locking` on Windows) from unlock to its end; others wait up to two minutes and then
fail with "bw data dir is busy".

## vw-put: the owner writes a secret from their own terminal

For values only the owner holds (a `claude setup-token`, a bot token) the agent asks the owner
to run this; the value never passes through the chat:

```bash
vw-put myapp CLAUDE_CODE_OAUTH_TOKEN
```

The value is typed twice into a hidden prompt (or `--file PATH`, or `--generate`), written as
the manager account like `set_secret`, journaled and notified; it is never printed.

## vw-rm: the owner deletes a secret from their own terminal

The pair of `vw-put`, for clean-ups where an approval code per deletion would be a chore:

```bash
vw-rm myapp OLD_TOKEN
```

The name is typed again to confirm, because nothing here undoes a deletion; `--yes` skips that
for a script that already asked. The action is journaled and notified like `vw-put`'s, and a
name that is not there is said plainly rather than treated as a failure.

## vw-env: read a collection in CI and on hosts

`vw-env` logs in with a read-only account and exports the items of the collection
(`VW_ORGANIZATION_ID` + `VW_COLLECTION`) as variables: a Login gives its password, a secure note
its notes. Items whose name is not a valid variable name are skipped. It is a command, not an
MCP tool, so agents still cannot read values.

- In GitHub Actions (`GITHUB_ENV` set) each value is masked with `::add-mask::` and then
  appended to `GITHUB_ENV`.
- Elsewhere it prints `export NAME='value'` lines: `eval "$(vw-env)"`.
- `--format systemd` prints `NAME='value'` lines for a systemd `EnvironmentFile`; a value with a
  quote, a backslash or a newline cannot be written that way and is skipped with its name on
  stderr.
- Names that could change how later steps run are never exported: `PATH`, `HOME`, `SHELL`,
  `IFS`, `ENV`, `BASH_ENV`, `NODE_OPTIONS`, `PYTHONPATH` and similar, plus the prefixes
  `GITHUB_`, `RUNNER_`, `LD_`, `DYLD_`, `BASH_FUNC_` (case-insensitive; the full list is
  `DANGEROUS_NAMES` / `DANGEROUS_PREFIXES` in [`src/vw_server/env.py`](../src/vw_server/env.py)).
  Such items are skipped with a warning on stderr (the name only) and the exit code stays 0.
- The account comes from the `VW_*` variables or from `--env-file` / `VW_ENV_FILE` (`KEY=VALUE`
  lines: `VW_URL`, `VW_CLIENT_ID`, `VW_CLIENT_SECRET_FILE`, `VW_MASTER_PASSWORD_FILE`,
  `VW_ORGANIZATION_ID`, `VW_COLLECTION`). `vw-env` does not use the keyring. The file must not
  be accessible by group or others. On a self-hosted runner it lives on the host as a root
  `0600` file, so the repository holds no secrets:

```yaml
- run: vw-env --env-file /etc/vw-env/reader.env
```

## vw-service-account: the account a service reads its own secrets with

Before a collection is of any use to an application, the application needs its own Vaultwarden
account with read access to it. That account is not made by hand:

```bash
vw-service-account --vault-file ansible/inventory/group_vars/all/vault.yml create my_app
```

It invites `svc-my-app@example.com` through the admin interface, registers it, issues an API key
and writes `vault_my_app_bw_email`, `_password`, `_clientid` and `_clientsecret` into that
Ansible Vault file, the variables a playbook feeds to `vw-env` on the host. Then
`grant_reader("my-app", "svc-my-app@example.com")` gives it the collection, and
`vw-service-account check my_app` signs in as the service and lists the variables it sees.
See [service-account.md](service-account.md).

## vw-vault: tidy the owner's personal vault without seeing it

The owner unlocks their personal vault once in their own terminal (`vw-vault unlock`); a daemon
holds the session and the `vault` toolset works through it: inventory, duplicates, leak,
breach, site, token and 2FA checks, the rotation list and rotation modules. No value ever leaves
the daemon; changes go to the trash and need a fresh backup. See [vault.md](vault.md).

## The older single-purpose servers

`vw-server` serves the collection tools above plus the first, folder-based pair:

| Tool | Confirmation | Description |
|------|--------------|-------------|
| `vw_list()` | None | Secret names in `VW_FOLDER` (or `VW_COLLECTION`), never values. |
| `vw_set(name, value)` | Owner approval | Writes a secret. |

`vw_set` takes the value as a tool argument, so the value passes through the chat. It stays in
`vw-server` for old setups and is not served by `blind-vault-mcp`. `vw-server` takes the
account settings from its environment only, not from `~/.config/vw/env`.

`vw-vault-server` serves the vault tools, Send included. `blind-vault-mcp` with
`VW_TOOLSETS=vault,send` gives the same.
