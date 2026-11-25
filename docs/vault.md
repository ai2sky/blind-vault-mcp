# vw-vault: cleaning up a personal vault without seeing it

`vw-vault` lets an agent tidy the owner's personal Vaultwarden vault (duplicates, dead sites,
breached or leaked passwords, missing 2FA, secrets due for rotation) while no value ever reaches
the agent.

**Contents**

- [How it works](#how-it-works)
- [Setup](#setup)
- [Tools](#tools)
- [Checks](#checks)
- [Rotation modules](#rotation-modules)
- [Self-generated secrets and Cloudflare tunnel tokens](#self-generated-secrets-and-cloudflare-tunnel-tokens)
- [Unlock with a security key](#unlock-with-a-security-key)
- [Login checks](#login-checks)

## How it works

```
owner's terminal                 daemon (owner's process)              agent
vw-vault unlock ──API key──▶  bw session in memory, items decrypted  ◀── blind-vault-mcp (MCP)
               ──master pw─▶  fingerprint key (random per unlock)        or vw-vault call
                              0600 Unix socket, idle timeout 2 h
```

- The owner runs `vw-vault unlock` in their own terminal. `VW_URL` must be set (there is no
  default; unlock refuses without it). The API key comes from the keyring (Secret Service,
  service `vw-vault`, entries `client_id`, `client_secret`) or a prompt; the master password is
  always typed (or unlocked with a [security key](#unlock-with-a-security-key)) and never
  stored. bw uses its own data directory, apart from a personal `bw login`.
- The daemon answers requests over `$XDG_RUNTIME_DIR/vw-vault.sock` (mode 0600; `VW_VAULT_SOCKET`
  overrides). No command returns a value: only names, cleaned URIs (no userinfo, query or
  fragment), which fields are filled, dates and HMAC fingerprints under a key that dies with the
  daemon.
- Defence in depth: a value that sits in a name, URI or field name is shown as
  `<redacted: contains a secret>`; a request or response that carries a vault value is refused.
  Either way the item goes on the rotation list.
- Changes use bw: edits, soft delete to the trash (restorable), restore. Each one is journaled
  (`~/.local/state/vw/vault/journal.log`, no values; the directory is `VW_VAULT_STATE_DIR`). A
  change needs a backup younger than 15 minutes: the daemon runs `VW_VAULT_BACKUP_CMD` itself
  and refuses when it fails or is unset.
- After the idle timeout (`VW_VAULT_IDLE`, seconds, default 7200) the daemon locks bw and exits;
  `vw-vault lock` does it at once. `vw-vault status` says whether it runs.

## Setup

```bash
vw-vault unlock
claude mcp add --scope user blind-vault -e VW_TOOLSETS=secrets,vault -- blind-vault-mcp
```

`~/.config/vw/env` (or the environment):

```
VW_URL=https://vault.example.com
VW_VAULT_BACKUP_CMD=ssh -o BatchMode=yes root@backup-host systemctl start backup-vaultwarden
VW_VAULT_IDLE=7200
VW_VAULT_LAN_URL=http://192.0.2.10:8080   # optional: bw through a loopback HTTPS proxy to the LAN
```

`VW_VAULT_LAN_URL` is for a vault behind a tunnel or proxy that stalls on a large sync: the daemon
starts a loopback HTTPS proxy (port `VW_VAULT_LAN_PORT`, default 18443) to that address, and bw
talks to it. The rotation modules below are switched on by their own variables.

## Tools

| Tool | What it does |
|------|--------------|
| `vault_status`, `vault_summary` | Unlocked or not; counts by type, folder, collection |
| `vault_inventory(query)`, `vault_export_inventory` | Items without values; the whole list to a JSONL file |
| `vault_reload` | Sync with the server and reload the items |
| `vault_backup` | Run `VW_VAULT_BACKUP_CMD` now |
| `dedupe_plan`, `dedupe_apply(limit)` | Exact duplicates: same username and password on an overlapping site (or equal content for non-logins). The newest is kept and gets URIs, fields, TOTP, notes, history and differing names of the rest, which go to the trash. Groups with attachments, a passkey only in a duplicate or conflicting TOTP are skipped. Similar groups (same site and username, different passwords) are only listed |
| `vault_trash`, `vault_restore`, `vault_move`, `vault_set_uri` | Changes by item id |
| `vault_rename(id, name)` | Rename an item; only the name changes. Refused when another live item of the same collection (or another personal one) already has the name: consumers that map item names to variables could not tell them apart |
| `vault_drop_field(id, field)` | Remove a custom field by name (a dead token kept next to a live one) |
| `vault_check(name)` | Background checks, see [Checks](#checks) |
| `vault_job` | Progress and result of the background job |
| `rotation_list`, `rotation_mark`, `rotation_clear` | Items to rotate, with reasons |
| `rotate(ids)`, `rotate_all` | Run the [rotation modules](#rotation-modules) for these items, or for the whole rotation list |
| `github_app_status(id)` | The installations of a GitHub App key item and the repositories each reaches; the tokens used for the listing are revoked at once |
| `openrouter_keys` | The OpenRouter API keys of the account, listed through the provisioning key: name, hash prefix (8 characters), created, updated, disabled, limit, usage; oldest first. No key text. It answers "which key at OpenRouter is the old one" before the owner deletes it in the dashboard. Needs the OpenRouter module |
| `vault_unarchive` | Take items out of the archive (archived items are seen, never trashed) |
| `vault_convert_passkeys`, `vault_drop_kpex_fields` | Rebuild KeePassXC passkeys (`KPEX_PASSKEY_*` fields) as Bitwarden passkeys; then drop the old fields |
| `collections_plan`, `vault_to_collection`, `vault_copy_to`, `vault_dedupe_collections` | Owner folders as collection candidates; move = copy checked by fingerprint + original to the trash (`bw move` fails on some Vaultwarden versions); copy between organizations; drop empty duplicate collections |
| `folders_plan`, `vault_delete_folders` | Personal folders and their counts; delete folders (items stay, without a folder). `vault_move` sets a folder through the API, so an item in a collection also shows in a personal folder |
| `vault_export_to_ansible_vault(id, vault_file, variable, field)` | Write an item's password, notes or a named custom field into a variable of an encrypted Ansible Vault file (view, replace or append, encrypt); the value stays in the daemon, only fingerprints come back |
| `vault_set_from_ansible_vault(id, vault_file, variable)` | The opposite: put an Ansible Vault variable into a login's password; only the fingerprints before and after come back |
| `vault_compare_keyring(id, attributes)` | Whether an item equals a keyring secret, compared inside the daemon; only the verdict leaves (no hash from outside: that would be a guessing oracle) |
| `vault_send(id, field, expires_hours, max_views, password, note)` | Toolset `send`. Hand a value to a person who has no access to the vault, see below |
| `vault_send_list`, `vault_send_delete(id)` | Toolset `send`. List the Sends (id, name, expiry, deletion date, views so far, view limit, disabled, whether a password is set; never the link) and delete one by id so its link dies at once |

Every change except a Send needs a fresh backup and is journaled.

### vault_send

A hidden text Bitwarden Send made from the item's password, notes or a named custom field
(`field`, default `password`). It is deleted and expires `expires_hours` ahead (default 24, at
most 168) and allows `max_views` views (default 1, at most 5); a larger value is refused.
`password` is an optional access password, to be told to the person by another route. The
Send's name says what it is (item, field, time), never the value.

The result is the access URL, the Send id, expiry, max views and whether a password is set.
**The URL carries the decryption key after `#`: it is returned to the caller only, never written
to the journal or a log, so hand it over and do not keep it.** This is why the tool sits in its
own toolset, off by default. The value goes to `bw send create` on stdin, not argv. Behind the
loopback proxy (`VW_VAULT_LAN_URL`) bw builds the link on 127.0.0.1, so the daemon swaps in the
public `VW_URL`. A Send is not a vault item, so no backup is needed.

## Checks

`vault_check(name)` starts a background job; `vault_job` follows it.

| Check | Network | Result |
|-------|---------|--------|
| `leaks` | none | Vault values found in local files (agent transcripts under `~/.claude`, shell history, `~/.gemini`, `~/.codex`; `paths` overrides the list) via GNU `grep -F` fed through a pipe. Values shorter than 10 characters or all digits are skipped. Found items go on the rotation list |
| `hibp` | api.pwnedpasswords.com, 5 hex of SHA-1, padded | Breached passwords, onto the rotation list. A range lookup that times out, drops the connection, gets a 429 (`Retry-After` is honoured, up to 60 s) or a 5xx is retried up to 3 times with backoff; a range that still fails does not void the run: its items are reported as `not_checked`. Only a run where every lookup failed is an error |
| `urls` | DNS and one GET per host, no credentials | Dead domains, HTTP errors, moved sites |
| `tokens` | the issuing API | GitHub, Telegram, Anthropic, OpenAI, OpenRouter, GitLab, Cloudflare tokens: alive or dead, account, scopes, expiry |
| `twofa` | api.2fa.directory | Logins whose site offers 2FA while the item has no TOTP |

Results land in `~/.local/state/vw/vault/check-<name>.json` (no values).

The opt-in `logins` check is the one exception to "no password is sent to a website": off by
default, started only by the owner with `vw-vault check logins`, never through `vault_check`.
See [Login checks](#login-checks).

## Rotation modules

`rotate(ids)` runs the modules in [`src/vw_vault/rotation.py`](../src/vw_vault/rotation.py):
issue a new secret, distribute it to the consumers (an Ansible Vault file, CI secrets,
collections, hosts), verify, then revoke the old one. A failed distribute or verify rolls back
(the old secret stays valid) and keeps the item on the rotation list with the reason; a success
takes it off. A failed revoke is reported as `old_alive`. Values never leave the daemon; errors
of a module are reduced to the exception type. A fresh backup is required. Items without a
matching module are reported, not touched. An item belongs to the first module that matches.

No module is on by default. Each is switched on by its `*_ITEMS` variable, a comma-separated list
of item names.

**Consumers.** Several modules hand the new value to consumers: `*_CONSUMERS` is the path of a
JSON file with a list of `{"name": ..., "cmd": ...}`. The command runs without a shell and gets
the value on stdin. An optional `"items": [...]` limits a consumer to those vault item names, so
one person's key never reaches a shared consumer.

### API tokens

| Module | Enable with | What it does |
|---|---|---|
| OpenRouter ([`openrouter.py`](../src/vw_vault/openrouter.py)) | `VW_VAULT_OPENROUTER_ITEMS`; `VW_VAULT_OPENROUTER_CONSUMERS`; `VW_VAULT_OPENROUTER_MASTER` | The provisioning key (login `OPENROUTER_PROVISIONING_KEY`, or the name in `_MASTER`; exactly one live item) creates a new API key under the item's name with the same limit. The vault item and the consumers get it, a call with the new key checks it, and the old key is deleted by name and must stop working |
| Cloudflare ([`cloudflare.py`](../src/vw_vault/cloudflare.py)) | `VW_VAULT_CLOUDFLARE_ITEMS`; `VW_VAULT_CLOUDFLARE_CONSUMERS`; `VW_VAULT_CLOUDFLARE_MASTER` | The manager token (login `CLOUDFLARE_API_TOKENS_EDIT`, or `_MASTER`; permission API Tokens: Edit) creates a copy of the item's token (same name, policies, condition and expiry; the old token is found by verifying its value) instead of a roll, which would kill the old value with no way back. The vault item and the consumers get it, the token verify call checks it, the old token is deleted and must stop working |
| GitLab ([`gitlab.py`](../src/vw_vault/gitlab.py)) | `VW_VAULT_GITLAB_ITEMS`; `VW_VAULT_GITLAB_CONSUMERS`; `VW_VAULT_GITLAB_URL` (default https://gitlab.com) | The item's personal access token rotates itself through the API (needs the `api` or `self_rotate` scope) and keeps the old lifetime, capped at 365 days. GitLab revokes the old token inside the rotate call, so a failed distribute or verify cannot go back: the new value is written again to every place and stays alive, and the result says so if that fails too |
| GitHub App ([`github_app.py`](../src/vw_vault/github_app.py)) | `VW_VAULT_GITHUB_APP_ITEMS`; `VW_VAULT_GITHUB_APP_CONSUMERS`; `VW_VAULT_GITHUB_APP_INSTALLATION` | The item is a login (app id as username, private key PEM as password) or a secure note (PEM in the notes, field `APP_ID`). The daemon signs a JWT, gets an installation token for an hour (the installation in `_INSTALLATION`, or the app's only one) and hands it to the consumers. A GitHub consumer may also name an `account` (picks the installation), `repositories` and `permissions` (a narrower token). The token is checked with the API; the item is not rewritten and the old token is not revoked (it expires by itself); a failed check revokes the new token |

### Passwords over SSH

[`src/vw_vault/ssh.py`](../src/vw_vault/ssh.py) (`SshPasswordRotator`) is the shared base for
modules that change an account password over SSH. One run: log in with the old password, set
the new one (the value goes to the stdin of `change_cmd`, `chpasswd` by default,
`stdin_template` for other tools), log in with the new one, check that the old one is refused,
write the new value to the vault item. A failure at any step puts the old password back on the
host and in the vault item; a host that cannot be reset is reported in `rollback_error`. The
transport is `sshpass -e ssh` (password by environment, never argv) and is replaceable, which
the tests use to stand in for a host.

All password and key transports run `ssh -F /dev/null`: the owner's `~/.ssh/config` (its
`Match`, proxy and agent rules) never applies; host keys still come from `~/.ssh/known_hosts`. A
host takes a port as `host:port` (`192.0.2.20:2222`; IPv6 as `[addr]:port`). Every vault write
edits the latest known version of the item, so a rollback after a failed check is accepted by
Vaultwarden.

| Module | Enable with | What it does |
|---|---|---|
| Pi-hole ([`pihole.py`](../src/vw_vault/pihole.py)) | `VW_VAULT_PIHOLE_ITEMS` and `VW_VAULT_PIHOLE_HOST`; `VW_VAULT_PIHOLE_SSH_USER` (default root); `VW_VAULT_PIHOLE_URL` (default `http://<host>`) | The item holds the Pi-hole web password. The daemon runs `pihole setpassword` on the host over key-based SSH (value on stdin), signs in to the API with the new password, checks that the old one is refused, and writes the vault item |
| Proxmox ([`proxmox.py`](../src/vw_vault/proxmox.py)) | `VW_VAULT_PROXMOX_ITEMS` and `VW_VAULT_PROXMOX_HOST`; `VW_VAULT_PROXMOX_MODE` | `password` (default): `chpasswd` on the node as the item's username (default root), value on stdin. `key`: the item password holds an ed25519 private key; the new public key replaces the account's `authorized_keys`, so one managed key per account. Either way the daemon logs in with the new secret and checks that the old one is refused |
| MikroTik ([`mikrotik.py`](../src/vw_vault/mikrotik.py)) | `VW_VAULT_MIKROTIK_ITEMS` and `VW_VAULT_MIKROTIK_HOST` | The item username is the RouterOS user. The daemon runs `/user set` over SSH, then logs in with the new password **before** writing the vault item: RouterOS exits 0 even on a rejected command, so only a real login counts. A value or username with characters that cannot be quoted safely is refused. RouterOS has no stdin for this command, so the value is on the ssh command line for the moment of the call |
| Backup repository ([`backup.py`](../src/vw_vault/backup.py)) | `VW_VAULT_BACKUP_ITEMS` and `VW_VAULT_BACKUP_HOST`; `VW_VAULT_BACKUP_TOOL` (`restic` default, or `borg`); `VW_VAULT_BACKUP_REPO` or the item field `repo`; `VW_VAULT_BACKUP_SSH_USER` (default root) | The item password is the repository password. The daemon opens the repository with the old password, changes it (old and new on stdin, never argv), opens it with the new one, and only then writes the vault item. The check is opening the repository, not a restore |

The Pi-hole, MikroTik and backup modules are tested against mocks only; do the first run on a
host where a lockout is easy to undo.

## Self-generated secrets and Cloudflare tunnel tokens

Two modules for secrets no issuer hands out. Both are off until the daemon is pointed at a JSON
file; no secret is listed by default, and the files hold names and commands, never values (a
stray key such as `value` makes the daemon refuse the file at start). Both are tested on mocks
only.

**What rotates.** [`selfgen.py`](../src/vw_vault/selfgen.py) rotates secrets an application makes
up itself (an admin token, a signing key): the daemon generates the value.
[`cf_tunnel.py`](../src/vw_vault/cf_tunnel.py) rotates the token of a remotely managed
Cloudflare tunnel through the tunnels API. Items are matched by name **and** collection (the
collection the application reads), so a same-named item elsewhere is never touched.

**How to enable.**

```
VW_VAULT_SELFGEN_CONFIG=~/.config/vw/selfgen.json   # self-generated secrets
VW_VAULT_CF_TUNNELS=~/.config/vw/cf-tunnels.json    # tunnel tokens
VW_VAULT_CF_TUNNELS_MASTER=CLOUDFLARE_TUNNEL_EDIT   # optional: login of an API token with Cloudflare Tunnel: Edit
```

`selfgen.json` is a list of entries:

```json
[{"name": "MYAPP_ADMIN_TOKEN", "collection": "my-app", "length": 48, "alphabet": "alnum",
  "consumers": [{"name": "env-file", "cmd": "ssh root@app-host tee /etc/myapp/admin-token"}],
  "restart": "ssh root@app-host systemctl restart myapp",
  "check_url": "http://app-host:8000/api/health", "check_retries": 5, "check_delay": 3,
  "precheck_cmd": "optional command; the new value on stdin, exit 0 to accept"}]
```

`name` and `collection` are required. `alphabet` is `alnum` (default), `hex` or `urlsafe`;
`length` 32 to 256 (default 48). A check is mandatory: `check_url` (any 2xx) and/or `check_cmd`
(new value on stdin, exit 0). `consumers` and `restart` are optional commands without a shell;
the value goes to the stdin of consumers only. The vault item in the collection is always
written: it is what the application reads on start.

`cf-tunnels.json`: a list of `{"item", "collection", "account_id", "tunnel_id", "restart",
"consumers", "check_url", "check_retries", "check_delay", "owner_consent"}`. The first five are
required; `restart` restarts cloudflared with the new token; `check_url` is an optional public
hostname that must answer 2xx.

**One run.** Generate (or, for a tunnel, set a new tunnel secret and fetch the token), then judge
the new value **before the first write**: length, alphabet, differs from the old one, the
optional `precheck_cmd` (a tunnel token must decode to the same account and tunnel and carry the
new secret). Then: write the vault item, run the consumers, restart, check (the tunnel: a
connector that did not exist before the restart is connected, then the hostname). A refused
value or a failed check leaves the old value in place. A success has nothing to revoke at an
issuer.

**Only with the owner's explicit consent.** Some secrets cost something to rotate: a new session
signing key signs every user out. An entry with `"requires_consent": true` is refused until it
also has `"owner_consent": true` (a real boolean). A deployment can also list names that always
need consent in `OWNER_CONSENT_ONLY` in `selfgen.py`, which the file cannot switch off (empty by
default). A refused entry does nothing (no value generated, no call, no write) and the reason
lands in the result, the journal and the rotation list. Tunnel tokens always need
`owner_consent`: the old token dies at once, restarting cloudflared drops the tunnel, and the
vault itself may be served through it. Give consent for one run and remove the flag afterwards.

**Risks.**
- The consumer is restarted: expect a short outage. For tunnel tokens that includes the vault
  when it is reached through the tunnel: set `VW_VAULT_LAN_URL`; the vault item is written
  first, while the tunnel still runs, and the restart comes last.
- Tunnel: the secret changes at Cloudflare before the new token is stored anywhere. If the API
  does not take the new secret, the module puts the old one back and writes nothing; if even
  that fails, the error says so and the secret has to be restored by hand. Do the first run on a
  spare tunnel.
- A secret that others hold a copy of (a session key, a token in a client) breaks for them; list
  every consumer.
- Values never leave the daemon: results, the journal and logs carry stage names, consumer names
  and the module's own error sentences, no values and no command output.

**How to roll back.** A failed run rolls back by itself: the old value returns to the vault item
and every consumer in reverse order, the consumer is restarted and checked on the old value (a
tunnel also gets its old secret back at Cloudflare first). What could not be restored is named in
`rollback_error` and the item stays on the rotation list. After a successful run the way back is
the vault backup the daemon takes before each rotation (`VW_VAULT_BACKUP_CMD`): restore the item
from it, put the old value on the consumers, restart. For a tunnel the old token holds the old
secret: set it again with a PATCH of `tunnel_secret` and restart cloudflared.

## Unlock with a security key

`vw-vault unlock --enroll` unlocks with the master password once, then registers FIDO2 security
keys (USB or NFC; one after another, any number). The password is encrypted for each key with a
key from the WebAuthn PRF (hmac-secret) extension and stored in
`~/.local/state/vw/vault/fido-unlock.json` (0600). From then on `vw-vault unlock` asks for the
key's PIN and a touch instead of the password; with no key at hand it falls back to the
password. `vw-vault forget-keys` drops the file.

Nothing that runs as the owner can decrypt the file without the physical key, its PIN and a
touch, so an agent still cannot unlock the vault by itself. A plain keyring entry would not give
that: any process of the user reads it.

## Login checks

An optional module ([`src/vw_vault/logins.py`](../src/vw_vault/logins.py)), off by default, that
answers "does this site still accept the password in the vault?" for a few sites the owner
chose. A headless browser inside the daemon opens the site, types the item's login and password,
and the daemon reduces what happened to one status. The agent never starts a run and sees only
statuses. It has been tested against a fake browser only.

### Turning it on and running it

1. Install the extra and the browser once on the owner's workstation:
   `uv tool install 'blind-vault-mcp[login-checks] @ git+https://github.com/ai2sky/blind-vault-mcp'`,
   then `uvx --from 'blind-vault-mcp[login-checks] @ git+https://github.com/ai2sky/blind-vault-mcp' playwright install chromium`
   (the same package spec, so the browser matches the Playwright version).
2. Write `~/.config/vw/login-checks.toml` (or the path in `VW_VAULT_LOGIN_CHECKS_FILE`; format
   below). Without the file, without the extra, or with `VW_VAULT_LOGIN_CHECKS=0`, the module is
   off: `vw-vault check logins` answers "login checks are off: <reason>" and opens no browser.
3. `vw-vault unlock` shows the sites and the hash of the file and asks for confirmation when the
   file is new or changed (the confirmed hash is kept in `login-checks-confirmed.json`, no
   values). It then asks for a check phrase (twice; empty keeps the checks off). The daemon keeps
   only a salted scrypt hash of it in memory.
4. `vw-vault check logins --dry-run` first (opens the login page, finds the fields, submits
   nothing: status `form_found`), then `vw-vault check logins`. It needs an interactive terminal
   and asks for the check phrase on the tty. The daemon socket has no caller identity, so the
   daemon itself refuses `check_logins` without that phrase: a raw socket request or
   `vw-vault call check_logins` (refused by the CLI as well) does not start a run. An agent
   calling `vault_check("logins")` gets a refusal with this hint.

Results: `check-logins.json` (statuses, fingerprints), the journal, and
`login-checks-state.json` (last check and pause reason per site; the owner clears a pause by
editing it).

### Statuses

| Status | Meaning |
|--------|---------|
| `works` | Signed in (or the site accepted the password and stopped at 2FA, where the profile says so) |
| `wrong_password` | The site says the password is wrong for this account |
| `account_missing` | The site says there is no such account |
| `rejected` | The site refused the pair and does not say which part is wrong (many sites hide it on purpose) |
| `needs_human` | 2FA prompt, captcha, "verify it's you", e-mail confirmation, a terms page: the check stops and does nothing more |
| `unknown` | The page matched none of the markers of the site's profile; nothing is guessed |
| `refused` | The daemon's own guard stopped it: origin not on the list, redirect to another host, no HTTPS |
| `skipped` | Paused or too soon after the last attempt |
| `error` | Network or engine failure; only the exception type is kept |
| `form_found` | Dry run: the form was found, nothing was submitted |

What keeps this safe is where the value goes. It is decrypted in the daemon (as it already is
for rotation), typed into the one form of one allowed site, and goes nowhere else: not into the
result, the journal, a screenshot, an agent answer or a child process argument. This is the same
boundary as the rotation modules, with the browser as one more consumer.

### Which sites are allowed

An allow list in the config file, never "all items". No secrets in it; the daemon reads it only
at unlock:

```toml
[[site]]
name  = "router"                 # a label for results
item  = "ROUTER_ADMIN"           # one vault item, by exact name (not a query, not a folder)
origin = "https://router.example.com"   # scheme and host; the login page is origin + login_path
login_path = "/admin/login"
fields = { user = "", password = "input[type=password]" }   # selectors of the form
ok     = { url_not_contains = "/login" }                    # what a success looks like
bad    = { text_any = ["Wrong password"] }                  # what a refusal looks like
distinguishes_account = false    # true only when the site says "no such account" apart
min_interval_days = 30
```

An entry also accepts `missing = { text_any = [...] }` for sites that say "no such account".

Rules the daemon enforces before it types anything:

- The item must be named in the file, and its URI host must equal the entry's host exactly
  (same origin, no suffix match). An item that was edited to point at a look-alike domain is
  refused, which is the main defence against sending a password to the wrong place.
- HTTPS only, valid certificate, no redirect to another host before the form is filled; once the
  password field holds a value, any request to a host outside the entry is aborted.
- No profile means no check. The daemon never guesses selectors for a site.
- Never allowed, whatever the file says (a built-in deny list in `logins.py`): banks and payment
  services, government services, mail providers, identity providers, registrars, the
  Vaultwarden/Bitwarden servers. A lockout there costs more than the knowledge is worth.
- The file is the owner's decision, so the agent must not be able to widen it unseen. A change to
  the file is shown by `vw-vault unlock` and takes effect only after the owner confirms it in
  their own terminal. No MCP tool can edit the file or start a different list.

### Rate limits

The site is someone else's and treats each failed attempt as a signal:

- One attempt per item per run, no retries. A failure is a result, not a reason to try again.
- At least 30 days between checks of one item (`min_interval_days`; a lower value in the file is
  raised to 30), and no scheduler: the daemon lives only while the owner is unlocked, and a run
  starts only when the owner asks.
- One site at a time, 60 seconds plus random jitter between sites, at most 5 items per run.
- A circuit breaker per site. `needs_human`, `rejected`, `wrong_password` on a login that worked
  last time, HTTP 429 or 403, or text about a lock or "unusual activity" pauses that site until
  the owner clears it in `login-checks-state.json`. A paused site is reported as `skipped`.
- The attempts are journaled (site, status, time) so the owner can match a "new sign-in" mail to
  a check. The mail itself cannot be avoided.

### 2FA and captchas

Never bypassed. No captcha solver, no stealth plugins, no spoofed fingerprints, no TOTP typed
from the item, no reading of mail for a code. The check stops at the first of: a 2FA field
(`autocomplete=one-time-code`, a known 2FA field name), a captcha frame or script (reCAPTCHA,
hCaptcha, Turnstile), an "unusual activity" page, or a terms wall, and reports `needs_human`.
Only on a site whose profile says the 2FA prompt appears after a correct password does stopping
at the prompt count as `works`, with the note `stopped_at_2fa`.

### Values in logs and reports

- Result record: item id, label, host, status, time, and an HMAC fingerprint of the login and
  password pair under the key that dies with the daemon.
- The browser runs with no screenshots, traces, videos, HAR files, console capture or page text
  in anything the daemon stores or returns. The profile is a fresh directory in a private
  temporary location (0700), deleted after every run; no cookies, extensions or saved passwords.
- Errors are reduced to the exception type, because automation libraries put call details in
  their messages.
- A request or response that carries a vault value is refused, as everywhere in the daemon.

### Where it runs, and turning it off

It runs on the owner's own workstation, inside the daemon the owner unlocks, and only there: not
in CI or on a server. A login from the owner's usual address is the least surprising to a site.
The browser is a child process of the daemon; `vw-vault lock` and the idle exit end it.

Removing the file (or `VW_VAULT_LOGIN_CHECKS=0`) and unlocking again turns the module off. The
check changes nothing in the vault, so there is nothing to restore there; what cannot be undone
is the effect at a site (a lockout, a notification mail), which is why the limits and the
circuit breaker exist. A `wrong_password` never touches the rotation list by itself, since the
site may have changed its form; the owner decides on rotation.

### Rolling out

1. A dry run on any allowed site: it proves the engine, the guard and the profile.
2. A site the owner runs (a router or a self-hosted admin page), so a lockout can be undone at
   once and there is no captcha or 2FA.
3. One low-stakes third-party site with a plain form: the item has no TOTP, the `twofa` check
   says the site offers none, the `urls` check shows it alive, and it is not on the deny list.
   The agent can list candidates from the `urls` and `twofa` results without a value, for the
   owner to pick.
