# vw-service-account: the account a service reads its own secrets with

An application does not get its secrets handed to it at deploy time. It reads them itself: it
logs in to Vaultwarden as its own account `svc-<name>@<domain>`, which has read access to one
collection of the organization and to nothing else. `vw-service-account` creates that account.

This is the **first step** of the arrangement in [the manager account and
collections](manager.md), and it is not done by hand in the web vault.

```
vw-service-account create my_app                       the account and its API key
MCP: create_collection("my-app")                       the collection, if it is not there yet
MCP: grant_reader("my-app", "svc-my-app@example.com")  read access, invitation confirmed
vw-put my-app SOME_TOKEN                               the secrets themselves
vw-service-account check my_app                        the service signs in and lists what it sees
```

**Contents**

- [Commands](#commands)
- [What it writes](#what-it-writes)
- [Configuration](#configuration)
- [Granting access to the collection](#granting-access-to-the-collection)

## Commands

```bash
vw-service-account create <name> [--invited]
vw-service-account check  <name>
vw-service-account rotate <name>
vw-service-account import <name> "<item>" <vault_variable>
```

| Command | What it does |
|---|---|
| `create` | Invites `svc-<name>@<domain>` through the admin interface, registers it with a generated master password, issues an API key, and writes all four values into the Ansible Vault file. `--invited` skips the invitation and needs no admin token. |
| `check` | Logs in as the service with `bw` and prints the variables of its collection: names only, never values. The answer to "did the access actually work". |
| `rotate` | Issues a new API key for an existing account and writes it. The master password is unchanged. |
| `import` | Copies one item's password from the collection into a vault variable (`vault_<what>_<name>`), for deploy secrets the playbook needs before the application runs. |

The service name is lowercase letters, digits and `_`, starting with a letter. The collection
is that name with `_` replaced by `-`: `my_app` is the account `svc-my-app@...` reading the
collection `my-app`.

### `create --invited`: when the admin token is of no use

`create` normally needs the Vaultwarden admin token, because an invitation is what lets an
account register while self-registration is closed, and it sends that invitation through
`POST /admin`. Some setups keep the admin token in the vault file only **hashed**, the way
Vaultwarden itself wants it in `ADMIN_TOKEN`, and a hash cannot be used to sign in: `/admin`
answers 401 and `create` stops before anything is created.

The admin interface is only one way to send an invitation, though: `grant_reader` sends one too.
So invert the order: grant access first, create the account after.

```
MCP: create_collection("my-app")
MCP: grant_reader("my-app", "svc-my-app@example.com")   invites; reports the account has not accepted yet
vw-service-account create my_app --invited              registers, issues the API key
MCP: grant_reader("my-app", "svc-my-app@example.com")   confirms the now accepted member
vw-service-account check my_app
```

The first `grant_reader` sends the invitation and then stops with "account has not accepted the
invitation", because the account does not exist yet. After registration Vaultwarden (without
SMTP) accepts the invitation itself, and the second call confirms the member.

With the flag the command asks for no admin token and sends no invitation; everything else (the
pre-flight check on the vault file, the master password, the key, the four variables) is the
same. Run it only when the account really has been invited: without an invitation the
registration is refused.

### Registration on newer Vaultwarden

Older servers register an account with one `POST /identity/accounts/register`. Newer ones answer
it with 404 and register in two steps: `register/send-verification-email`, then
`register/finish` with the token. Without SMTP the server returns that token in the response
body, so `create` goes on by itself; with SMTP on it stops and says the token went by mail.

## What it writes

Four variables in the Ansible Vault file, the names the playbooks expect:

| Variable | Holds |
|---|---|
| `vault_<name>_bw_email` | `svc-<name-with-dashes>@<domain>` |
| `vault_<name>_bw_password` | The generated master password |
| `vault_<name>_bw_clientid` | `user.<id>` |
| `vault_<name>_bw_clientsecret` | The API key secret |

A host then reads the collection with [`vw-env`](overview.md#vw-env-read-a-collection-in-ci-and-on-hosts)
using those credentials. Nothing is printed and nothing reaches a chat: the command is the
owner's, run in their own terminal.

The file is created if it does not exist, so a new service needs no `vault.yml` made by hand.
Before anything is created the command checks that the file *can* be written: a master
password generated for an account and then not stored is unrecoverable, and the account would
have to be deleted through the admin interface and made again. If the check fails with "The
given address is empty", the shell cannot reach the keyring that holds the Ansible Vault
password; `export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus` and try again.

## Configuration

From the environment or `~/.config/vw/env` (`KEY=VALUE` lines):

- `VW_SERVICE_VAULT_FILE`, or `--vault-file`: the Ansible Vault file the keys go into.
- `VW_SERVICE_REPO`, or `--repo`: the directory `ansible-vault` runs in. Unset, it is the
  nearest directory above the vault file that holds an `ansible.cfg`: that config is what knows
  the vault password, often through a `vault-pass` script reading the keyring.
- `VW_ORG_DOMAIN` (required): the mail domain of the service accounts. There is no default: a
  wrong one would create an account that cannot be taken back.
- `VW_ADMIN_URL`, else `VW_URL`: the Vaultwarden API and admin interface. Every call carries
  `User-Agent: blind-vault-mcp/<version>`, because Cloudflare in front of a vault answers
  *Error 1010* (403) to the default Python one. If it still answers 1010, point this at the LAN
  address of the same server (plain HTTP: from the LAN only).
- `VW_BW_URL`, else `VW_URL`: the URL the `bw` CLI uses, which insists on HTTPS (`check`,
  `import`).
- `VW_ADMIN_TOKEN` (for `create` only): the Vaultwarden admin token. Unset, it is read from
  `vault_vaultwarden_admin_token` or `vault_vaultwarden_admin_token_raw` in the same vault
  file. It must be the raw token, not its hash; `create --invited` needs none of it.

`ansible-vault` must be installed; `check` and `import` also need the `bw` CLI.

Different repositories keep their vault files in different places, so each passes its own,
directly or through a thin wrapper script:

```bash
vw-service-account --vault-file ansible/inventory/group_vars/all/vault.yml create my_app
vw-service-account --vault-file deploy/inventory/prod/group_vars/all/vault.yml create other_app
```

## Granting access to the collection

`create` does not grant it: the account exists, but sees nothing. That is one MCP call:

```
grant_reader("my-app", "svc-my-app@example.com")
```

It invites the account to the organization with read-only access to that collection and
confirms the invitation itself (a Vaultwarden without SMTP accepts the invitation of an existing
account on its own), so there is nothing to do in the web vault. `check` is how you confirm it
worked; when it cannot find the collection it names the organizations and collections the
service can actually reach.
