# The manager account and collections

All secrets live in Vaultwarden collections of one organization. Applications and CI read them
from there. The owner does not file entries into collections by hand: a manager account does it
through the `secrets` toolset of `blind-vault-mcp`. This page describes that setup. It never
contains real secret values.

**Only one account is set up by hand: the one that bootstraps the rest.** The accounts
applications read with are made by [`vw-service-account`](service-account.md), the collections
by `create_collection`, and read access by `grant_reader`. The steps through the web vault below
are the fallback for when a tool refuses.

**Contents**

- [The manager account](#the-manager-account)
- [Organization and collections](#organization-and-collections)
- [Limit the account to the collections it needs](#limit-the-account-to-the-collections-it-needs)
- [Variables](#variables)
- [Move existing secrets into collections](#move-existing-secrets-into-collections)

## The manager account

This account is what the tools themselves sign in as, so nothing can create it for you. Every
account after it (one per application, read access to one collection) is
`vw-service-account create <name>`; see [service-account.md](service-account.md).

- A dedicated Vaultwarden user, not the owner's personal account. It is a member of the
  organization with a role that can create and manage collections.
- An API key is issued for this account (Account settings, Security, View API key).
- Its credentials go into the OS keyring of the user that runs the server, under the service
  `VW_KEYRING_SERVICE` (default `vw-manager`):

  ```bash
  uvx keyring set vw-manager client_id         # user.xxxxxxxx-...
  uvx keyring set vw-manager client_secret
  uvx keyring set vw-manager master_password
  uvx keyring set vw-manager notify_token      # optional: bearer token for VW_NOTIFY_URL
  ```

  Each value is typed into a hidden prompt.
- Without a keyring, use files instead: the client id goes into `VW_CLIENT_ID`, the client
  secret and the master password into two files outside any repository, pointed to by
  `VW_CLIENT_SECRET_FILE` and `VW_MASTER_PASSWORD_FILE`. Keep both readable only by the user
  that runs the server (`chmod 600`). A variable that is set wins over the keyring entry.

`grant_reader` invites accounts into the organization and confirms them through the
Vaultwarden API as this account. If it fails at the invitation ("Vaultwarden API invite
failed"), the account's role is not allowed to invite members: raise the role, or invite and
confirm the member by hand once.

## Organization and collections

One organization holds the secrets. Inside it there is one collection per application or
purpose, for example:

| Collection | Purpose |
|------------|---------|
| `agents` | Secrets for agents and their pipelines. |
| `ci` | Tokens CI jobs need. |
| `my-app` | What the application `my_app` reads at start (see [service-account.md](service-account.md)). |

New collections are created with `create_collection(collection)`, not in the web interface,
which stays as the fallback. Collection names are matched exactly.

An account is given read access to a collection with `grant_reader(collection, account)`: an
account that is not in the organization yet is invited with that access and the invitation is
confirmed by the tool itself (a Vaultwarden without SMTP accepts the invitation of an existing
account on its own), so there is nothing to click. Inviting and confirming a member by hand is
the fallback.

## Limit the account to the collections it needs

The manager account should see only the collections it writes to:

1. In the organization, open Members and select the manager account.
2. Select **Limit access to selected collections** (not "access all collections").
3. Tick the collections it manages, with the "Can manage" permission, and save.
4. Any other collection stays invisible to the account and to the agent. Add a collection to
   the list only when a new purpose appears. If a collection the account created itself does
   not show up in `list_collections`, add it here.

The server never reads values (`list_items` returns names only), so the account's reach through
the agent is limited to writing, deleting and listing names in these collections.

## Variables

The names below are the ones read by
[`src/vw_server/client.py`](../src/vw_server/client.py):

- `VW_URL` (required): URL of the Vaultwarden server. There is no default.
- `VW_ORGANIZATION_ID` (required for the collection tools): id of the organization.
- `VW_CLIENT_ID`: API key client id of the manager account; else the keyring entry `client_id`.
- `VW_CLIENT_SECRET_FILE`: file with the API key client secret; else the keyring entry
  `client_secret`.
- `VW_MASTER_PASSWORD_FILE`: file with the master password; else the keyring entry
  `master_password`.
- `VW_KEYRING_SERVICE` (optional, default `vw-manager`): the keyring service of the entries
  above and of `notify_token`.
- `VW_COLLECTION` (optional): a fixed collection, for `vw-env` and the older `vw_set`/`vw_list`.
  `VW_ORGANIZATION_ID` and `VW_COLLECTION` are set together there; the collection tools take the
  collection per call and need only `VW_ORGANIZATION_ID`.
- `VW_FOLDER` (optional, default `agents`): personal folder, used by `vw-env` and the older
  tools only when no collection is configured.

## Move existing secrets into collections

Secrets that now sit in files and `.env` files move into collections without passing through
the chat:

1. Pick the target collection by purpose and create it if needed (`create_collection`).
2. Choose a name for each secret: a letter or `_` first, then letters, digits and `_`, up to 64
   characters (for example `GOOGLE_REFRESH_TOKEN`). Rename keys that do not fit, such as ones
   with `-` or `.`.
3. Write each secret with `set_secret(collection, name, from_file="/path/to/file")`, where the
   file holds the value alone; or the owner runs `vw-put <collection> <NAME>` and types it. Check
   with `list_items(collection)` that the name appeared.
4. Remove the secret from the file or `.env` only after the application or CI reads it from the
   collection successfully.

`set_secret` needs no per-write approval: a write that replaces a value first takes a backup
(`VW_BACKUP_CMD`), and every write is journaled and notified. `delete_secret` needs the owner's
code ([approval](approval.md)). See [the overview](overview.md#the-secrets-toolset-organization-collections).

The agent must not see the values it migrates. With `from_file` the server reads the file
itself; the agent passes only the path and never prints the file.
