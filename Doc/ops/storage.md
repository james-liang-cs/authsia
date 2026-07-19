# Storage Mechanism

## Table of Contents

- [Overview](#overview)
- [Application and Runtime Paths](#application-and-runtime-paths)
- [OTP Accounts](#otp-accounts)
- [Vault Items](#vault-items)
- [Synchronization](#synchronization)
- [Load and Cleanup Behavior](#load-and-cleanup-behavior)
- [Import and Export](#import-and-export)
- [CLI and SSH Access](#cli-and-ssh-access)
- [Audit Logs](#audit-logs)
- [Operational Rules](#operational-rules)

## Overview

Authsia separates secrets from metadata.

- Secrets are stored in Apple Keychain.
- Live app metadata is JSON-encoded and stored in Keychain.
- The CLI metadata snapshot is the only current on-disk JSON metadata cache.
- Repositories combine metadata and secrets only when a caller needs a full item.

This keeps list views fast and avoids exposing secret bytes during normal UI
rendering. The main implementation lives in `Packages/AuthenticatorData`.

## Application and Runtime Paths

The tables below list Authsia-owned macOS filesystem paths used by the app,
helpers, CLI, and optional browser integration. `~` means the current user's
home directory. These paths are separate from the Keychain services described in
later sections.

Authsia does not currently maintain a dedicated `~/Library/Logs/Authsia` or
`~/Library/Caches/Authsia` directory. File-backed operational logs live under
Application Support unless noted otherwise.

### Installed App and Helper Binaries

| Path | Owner | Purpose |
|---|---|---|
| `/Applications/Authsia.app` | User install / Sparkle | Canonical installed macOS app bundle for direct distribution. |
| `/Applications/Authsia.app/Contents/MacOS/Authsia` | App bundle | GUI app executable and background-activity unregister entry point. |
| `/Applications/Authsia.app/Contents/Helpers/authsia` | App bundle | Bundled CLI helper. It has no vault Keychain entitlement and talks to the bridge for secrets. |
| `/Applications/Authsia.app/Contents/Helpers/AuthsiaHeadless.app` | App bundle | Nested helper app used for headless bridge and SSH-agent roles. |
| `/Applications/Authsia.app/Contents/Helpers/AuthsiaHeadless.app/Contents/MacOS/authsia-headless` | App bundle | Executable launched by the bridge and SSH-agent LaunchAgents. |
| `~/.local/bin/authsia` | App Settings / install scripts | Preferred user-local symlink to the bundled CLI helper. |
| `/usr/local/bin/authsia` | App Settings / legacy install scripts | Optional system symlink to the bundled CLI helper. |
| `/opt/homebrew/bin/authsia` | App Settings | Optional Homebrew-prefix symlink candidate for the bundled CLI helper. |

### LaunchAgent Plists

| Path | Owner | Purpose |
|---|---|---|
| `/Applications/Authsia.app/Contents/Library/LaunchAgents/Authsia.Bridge.plist` | App bundle | Signed bundled bridge plist registered by `SMAppService.agent(plistName:)`. It declares label and Mach service `Authsia.Bridge`, sets `AUTHSIA_ROLE=bridge`, and runs `authsia-headless`. |
| `~/Library/LaunchAgents/Authsia.SSHAgent.plist` | App runtime | Per-user generated SSH-agent LaunchAgent. It is written only when the SSH agent is enabled, because its socket path must include the current user's home directory. It sets `AUTHSIA_ROLE=ssh-agent`, runs `authsia-headless`, and owns `~/.authsia/agent.sock` through launchd socket activation. There is no checked-in source plist for this generated file. |

### Application Support, Preferences, and Logs

| Path | Owner | Contents |
|---|---|---|
| `~/Library/Application Support/Authsia/CLI/vault_metadata_snapshot.json` | App / bridge | Non-secret CLI metadata snapshot for vault list and lookup fallback. |
| `~/Library/Application Support/Authsia/bridge_audit.log` | Bridge / SSH agent | HMAC-chained audit log for sensitive bridge requests and SSH signing. |
| `~/Library/Application Support/Authsia/agent-jit-grants.json` | App bridge | Agent JIT grants approved in Access Center. |
| `~/Library/Application Support/Authsia/AgentRuntimeContext/events.jsonl` | Optional agent hook scripts / CLI | Short-lived agent attribution events read by the CLI when building bridge request context. |
| `~/Library/Preferences/app.authsia.plist` | UserDefaults | App preferences domain for CLI access, CLI and SSH session TTLs, SSH-agent opt-in state, iCloud Keychain sync preference, interface settings, and registration identities. macOS may cache this through `cfprefsd`. |

### `~/.authsia` Runtime State

| Path | Owner | Contents |
|---|---|---|
| `~/.authsia/agent.sock` | SSH-agent LaunchAgent | Unix-domain socket used by `git`, `ssh`, and shell integration via `SSH_AUTH_SOCK`. |
| `~/.authsia/cli-session-status.json` | Bridge | Current bridge session status for `authsia status` and Developer Control Center display. |
| `~/.authsia/ssh-agent-session.json` | SSH agent | Current SSH approval-session status. |
| `~/.authsia/ssh-automation-grants.json` | App / bridge / CLI | Temporary SSH automation grants tied to automation credentials. |
| `~/.authsia/access-credentials.json` | CLI / bridge | Automation access credentials created by `authsia access`. The bridge re-validates this file server-side. |
| `~/.authsia/environment-profiles.json` | CLI | `authsia env` profiles and the active profile name. |
| `~/.authsia/machine.json` | CLI / app import flows | Stable machine UUID and hostname used for multi-machine provenance. |
| `~/.authsia/session.json` | Legacy CLI | Legacy plaintext session cache. Current builds migrate valid entries into terminal-scoped Keychain records and remove this file. |

### Optional Browser and Temporary Paths

| Path | Owner | Purpose |
|---|---|---|
| `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.authsia.nativehost.json` | Optional native-host installer | Chrome native messaging manifest for `com.authsia.nativehost`. |
| `/tmp/authsia-native.log` | Native host debug mode | Debug-only native-host log written only when `AUTHSIA_DEBUG` is set. |
| `${TMPDIR}/authsia-askpass-<UUID>.sh` | CLI `authsia load ssh --system-agent` flow | Transient `SSH_ASKPASS` helper script. It contains no passphrase and is removed after `ssh-add` exits. |

Authsia can also modify user-chosen files when a user explicitly asks it to,
for example shell profile files for shell integration, SSH config files for
`authsia ssh config`, Git config and `.git/authsia/allowed_signers` for Git
signing setup, selected `.env` files during scrape/rewrite flows, and explicit
`--out-file` destinations. Those are user/project files, not Authsia-owned
application storage.

## OTP Accounts

OTP account secrets use `KeychainStore`.

Current Keychain service:

```text
com.authsia.service
```

Secret item account key:

```text
<account UUID>
```

Account metadata uses `MetadataStore`. It is JSON-encoded and saved through
`KeychainStore` with these account keys:

```text
account_metadata
account_folders
account_deletion_tombstones
```

On load, `MetadataStore` reads these Keychain records. Historical Documents
filenames such as `accounts_metadata.json` and `accounts_folders.json` may still
appear in older builds or code paths, but they are not the current live metadata
store.

## Vault Items

Vault secrets use `VaultKeychainStore`.

Current Keychain service:

```text
com.authsia.vault
```

Legacy Keychain service still read for migration/backfill:

```text
com.authenticator.vault
```

Secret account key prefixes:

| Item type | Keychain account key |
|---|---|
| Password | `password-<item UUID>` |
| API key | `apikey-<item UUID>` |
| Certificate data | `cert-<item UUID>` |
| Certificate private key | `certkey-<item UUID>` |
| Secure note content | `note-<item UUID>` |
| SSH public key | `sshpub-<item UUID>` |
| SSH private key | `sshpriv-<item UUID>` |
| SSH passphrase | `sshpass-<item UUID>` |

Vault metadata uses `VaultMetadataStore`. It is JSON-encoded and saved into the
synced Keychain metadata service:

```text
com.authsia.vault.metadata
```

The local fallback metadata service is:

```text
com.authsia.vault.metadata.local
```

Metadata account keys:

```text
vault_passwords_metadata
vault_api_keys_metadata
vault_certificates_metadata
vault_notes_metadata
vault_sshkeys_metadata
vault_folders
```

The app can also save a non-secret CLI metadata snapshot at:

```text
~/Library/Application Support/Authsia/CLI/vault_metadata_snapshot.json
```

This snapshot contains only list-safe metadata: names, folders, timestamps,
CLI flags, scrape provenance, public SSH metadata, and folder paths. It must
not contain password values, note contents, certificate bytes, private keys, or
passphrases. The snapshot exists so the bridge can still list and locate vault
items when live metadata has been rebuilt or pruned differently from the CLI's
last known IDs.

## Synchronization

`KeychainSyncSettings.iCloudKeychainSyncEnabledKey` controls whether Authsia
writes iCloud-synchronizable Keychain records. The setting is disabled by
default.

When sync is disabled, `KeychainStore`, `VaultKeychainStore`, and
`VaultMetadataStore` write local Keychain records only:

```text
kSecAttrSynchronizable = false
```

Reads prefer the local record. They may still read an existing synchronizable
record as a recovery fallback and backfill the local record, but disabled sync
does not delete synchronizable records.

When sync is enabled, the stores write both preferred Keychain variants:

```text
kSecAttrSynchronizable = true
kSecAttrSynchronizable = false
```

The synced item is the primary copy. The local item is a fallback for cases
where iCloud Keychain is temporarily unavailable. On retrieval, enabled sync
tries the synced item first. If the synced item is found, it keeps the local
fallback up to date. If only the local fallback is found, it backfills the
synced item.

For vault secrets, `VaultKeychainStore` also tries the legacy
`com.authenticator.vault` service after the current `com.authsia.vault`
service. A legacy hit is backfilled into the current service. This migration
path is intentionally in the secret retrieval layer, not the metadata layer:
metadata can survive a namespace migration even when the matching secret is
still stored under the old service.

The same toggle applies to live metadata. OTP metadata uses `KeychainStore`.
Vault metadata uses `com.authsia.vault.metadata` for the synchronizable copy
and `com.authsia.vault.metadata.local` for the local copy.

Deletions of any vault item type also write non-secret tombstones under
`vault_password_deletion_tombstones`, `vault_api_key_deletion_tombstones`,
`vault_certificate_deletion_tombstones`, `vault_note_deletion_tombstones`, and
`vault_ssh_key_deletion_tombstones`. Each tombstone contains only the deleted
item UUID and deletion time. When local and synchronizable metadata disagree,
a tombstone suppresses metadata that is not newer than the deletion, so an
offline device's stale local fallback cannot restore a converted or deleted
item. Repository loading retries removal of any tombstoned local or
synchronizable secret without returning its value. An explicit later restore
of the same UUID is stamped newer than the tombstone and remains visible. A
subsequent deletion is in turn stamped strictly newer than the current item,
so deleting immediately after a restore still wins. The enable-sync copy
filters collected items against every tombstone set, then reloads deletion
intent after copying secrets, re-filters metadata, and reaps any secret covered
by a deletion that arrived during the copy. It re-saves the latest tombstones
through the sync-enabled write policy, so a stale device enabling sync cannot
reintroduce deleted items.

OTP account deletions write the same kind of tombstone under
`account_deletion_tombstones`, with `lastUsed` as the freshness timestamp.
Account metadata loads filter each stored candidate against tombstones before
choosing the preferred value for an account ID, and saves merge all visible
candidates, so a stale whole-blob write cannot erase or resurrect accounts.

Tombstone loads merge every stored candidate; when a writable candidate is
missing or lacks entries the union has, the union is re-saved through the
current write policy, so deletion intent survives iCloud Keychain whole-item
conflict resolution on another device without repeatedly rewriting a
read-only fallback while sync is disabled.

Enabling sync from Settings first collects the current local-first account and
vault records, then saves those records through a scoped sync-enabled write
policy. The persisted preference is turned on only after that copy succeeds.
Turning sync off only changes future write policy; it does not delete local or
synchronizable records.

## Load and Cleanup Behavior

List views load metadata first and do not retrieve secret bytes for normal rows.
Full item access happens only through repository methods such as:

- `getFullAccount(metadata:)`
- `getFullPassword(metadata:)`
- `getFullCertificate(metadata:)`
- `getFullNote(metadata:)`
- `getFullSSHKey(metadata:)`

After Keychain namespace or access-group changes, old metadata can survive while
the matching secret is no longer available in the current Keychain namespace.
`VaultRepository.load()` performs a one-time per-repository validation pass to
prune these stale vault rows.

That validation uses lightweight Keychain existence queries:

- `containsPassword(for:)`
- `containsCertificate(for:)`
- `containsNoteContent(for:)`
- `containsSSHKey(for:)`

These checks use `SecItemCopyMatching` with `kSecMatchLimitOne` and do not return
secret data. They also avoid the normal retrieve path's fallback backfill writes.
After the first validation pass, later loads on the same repository instance
read metadata directly to avoid repeated main-thread Keychain work.

`VaultRepository.load()` and every repository mutation also write the non-secret
CLI metadata snapshot automatically. The Vault UI does not expose a manual
rebuild action; if `authsia list ...` is empty while the app UI shows rows,
verify `authsia status`, relaunch the current app build to force a vault load,
and inspect bridge logs if the list remains empty.

## Import and Export

Exports reconstruct full items by loading metadata and then retrieving each
selected item's secret from Keychain. Items whose secrets cannot be retrieved are
logged and skipped.

Imports decode backup data into full item models and save secrets before
metadata. The stale metadata cleanup matters before import because stale rows can
otherwise look like duplicate IDs and cause `keepExisting` imports to skip the
backup item.

## CLI and SSH Access

The macOS XPC bridge reads from the same repositories and Keychain stores as the
app. On macOS, launchd runs that bridge through the nested
`AuthsiaHeadless.app` helper bundle:

```text
/Applications/Authsia.app/Contents/Helpers/AuthsiaHeadless.app/Contents/MacOS/authsia-headless
```

That helper carries the app bundle identifier, embedded provisioning profile,
and app Keychain access group. The standalone CLI helper at
`Contents/Helpers/authsia` has no vault Keychain entitlements and must reach
secrets only by talking to the bridge. CLI reads still require bridge approval
unless an active session or authorized automation credential applies.

For non-secret list output, the bridge uses live metadata first and falls back
to the CLI metadata snapshot only when live metadata for that item kind is
empty. For secret lookup by ID, the bridge merges any snapshot rows whose IDs
are missing from live metadata before calling `VaultKeychainStore`. This keeps
`authsia load password --folder ...` aligned with `authsia list passwords`
without ever storing secret bytes in the snapshot.

The SSH agent advertises only CLI-enabled SSH metadata whose current Keychain
public and private key entries exist. Identity listing uses the lightweight
`containsSSHKey(for:)` check and does not read private key bytes. The private key
is retrieved only for the selected sign request after policy and approval checks
allow signing.

## Audit Logs

Bridge and SSH-agent access events are written to the local audit log:

```text
~/Library/Application Support/Authsia/bridge_audit.log
```

This is not a general GUI activity log, and it does not record every CLI
command. Current producers are `XPCRequestHandler` for selected sensitive bridge
requests such as unlock, secret reads, and account export, plus
`SSHAgentListener` for SSH-agent signing. Routine status, doctor, list, and
GUI-only browsing/editing flows are outside this log unless code explicitly
records a `BridgeAuditRecord`.

In this scope, a "secret read" means a bridge request that retrieves Keychain
secret bytes, such as `getOTP`, `getPassword`, `getCertificate`, `getNote`, or
`getSSH`. The audit record describes the access event only; it does not store
the returned secret bytes.

Current CLI-facing audit scope:

| Surface | Secret read? | Audit record? | Notes |
| --- | --- | --- | --- |
| `authsia list ...` | No | No | Uses list-safe metadata. A list request can still require approval, but it is not written to `bridge_audit.log`. |
| `authsia get ...` | Yes | Yes | Records the underlying `getOTP`, `getPassword`, `getCertificate`, `getNote`, or `getSSH` bridge request with `requestedCommand=get`. Current `get*` bridge calls retrieve the item payload even when the CLI prints only one field. |
| `authsia load password/api-key/cert/note ...` | Yes | Yes | The metadata selection `list` request is not audited. Each selected `get*` secret read is audited with `requestedCommand=load`. |
| `authsia load ssh` | No by default | No by default | The default path refuses direct SSH loading; normal SSH use should go through the built-in Authsia SSH agent. |
| `authsia load ssh --system-agent --ttl ...` | Yes | Yes | Reads the SSH private key through `getSSH` so it can be copied into an external `ssh-agent`; audited with `requestedCommand=load`. |
| `authsia exec ...` | Yes | Yes | Secret references are resolved before the child process starts. Each underlying `get*` secret read is audited with `requestedCommand=exec`. `exec` does not support SSH keys. |
| `authsia read ...` and `authsia code ...` | Yes | Yes | `read` resolves an `authsia://` reference through a `get*` request. `code` uses `getOTP`. |
| Built-in Authsia SSH-agent signing | Yes, for signing | Yes | Records `.sshAgentSign` after policy and approval checks. This is a signing event, not a `getSSH` export of the private key. |

Add, update, delete, and access-credential approval flows may require bridge
approval and may write Keychain or metadata state, but they are not currently
audit-log producers unless their code path explicitly calls `recordAudit`.

The log is newline-delimited JSON. Each line wraps a `BridgeAuditRecord` with an
entry schema version, the previous entry hash, and the current entry hash. The
current logger uses an HMAC-SHA256 hash chain so modifications, deletions, or
reordering can be detected by `authsia audit verify`.

The HMAC key is stored in the local Keychain:

```text
service: com.authsia.audit.hmac-key
account: audit-chain
```

The key uses the data-protection Keychain and
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. It is not synchronizable.

The audit log directory is created with `0700` permissions, and the log file is
created/appended with `0600` permissions. Normal writes append one line per
successful audited access. Integrity verification may rewrite older audit lines
to migrate legacy hash versions to the current schema while preserving the
records and chain order.

Audit records are operational metadata, not secret storage. They may include the
bridge command, item ID, item name, approval source, timestamp, caller identity,
requested CLI command, and SSH-agent requester/target-host context. They must
not include OTP seeds, passwords, note contents, certificate private keys, SSH
private keys, SSH passphrases, or other secret bytes.

`authsia audit list` and `authsia audit export` read this local log and format
the entries for operators. `authsia audit verify` asks the bridge to verify the
HMAC chain using the Keychain-stored HMAC key.

## Operational Rules

- Never store OTP seeds, passwords, note contents, certificate private keys, SSH
  private keys, or passphrases in metadata JSON.
- Never log secret bytes or seed material.
- The iCloud Keychain Sync toggle must never delete data.
- Delete flows must remove both synced and local Keychain variants.
- Data deletion must stay behind explicit delete actions such as item delete,
  folder delete, and Delete All Data.
- Do not reset data with `security delete-generic-password` alone; it can miss
  synchronizable iCloud copies.
- Do not add vault Keychain entitlements to the standalone CLI helper or a bare
  helper executable. Keychain-backed CLI and SSH access must run through the
  signed app or nested headless app bundle.
- If a backup import follows a namespace change, stale metadata must be pruned
  before duplicate detection runs.
