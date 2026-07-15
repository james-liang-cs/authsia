# Authsia CLI Feature Spec (XPC Bridge Architecture)

## Table of Contents

- [Overview](#overview)
- [Architecture &amp; Security Model](#architecture-security-model)
- [Command Summary](#command-summary)
- [List: Items &amp; Output Fields (Includes Scraped)](#list-items-output-fields-includes-scraped)
  - [authsia load &lt;type&gt; \[&lt;query&gt;\] — Load vault values into runtime environment variables or ssh-agent](#authsia-load-type-query-load-vault-values-into-runtime-environment-variables-or-ssh-agent)
  - [authsia exec \[&lt;type&gt; \[&lt;query&gt;\]\] — Run a command with vault secrets injected and masked](#authsia-exec-type-query-run-a-command-with-vault-secrets-injected-and-masked)
  - [authsia read &lt;uri&gt; — Resolve a secret reference URI](#authsia-read-uri-resolve-a-secret-reference-uri)
  - [authsia code &lt;query&gt; — Generate a TOTP code](#authsia-code-query-generate-a-totp-code)
  - [authsia get &lt;type&gt; &lt;query&gt; — Retrieve a secret](#authsia-get-type-query-retrieve-a-secret)
- [Add/Edit/Delete: Item Types](#addeditdelete-item-types)
  - [authsia edit &lt;type&gt; &lt;query&gt; — Update an existing item](#authsia-edit-type-query-update-an-existing-item)
  - [authsia delete &lt;type&gt; &lt;query&gt; — Delete an item](#authsia-delete-type-query-delete-an-item)
  - [authsia unlock — Start a timed session](#authsia-unlock-start-a-timed-session)
  - [authsia lock — End the active session](#authsia-lock-end-the-active-session)
  - [authsia scrape — Scan for and migrate hardcoded secrets](#authsia-scrape-scan-for-and-migrate-hardcoded-secrets)
  - [authsia inject — Inject secrets into templates](#authsia-inject-inject-secrets-into-templates)
  - [authsia completion &lt;shell&gt; — Shell completions](#authsia-completion-shell-shell-completions)
  - [authsia agent init — AI-agent rule setup](#authsia-agent-init-ai-agent-rule-setup)
  - [authsia workspace — Repo-local secure workspace](#authsia-workspace--repo-local-secure-workspace)
  - [authsia access — Automation credentials](#authsia-access-automation-credentials)
  - [authsia env — Environment profiles](#authsia-env-environment-profiles)
  - [authsia ssh — SSH tooling](#authsia-ssh-ssh-tooling)
  - [authsia status — System health](#authsia-status-system-health)
  - [authsia doctor — Diagnostics](#authsia-doctor-diagnostics)
  - [authsia setup — First-run and repair](#authsia-setup-first-run-and-repair)
  - [authsia audit — Audit event access](#authsia-audit-audit-event-access)
- [Agentic AI Workflows](#agentic-ai-workflows)
  - [The pattern: references until the last mile](#the-pattern-references-until-the-last-mile)
  - [Project rules](#project-rules)
  - [Just-in-time agent grants](#just-in-time-agent-grants)
  - [Automation credentials for background agents](#automation-credentials-for-background-agents)
  - [Per-item CLI access control](#per-item-cli-access-control)
  - [Quick reference by tool](#quick-reference-by-tool)
  - [Migration: existing plaintext secrets](#migration-existing-plaintext-secrets)
- [CLI Request Flow (Current Behavior)](#cli-request-flow-current-behavior)
- [Session Model (CLI Unlock)](#session-model-cli-unlock)
  - [Implicit Session Creation](#implicit-session-creation)
- [App Lock &amp; Auto-Lock (GUI)](#app-lock-auto-lock-gui)
- [Limitations &amp; Constraints (Current)](#limitations-constraints-current)
- [Output Formats](#output-formats)
- [File Structure](#file-structure)
- [CLI Access Toggle (Security Feature)](#cli-access-toggle-security-feature)
  - [Global Toggle](#global-toggle)
  - [Per-Item Toggle](#per-item-toggle)
  - [Error Messages](#error-messages)
- [Security Model](#security-model)
- [Testing Strategy](#testing-strategy)
- [Verification Steps](#verification-steps)
- [Future Enhancements](#future-enhancements)

## Overview

Authsia CLI is a macOS command-line tool that accesses the Authsia vault through the Authenticator app
over an XPC bridge. The CLI never reads the Keychain directly; the app enforces policy, biometric
approval, per-item CLI access, and audit logging.

The CLI supports OTP items, passwords, API keys, certificates, secure notes (including JSON credentials),
and SSH keys. List commands are non-secret. Get/add/edit/delete/convert actions require approval or an
active session. Everything operates offline on the local machine; the only online component is Apple
Keychain/iCloud sync.

## Architecture & Security Model

Flow: authsia CLI → XPC BridgeRequest → Authenticator app → policy + approval + audit → repositories
→ Keychain → response to CLI.

Key properties:
- Central security gate in the app (biometric auth, XPC callback approval, timed sessions)
- Per-item CLI access control (enable/disable in the app UI)
- Audit logging in one place
- CLI has no Keychain entitlements; launchd starts the signed nested
  `AuthsiaHeadless.app` executable in a bridge role so vault/audit Keychain work
  runs with the app's shared Keychain access group
- Offline-first by design; no network calls
- Scraped items carry structured machine provenance and are surfaced in list/load output and UI

## Command Summary

| Command | Description | Example |
|---------|-------------|---------|
| `authsia list otp` | List OTP items (no secrets) | `authsia list otp --format table` |
| `authsia list passwords` | List passwords (no secrets) | `authsia list passwords --cli-enabled` |
| `authsia list api-keys` | List API keys (no secrets) | `authsia list api-keys --format table` |
| `authsia list certs` | List certificates (no secrets) | `authsia list certs --format table` |
| `authsia list notes` | List secure notes (no secrets) | `authsia list notes` |
| `authsia list ssh` | List SSH keys (no secrets) | `authsia list ssh --format table` |
| `authsia load <type>` | Load vault values as shell exports or JSON | `authsia load api-key API_KEY --folder Team/API --silent` |
| `authsia exec [<type> [<query>]]` | Run a command with secrets injected and masked | `authsia exec api-key API_KEY --folder Team/API -- npm start` |
| `authsia read <uri>` | Resolve an `authsia://` secret reference URI | `authsia read "authsia://password/GitHub/password"` |
| `authsia code <query>` | Generate TOTP code | `authsia code GitHub --copy` |
| `authsia get password <query>` | Retrieve password fields | `authsia get password DB_PASSWORD --folder Team/API --field username` |
| `authsia get api-key <query>` | Retrieve API key fields | `authsia get api-key Stripe --folder Team/API --field key` |
| `authsia get cert <query>` | Retrieve certificate fields | `authsia get cert TLS_CERT --folder Team/API --field certificate` |
| `authsia get note <query>` | Retrieve note fields | `authsia get note Runbook --folder Team/Ops --field content` |
| `authsia get ssh <query>` | Retrieve SSH key fields | `authsia get ssh DeployKey --folder Infra/SSH --field fingerprint` |
| `authsia get otp <query>` | Retrieve OTP via get | `authsia get otp GitHub --copy` |
| `authsia add password` | Create a password item | `authsia add password --name GitHub --username user --password -` |
| `authsia add api-key` | Create an API key item | `authsia add api-key --name Stripe --key -` |
| `authsia add cert` | Create a certificate item | `echo "CERTDATA" &#124; authsia add cert --name MyCert --certificate -` |
| `authsia add note` | Create a note item | `echo "secret" &#124; authsia add note --title "API Keys" --content -` |
| `authsia add ssh` | Create one SSH key item; infer metadata from `--public-key`, a matching `.pub`, or the private key | `authsia add ssh --name Work --private-key ~/.ssh/id_ed25519` |
| `authsia load ssh [<query>]` | Unsafe compatibility opt-in: copy eligible SSH key(s) to an external ssh-agent with a TTL | `authsia load ssh "Work Key" --system-agent --ttl 300` |
| `authsia edit password <query>` | Update a password | `authsia edit password GitHub --password -` |
| `authsia edit api-key <query>` | Update an API key | `authsia edit api-key Stripe --key -` |
| `authsia edit cert <query>` | Update a certificate | `authsia edit cert MyCert --certificate ./cert.pem` |
| `authsia edit note <query>` | Update a note | `echo "updated content" \| authsia edit note "API Keys" --content -` |
| `authsia edit ssh <query>` | Update an SSH key | `authsia edit ssh Work --public-key ~/.ssh/id_ed25519.pub` |
| `authsia delete password <query>` | Delete a password | `authsia delete password 11111111-1111-1111-1111-111111111111 --force` |
| `authsia delete api-key <query>` | Delete an API key | `authsia delete api-key Stripe --force` |
| `authsia delete cert <query>` | Delete a certificate | `authsia delete cert MyCert --force` |
| `authsia delete note <query>` | Delete a note | `authsia delete note "API Keys" --force` |
| `authsia delete ssh <query>` | Delete an SSH key | `authsia delete ssh Work --force` |
| `authsia unlock` | Start a timed session | `authsia unlock` |
| `authsia lock` | End active Authsia sessions | `authsia lock` |
| `authsia scrape` | Scan and migrate hardcoded secrets; auto-rewrites `.env` files with `authsia://` refs; skips SSH keys with `ssh adopt` guidance | `authsia scrape --replace-all` |
| `authsia scrape --revert <path>` | Preview a redacted diff, then revert a modified file to the latest backup | `authsia scrape --revert ~/.zshrc` |
| `authsia convert password <query>` | Convert a password item to an API key | `authsia convert password Stripe --to api-key` |
| `authsia scrape --revert-original <path>` | Preview a redacted diff, then revert to the first pre-scrape backup | `authsia scrape --revert-original ~/.zshrc` |
| `authsia scrape --revert-all` | Preview redacted diffs, then revert all modified files | `authsia scrape --revert-all` |
| `authsia scrape --list-modified` | List modified backup entries as a table | `authsia scrape --list-modified` |
| `authsia scrape --list-modified --all-machines` | List modified backup entries across all machines | `authsia scrape --list-modified --all-machines` |
| `authsia inject` | Resolve `authsia://` refs in a template from stdin or file | `authsia inject < config.template.yaml > config.yaml` |
| `authsia completion <shell>` | Generate shell completions | `authsia completion zsh` |
| `authsia agent init` | Create local AI-agent rule files | `authsia agent init --agent claude-code` |
| `authsia workspace init` | Preview-first repo setup with selected env migration, selected agent rules, and commit-safe config | `authsia workspace init --env-file .env --agent codex` |
| `authsia workspace update` | Re-scan configured env files, add explicit env files, refresh agent rules, and guide missing refs | `authsia workspace update --env-file .env.local` |
| `authsia workspace reset` | Preview managed env restore, warn when refs would remain unusable without a scrape backup, and remove repo-local workspace metadata plus Authsia-managed agent rules; `--yes` is for externally confirmed callers | `authsia workspace reset --dry-run` |
| `authsia workspace sync` | Compare managed env-file references and workspace env bindings with the vault workspace folder, then preview missing, extra, or mismatched refs without printing secrets | `authsia workspace sync --dry-run` |
| `authsia workspace run` | Run explicit workspace commands; secret-bearing runs use `exec`, while no-secret runs, read-only infra probes, and binding-free commands pass through without JIT | `authsia workspace run -- npm start` |
| `authsia workspace run --environment <name>` | Use one tagged environment plus default-environment items for this run without changing the saved selection | `authsia workspace run --environment Production -- npm start` |
| `authsia workspace run --default-only` | Ignore the saved selection for one run and resolve only default-environment items | `authsia workspace run --default-only -- npm test` |
| `authsia workspace status` | Show non-secret workspace health, env references, rule state, and recovery guidance | `authsia workspace status --format json` |
| `authsia workspace guard` | Create guarded-terminal shims and a visible banner for supported developer tools | `eval "$(authsia workspace guard --print-env)"` |
| `authsia workspace agent` | Preview, open, or print a secret-free AI tool launch or goal handoff from the workspace root | `authsia workspace agent --tool codex --goal "Fix checkout" --dry-run` |
| `authsia access create` | Create an automation credential | `authsia access create --name ci --ttl 2h --allow exec,ssh` |
| `authsia access list` | List automation credentials | `authsia access list --format table` |
| `authsia access revoke <id>` | Revoke an automation credential | `authsia access revoke <uuid>` |
| `authsia env add` | Add an environment scope profile | `authsia env add --name prod --folder Production --folder Shared` |
| `authsia env list` | List profiles outside a workspace; inside one, list referenced item tags, active state, counts, and matching profiles | `authsia env list --format table` |
| `authsia env show` | Show the active workspace environment or global profile | `authsia env show` |
| `authsia env use <name>` | Set the one active environment for the current workspace, or a global profile outside one | `authsia env use Production` |
| `authsia env clear` | Return the current workspace to the Default environment, or clear the global profile outside one | `authsia env clear` |
| `authsia ssh adopt` | Adopt existing SSH private keys into Authsia, replace disk keys with stubs, and enable shell integration in the user's shell startup file without creating duplicate backup notes | `authsia ssh adopt --path ~/.ssh --dry-run` |
| `authsia ssh adopt --revert <path>` | Restore a private key file from a legacy SSH adoption backup | `authsia ssh adopt --revert ~/.ssh/id_ed25519` |
| `authsia ssh adopt --revert-all` | Restore all private key files with legacy SSH adoption backups on the current machine | `authsia ssh adopt --revert-all` |
| `authsia ssh generate` | Generate a keypair, store the private key in the vault, and leave a disk stub | `authsia ssh generate --name deploy` |
| `authsia ssh config` | Add/update SSH config host entry | `authsia ssh config --host github.com --key deploy` |
| `authsia ssh git-signing` | Configure repo-local Git SSH signing | `authsia ssh git-signing --principal user@example.com --public-key key.pub` |
| `authsia status` | Show app, session, shell, SSH agent, and SSH approval status | `authsia status --format json` |
| `authsia doctor` | Diagnose common setup issues | `authsia doctor` |
| `authsia setup` | Set up, inspect, repair, or clean Authsia-managed local CLI integration | `authsia setup --status` |
| `authsia audit list` | List audit events | `authsia audit list --format table` |
| `authsia audit export` | Export audit events to file | `authsia audit export --format ndjson --out events.ndjson` |
## List: Items & Output Fields (Includes Scraped)

Lists all items of the given type. No sensitive data is returned.
Each item shows whether CLI access is enabled or disabled.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<type>` | Yes | `otp`, `passwords`, `api-keys`, `certs`, `notes`, `ssh` | Item type to list |
| `--favorites` | No | flag | Only show favorited items |
| `--folder, -f` | No | folder path | Filter by folder path (includes nested folders) |
| `--cli-enabled` | No | flag | Only show items with CLI access enabled |
| `--all-machines` | No | flag | Include scraped/adopted items from all machines (default: current machine only) |
| `--format` | No | `json` (default), `table` | Output format |

**Machine scoping for scraped items:**
- Non-scraped items are always included.
- Scraped passwords, API keys, certs, notes, and adopted SSH keys default to items created on the current machine.
- Current-machine matching uses the stored machine ID, with a machine-name fallback for local machine ID regeneration.
- Legacy scraped items without machine metadata remain visible by default.
- Use `--all-machines` to include scraped items created on other machines that share the same synced vault.

**List output fields by type:**

| Type | Table Columns | JSON Fields |
|------|--------------|-------------|
| otp | Issuer, Label, Favorite, ID, CLI, Scraped, Created, Updated | id, issuer, label, isFavorite, isCliEnabled, isScraped, createdAt, updatedAt |
| passwords | Name, Folder, Machine, Expires, Favorite, ID, CLI, Scraped, Created, Updated | id, name, username, website, folderPath, expiresAt, isFavorite, isCliEnabled, isScraped, scrapeMachineName, scrapeMachineId, createdAt, updatedAt |
| api-keys | Name, Folder, Machine, Expires, Favorite, ID, CLI, Scraped, Created, Updated | id, name, website, folderPath, expiresAt, isFavorite, isCliEnabled, isScraped, scrapeMachineName, scrapeMachineId, createdAt, updatedAt |
| certs | Name, Folder, Machine, Issuer, Expires, Favorite, ID, CLI, Scraped, Created, Updated | id, name, expirationDate, issuer, subject, folderPath, isFavorite, isCliEnabled, isScraped, scrapeMachineName, scrapeMachineId, createdAt, updatedAt |
| notes | Title, Folder, Machine, Favorite, ID, CLI, Scraped, Created, Updated | id, title, folderPath, isFavorite, isCliEnabled, isScraped, scrapeMachineName, scrapeMachineId, createdAt, updatedAt |
| ssh | Name, Folder, Machine, Type, Approval, Hosts, Comment, Fingerprint, Public Key, Favorite, ID, CLI, Adopted, Created, Updated | id, name, comment, fingerprint, publicKey, keyType, approvalPolicy, boundHosts, folderPath, isFavorite, isCliEnabled, isScraped, scrapeMachineName, scrapeMachineId, createdAt, updatedAt |

**Date Fields:**
- `createdAt`: When the item was first created (ISO 8601 in JSON, short date in table)
- `updatedAt`: When the item was last modified (ISO 8601 in JSON, short date in table)
- `expiresAt`: When a password or API key auto-destroys; absent in JSON and shown as `Never` in the table when no expiry is set

**Machine Field Semantics:**
- Table output shows `-` for non-scraped items.
- Scraped items show the recorded machine hostname when available.
- Legacy scraped items without structured provenance show `legacy scrape`.

Examples are included in the command table above. List never returns secrets.

### `authsia load <type> [<query>]` — Load vault values into runtime environment variables or ssh-agent

Loads secret values from Authsia. Behaviour differs by type:

- **`password`, `api-key`, `cert`, `note`** — Emits shell assignments or JSON records. For active-shell export with `--silent`, enable one-time shell integration first.
- **`ssh`** — Uses Authsia's built-in SSH agent by default; external `ssh-agent` loading requires `--system-agent --ttl <seconds>`. Does not emit shell assignments. See SSH-specific behaviour below.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<type>` | Yes | `password`, `api-key`, `cert`, `note`, `ssh` | Item type to load |
| `<query>` | No | name or ID | Individual item to load |
| `--folder, -f` | No | folder path | With `<query>`, restrict lookup to an exact folder; without `<query>`, load the folder tree including nested folders |
| `--all` | No | flag | Load all items of the given type |
| `--all-machines` | No | flag | Include scraped items from all machines (default: current machine only) |
| `--field` | No | type-specific field | Defaults to password/certificate/content/privateKey (not applicable for `ssh`) |
| `--format` | No | `shell` (default), `json` | Output format (not applicable for `ssh`) |
| `--no-export` | No | flag | Emit `KEY=value` without the `export` prefix (not applicable for `ssh`) |
| `--silent` | No | flag | Apply values to the current shell session via shell integration (not applicable for `ssh`) |
| `--system-agent` | No | flag | For `ssh` only: unsafe opt-in to copy keys into an external `ssh-agent` |
| `--ttl` | Required with `--system-agent` | seconds | Lifetime for keys copied into the external `ssh-agent` |

**Load scoping rules:**
- Choose one scope: `<query>`, `<query> --folder <path>`, `--folder <path>`, `--all`, or `--env <name>`.
- `<query> --folder <path>` loads one matching item from that exact folder; child folders are not included.
- Bare `--folder <path>` loads all CLI-enabled matching items in that folder tree, including nested folders.
- Scraped items follow the same machine rules as `list`: current machine by default, `--all-machines` to broaden scope, legacy scraped items remain included.
- JSON output includes `scrapeMachineName` and `scrapeMachineId` for each loaded entry when present.

Examples:

```bash
authsia load api-key API_KEY
authsia load api-key Stripe --field key
authsia load api-key API_KEY --folder Team/API
authsia load password --folder Team/API
authsia load password --folder Team/API/Prod
authsia load password --env Production
```

#### `authsia load ssh` — SSH Agent Loading

Normal SSH access should use Authsia's built-in SSH agent, which listens on
`~/.authsia/agent.sock`. The socket is owned by a per-user LaunchAgent
(`Authsia.SSHAgent`) using launchd socket activation, so `git`/`ssh` reach the
agent and the app is spawned headless on demand — the GUI app does not need to be
running. Launch the app once after install (kept in `/Applications`) so the
LaunchAgent registers. Shell integration exports
`SSH_AUTH_SOCK="$HOME/.authsia/agent.sock"` when that socket exists, so `git push`, `git pull`, and
`ssh` can use vault SSH keys without `authsia load ssh` or `ssh-add`.

```bash
eval "$(authsia init zsh)"
SSH_AUTH_SOCK="$HOME/.authsia/agent.sock" ssh-add -L
SSH_AUTH_SOCK="$HOME/.authsia/agent.sock" git ls-remote --heads origin
```

At signing time the app enforces per-key approval policy, optional bound-host checks, and audit logging.
The agent handles OpenSSH's `session-bind@openssh.com` extension so host-bound signing continues to work
with modern OpenSSH clients. If a stored key is encrypted, Authsia prompts for the passphrase only when
needed; unencrypted keys must not trigger a passphrase prompt.

`authsia load ssh` no longer copies keys into the external `ssh-agent` by default, because that bypasses
Authsia's approval policy, bound-host checks, and audit controls.

To explicitly copy a key into the system `ssh-agent`, use `--system-agent --ttl <seconds>`. Policy-bound
or host-bound keys are refused; use the built-in agent for those keys. For each matched key:

1. Retrieves the private key (and passphrase, if stored) via XPC.
2. If a passphrase is stored, sets `SSH_ASKPASS` to a temporary helper script that echoes the passphrase and sets `SSH_ASKPASS_REQUIRE=force`. The helper is deleted immediately after `ssh-add` completes.
3. Pipes the private key to `ssh-add -t <ttl> -`.
4. If the key is already loaded in the agent, skips silently (idempotent).

Output on success:
```
Added identity: SHA256:abc123 (Work Key)
```

Error conditions:

| Condition | Message |
|---|---|
| Missing unsafe opt-in | `Use the built-in Authsia SSH agent for normal SSH access. To copy a key into the external ssh-agent, rerun with --system-agent --ttl <seconds>.` |
| Missing TTL | `--ttl must be greater than 0 when using --system-agent.` |
| Policy-bound key | Refused with guidance to use the built-in Authsia SSH agent |
| `SSH_AUTH_SOCK` points to Authsia while using `--system-agent` | Start a separate external `ssh-agent`, then rerun before shell integration resets `SSH_AUTH_SOCK` |
| `ssh-agent` not running | `No ssh-agent found. Start one with: eval $(ssh-agent)` |
| Key already loaded | Silently skipped |
| Biometric denied | Standard `policyDenied` error |

### `authsia exec [<type> [<query>]]` — Run a command with vault secrets injected and masked

Fetches secrets from the vault and injects them as environment variables **only** into the target
command's process. Secrets never appear in the parent shell's environment. By default, any secret
value that appears in the subprocess's stdout or stderr is replaced with `<concealed by authsia>`
before it reaches the terminal.

The positional `<type>` syntax matches `authsia load <type> [<query>]`. The legacy
`--type`/`--query` flags remain supported for existing scripts. You can use `exec` without an item
type when all secret references come from the current directory's `.env` file, `--env-file`, or
existing environment variables.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<type>` | No | `password`, `api-key`, `cert`, `note` | Item type to load by scope (SSH not supported — use `load ssh`) |
| `<query>` | No | name or ID | Individual item to load |
| `--type, -t` | No | `password`, `api-key`, `cert`, `note` | Legacy alias for `<type>` |
| `--query` | No | name or ID | Legacy alias for `<query>` |
| `--folder, -f` | No | folder path | With `<query>`/`--query`, restrict lookup to an exact folder; without a query, load the folder tree including nested folders |
| `--all` | No | flag | Load all items of the given type |
| `--all-machines` | No | flag | Include scraped items from all machines (default: current machine only) |
| `--field` | No | type-specific field | Defaults to password/certificate/content |
| `--env-file <path>` | No | file path | Explicitly load env vars from a `.env` file (repeatable; last file wins on duplicate keys) |
| `--shell <command>` | No | quoted shell command string | Run the command string through `/bin/sh -c` for child-shell expansion |
| `-- <command> [args...]` | Yes, unless `--shell` is used | command argv | Command to run directly with injected secrets |

**Exec scoping rules:** If an item type is given with `<type>` or `--type`, choose one scope:
`<query>`, `<query>` with `--folder`, `--folder`, `--all`, or `--env`. Scope flags without an item
type produce an error. `<query> --folder <path>` loads one matching item from that exact folder.
Bare `--folder <path>` loads all CLI-enabled matching items in that folder tree, including nested
folders.

**Secret references in env vars:** Any environment variable with a value matching
`authsia://type/item[/field][?folder=path]` is automatically resolved before the subprocess
launches. This includes existing parent environment variables and values from `--env-file` files. If
at least one parent environment variable contains an `authsia://` reference, no item type or
`--env-file` is required.

If no `--env-file` or parent environment reference is provided, `exec` auto-loads a literal `.env`
file in the current working directory when that file contains at least one `authsia://` reference.
This also applies when an item type/scope is provided, so scoped folder loads can be combined with
Docker Compose-style `.env` references. Type-scoped `--shell` commands skip this implicit `.env`
discovery; pass `--env-file` when a shell command should also load env-file references. This is the
default scraped-project workflow:

```bash
authsia exec -- python app.py
```

Use `--env-file <path>` when the env file has a different name or lives outside the current
directory.

**Using injected env vars in command arguments:** by default, `exec` launches the target process
directly and does not run the command through a shell. A bare command like
`authsia exec password --folder Team/API -- curl $DemoKey` expands `$DemoKey` in the parent shell
before Authsia injects secrets, so `authsia` never receives the intended variable reference. Add
`--shell` when the child command line itself needs `$VAR` expansion:

```bash
authsia exec password --folder Team/API --shell 'curl "$DemoKey"'
```

The command string passed to `--shell` is still read by the parent shell first. Quote or escape `$`
references that must be expanded by Authsia's child shell, for example
`--shell 'curl "$DemoKey" | jq'`.

If an automation credential is present in the parent shell, `exec` consumes it for the bridge
request and removes `AUTHSIA_ACCESS_CREDENTIAL` from the child environment before launch. This keeps
the credential from becoming ambient authority inside the executed tool, even if a loaded `.env` file
tries to set the same key. If the credential includes `ssh`, `exec` forwards only
`AUTHSIA_SSH_ACCESS_CREDENTIAL` so the built-in Authsia SSH agent can authorize scoped signing without
giving the child process general CLI authority. `exec` also writes a transient process-bound SSH
automation grant for the child, so Git/SSH signing does not depend on macOS exposing environment
variables from `/usr/bin/ssh` to the agent process.

When `exec` itself starts from a guarded terminal, the child environment removes the active guarded
shim directory from `PATH` and drops `AUTHSIA_WORKSPACE_GUARD`,
`AUTHSIA_WORKSPACE_GUARD_SHIM_DIR`, and `AUTHSIA_WORKSPACE_ROOT` before launch. The command still
receives secrets resolved by `exec` and keeps output masking, but nested tools in scripts run as the
real executable inside that explicit boundary instead of re-entering `authsia workspace run`.

**Secret masking:** Resolved secret values and common deterministic encodings of those values
(Base64 padded/unpadded/URL-safe, hex, percent encoding, and JSON escaping) are scanned out of
subprocess stdout and stderr and replaced with `<concealed by authsia>`. When the command clearly
references an injected secret environment variable through a shell, pipeline, or runtime accessor,
`exec` also masks common deterministic transformations: shell substrings, prefix/suffix trims,
simple replacements, indexed character output such as `00=a`, `cut`/`head`/`tail`/`dd`,
`awk`/`sed`/`tr`/`fold`/`rev`/`sort`/`paste`, Base32/uuencode/hex/`od`/`hexdump`, digest output,
`jq`, and common runtime environment access from Python, Node, Ruby, Perl, PHP, Lua, Go, Java, and
Swift. Masking is longest-match-first to avoid partial replacement. Masking is stream-aware: if a
subprocess writes a secret or supported encoded form split across multiple OS pipe reads, `exec`
holds the boundary bytes until it can mask the full value. Masking reduces accidental leaks in logs
and agent transcripts; it does not stop a launched program from intentionally exfiltrating a secret
it was given.

**Signal forwarding:** SIGINT, SIGTERM, and SIGHUP are forwarded to the child process. Exit codes
follow shell convention: signal-killed processes exit with `128 + signum` (e.g. 130 for SIGINT).

Examples:

```bash
# Load by type+scope
authsia exec api-key API_KEY -- npm start
authsia exec api-key Stripe --field key -- npm start
authsia exec api-key API_KEY --folder Team/API -- npm start
authsia exec password --folder Team/API -- npm start
authsia exec password --folder Team/API/Prod -- npm start
authsia exec password --env Production -- npm start
authsia exec password --all -- npm start
authsia exec cert TLS_CERT --field privateKey -- nginx -c nginx.conf
authsia exec password --folder Team/API --shell 'curl "$DemoKey" | jq'

# Load from .env file or parent env var (secret references resolved automatically)
authsia exec -- npm start
authsia exec --env-file prod.env -- npm start
authsia exec --env-file config/.env -- make deploy
API_KEY=authsia://api-key/Stripe/key?folder=Team/API authsia exec -- npm start

# Combine type scope with .env file
authsia exec password --folder Team/API -- docker compose up
authsia exec password --folder CI --env-file prod.env -- ./app
```

#### `load` vs `exec` — Choosing the Right Command

| Concern | `load` | `exec` |
|---------|--------|--------|
| **Where secrets live** | Parent shell environment (persistent until `unset`) | Target process only (dies when process exits) |
| **Stdout exposure** | Emits `export KEY='value'` to stdout | No stdout emission — secrets never printed |
| **Output masking** | Not applicable | Masks secret values in subprocess output by default |
| **Shell history risk** | `eval "$(authsia load ...)"` is safe; recovery/fallback paths may leak | Command itself is harmless: `authsia exec ... -- npm start` |
| **AI tool / terminal observer risk** | High — any tool reading stdout or `env` sees secrets | Low — secrets only in the child process's env for its duration; the automation credential is stripped before launch |
| **Process table exposure** | Every child process inherits secret env vars | Only the target process and its children have them |
| **`.env` file support** | Not applicable | Auto-discovers current `.env` with `authsia://` refs; `--env-file` loads explicit paths |
| **Multi-command workflows** | Export once, use many times | One command per invocation — wrap each command |
| **SSH keys** | Built-in Authsia SSH agent for normal use; `load ssh --system-agent --ttl` only for explicit external-agent compatibility | Not supported — use SSH agent flow instead |
| **Shell integration** | `--silent` with FIFO for zero-stdout export | Not needed — stdout is never used |
| **Best for** | Interactive sessions needing many commands with secrets | CI/CD, single commands, security-sensitive environments |

**Recommendation:** Use `exec` when running a single command that needs secrets, especially in
environments where AI coding assistants or terminal observers are active. Use `load` when you need
secrets available across multiple commands in an interactive shell session.

### `authsia read <uri>` — Resolve a secret reference URI

Resolves a single `authsia://` secret reference URI and prints the plaintext value to stdout.
Useful for composing secrets in shell scripts, writing key files, or piping to other tools.

URI format: `authsia://type/item[/field][?folder=path]`

| Segment | Required | Description |
|---------|----------|-------------|
| `type` | Yes | `password`, `api-key`, `cert`, `note`, `ssh`, `otp` |
| `item` | Yes | Item name or UUID (fuzzy matched, same as `--query`) |
| `field` | No | Specific field; defaults to `password`/`key`/`certificate`/`content`/`privateKey`/`code` |
| `?folder=path` | No | Restrict match to one exact vault folder |

Folder scoping is enforced before the item lookup for `read`, `inject`, and `exec --env-file`
references. Use it to disambiguate duplicate item names or to keep a reference pinned to one folder.
Unlike `load --folder`, URI folder scoping does not include child folders. OTP references are not
folder-scoped because OTP items do not live in vault folders.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<uri>` | Yes | `authsia://…` | Secret reference URI |
| `--out-file <path>` | No | file path | Write value to file instead of stdout (creates parent dirs; sets 0600 permissions) |
| `--copy` | No | flag | Copy value to clipboard instead of stdout |

Examples:

```bash
# Print to stdout
authsia read "authsia://password/GitHub/password"

# Export inline
export API_KEY=$(authsia read "authsia://api-key/Stripe/key")

# Read an API key
authsia read "authsia://api-key/Stripe/key"

# Write private key to file
authsia read "authsia://cert/TLS/privateKey" --out-file key.pem

# Copy OTP code
authsia read "authsia://otp/GitHub/code" --copy

# Pipe SSH public key
authsia read "authsia://ssh/deploy/publicKey" >> ~/.ssh/authorized_keys

# Folder-scoped lookup
authsia read "authsia://password/deploy?folder=Team/Infrastructure"
```

#### Secret Reference URIs (`authsia://`)

Any CLI command or `.env` file can use `authsia://` URIs as values. The URI is resolved on demand
via the bridge:

```
authsia://type/item[/field][?folder=path]
```

Examples:

| URI | Resolves to |
|-----|-------------|
| `authsia://password/GitHub/password` | Password field of the "GitHub" password item |
| `authsia://password/GitHub/username` | Username field |
| `authsia://api-key/Stripe/key` | API key field of the "Stripe" API key item |
| `authsia://cert/TLS/privateKey` | Private key of the "TLS" certificate |
| `authsia://note/Runbook/content` | Content of the "Runbook" note |
| `authsia://ssh/deploy/publicKey` | Public key of the "deploy" SSH key |
| `authsia://otp/GitHub/code` | Current TOTP code for GitHub |
| `authsia://password/Prod DB?folder=Team/Infra` | "Prod DB" scoped to the Team/Infra folder |

**Percent encoding:** Spaces in item names can be percent-encoded (`My%20Key`) or left as-is in
quoted strings. Slashes inside values must be percent-encoded (`%2F`).

**In `.env` files with `exec`:**

```bash
# .env (safe to commit — no secrets)
DB_HOST=localhost
DB_PASS=authsia://password/Prod-DB/password
API_KEY=authsia://api-key/Stripe/key
```

```bash
authsia exec -- npm start
authsia exec -- make deploy
```

The CLI resolves all `authsia://` values before launching the subprocess. If any reference fails to
resolve (item not found, access denied, etc.), **all** errors are reported before the subprocess
launches — nothing is silently skipped.

For detected local coding agents, just-in-time `exec` approval supports password, API key, certificate,
and note references only. OTP and SSH references are rejected in that JIT path; SSH access should use the
built-in SSH-agent flow. Direct agent commands that intentionally emit plaintext (`get`, `read`,
`load`, and `inject`) are not authorized by JIT. Direct agent `authsia list` for passwords,
API keys, certificates, notes, and SSH metadata runs through JIT preflight and returns only the approved
named-folder subtrees or root-only scope.

### `authsia code <query>` — Generate a TOTP code

Generates a time-based one-time password. Requires biometric authentication or an active session.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<query>` | Yes | name or ID | Account to match |
| `--copy` | No | flag | Copy code to clipboard |
| `--watch` | No | flag | Refresh every second until interrupted |
| `--format` | No | `json` (default), `table` | Output format |

Examples are included in the command table above.

### `authsia get <type> <query>` — Retrieve a secret

Fetches the full secret for a single item. Requires biometric authentication or an active session.
Only items with CLI access enabled can be retrieved.
Use `--folder` with `password`, `cert`, `note`, or `ssh` when the same item name exists in multiple
vault folders. Folder-qualified `get` matches the exact folder only; nested child folders are not
included. OTP items are not folder-scoped.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<type>` | Yes | `password`, `api-key`, `cert`, `note`, `ssh`, `otp` | Item type |
| `<query>` | Yes | name or ID | Item to match |
| `--folder, -f` | No | folder path | Restrict password/API key/cert/note/ssh lookup to one exact folder |
| `--field` | No | see below | Return a specific field only |
| `--copy` | No | flag | Copy result to clipboard |
| `--format` | No | `json` (default), `table` | Output format |

**Available `--field` values by type:**

| Type | Allowed Fields | Default |
|------|---------------|---------|
| password | `username`, `password`, `all` | `all` |
| api-key | `key`, `all` | `all` |
| cert | `certificate`, `privateKey`, `all` | `all` |
| note | `content`, `all` | `all` |
| ssh | `publicKey`, `privateKey`, `comment`, `fingerprint`, `keyType`, `approvalPolicy`, `boundHosts`, `all` | `all` |
| otp | (not applicable) | — |

Examples:

```bash
authsia get password DB_PASSWORD --folder Team/API
authsia get api-key Stripe --folder Team/API --field key
authsia get cert TLS_CERT --folder Team/API
authsia get note Runbook --folder Team/Ops
authsia get ssh DeployKey --folder Infra/SSH
authsia get otp GitHub --copy
```

## Add/Edit/Delete: Item Types

All add/edit/delete actions require biometric approval or an active session. Edit updates only the
fields you provide. Delete prompts for confirmation unless `--force` is used.

Required and optional flags by type:

| Type | Required Flags | Optional Flags |
|------|----------------|----------------|
| `password` | `--name`, `--username`, `--password` | `--website`, `--notes`, `--folder, -f`, `--expires-at` |
| `api-key` | `--name`, `--key` or `--token` | `--website`, `--notes`, `--folder, -f`, `--expires-at` |
| `cert` | `--name`, `--cert-file` | `--key-file`, `--notes`, `--folder, -f` |
| `note` | `--title`, `--content` or `--content-file` | `--folder, -f` |
| `ssh` | `--name`, `--private-key` | `--public-key`, `--comment`, `--fingerprint`, `--folder, -f` |

**Input conventions:**
- Use `-` as a flag value to read from stdin.
- `--token` is accepted as an input alias for API keys; output and `--field` use the canonical `key` name.
- `--cert-file` and `--certificate` are equivalent. Both accept a file path or `-` for stdin.
- `--key-file` accepts a file path or `-` for stdin.
- `--content-file` accepts a file path or `-` for stdin (notes).
- `--expires-at` (passwords and API keys) sets an auto-destroy date. Accepts `YYYY-MM-DD` (local start
  of day) or a full ISO-8601 timestamp. Expired passwords and API keys are removed on vault load before
  they can appear in CLI output. The pending value shows in the `Expires` table column and the
  `expiresAt` JSON field.
- `authsia add ssh` reads the private key from `--private-key`; when `--public-key` is omitted, it
  first uses a matching `.pub` file next to the private key, then falls back to deriving the public key
  from the private key with `ssh-keygen -y`. The derived public key supplies fingerprint and key type;
  the private-key filename is used as the fallback comment when no public-key comment is available.

Examples are included in the command table above.

### `authsia edit <type> <query>` — Update an existing item

Updates an existing item. All flags are optional; only provided fields are updated.
Requires biometric authentication or an active session.

For passwords and API keys, `--expires-at <date>` sets or replaces the auto-destroy date and
`--clear-expires-at` removes it. The two flags are mutually exclusive.

Examples are included in the command table above.

### `authsia delete <type> <query>` — Delete an item

Deletes the matched item. Prompts for confirmation unless `--force` is used.
Requires biometric authentication or an active session.

Examples are included in the command table above.

### `authsia convert password <query> --to api-key` — Convert a password item

Converts a password item into a first-class API key item without printing secret material. The password
secret becomes the API key secret, the password username is appended to the API key notes when present,
and the original password is removed only after the API key has been created successfully.

```bash
authsia convert password Stripe --to api-key
```

### `authsia unlock` — Start a timed session

Authenticates once via biometrics and creates a terminal-scoped interactive session. Subsequent
`get`/`code` commands from the same terminal context skip per-request approval until the session
expires. Session duration is configured in the Authsia app GUI. Shells that carry
`AUTHSIA_ACCESS_CREDENTIAL` or `AUTHSIA_SSH_ACCESS_CREDENTIAL` do not read or write the interactive
session cache, so automation must use its credential instead of inheriting a human approval.
SSH keys that use session-based approval keep a separate per-key, terminal-scoped SSH approval
session with its own TTL. `authsia status` reports the Authsia session and SSH session separately,
and `authsia lock` clears both for the current terminal. Running `authsia unlock` does not
pre-approve SSH signing; the first session-based signing request for a key still prompts.

Examples are included in the command table above.

### `authsia lock` — End the active session

Clears the current terminal's cached CLI session token, asks the app to revoke the matching active
bridge session, and clears the current terminal's SSH approval-session status. Subsequent protected
commands and session-based SSH signing in this terminal require approval again. Automation
credentials are independent and must be revoked with `authsia access revoke <id>`. `lock` targets
the current human terminal scope even when an automation credential environment variable is present.
When the CLI runs without tty stdio (IDE tasks, agent-driven shells, pipelines), the terminal scope
is resolved from the controlling terminal of the nearest tty-bearing ancestor process, matching the
scope the SSH agent records for approvals made from that terminal.

Examples are included in the command table above.

### `authsia scrape` — Scan for and migrate hardcoded secrets

Scans local files for hardcoded secrets (API keys, tokens, passwords) and offers to migrate them
into Authsia. Operates entirely on the local filesystem — does not use the XPC bridge for scanning.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--path, -p` | No | file or directory paths | Paths to scan (supports tilde expansion; directory scans are shallow by default) |
| `--recursive` | No | flag | Recursively scan subdirectories for directory paths |
| `--folder, -f` | No | folder path | Store migrated items in this vault folder; scrape backups go under `<folder>/Authsia Backups` |
| `--confidence` | No | `high`, `medium`, `low` (default) | Minimum confidence threshold |
| `--type, -t` | No | `api-key`, `password`, `json`, `cert` | Limit detected credentials to one or more storage families |
| `--dry-run` | No | flag | Preview changes without modifying files or vault items |
| `--yes, -y` | No | flag | Skip interactive selection, auto-select all |
| `--replace-all` | No | flag | Apply all changes non-interactively, including `.env` file rewrites |
| `--quiet, -q` | No | flag | Suppress non-essential output |
| `--revert` | No | file path | Preview a redacted diff, then revert a previously modified file to its backup |
| `--revert-original` | No | file path | Preview a redacted diff, then revert a previously modified file to its first pre-scrape backup |
| `--revert-all` | No | flag | Preview redacted diffs, then revert all modified files |
| `--list-modified` | No | flag | List modified backup entries as a table |
| `--all-machines` | No | flag | Include backups from all machines (default: current machine only) |

#### SSH Key Migration

SSH key migration is explicit and should use `authsia ssh adopt`, not the generic secret scanner.
`authsia scrape` does **not** migrate or stub SSH private keys, even if an explicit `--path` points to
one. When scrape detects an SSH private key, it skips the key and prints the `authsia ssh adopt`
command to preview instead.

```bash
authsia ssh adopt --path ~/.ssh --dry-run
authsia ssh adopt --path ~/.ssh --yes --folder Infra/SSH
```

`authsia ssh adopt` discovers private key files, reads matching `.pub` files when present or derives
public-key metadata from unencrypted private keys when absent, maps `IdentityFile` entries from SSH config
to inferred bound hosts, stores each key in the vault with session-based approval, replaces the private
key file with an Authsia stub, and annotates matching SSH config entries. See
[`authsia ssh adopt`](#authsia-ssh-adopt) for the authoritative flow and options.

**Default scan paths** (when `--path` is not provided):
- Current directory: `.env`, `.env.local`, `.env.development`, `.env.production`
- Home directory: `~/.zshrc`, `~/.bashrc`, `~/.bash_profile`, `~/.zprofile`
- Kubernetes config: `~/.kube/config`

SSH private keys are never included in default scans. If a user explicitly scans `~/.ssh` or a key
file, scrape treats the detection as informational only. Use `authsia ssh adopt --path ~/.ssh --dry-run`
when you intentionally want Authsia to import and stub key files.

When `--path` points at a directory, scrape scans matching target files directly inside that directory
and prints progress as `Scanning <folder>, <current>/<total>`. It does not scan subdirectories unless
`--recursive` is provided. Recursive scans use the same progress format and prune generated, dependency,
VCS, cache, Terraform working, Python virtualenv, local worktree, Qoder, Graphify, and Xcode build directories named
`.git`, `.hg`, `.svn`, `.build`, `build`, `node_modules`, `DerivedData`, `Library`, `venv`, `.venv`,
`__pycache__`, `.terraform`, `.worktrees`, `.qoder`, and `graphify-out`; Xcode asset catalog directories ending in
`.xcassets` are also pruned. Directory scans skip generated dependency lockfiles such as
`package-lock.json`; passing a specific file path such as `--path .env` remains the fastest and most
predictable scan.

Whole `.json` files are imported only when their parsed key set looks credential-shaped. Ordinary
`.json` files are not scanned line-by-line as password-style key/value text; use `.env`, shell config,
or explicit credential file paths for password-style migration.

Use `--type` to narrow results before the interactive selector or non-interactive migration. `api-key`
includes API keys, tokens, access keys, and generic named secrets that are stored as API Key items.
`password` includes password-shaped key/value secrets and unknown high-entropy values that are stored
as password items. `json` includes JSON/YAML credential file detections. `cert` includes PEM
certificate/private-key detections. Multiple values are allowed, for example
`authsia scrape --type api-key --path .env` or
`authsia scrape --path ./config --type json cert --recursive`.

#### Secret Detection

A multi-layered scoring system evaluates each key-value pair (max 100 points):

| Signal | Points | Criteria |
|--------|--------|----------|
| Keyword match | +40 | Key contains `api_key`, `secret`, `password`, `token`, `access_key`, `private_key`, `client_secret`, etc. |
| Pattern match | +30 | Value matches Base32 (16+ chars), Base64 (32+ chars), Hex (32+ chars), or JWT format |
| High entropy | +30 | Shannon entropy > 4.5 |
| Medium entropy | +15 | Shannon entropy 3.5–4.5 |
| Char variety | +10 | 3+ character classes (uppercase, lowercase, digits, special) |

**Confidence levels:** high (>= 70), medium (>= 40), low (>= 25). Scores below 25 are rejected.

**Rejection filters:**
- Values shorter than 8 characters
- Known test/placeholder values (`JBSWY3DPEHPK3PXP`, `your_api_key`, `xxx`, etc.)
- Boolean/trivial values (`true`, `false`, `null`, `1`, `0`)
- Shell configuration keys (`PATH`, `HOME`, `SHELL`, `TERM`, `LANG`, `EDITOR`, `PS1`, `HISTFILE`, etc.)
- Generated/dependency metadata keys such as package-lock `integrity`/`resolved`, build `id`/`guid`/`cwd`, graph `source_file`/`label`, SDK `operation`/`shape`, paginator `input_token`/`output_token`, and example checksum/pagination fields

**Supported file formats:**
- KEY=VALUE / `export KEY=VALUE` (shell configs, `.env`)
- `"key": "value"` (JSON)
- `key: value` (YAML)
- PEM certificate files (`.pem`, `.crt`, `.cer`) and PEM private key files (`.key`); explicit file paths may import private-key-only PEM files, while directory scans skip unpaired key-only PEM files

Whole `.json` files are imported as JSON credentials only when their parsed keys look credential-shaped
(for example service-account, OAuth token, AWS credential, or Docker auth fields). Ordinary config JSON
such as `package.json` is scanned for key/value secrets but is not imported wholesale as a JSON credential.
Generated metadata such as package locks, build graphs, SDK model files, paginator files, and SDK example
files is filtered before scoring so those files do not flood the selector with checksum, path, label, or
pagination-token rows.

#### Type Unknown Handling

When scrape detects a secret but cannot determine its type from the key name (no keywords match), it defaults to storing the secret as a **password** item. This ensures secrets are not lost during migration.

**Behavior by Storage Type:**

| Original Type | Storage Type | Shell Config Replacement |
|--------------|--------------|-------------------------|
| apiKey, token, secret, accessKey | api-key | `export KEY=$(authsia get api-key KEY --field key)` |
| password | password | `export KEY=$(authsia get password KEY)` |
| jsonCredential | note | `export KEY=$(authsia get note KEY --field content \| jq -r '.')` |
| sshKey | skipped | Not migrated by scrape; prints guidance to use `authsia ssh adopt` for SSH-specific metadata, approval policy, and host bindings |
| certificate | cert | `authsia load cert KEY --field certificate --silent` or `--field privateKey` for private-key-only PEM |
| unknown | password | `export KEY=$(authsia get password KEY)` |

API-key-like scrape detections are stored as first-class API Key vault items. Existing password items
that were created before API Keys existed can still be moved manually with
`authsia convert password <name> --to api-key`.

**Important:** If you manually change an item's type in the Authsia app after scrape migration, you must also update any shell configurations that reference it. The scraper cannot automatically update configurations after the initial migration.

**Best Practice:** Use descriptive key names to ensure proper type detection:
- `API_KEY`, `SECRET_KEY` → Detected as apiKey/secret
- `GOOGLE_APPLICATION_CREDENTIALS` → Detected as jsonCredential (if path ends in .json)
- `DATABASE_PASSWORD` → Detected as password
- Generic names like `MY_VAR` → Falls back to unknown/password

#### Path-Based Credentials

Scrape can detect environment variables that point to credential files (e.g., `GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json`) and migrate the **file content** rather than just the path.

**Supported Path Variables:**

| Environment Variable | File Extensions | Storage Type |
|---------------------|-----------------|--------------|
| GOOGLE_APPLICATION_CREDENTIALS | .json, .yaml, .yml | jsonCredential (note) |
| AWS_SHARED_CREDENTIALS_FILE | .json, .yaml, .yml | jsonCredential (note) |
| AZURE_CREDENTIALS_FILE | .json, .yaml, .yml | jsonCredential (note) |
| DOCKER_CONFIG | .json | jsonCredential (note) |
| KUBECONFIG | .json, .yaml, .yml | jsonCredential (note) |
| SSL_CERT_PATH, *_CERT_PATH | .pem, .crt, .cer, .key | certificate (cert) |

PEM bundles with multiple `BEGIN CERTIFICATE` blocks are stored as one certificate item. If matching
public certificate and private key PEM files share the same derived name in the same scrape run, scrape
combines them into one certificate item with the private key stored in the certificate's `privateKey`
field. Directory scans keep simple filename-derived names when unique, but duplicate basenames are
disambiguated with the relative path (`prod/server.crt` -> `prod_server`, `old/server.crt` -> `old_server`).
Recursive directory scans prune generated, dependency, VCS, and cache directories before matching
certificate files.

**Migration Behavior:**

When a path-based credential is detected:
1. The scraper attempts to read the file at the specified path
2. If successful, the **file content** is stored in Authsia (not the path)
3. The shell config is updated to retrieve the content dynamically:
   ```bash
   # Before
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
   
   # After
   export GOOGLE_APPLICATION_CREDENTIALS=$(authsia get note google_application_credentials --field content)
   ```
4. If the file cannot be read, only the path is stored as a password

**Limitations:**
- File must be readable at the time of scraping
- Paths with variables (e.g., `$HOME/creds.json`) are not resolved
- Relative paths (./creds.json) are resolved relative to the scanned file's directory
- Binary PKCS#12 files (`.p12`, `.pfx`) are not migrated by scrape; use manual certificate import or convert to PEM first

#### JSON Credentials (Notes)

JSON credential files (including complex structures like Kubernetes kubeconfig) are stored as **secure notes**.
The original content is preserved verbatim and returned exactly as stored. JSON path extraction is intentionally
not performed; users can extract fields externally if needed.

Recommended usage:
- `authsia add note --title "kubeconfig" --content-file ~/.kube/config`
- `cat credentials.json | authsia add note --title "gcp-service-account" --content -`

#### Interactive TUI

When run without `--yes`, an interactive checkbox selector is presented in the terminal:

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate between detected secrets |
| `←` / `→` | Move between pages |
| `Space` | Toggle selection of current item |
| `p` / `P` | Select or deselect all items on the current page |
| `a` / `A` | Select or deselect all items across all pages |
| `n` / `N` | Deselect all |
| `Enter` | Confirm selection |
| `q` / `Q` / `Esc` | Cancel |

The table displays: selection checkbox, confidence level with icon, secret type, file path, key name,
selected count, and current page. Pagination shows up to 50 detected secrets per page, keeping large
scrape results manageable while still allowing one-key selection of either the current page or every
detected secret.

#### Migration Behavior

Behavior differs by file type:

**Shell configs** (`.zshrc`, `.bashrc`, `.bash_profile`, `.zprofile`, `.profile`):
- Auto-replacement with backup. Original line is commented out and replaced:
  ```bash
  # Migrated to Authsia - Original: API_KEY
  authsia load api-key API_KEY --silent
  ```
- Selected shell config secrets are rewritten even when they were found through the default scan paths
  rather than an explicit `--path ~/.zshrc`.
- If the shell integration block is missing, scrape prepends a managed Authsia integration block to the same shell config before any migrated `load --silent` lines.
- Changes are applied bottom-up (reverse line order) to preserve line numbers.

**`.env` files:**
- Auto-rewritten in-place. Each detected secret line is replaced with an `authsia://` reference URI:
  ```
  # Migrated to Authsia - Original: API_KEY
  API_KEY=authsia://api-key/API_KEY/key
  ```
- With `--folder`, rewritten references include `?folder=<path>` so future `read`, `inject`, and
  `exec`/`exec --env-file` resolution stays pinned to the exact destination folder.
- A unified diff is shown before any changes are applied. Confirm interactively or use `--replace-all` to skip the prompt.
- The original file is backed up as a secure note in the Authsia vault before rewriting. The first scrape backup is preserved as the original baseline; later scrapes keep one rolling latest copy. Backup notes live in an `Authsia Backups` folder; with `--folder Team/API`, they are stored under `Team/API/Authsia Backups`.
- Existing-item overwrite checks are scoped to the exact destination folder. A same-named item in another folder does not prompt, block, or get moved by `--replace-all --folder`.
- After rewriting, scrape prints: `Use authsia exec -- <cmd>` and shows code examples for referencing secrets in app code.
- Rewritten `.env` files are safe to commit — they contain `authsia://` references, not plaintext secrets.

#### Backup & Revert

Every file modification made by `authsia scrape` (shell configs and `.env` files) creates a backup entry stored as a secure note in the Authsia vault:
- Backup content notes and manifest notes are stored in `Authsia Backups` (or `<folder>/Authsia Backups` when `--folder` is supplied), separate from normal user notes
- Stored with SHA256 content hash, timestamp, and originating machine identity (hostname + stable UUID)
- Scrape backups keep two slots per file per machine: an original baseline from the first scrape and one rolling latest copy. Re-running scrape replaces only the latest copy; older pre-slot scrape backups are treated as the original baseline after upgrade.
- Manifest note tracks backups with restore status and typed kind (`scrape`, plus legacy `sshAdoption` entries), scoped per machine by default
- `--revert <path>`: shows origin machine, timestamp, and a redacted restore diff before confirmation, then restores the latest unrestored backup from the current machine, falling back to the original baseline if no latest backup exists
- `--revert-original <path>`: shows a redacted restore diff before confirmation, then restores the preserved original baseline from the current machine; this can be repeated even if the baseline entry is marked `restored`, as long as its backup note was retained. If cleanup is confirmed after restore, deletes all scrape backup notes for that file and machine/folder scope.
- `--revert-all`: shows redacted restore diffs before confirmation, then restores all modified files from the current machine
- After normal `--revert`, choosing to delete the backup removes the restored latest backup content note and prunes the manifest note if no backups remain there. After `--revert-original`, cleanup removes the original and latest scrape backup notes for that file, but does not delete scraped vault items.
- `--list-modified`: lists all backup entries in a table, showing file path, machine name, date, status, slot, and backup note path
- `--all-machines`: broadens list/revert scope to include backups from all machines (useful with iCloud-synced vaults)

**Multi-machine behavior:** When the same vault is shared across multiple Macs via iCloud, backups from each machine are tagged with that machine's hostname and a stable UUID stored at `~/.authsia/machine.json`. The `--list-modified` output distinguishes them:

```
+--------------------+------------------+------------------+----------+----------+-----------------------------------------------------+
| File               | Machine          | Created          | Status   | Slot     | Backup Note Path                                    |
+--------------------+------------------+------------------+----------+----------+-----------------------------------------------------+
| /Users/example/.zshrc | Example-MacBook | 3/15/26, 2:30 PM | active   | latest   | Authsia Backups/authsia_backup_zshrc_20260315_143000 |
| /Users/example/.zshrc | Example-MacBook | 3/14/26, 9:12 AM | active   | original | Authsia Backups/authsia_backup_zshrc_20260314_091200 |
| /Users/example/.zshrc | Mac-Mini         | 3/14/26, 9:12 AM | restored | original | Authsia Backups/authsia_backup_zshrc_20260314_091200 |
+--------------------+------------------+------------------+----------+----------+-----------------------------------------------------+
```

The `--revert` command shows origin before acting:
```
Reverting: /Users/example/.zshrc
  Backup from:  Example-MacBook
  Created:      3/15/26, 2:30 PM
  Hash:         a3f2c1b8

--- current /Users/example/.zshrc
+++ backup Authsia Backups/authsia_backup_zshrc_20260315_143000
@@ restore preview (secret values redacted) @@
-API_KEY=authsia://api-key/API_KEY/key
+API_KEY=<concealed by authsia>

Proceed with revert? [y/N]:
```

**Scraped vault items** record machine provenance in structured metadata and preserve a human-readable note banner:
```
Scraped by authsia
Machine: Example-MacBook  |  File: ~/.zshrc  |  Line: 42
Date: 2026-03-15
```

```bash
# Scan default paths
authsia scrape

# Scan specific files with high confidence only
authsia scrape -p ~/.zshrc .env --confidence high

# Scan direct files in a targeted directory
authsia scrape --path ./certs --dry-run

# Scan a targeted directory recursively
authsia scrape --path ./certs --recursive --dry-run

# SSH migration is handled by authsia ssh adopt, not default scrape
authsia ssh adopt --path ~/.ssh --dry-run
authsia ssh adopt --path ~/.ssh --yes --folder Infra/SSH

# Preview without changes
authsia scrape --dry-run

# Non-interactive (select all, auto-rewrite .env files)
authsia scrape --replace-all

# Select all vault items without rewriting .env files
authsia scrape --yes

# Check what was modified (current machine only)
authsia scrape --list-modified

# Check what was modified across all machines
authsia scrape --list-modified --all-machines

# Revert a specific file (current machine's backup)
authsia scrape --revert ~/.zshrc

# Revert to the first pre-scrape backup
authsia scrape --revert-original ~/.zshrc

# Revert using a specific machine's backup
authsia scrape --list-modified --all-machines
authsia scrape --revert ~/.zshrc --machine james-macbook

# Revert everything
authsia scrape --revert-all
```

### `authsia inject` — Inject secrets into templates

Reads a template from stdin (or `--in-file`), resolves all `authsia://` references inline, and writes
the result to stdout (or `--out-file`). The output contains plaintext secrets — do not commit generated
files to version control.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--in-file` | No | file path | Read template from file instead of stdin |
| `--out-file` | No | file path | Write output to file instead of stdout |

When output goes to a TTY (no `--out-file` and stdout is not piped), a warning is printed to stderr:
```
Warning: output contains plaintext secrets. Pipe to a file or use --out-file.
```

Examples:

```bash
# Pipe template through stdin/stdout
authsia inject < config.template.yaml > config.yaml

# Use explicit file arguments
authsia inject --in-file config.template.yaml --out-file config.yaml

# Inline in a build script
cat deploy.template.env | authsia inject | kubectl apply -f -
```

### `authsia completion <shell>` — Shell completions

Generates shell completion scripts for the specified shell.

Generated completions for item query positions, such as `authsia get password <TAB>`,
`authsia load password <TAB>`, and `authsia exec password <TAB>`, read the same
safe list metadata used by `authsia list`. Suggestions include item name, item
type, and folder path when the shell supports descriptions. Secret values are
never printed by completion. Bash inserts item names only because bash
completion has no separate description channel.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<shell>` | Yes | `zsh`, `bash`, `fish` | Shell to generate completions for |

Examples:

```bash
# Add to shell profile for persistent completions
eval "$(authsia completion zsh)"
eval "$(authsia completion bash)"
authsia completion fish | source
```

### `authsia agent init` — AI-agent rule setup

Creates local project rule files that teach coding agents to use Authsia safely. This command writes
rules only; it does not create automation credentials, JIT grants, or new secret access.

Generated rules tell agents to avoid plaintext secrets, use `authsia://` references for placeholders,
use `authsia exec ... -- <command>` for secret-bearing commands, mark every agent-run Authsia terminal
command with `env AUTHSIA_AGENT_PLATFORM=<platform> AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia ...`,
avoid bare `authsia get/read/load/code/inject` secret reads, and require outside-sandbox execution for
every `authsia` CLI command.
The generated marker lines match the selected tool: `--agent codex` writes only
`AUTHSIA_AGENT_PLATFORM=codex`, while `--all` writes one marker per supported tool.
For Claude Code, generated local settings also install Bash `PreToolUse` and
`PostToolUse` hooks that call Authsia's hidden command recorder. For GitHub
Copilot, generated local settings install a Copilot CLI `PreToolUse` hook for
Bash tool calls. Codex rules include command-history guidance; where tool hooks
are unavailable, including local VS Code Copilot sessions, Access Center falls
back to macOS process monitoring for processes tied to active Authsia-managed
agent terminal scopes.

Claude settings installation is structural and idempotent. If
`.claude/settings.local.json` is absent, Authsia creates it. If an existing file
is valid JSON with compatible object/array containers, Authsia adds every exact
Authsia command-history hook plus the `~/.authsia/agent.sock` Unix-socket value,
and removes the legacy `Authsia.Bridge` and `Authsia.SSHAgent` Mach lookup values
while preserving unrelated settings and custom Mach services;
missing or `null` containers are treated as empty. Incompatible non-null
container shapes are left byte-for-byte unchanged and reported with manual
merge guidance. Repeating installation does not duplicate hooks or sandbox
values.

When workspace update retains or adds Claude Code, it uses the same structural
merge. When workspace update removes Claude Code, or when uninstall/reset
removes its rules, Authsia uses the inverse structural cleanup. A file containing
only Authsia's generated structure is deleted.
Otherwise, Authsia removes every exact Authsia hook object, including copies
across repeated matcher entries, the exact Authsia socket value, and both legacy
Authsia Mach lookup values while preserving custom content. A custom-only no-op remains
byte-for-byte unchanged. If removal cannot be proved safe, the file is left
unchanged with manual cleanup guidance.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--agent` | No | `claude-code`, `cursor`, `codex`, `windsurf`, `copilot` | Agent rule set to create. If omitted, the command prompts. |
| `--all` | No | flag | Create rules for all supported agents. Use either `--agent` or `--all`, not both. |
| `--dry-run` | No | flag | Print planned changes without writing files. |

Created files depend on the selected agent:

| Agent | Rule files | Local sandbox helper |
|-------|------------|----------------------|
| Claude Code | `.authsia/agent-rules.md`, `CLAUDE.md` | Creates or safely merges `.claude/settings.local.json` with the exact SSH-agent socket value and Bash command-history hooks, while removing legacy Authsia Mach lookup values; incompatible shapes remain unchanged with manual guidance. |
| Codex | `.authsia/agent-rules.md`, `AGENTS.md` | Existing `AGENTS.md` content is preserved and Authsia's managed block is appended or replaced; command history uses explicit Authsia markers plus process-monitor fallback. |
| Cursor | `.authsia/agent-rules.md`, `.cursor/rules/authsia.mdc` | Rule text only. |
| Windsurf | `.authsia/agent-rules.md`, `.windsurf/rules/authsia.md` | Rule text only. |
| GitHub Copilot | `.authsia/agent-rules.md`, `AGENTS.md` | Creates `.github/copilot/settings.local.json` with a Copilot CLI `PreToolUse` Bash command-history hook if absent; if present, prints a manual merge block. Rule text requires `env AUTHSIA_AGENT_PLATFORM=copilot AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia ...`; existing `AGENTS.md` content is preserved and Authsia's managed block is appended or replaced. Unprefixed commands are direct human CLI. Cloud-hosted agents must leave `authsia://` placeholders for local execution. |

Examples:

```bash
authsia agent init
authsia agent init --agent claude-code
authsia agent init --agent codex --dry-run
authsia agent init --all
```

When `.authsia/workspace.json` exists, generated agent rules also add workspace
guidance: run `authsia workspace status` first, keep the same agent attribution
marker on workspace commands, and use `authsia workspace run -- <command>` or
`authsia workspace run --shell -- '<command>'` instead of fetching plaintext
secrets.

### `authsia workspace` — Repo-local secure workspace

`authsia workspace` is a repo-first wrapper around existing Authsia flows. It is intended for
terminal-first projects and local coding agents: keep `authsia://` references in committed project
files, then run commands through `authsia workspace run -- <command>` so existing `exec` masking,
JIT, audit, and per-item CLI access rules apply.

Workspace commands do not introduce command allowlists or a separate revocation model. Any command
can run; Authsia controls only secret resolution. Use `authsia lock` for the current terminal
session, and use Access Center or the menu bar's Revoke all action for broader live-access cleanup.

Current Workspace CLI capabilities:

- `workspace init` for preview-first setup, selected password/API-key env
  migration, selected agent rules, and commit-safe config writing.
- `workspace update` for re-scanning configured env files, adding explicit env
  files, refreshing agent rules, migrating new password/API-key detections, and
  guiding missing or unverified refs.
- `workspace init --plan-json` / `workspace update --plan-json` for sanitized
  setup/update previews, `--local-preview` for approval-free previews that skip
  live vault conflict checks, and `--apply-json <path>` for applying the app's
  structured selection without terminal prompts.
- `workspace status` for non-secret health, managed env-file refs, workspace
  env bindings, agent-rule state, missing-reference health, and JSON output
  for tooling. Live reference validation uses a scoped metadata-only bridge
  request and does not prompt for approval.
- `workspace run` for explicit project commands, including extra env files,
  dry-run execution-path preview, and child-shell expansion through `--shell`.
- `workspace env` for commit-safe env bindings when a project should inject
  `authsia://` references without maintaining a managed `.env` file.
- `workspace guard` for guarded-terminal PATH shims with a visible Authsia
  banner, default coverage for common developer/devops tools, and optional
  extra tool shims.
- `workspace agent` for secret-free Codex, Claude Code, VS Code, Cursor, and
  Windsurf launches or validated goal handoffs from inline text, a file, or
  stdin.
- `workspace reset` for previewing managed env restore and applying repo-local
  workspace config plus managed agent-rule cleanup. `--yes` is reserved for
  callers that already performed their own confirmation.
- `workspace sync` for comparing managed env-file references and
  `.authsia/workspace.json` env bindings with password/API-key items in the
  vault workspace folder as the source of truth. It
  reports missing local items, vault-folder extras, config mismatches, satisfied
  refs, and unverified rows without printing secret values. Dry-run and JSON
  previews use the same no-approval scoped metadata path as the native app.
- Successful workspace setup, update, status, reset, and env-binding changes
  record only the local repo root in a non-secret known-roots file shared with
  the macOS app, so CLI-created workspaces can appear in the Workspace sidebar
  and menu bar on refresh or app launch.

All built-in workspace help screens include concrete examples. This applies to
the top-level `authsia workspace -h`, every workspace subcommand, and nested
env-binding help such as `authsia workspace env -h` and
`authsia workspace env add -h`.

Workspace intentionally has no `workspace sessions` command, no inferred
project lanes, no recommended project command generation, no command history or
allowlist, and no raw-secret display path.

The shared CLI/app known-roots file lives under Application Support and stores
only standardized local repo paths. It does not store secret values,
`authsia://` refs, vault folder contents, JIT grants, command history, or audit
events. The app still reads each repo's `.authsia/workspace.json` before showing
health or launch actions.

`authsia workspace init` scans the repo root and env-like files up to three directories below it,
proposes `Workspaces/<repo-name>` as the Authsia folder, previews password/API-key rows without printing
raw values, lets the user choose which env files and password/API-key variables to manage, stores
selected vault rows through the existing scrape migration path, rewrites selected env values to
folder-scoped `authsia://` references, writes agent rules through the existing `agent init`
installer when requested, and defaults normal CLI setup to Claude Code rules when no agent is specified.

Workspace setup and update auto-create **password items** and **API key items**. API keys, tokens,
generic secrets, and access keys are stored as API Key vault items; password-shaped detections and
unknown high-entropy values are stored as password items. JSON credentials, certificates, notes, and
SSH keys are not created by workspace setup/update. `--folder <path>` is normalized under
`Workspaces/`, so `--folder api`, `--folder Workspaces/api`, and `--folder /Workspaces/api` all target
`Workspaces/api`; an empty or root-only folder falls back to `Workspaces/<repo-name>`.

The init review groups password/API-key rows under each env file with stable `[file.secret]` numbering. Each
row shows the selection marker, key name, detected type, confidence, Authsia store target, and
replacement reference; it never prints the raw secret value. In interactive mode, after the user
chooses env files, Enter confirms all preselected non-conflicting password/API-key rows, numbers toggle
individual rows, `a` selects all password/API-key rows, hidden `h` narrows back to high-confidence rows, and
`c` clears all non-conflict selections before the final apply confirmation.

Native app setup/update uses the same planner and apply path without embedding the terminal prompt
flow. `authsia workspace init --plan-json` and `authsia workspace update --plan-json` print sanitized
JSON containing env files, password/API-key rows, conflict state, generated references, and agent rule
options. Add `--local-preview` when the preview must not contact the bridge or ask for approval; this
local-only mode skips live vault conflict and reference checks, and the native app uses it for setup
preview. `--apply-json <path>` reads the app's selected env files, selected rows, conflict actions,
and selected agent rules, then stores/reuses secrets, rewrites env files, installs agent rules, ensures
the workspace vault folder exists, and writes commit-safe config through the same Workspace apply
logic. The JSON plan and selection never contain raw secret values. Native update treats selected agent
rules as exact: unchecked existing rules are removed from Authsia-managed artifacts, and generated
prompt markers match the selected tools only.

Non-interactive `--yes` mode requires explicit existing `--env-file` paths so a typo cannot create
a workspace config that immediately fails at run time. If a detected env secret maps to an existing
Authsia item in the target folder, `--yes` skips that secret instead of overwriting or rewriting it.
Interactive mode shows the existing item and lets the user skip, update the existing Authsia item, or
reuse the existing item without changing vault content.

Default env discovery includes root env files and env files up to three directories deep, such as
`.env`, `.delphi.env.local`, `delphi.env.local`, `apps/api/.env`, or
`services/worker/config/.env.local`, while generated/dependency folders stay
pruned. Repeat `--env-file <path>` to manually choose one or more specific files; explicit paths
stay exact for non-interactive `--yes` runs. `--recursive-env` remains available for compatibility
and merges the bounded auto-discovered set when explicit `--env-file` paths are also supplied.

`authsia workspace update` reads the existing workspace config, reuses the same preview/apply flow,
re-scans configured env files, merges any additional `--env-file` paths the user chose, and updates
agent rules through the existing `agent init` installer. Use it when a repo adds a new env file,
a teammate adds raw password/API-key values that should become Authsia references, or agent rule choices
change. The preview flags same-name existing password/API-key items before any env rewrite, without printing
raw secret values.

`authsia workspace sync` treats password and API Key items under `Workspaces/<workspace-folder>` as the source of
truth for managed env-file references and workspace env bindings. Valid `authsia://` entries in configured
managed env files count as tracked, so matching vault items are satisfied rather than local extras and do not
need duplicate env bindings. It handles importers that have no matching credential folder, only a
partial set of expected password/API-key items, local password/API-key items that are not yet bound in
`.authsia/workspace.json`, and config refs that point at a different name, type, or folder than the
local vault item. Non-credential folders under `Workspaces/` are hidden from workspace sync/import
review. `--dry-run` prints a non-secret table; `--plan-json` emits sanitized rows for the macOS app;
`--folder <path>` lets the app review or link an imported vault workspace folder before local
`.authsia/workspace.json` exists; and `--apply-json <path>` applies only config-safe actions such as
`repairConfig`, `addToConfig`, and `skip`. Secret value actions are app-mediated: the native sync
review lets a user use `Select all missing`, `Select local extras`, `Clear selection`, and `Set
selected action` to create password/API-key values, import an encrypted vault bundle, skip, or add local
extras to config before the CLI repairs refs. Copy/move from existing password/API-key items is visible as a
review action but waits for source-item selection before it can apply. Workspace sharing remains
refs-only by default; sharing encrypted secret bundles is an explicit export/import choice, not an
automatic part of workspace sharing.

`authsia workspace status`, `authsia workspace sync --dry-run`,
`authsia workspace sync --plan-json`, and config-safe
`authsia workspace sync --apply-json` do not request biometric or JIT approval.
They use a dedicated bridge request that returns only CLI-enabled item metadata
needed for the configured workspace folder: Status asks for its exact typed
references, while Sync preview and apply can enumerate password and API Key rows
in that exact folder. Apply uses this metadata only to validate the selected plan
before writing workspace references. The response never contains OTP accounts or password, API Key,
certificate, note, SSH private-key, or OTP values. The same behavior applies
when Workspace Center launches these commands and when a local coding agent
runs workspace status.

This is an intentional metadata exposure boundary: a local workspace agent can
learn matching item names, types, folder paths, CLI-enabled state, and whether a
stored secret exists without a JIT prompt. The bridge still requires trusted
Authsia CLI code signing, global CLI access, non-SSH/non-CI
context, an exact workspace-context match, and server-side scope filtering.
Because the payload is scoped non-secret metadata, these previews are also
served while the app is locked — the app lock routinely engages silently (and
always in the headless bridge helper), and requiring an unlock here made every
preview report unverified rows. Secret reads remain gated on approval
regardless of lock state.
Malformed, mismatched, or out-of-folder requests fail closed and return no
metadata. Direct `authsia list`, Sync apply, secret reads, decrypted imports,
copy/move/create actions, and vault mutations keep their existing approval,
session, automation, or JIT controls.

`workspace init`, `workspace update`, and `workspace status` also check committed `authsia://` refs
against the local vault when Authsia is reachable. If an env file already contains a reference that
is not in the vault, the CLI names the file and item and tells the user to either replace that URI
with the original raw value and run `authsia workspace update --env-file <path>`, add the missing
item in Authsia with the same name and folder, or edit the env file to point at an existing Authsia
item. Applying `workspace init` or `workspace update` (interactive or `--yes`) fails without
writing workspace files when a selected env file still contains a known missing ref, so setup never
reports ready for a workspace whose references cannot resolve. Missing refs make
`workspace status` report `Needs attention` instead of `Ready`. If the
vault cannot be validated, the preview/status output names the unverified file and item, then tells
the user to open Authsia or run the relevant scoped list command such as
`authsia list passwords` and rerun the workspace command before deciding whether the item is actually
missing. If Authsia reports that it cannot read the Keychain, the output tells the user to open
Authsia once and grant Keychain access, or ask an administrator to allow team identifier `33M8QU65SP`
under managed keychain access.

`authsia workspace reset --dry-run` previews the cleanup required to remove repo-local workspace
metadata. It lists `.authsia/workspace.json`, managed env files that contain `authsia://` refs,
redacted scrape-backup restore diffs when available, and Authsia-managed agent rule artifacts.
Applying reset requires interactive confirmation, restores managed env files from their latest
Authsia scrape backups when available, then removes the workspace config plus Authsia-owned managed
rule files/blocks. For merged Claude settings, reset deletes a generated-only
file or structurally
removes all exact Authsia hook/socket entries and legacy Authsia Mach lookup values while preserving custom content; unsafe
shapes remain unchanged with manual guidance. If a managed env file has refs but no matching backup, reset leaves that env file
unchanged, warns that it will keep unusable `authsia://` references, and still removes workspace
metadata. The macOS app requires the user to acknowledge that warning before applying reset. `--yes`
skips the CLI prompt only for already-confirmed surfaces such as the macOS Workspace delete dialog.

```text
.authsia/workspace.json
```

The workspace file is commit-safe. It contains the workspace name, Authsia folder, selected managed
env files, optional env bindings that hold only `authsia://` references, and selected agent rule names. It must not contain secret values, fingerprints,
automation credentials, JIT grant IDs, session IDs, absolute local paths, command allowlists, or
audit history.

Workspace schema version 1 is the current stable format. Authsia reads v1 files through the
workspace config migration path before validation, so future schema changes have a single upgrade
point. If the CLI sees a newer unsupported schema, it stops before using the config and tells the
user to update Authsia, then run `authsia workspace update`.

Example workspace file:

```json
{
  "agents" : {
    "rules" : [
      "codex",
      "claude-code"
    ]
  },
  "managedEnvFiles" : [
    ".env",
    ".env.local"
  ],
  "envBindings" : [
    {
      "name" : "API_KEY",
      "reference" : "authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi"
    }
  ],
  "schemaVersion" : 1,
  "workspace" : {
    "authsiaFolder" : "Workspaces/api",
    "name" : "api"
  }
}
```

`authsia workspace env add <NAME> <authsia://...>` stores a commit-safe env binding in
`.authsia/workspace.json`; `list`, `remove`, and `validate` manage and check those bindings. When a
schema-v2 variable has multiple environment-specific bindings, `remove` requires the exact reference
(`authsia workspace env remove <NAME> <authsia://...>`) so it cannot remove every variant. This is
for projects that want `API_KEY`-style environment variables during `workspace run` without keeping a
managed `.env` file. Validation uses the live vault when available and reports missing or unverified
Authsia references without resolving secret values.

`authsia workspace run -- <command>` searches upward for `.authsia/workspace.json` and launches the
child command in the caller's current directory. It loads only managed env files whose directories
are ancestors of that working directory, ordered from workspace root to the nearest applicable
scope. Within one source tier, resolution chooses the activated environment first, then the nearest
env-file scope, then the most-specific Authsia vault folder. A parent Production-tagged item therefore
outranks a nested untagged default; when both are Production-tagged, the nested env-file definition
wins. Sibling directories are independent because only ancestor env files apply to a command; equal
definitions at the same applicable scope remain a blocking conflict. If the run has managed env files, workspace env bindings, parent
`authsia://` references, or automation credentials, it delegates to the existing `exec` path with the
same secret-reference resolution, output masking, signal forwarding, audit logging, automation
credential stripping, and agent JIT behavior as `authsia exec`. If the workspace has no secret inputs, it runs as a no-secret
passthrough instead of blocking on `exec`'s secret-input guard. Known read-only infrastructure
probes that agent and IDE harnesses spawn automatically — `docker context ls`/`inspect`, `docker`
`version`/`info`/`ps`/`images`, `npm`/`pnpm`/`yarn` `view`/`info`/`ls`/`list`/`outdated`,
`config get`/`list`, `npm ping`, `pip`/`pip3` `list`/`show`, `kubectl`/`terraform`/`tofu`/`go`
`version`, `cargo` `metadata`/`tree`, `gcloud` `version`/`config list`/`config get-value`, and bare
`--version`/`--help`
invocations — also pass through without injecting secrets, forwarding automation credential markers,
or firing a JIT preflight, so launching an agent tool does not request approval until a command
actually consumes a secret. Binding-free invocations pass through the same way: inline interpreter
code (`python3 -c '…'`) and `docker` commands, whose env consumption is explicit in the command
line, run without secret resolution when no configured binding name (workspace env bindings,
managed-file `authsia://` names, or parent-env `authsia://` reference names) appears in the
arguments. Referencing a binding name, `docker` `--env-file` or `compose`, python script/module/REPL
forms, and bindings inside the tool's own env namespace (`PYTHON*`, `DOCKER_*`) still delegate to
`exec`. A misclassified passthrough runs without the secret and fails loudly; the guarded parent env
holds no secret values, so nothing can leak. This skip only
applies to explicit `--` command vectors; a `--shell` string always delegates. `--dry-run` names which execution
path would be used before the command starts, and distinguishes plain managed env files from
`authsia://` references that can trigger biometric or JIT approval unless an active session, grant,
or credential already authorizes the access. Use
`authsia workspace run --shell -- 'curl "$API_KEY"'` when the child command needs shell expansion;
quote or escape `$` so the parent shell does not expand it before Authsia resolves the workspace env
files.

`authsia workspace status` shows the configured Authsia folder, managed env files, workspace
env bindings, count of `authsia://` references in managed files and bindings, installed/missing
agent rule state, missing or unverified reference guidance, and reminders for `authsia workspace run -- <command>`,
`authsia lock`, and Access Center/menu-bar revocation. Known missing `authsia://` references are
part of the shared health summary and make the status `Needs attention`. The macOS Workspace card
also moves to `Needs attention` when the configured workspace vault folder contains items but the
workspace has zero Authsia refs, so local extras can be added to config.

`authsia guard` is the convenient way to enable guarded mode in an already-open shell. It requires
the standard Authsia shell integration, installed with `authsia setup --repair`; open a new terminal
after repair, then run `authsia guard` from the workspace root. The shell integration evaluates the
existing `workspace guard --print-env` output in the current shell. Without that integration, the
top-level command exits non-zero and explains how to enable it instead of pretending it changed the
parent shell.

`authsia unguard` restarts the current tab in the same folder with normal shell behavior. It skips
Auto-guard only for that replacement shell; later tabs still follow the workspace toggle. It does not
restore workspace-managed environment values that guarded mode cleared. Without shell integration,
the command exits non-zero with repair guidance because it cannot replace the caller's shell.

`authsia workspace guard` creates a temporary shim directory for common developer/devops tools and
prints exports for a guarded terminal. With a named workspace environment selected, the first
guarded-terminal message names the effective environment and confirms that Default-environment
items remain available; Default-environment selection adds no extra message. Guarded terminal does not export resolved secrets into the
parent shell. When the exports are evaluated, Authsia also unsets parent-shell variables for
workspace env bindings and `authsia://` keys in managed env files; unrelated ambient environment
variables are not scrubbed. It prepends a temporary shim directory to `PATH` so known tools such as `npm`,
`pnpm`, `yarn`, `python`, `python3`, `pip`, `pip3`, `poetry`, `uv`, `docker`,
`docker-compose`, `kubectl`, `helm`, `kustomize`, `skaffold`, `tilt`, `aws`, `gcloud`, `az`,
`doctl`, `flyctl`, `terraform`, `tofu`, `terragrunt`, `pulumi`, `cdk`, `sam`, `serverless`, `sls`,
`ansible`, `ansible-playbook`, `packer`, `swift`, `go`, `cargo`, `make`, `just`, `task`, `mvn`,
and `gradle` run through `authsia workspace run -- <tool>`. Agent startup launchers such as `node`,
`bun`, and `npx` are not shimmed by default because agent harnesses, language servers, MCP servers,
and plugin hooks spawn them recursively, which would route startup work through `workspace run` and
resolve workspace secrets at agent launch; run them explicitly with `authsia workspace run -- <tool> ...`
or add them with `workspace guard --tool <name>`. Non-default tools added with `workspace guard --tool <name>`
are saved in the workspace's `guard.tools` settings for future guarded terminals; when shell exports
are printed, all shimmed tool names are unaliased so a user alias cannot bypass the PATH shim.
Generated shims preserve the caller's current working directory so nested package and build tools
still discover package-local config while Authsia resolves workspace metadata from the project tree.
Shell-expanded commands such as `curl $API_KEY` and
`curl ${API_KEY}` are not made safe by shims because expansion happens before the shim receives
arguments; use `authsia workspace run --shell -- 'curl "$API_KEY"'` for those cases. Third-party
secret-manager CLIs such as `vault` and `op` can print secrets outside Authsia's masking boundary,
so they are never shimmed; naming one with `workspace guard --tool <name>` is skipped with a warning.
Guarded shells also define wrappers for `python`, `python3`, `pip`, and `pip3` so activating a
Python virtual environment after the guard still routes those commands through
`authsia workspace run` while using the active virtualenv executable.
Shimmed invocations that reach `workspace run` with a confirmed agent marker,
or with known coding-agent ancestry and no stdin TTY, run as direct passthrough
without resolving `authsia://` workspace refs and without a JIT approval;
literal non-secret values from managed env files remain available. An agent command such
as `python3 script.py` never resolves workspace secrets implicitly. Agents that need secrets must ask
explicitly with `authsia workspace run -- <tool> ...` or `authsia exec`, which still resolve references
and go through JIT approval. An ancestry-only guarded invocation with stdin attached to a TTY keeps
human behavior; redirecting stdout does not change that routing. `TerminalContext.isInteractiveSession`
still requires both stdin and stdout TTYs where a full-screen interactive UI needs them.
The printed shell exports also emit a visible Authsia guarded-terminal banner when evaluated.
To enable guarded mode in an already-open Terminal, iTerm, Ghostty, or other normal shell, run
`authsia guard` from the workspace root after shell integration is enabled. The low-level form
remains available for scripts and advanced options:

```sh
__authsia_guard_env="$(authsia workspace guard --print-env)" && eval "$__authsia_guard_env" && unset __authsia_guard_env
```

To return that tab to normal mode, run `authsia unguard`. It restarts the interactive shell rather
than attempting to reconstruct aliases, functions, or workspace-secret values from the guarded session.

New interactive shell tabs opened from an opted-in workspace start guarded automatically when the
standard Authsia shell integration is installed. `authsia setup --repair` installs the managed
startup block that evaluates `authsia init <shell>`, and that init script runs
`authsia workspace guard --print-env --auto` during shell startup. `--auto` prints nothing outside an
Authsia workspace, when the current shell is already guarded, or when the workspace's macOS Workspace
UI toggle "Auto-guard new tabs" is off. That toggle is enabled by default for new workspace configs.

Use `echo "$AUTHSIA_WORKSPACE_GUARD"` to confirm the session is guarded.

`authsia workspace agent` opens or prints a secret-free launch for Claude Code by default; pass
`--tool codex` or another `--tool <tool>` for Codex, VS Code, Cursor, or Windsurf from the workspace root. GUI tools
(VS Code, Cursor, Windsurf) open their app; terminal tools (Codex, Claude Code) run in the current
terminal, inheriting this shell's TTY and environment so a guarded shell's PATH still applies.
Every launch sets `AUTHSIA_AGENT_PLATFORM` and `AUTHSIA_AGENT_INVOKES_AUTHSIA=1` on the selected
tool process (`codex`, `claude-code`, `copilot` for VS Code, `cursor`, or `windsurf`). GUI launches
request a new app process so an already-running unmarked IDE cannot absorb the workspace-open
request. These values identify agent provenance for Authsia routing; they are not credentials and do
not grant access by themselves. Authsia commands outside this launch flow remain direct human CLI.
"Secret-free" means Authsia injects no managed secrets into the tool, not that it scrubs unrelated
ambient environment: terminal tools inherit the launching shell, so launch from a guarded terminal
(`authsia workspace guard`) to avoid passing ambient shell secrets to the agent. GUI tools launch
from a clean app environment. Either way the agent uses `authsia workspace run`/`authsia exec` for
JIT/automation-controlled secret access.
`--dry-run` previews the command and app target without opening anything, and `--print` prints a shell
command instead of launching. Printed launch commands and goal handoffs start by evaluating
`authsia workspace guard --print-env` from the workspace root before running the selected tool. Add
`--goal "<task>"`, `--goal-file <path>`, or `--goal-file -` to print a paste-ready agent handoff with
the workspace name, selected tool, launch command, goal text, workspace status and
`workspace run --dry-run` preflight guidance, and JIT/automation-token guidance.
Goals are output only, do not open GUI tools, and are not written to `.authsia/workspace.json`.
`--goal` and `--goal-file` are mutually exclusive; `--goal-file -` reads UTF-8 goal text from stdin
for `pbpaste`, editor, or agent-pipeline workflows. Goal text rejects obvious pasted secret values
such as common provider keys or private-key blocks, while placeholders such as `$API_KEY`, `${API_KEY}`,
and `authsia://` references are allowed. The launched tool does not receive plaintext vault secrets
from the parent process; follow-up secret access still goes through `authsia workspace run -- <command>`,
`authsia exec`, Agent JIT grants, or automation credentials.

| Subcommand | Description | Example |
|------------|-------------|---------|
| `workspace init` | Interactive setup wizard; previews before writing and confirms before apply | `authsia workspace init` |
| `workspace init --dry-run` | Preview root and nested workspace setup without writing | `authsia workspace init --dry-run` |
| `workspace init --recursive-env --env-file <path> --dry-run` | Preview explicit env files plus bounded auto-discovered env files | `authsia workspace init --recursive-env --env-file apps/api/.env --dry-run` |
| `workspace init --yes --env-file <path>` | Non-interactive setup for explicit env files only; repeatable; applies non-conflicting detected passwords | `authsia workspace init --yes --env-file .env --env-file apps/api/.env` |
| `workspace init --plan-json` | Print a sanitized setup plan; add `--local-preview` for approval-free local-only preview | `authsia workspace init --plan-json --local-preview` |
| `workspace init --apply-json <path>` | Apply a structured native app setup selection | `authsia workspace init --apply-json /tmp/authsia-workspace-selection.json` |
| `workspace update` | Re-scan configured env files, add explicit env files, and refresh agent rules | `authsia workspace update` |
| `workspace update --dry-run` | Preview workspace repair without writing | `authsia workspace update --dry-run --env-file .env.local` |
| `workspace update --recursive-env --env-file <path> --dry-run` | Preview explicit env files plus bounded auto-discovered env files | `authsia workspace update --recursive-env --env-file apps/api/.env --dry-run` |
| `workspace update --yes --env-file <path>` | Non-interactive update for explicit env files; repeatable; selects non-conflicting detected passwords | `authsia workspace update --yes --env-file .env.local --env-file apps/api/.env` |
| `workspace update --plan-json` | Print a sanitized update plan; add `--local-preview` for approval-free local-only preview | `authsia workspace update --plan-json --local-preview` |
| `workspace update --apply-json <path>` | Apply a structured native app update selection | `authsia workspace update --apply-json /tmp/authsia-workspace-selection.json` |
| `workspace reset --dry-run` | Preview managed env restore, unusable-ref warnings, and workspace config/rule cleanup without writing | `authsia workspace reset --dry-run` |
| `workspace reset` | Confirm, restore managed env files when backups exist, warn when refs would remain unusable, and remove workspace config plus Authsia-managed agent rule artifacts | `authsia workspace reset` |
| `workspace reset --yes` | Apply reset after an external confirmation, such as the macOS Workspace delete dialog | `authsia workspace reset --yes` |
| `workspace sync --dry-run` | Preview password vault-folder/source-of-truth drift without writing or printing secrets | `authsia workspace sync --dry-run` |
| `workspace sync --plan-json` | Print a sanitized sync plan for the native app importer review | `authsia workspace sync --plan-json` |
| `workspace sync --folder <path> --plan-json` | Print a sanitized sync plan before local workspace config exists | `authsia workspace sync --folder Workspaces/api --plan-json` |
| `workspace sync --apply-json <path>` | Apply config-safe sync selections such as repair, add-to-config, and skip | `authsia workspace sync --apply-json /tmp/authsia-workspace-sync-selection.json` |
| `workspace sync --folder <path> --apply-json <path>` | Link an imported vault workspace folder by applying config-safe selections | `authsia workspace sync --folder Workspaces/api --apply-json /tmp/authsia-workspace-sync-selection.json` |
| `workspace env add <NAME> <authsia://...>` | Add or update a commit-safe workspace env binding | `authsia workspace env add API_KEY 'authsia://api-key/API_KEY/key?folder=Workspaces%2Fapi'` |
| `workspace env list` | List bindings with active environment, item environment properties, and effective/inactive state | `authsia workspace env list` |
| `workspace env remove <NAME> [authsia://...]` | Remove one workspace env binding; a repeated schema-v2 name requires its exact reference | `authsia workspace env remove API_KEY 'authsia://api-key/API_KEY/key'` |
| `workspace env validate` | Validate exact workspace-scoped env refs without listing the vault or returning values; unavailable scoped metadata is reported as unverified | `authsia workspace env validate` |
| `workspace run -- <command>` | Validate exact active workspace refs through scoped metadata, then run the command; secret-bearing env refs use `exec` | `authsia workspace run -- npm dev` |
| `workspace run --env-file <path> -- <command>` | Add an extra env file for one run; its exact workspace-scoped refs join the run preflight | `authsia workspace run --env-file .env.production -- npm run deploy` |
| `workspace run --environment <name> -- <command>` | Use one tagged environment plus default-environment items without persisting the choice | `authsia workspace run --environment Production -- npm run deploy` |
| `workspace run --default-only -- <command>` | Use only default-environment items for one run | `authsia workspace run --default-only -- npm test` |
| `workspace run --shell -- <command>` | Run a quoted shell command through `/bin/sh -c` with managed env files | `authsia workspace run --shell -- 'curl "$API_KEY"'` |
| `workspace run --dry-run` | Show env files, command, and direct-vs-`exec` execution path | `authsia workspace run --dry-run -- npm test` |
| `workspace status` | Show workspace config, managed env files, env bindings, reference/rule state, and missing/unverified-vault guidance for `authsia://` refs | `authsia workspace status` |
| `guard` | Activate guarded mode in the current shell after standard shell integration is enabled | `authsia guard` |
| `unguard` | Restart the current tab in normal mode; skip Auto-guard once | `authsia unguard` |
| `workspace guard --dry-run` | Preview guarded terminal shim setup without writing files | `authsia workspace guard --dry-run` |
| `workspace guard --print-env` | Create shims and print exports for a guarded terminal | `eval "$(authsia workspace guard --print-env)"` |
| `workspace guard --print-env --auto` | Shell-startup mode; print exports only for opted-in workspaces that are not already guarded | `eval "$(authsia workspace guard --print-env --auto)"` |
| `workspace guard --tool <name> --print-env` | Save an extra tool shim in workspace guard settings and include it in guarded terminal setup | `eval "$(authsia workspace guard --tool rails --print-env)"` |
| `workspace agent --dry-run` | Preview the default secret-free Claude Code launch from the workspace root | `authsia workspace agent --dry-run` |
| `workspace agent --tool <tool> --dry-run` | Preview a secret-free AI tool launch from the workspace root | `authsia workspace agent --tool cursor --dry-run` |
| `workspace agent --tool <tool> --print` | Print the launch command instead of opening a GUI app | `authsia workspace agent --tool vscode --print` |
| `workspace agent --tool <tool> --goal <text>` | Print a paste-ready agent goal handoff without opening the tool, storing the goal, or accepting obvious pasted secrets | `authsia workspace agent --tool codex --goal "Fix checkout"` |
| `workspace agent --tool <tool> --goal-file <path>` | Read a UTF-8 goal file and print the same validated goal handoff without storing the goal | `authsia workspace agent --tool codex --goal-file agent-goal.txt` |
| `workspace agent --tool <tool> --goal-file -` | Read UTF-8 goal text from stdin and print the same validated goal handoff | `pbpaste \| authsia workspace agent --tool codex --goal-file -` |

### `authsia access` — Automation credentials

Manages time-limited credentials for non-interactive use (CI/CD pipelines, scheduled jobs).
Automation credentials bypass biometric prompts and enforce folder limitations when `--scope` or
`--env` is set.
Creating a credential always requires a fresh manual approval in the app so a human reviews the
requested scope, TTL, machine, and capability allowlist before the credential is persisted.

**Subcommands:**

#### `authsia access create`

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--name` | Yes | string | Human-readable credential name |
| `--scope` | No | folder path | Optional folder scope the credential is restricted to. Omit to allow all CLI-enabled non-OTP items. |
| `--env` | No | profile name | Optional environment profile whose all/folder scope is used for the credential. Profiles with multiple folders grant access to each folder tree. Use either `--scope` or `--env`, not both. |
| `--ttl` | Yes | duration | Time-to-live with suffix: `15m`, `2h`, `7d` |
| `--allow` | Yes | comma-separated capabilities | Which capabilities this credential permits. One or more of `exec`, `load`, `read`, `get`, `inject`, `ssh`, `list`. Pick the narrowest set — `exec` alone is safest for secret injection; add `list` only when the automation needs metadata discovery, and `ssh` only for Git/SSH signing. |

`authsia access create` sends the requested scope (explicit folder, environment profile, or `all`
when neither is provided) and allowlist to the app for approval before saving anything locally. A
denied approval leaves no credential behind.

#### `authsia access list`

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--format` | No | `json` (default), `table` | Output format |
| `--all` | No | flag | Include expired/revoked credentials |

#### `authsia access revoke <id>`

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<id>` | Yes | UUID | Credential ID to revoke |

**Automation credential properties:**
- Enforce a capability allowlist (`--allow`) — only the listed CLI commands are permitted.
- Scope-filter non-secret `authsia list` responses when an automation credential is scoped. Direct
  `list` calls require the `list` capability.
- Deny OTP access (TOTP codes cannot be generated).
- Enforce folder scope when `--scope` or `--env` is set. If both are omitted, the credential applies
  to all CLI-enabled non-OTP items.
- OTP export/backup is not available through the CLI; use the app UI.
- Allow SSH signing only when the credential explicitly includes `ssh`; normal CLI unlocks and
  `exec`-only automation credentials do not bypass SSH approval. Shell integration creates a
  transient per-terminal SSH automation grant before foreground commands when
  `AUTHSIA_ACCESS_CREDENTIAL` or `AUTHSIA_SSH_ACCESS_CREDENTIAL` is set; `authsia exec` creates a
  process-bound grant for its launched child.
- Bypass biometric prompts (intended for headless environments).
- Expire automatically after TTL.

**Capabilities (`--allow`):**

| Capability | Purpose | Caller sees plaintext? |
|------------|---------|------------------------|
| `exec` | Run a child process with secrets injected as env vars. | No — stays in child. |
| `load` | Emit `export KEY=…` lines for the current shell. | Yes. |
| `read` | Resolve a single `authsia://…` URI to stdout. | Yes. |
| `get` | Print a secret field (password, key, note content). | Yes. |
| `inject` | Substitute `authsia://…` references inside a template. | Yes. |
| `ssh` | Allow the built-in Authsia SSH agent to sign with allowed SSH keys without an interactive approval prompt. | No. |
| `list` | List CLI-enabled item metadata within the allowed scope. | No secret values. |

Both the CLI and the main app (XPC service) enforce the allowlist. A tampered CLI cannot bypass
the check — the service re-reads the credential file and validates independently.

**Usage:** `authsia access create` prints copy-pasteable `export` lines for the credential it created.
Credentials with any non-SSH capability use `AUTHSIA_ACCESS_CREDENTIAL`. Credentials with `ssh` use
`AUTHSIA_SSH_ACCESS_CREDENTIAL`; mixed credentials print both, while SSH-only credentials print only
the SSH variable.

Examples:

```bash
# Exec-only credential (recommended for most agents)
authsia access create --name ci --scope CI --ttl 2h --allow exec
# All-scope credential for jobs that need every CLI-enabled non-OTP item
authsia access create --name ci-all --ttl 2h --allow exec
# Exec + metadata discovery for agents that need to inspect scoped item names
authsia access create --name ci --scope CI --ttl 2h --allow exec,list
# Exec + env loader (CI that sources into its shell)
authsia access create --name ci --scope CI --ttl 2h --allow exec,load
# Reuse an environment profile; multi-folder profiles grant each folder tree
authsia access create --name ci-prod --env prod-apps --ttl 2h --allow exec,load
# Exec + SSH signing for a local coding agent that needs Git over SSH
authsia access create --name agent --scope Team/API --ttl 15m --allow exec,ssh
export AUTHSIA_ACCESS_CREDENTIAL=<uuid>
export AUTHSIA_SSH_ACCESS_CREDENTIAL=<uuid>

authsia access list --format table      # shows an "Allow" column
authsia access revoke <uuid>
AUTHSIA_ACCESS_CREDENTIAL=<uuid> authsia exec password --folder CI -- make deploy
```

### `authsia env` — Environment profiles

Named mappings of scope selections for quick switching. Profiles can target all CLI-enabled items
of the selected type, or one or more folders. The active profile is used as the default scope when
no explicit scope (`<query>`, `--folder`, `--all`, or `--env`) is given.

**Subcommands:**

#### `authsia env add`

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--name` | Yes | string | Profile name |
| `--folder, -f` | No | folder path, repeatable | Folder path to associate; child folders are included |
| `--all` | No | flag | Use all CLI-enabled items of the selected type |

Use either one or more `--folder` values, or `--all`.

#### `authsia env list`

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--format` | No | `table` (default), `json` | Output format |

#### `authsia env use <name>`

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `<name>` | Yes | string | Profile name to activate |

#### `authsia env clear`

Clears the active environment profile without deleting saved profiles.

Examples:

```bash
authsia env add --name prod --folder Production
authsia env add --name prod-apps --folder Team/API --folder Team/Web
authsia env add --name default --all
authsia env add --name staging --folder Staging
authsia env list
authsia env use prod
# Now "authsia exec password -- make deploy" uses the Production folder scope
authsia env clear
# Explicit scope still wins: --all loads all CLI-enabled items of the selected type
```

### `authsia ssh` — SSH tooling

Utilities for managing SSH keys, config entries, and Git SSH signing.

**Subcommands:**

#### `authsia ssh adopt`

Adopts existing SSH private keys into Authsia. This is the recommended migration path for users who
already have keys and SSH config entries.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--path` | No | file or directory path | SSH private key file or directory to scan (default: `~/.ssh`) |
| `--config` | No | file path | SSH config file to inspect and annotate (default: `config` next to `--path`) |
| `--folder, -f` | No | folder path | Vault folder path for adopted SSH keys |
| `--revert` | No | file path | Restore a previously adopted private key file from a legacy adoption backup |
| `--revert-all` | No | flag | Restore all unrestored private key files that still have legacy adoption backups for the current machine |
| `--machine` | No | machine name | Restore from a specific machine's legacy backup |
| `--dry-run` | No | flag | Preview adoption without modifying files or vault items |
| `--yes, -y` | Required to apply | flag | Apply the adoption plan without an interactive prompt |

Discovery rules:
- Directory scans inspect regular files that are not `.pub` files, then keep only files whose content
  looks like an SSH private key.
- `IdentityFile` paths from SSH config are also considered, including nonstandard filenames.
- A matching `.pub` file is preferred but not required for unencrypted private keys. Authsia uses the
  `.pub` file when present, otherwise derives the public key with `ssh-keygen -y`; derived keys use the
  private-key filename as the fallback comment.
- `HostName`, `User`, and `Host` entries are used to infer per-key bound hosts. Wildcard `*` and
  negated host patterns are not imported as bound hosts.
- Authsia-managed stub files are reported as already managed and skipped.

Apply behavior:
1. Stores the private key in the vault with the derived metadata.
2. Sets approval policy to `session` by default.
3. Applies inferred bound hosts when available.
4. Replaces the private key file with an Authsia-managed stub (permissions preserved).
5. Annotates matching `IdentityFile` entries in the SSH config.
6. Does not create a separate backup note for the private key, because the vault SSH item already contains the private key needed for future recovery.

If the vault already contains a key with the same name, matching fingerprint, and restorable private
key content, adoption does not create another vault item, but still counts the local key as adopted
after replacing it with an Authsia stub. If the same name exists with a different fingerprint, or the
vault private key cannot be retrieved and matched to the local file, adoption skips that file and
leaves it unchanged.

Legacy backup revert behavior:
- Older adoption backup content notes and manifest notes may exist in `Authsia Backups` (or `<folder>/Authsia Backups` when `--folder` was supplied), separate from the adopted SSH key items.
- Legacy adoption backup entries are tagged with kind `sshAdoption`; older entries without kind are interpreted from their existing description.
- `authsia ssh adopt --revert <path>` restores the most recent unrestored legacy backup for the
  current machine.
- `authsia ssh adopt --revert <path> --machine <name>` restores from a specific machine's legacy
  backup.
- `authsia ssh adopt --revert-all` restores all unrestored legacy SSH adoption backups for the
  current machine.
- `authsia ssh adopt --revert-all --machine <name>` restores all unrestored legacy SSH adoption
  backups for the named machine.
- Revert restores key file content and does not prompt to delete the legacy backup note afterward.
- To discover machine names for older or cross-machine backups, run
  `authsia scrape --list-modified --all-machines`.

Examples:

```bash
authsia ssh adopt --path ~/.ssh --dry-run
authsia ssh adopt --path ~/.ssh --yes --folder Infra/SSH
authsia ssh adopt --path ~/.ssh/id_ed25519 --config ~/.ssh/config --yes
authsia ssh adopt --revert ~/.ssh/id_ed25519
authsia ssh adopt --revert-all
```

#### `authsia ssh generate`

Generates an ed25519 or RSA keypair with no passphrase, stores the private key in the vault, writes the
public key to disk, and leaves an Authsia-managed stub at the private-key path.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--name` | Yes | string | Key name in the vault |
| `--path` | No | directory path | Output directory for key files (default: `~/.ssh`) |
| `--type, -t` | No | `ed25519`, `rsa` | Key type to generate (default: `ed25519`) |
| `--bits` | No | `2048`, `3072`, `4096` | RSA key size (default: `4096` when `--type rsa`) |

The public key file is written to disk for normal SSH configuration. The private key is stored in the
vault; the on-disk private-key path contains only the Authsia-managed stub at 0600.

#### `authsia ssh config`

Adds or updates an SSH config host entry (`~/.ssh/config`).

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--host` | Yes | hostname | SSH host pattern |
| `--alias` | No | string | Host alias (defaults to `--host` value) |
| `--key` | Yes | string | Vault SSH key name for Authsia guidance in the host entry |
| `--user` | No | string | SSH user |
| `--config` | No | file path | SSH config file path (default: `~/.ssh/config`) |

Upserts the host entry — if a matching `Host` block exists, it is updated in place. The entry points
SSH at `IdentityAgent $SSH_AUTH_SOCK`; shell integration is responsible for setting `SSH_AUTH_SOCK`
to Authsia's built-in agent socket (`~/.authsia/agent.sock`), which is launchd
socket-activated and available even when the GUI app is closed.

#### `authsia ssh git-signing`

Configures repo-local Git SSH signing.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--principal` | Yes | email | Signer identity (e.g., `user@example.com`) |
| `--public-key` | Yes | file path | Path to the public key file |
| `--repo` | No | directory path | Repository path (default: current directory) |

Sets `gpg.format=ssh`, `user.signingkey`, `commit.gpgsign=true`, and `tag.gpgsign=true` in the
repo's local git config. Creates or updates an `allowed_signers` file in the repo.

Examples:

```bash
authsia ssh generate --name deploy
authsia ssh adopt --path ~/.ssh --dry-run
authsia ssh config --host github.com --key deploy --user git
authsia ssh git-signing --principal user@example.com --public-key ~/.ssh/deploy.pub
```

### `authsia status` — System health

Displays bridge connectivity, this terminal's interactive session state, shell integration status,
SSH agent status, and this terminal's session-based SSH approval status. CLI and SSH approval
session state comes from the current terminal scope only; sessions held by other terminals or apps
are not reported and do not make this terminal report as unlocked.
`status` reports the current human terminal scope even when an automation credential environment
variable is present. When the CLI runs without tty stdio, the terminal scope is resolved from the
controlling terminal of the nearest tty-bearing ancestor process, so `status` and `lock` see the
same scope the SSH agent records for approvals made from that terminal.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--format` | No | `table` (default), `json` | Output format |

Example output (table):

```
Authsia Status
Bridge: Connected
Session: Active (12s remaining)
Shell Integration: Enabled
SSH Agent: Running
SSH Session: Active (10s remaining, 1 key)
Workspace: selected-api (api) - Workspaces/selected-api
```

`SSH Session` reflects only the current terminal's approval session; approvals held by other
terminals are not shown. JSON output includes a `terminalScope` field with the CLI-resolved
terminal scope (`tty` path + process session ID) for diagnosing scope mismatches against
`~/.authsia/ssh-agent-session.json`. When run inside a repo with `.authsia/workspace.json`,
status also includes display-only workspace context (`workspace.name`, `workspace.rootLabel`,
and `workspace.authsiaFolder`) so users can confirm which repo-local workspace the terminal is in.
The workspace label is never used for authorization.

### `authsia doctor` — Diagnostics

Checks for common setup issues and prints results with suggested fixes.

Checks performed:
- Bridge connectivity (is the app running and XPC listener active?)
- Shell integration (is the shell integration block present in the active shell config?)
- SSH agent (is Authsia's built-in `~/.authsia/agent.sock` available, or is an external agent available for explicit `--system-agent` use?)
- Session expiry (does this terminal have a valid scoped cached session?)

Example output:

```
[PASS] Bridge connected
[PASS] Shell integration installed (zsh)
[WARN] Authsia SSH agent socket not found
       Fix: Launch Authsia once to register its SSH agent, then run `eval "$(authsia init zsh)"`
[PASS] Session valid (expires in 8s)
```

### `authsia setup` — First-run and repair

The app provides the native first-run flow. On first launch it guides the user through:

1. Enable CLI access
2. Install the CLI and managed shell integration
3. Register the bridge
4. Enable the Authsia SSH agent
5. Create the first password folder path
6. Create the first vault password, including per-item CLI access and auto-destroy
7. Run doctor and show "Authsia is ready"

The CLI command is the terminal repair/status entrypoint for the pieces the CLI can safely manage.

| Command | Behavior |
|---|---|
| `authsia setup` | Repair managed shell integration, then print setup status |
| `authsia setup --status` | Print setup status without changing files |
| `authsia setup --repair` | Reinstall managed shell integration, then print setup status |
| `authsia setup --uninstall-clean` | Remove only Authsia-managed shell integration blocks and the managed user symlink |

Example output:

```
Authsia setup status:
  OK  Install CLI
  OK  Install shell integration
  OK  Register bridge
  Needs attention  Enable SSH agent
  Needs attention  Run doctor
```

#### Bridge and metadata troubleshooting

| Symptom | Meaning | Fix |
|---|---|---|
| `authsia status` shows `Bridge: Disconnected` after install | The LaunchAgent is not registered/running, or launchd cannot exec the bridge role | Open `/Applications/Authsia.app` once, then check `launchctl print "gui/$(id -u)/Authsia.Bridge"` and verify the plist points to `/Applications/Authsia.app/Contents/Helpers/AuthsiaHeadless.app/Contents/MacOS/authsia-headless`. |
| `launchctl` shows `Authsia.Bridge` repeatedly scheduled or exiting | Signing/AMFI or plist path issue before the Mach service starts | Verify `codesign --verify --verbose=4 /Applications/Authsia.app`; inspect unified logs for `Authsia.Bridge` and `No matching profile found`. Do not add Keychain entitlements to copied helper binaries. |
| `authsia list passwords` is empty but vault rows are visible in the app | The bridge is not seeing live vault metadata, or automatic CLI metadata snapshot refresh did not run | Verify `authsia status`, relaunch the current Authsia app build once to force a vault load and snapshot refresh, then retry `authsia list passwords --format table --all-machines`. |
| `authsia list passwords` shows rows but `authsia load password --folder ...` reports `Keychain item not found` | Metadata lookup succeeded, but the bridge could not read the matching secret from the current or legacy vault Keychain service | Verify `authsia status` is connected and reinstall the current app build so launchd runs the entitled nested headless helper in bridge mode. |

#### Git/SSH troubleshooting

| Symptom | Meaning | Fix |
|---|---|---|
| `git push` appears to wait forever | The SSH client is waiting for the Authsia signing approval flow, or the app is not presenting the approval window | Bring Authsia to the foreground, confirm the prompt, then retry. If no prompt appears, restart the app and verify the socket with `ssh-add -L`. |
| `sign_and_send_pubkey: ... string is too large` | An older agent build used a nested signing socket path that could exceed macOS Unix-domain socket limits | Install the current app build and restart Authsia; the agent now uses short `/tmp/authsia-.../agent.sock` paths. |
| `sign_and_send_pubkey: ... agent refused operation` | Approval was denied/timed out, the key is disabled or missing, the host is not allowed, or signing failed | Run `authsia list ssh --format table`, check the key approval policy and bound hosts, then test `SSH_AUTH_SOCK="$HOME/.authsia/agent.sock" ssh-add -L`. |
| Git reports `Permission denied (publickey)` | The remote does not accept any public key offered by the agent, or host binding rejected the requested host | Add the vault key's public key to the remote service and verify bound hosts include the remote host, for example `github.com`. |
| A passphrase prompt appears for an unencrypted key | This should not happen on the current build | Restart Authsia and reinstall the current app. Encrypted keys may prompt unless a passphrase is stored with the vault item. |

### `authsia audit` — Audit event access

#### `authsia audit list`

Displays selected audit events oldest-to-newest, so the newest event appears at the bottom.
When `--limit` is used, Authsia selects the most recent matching events before applying that display order.
Table output includes an `Agent` column when hook-provided Claude Code or Codex attribution is present,
the `Workspace` column for entries captured from commands run inside a repo-local workspace, and an
`Environment` column for environment-scoped JIT approvals and secret reads.
Workspace attribution stores only the workspace name, root basename label, and configured Authsia
folder; it does not store the absolute local repo path or change authorization. Environment attribution
stores only `Default environment` or the selected environment tag, never resolved secret values.

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--format` | No | `table` (default), `json` | Output format |
| `--type, -t` | No | event type | Filter by event type |
| `--limit` | No | integer | Maximum number of events to return |

#### `authsia audit export`

| Parameter | Required | Values | Description |
|-----------|----------|--------|-------------|
| `--format` | No | `json` (default), `ndjson` | Export format |
| `--out` | Yes | file path | Output file path |

Examples:

```bash
authsia audit list --format table
authsia audit list --type get --limit 50
authsia audit export --format ndjson --out events.ndjson
```

## Agentic AI Workflows

AI coding agents (Codex, Claude Code, Cursor, Windsurf, GitHub Copilot) observe terminal output, environment
variables, file contents, and shell history. Any plaintext secret that appears in any of these surfaces
is captured by the agent's context window and potentially sent to a remote API.

### The pattern: references until the last mile

Use `authsia://` URIs everywhere a secret would go. These references contain no secret data — they are
safe to display, commit, and share with agents. Secrets are only resolved at the final
biometric-approved or scoped automation execution step via `authsia exec`.

```
Agent writes:     DB_PASS=authsia://password/Prod-DB/password   (no secret data)
User approves:    Touch ID / session unlock                      (one-time gate)
Exec resolves:    DB_PASS=actual-secret → child process only     (masked in output)
```

### Project rules

Add instructions to the agent's rules file so it uses `authsia://` references by default.

**Codex** — `AGENTS.md`:

```markdown
## Secret Management
- Never inline plaintext secrets in code, env files, shell commands, logs, or final answers.
- Use authsia:// reference URIs for secret values:
  - authsia://password/<name>/password
  - authsia://api-key/<name>/key
  - authsia://cert/<name>/privateKey
  - authsia://note/<name>/content
- Run commands that need secrets through:
  - env AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia exec -- <command>
  - env AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia exec --env-file path/to/.env -- <command>
- For background runs, use automation credentials with --allow exec, plus list only when metadata discovery is required, and ssh only when Git/SSH signing is required.
- Masking is always enabled for `authsia exec`.
- Do not use authsia get/load/read/inject to expose plaintext secrets to the agent context.
- List non-secret item names with: env AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia list passwords --format table
- List non-secret API key names with: env AUTHSIA_AGENT_PLATFORM=codex AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia list api-keys --format table
```

**Claude Code** — `CLAUDE.md`:

```markdown
# Secret Management
# - NEVER inline plaintext secrets in code, env files, or shell commands.
# - Use authsia:// reference URIs for all secret values:
#     authsia://password/<name>/password
#     authsia://api-key/<name>/key
#     authsia://cert/<name>/privateKey
#     authsia://note/<name>/content
# - Run commands that need secrets via:
#     env AUTHSIA_AGENT_PLATFORM=claude-code AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia exec -- <command>
#     env AUTHSIA_AGENT_PLATFORM=claude-code AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia exec --env-file path/to/.env -- <command>
# - NEVER run: export SECRET=..., echo $SECRET, or cat credentials.
# - Available passwords: env AUTHSIA_AGENT_PLATFORM=claude-code AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia list passwords --format table
# - Available API keys: env AUTHSIA_AGENT_PLATFORM=claude-code AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia list api-keys --format table
```

**Cursor** — `.cursor/rules`:

```
# Secret Management
# Never inline plaintext secrets. Use authsia:// URIs:
#   authsia://password/<name>/password
#   authsia://api-key/<name>/key
# Run: authsia exec -- <command>
# Agent JIT: env AUTHSIA_AGENT_PLATFORM=cursor AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia exec -- <command>
# Explicit env file: authsia exec --env-file path/to/.env -- <command>
# List: env AUTHSIA_AGENT_PLATFORM=cursor AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia list passwords --format table
# List API keys: env AUTHSIA_AGENT_PLATFORM=cursor AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia list api-keys --format table
```

**Windsurf** — `.windsurfrules` / **GitHub Copilot** — `AGENTS.md`:

```
# Secret Management
# Never hardcode secrets. Reference them via authsia:// URIs.
# Pattern: authsia://password/<name>/password
# Pattern: authsia://api-key/<name>/key
# Execute: authsia exec -- <command>
# Agent JIT: env AUTHSIA_AGENT_PLATFORM=<windsurf|copilot> AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia exec -- <command>
# Explicit env file: authsia exec --env-file path/to/.env -- <command>
# List: env AUTHSIA_AGENT_PLATFORM=<windsurf|copilot> AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia list passwords --format table
# List API keys: env AUTHSIA_AGENT_PLATFORM=<windsurf|copilot> AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia list api-keys --format table
# Never run bare authsia get/read/load/code/inject from an agent; unprefixed Authsia commands are direct human CLI.
```

### Just-in-time agent grants

When Authsia detects a local coding agent or IDE helper/extension host running `authsia exec`
for CLI-enabled vault items, or direct `authsia list` for supported Vault metadata, it can create a
temporary JIT grant after user approval. Direct human terminal requests keep the normal session or
biometric approval flow instead of creating JIT grants. A named-folder JIT scope covers that folder
and slash-delimited descendants, but never ancestors or sibling trees. Root is a special root-only
scope and never means the whole vault. JIT permits only `exec` and scoped metadata `list`, follows the
CLI session timeout setting, retains caller-fingerprint, terminal/session, working-directory,
CLI-enabled-item, audit, and revocation checks, and appears in Access Center.

The grant is approved once for the folder tree, then every later `exec`/`list` in that tree
matches it silently for the grant's lifetime. Descendant requests collapse into and reuse an active
ancestor grant. An unrelated folder tree needs a separate approval, and the same covered tree can
need another approval when the request adds a capability not already present, such as `exec` after a
list-only grant. Approval copy states whether the request adds an unrelated
folder scope or a new capability. A first broad unscoped list approval with no
active scopes says `across all resolved folders` and does not enumerate pending
paths. When active grants exist and separate approval adds unrelated scopes, the
prompt lists pending new folder paths and active scopes. Broad prompts never
include vault item or secret names.
So an agent whose first action touches several
`authsia://` references — for example a connectivity check that probes every configured token — can
surface a single up-front approval before the user types a follow-up prompt. This is expected: it is
one scoped grant for the session, not a per-secret prompt and not a duplicate of a direct-CLI
approval.

Routing uses more than terminal appearance. When no explicit automation
credential is supplied, confirmed `agentRuntimeContext` takes the JIT path;
automation credentials use their separate authorization path. Ancestry-only
invocations without an stdin TTY remain JIT. An ancestry-only IDE terminal is
an ongoing human session only when stdin is a TTY and the request presents the server-current token
for the same terminal scope. TTY alone is neither authorization nor a classifier override. A first
stdin-TTY request without confirmed agent runtime context may take the narrow biometric bootstrap
path; it returns no metadata or secret before approval and then mints the normal scoped terminal
session. Existing JIT grants do not authorize that bootstrap or the human list path. Redirecting
stdout does not alter this decision because it is based on stdin.

Access Center's `Include human sessions` toggle shows active human CLI sessions
for revocation and recent 30-day human CLI activity, up to 200 records,
reconstructed from audit records in a right-side column beside agent grants.
The same toggle lets human audit records contribute to Access Insights folder
and vault-item summaries.

Claude Code, Codex, and GitHub Copilot command-history integrations are observability only. Claude
Code uses generated Bash tool hooks as the first capture layer. GitHub Copilot uses the generated
Copilot CLI `PreToolUse` Bash hook when `.github/copilot/settings.local.json` can be installed.
Authsia also uses macOS process monitoring as a fallback/corroboration layer, but only records
processes that can be tied to an active Authsia-managed agent terminal scope, including local VS Code
Copilot extension-host ancestry. Access Center grant cards expose an Agent activity sheet with
Commands and Files views plus JSON export. Records are redacted before persistence and store command metadata only:
time, tool/platform, grant/session context, cwd when available, executable, argv or command string
after safe redaction, exit status when available, and capture source. They do not store command
output, stdin, environment values, vault item contents, or secrets.

Agent file activity in Access Center is local display evidence only. Authsia records path metadata
from supported agent tool hooks, including action, status, source, and confidence. It does not store
file contents, command output, stdin, environment values, or plaintext secrets. JSON export uses
workspace-relative paths for workspace-contained file activity and omits the matching absolute path,
working directory, and workspace root.

Confidence labels are:

- `Direct`: a supported hook reported the file or directory for the tool call.
- `Confirmed`: a post-tool hook reported success for the same tool call.
- `Inferred`: Authsia detected a workspace change during the session, not a direct read.
- `Fallback`: Authsia associated activity by terminal/session scope and working directory.

Actual Authsia secret access remains governed by JIT grants, bridge policy, named-folder subtree scope,
capability, TTL, and audit records. File activity does not grant or deny access.

Access Center derives local investigation flags from this metadata, matching JIT grants, and audit
records. Flags are display-only and do not call AI, send data out, persist separately, store command
output, block commands, revoke grants, or change authorization. Severities are limited to `Info`,
`Review`, and `Warning`. V1 flags commands recorded after ended grants, process-only captures without
a nearby matching hook event for hook-capable tools, direct agent secret-read attempts (`authsia get`,
`authsia read`, `authsia load`, `authsia inject`), possible environment exposure commands (`env`,
`printenv`, `.env` reads), and process fallback where hooks are unavailable. The Commands view can
filter `All` or `Flagged` rows, and JSON export includes `commands`, `files`, `findings`, and
`summary` counts.

The same hook metadata can attach display-only agent or subagent attribution to JIT grants and audit
records. Attribution is not trusted for authorization. JIT still binds grants to the OS caller
fingerprint, terminal/session scope, working directory, folder-tree scope, capability, and TTL.

Agents that cannot install a hook, including VS Code-only Copilot terminal flows, can mark a single
Authsia command explicitly instead:

```bash
env AUTHSIA_AGENT_PLATFORM=copilot AUTHSIA_AGENT_INVOKES_AUTHSIA=1 authsia exec api-key API_KEY -- npm test
```

The marker contains metadata only. It makes `exec` and approved metadata `list` requests eligible for
agent JIT; it does not authorize plaintext export commands such as `get`, `load`, `read`, or `inject`.
Unprefixed Authsia commands are treated as direct human CLI, so GitHub Copilot must include the marker
on every local Authsia terminal command it runs.

Maintainer-level flow, enforcement, and triage details live in
[`Doc/ops/jit-agent-grants.md`](../ops/jit-agent-grants.md).

### Automation credentials for background agents

For agents that run without interactive biometric approval (CI runners, background editors, scheduled
tasks), create an automation credential. Add `--scope` to restrict it to one folder, use `--env`
to reuse an environment profile with one or more folders, or omit both to apply it to all
CLI-enabled non-OTP items:

```bash
# Exec + SSH credential scoped to Team/API, expires in 15 minutes
authsia access create --name claude-code --scope Team/API --ttl 15m --allow exec,ssh

# Or scope to every folder in an environment profile
authsia access create --name claude-code --env prod-apps --ttl 15m --allow exec,ssh

# Set the env vars printed by the create command so Authsia CLI and SSH agent can validate this session
export AUTHSIA_ACCESS_CREDENTIAL=<uuid>
export AUTHSIA_SSH_ACCESS_CREDENTIAL=<uuid>

# Agent can now inject secrets via exec — no biometric prompt
authsia exec -- npm test

# Agent can also use allowed SSH keys for Git without a separate approval prompt
git push

# Output masking: even if the agent dumps the environment, secret VALUES are
# concealed in the output — only the variable names remain visible
authsia exec password --folder Team/API -- printenv
# ELASTICSEARCH_URL=<concealed by authsia>
# ELASTICSEARCH_API_KEY=<concealed by authsia>

# The same credential cannot read secrets any other way:
authsia get password GitHub           # → denied: does not permit 'get'
authsia load password --query API_KEY # → denied: does not permit 'load'

# Revoke when done
authsia access revoke <uuid>
```

Guardrails:

| Property | Protection |
|----------|------------|
| `--allow` | Only the listed capabilities are permitted. `--allow exec` keeps secrets inside child processes; add `list` only for scoped metadata discovery, and `ssh` only when the agent also needs Git/SSH signing. |
| `--scope` / `--env` | Optional. `--scope` grants one folder tree; `--env` grants the all/folder scope from an environment profile, including multiple folder trees. When both are omitted, the credential applies to all CLI-enabled non-OTP items. |
| `--ttl` | Credential auto-expires after the time window. |
| Local only | Credential is machine-bound — cannot be used remotely. |
| OTP export unavailable | OTP export/backup is not available through the CLI; use the app UI. |
| Credential not inherited | `authsia exec` removes `AUTHSIA_ACCESS_CREDENTIAL` from the launched child process. If the credential allows `ssh`, it forwards only `AUTHSIA_SSH_ACCESS_CREDENTIAL`, which only the built-in Authsia SSH agent accepts. |
| SSH scope checked | SSH signing still requires an active local credential, the `ssh` capability, a CLI-enabled SSH key inside scope when scoped, and a matching bound host when the key has host bindings. |
| Stream-safe masking | `authsia exec` masks secret values, supported common encodings, and supported deterministic transformations in stdout/stderr even when the child writes the value across pipe-buffer boundaries. |
| Audit logged | Every create, use, and revoke is in the tamper-evident audit log; each entry records both the underlying RPC and the initiating CLI command (`requestedCommand`). |

### Scoped SSH for agentic Git

The normal CLI unlock window does not automatically approve SSH signing. SSH operations are evaluated
by the built-in Authsia SSH agent because OpenSSH asks the agent to sign, not the CLI. For agentic Git
workflows, grant `ssh` explicitly on the automation credential:

```bash
authsia access create --name claude-code --ttl 15m --allow exec,ssh
export AUTHSIA_ACCESS_CREDENTIAL=<uuid>
export AUTHSIA_SSH_ACCESS_CREDENTIAL=<uuid>
git push
```

With Authsia shell integration, `git push` runs through the built-in SSH agent. The shell hook creates
a transient grant for the current terminal, and the SSH agent re-validates `AUTHSIA_SSH_ACCESS_CREDENTIAL`
before signing.

Without an automation credential, a key with session-based approval prompts through the Authsia app
and caches that SSH approval per key for the current terminal until the SSH approval session TTL
expires (`sshSessionTTL`, default 30 minutes). This is independent from the password/CLI session
token and `authsia unlock` does not pre-approve SSH signing.

### Per-item CLI access control

Every vault item has an individual CLI toggle in the Authsia app (Settings → item detail). When
disabled, the CLI will refuse to return that item regardless of session state or automation
credentials. SSH signing also honors this toggle, so disable it for SSH keys that should never be
available to agentic or CLI workflows.

### Quick reference by tool

| Tool | Rules file | Recommended pattern |
|------|-----------|-------------------|
| Codex | `AGENTS.md` | Local IDE: `authsia exec -- <cmd>` with the Authsia agent marker |
| Claude Code | `CLAUDE.md`, `.claude/settings.local.json` | Outside-sandbox `authsia exec -- <cmd>` + the SSH-agent socket exception and command-history hooks |
| Cursor | `.cursor/rules/authsia.mdc` | `authsia exec -- <cmd>` |
| Windsurf | `.windsurf/rules/authsia.md` | `authsia exec -- <cmd>` |
| GitHub Copilot | `AGENTS.md` | Local IDE: `authsia exec -- <cmd>`; cloud agents leave `authsia://` refs for local execution |
| GitHub Actions | `.github/workflows/*.yml` | `authsia exec -- make deploy` with automation credential |
| Any terminal agent | — | Set `AUTHSIA_ACCESS_CREDENTIAL` + `authsia exec`; add `--allow list` for metadata discovery and `--allow ssh` only for Git/SSH signing |

### Migration: existing plaintext secrets

If a project already has plaintext secrets in `.env` files or shell configs, use `authsia scrape` to
detect and auto-rewrite them:

```bash
# Preview what would change
authsia scrape --path .env --dry-run

# Auto-migrate secrets and rewrite files with authsia:// references
authsia scrape --path .env --replace-all --folder Team/API
```

For one-off snippets, use the macOS menu-bar action **Store Clipboard in Authsia...** after copying the
selected secret text. The importer recognizes:

- `export NAME=value`
- `NAME=value`
- `name: value` pairs, including names with dots or hyphens
- JSON objects, stored as secure notes
- Plain fallback text, stored as a secure note

Clipboard imports default to per-item CLI access on. The import panel can choose a vault folder, disable
CLI access for the imported items, and clear the clipboard only if it still contains the imported text.
When storing into a workspace, **Environment association** defaults to its active named environment or
the **Default environment** when no named environment is active. The user can associate the item with multiple named
environments; the Default environment remains the empty-tag tier and is exclusive. Same-name items in the exact same folder
are duplicates only when both use the Default environment or their named tag sets overlap. Updating an existing item
preserves its tags, and generated `authsia://` references do not gain an environment component.
When the active project is an Authsia workspace with no managed env file, the import panel offers
**Add to workspace env** after storing. Applying that preview writes `NAME=authsia://...` bindings to
`.authsia/workspace.json`, so future commands can use `authsia workspace run -- <command>` without a
temporary env file or one `workspace env add` command per secret.

---

## CLI Request Flow (Current Behavior)

1. CLI loads a cached session token from its terminal-scoped Keychain account on startup, when a
   live tty and macOS process session identity exist and no automation credential marker is present.
   Inherited terminal environment IDs such as `TERM_SESSION_ID` are not used as an interactive session boundary.
2. CLI builds a `BridgeRequest` with context flags (TTY/piped/SSH/CI), the current terminal session scope (`tty` + process session ID), and the session token (if available).
3. XPC connection is established; the app validates the caller's code signature and team ID before accepting.
4. App XPC handler checks policy. SSH signing is handled by the built-in Authsia SSH agent, which
   enforces per-item CLI access, host bindings, approval policy, and scoped automation credentials.
5. Global CLI access toggle is enforced:
   - If disabled, `list` returns an empty payload; other commands return `policyDenied`.
6. Human/agent routing is resolved before secret release:
   - Without an explicit automation credential, confirmed agent runtime context selects JIT; automation credentials use their separate authorization path. Ancestry-only noninteractive invocations also select JIT.
   - An ancestry-only IDE invocation counts as an ongoing human session only with stdin TTY plus a server-current same-scope token. TTY alone does not authorize the request.
   - An eligible first stdin-TTY request with no confirmed agent runtime context can reach biometric bootstrap, but receives no metadata or secret before approval. Active JIT grants do not authorize this human path, and stdout redirection does not change the result.
7. Session and anti-replay validation:
   - The handler calls `validateSessionAndRequest()` which checks that the session token belongs to the same terminal scope and that the request ID has not been used before.
   - If the scoped session is valid and the request ID is fresh, approval is **skipped** (no biometric prompt).
   - Otherwise: a biometric prompt (`deviceOwnerAuthentication`) is presented. The app activates
     itself first so the prompt appears even when the bridge is running headless (launchd-spawned),
     and suppresses its main window (`BridgeApprovalCoordinator.isApprovalInProgress`) so only the
     approval prompt is shown — never the app window.
   - If biometric is unavailable or denied, the request is rejected (`notAuthorized`). CLI approval is
     biometric-only; there is no terminal y/n fallback.
8. On successful biometric/approval, a **new scoped session is created** server-side and the new session token is returned in `BridgeResponse.sessionToken`.
9. Per-item CLI toggle is enforced for get/edit/delete on passwords, API keys, certs, and notes, and for SSH key signing.
10. Repository load occurs before writes; metadata is saved, secrets go to Keychain.
11. Response is encoded as `BridgeResponse` (including `sessionToken` if newly issued) and returned to the CLI.
12. CLI receives the response, extracts any new session token, and caches it in a terminal-scoped
    CLI Keychain item. Automation credential shells and non-terminal contexts do not persist or load
    the interactive session token.

```
┌──────────┐        XPC (Mach Service)        ┌──────────────┐
│ authsia  │ ──── BridgeRequest + token ────▶  │  Authsia App │
│  CLI     │                                   │              │
│          │  ◀── BridgeResponse + newToken ── │  XPCHandler  │
└──────────┘                                   └──────────────┘
     │                                               │
     │  SessionCache                          BridgeSessionManager
     │  terminal-scoped Keychain              (in-memory, server-side)
     │  - token (string)                      - session scope -> token
     │  - expiresAt (date)                    - used request IDs (Set<UUID>)
     │  - no automation marker                - TTL from app.authsia preferences
     │                                        - max 1000 tracked request IDs
```

## Session Model (CLI Unlock)

- `authsia unlock` triggers biometric and creates a new terminal-scoped session in the app process.
- The session token (32 bytes from `SecRandomCopyBytes`, base64-encoded) is returned to the CLI.
- CLI persists the token to a terminal-scoped Keychain account keyed by live tty plus macOS process session ID, with the server-provided expiry time.
- Subsequent CLI invocations from the same terminal process session load the cached token and attach it to protected requests.
- CLI processes with `AUTHSIA_ACCESS_CREDENTIAL` or `AUTHSIA_SSH_ACCESS_CREDENTIAL` do not load or save this interactive cache.
- `authsia lock` clears the current terminal's cached token, asks the app to revoke the matching scoped server-side session, and clears the current terminal's SSH approval-session status.
- Session TTL is read from the GUI app preferences key `cliSessionTTL` in the `app.authsia` domain; default is **15 seconds** (`BridgeSessionManager.configuredTTL`).
- SSH approval session TTL is read from `sshSessionTTL` in the same preferences domain; default is
  **30 minutes** and is independent from `cliSessionTTL`. Both settings have a maximum of **24 hours**;
  legacy negative (Never) values are treated as 24 hours.
- GUI-mode and headless bridge runs share the app bundle identifier and preferences domain because launchd runs the nested `AuthsiaHeadless.app` helper with `AUTHSIA_ROLE=bridge`.
- `XPCRequestHandler` delegates to `BridgeSessionManager.configuredTTL` — no separate fallback value.
- Sessions are **in-memory on the server** (do not survive app relaunch); cached tokens on the CLI side become invalid when the app restarts.

### Implicit Session Creation

When a non-unlock command (e.g., `list`, `get password`, `get api-key`) triggers biometric approval (because no valid session exists), the server **also creates a session** and returns the token in the response. This means:
- The user does not need to run `authsia unlock` explicitly.
- Any command that triggers biometric will establish a session for subsequent commands.
- The CLI caches this token identically to an explicit `unlock` only when the process is eligible for the interactive terminal cache.

## App Lock & Auto-Lock (GUI)

Current behavior (as implemented by AppLockService):
- App starts locked by default (isLocked = true).
- Lock UI is only shown when shouldShowLockUI becomes true.
- shouldShowLockUI is set on:
  - Returning from background or deminiaturizing a window when the app decides to lock.
  - Foreground inactivity timer expiry (timeout > 0).
- Activity is tracked continuously; any interaction resets the inactivity timer.

Auto-lock logic (appAutoLockTimeout):
- -1: never auto-lock.
- 0: lock immediately when returning from background.
- >0: lock when inactivity exceeds the timeout; timer checks every second.
- On macOS, minimize/restore uses a separate path; background transitions are not always triggered.

Initial launch behavior:
- On initial app launch (first active foreground without backgrounding), the lock UI is shown immediately when locked.
- The lock overlay triggers biometric authentication on appearance.

## Limitations & Constraints (Current)

- macOS only. The CLI talks to the app over a launchd Mach service (`Authsia.Bridge`) that launches
  the signed nested `AuthsiaHeadless.app` executable **on demand, headless** — so the app does not need to be kept running. It must, however,
  have been launched at least once (the GUI launch registers the LaunchAgent via `SMAppService`) and
  be installed in `/Applications` (the agent's `ProgramArguments` path is fixed). Until then the CLI
  reports that the bridge is unreachable.
- SSH signing works the same way: a second per-user LaunchAgent (`Authsia.SSHAgent`) owns
  `~/.authsia/agent.sock` via launchd **socket activation** and spawns the nested headless helper when `git`/`ssh`
  connect, so the GUI app does not need to be running. This agent's plist is generated at runtime into
  `~/Library/LaunchAgents` (its `SockPathName` must contain the user's home, which can't be baked into the
  signed bundle), so it too requires launching the GUI app once to register.
- CLI never accesses Keychain directly; all secrets flow through the app.
- List commands return live metadata when available and may use the app-written
  non-secret CLI metadata snapshot when live vault metadata is empty. Secret
  lookup by ID merges missing snapshot rows before reading from Keychain, so
  folder loads can use the same IDs shown by `list` without storing secret
  values in the snapshot.
- Generic SSH/CI secret retrieval is policy-gated; SSH key signing uses the built-in Authsia SSH agent policy path.
- List returns metadata only; no secrets are ever listed.
- Writes only support JSON output; table output is rejected for add/edit/delete.
- Match behavior is deterministic: exact ID match → exact name → prefix (unique) → contains (unique); multiple matches return a `multipleMatches` error with candidate IDs for disambiguation.
- Per-item CLI access must be enabled in the app for get/edit/delete and SSH key signing.
- CLI approval is biometric-only and presents whether the app is already running or launched headless
  on demand; the approval prompt is shown without surfacing the app's main window.
- CLI session TTL default is 15 seconds and maximum is 24 hours
  (`BridgeSessionManager.configuredTTL` / `cliSessionTTL`).
- SSH session-based approval uses an independent SSH approval TTL (`sshSessionTTL`, default 30
  minutes, maximum 24 hours) plus a separate per-key SSH signing approval cache.
- Server-side sessions are in-memory only; app restart invalidates all cached CLI tokens.
- Anti-replay request ID set is capped at 1000 entries; oldest entries are pruned on overflow.
- Scrape operates locally — does not use XPC bridge for scanning, only for adding migrated secrets.
- SSH private key files are replaced with a stub only after explicit `authsia ssh adopt`.
  `authsia scrape` skips SSH private keys and prints adoption guidance instead. Adoption stores the
  private key in the vault before stubbing the local file and does not create a separate plaintext
  backup note. Legacy adoption backups can still be restored with `authsia ssh adopt --revert <path>`.
- Normal SSH use should go through the built-in Authsia SSH agent. `authsia load ssh --system-agent --ttl <seconds>` is an unsafe compatibility escape hatch for copying eligible keys into an external `ssh-agent`.
- The built-in SSH agent supports OpenSSH host-bound sessions through `session-bind@openssh.com` and uses short temporary signing sockets to stay under macOS Unix-domain socket path limits.
- `authsia ssh adopt` can derive public-key metadata when a matching `.pub` file is absent, but it does
  not prompt for private-key passphrases during adoption. Encrypted keys without readable `.pub` metadata
  may still need a `.pub` file, and encrypted adopted keys may prompt during signing unless their
  passphrase was stored by another migration path.
- Scrape backups are stored as secure notes in the `Authsia Backups` folder (or `<folder>/Authsia Backups` when scoped); backup scope defaults to the current machine. A shared manifest note indexes entries with a typed `kind` rather than maintaining separate metadata notes per category. Legacy SSH adoption backups may still appear there, but new SSH adoption does not create duplicate backup notes.
- Server-side sessions are in-memory only; app restart invalidates all cached CLI tokens after backup restore.

---

## Output Formats

All commands that return data support `--format json` (default) and `--format table`.

- **JSON**: Pretty-printed with sorted keys and ISO 8601 dates. Suitable for scripting and piping to `jq`.
- **Table**: ASCII table for lists, key-value pairs for single items. Human-readable.

When `--field` returns a single raw value (e.g., `--field username`), the output is always plain text regardless of `--format`.

Write commands (`add`, `edit`, `delete`) only support `--format json`. Using `--format table` returns an error.

---

## File Structure

```
Packages/AuthsiaCLI/
├── Package.swift
├── Signing/
│   └── authsia.entitlements.template
├── Sources/authsia/
│   ├── AuthsiaCLI.swift              # @main entry point, subcommand routing
│   ├── CodeService.swift             # OTP generation service
│   ├── Bridge/
│   │   ├── AuthsiaBridgeClient.swift # XPC client (retry, timeout, context, token caching)
│   │   ├── WriteRequestBuilder.swift # Builds write BridgeRequests with session token
│   │   └── SessionCache.swift        # Terminal-scoped session token persistence (Keychain)
│   ├── Commands/
│   │   ├── AccessCommand.swift      # authsia access
│   │   ├── AgentCommand.swift       # authsia agent
│   │   ├── CodeCommand.swift         # authsia code
│   │   ├── CompletionCommand.swift  # authsia completion
│   │   ├── DoctorCommand.swift      # authsia doctor
│   │   ├── EnvCommand.swift         # authsia env
│   │   ├── ExecCommand.swift        # authsia exec
│   │   ├── GetCommand.swift          # authsia get
│   │   ├── InjectCommand.swift      # authsia inject
│   │   ├── ListCommand.swift         # authsia list
│   │   ├── LockCommand.swift        # authsia lock
│   │   ├── ReadCommand.swift        # authsia read
│   │   ├── ScrapeCommand.swift       # authsia scrape (scan + migrate secrets)
│   │   ├── SetupCommand.swift       # authsia setup
│   │   ├── SSHCommand.swift         # authsia ssh
│   │   ├── StatusCommand.swift      # authsia status
│   │   └── UnlockCommand.swift       # authsia unlock
│   ├── Services/
│   │   ├── AccessCredentialStore.swift  # Automation credential persistence
│   │   ├── AgentRuleInstaller.swift     # AI-agent rule file generation
│   │   ├── AutomationAccessResolver.swift # Automation scope enforcement
│   │   ├── BackupService.swift           # Actor-based backup & revert
│   │   ├── EnvFileParser.swift          # .env file parsing
│   │   ├── EnvFileRewriteService.swift  # .env auto-rewrite with authsia:// URIs
│   │   ├── EnvironmentProfileStore.swift # Environment profile persistence
│   │   ├── FileScannerService.swift      # File parsing (env/JSON/YAML)
│   │   ├── GitSigningConfigWriter.swift # Git SSH signing configuration
│   │   ├── OutputMasker.swift           # Secret masking in subprocess output
│   │   ├── SecretDetectionService.swift  # Multi-signal scoring engine
│   │   ├── SecretReferenceResolver.swift # authsia:// URI resolution
│   │   ├── SetupRepairService.swift      # setup shell repair/status cleanup helpers
│   │   ├── ShellConfigService.swift      # Diff generation + auto-replacement
│   │   ├── SSHAdoptionService.swift     # Existing SSH key discovery/adoption
│   │   ├── SSHConfigWriter.swift        # SSH config file management
│   │   ├── SSHKeyGenerator.swift        # SSH key generation + vault storage
│   │   ├── SSHKeyMetadataResolver.swift # Public key parsing, fingerprint, key type
│   │   └── SSHKeyStubService.swift      # Private-key stub and config annotation
│   ├── Models/
│   │   ├── AccessCredential.swift   # Automation credential model
│   │   ├── AuditEvent.swift         # Audit event model
│   │   ├── DetectedSecret.swift      # Detected secret with metadata
│   │   ├── EnvironmentProfile.swift # Environment profile model
│   │   ├── SecretType.swift          # apiKey, token, password, etc.
│   │   └── SecretConfidence.swift    # high/medium/low with Comparable
│   ├── UI/
│   │   ├── CheckboxTUI.swift         # Interactive terminal checkbox selector
│   │   └── CodeExamples.swift        # Migration code examples (JS/Python/Shell)
│   ├── Formatters/
│   │   ├── AuditFormatter.swift     # Audit event formatting (table, JSON, NDJSON)
│   │   ├── OutputFormatter.swift     # JSON + OutputFormat enum
│   │   ├── TableFormatter.swift      # ASCII tables
│   │   └── CodeFormatter.swift       # TOTP display formatting
│   └── Utils/
│       ├── CLIError.swift            # Error types
│       ├── ClipboardClient.swift     # pbcopy integration
│       ├── DataString.swift          # UTF-8/Base64 conversion
│       ├── FolderPathSupport.swift  # Re-exports shared folder matching from AuthenticatorBridge
│       ├── MachineIdentity.swift     # Stable machine UUID + hostname (~/.authsia/machine.json)
│       ├── MatchHelper.swift         # Item name/ID matching
│       ├── StandardError.swift      # stderr output helper
│       └── StringExtensions.swift    # Shared string utilities (padding)
└── Tests/AuthsiaCLITests/

Packages/AuthsiaBridgeHost/Sources/           # macOS host runtime and authorization policy
├── XPCListenerManager.swift                 # NSXPCListener + connection auth (code sig + team ID)
├── XPCRequestHandler.swift                  # Request dispatch, session validation, approval flow
├── BridgeSessionManager.swift               # Server-side session + anti-replay tracking
└── SSHAgentListener.swift                   # OpenSSH agent protocol and signing authorization

Authenticator/Authenticator/Bridge/          # Private approval UI and runtime adapters
├── BridgeHostRuntime.swift                  # XPC host composition
├── BridgeApprover.swift                     # LocalAuthentication/AppKit approval adapter
└── SSHAgentRuntime.swift                    # SSH host composition

Packages/AuthenticatorBridge/Sources/        # Shared protocol + models (used by both app and CLI)
├── AuthsiaBridgeXPCProtocol.swift           # @objc XPC protocol
├── FolderPathSupport.swift              # Shared folder path normalization and matching
├── BridgeModels.swift                       # BridgeRequest, BridgeResponse, DTOs, write payloads
├── BridgeResponseBuilder.swift              # Helper to build success/error responses
├── BridgeCoder.swift                        # JSON encoder/decoder with ISO8601 dates
└── BridgePolicy.swift                       # BridgeSession (32-byte token), BridgePolicyDecision
```

**Build & Installation:**
- Homebrew installs the released app and symlinks the bundled CLI:
  ```bash
  brew install --cask james-liang-cs/authsia/authsia
  ```
- Existing DMG installs can be adopted by Homebrew:
  ```bash
  brew install --cask --adopt james-liang-cs/authsia/authsia
  ```
- `scripts/build_and_install.sh` runs `xcodebuild` which triggers the "Copy CLI Binary" build phase.
- The build phase runs `scripts/copy-cli.sh` which:
  1. Runs `swift build -c release` in `Packages/AuthsiaCLI/` (compiles CLI from source).
  2. Copies the binary to `$BUILT_PRODUCTS_DIR/Authsia.app/Contents/Helpers/authsia`.
  3. Signs the CLI binary with hardened runtime and no Keychain entitlements.
- The bridge LaunchAgent runs
  `/Applications/Authsia.app/Contents/Helpers/AuthsiaHeadless.app/Contents/MacOS/authsia-headless`
  with `AUTHSIA_ROLE=bridge`; the SSH agent LaunchAgent runs the same nested
  helper with `AUTHSIA_ROLE=ssh-agent`.
- Do not copy/sign `authsia-bridge` or `authsia-ssh-agent` helper binaries with
  Keychain entitlements. Bare helper executables are not covered by the app
  bundle's provisioning profile and can be rejected by launchd/AMFI before they
  register their Mach/socket services.
- Installed in app bundle: `/Applications/Authsia.app/Contents/Helpers/authsia`
- Homebrew symlinks the released CLI to `$(brew --prefix)/bin/authsia`; local
  app setup can also manage `~/.local/bin/authsia`.
- CLI is **always rebuilt from source** as part of the Xcode build — no separate build step needed.

---

## CLI Access Toggle (Security Feature)

Two-level access control for CLI operations:

### Global Toggle
- **Settings → Security → CLI Access** (macOS only)
- **Default:** OFF
- **Behavior:**
  - OFF: interactive CLI commands fail with a user-facing message to enable CLI Access in
    Settings → Security. Non-secret list commands may return empty results when the bridge policy denies access.
  - ON: Per-item settings are evaluated

### Per-Item Toggle
- **Edit Item → CLI Access** section (macOS only)
- **Default:** ON
- **Applies to:** Accounts, Passwords, Certificates, Secure Notes
- **Behavior:**
  - `list`: Always shows the item (with CLI status on/off) — no secrets exposed
  - `get`/`code`: Denied if item CLI access is off

Mac vault context menus also provide bulk enable/disable:
- Folder right-click → **Enable CLI Access** or **Disable CLI Access** changes matching items in that
  folder and nested folders. In the All filter it applies to all vault item types; in a type filter it
  applies only to that type.
- Multi-select item right-click → **Enable CLI Access for Selected** or
  **Disable CLI Access for Selected** changes the selected items only.
- Clipboard-imported secrets default to CLI enabled unless the import panel's CLI option is disabled.

### Error Messages
- Global OFF: "CLI access is disabled"
- Item OFF: "CLI access is disabled for '<item name>'"

---

## Security Model

| Concern | Mitigation | Status |
|---------|-----------|--------|
| Keychain access | CLI never touches Keychain; all access via XPC to app | Implemented |
| User presence | Biometric (Touch ID / password) required for secrets | Implemented |
| XPC connection auth | Caller code signature and team ID validated via `SecCodeCopyGuestWithAttributes` | Implemented |
| Session tokens | 32-byte `SecRandomCopyBytes` tokens, base64-encoded; validated server-side | Implemented |
| Anti-replay | Each request carries a unique UUID; server tracks used IDs (max 1000) and rejects duplicates | Implemented |
| Session persistence | CLI caches interactive tokens in terminal-scoped Keychain items keyed by live tty plus macOS process session ID; the app validates tokens against the same terminal scope; automation credential shells do not read/write them; server is authority on validity | Implemented |
| Human/agent routing | Without an explicit automation credential, confirmed agent runtime context selects JIT; automation credentials use their separate path. Ancestry-only IDE use becomes an ongoing human session only with stdin TTY plus a server-current same-scope token; first-use biometric bootstrap releases nothing before approval | Implemented |
| JIT boundary | Named folders include slash-delimited descendants but not ancestors/siblings; root is root-only; grants permit only scoped `list` and `exec` and retain caller, TTL, revocation, audit, and CLI-enabled checks | Implemented |
| Session management | Timed sessions configured in app GUI; CLI cannot override TTL; default 15s | Implemented |
| Token propagation | Every response can carry a new session token; CLI auto-caches it | Implemented |
| Per-item control | Each item has CLI enable/disable toggle in app | Implemented |
| Exfiltration | Generic SSH/CI secret retrieval is blocked by policy; SSH signing requires explicit `ssh` capability and scope checks | Implemented |
| Audit trail | All access logged to `bridge_audit.log` | Implemented |
| Clipboard | Secrets copied via `--copy` flag with `--clipboard-timeout` auto-clear (default 30s) | Implemented |
| List safety | `list` returns no secrets — only names, IDs, and metadata | Implemented |
| Debug logging | No sensitive data (tokens, secrets) in production logs | Implemented |
| SSH passphrase storage | Passphrase stored encrypted in Keychain as field on SSH item; used only for encrypted keys | Implemented |
| SSH_ASKPASS helper | Compatibility path only: temporary script written to `mktemp`, chmod 700, deleted immediately after `ssh-add` completes for `--system-agent` loads | Implemented |
| SSH key on disk | `authsia ssh adopt` stores the private key in the vault before replacing the disk key with a stub; `scrape` skips SSH keys and leaves files unchanged | Implemented |
| SSH signing | Built-in agent enforces approval, per-item CLI access, host bindings, and scoped `ssh` automation credentials; supports `session-bind@openssh.com` and avoids long macOS socket paths during signing | Implemented |

---

## Testing Strategy

1. **Unit Tests** — Policy evaluation, formatters, matching, error handling, secret detection, file scanning, scrape models
2. **Integration Tests** — CLI → XPC → App round-trips, approval flows, deny/timeout
3. **Manual Tests** — Unlock + session expiry, CLI with/without app running, piped output restrictions, scrape scan + revert

---

## Verification Steps

```bash
# Build (standalone CLI)
cd Packages/AuthsiaCLI && swift build

# Build + install (full app + CLI via Xcode)
./scripts/build_and_install.sh

# Run tests
cd Packages/AuthenticatorBridge && swift test   # 10 tests (shared models)
cd Packages/AuthsiaBridgeHost && swift test     # host authorization and runtime tests
cd Packages/AuthenticatorCore && swift test     # 18 tests (TOTP/HOTP)
cd Packages/AuthsiaCLI && swift test            # 315 tests (commands, matching, SSH adoption, scrape detection)

# Manual verification
authsia --help                          # Shows all commands with examples
authsia list --help                     # Shows scope values and options
authsia get --help                      # Shows types, fields, and examples
authsia list otp                        # Lists all OTP items (triggers biometric once)
authsia list passwords --format table   # Table with Name, Favorite, ID, CLI (uses cached session)
authsia list api-keys --format table    # API key metadata without key values
authsia code GitHub --copy              # TOTP code + clipboard (uses cached session)
authsia get password MyBank             # Full password (uses cached session)
authsia get api-key Stripe --field key  # API key value (uses cached session)
authsia unlock                          # Explicit session start

# New commands
authsia inject --help
authsia completion zsh
authsia access list
authsia env list
authsia ssh --help
authsia ssh adopt --help
authsia status
authsia doctor
authsia audit list --format table

# Scrape verification
authsia scrape --help                  # Shows all scrape options
authsia scrape --dry-run               # Scan default paths, preview only
authsia scrape -p .env --confidence high  # Scan .env with high confidence
authsia scrape --list-modified         # Show backup table
authsia scrape --revert ~/.zshrc       # Revert a file

# SSH adoption verification
authsia ssh adopt --path ~/.ssh --dry-run  # Preview keys and inferred host bindings only

# Session verification
authsia unlock                          # Starts this terminal's interactive session
authsia status --format json            # Shows this terminal's scoped session state
authsia list otp                        # Uses this terminal's cached session
authsia list passwords                  # Within TTL: no biometric prompt
```

---

## Future Enhancements

- Stdout secret protection (require `--reveal` flag)
- SSH agent integration for certificates
- Rate limiting and brute force protection
