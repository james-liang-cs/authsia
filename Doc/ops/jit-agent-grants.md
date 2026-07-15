# Just-in-Time Agent Grants

This document describes Authsia's just-in-time (JIT) grant path for local coding
agents that need to run `authsia exec` or scoped Vault metadata `authsia list`
without turning a human CLI session into ambient agent authority.

JIT grants are deliberately narrow:

- They apply only to `authsia exec` secret reads and scoped Vault metadata
  `authsia list`.
- They resolve only CLI-enabled password, API key, certificate, secure note, and
  SSH metadata items. `exec` secret reads remain limited to password, API key,
  certificate, and secure note items.
- They grant only `exec` and scoped `list`.
- A named-folder scope includes that folder and slash-delimited descendants,
  never ancestors or siblings. Root is a separate root-only scope.
- They expire with the same TTL as the CLI session setting.
- They are bound to the caller fingerprint, terminal/session scope, and working directory.

## Why This Exists

`authsia exec` is the safest agent-facing command because secrets are injected
only into the launched child process and Authsia masks output. The risky part is
approval reuse: a human may already have an unlocked terminal session, while an
agent running in that terminal or through an IDE extension is a different actor.

JIT grants split those cases:

- When no explicit automation credential is supplied, confirmed agent runtime
  context uses JIT. Automation credentials are evaluated through their separate
  authorization path. An ancestry-only invocation without an stdin TTY also
  uses JIT.
- An ancestry-only IDE terminal becomes an ongoing human session only when stdin
  is a TTY and the request carries the server-current token for the same
  terminal scope. TTY alone is not authorization or a classifier override.
- A first stdin-TTY request without confirmed agent runtime context may use a
  narrow biometric bootstrap. It returns no metadata or secret before approval,
  then mints the normal scoped terminal session. Active JIT grants do not
  authorize this bootstrap or the human list path.
- Background or unattended automation should use explicit automation credentials
  instead of JIT.

## When JIT Runs

The CLI starts JIT preflight when all of these are true:

1. The command is `authsia exec`, or `authsia list` for supported Vault metadata
   scopes.
2. No `AUTHSIA_ACCESS_CREDENTIAL` is present in the parent environment.
3. The invocation has an explicit confirmed agent marker, or the process
   ancestry contains a known coding agent or automation-suspect IDE
   helper/extension host and stdin is not a TTY.
4. The command has secret inputs through a type scope, an env file, or
   `authsia://` references, or it is a Vault metadata list for passwords,
   API keys, certificates, notes, or SSH keys.

Known coding-agent names contribute a strong ancestry signal. Examples include `claude`,
`claude-code`, `codex`, `cursor-agent`, `windsurf-agent`, and GitHub Copilot
process names or bundle fragments.

IDE helpers are treated as automation-suspect rather than proven agents when
only ancestry is available.
Examples include VS Code, Cursor, Windsurf, JetBrains IDEs, Zed, and extension
host processes. An IDE name in the ancestry does not by itself turn a
stdin-TTY command into a human session: ongoing human authority also requires a
server-current token for the same terminal scope.

## Process Detection

Detection is heuristic. It is not cryptographic agent attestation.

The CLI-side detector walks the current process ancestry and records:

- process name
- bundle identifier when available
- argv values for runtime wrappers

Runtime wrappers are inspected so commands such as `node /opt/homebrew/bin/claude`
or similar `bun`, `deno`, `python`, `ruby`, or `java` wrappers can still resolve
to the application name that matters.

The bridge-side caller identity extractor records the connecting CLI process and
walks past shell intermediaries such as `zsh`, `bash`, `fish`, and `sh` to find
the real parent application. When that parent is a coding agent launched through
an editor or IDE extension, the extractor also records the editor host so Access
Center can display names such as `Claude via Visual Studio Code`.

For requests without an explicit automation credential, the final secret-read
and direct Vault metadata list gates treat confirmed `agentRuntimeContext` as
JIT. Automation credentials use their separate authorization path. For
ancestry-only callers, a server-current same-scope token plus stdin TTY keeps
the ongoing human path; otherwise agent or automation-suspect IDE ancestry
requires JIT. Redirecting stdout does not change this decision because stdin
TTY drives routing.

`TerminalContext.isInteractiveSession` still requires stdin and stdout TTYs for
full-screen interactive CLI experiences. That UI check is separate from the
stdin-TTY routing rule and is not an authorization signal.

The detector only decides whether JIT is required. The actual authorization is
the stored grant plus caller fingerprint comparison.

## Grant Flow

1. `authsia exec` discovers the requested secret references.
   - For a single item scope, for example
     `authsia exec password SERVICE_ENDPOINT -- ...`, the CLI can preflight that item
     before metadata listing.
   - For folder, global, or multi-folder scopes, the CLI preflights scope
     references before metadata listing.
   - For env-file or env-reference scopes, the CLI preflights resolved
     password, API key, certificate, and note references. OTP and SSH references
     are not supported in agentic JIT.
2. The CLI sends `agentJITPreflight` to the bridge with `requestedCommand=exec`.
3. The bridge resolves every reference against live vault metadata.
   - The item must exist.
   - The item must be CLI-enabled.
   - Duplicate names must be disambiguated with a sufficiently narrow requested
     folder subtree or a stable item ID. If duplicates remain inside the
     requested subtree, use a narrower subtree or the item ID.
4. The bridge converts each item to a folder scope, removes duplicate scopes,
   and collapses descendant requests already covered by an ancestor scope.
5. For each scope without an active matching grant, the app asks the user to
   approve temporary access.
6. Approved grants are saved locally and returned to the CLI.
7. The `exec` internal metadata list can use the grant's `list` capability, but
   only scoped to the active grant folders.
8. Final secret reads must find an active matching `exec` grant. Without it, the
   bridge fails closed with:

```text
Agent exec secret reads require a valid JIT preflight grant for this item scope.
```

For direct agent `authsia list passwords`, `authsia list api-keys`,
`authsia list certs`, `authsia list notes`, or `authsia list ssh`, the CLI sends `agentJITPreflight`
with `requestedCommand=list` before loading metadata. These approvals create
list-only grants. If no matching list grant exists, the bridge fails closed
instead of falling back to the normal list approval prompt:

```text
Agent list requests require a valid JIT preflight grant for a supported Vault scope.
```

## Scope Rules

JIT scopes are folder scopes, not individual item IDs. This keeps the approval
count manageable while still preventing broad vault access.

| Secret location | Granted scope | What it covers |
| --- | --- | --- |
| Root | Root only | Root items only; never the whole vault |
| `Team/API` | `Team/API` subtree | `Team/API` and slash-delimited descendants such as `Team/API/Prod` |
| `Team/API/Prod` | `Team/API/Prod` subtree | That folder and its descendants, not `Team/API` or sibling folders |

Important edge cases:

- A root grant covers root items only. It does not include any folder.
- Multiple root references are grouped into one root approval.
- Multiple references collapse only when an actual requested or active ancestor
  scope covers the descendants. Sibling scopes remain separate when their
  common ancestor was not requested or already active.
- A grant for `Team/API` covers `Team/API/Prod`, but a grant for
  `Team/API/Prod` does not cover `Team/API`.
- Prefix lookalikes are not descendants: `Team/API2` and `Team/API` are sibling
  scopes.
- Another unrelated folder tree requires separate approval unless an active
  matching grant already exists.
- A covered tree may still require a separate approval when the request adds a
  capability not already present, such as `exec` after a list-only grant.

## Approval Copy

The prompt states why another approval is needed. It distinguishes an unrelated
folder tree from a new capability on a covered tree. A first broad unscoped list
approval with no active scopes uses concise `across all resolved folders`
wording and does not enumerate pending paths. When active grants exist and a
separate approval adds unrelated scopes, the prompt lists the pending new folder
paths and active folder scopes. Broad prompts never name vault items or secrets.

## Capabilities

JIT grants currently store exactly these capabilities:

- `exec`: allows the final secret read for `authsia exec`.
- `list`: allows scoped metadata listing needed by `authsia exec` to resolve
  selected items, or direct agent `authsia list` for supported Vault metadata,
  without falling back to the normal list approval path.

The `list` capability is valid only for `requestedCommand=list` and
`requestedCommand=exec`. The `exec` capability is valid only for
`requestedCommand=exec`.

JIT does not grant `get`, `read`, `inject`, `load`, SSH private-key reads,
`unlock`, access creation, export, add, edit, delete, or OTP access. When
no explicit automation credential is supplied, confirmed agent runtime context
uses the JIT path, which permits only `list` and `exec`; direct secret reads
through non-`exec` commands are denied even if a human session exists. A valid
explicit automation credential instead uses separate automation policy and may
authorize `get`, `load`, `read`, or `inject` within its capability and scope.
An ancestry-only stdin-TTY request can use the human path only with a
server-current same-scope token, or through the narrow biometric bootstrap
before any metadata or secret is returned. Internal metadata lists for JIT
callers return no vault items instead of falling back to the normal broad list
approval path.

Explicit automation credentials are separate from JIT grants. When
`AUTHSIA_ACCESS_CREDENTIAL` is present, the bridge evaluates the credential's own
command capabilities and scope before applying JIT-only limits. This preserves
token-authorized agent automation for commands such as `list`, `get`, `load`,
`read`, `inject`, and `ssh`.

## TTL And Revocation

JIT grants use the configured CLI session TTL (`cliSessionTTL`). The default is
the same default used by normal CLI sessions, and the maximum is 24 hours.
Legacy negative TTL preferences are treated as 24 hours.

Grants are stored at:

```text
~/Library/Application Support/Authsia/agent-jit-grants.json
```

The directory is kept at `0700`; the file is kept at `0600`.

Grants can become inactive in three ways:

- expiry
- manual revocation from Access Center
- lazy revocation when the associated terminal/session scope is detected as
  closed

Access Center shows the resolved grant folder, the concrete vault items that
were resolved during preflight, and terminal status so the user can see what was
approved and whether the originating terminal still appears alive. Expired and
revoked agent grant rows remain visible for review, but their revoke buttons are
disabled because there is no active grant left to revoke.

When the optional Claude Code or Codex hook integration is enabled, Access
Center also shows tool-provided agent attribution such as `Claude Code / Explore`
or `Codex / reviewer` under the OS-visible requester. This attribution is
display metadata only. A local process can spoof hook records, so grant matching
does not use `agent_id`, `agent_type`, session IDs, or turn IDs. The CLI only
attaches hook metadata when the current process ancestry also detects the same
coding tool platform; a hook record by itself is ignored.

Access Center also derives local investigation flags from command metadata,
matching JIT grants, and audit records. These flags are deterministic and
display-only: they do not call AI, send data out, store command output, block a
command, revoke a grant, or change authorization. Severities are limited to
`Info`, `Review`, and `Warning`.

The first rules are intentionally narrow:

- `Warning`: a command was recorded after the matching grant expired or was
  revoked.
- `Review`: a process-monitor record exists for a hook-capable tool, but no
  matching hook record was found for the same grant/scope/command within the
  short correlation window.
- `Review`: a direct agent secret-read command such as `authsia get`,
  `authsia read`, `authsia load`, or `authsia inject` was recorded or appears in
  a matching audit record.
- `Review`: an active-grant command could expose environment data, such as
  `env`, `printenv`, or direct reads of `.env` files.
- `Info`: process monitoring was used where hook capture is unavailable.

Grant rows show a calm count such as `2 flags` when findings exist. The Commands
sheet has `All` and `Flagged` filters, and flagged command rows show the derived
reason. Command-history JSON export includes the original events, a `findings`
array with evidence event IDs, and summary counts.

Access Center has an opt-in `Include human sessions` toggle for showing normal
interactive CLI sessions in a right-side column beside agent grants. These rows
expose only terminal scope and expiry, not session tokens. Revoking a human
session from Access Center invalidates the bridge session for that terminal
scope, matching the authorization effect of `authsia lock`, and also clears SSH
approval-session status for that scope. The terminal's local cached token is not
displayed or exported to the UI. The same toggle also shows recent 30-day human
CLI activity reconstructed from audit records, up to 200 records, so expired or
closed sessions remain visible as read-only access history without becoming
revocable session rows.

Human CLI sessions are mirrored to a token-free status file so the UI process
can display sessions created by the bridge/headless process:

```text
~/.authsia/cli-session-status.json
```

The file stores only the bridge PID, terminal/session scope, expiry, and update
time. The actual session token remains in the bridge process and the
terminal-scoped Keychain item used by the CLI. If Access Center clears a scope
from the status file, the bridge treats the matching in-memory session as
revoked on the next request.

The `Revoke all` action revokes every active JIT grant and every active human
CLI session known to the app. It is disabled when there is no active access to
revoke.

For IDE-launched shells, terminal/session scope can fall back to the nearest
ancestor process with a controlling terminal. That scope discovery does not
make stdin a TTY and does not override JIT routing. Automation-credential
requests do not use this fallback.

## Agent File Activity Evidence

Agent file activity is local display evidence only. Authsia records path
metadata from supported agent tool hooks, including action, status, source, and
confidence. It does not store file contents, command output, stdin, environment
values, or plaintext secrets. Agent activity JSON export uses workspace-relative
paths for workspace-contained file activity and omits the matching absolute path,
working directory, and workspace root.

Confidence labels mean:

- `Direct`: a supported hook reported the file or directory for the tool call.
- `Confirmed`: a post-tool hook reported success for the same tool call.
- `Inferred`: Authsia detected a workspace change during the session, not a
  direct read.
- `Fallback`: Authsia associated activity by terminal/session scope and working
  directory.

Actual Authsia secret access remains governed by JIT grants, bridge policy,
named-folder subtree scope, capability, TTL, and audit records. File activity
does not grant or deny access.

## Access Insights

Access Center includes a global Access Insights dashboard above the grant list.
It summarizes:

- active JIT grants
- investigation flag counts derived from command history
- visible human CLI sessions and recent 30-day human CLI activity, up to 200
  records, when the human session toggle is enabled
- 30-day audit activity
- top caller
- recent usage trend
- folders and vault items associated with grants or item-read audit records

The folder and vault-item rows in the dashboard are clickable. Selecting a row
focuses the dashboard to that folder or item; selecting it again or using
`Clear focus` returns to the global view. The Agent grants list is filtered by
the same focused folder or vault item so the summary and grant rows stay in
sync. Focused item insights are exact by vault item ID. Focused folder insights
are exact for active JIT grant metadata and for audit records tied to a matching
JIT grant or requested item ID. Human audit records contribute to folder and
vault-item insights only when `Include human sessions` is enabled.

Historical audit records do not currently store every vault item's folder path.
Access Center resolves historical item activity through the current non-secret
vault metadata catalog when possible, then falls back to grant or audit data.
Records for deleted or renamed items can remain conservative when no current
item relationship is available.

## Audit

JIT activity is recorded in the bridge audit log.

The bridge records:

- `agentJITPreflight` approval or denial
- grant ID for created grants
- grant ID on secret reads approved by JIT
- requested command context
- caller identity when available
- optional hook-provided agent attribution when available
- selected environment scope (`Default environment` or one named environment) for environment-scoped approvals and reads

Audit records must never include secret values.

## Failure Behavior

JIT should fail closed in these cases:

- the command is not `authsia exec` or a supported Vault metadata `authsia list`
- caller identity is missing
- the preflight payload is malformed
- the referenced item does not exist
- the referenced item is not CLI-enabled
- the referenced item is OTP, or SSH outside the list-metadata path
- a duplicate item name cannot be resolved exactly
- an agentic caller attempts a non-`exec` secret read
- the final secret read or direct metadata list has no active matching grant
- the grant is expired, revoked, outside its folder subtree, wrong-command, or
  wrong-caller
- the grant store is corrupted or unreadable

Automation credentials are a separate path. If a valid
`AUTHSIA_ACCESS_CREDENTIAL` is present, the CLI does not create JIT grants and
the bridge evaluates the credential's own scope and capabilities.

## Operational Checks

Use non-leaking checks when validating live behavior. Never print the secret.

```sh
authsia exec password SERVICE_ENDPOINT --shell 'test -n "$SERVICE_ENDPOINT" && echo SERVICE_ENDPOINT=set'
```

Useful focused test commands:

```sh
cd Packages/AuthenticatorBridge
swift test --filter AgenticProcessDetectorTests

cd ../AuthsiaCLI
swift test --filter AgentJITPreflightTests
```

For runtime triage, first verify the installed app/helper has the current build.
The common local CLI path is:

```text
/Users/example/.local/bin/authsia -> /Applications/Authsia.app/Contents/Helpers/authsia
```

If JIT does not prompt, check:

1. Is the item CLI-enabled?
2. Is the command `authsia exec` or supported Vault metadata `authsia list`,
   not `get`, `load`, `read`, or `inject`?
3. Is an automation credential present in the parent environment?
4. Does the process ancestry expose a known agent or IDE helper?
5. Is the installed CLI/helper from the current build?
6. Did an active matching grant already exist, causing the prompt to be skipped?

## Source Map

- CLI exec preflight and reference collection:
  `Packages/AuthsiaCLI/Sources/authsia/Commands/ExecCommand.swift`
- CLI list preflight:
  `Packages/AuthsiaCLI/Sources/authsia/Commands/ListCommand.swift`
- Agent and IDE process detection:
  `Packages/AuthenticatorBridge/Sources/AuthenticatorBridge/AgenticProcessDetector.swift`
- Grant model and scope matching:
  `Packages/AuthenticatorBridge/Sources/AuthenticatorBridge/AgentJITGrant.swift`
- Bridge request dispatch and approval orchestration:
  `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/XPCRequestHandler.swift`
- Agent caller fingerprinting and agent/IDE wrapper detection:
  `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/AgentJITCallerContext.swift`
- Bridge preflight scope resolution:
  `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/AgentJITPreflightResolver.swift`
- Active JIT grant authorization:
  `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/AgentJITGrantAuthorizer.swift`
- Scoped list filtering:
  `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/BridgeListPayloadFilter.swift`
- Bridge list payload construction:
  `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/BridgeListPayloadFactory.swift`
- Grant persistence and closed-terminal revocation:
  `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/AgentJITGrantStore.swift`
