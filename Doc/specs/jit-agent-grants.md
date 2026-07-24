# Just-in-Time Agent Grants

## Table of Contents

- [Remote iPhone Approval Status](#remote-iphone-approval-status)
  - [Current authority flow](#current-authority-flow)
  - [CloudKit architecture](#cloudkit-architecture)
  - [Current notification implementation](#current-notification-implementation)
  - [Findings and attempted fixes](#findings-and-attempted-fixes)
  - [Blockers and residual risks](#blockers-and-residual-risks)
- [Why This Exists](#why-this-exists)
- [Current Exfiltration Coverage](#current-exfiltration-coverage)
- [When JIT Runs](#when-jit-runs)
- [Process Detection](#process-detection)
- [Grant Flow](#grant-flow)
- [Scope Rules](#scope-rules)
- [Approval Copy](#approval-copy)
- [Capabilities](#capabilities)
- [TTL And Revocation](#ttl-and-revocation)
- [Agent File Activity Evidence](#agent-file-activity-evidence)
- [Access Insights](#access-insights)
- [Audit](#audit)
- [Failure Behavior](#failure-behavior)
- [Operational Checks](#operational-checks)
- [Source Map](#source-map)

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
- Exact stable item identities are the default. Reusable folder scope applies
  only when the approval explicitly displays it; root remains root-only.
- They expire with the same TTL as the CLI session setting.
- They are bound to caller fingerprint, terminal/session scope, exact working
  directory (the workspace authority key), environment, and capability.

## Remote iPhone Approval Status

This section records the remote JIT approval state as of 2026-07-20. Remote
approval is an alternate way to approve the same bounded Agent JIT preflight;
it does not create a second grant type or move grant authority to the phone or
CloudKit.

### Current authority flow

- Only Agent JIT preflight requests are eligible for remote approval. Other
  Bridge approvals remain local to the Mac.
- The Mac freezes and signs the complete approval descriptors, encrypts the
  application payload, and publishes short-lived records to the user's private
  CloudKit database. The request lifetime remains 90 seconds.
- Local Mac approval remains available while the remote request is pending.
  CloudKit failure, notification failure, or an unavailable phone must not turn
  into approval.
- The paired iPhone fetches current records, decrypts and verifies the requests,
  requires a fresh biometric decision, and signs Approve or Deny responses.
- The originating Mac verifies the response against the current pairing and
  request, wins the local-versus-remote race exactly once, reruns live caller,
  scope, item, environment, and grant policy, then persists the grant batch
  atomically.
- No vault secret, grant token, pairing private key, or approval authority is
  sent to iOS or stored in CloudKit. A notification is only a generic prompt to
  review current state.

The public request model, canonical encoding, signature verification, typed
approver seam, final policy revalidation, and atomic grant persistence are
implemented. Private pairing, encrypted CloudKit transport, the iOS approval
surface, and Face ID response path live in the parent application repository.
Earlier Development and Production physical-device CloudKit round trips passed;
on 2026-07-19 the matching version 1.7.0 (22) Developer ID Mac and TestFlight
iPhone also passed the full Production notification and approval flow. The
different-iCloud-account device test remains waived and not run.

### CloudKit architecture

CloudKit is an untrusted, account-scoped courier for pairing messages, approval
requests and decisions, and pairing revocations. Both devices use the private
database in container `iCloud.app.authsia` and the custom record zone
`RemoteJITApprovalsV1`. Devices must therefore reach the same iCloud private
database to discover one another's records. CloudKit availability is not an
authorization signal, and a transport failure never becomes approval.

The zone contains three versioned record types:

| Record type | Purpose | Important cleartext routing fields | Protected payload |
| --- | --- | --- | --- |
| `RemoteJITPairingV1` | Drives the short-lived pairing state machine. | Pairing ID, expiry, transport state, and bootstrap exchange bytes. | Authenticated pairing messages after the initial pending state. |
| `RemoteJITApprovalV1` | Carries a signed request from Mac to iPhone, then the signed decision from iPhone to Mac. | Request ID, 16-byte routing tag, expiry, transport state, and the `notify` marker. | The canonical signed request or decision, encrypted and authenticated for the current pairing. |
| `RemoteJITRevocationV1` | Tells a previously paired Mac that the iPhone removed that pairing. | Revocation ID, 16-byte routing tag, expiry, and transport state. | A generation- and device-bound revocation notice encrypted and authenticated with the removed pairing. |

Record IDs are deterministic lowercase UUID strings inside the custom zone.
Strict decoders reject missing, extra, mistyped, or inconsistent fields.
Pairing and approval updates use CloudKit record change tags and conditional
saves so a stale writer cannot overwrite a newer state. Approval records for
one preflight are created atomically; only the first record in that batch sets
`notify = 1`.

The end-to-end approval flow is:

1. The Mac signs each canonical approval request, encrypts it for the active
   pairing, and writes an atomic `RemoteJITApprovalV1` batch in `pending` state.
2. A generic query-subscription push tells the iPhone only that CloudKit may
   contain new work. The notification carries no approval authority and is not
   scoped to a particular routing tag.
3. The iPhone queries pending records using its current pairing's routing tag,
   then decrypts and verifies all request, generation, device, key, and expiry
   bindings before showing actionable approval UI.
4. After Face ID, the iPhone signs the decision, encrypts it for the same
   pairing, and conditionally changes the record to `responded`.
5. The originating Mac decrypts and verifies the decision and reruns current
   local JIT policy before creating a grant. Closing or expiring the local
   request makes the CloudKit record non-actionable or removes it.

The generic notification predicate explains the multi-device edge case. If an
iPhone replaces pairing A with pairing B, a notification caused by stale Mac A
can still reach that iCloud account, but the phone's B routing tag cannot fetch
or decrypt A's request. Opening that notification therefore shows no approval.
To prevent new ghost requests, iPhone unpairing publishes a
`RemoteJITRevocationV1` record keyed by pairing A's generation before clearing
its local identity. Mac A checks that exact generation for revocation before
publishing every new approval batch; revocation does not depend on a second
push. This exact lookup adds one CloudKit read per atomic approval batch and is
intentionally not cached, because a cache would reopen the unpair-to-publish
race. A valid notice clears A's local pairing and fails the request as not
paired. A malformed or unauthenticated notice grants no revocation authority,
but it is retained and blocks publication rather than being deleted and
silently treated as no revocation. The phone still clears its local pairing if
revocation publication fails, so unpair remains fail-closed locally, but the
stale Mac cannot learn that change through this channel and the phone reports
the publication error.

Unacknowledged revocation records use a 24-hour retention horizon. An active
paired iPhone opportunistically removes expired records during refresh, with
cleanup throttled to one successful attempt per 24 hours. Cleanup failure does
not hide or reject otherwise actionable approvals; it is retried on a later
refresh.

Development CloudKit schema changes must be promoted before distributing code
that depends on them. Production requires all three record types, and the
approval query fields `routingTag`, `transportState`, and `notify` must support
the pending-record query and v2 notification predicate. The revocation
`expiresAt` field must be queryable for retention cleanup. In particular,
`RemoteJITRevocationV1` and its expiry index must be deployed before releasing
the multi-device revocation flow; a missing record type or index must fail
publication rather than bypass a pairing check.

### Current notification implementation

The Notification Service Extension experiment has been reverted. The current
application has no `NotificationService.appex`, does not request mutable-content
delivery, and does not carry the
`com.apple.developer.usernotifications.filtering` entitlement.

The retained notification work uses the CloudKit query subscription
`RemoteJITApprovalV1.pending-created.v2`:

- Each approval record has a required integer `notify` field whose only valid
  values are `0` and `1`.
- An atomic approval batch marks only its first record as `notify = 1`; all
  remaining records use `notify = 0`.
- The subscription fires on record creation when
  `transportState == "pending" AND notify == 1`, producing one creation push
  per batch instead of one push per record.
- Before publishing a batch, the Mac prepares v2 and deletes both the v1
  per-record subscription `RemoteJITApprovalV1.pending-created.v1` and the
  reverted v3 mutable-content subscription
  `RemoteJITApprovalV1.pending-created.v3`. A non-missing deletion failure
  blocks publication so only v2 is knowingly active.
- The capability-spike zone subscription `RemoteJITApprovalsV1.changes` was
  found in both CloudKit environments and manually removed. It fired on every
  zone change and was the source of additional completion-time alerts. The
  current application does not recreate it; the observed final Development and
  Production state contains only v2.
- Subscription compatibility is versioned by subscription ID and structural
  properties. The server's rewritten predicate string is not used as a
  re-save signal.
- The app removes delivered approval notifications after a refresh or response
  observes no pending requests. This cleanup works only while application code
  is running.

The notification does not authorize anything. On open, iOS fetches current
CloudKit state, and expired, closed, denied, malformed, or already-completed
records remain non-actionable.

### Findings and attempted fixes

1. The original v1 subscription fired once for every approval record. A broad
   approval containing several scopes therefore produced several pushes. The
   v2 `notify` marker and predicate address this fan-out at record creation.
2. A collapse identifier was attempted and removed. CloudKit treats
   `collapseIDKey` as the name of a record field, not as a literal collapse
   value; configuring an unbacked key made subscription delivery invalid rather
   than providing reliable batch cancellation.
3. Comparing CloudKit's round-tripped `predicateFormat` with the locally
   constructed string caused an equivalent subscription to be saved again
   before later batches. The current code versions predicate changes through
   the subscription ID and compares only stable structural properties.
4. Clearing delivered alerts in the app handles completion while Authsia is
   active, but cannot run after the user swipes the app away.
5. A v3 mutable-content subscription and iOS Notification Service Extension
   were tested to re-query CloudKit at delivery time. When no actionable request
   remained, the extension softened the alert and removed its sound; errors and
   timeouts failed open to the original alert. This experiment regressed normal
   notification and approval visibility and was reverted. Current v2 preparation
   removes the experimental v3 subscription before accepting or saving v2.
6. Fully suppressing a stale alert from a Notification Service Extension by
   returning empty notification content requires Apple's restricted filtering
   entitlement. Apple's request form currently limits eligibility to encrypted
   messaging, earthquake warning, education, and healthcare patient-care use
   cases. Authsia's security approval workflow does not truthfully fit those
   categories, so this entitlement is not an available architectural dependency.
7. The first Production v2 save failed closed because the deployed
   `RemoteJITApprovalV1` schema did not contain `notify`. Unified CloudKit logs
   reported `could not find required field 'notify'`. The installed Developer
   ID Mac app and embedded profile were verified to use Production, isolating
   the failure to schema deployment. Promoting the working Development schema
   added the field and index; v2 then saved and the matching TestFlight device
   completed the notification and approval flow.

### Blockers and residual risks

- **A queued visible push cannot be recalled.** Once CloudKit/APNs has accepted
  the generic alert, approval completion on the Mac cannot retract it. If iOS
  delivers it after Authsia has been swiped away, it can still appear once even
  though opening the app shows no pending approval.
- **The current guarantee is creation cardinality, not retraction.** V2 targets
  one push per newly created batch. It cannot guarantee that a delayed push is
  still actionable when displayed.
- **The batch is not a first-class transport record.** `notify = 1` marks an
  arbitrary first approval record; there is no batch notification record with
  its own lifecycle. This is sufficient for one creation trigger, but it cannot
  express batch-level cancellation or exact notification reconciliation.
- **Obsolete-subscription cleanup requires one preparation run.** A rebuilt Mac
  must prepare an approval subscription once before any saved v1 or v3
  subscription is removed. Missing obsolete subscriptions are tolerated, while
  a real deletion failure blocks v2 saving and approval publication. The older
  capability-spike `.changes` subscription is not part of this automated list;
  it was removed manually and must not be recreated by running a spike build.
- **Schema changes must precede matching releases.** Production now has the
  required `notify` field and queryability for v2. Any future subscription
  predicate that adds a field or index must promote its Development schema
  change before distributing code that depends on it; otherwise publication
  fails closed before approval records are created.
- **Mixed record versions are not compatible.** The strict decoder rejects old
  records missing `notify`, and an older decoder rejects new records containing
  it. The impact is bounded by the 90-second request lifetime, but macOS and iOS
  should be upgraded together for device verification.
- **Old APNs work cannot be migrated.** Pushes already queued from v1, the
  capability-spike `.changes` subscription, or experimental v3 retain their
  original payload and can be observed once while the queue drains.
- **Account-isolation evidence is incomplete.** The different-iCloud-account
  physical-device scenario remains explicitly waived and not run.

These constraints do not weaken the security boundary: a stale notification
cannot recreate a request or grant access. They do limit the notification UX.
Without the restricted entitlement, the product must choose between a reliable
visible alert that may arrive stale and a background-only signal that iOS may
not deliver after force-quit. The current design chooses the visible generic
alert, treats CloudKit state as the source of truth, and accepts the possibility
of one late, non-actionable notification.

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

## Current Exfiltration Coverage

This matrix describes the implemented Authsia-owned boundary. Each channel
receives one primary classification:

- **prevented** — the Authsia boundary rejects the channel;
- **mediated** — Authsia is in the data path, but mediation is not a complete
  leak-prevention guarantee;
- **detected** — Authsia can record best-effort evidence but does not block it;
- **out of scope** — Authsia neither owns nor reliably observes the channel.

| Exfiltration channel | Current classification | Current boundary and limitation |
| --- | --- | --- |
| Standard output | Mediated | `authsia exec` masks known secret values and common transforms; novel transforms can bypass masking. |
| Standard error | Mediated | Uses the same masking boundary and has the same limitations as stdout. |
| Invalid or incomplete UTF-8 output | Prevented by default | Strict output buffers a valid multibyte code point split across read chunks. Invalid sequences, or a partial code point still incomplete when the stream closes, are withheld; the child is terminated and the CLI exits `74`. Explicit `masked-compatibility` may pass those bytes with a warning. Valid UTF-8 using a novel transform remains mediated, not categorically prevented. |
| File writes | Detected | Agent file-activity evidence can show best-effort writes in a managed scope; it does not block or inspect arbitrary content. |
| Network | Out of scope | Arbitrary child network traffic is not mediated. |
| Subprocesses | Detected | Command and ancestry evidence can identify supported activity; child-process behavior is not contained. |
| Clipboard | Out of scope | Authsia does not monitor arbitrary child clipboard access. |
| IPC | Out of scope | Authsia validates its own XPC boundary but does not police arbitrary same-user IPC. |
| Agent transcripts | Out of scope | Hook attribution is metadata, not transcript inspection or sanitization. |
| Process memory | Out of scope | Root, debugger, injection, and arbitrary same-user memory inspection are not application-level guarantees. |

Full operating-system filesystem, process, and network DLP is intentionally
outside Authsia's responsibility. Product claims must stay limited to
Authsia-owned CLI, hook, workspace, and execution surfaces.

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
4. The bridge resolves each item to its stable type-and-UUID identity. Folder
   and environment metadata remain live policy and display context.
5. For every item or capability without matching authority, the app asks the
   user to approve the canonical descriptor. Local and paired-iPhone panels
   show the same caller, workspace, working directory, environment, capability,
   duration, reuse policy, and exact item metadata.
6. A multiple-item decision persists atomically; denial or storage failure
   creates no partial grant.
7. Approved grants are saved in authenticated Bridge-owned authority and
   returned to the CLI.
8. The `exec` internal metadata list can use the grant's `list` capability only
   within the displayed exact-item or explicit folder scope.
9. Final secret reads rerun live item, caller, exact working-directory/workspace,
   environment, capability, and grant policy and must find an active matching
   `exec` grant.
   Without it, the bridge fails closed with:

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

Chrome autofill is not an agent caller. Bridge only takes the chrome path when
both `--chrome-native-host` (`requestedCommand=chromeNativeHost`) and an
`AuthsiaNativeHost` parent are present. That path issues a reusable
`chrome-native-host` session after the first approval and keeps it across
Chrome's per-message native-host process restarts (stable origin, not
PID-bound). Terminal, agent JIT, and IDE-hosted CLI callers are unchanged.

## Scope Rules

JIT grants use exact stable item identities by default. An approval for item A
does not authorize item B because they share a folder. A multiple-item request
shows and persists every exact item atomically.

Reusable folder scope remains an explicit compatibility choice only when the
approval displays that broader scope:

| Displayed scope | What it covers |
| --- | --- |
| Exact item | Only the displayed type-and-UUID item, subject to live folder and environment policy |
| Root folder | Root items only; never the whole vault |
| `Team/API` folder | `Team/API` and slash-delimited descendants such as `Team/API/Prod` |

Important edge cases:

- A root grant covers root items only. It does not include any folder.
- Exact references remain separate item identities even when their display
  folders share an ancestor.
- A grant for `Team/API` covers `Team/API/Prod`, but a grant for
  `Team/API/Prod` does not cover `Team/API` only when the user explicitly
  approved that folder scope.
- Prefix lookalikes are not descendants: `Team/API2` and `Team/API` are sibling
  scopes.
- Moving the same exact item preserves its identity but does not bypass a live
  folder or environment restriction.
- Workspace authority is the exact working-directory string, including
  nil-versus-present state. The workspace name is derived display context, not
  a second mutable authority key.
- A changed caller, working-directory/workspace, environment, or capability
  requires matching authority and can require another approval.

## Approval Copy

The prompt states why another approval is needed and shows exact item name,
type, and folder without showing values. It also shows caller, workspace and
working directory, capability, environment, duration, and whether reuse is
`Exact items only` or an explicit folder scope. Multiple exact items use one
atomic approve/deny decision. A list-only grant does not silently widen to
`exec`.

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

The bearer is displayed once and is not stored in the token-free CLI cache.
Bridge-owned authenticated authority enforces its machine binding, expiry,
revocation, capability, item or folder scope, environment, maximum uses, and
rate limits. A denied credential does not fall back to human or JIT approval,
and the general bearer is removed before launching an `exec` child. The
operator must still protect the bearer before launch: Authsia does not make a
parent process's environment confidential. The parent app's canonical security
model documents credential generation, verifier storage, upgrade behavior, and
the residual same-user boundary in
[`security-model.md#automation-credentials`](security-model.md#automation-credentials).

## TTL And Revocation

JIT grants use the configured CLI session TTL (`cliSessionTTL`). The default is
the same default used by normal CLI sessions, and the maximum is 24 hours.
Legacy negative TTL preferences are treated as 24 hours.

Active grants are stored in the versioned, HMAC-authenticated Bridge authority
store backed by Keychain. The former path:

```text
~/Library/Application Support/Authsia/agent-jit-grants.json
```

is legacy input only. On first grant-store access after upgrade it is moved to a
quarantine name and is never read as authority. Its former `0700` directory and
`0600` file permissions do not make it trusted.

Grants can become inactive in three ways:

- expiry
- manual revocation from Access Center
- lazy revocation when the associated terminal/session scope is detected as
  closed

Cursor extension-host grants replace the short-lived CLI process-session
component with the Bridge-observed extension-host PID. Repeated calls from the
same Cursor host and working directory therefore reuse the grant, while closing
that host triggers the same lazy revocation path as a closed terminal session.

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
exact-item or explicitly approved folder scope, caller, workspace, environment,
capability, TTL, and audit records. File activity does not grant or deny access.

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
- the grant is expired, revoked, outside its exact-item or explicit folder
  scope, wrong-workspace, wrong-environment, wrong-command, or wrong-caller
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

## GA Hardening Contract

- Agent/suspect ancestry is evaluated before human-session reuse. Reusable
  human sessions require a signed supported terminal host and are bound to that
  observed host origin; an unknown interactive caller may receive one-request
  biometric approval but no reusable session.
- Approval descriptors carry exact stable item identities, caller, workspace,
  environment, duration, and reuse semantics. Local and remote approval use the
  same versioned descriptor and reject mixed canonical versions.
- Bridge-owned authority is the only active authority. Unsigned legacy JIT JSON
  and legacy automation metadata are non-authoritative and require reapproval
  or credential recreation.
- Sensitive requests require security protocol version 2. A new Bridge rejects
  omitted bindings, while a new CLI checks the Bridge version before sending.
- Caller-binding or exact-scope violations revoke the related JIT grant in the
  same Bridge store mutation and add an HMAC-backed redacted audit marker.
- Strict output is the default. Known plaintext and recognized deterministic
  transforms are masked across stdout/stderr stream boundaries; invalid or
  incomplete UTF-8 is withheld, terminates the child, and exits `74`.
  `masked-compatibility` is explicit and warned.
- Supported Claude Code and Copilot pre-tool hooks support workspace
  `observe`, `confirm`, and `block` response modes. Post-tool evidence may alert
  or revoke but never claims that a completed action was prevented.
- This boundary is not full OS process DLP. An approved child can still write,
  encode, or transmit values through channels Authsia does not mediate.
