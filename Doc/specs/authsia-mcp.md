# Local Authsia MCP Server

Status: release-candidate implementation contract for M14; signed installed-product validation pending

## Table Of Contents

- [Purpose](#purpose)
- [Protocol And Process Boundary](#protocol-and-process-boundary)
- [Trust And Authorization Model](#trust-and-authorization-model)
- [Agent JIT And MCP Capability Comparison](#agent-jit-and-mcp-capability-comparison)
- [Workspace Binding](#workspace-binding)
- [Tool Contract](#tool-contract)
- [Execution Lifecycle](#execution-lifecycle)
- [Grant Ownership And Revocation](#grant-ownership-and-revocation)
- [Audit And Activity Correlation](#audit-and-activity-correlation)
- [Errors And Output](#errors-and-output)
- [Threat Model](#threat-model)
- [Client Configuration](#client-configuration)
- [Compatibility And Upgrade Policy](#compatibility-and-upgrade-policy)
- [Verification Contract](#verification-contract)

## Purpose

Authsia MCP gives local coding agents a standard, constrained way to use the
existing Authsia Workspace and Agent JIT flow. It does not create another
secret API or another authorization authority.

The server is launched as:

```text
authsia mcp serve
```

It exposes six tools over local standard input/output. Side-effect-free read-only
tools report non-secret runtime or commit-safe workspace metadata.
`authsia_list` returns scoped CLI-enabled Vault item metadata through the
existing list-only Agent JIT preflight and Bridge list filter. The execution
tool starts the same installed `authsia` binary with `workspace run`, so
Keychain reads, approval, grant checks, output masking, file cleanup, Process
Tree evidence, network evidence, and Bridge audit remain on their existing
paths.

The intended security property is:

> An MCP client may ask Authsia to run an approved command, but it cannot ask
> Authsia to return a plaintext secret or grant itself broader authority.

This document owns the public MCP protocol and security contract. JIT
authorization remains owned by [`jit-agent-grants.md`](jit-agent-grants.md),
the overall boundary by [`security-model.md`](security-model.md), and runtime
paths by [`storage.md`](storage.md).

## Protocol And Process Boundary

- Transport is local `stdio` only. V1 opens no HTTP listener, Unix socket, or
  network port.
- The client launches `authsia mcp serve` outside its agent command sandbox so
  the server can reach the local Authsia Bridge and launch mediated child
  processes. Agents use the client-managed tool connection and must not start
  another server from a sandboxed shell.
- The implementation uses the official Swift MCP SDK pinned to `0.12.1` and
  the MCP `2025-11-25` protocol revision supported by that release.
- V1 advertises only the `tools` capability with a static tool list.
  `listChanged` is false.
- V1 does not advertise resources, prompts, sampling, elicitation, MCP Apps,
  task-augmented execution, or server-initiated model calls.
- Standard output contains MCP frames only. Redacted diagnostics go to standard
  error. Child standard output and error are captured and returned inside the
  tool result; they are never written directly to server standard output.
- A server process creates one random server-instance UUID in memory whether it
  starts bound or unbound. It does not persist or accept that UUID from the
  client.
- Client initialization name and version are untrusted display metadata. They
  never replace OS-observed caller identity or any Bridge authorization check.
- The tool catalog is closed. Unknown tools are protocol errors, and unknown
  input fields are rejected.

The MCP server is a signed Authsia adapter, not a policy authority. The Bridge
continues to decide whether a secret-bearing request is allowed.

## Trust And Authorization Model

The MCP client and model are untrusted. Tool arguments, initialization
metadata, cancellation reasons, and client-side confirmation state are all
untrusted input.

MCP integrations are an explicit macOS app opt-in and are disabled when the
`mcpAccessEnabled` preference is absent or false. The client may still launch
the local stdio process, but every recognized tool returns
`mcpAccessDisabled` before workspace selection, grant access, Vault access, or
child-process launch. Enabling MCP does not enable CLI access, create a grant,
or bypass any existing Bridge/JIT check.

For every JIT-mediated list or secret-bearing execution, all existing
conditions still apply:

- the Bridge verifies the connecting Authsia code and OS-observed caller;
- CLI access and per-item CLI access are enabled;
- the canonical workspace and invocation directory are valid;
- requested items resolve live and are in approved scope;
- requested capability and environment match;
- an active, unexpired, unrevoked JIT grant exists after approval;
- final secret reads revalidate policy immediately before release.

MCP V1 is JIT-only. Before launching the wrapper, the server constructs a new
environment from a fixed set of basic process variables (`HOME`, `LANG`,
`LOGNAME`, `PATH`, `SHELL`, `TERM`, `TMPDIR`, `USER`,
`__CF_USER_TEXT_ENCODING`, and `LC_*`) plus the non-secret TLS trust settings
`REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE`, and server-generated MCP runtime
context. It does not copy the rest of the MCP server environment, including
cloud credentials, access tokens, stale Authsia runtime context, or Authsia
automation credentials. The internal process-control and error-status markers
are removed before the requested payload process launches. An MCP client cannot
select the automation-credential path. Unattended MCP automation needs a
separate future design and is not implied by this contract.

MCP client confirmation is additive usability only. It is not Authsia
authorization. A client may skip, mislabel, or automatically approve its own
tool prompt; Authsia still requires its Bridge/JIT decision.

The MCP runtime identity narrows existing authority but never creates it:

- `agentType` is `authsia-mcp`;
- `sessionID` is `mcp:<server-instance-uuid>`;
- `turnID` and `toolUseID` are `mcp-call:<invocation-uuid>`;
- `platform` is a normalized client display label when available;
- `agentID` is omitted in V1.

`platform`, client name, and client version remain display metadata. The
server-generated MCP `agentType` plus `sessionID` may only prevent reuse of an
MCP grant from another server instance. They are never sufficient to match a
grant and never weaken caller, workspace, scope, capability, environment, TTL,
or revocation checks. Non-MCP JIT behavior remains unchanged.

## Agent JIT And MCP Capability Comparison

“Direct Agent JIT” below means the agent-classified Authsia CLI path described
in [`jit-agent-grants.md`](jit-agent-grants.md), not the broader human CLI or
automation-credential surfaces. Agent JIT stores only `list` and `exec`
capabilities. Of the six MCP tools, only `authsia_list` and `authsia_exec` enter
JIT; status, workspace inspection, owned-grant status, and owned-grant
revocation are bounded non-secret control tools.

| Capability | Direct Agent JIT | Local Authsia MCP V1 |
| --- | --- | --- |
| Bridge readiness and commit-safe workspace inspection | **Outside JIT.** Normal non-secret CLI and Workspace paths provide this context. | **Supported without JIT.** `authsia_status` and `authsia_workspace_inspect` expose bounded non-secret state. |
| Scoped Vault metadata list | **Supported.** `authsia list` can request CLI-enabled Password, API Key, Certificate, Secure Note, or SSH Key metadata under the approved item/folder scopes. | **Supported with tighter input scope.** `authsia_list` requests one supported type per call, stays inside the configured workspace Vault folder, reapplies environment scope, and paginates 1–100 common-metadata rows. |
| Secret-bearing command execution | **Supported.** `authsia exec` and secret-bearing `authsia workspace run` can inject approved Password, API Key, Certificate, and Secure Note values into the launched child. | **Supported only through the bound workspace.** `authsia_exec` delegates to secret-bearing `authsia workspace run` for the same four secret-bearing item types. |
| Raw secret-return commands | **Not supported.** JIT denies `get`, `read`, `load`, and `inject` even when a human session exists. | **Not supported.** No raw-secret tool exists, and tool output must never contain plaintext secret values. |
| SSH capability | **Metadata list only.** `authsia list ssh` is supported; SSH private-key reads, loading, agent operations, and signing are outside Agent JIT. | **Metadata list only.** `authsia_list` can return common SSH Key metadata; private/public key material, loading, agent operations, and signing are absent. |
| OTP capability | **Not supported.** OTP metadata and values are excluded from Agent JIT. | **Not supported.** No OTP list, value, or execution input exists. |
| Local Mac and paired-iPhone approval | **Supported.** Both approve the same canonical Agent JIT descriptor; the Bridge remains grant authority. | **Supported by reuse.** MCP list and exec use that same local or remote approval flow and do not create a second approval type. |
| Grant capabilities | **Supported as `list` and `exec` only.** A direct list creates list-only authority; exec approval creates the authority needed for final exec reads and scoped metadata resolution. | **Same capabilities.** MCP cannot request any additional JIT capability. |
| Grant reuse and isolation | **Ordinary JIT matching.** Caller fingerprint, workspace or exact working directory, item/folder scope, environment, capability, TTL, and revocation must match. | **More narrowly isolated.** Every ordinary JIT check must match, and MCP-backed grants must also belong to the same server-instance ID. |
| Grant inspection and revocation | **Operator path.** Access Center and Bridge-owned controls review or revoke JIT grants; this is not a JIT grant capability. | **Supported for owned active grants.** `authsia_access_status` and `authsia_access_revoke` can affect only the current MCP server instance; Access Center handles global, historical, or orphaned review. |
| Human CLI sessions | **Separate from JIT.** Trusted human-terminal approval can create a terminal-scoped reusable session, but an agent cannot inherit it as JIT authority. | **Not supported.** MCP neither accepts nor creates a human session token and never falls back to the human approval path. |
| Automation credentials and unattended access | **Separate from JIT.** An explicit automation credential follows its own policy and may authorize capabilities that JIT does not. | **Not supported.** The server strips ambient automation authority, exposes no credential input, and requires interactive JIT for mediated list or exec. |
| Workspace reach | **Workspace or exact directory.** Inside a managed workspace, canonical workspace authority applies; outside one, exact working-directory matching remains available. | **Managed workspace only.** Explicit server binding, an optional validated `workspaceRoot` tool argument, or safe launch context must resolve one initialized workspace. No tool can select an arbitrary working directory. |
| Vault administration | **Not supported.** JIT cannot unlock Authsia, create access, export, add, edit, delete, or otherwise mutate Vault items. | **Not supported.** No unlock, access creation, import/export, clipboard, or Vault mutation tool exists. |
| Command shape | **Normal CLI argv.** Direct Agent JIT follows the `authsia exec` CLI contract and generated agent guidance favors explicit argv or reviewed scripts. | **Direct argv only.** `authsia_exec` rejects shell command strings and control characters; it does not interpret pipe, redirect, or compound-command syntax. Reviewed workspace scripts may be executed directly. |
| Output, cleanup, and activity evidence | **Supported on secret-bearing exec.** Existing masking, observed-file cleanup, Process Tree, network evidence, and Bridge audit apply. | **Same runtime protections plus MCP bounds.** Output is structured and capped at 65,536 bytes per stream, with invocation correlation and managed process-group cancellation. |
| Audit and Access Center | **Supported.** Existing grant, command, file, Process Tree, network, and HMAC audit records remain canonical. | **Supported by reuse.** The same records add MCP source, server-instance, invocation, and revocation correlation; MCP cannot read global audit history. |
| MCP resources, prompts, sampling, elicitation, Apps, tasks, or remote transport | **Not applicable to Agent JIT.** | **Not supported in V1.** The server advertises only six tools over local `stdio`. |

MCP therefore adds a standard client interface, safe context queries, and
current-instance grant controls around Agent JIT. It does not add a new secret
delivery mode, item type, approval authority, or grant capability.

## Workspace Binding

One server process is either unbound or serves one canonical managed workspace
at a time:

1. Startup establishes safe launch context from explicit `--workspace`, one
   absolute `WORKSPACE_FOLDER_PATHS` entry, or the process working directory.
2. Every workspace-dependent tool accepts an optional `workspaceRoot` absolute
   local path. IDE-hosted clients pass their active repository through this
   field; the tool schema and server instructions expose the requirement.
3. A supplied directory passes through the existing `WorkspaceRootResolver`,
   standardized authority validation, and validated `.authsia/workspace.json`
   store. Nested paths may converge on their canonical managed workspace.
4. Explicit `--workspace` is authoritative and disables tool-driven rebinding.
   Otherwise, a valid `workspaceRoot` takes precedence over launch context; an
   omitted field retains the current binding. Existing Claude Code and Codex CLI
   sessions therefore keep their working-directory behavior.
5. Changing the canonical tool-selected workspace first attempts to revoke
   active grants owned by that MCP server instance. Rebinding is rejected while
   a mediated list or execution is active. Because concurrent tool calls share
   one binding, each call selects its workspace and claims the mediated slot
   without yielding in between, so a mediated operation always runs against the
   workspace its own call named.
6. When the workspace is missing, invalid, unsupported, an unsafe path, or
   reached through a containment-breaking symlink, the process remains unbound.
7. An unbound server keeps `authsia_status` available with a
   `workspaceUnavailable` diagnostic. Workspace inspection, metadata listing,
   and execution return the stable `workspaceUnavailable` tool error.

The server may inspect only these workspace sources:

- validated fields in `.authsia/workspace.json`;
- managed environment files named by that configuration, after canonical
  containment and regular-file checks;
- `authsia://` reference tokens and their variable names in those files.

Inspection must not return other environment-file values, comments, complete
lines, file contents, Keychain values, or live vault metadata. It inspects at
most 128 configured files, rejects a file larger than 1 MiB before parsing,
reads at most 4 MiB in aggregate, returns at most 1,000 references and 100
diagnostics, and reports truncation where the response contract provides it.
Returned references are reconstructed as canonical `authsia://` URIs; unknown
query fields and their values are discarded. Missing, oversized, unreadable, or
unsafe managed files produce fixed redacted diagnostics rather than raw errors
or reads outside the workspace.

## Tool Contract

All input schemas are JSON objects with `additionalProperties: false`. All
tools declare a closed `outputSchema` with top-level `type: "object"` for strict
client compatibility; its `oneOf` branches describe either that tool's success
object or the common stable error object. Results return
matching `structuredContent`, plus a compact JSON text block for compatible
clients. Tool and output descriptions must state that plaintext secrets are
never returned.

### Catalog And Annotations

| Tool | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `openWorldHint` |
| --- | --- | --- | --- | --- |
| `authsia_status` | true | false | true | false |
| `authsia_workspace_inspect` | true | false | true | false |
| `authsia_list` | false | false | false | false |
| `authsia_access_status` | true | false | true | false |
| `authsia_exec` | false | true | false | true |
| `authsia_access_revoke` | false | true | true | false |

Annotations are conservative risk hints for the client. They do not change
Bridge authorization. `authsia_list` is non-destructive but not marked
read-only or idempotent because it can create or reuse a temporary JIT grant
and append approval/audit activity.

### `authsia_status`

Input fields:

| Field | Type | Rules |
| --- | --- | --- |
| `workspaceRoot` | string or null | Optional safe absolute local path to the active initialized Authsia workspace. Ignored for authority when the server has explicit `--workspace`. |

Output fields:

| Field | Contract |
| --- | --- |
| `serverInstanceID` | Server-generated UUID string; not an authorization token. |
| `protocolRevision` | MCP revision implemented by this server. |
| `workspaceName` | Validated workspace display name. |
| `workspaceRoot` | Canonical root already visible to the local client. |
| `bridgeState` | `ready`, `unavailable`, or `cliAccessDisabled`. |
| `ready` | True only when workspace and Bridge checks permit an execution attempt. |
| `diagnostics` | Bounded code/message pairs with no raw errors or secret material. |

The status check performs a live Bridge ping, including the Bridge's CLI-access
flag, but performs no approval, vault listing, or secret read. A Bridge that is
reachable while CLI access is disabled reports `cliAccessDisabled`, not
`ready`. Older compatible ping payloads that omit the optional flag continue to
decode as reachable.

### `authsia_workspace_inspect`

Input fields:

| Field | Type | Rules |
| --- | --- | --- |
| `environment` | string or null | Optional existing workspace environment name; 1–128 characters after trimming. |
| `workspaceRoot` | string or null | Optional safe absolute local path to the active initialized Authsia workspace. |

Output contains the workspace name/root, workspace schema version, selected and
available environment names, managed relative file paths, and discovered
reference descriptors. Each reference descriptor contains only its normalized
`authsia://` URI, optional environment-variable name, relative source path, and
selected-environment state.

The result contains at most 1,000 reference descriptors and reports
`referencesTruncated=true` when more valid references were found. V1 has no
pagination cursor; users must narrow the managed workspace configuration rather
than use MCP to enumerate unbounded repository content.

This tool does not validate a reference against live vault metadata. Use
`authsia_list` for approved scoped discovery. Existence, CLI enablement, item
identity, scope, and authorization for execution are resolved during the
existing JIT preflight started by `authsia_exec`.

### `authsia_list`

Input fields:

| Field | Type | Rules |
| --- | --- | --- |
| `type` | enum string | Required: `password`, `api-key`, `certificate`, `note`, or `ssh`. OTP is intentionally unsupported by Agent JIT. |
| `folder` | string or null | Optional workspace-folder subtree. Defaults to the configured Authsia workspace folder and cannot name an ancestor, sibling, root, or unrelated tree. |
| `environment` | string or null | Optional named environment; 1–128 UTF-8 bytes with no control characters. |
| `workspaceRoot` | string or null | Optional safe absolute local path to the active initialized Authsia workspace. |
| `limit` | integer | Defaults to 50; allowed range 1–100. |
| `offset` | integer | Defaults to 0; allowed range 0–100,000. |

The tool allocates a fresh MCP invocation context, submits the ordinary
`agentJITPreflight` request with `requestedCommand=list`, and then performs the
ordinary Bridge list request with the same context. Approval may therefore use
the existing local Mac or paired-iPhone remote Agent JIT decision path. Any
created grant has only the `list` capability and remains narrowed to the current
MCP server instance, caller, workspace, folder/resource scope, environment,
TTL, and revocation state.

Output contains the invocation ID, effective type/folder/environment, page
items, `totalCount`, `count`, `offset`, `hasMore`, and `nextOffset`. Each item
contains only ID, display name, folder path, favorite state, CLI-enabled state,
and environment tags. Passwords, API-key values, note content, certificate
material, SSH public/private key material, usernames, websites, comments, and
other type-specific fields are not part of the MCP schema.

When the requested workspace subtree has no CLI-enabled items of that type,
the Bridge preflight `notFound` result is normalized to a successful empty page
with `totalCount=0`, `count=0`, and `items=[]`. No approval or grant is created
for that empty category. Other Bridge, policy, approval, and transport failures
remain tool errors.

Bridge policy first limits results to CLI-enabled metadata covered by active
list grants. The MCP adapter then reapplies type, workspace-folder containment,
and environment filtering before deterministic sorting and pagination. It never
falls back to a human CLI session, automation credential, unscoped list, or
whole-vault enumeration.

A named `environment` limits results to items tagged with that exact environment
or `All`; Default-only and other-environment items are excluded.

### `authsia_access_status`

Input: an empty object.

Output contains only grants created for the current MCP server instance. Each
grant summary may include:

- grant UUID and `active`, `expired`, or `revoked` state;
- non-secret scope summary and item count;
- `list`/`exec` capabilities;
- selected environment name;
- created, expiry, last-used, and revoked times;
- approval source;
- current MCP server and originating invocation IDs.

The result excludes secret values, requested item payloads, caller fingerprint
internals, other agents' grants, human sessions, automation credentials, and
global audit history.

### `authsia_exec`

Input fields:

| Field | Type | Rules |
| --- | --- | --- |
| `argv` | string array | Required; 1–64 elements, no NUL, no empty executable, at most 32 KiB UTF-8 combined. |
| `environment` | string or null | Optional existing environment name; mutually consistent with `defaultOnly`. |
| `defaultOnly` | boolean | Defaults to false; uses existing Workspace semantics. |
| `envFiles` | string array | Defaults to empty; at most 16 commit-safe relative paths contained by the workspace. |
| `timeoutSeconds` | integer | Defaults to 900; allowed range 1–1800. |
| `workspaceRoot` | string or null | Optional safe absolute local path to the active initialized Authsia workspace. |

There is no shell-string, arbitrary working-directory, automation credential,
secret, raw environment map, approval bypass, or arbitrary executable-path
field. `argv` is passed as an argument vector to the exact resolved Authsia
binary; the MCP server never invokes a shell.

Agents must not add the CLI `--shell` option to an MCP call; it is not an
`authsia_exec` field. A program that reads an injected variable directly can be
launched as ordinary `argv`. If the requested behavior inherently needs shell
expansion, substitution, pipes, or redirects, the agent must create or use a
reviewed workspace script and pass that script as direct `argv` instead.

Output fields:

| Field | Contract |
| --- | --- |
| `invocationID` | Server-generated UUID used for audit/activity correlation. |
| `termination` | `exited`, `signalled`, `timedOut`, `cancelled`, or `launchFailed`. |
| `exitCode` | Child exit code when available. Nonzero is not a protocol error. |
| `stdout` / `stderr` | Existing Authsia-masked UTF-8 output, each bounded to 65,536 bytes. |
| `stdoutTruncated` / `stderrTruncated` | True when the corresponding bounded capture omitted bytes. |
| `durationMilliseconds` | Nonnegative bounded duration metadata. |

Truncation happens after continuous streaming through the existing output
masker. The implementation must not retain an unmasked prefix merely to apply
the final size limit.

Calling `authsia_exec` performs the existing JIT preflight as part of
`workspace run`. There is no separate approval or grant-creation tool in V1.
`environment` selects exact-tagged and `All` items for that call without changing
the saved workspace selection. `defaultOnly` selects the Default and `All` scope
for that call; the two fields cannot be combined.

### `authsia_access_revoke`

Input contains one required `grantID` UUID string.

The Bridge revokes the grant only when it is active, has `agentType` equal to
`authsia-mcp`, and its server-generated `sessionID` matches this server process.
Another server's grant, a normal agent grant, human session, automation
credential, expired row, or malformed identifier is not owned by this tool.

Repeating a successful revocation is idempotent for the same server process and
returns the final inactive state. It does not terminate a command that has
already received secrets and started. Access Center is the operator surface for
reviewing and revoking historical or orphaned MCP grants.

## Execution Lifecycle

`authsia_list` validates and bounds its input, allocates a fresh invocation,
and performs the existing list-only JIT preflight and Bridge list request
without a shell or child command. It returns only the normalized paginated
metadata described above. Because the request is issued in-process rather than
through a mediated child, it reports the bound workspace root as its working
directory, so approval and audit attribute the call to the workspace the tool
named. A pending local or remote approval uses the existing bounded Bridge wait
behind a server deadline, and MCP cancellation abandons that wait instead of
holding shutdown open; status and owned-grant revocation remain separate tools.

`authsia_exec` follows this execution lifecycle:

1. Validate the tool request and allocate a random invocation UUID.
2. Reject the call with `busy` when another JIT-mediated `authsia_list` or
   `authsia_exec` operation is active in this server. Read-only status calls and
   revocation may continue.
3. Resolve the exact running Authsia binary; reject symlinks or substitutions
   that do not satisfy the installed-product resolution rules.
4. Construct `authsia workspace run` arguments without a shell.
5. Build the allowlisted environment described above and add the
   server-generated MCP runtime context.
6. Start the wrapper in a dedicated process group with captured standard
   output/error and no interactive TTY; do not pass internal MCP control markers
   to the requested payload.
7. The child runs existing reference discovery, JIT preflight, approval, live
   policy checks, secret injection, output masking, activity capture, cleanup,
   and audit behavior.
8. Return the bounded structured result after the child and existing cleanup
   work complete.

Only one JIT-mediated list or execution operation may run per server in V1.
This prevents overlapping approval prompts and ambiguous attribution without
adding a new scheduler. Separate workspace-scoped MCP server processes remain
isolated.

For `authsia_list`, cancellation or server shutdown stops accepting mediated
work and waits for the existing bounded Bridge approval/list request before
grant cleanup. For `authsia_exec`, cancellation, timeout, EOF, SIGINT, and
SIGTERM cancel the active execution and wait for its managed wrapper process
group. The runner sends `SIGTERM` to the group, escalates to `SIGKILL` after the
bounded grace period, drains the captured streams, and observes termination
before server grant cleanup and shutdown finish. If the wrapper exits while
descendants remain in its group, the runner applies the same bounded cleanup
before returning an otherwise normal result. Cancellation and timeout are
stable tool errors rather than success merely because a signal was sent. MCP V1
does not use the experimental Tasks extension. This lifecycle controls the
Authsia-created process group; it does not claim OS-wide containment of a
process that independently escapes that group.

Graceful server shutdown attempts to revoke active grants owned by that server
instance. Abrupt termination may leave them visible until Bridge liveness,
manual Access Center revocation, or TTL expiry makes them inactive. Because MCP
instance matching is a narrowing condition, a later server instance cannot
reuse those grants.

## Grant Ownership And Revocation

An MCP grant remains an ordinary authenticated Bridge-owned Agent JIT grant.
It adds no second store and no bearer token.

For any grant lookup, the existing JIT checks must pass and the following
MCP-separation rule applies:

- when either the stored grant or current request is MCP-backed, both must have
  `agentType == "authsia-mcp"` and the same server-generated `sessionID`;
- when neither side is MCP-backed, existing ordinary JIT matching is unchanged.

This rule only narrows MCP reuse. It does not make runtime metadata sufficient
authority and does not alter matching for ordinary Agent JIT grants.

Consequences:

- tools in one server process can reuse its approved grant while all existing
  scope and liveness conditions continue to match;
- another workspace, MCP process, client, or restarted process cannot reuse it;
- a direct agent JIT grant cannot silently authorize MCP execution, and an MCP
  grant cannot silently authorize a direct agent invocation;
- Access Center can revoke any active MCP grant through existing Bridge
  authority, including an orphan from an abruptly terminated process.

## Audit And Activity Correlation

MCP creates no audit file and no activity database. Existing records remain
canonical:

- HMAC-chained `bridge_audit.log` for sensitive Bridge activity;
- Agent command history;
- Agent file activity;
- Agent network activity;
- injected Process Tree history;
- authenticated Bridge Agent JIT grant authority.

Correlation uses existing fields:

| Meaning | Existing field |
| --- | --- |
| OS-observed requester | `caller` / caller fingerprint |
| Grant | `agentJITGrantID` |
| Workspace and invocation directory | `workspaceContext` |
| Environment | `environmentScope` |
| Approval source | `approvedBy` |
| MCP source classification | `agentRuntimeContext.agentType` |
| MCP server instance | `agentRuntimeContext.sessionID` |
| MCP tool invocation | `agentRuntimeContext.turnID` and `toolUseID` |
| Client display label | `agentRuntimeContext.platform` |

Authorization-sensitive records must preserve the same runtime context from
MCP call through preflight, grant, final secret read, command event, and
available file/network/Process Tree evidence. Correlation IDs are metadata, not
credentials.

An MCP access-revocation call receives its own fresh invocation ID. The Bridge
revocation audit record preserves that invocation context, grant ID, workspace,
environment, and requested operation so Access Center can correlate the
terminal event rather than showing an unattributed revoke.

Audit and activity must never store raw JSON-RPC requests/responses, MCP client
conversation content, command output, stdin, environment values, secret values,
or cancellation text. Existing HMAC verification and export redaction apply.

## Errors And Output

Malformed JSON-RPC, unknown tools, and requests that do not satisfy the MCP
request envelope are protocol errors. Valid tool calls that fail validation,
policy, approval, or execution return a tool result with `isError: true` and a
stable structured error:

| Code | Meaning |
| --- | --- |
| `invalidInput` | Tool arguments violate the closed schema or bounds. |
| `workspaceUnavailable` | The locked workspace is missing, invalid, or unsafe. |
| `bridgeUnavailable` | The local Bridge cannot be reached or validated. |
| `mcpAccessDisabled` | MCP integrations are disabled in Authsia Developer Access settings. |
| `cliAccessDisabled` | Authsia CLI access is disabled. |
| `approvalDenied` | The user denied or cancelled Authsia approval. |
| `grantUnavailable` | Required grant is absent, expired, revoked, or no longer matches. |
| `grantNotOwned` | Status/revoke target is not owned by this MCP instance. |
| `busy` | This server already has an active JIT-mediated list or execution operation. |
| `timedOut` | Execution exceeded the requested timeout, or a listing exceeded the server deadline. |
| `cancelled` | MCP cancellation terminated or abandoned the call. |
| `executionFailed` | Launch or mediated execution failed. |
| `internalError` | A redacted unexpected failure occurred. |

Errors contain a short corrective message and invocation ID when allocated.
They do not return raw Swift errors, stack traces, absolute paths outside the
known workspace, secret reference resolutions, grant-store contents, or Bridge
payloads.

## Threat Model

| Threat | Required control |
| --- | --- |
| Client requests a plaintext secret | No raw-secret tool exists; unknown tools fail; execution delegates to masked Workspace run. |
| Client lies about name/version | Treat initialization and platform as display metadata only. |
| Client broadens workspace | A valid root is fixed at startup; an unbound server remains unbound; canonical containment is checked; no root/cwd tool field exists. |
| Managed file is a symlink escape | Canonicalize and reject sources outside the workspace before reading. |
| Shell or argument injection | Accept a bounded argv array and self-execute without a shell. |
| Ambient server credential or stale authority reaches the child | Construct the child environment from the fixed basic-variable and TLS-trust allowlist, add only fresh MCP context, remove internal markers before payload launch, and test the effective environment. |
| Another MCP instance reuses a grant | MCP session ID narrows matching in addition to all existing JIT checks. |
| MCP client views or revokes global access | Status/revoke output is limited to the current server instance; global review stays in Access Center. |
| Secret leaks through tool output | Reuse continuous strict masking, bound both streams, and test raw and transformed synthetic values. |
| Secret leaks through error/audit | Redact errors; store no JSON-RPC payload or output; preserve existing audit redaction and HMAC chain. |
| Concurrent calls confuse approval or attribution | Permit one active JIT-mediated list or execution operation per server and generate one invocation ID per call. |
| Cancellation leaves execution or descendants running | Put the wrapper and descendants in a dedicated process group, terminate then force-kill the group, and await observed exit before cleanup. |
| Abrupt server death leaves a reusable grant | Instance-narrowed matching prevents reuse; Bridge liveness, TTL, or Access Center revokes the orphan. |
| Client-side auto-approval is mistaken for authority | Authsia approval remains independent and mandatory when no matching grant exists. |
| New MCP protocol feature expands capability | Advertise only the frozen V1 capability set; require explicit spec and security review for additions. |

The model does not claim to sandbox an approved child or stop it from sending a
secret through every possible channel. Existing output masking and activity
evidence reduce accidental leakage and improve investigation; they are not
operating-system-wide DLP.

## Client Configuration

`authsia mcp configure --client <codex|claude|cursor|windsurf|vscode>` prints a
deterministic user-global local-stdio configuration for the exact installed
Authsia binary. V1 does not edit third-party configuration, launch the client,
add credentials, or use a shell wrapper.

Before using the configured client, the user explicitly enables **MCP
Integrations** under Authsia **Settings > Developer Access**. Client
configuration and MCP authorization remain separate: configuring a client
does not turn the Authsia setting on.

For Codex, Claude Code, and VS Code, the output includes a shell-safe direct
command using the client's supported user-global MCP installation surface, plus
the manual configuration fallback. Cursor and Windsurf receive only the manual
configuration because they do not expose a documented equivalent command.

Generated configuration must:

- pass `mcp serve` as an argv array;
- omit fixed repository paths so one user-global entry works across managed
  workspaces;
- contain no secret, bearer token, automation credential, or private endpoint;
- reject control characters and unsupported clients;
- warn that the user-global configuration contains a machine-specific absolute
  binary path and must not be committed or shared.

The delivered output uses user-global Codex `~/.codex/config.toml`, Claude Code
`~/.claude.json`, Cursor `~/.cursor/mcp.json`, Windsurf
`~/.codeium/windsurf/mcp_config.json`, and the VS Code user-profile `mcp.json`
shapes verified against each client's primary documentation. At startup, an
explicit `--workspace` takes precedence and disables client-driven rebinding.
Otherwise, each workspace-dependent tool may supply its active repository as a
validated absolute `workspaceRoot`. The server binds that canonical managed
workspace and attempts to revoke its active grants before later mediated work
after a switch. One absolute path from Cursor's `WORKSPACE_FOLDER_PATHS` launch
hint, then the process working directory, remain compatibility fallbacks.
Outside an initialized Authsia workspace the server remains available but
unbound, and workspace-dependent tools fail closed. Configuration formats
remain client-owned compatibility surfaces, not part of Authsia authorization.

## Compatibility And Upgrade Policy

The implementation baseline is the protocol revision supported by the pinned
Swift SDK. A newer MCP draft, release candidate, Tasks extension, transport, or
client feature is not adopted merely because a client supports it.
The server intentionally does not use MCP Roots: [protocol revision
2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)
deprecated that feature and directs new implementations toward tool parameters,
resource URIs, or server configuration. Authsia uses the closed `workspaceRoot`
tool parameter plus explicit and launch-context server configuration.

Before changing the SDK or protocol revision:

1. review the upstream changelog and protocol security changes;
2. rerun tool-schema, initialization, cancellation, stdout-framing, and client
   compatibility tests;
3. confirm the static six-tool surface did not expand;
4. update this specification before changing behavior.

Pre-1.0 Swift SDK minor releases may contain breaking changes, so the package
dependency remains exact rather than a floating range.

Primary upstream references:

- [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation)
- [Official Swift MCP SDK](https://github.com/modelcontextprotocol/swift-sdk)

## Verification Contract

Implementation is not complete until automated tests prove:

- exactly six tools are advertised with the specified closed schemas and
  annotations;
- the server initializes outside a managed workspace, status reports the
  unbound state, and workspace-dependent tools return `workspaceUnavailable`;
- list requests stay inside the configured workspace folder, create only
  list-capability JIT grants, preserve MCP instance/invocation context through
  the existing local or remote approval path, and return paginated common
  metadata without type-specific values;
- standard output contains valid MCP traffic only;
- initialization metadata cannot change authorization;
- workspace and managed-file symlink escapes fail closed;
- ambient credentials, stale Authsia context, automation authority, and internal
  MCP markers are absent from the requested payload environment;
- direct agent and different-instance grants cannot authorize MCP calls;
- the same-instance grant can be inspected and revoked only by that instance;
- execution uses argv without a shell, owns a process group, and leaves no
  managed descendants after normal wrapper exit, cancellation, timeout, or
  server shutdown;
- stdout/stderr are masked before bounded truncation;
- cancellation, timeout, nonzero exit, and Bridge failure are distinguishable;
- audit correlation preserves MCP instance, invocation, grant, workspace,
  environment, approval source, and OS-observed caller;
- HMAC audit verification passes and exported records contain neither the
  synthetic secret nor raw JSON-RPC payloads;
- existing human CLI, normal Agent JIT, automation credential, SSH, Chrome, and
  iOS builds remain unchanged.

Installed-product validation must exercise at least Codex, Claude Code, Cursor,
and VS Code from a real managed workspace before M14 is marked delivered.
