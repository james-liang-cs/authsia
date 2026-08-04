# Local Authsia MCP Server

Status: release-candidate implementation contract for M14; signed installed-product validation pending

## Table Of Contents

- [Purpose](#purpose)
- [Protocol And Process Boundary](#protocol-and-process-boundary)
- [Trust And Authorization Model](#trust-and-authorization-model)
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

It exposes five tools over local standard input/output. Read-only tools report
non-secret runtime or commit-safe workspace metadata. The execution tool starts
the same installed `authsia` binary with `workspace run`, so Keychain reads,
approval, grant checks, output masking, file cleanup, Process Tree evidence,
network evidence, and Bridge audit remain on their existing paths.

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
- The implementation uses the official Swift MCP SDK pinned to `0.12.1` and
  the MCP `2025-11-25` protocol revision supported by that release.
- V1 advertises only the `tools` capability with a static tool list.
  `listChanged` is false.
- V1 does not advertise resources, prompts, sampling, elicitation, MCP Apps,
  task-augmented execution, or server-initiated model calls.
- Standard output contains MCP frames only. Redacted diagnostics go to standard
  error. Child standard output and error are captured and returned inside the
  tool result; they are never written directly to server standard output.
- A server process creates one random server-instance UUID in memory after it
  resolves a valid workspace. It does not persist or accept that UUID from the
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

For every secret-bearing execution, all existing conditions still apply:

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
`__CF_USER_TEXT_ENCODING`, and `LC_*`) plus server-generated MCP runtime
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

## Workspace Binding

One server process serves one managed workspace:

1. Startup resolves the current directory through the existing
   `WorkspaceRootResolver`.
2. The resolved root is standardized and canonicalized.
3. The server reads `.authsia/workspace.json` through the existing validated
   workspace configuration store.
4. The process refuses to start when the workspace is missing, invalid,
   unsupported, an unsafe root, or reached through a containment-breaking
   symlink.
5. No tool argument can select another workspace root or arbitrary working
   directory.

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
tools declare a closed `outputSchema` whose `oneOf` branches describe either
that tool's success object or the common stable error object. Results return
matching `structuredContent`, plus a compact JSON text block for compatible
clients. Tool and output descriptions must state that plaintext secrets are
never returned.

### Catalog And Annotations

| Tool | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `openWorldHint` |
| --- | --- | --- | --- | --- |
| `authsia_status` | true | false | true | false |
| `authsia_workspace_inspect` | true | false | true | false |
| `authsia_access_status` | true | false | true | false |
| `authsia_exec` | false | true | false | true |
| `authsia_access_revoke` | false | true | true | false |

Annotations are conservative risk hints for the client. They do not change
Bridge authorization.

### `authsia_status`

Input: an empty object.

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

Output contains the workspace name/root, workspace schema version, selected and
available environment names, managed relative file paths, and discovered
reference descriptors. Each reference descriptor contains only its normalized
`authsia://` URI, optional environment-variable name, relative source path, and
selected-environment state.

The result contains at most 1,000 reference descriptors and reports
`referencesTruncated=true` when more valid references were found. V1 has no
pagination cursor; users must narrow the managed workspace configuration rather
than use MCP to enumerate unbounded repository content.

This tool does not validate a reference against live vault metadata. Existence,
CLI enablement, item identity, scope, and authorization are resolved during the
existing JIT preflight started by `authsia_exec`.

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

There is no shell-string, root, working-directory, automation credential,
secret, raw environment map, approval bypass, or arbitrary executable-path
field. `argv` is passed as an argument vector to the exact resolved Authsia
binary; the MCP server never invokes a shell.

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

1. Validate the tool request and allocate a random invocation UUID.
2. Reject the call with `busy` when another `authsia_exec` is active in this
   server. Read-only status calls and revocation may continue.
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

Only one `authsia_exec` may run per server in V1. This prevents overlapping
approval prompts and ambiguous output/cancellation attribution without adding a
new scheduler. Separate workspace-scoped MCP server processes remain isolated.

MCP cancellation, timeout, EOF, SIGINT, and SIGTERM cancel the active execution
and wait for its managed wrapper process group. The runner sends `SIGTERM` to
the group, escalates to `SIGKILL` after the bounded grace period, drains the
captured streams, and observes termination before server grant cleanup and
shutdown finish. If the wrapper exits while descendants remain in its group,
the runner applies the same bounded cleanup before returning an otherwise normal
result. Cancellation and timeout are stable tool errors rather than
success merely because a signal was sent. MCP V1 does not use the experimental
Tasks extension. This lifecycle controls the Authsia-created process group; it
does not claim OS-wide containment of a process that independently escapes that
group.

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
| `cliAccessDisabled` | Authsia CLI access is disabled. |
| `approvalDenied` | The user denied or cancelled Authsia approval. |
| `grantUnavailable` | Required grant is absent, expired, revoked, or no longer matches. |
| `grantNotOwned` | Status/revoke target is not owned by this MCP instance. |
| `busy` | This server already has an active execution. |
| `timedOut` | Execution exceeded the requested timeout. |
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
| Client broadens workspace | Root is fixed at startup; canonical containment is checked; no root/cwd tool field exists. |
| Managed file is a symlink escape | Canonicalize and reject sources outside the workspace before reading. |
| Shell or argument injection | Accept a bounded argv array and self-execute without a shell. |
| Ambient server credential or stale authority reaches the child | Construct the child environment from the fixed basic-variable allowlist, add only fresh MCP context, remove internal markers before payload launch, and test the effective environment. |
| Another MCP instance reuses a grant | MCP session ID narrows matching in addition to all existing JIT checks. |
| MCP client views or revokes global access | Status/revoke output is limited to the current server instance; global review stays in Access Center. |
| Secret leaks through tool output | Reuse continuous strict masking, bound both streams, and test raw and transformed synthetic values. |
| Secret leaks through error/audit | Redact errors; store no JSON-RPC payload or output; preserve existing audit redaction and HMAC chain. |
| Concurrent calls confuse approval or attribution | Permit one active exec per server and generate one invocation ID per call. |
| Cancellation leaves execution or descendants running | Put the wrapper and descendants in a dedicated process group, terminate then force-kill the group, and await observed exit before cleanup. |
| Abrupt server death leaves a reusable grant | Instance-narrowed matching prevents reuse; Bridge liveness, TTL, or Access Center revokes the orphan. |
| Client-side auto-approval is mistaken for authority | Authsia approval remains independent and mandatory when no matching grant exists. |
| New MCP protocol feature expands capability | Advertise only the frozen V1 capability set; require explicit spec and security review for additions. |

The model does not claim to sandbox an approved child or stop it from sending a
secret through every possible channel. Existing output masking and activity
evidence reduce accidental leakage and improve investigation; they are not
operating-system-wide DLP.

## Client Configuration

`authsia mcp configure --client <codex|claude|cursor|vscode>` prints a
deterministic local-stdio configuration for the exact installed Authsia binary
and current workspace. V1 does not edit third-party configuration, launch the
client, add credentials, or use a shell wrapper.

Generated configuration must:

- pass `mcp serve` as an argv array;
- set the workspace root through the client's documented working-directory
  mechanism when supported, otherwise print an explicit command to run from
  that root;
- contain no secret, bearer token, automation credential, or private endpoint;
- reject control characters and unsupported clients;
- warn that checked-in client configuration containing a machine-specific
  absolute binary path may not be portable.

The delivered output uses Codex `config.toml`, Claude Code project `.mcp.json`,
Cursor project `.cursor/mcp.json`, and VS Code workspace `.vscode/mcp.json`
shapes verified against each client's primary documentation. Codex and VS Code
receive an explicit working directory. Claude Code and Cursor configuration is
placed under the managed workspace root so the spawned server inherits that
root. Configuration formats remain client-owned compatibility surfaces, not
part of Authsia authorization.

## Compatibility And Upgrade Policy

The implementation baseline is the protocol revision supported by the pinned
Swift SDK. A newer MCP draft, release candidate, Tasks extension, transport, or
client feature is not adopted merely because a client supports it.

Before changing the SDK or protocol revision:

1. review the upstream changelog and protocol security changes;
2. rerun tool-schema, initialization, cancellation, stdout-framing, and client
   compatibility tests;
3. confirm the static five-tool surface did not expand;
4. update this specification before changing behavior.

Pre-1.0 Swift SDK minor releases may contain breaking changes, so the package
dependency remains exact rather than a floating range.

Primary upstream references:

- [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP cancellation](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/cancellation)
- [Official Swift MCP SDK](https://github.com/modelcontextprotocol/swift-sdk)

## Verification Contract

Implementation is not complete until automated tests prove:

- exactly five tools are advertised with the specified closed schemas and
  annotations;
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
