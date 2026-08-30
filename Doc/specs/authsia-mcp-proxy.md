# Local Authsia MCP Proxy

Status: release-candidate implementation contract for M14; signed installed-product
validation pending

This document owns wrapping a local stdio MCP server through Authsia: user
flow, company allowlist shape, workspace `mcpUpstreams`, client launch,
admission, catalog discovery, child lifecycle, and detective scan. The frozen
six-tool Authsia catalog remains in
[`authsia-mcp.md`](authsia-mcp.md). JIT grant matching remains in
[`jit-agent-grants.md`](jit-agent-grants.md). Access Center presentation remains
in the private Access Center spec.

## Table Of Contents

- [Purpose](#purpose)
- [Complementary Lanes](#complementary-lanes)
- [User Flow](#user-flow)
- [Company Local MCP Allowlist](#company-local-mcp-allowlist)
- [Declare The Upstream](#declare-the-upstream)
- [Print And Apply Client Configuration](#print-and-apply-client-configuration)
- [Technical Flow](#technical-flow)
- [Runtime Contract](#runtime-contract)
- [Catalog Listing And Discovery](#catalog-listing-and-discovery)
- [Approval And Grants](#approval-and-grants)
- [Child Lifecycle](#child-lifecycle)
- [Client Configuration Scan](#client-configuration-scan)
- [Access Center](#access-center)
- [Observability](#observability)
- [Errors](#errors)
- [Threat Model](#threat-model)
- [Verification Contract](#verification-contract)

## Purpose

`authsia mcp proxy` is a separate local `stdio` MCP server. It wraps one named
upstream declared by the bound workspace. It does not add tools to
`authsia mcp serve`, change the frozen six-tool Authsia catalog, or make
Authsia an implementation of the upstream service.

There is no client setting that intercepts a server the client already
launches. The client must start Authsia instead of the child command. Authsia
never rewrites third-party MCP configuration. Workspace Setup does not write
`mcpUpstreams`.

Company policy allowlists Authsia. Workspace `mcpUpstreams` names each child.
Admission, redacted call evidence, and revoke-kill apply only on the wrapped
path.

## Complementary Lanes

The company MCP gateway and Authsia are complementary, not a pipeline. A local
stdio server may never traverse the gateway. Authsia MCP V1 does not execute
HTTP, SSE, Streamable HTTP, or URL upstreams.

```text
                     coding client + model
                               |
              selects a configured MCP server entry
                     /                    \
                    /                      \
         local stdio lane              remote service lane
              Authsia                  company MCP gateway
                    |                      |
          authsia mcp proxy            SSO + remote policy
                    |                      |
          local admission or JIT       remote MCP services
                    |
          declared local MCP child
```

Approved wording: preventive for proxy-wrapped local servers, detective for
known direct configuration. Do not claim “all local MCP is blocked,” gateway
parity, executable attestation, or DLP.

## User Flow

```text
  company policy                         user / workspace
  --------------                         ----------------
  allow only:                            1. Enable MCP Integrations
    authsia mcp serve                       (Settings > Developer Access)
    authsia mcp proxy                    2. Declare the child in mcpUpstreams
                                            (Access Center Declare, or edit
                                            .authsia/workspace.json)
                                         3. Point the named client file at
                                            Authsia mcp proxy +
                                            AUTHSIA_MCP_UPSTREAM=<name>
                                         4. Open the managed workspace
                                            (pinned tools list without child;
                                            empty policy requests admission
                                            before discovery)
                                         5. Approve the first operation that
                                            must start the child (discovery or
                                            tools/call)
                                         6. Use the child's tools
                                         7. Revoke in Access Center when done
```

### Preconditions

- An initialized, validated Authsia workspace.
- **MCP Integrations** enabled under Authsia **Settings > Developer Access**.
  The setting is off by default. Configuring a client does not turn it on.
  Enabling it creates no grant and bypasses no Bridge or JIT check.

### Steps

1. Initialize and validate the managed Authsia workspace.
2. Add a `mcpUpstreams` entry, or open Access Center **MCP proxy** and use
   **Declare in workspace** for a wrap-eligible scanned server. Declare writes
   command and argv only; it does not require listing tool names. Keep live
   credentials, private endpoints, and absolute paths out of committed policy.
3. Enable **MCP Integrations**.
4. From that workspace, run `authsia mcp configure --client
   <codex|claude|cursor|devin|vscode>`, or copy the Access Center wrap recipe.
5. Replace the direct launch in the printed user-global client file, or use an
   Access Center recipe to replace the exact scanned user-global or project
   file. Project-scoped Claude, Cursor, and VS Code entries override matching
   user-global entries. Authsia never edits either file.
6. Open the managed workspace. Pinned policy lists without starting the child.
   Empty-policy discovery requests local MCP admission before starting its
   short-lived child. A permitted call also requires admission before the
   long-lived child starts; an existing matching grant is reused.

Access Center **Copy wrap recipe** pastes a client-native replacement for the
scanned file. After Declare, that copy is only the client-launch replacement,
not a second `mcpUpstreams` paste.

## Company Local MCP Allowlist

Company policy allowlists Authsia, not each local tool. Child names belong in
workspace `mcpUpstreams` and are admitted through Authsia. Claude Code
`allowedMcpServers` `serverCommand` matches the exact client argv, so Authsia
does not put `--upstream <name>` in that argv.

A Claude Code managed `serverCommand` allowlist is two entries: the installed
Authsia binary with `mcp serve`, and the same binary with `mcp proxy`. Users
may add further client entries that share that proxy argv. Do not list
Playwright, Codegraph, or other child names in the company file.

```text
  company Claude policy          workspace.json              Authsia runtime
  ---------------------          --------------              ---------------
  [authsia, mcp, serve]          name: filesystem            bind workspace
  [authsia, mcp, proxy]          command + args              admit / exec JIT
                                 env: {} or authsia://       spawn no-shell child
                                 optional allow/deny         revoke-kill
```

Do not enable Claude Code `allowManagedMcpServersOnly` (exclusive managed
catalog) if users should adopt new local tools through Authsia. That mode
blocks user-added servers even when the argv matches. Remote HTTP/SSE company
gateways remain a separate lane; they do not see this local stdio path.

`--upstream` remains valid for terminal launches and for existing client files.
Generated client configuration uses a stable `mcp proxy` argv plus
`AUTHSIA_MCP_UPSTREAM`.

## Declare The Upstream

Add one named entry to the optional `mcpUpstreams` array in
`.authsia/workspace.json`. That array is the admission allowlist. Access Center
**Declare in workspace** appends a wrap-eligible scanned stdio server to the
selected managed workspaces after confirmation; Workspace Setup still does not
write `mcpUpstreams`.

- `name` must be unique and match `[A-Za-z][A-Za-z0-9_-]{0,31}`.
- `command` is a PATH basename or workspace-relative executable, plus a
  bounded argv array. Absolute paths and shell-shaped commands are rejected.
- Sensitive `env` values must be `authsia://` password, API-key, certificate,
  or secure-note references. OTP and SSH references are not injectable. A
  credential-less server uses an empty `env` object and is still an admission
  allowlist entry.
- Disjoint `allow`, `approve`, and `deny` tool-name lists plus optional
  non-secret catalog schemas pin the client-visible tools when present. When
  `allow` or `approve` is set, `tools/list` comes from this policy without
  starting the child. When both are omitted on a credential-less stdio entry,
  Authsia discovers the child's tool names and sanitized schemas on first
  `tools/list` with a short-lived probe only after local `mcp-admission`. The
  cache holds what the child advertised; `deny` is read from workspace policy
  and subtracted on every list and call, so a `deny` added while a client is
  connected applies without restarting the proxy. Automatic discovery requires the entire declared `env` to
  be empty; literal values as well as `authsia://` references disable it. The
  long-lived child also requires admission before the first permitted
  `tools/call`, reusing a matching grant. Any non-empty env requires explicit
  `allow`/`approve`.
- Do not store live credentials, tokens, private endpoints, or
  machine-specific paths. HTTP, SSE, Streamable HTTP, and `url` entries decode
  for forward compatibility but are not executable in V1.

Credential-less example with pinned tools (no secret bytes):

```json
{
  "mcpUpstreams": [
    {
      "name": "filesystem",
      "command": "mcp-filesystem",
      "env": {},
      "tools": {
        "allow": ["read_file", "list_directory"]
      }
    }
  ]
}
```

Credential-less example that lets Authsia discover the child catalog:

```json
{
  "mcpUpstreams": [
    {
      "name": "codegraph",
      "command": "codegraph",
      "args": ["serve", "--mcp"],
      "env": {}
    }
  ]
}
```

## Print And Apply Client Configuration

From the managed workspace, run:

```text
authsia mcp configure --client <codex|claude|cursor|devin|vscode>
```

Configure always prints the `authsia mcp serve` entry. With declared
upstreams it also prints one `authsia mcp proxy` entry per name, with
`AUTHSIA_MCP_UPSTREAM` set to that name, no repository path, and no resolved
secret references. Codex, Claude Code, and VS Code receive a direct
installation command plus a manual fallback. Cursor and Devin Desktop receive
only the manual user-global configuration.

Apply the printed **proxy** form so the client launches the installed Authsia
binary with argv `mcp proxy` and `AUTHSIA_MCP_UPSTREAM=<name>`. A remaining
direct command/argv entry bypasses admission, redacted call evidence, and
revoke-kill.

The printed form is a user-global fallback derived from the currently bound
workspace. It is effective only when that workspace declares the named
upstream and no project-scoped entry overrides it. For Claude, Cursor, and VS
Code, inspect and replace a matching project entry as well; Access Center copy
recipes target the exact scanned scope and never emit a user-global install
command for a project file.

```text
  ~/.claude.json  (user-global; same argv for every local tool)

    "authsia":      authsia  mcp serve
    "filesystem":   authsia  mcp proxy     env AUTHSIA_MCP_UPSTREAM=filesystem
    "codegraph":    authsia  mcp proxy     env AUTHSIA_MCP_UPSTREAM=codegraph
```

Generated configuration must:

- pass each declared proxy as argv `mcp proxy` plus `AUTHSIA_MCP_UPSTREAM`
  without a fixed repository path;
- omit `--upstream` from generated client argv so company command allowlists
  can match one proxy launch;
- omit fixed repository paths so one user-global entry works across managed
  workspaces;
- contain no secret, bearer token, automation credential, or private endpoint;
- reject control characters and unsupported clients;
- warn that the user-global configuration contains a machine-specific absolute
  binary path and must not be committed or shared.

The delivered output uses user-global Codex `~/.codex/config.toml`, Claude Code
`~/.claude.json`, Cursor `~/.cursor/mcp.json`, Devin Desktop
`~/.config/devin/mcp_config.json`, and the VS Code user-profile `mcp.json`
shapes. Configuration formats remain client-owned compatibility surfaces, not
part of Authsia authorization. V1 does not edit third-party configuration,
launch the client, add credentials, or use a shell wrapper.

## Technical Flow

```text
  coding client
       |
       |  launches this MCP server entry
       v
  +----------------------+     NO      +---------------------------+
  | argv is authsia      |-----------> | direct child              |
  | mcp proxy ?          |             | Authsia never sees calls  |
  +----------------------+             | no admission, no revoke   |
       | YES                           +---------------------------+
       v
  authsia mcp proxy
  name from AUTHSIA_MCP_UPSTREAM or --upstream
  bind workspace (explicit --workspace /
    workspaceRoot / WORKSPACE_FOLDER_PATHS / cwd)
       |
       v
  .authsia/workspace.json  mcpUpstreams[<name>]
       |
       +-- missing / HTTP / secrets without allow|approve
       |     -> fail closed, no child
       |
       +-- credential-less stdio  -----> mcp-admission before first
                                         discovery or permitted tools/call
                                         (local Mac)
       |
       +-- authsia:// env  ------------> Agent JIT exec
                                         (Mac or paired iPhone)
```

The proxy starts and initializes even when it is unbound, the named upstream
is absent, or its transport is unsupported. Workspace-dependent work then fails
closed with a stable error. Binding matches `mcp serve`: optional `--workspace`
is authoritative; otherwise one safe `WORKSPACE_FOLDER_PATHS` hint and then the
process working directory.

## Runtime Contract

The name comes from `--upstream` or from `AUTHSIA_MCP_UPSTREAM`. If both are
set they must name the same upstream. Names match
`[A-Za-z][A-Za-z0-9_-]{0,31}`. The named upstream is resolved after workspace
bind, not as a process-exit condition.

The proxy does not expose the serve-only `authsia_access_status` or
`authsia_access_revoke` tools.

Unknown and denied calls fail before JIT or the long-lived spawn. Extra child
tools never become visible when `allow` or `approve` is set. Empty-policy
credential-less discovery is the only path that advertises extra child tools
(minus `deny`). A policy-advertised or discovered tool missing from the child
fails closed.

Overlapping forwarded `tools/call` requests are multiplexed against one child.
At most eight calls may be in flight at once; a ninth is rejected with `busy`
rather than queued. Each forwarded call is also bounded by the proxy-side
deadline documented under Errors.

## Catalog Listing And Discovery

```text
  tools/list
       |
       +-- allow or approve set?
       |     YES: answer from workspace.json (never start child)
       |
       +-- empty policy, credential-less stdio?
             YES: request mcp-admission; if granted, short-lived
                  probe spawn, listTools, kill, reap, cache child
                  names; subtract deny on every read
             declined admission: cache empty for this proxy session
             transient probe failure: cache nothing; later list retries
```

Discovery starts a short-lived declared child so the client can see tool names
when the workspace opens. Because the executable comes from repository policy,
the probe takes `mcp-admission` before resolution or spawn. The long-lived spawn
also requires that grant on the first permitted `tools/call`; the Bridge can
reuse a matching grant. Concurrent list or call joins an in-flight probe
instead of publishing an empty catalog.

Any non-empty declared env, whether literal or `authsia://`, disables automatic
catalog discovery. Listing must not resolve or forward environment values.
Those upstreams require explicit `allow`/`approve`.

## Approval And Grants

No upstream child starts until an approval covers it. Empty-policy `tools/list`
requests local admission before a short-lived discovery probe; a permitted
`tools/call` requires the same authority before the long-lived child starts.
The discovery probe is killed after `listTools`.

- Declared `authsia://` references use the existing Agent JIT `exec` path.
  Approval may be local Mac or paired iPhone.
- No references request a local-Mac `mcp-admission` grant with no Vault items,
  and no `list` or `exec` authority. Admission is not on paired-iPhone remote
  approval v2.
- Both approvals name the declared child argv, not only the upstream name. The
  upstream name is committed repository content; the argv is what the approval
  actually starts.
- A denied or missing admission grant prevents both discovery and the
  long-lived spawn. A declined discovery caches an empty catalog for that proxy
  session so the client does not re-prompt on every `tools/list`.

```text
  client          proxy                         Bridge / Access Center
    |               |                                  |
    | initialize    |  (child not started)             |
    | tools/list    |                                  |
    |-------------->|  policy catalog, or admission    |
    |               |  then credential-less probe      |
    | tools/call    |                                  |
    |-------------->|  reuse/admit / exec JIT          |
    |               |--------------------------------->|
    |               |              Mac prompt:         |
    |               |              MCP tool, upstream, |
    |               |              child argv          |
    |               |<----- grant / decline -----------|
    |               |  long-lived child, forward call  |
    |               |  redact tool name to activity    |
    | Access Center revoke ----------------------------|
    |               |  kill process group (up to 5s)   |
```

Decline prevents the long-lived spawn. An approved grant is reusable only by that caller,
workspace, upstream, and MCP server instance. A preflight that authorizes the
call without issuing an owned grant returns `grantUnavailable` before any
reference is resolved and before the child starts, because a child that no
revocation can reach must not hold secrets or stay live.

## Child Lifecycle

After startup, calls may overlap through the single child. Known injected
secret values of at least four UTF-8 bytes are concealed only inside JSON
string values in both forwarded arguments and returned results. JSON keys,
numbers, booleans, nulls, and structure are unchanged. Raw JSON-RPC frames are
never written to audit or activity records. The child's standard error is
relayed to the proxy's own standard error under the same concealment and a
bounded volume.

The child environment is a stripped allowlist plus declared literals and
freshly resolved refs. The allowlist includes basic process variables and the
non-secret TLS trust settings `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, and
`SSL_CERT_FILE`. `AUTHSIA_AGENT_*`, automation authority, and
`AUTHSIA_MCP_UPSTREAM` are omitted from the child.

The child is associated in memory with the exact Bridge grant IDs that
authorized its environment. The proxy checks those grants on every call and
while the child is live. Revocation kills the upstream process group and drops
the client, secrets, and grant association; the periodic check may take up to
five seconds after the Bridge snapshot first reports no active associated
grant. Graceful proxy shutdown performs the same child cleanup and revokes
active grants owned by that proxy instance. A later call starts a fresh JIT
session when required.

Before forwarding each permitted `tools/call`, Authsia records one redacted
Agent command event containing only the proxy source, grant ID,
workspace/runtime correlation, and MCP tool name. If that record cannot be
persisted, the call fails before it reaches the upstream.

## Client Configuration Scan

After printing configuration for a managed workspace, `mcp configure` also
performs a best-effort read-only scan of the known user-global client paths:
Codex `~/.codex/config.toml`, Claude `~/.claude.json`, Cursor
`~/.cursor/mcp.json`, Devin `~/.config/devin/mcp_config.json`, and VS Code's
user `mcp.json`. It also scans the bound workspace root for the project-scoped
files that outrank those: Claude `.mcp.json`, Cursor `.cursor/mcp.json`, and
VS Code `.vscode/mcp.json`. Codex and Devin have no project scope. Project
scanning stays inside managed workspace roots and opens no new discovery
surface. It reads server name, command, argv, and the
`AUTHSIA_MCP_UPSTREAM` name only; other environment values and raw protocol
frames are neither retained nor reported. Every finding names its config scope,
workspace context, exact path, and precedence:

| Precedence | Meaning |
| --- | --- |
| effective | This is the entry the client resolves for the named workspace. |
| overridden | A project-scoped entry with the same client/server name wins for this workspace. |
| conditional | A user-global fallback is visible, but no managed workspace is selected to evaluate its declaration or project override. |

Admission matching is workspace-local. A declaration from repository A never
makes the same server name in repository B appear admitted. User-global entries
are evaluated once per known workspace; project entries are evaluated only
against their owning root. Findings are:

| Scan result | Meaning |
| --- | --- |
| wrapped | The client launches `authsia mcp proxy` for an upstream declared by that finding's workspace (via `AUTHSIA_MCP_UPSTREAM` or a legacy `--upstream` argv). This is declared, not pre-approved; admission is still required before discovery or a first call. |
| direct bypass | The declared command/argv exists, but the client launches it directly. |
| unadmitted | No known workspace declaration matches the observed launch. |

Malformed, missing, or oversized config files are skipped. The scanner never
edits client configuration. A direct or unadmitted entry is visibility only:
Authsia cannot audit those calls, kill them on revoke, or prevent launch. An
empty or partial allowlist therefore fails open and can only affect the
displayed finding. Command/argv matching is an identity hint, not executable
attestation; pin a local binary instead of a drifting package launcher when
stronger identity matters.

## Access Center

Access Center remains the operator surface for proxy grants. It labels them as
`<client> via Authsia MCP proxy <upstream>`, derives its timeline from existing
grant and activity records without retaining raw frames, and revokes through
the existing Bridge-owned control. A long-lived proxy observes the revoked
snapshot and terminates its child process group; Access Center does not signal
the child directly.

The **MCP proxy** filter lists admission and `proxy:<upstream>` grants first.
Scan findings sit in a collapsed coverage strip grouped by wrap status, not
workspace path. The Agent grants Workspace menu filters every source tab; it
lists **~** for grants with no workspace, the same pinned and recent local
workspaces Workspace Center shows that still exist on this Mac, and existing
roots of active proxy grants. It omits
historical grant paths even when the folder is still on disk. Project config
scans use the same roots so a newly used workspace is visible before it is
added to Workspace Center. The strip includes wrap-eligible Direct
launch and Not wrapped rows,
wrapped entries with no live grant, and valid Authsia proxy entries even when
their upstream is not declared in that workspace. It hides absolute commands,
shell wrappers, and an Authsia proxy launch with no valid upstream name.
Presentation rules live in the Access Center spec; this document owns the wrap,
admission, and revoke-kill contract those rows display.

## Observability

The proxy can see wrapped `tools/call` traffic at runtime. Persistence is a
redacted Agent command event only: proxy source, optional grant ID,
workspace/runtime correlation, MCP tool name, and a bounded outcome. An
admitted call is written as `started` before forwarding, then an appended event
with the same invocation merge key records `succeeded`, `mcpError`,
`timedOut`, `cancelled`, or `upstreamUnavailable`. Policy and lifecycle
failures that occur before a grant exists are recorded as `denied`, `busy`, or
`upstreamUnavailable` without a grant when the proxy can persist them. If the
record cannot be saved, the call still fails closed and its error omits the
invocation identifier. Raw JSON-RPC, tool arguments, results, and child stderr
are never written to audit or activity stores.

An error envelope carries the invocation UUID only after the redacted decision
event has been saved. The matching audit row's `turnID` (and `toolUseID`) is
`mcp-call:` followed by that UUID when a Bridge authorization row exists. A
pre-admission decision may have no matching audit row, but remains visible as
an unowned proxy decision in Access Center.

Review that event on the owning grant in Access Center: **MCP proxy** filter →
grant → **Activity** → Timeline or Commands. Timeline titles a wrapped call
**MCP tool called** and shows the child basename, tool name, and redacted
outcome. Decisions without a grant appear as recent unowned proxy decisions.
Direct client launches outside the proxy produce no call events.

`tools/list`, including the admitted credential-less discovery probe, is not
per-tool command activity. File, network, and Process Tree tabs remain the
existing Authsia-mediated exec stores; they are not a transcript of a generic
MCP child. Access Center labels those three surfaces as unavailable for a
generic proxy grant instead of presenting an empty result as proof of no
activity. Child liveness is not persisted as a separate status; the grant
state and last redacted proxy decision are the available status signals.

Operator guidance:

1. Wrap every local stdio server that should be auditable. Visibility and
   revoke-kill exist only when the client starts `authsia mcp proxy` with
   `AUTHSIA_MCP_UPSTREAM`. On **MCP proxy**, review grants first; wrap remaining
   Direct launch and Not wrapped rows from Coverage.
2. Review by grant. Expect *which tool ran*, not *what it was asked*.
3. Treat the client-config scan as detective. A direct entry is a finding, not
   a block, and is not a call log.
4. Keep remote HTTP, SSE, Streamable HTTP, and URL MCP on the company gateway.
   This local ladder does not replace gateway audit.
5. Do not persist proxied JSON. Argument or result logging would become a
   secret and PII store. A child that needs richer traces uses its own redacted
   logs.

Approved wording remains: preventive for proxy-wrapped local servers, detective
for known direct configuration. Do not claim “all local MCP is logged.”

## Errors

Proxy calls use the same structured MCP tool-error envelope as serve. Codes
specific to wrapping:

| Code | Meaning |
| --- | --- |
| `grantUnavailable` | Required grant is absent, expired, revoked, or no longer matches. Also returned when a preflight authorizes the call without issuing an owned grant, since the child would then be unrevokable. |
| `upstreamDenied` | The requested upstream tool is unknown, denied, or absent from the advertised workspace policy. |
| `upstreamUnavailable` | The named upstream is missing, cannot start or initialize, or does not implement the advertised tool. |
| `httpUpstreamUnsupported` | The workspace declares an HTTP, SSE, Streamable HTTP, or URL upstream, which V1 cannot execute. |
| `timedOut` | The child did not answer a forwarded `tools/call` before the proxy's call deadline. The proxy cancels the request upstream and leaves the child running for the next call. |
| `busy` | Too many forwarded `tools/call` requests are already in flight for this upstream. The proxy rejects rather than queues. |

Shared codes such as `mcpAccessDisabled`, `approvalDenied`, and
`workspaceUnavailable` keep the meanings in [`authsia-mcp.md`](authsia-mcp.md#errors-and-output).

## Threat Model

| Threat | Required control |
| --- | --- |
| Proxy policy is mistaken for live upstream authority | Derive `tools/list` from commit-safe policy when `allow` or `approve` is set. When both are empty and `env` is empty on a credential-less stdio upstream, take admission before a bounded listing probe, then reject deny and unknown tools before the long-lived spawn, and privately verify advertised names after child initialization. |
| Empty-policy `tools/list` starts repository code before approval | Require `mcp-admission` before resolving or spawning the declared child. Allow automatic discovery only when declared `env` is entirely empty, and kill the probe after `listTools`. |
| One workspace declaration makes another workspace look admitted | Match declarations by standardized workspace root, report the workspace on every finding, and evaluate user-global fallbacks separately for each root. |
| Project config silently overrides a protected user-global entry | Report both entries with user-global/project scope and effective/overridden precedence; generate project wrap recipes for the exact project file without user-global CLI commands. |
| Upstream receives ambient credentials or Authsia runtime markers | Build a stripped environment, add only declared literals and freshly resolved refs, and omit `AUTHSIA_AGENT_*` and automation authority from the child. |
| Injected values leak through proxied JSON-RPC | Parse and mask JSON string values in both directions; never patch raw frames or store them in audit or diagnostics. |
| Revocation leaves a long-lived upstream authorized | Associate the child with exact owned grant IDs, recheck on every call and periodically, and terminate the complete process group when association fails. |
| A `deny` added mid-session keeps answering from a stale catalog | Cache only what the child advertised and subtract `deny` from live workspace policy on every list and call. |
| A wedged child holds the caller until its grant expires | Bound every forwarded `tools/call` with a proxy-side deadline, cancel the request upstream on expiry, and return `timedOut`. |
| A terminated child cannot be observed dying | Reap every child the proxy starts, including the discovery probe. An unreaped process group still answers `kill(-pgid, 0)`, so termination would wait out the whole grace and force window. |
| Company policy must enumerate every local tool | Generated client argv is `mcp proxy`; the name is `AUTHSIA_MCP_UPSTREAM`. Workspace `mcpUpstreams` is the child allowlist. |
| Approved upstream, package launcher, or unmanaged sibling MCP exfiltrates data | Treat the upstream and MCP client as untrusted; Authsia does not sandbox an approved child, police sibling client configuration, or provide OS-wide DLP. |
| Read-only config detection is mistaken for launch enforcement | Label direct launches as existence-only findings; never claim call audit, revoke-kill, or blocking outside the proxy. |

The model does not claim to sandbox an approved child or stop it from sending a
secret through every possible channel. Existing output masking and activity
evidence reduce accidental leakage and improve investigation; they are not
operating-system-wide DLP.

## Verification Contract

Implementation is not complete until automated tests prove:

- proxy catalog listing with `allow` or `approve` does not JIT or spawn;
- empty-policy credential-less `tools/list` takes `mcp-admission` before the
  probe, and any non-empty declared env disables automatic discovery;
- a declined discovery admission starts no child, caches empty for the proxy
  session, and does not re-prompt `tools/list`; a transient probe failure is
  not cached;
- denied tools fail before JIT, and missing/unbound/HTTP declarations return
  their stable errors;
- a permitted proxy call starts one no-shell child with only declared
  environment, masks JSON string values in both directions, and rejects live
  catalog drift without exposing extra child tools when policy pins the catalog;
- both admission and exec prompts carry the declared child argv;
- client scan findings preserve user-global/project scope, resolve project
  precedence per workspace, and never reuse another workspace's declaration;
- a `deny` added after discovery is subtracted from the next `tools/list` and
  rejects the next `tools/call`, without a second probe;
- the discovery probe child is reaped, so nothing is left waiting after
  `tools/list` returns;
- a forwarded `tools/call` that outruns the call deadline returns `timedOut`
  and leaves the child usable for the next call;
- a ninth overlapping forwarded call is rejected with `busy` while eight are
  in flight, and the counter drains so a later call succeeds;
- an error after audit persistence carries the UUID prefix of the recorded
  audit `turnID`, while an audit-write failure omits `invocationID`;
- persisted proxy decisions merge one redacted `started` row with a terminal
  outcome when forwarding begins, while pre-admission decisions remain
  visible without a grant;
- Access Center revocation removes the associated child process group within
  the documented polling window, while restart cannot reuse the old instance's
  grant;
- client configuration remains byte-stable without upstream declarations and
  prints one client-native `mcp proxy` block plus `AUTHSIA_MCP_UPSTREAM` per
  declared upstream when present, with no `--upstream` in generated argv;
- the scanner reports wrapped, direct bypass, and unadmitted without retaining
  other environment values;
- Access Center presents a wrapped `tools/call` as the child basename plus MCP
  tool name, and does not persist arguments, results, or JSON-RPC.

Installed-product validation must exercise at least Codex, Claude Code, Cursor,
and VS Code from a real managed workspace before M14 is marked delivered.

Related: [`authsia-mcp.md`](authsia-mcp.md) (serve catalog),
[`jit-agent-grants.md`](jit-agent-grants.md) (grant matching),
[`security-model.md`](security-model.md).
