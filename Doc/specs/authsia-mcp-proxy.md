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
launches. The client must start Authsia instead of the child command. Access
Center **Wrap** / **Write wrap** and `authsia mcp wrap --write` may replace a
scanned client launch after confirmation and a checksum check. Authsia never
silent-rewrites. `mcp configure` still prints only. Workspace Setup does not
write `mcpUpstreams`.

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
  allow only:                            1. Init workspace
    authsia mcp serve                    2. Enable MCP Integrations
    authsia mcp proxy                       (Settings deep-links to Coverage;
                                            Coverage can turn it on)
                                         3. Choose Protect server on the
                                            winning (usually project) file
                                         4. Approve first discovery or call;
                                            active grant verifies protection
```

### Preconditions

- An initialized, validated Authsia workspace.
- **MCP Integrations** enabled under Authsia **Settings > Developer Access**.
  The setting is off by default. Configuring a client does not turn it on.
  The Settings toggle opens Coverage; Coverage can turn it on. Enabling it
  creates no grant and bypasses no Bridge or JIT check.

### Steps

1. Initialize and validate the managed Authsia workspace.
2. Enable **MCP Integrations**. Settings → Developer Access deep-links to
   Access Center Coverage; Coverage can turn the setting on.
3. On Access Center **MCP proxy** Protection coverage, choose **Protect
   server** on the winning (usually project) file. Authsia declares command
   and argv in `mcpUpstreams` when needed and, after showing the current entry,
   protected entry, and a SHA256 checksum, writes the scanned client file.
   Absolute Homebrew or system paths store a PATH
   basename; committed `workspace.json` still forbids absolute paths. Keep live
   credentials and private endpoints out of committed policy. Project-scoped
   Claude, Cursor, and VS Code entries override matching user-global entries;
   an overridden write is refused. Authsia never rewrites a client file
   silently.
4. Run `authsia mcp catalog --server <name> --write` once. It approves local
   MCP admission, starts the declared child long enough to read its tool list,
   stops it, and records the names and sanitized schemas in `mcpUpstreams`.
5. Open the managed workspace. Opening it starts nothing and asks nothing:
   `tools/list` is answered from committed policy. The first `tools/call`
   requests local MCP admission before the long-lived child starts; an existing
   matching grant is reused. Revoke in Access Center when done.

**Copy manual recipe**, `authsia mcp configure`, and `authsia mcp wrap --write
--server <name> --yes` are fallbacks, not required steps. A client that already
launches `mcp proxy` without a matching `mcpUpstreams` entry still needs
workspace policy; Authsia cannot infer child argv from a proxy launch.

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

Enable Claude Code `allowManagedMcpServersOnly` with the two Authsia
`serverCommand` entries when the company requires an Authsia-only local MCP
launch policy. This setting restricts user additions to matching approved
argv; it is distinct from deploying exclusive `managed-mcp.json`, which would
freeze the server-name catalog and block self-service protection of new local
tools. Remote HTTP/SSE company gateways remain a separate lane; they do not
see this local stdio path.

`--upstream` remains valid for terminal launches and for existing client files.
Generated client configuration uses a stable `mcp proxy` argv plus
`AUTHSIA_MCP_UPSTREAM`.

## Declare The Upstream

Add one named entry to the optional `mcpUpstreams` array in
`.authsia/workspace.json`. That array is the admission allowlist. Access Center
**Wrap** is the operator action for a wrap-eligible scanned stdio server: it
declares command and argv and writes the scanned client launch after
confirmation. **Declare in workspace** remains for a missing declaration when
the client already launches `mcp proxy` and Wrap cannot infer child argv.
Workspace Setup still does not write `mcpUpstreams`.

- `name` must be unique and match `[A-Za-z][A-Za-z0-9_-]{0,31}`.
- `command` is a PATH basename or workspace-relative executable, plus a
  bounded argv array. Absolute paths and shell-shaped commands are rejected.
- Sensitive `env` values must be `authsia://` password, API-key, certificate,
  or secure-note references. OTP and SSH references are not injectable. A
  credential-less server uses an empty `env` object and is still an admission
  allowlist entry.
- Disjoint `allow`, `approve`, and `deny` tool-name lists plus optional
  non-secret catalog schemas pin the client-visible tools. `tools/list` always
  comes from this policy and never starts the child, so connecting a client to
  a managed workspace raises no approval prompt. An entry with no `allow` or
  `approve` advertises nothing; `authsia mcp catalog --server <name> --write`
  records what the child offers, and the proxy names that command on stderr
  when a client lists an unrecorded upstream. `deny` is read from workspace
  policy and subtracted on every list and call, so a `deny` added while a
  client is connected applies without restarting the proxy. Catalog capture
  requires the entire declared `env` to be empty; literal values as well as
  `authsia://` references disable it, and those upstreams list their tools by
  hand. The long-lived child requires admission before the first permitted
  `tools/call`, reusing a matching grant. An unrecorded credential-less
  upstream still discovers its catalog on that first call, so a tool the client
  already knows works without a prior capture.
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

The write path is Access Center **Wrap** / **Write wrap**, or `authsia mcp wrap
--write --server <name>` (prints a plan; `--yes` writes). `mcp configure`
stays print-only.

From the managed workspace, the fallback print is:

```text
authsia mcp configure --client <codex|claude|cursor|devin|vscode>
```

Configure always prints the `authsia mcp serve` entry. With declared
upstreams it also prints one `authsia mcp proxy` entry per name, with
`AUTHSIA_MCP_UPSTREAM` set to that name, no repository path, and no resolved
secret references. Codex, Claude Code, and VS Code receive a direct
installation command plus a manual fallback. Cursor and Devin Desktop receive
only the manual user-global configuration.

Wrap writes that **proxy** form so the client launches the installed Authsia
binary with argv `mcp proxy` and `AUTHSIA_MCP_UPSTREAM=<name>`. A remaining
direct command/argv entry bypasses admission, redacted call evidence, and
revoke-kill.

The printed form is a user-global fallback derived from the currently bound
workspace. It is effective only when that workspace declares the named
upstream and no project-scoped entry overrides it. For Claude, Cursor, and VS
Code, prefer Wrap on the matching project file. Access Center copy
recipes remain a fallback and target the exact scanned scope; they never emit a
user-global install command for a project file.

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
part of Authsia authorization. `mcp configure` still prints only. Confirmed
**Write wrap** / `authsia mcp wrap --write` may replace a scanned server entry
after a checksum check; Authsia does not silent-rewrite, launch the client,
add credentials, or use a shell wrapper.

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
       +-- credential-less stdio  -----> mcp-admission before the first
                                         permitted tools/call, or before a
                                         catalog capture (local Mac)
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
  tools/list                            authsia mcp catalog --server <name>
       |                                     |
       +-- answer from workspace.json        +-- credential-less stdio?
           (never start the child,                 YES: request mcp-admission;
            never request admission)                    if granted, short-lived
       |                                                 probe spawn, listTools,
       +-- nothing recorded?                              kill, reap
             name the capture command                +-- --write: record names
             on stderr, advertise nothing                 and sanitized schemas
                                                          in mcpUpstreams

  tools/call on an unrecorded credential-less upstream
       +-- same admission-gated probe, cached for this proxy session
           declined admission: cache empty; transient failure: cache nothing
```

Listing is answered from committed policy, so opening a workspace starts no
repository code and asks the human for nothing. Recording the catalog is a
separate, human-initiated step: `authsia mcp catalog` takes `mcp-admission`
before it resolves or spawns the declared child, reads `tools/list` once, kills
and reaps the probe, and drops its grant so the next client call still prompts.

The first permitted `tools/call` requires the same grant before the long-lived
child starts; the Bridge can reuse a matching one. On an upstream with no
recorded catalog, that call falls back to the same bounded probe, and a
concurrent call joins the in-flight probe instead of reading an empty catalog.

Any non-empty declared env, whether literal or `authsia://`, disables catalog
capture and the call-path probe. Listing must not resolve or forward
environment values. Those upstreams require explicit `allow`/`approve`.

## Approval And Grants

No upstream child starts until an approval covers it. `tools/list` starts no
child at all. `authsia mcp catalog` and a permitted `tools/call` both request
local admission before the declared child starts. The discovery probe is killed
after `listTools`.

- Declared `authsia://` references use the existing Agent JIT `exec` path.
  Approval may be local Mac or paired iPhone.
- No references request a local-Mac `mcp-admission` grant with no Vault items,
  and no `list` or `exec` authority. Admission is not on paired-iPhone remote
  approval v2.
- Both approvals name the declared child argv, not only the upstream name. The
  upstream name is committed repository content; the argv is what the approval
  actually starts.
- A denied or missing admission grant prevents both capture and the long-lived
  spawn. A declined call-path discovery caches an empty catalog for that proxy
  session so a retrying agent does not re-prompt.
- Local `mcp-admission` grants use the dedicated `mcpAdmissionTTL` preference,
  default 30 minutes, instead of the 15-second CLI session default. The
  `mcpAdmissionMaximumTTL` managed preference can lower the company maximum;
  the product ceiling remains 24 hours. Expiry is absolute and does not slide
  when tools are used.
- On expiry or revocation, the proxy observes the inactive grant within its
  polling interval and terminates the child process group. A later tool call
  requests a fresh admission. Access Center shows a live remaining-time label;
  **Renew admission** extends that grant in place from Access Center, keeping
  the same grant ID so the watching child survives and the countdown restarts.
  Renewal is restricted to Authsia.app: the MCP server may revoke its own
  grant, but may not extend it. Only an active `mcp-admission` grant renews --
  an exec grant names the vault items it opened, and an admission that already
  ended starts again from a client-originated approval.

```text
  client          proxy                         Bridge / Access Center
    |               |                                  |
    | initialize    |  (child not started)             |
    | tools/list    |                                  |
    |-------------->|  policy catalog, no child        |
    |               |  (recorded by mcp catalog)       |
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
edits client configuration. Confirmed **Wrap** / **Write wrap** may replace a
scanned launch after a checksum check; that write is not the scan. A direct or
unadmitted entry is visibility only until wrapped: Authsia cannot audit those
calls, kill them on revoke, or prevent launch. An empty or partial allowlist
therefore fails open and can only affect the displayed finding. Command/argv
matching is an identity hint, not executable attestation; pin a local binary
instead of a drifting package launcher when stronger identity matters.

## Access Center

Access Center remains the operator surface for proxy grants. It labels them as
`<client> via Authsia MCP proxy <upstream>`, derives its timeline from existing
grant and activity records without retaining raw frames, and revokes through
the existing Bridge-owned control. A long-lived proxy observes the revoked
snapshot and terminates its child process group; Access Center does not signal
the child directly.

The **MCP proxy** filter lists admission and `proxy:<upstream>` grants first.
Active admission rows show **Access expires in** with a live countdown and an
explicit **Renew admission** action. Renewal extends that grant in place: the
same grant ID, a fresh expiry, and a wrapped server that keeps running. Only
Authsia.app may renew, and only an active admission.
Scan findings sit in a protection-coverage strip grouped by effective status,
not workspace path. Coverage stays expanded while actionable rows exist.
**Protect server** declares and/or writes as required by that row. It requires
confirmation for client writes and refuses an overridden user-global row. The
strip shows protected known launches over total effective known launches, plus
the next onboarding step. The Agent grants Workspace menu filters every source tab; it
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
| Proxy policy is mistaken for live upstream authority | Derive `tools/list` from commit-safe policy only, then reject deny and unknown tools before the long-lived spawn, and privately verify advertised names after child initialization. |
| Opening a workspace starts repository code, or trains the human to approve prompts they did not cause | Answer `tools/list` from committed policy without starting the child or requesting admission. Record the catalog in a separate human-initiated `authsia mcp catalog` run, and raise the admission prompt on the first `tools/call`. |
| A catalog probe starts repository code before approval | Require `mcp-admission` before resolving or spawning the declared child, for capture and for the call-path fallback alike. Allow either only when declared `env` is entirely empty, and kill the probe after `listTools`. |
| One workspace declaration makes another workspace look admitted | Match declarations by standardized workspace root, report the workspace on every finding, and evaluate user-global fallbacks separately for each root. |
| Project config silently overrides a protected user-global entry | Report both entries with user-global/project scope and effective/overridden precedence; generate project wrap recipes for the exact project file without user-global CLI commands. |
| Upstream receives ambient credentials or Authsia runtime markers | Build a stripped environment, add only declared literals and freshly resolved refs, and omit `AUTHSIA_AGENT_*` and automation authority from the child. |
| Injected values leak through proxied JSON-RPC | Parse and mask JSON string values in both directions; never patch raw frames or store them in audit or diagnostics. |
| Revocation leaves a long-lived upstream authorized | Associate the child with exact owned grant IDs, recheck on every call and periodically, and terminate the complete process group when association fails. |
| A short shared CLI timeout makes MCP unusable, or activity silently extends authority | Give MCP admission an independent 30-minute default with a managed maximum, keep expiry absolute, and show remaining time. Extending it is an explicit human action in Access Center, never an effect of the agent using the tool; the MCP server itself may revoke but not renew. |
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

- `tools/list` never JITs or spawns, whatever the policy holds;
- catalog capture takes `mcp-admission` before the probe, records the advertised
  names and sanitized schemas in `mcpUpstreams`, keeps an existing `deny` and
  `approve` placement, and refuses an upstream with any declared env;
- the first `tools/call` on an unrecorded credential-less upstream takes
  `mcp-admission` before the probe;
- a declined discovery admission starts no child, caches empty for the proxy
  session, and does not re-prompt; a transient probe failure is not cached;
- denied tools fail before JIT, and missing/unbound/HTTP declarations return
  their stable errors;
- a permitted proxy call starts one no-shell child with only declared
  environment, masks JSON string values in both directions, and rejects live
  catalog drift without exposing extra child tools when policy pins the catalog;
- both admission and exec prompts carry the declared child argv;
- client scan findings preserve user-global/project scope, resolve project
  precedence per workspace, and never reuse another workspace's declaration;
- a `deny` added after discovery rejects the next `tools/call`, without a
  second probe;
- renewal extends the same admission grant in place, is refused for an exec
  grant, an ended admission, and any caller but Authsia.app;
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
- wrap write shows the current entry, replacement, and checksum, and refuses
  when the file changed underfoot or the row is overridden by project config;
- the scanner reports wrapped, direct bypass, and unadmitted without retaining
  other environment values;
- Access Center presents a wrapped `tools/call` as the child basename plus MCP
  tool name, and does not persist arguments, results, or JSON-RPC.

Installed-product validation must exercise at least Codex, Claude Code, Cursor,
and VS Code from a real managed workspace before M14 is marked delivered.

Related: [`authsia-mcp.md`](authsia-mcp.md) (serve catalog),
[`jit-agent-grants.md`](jit-agent-grants.md) (grant matching),
[`security-model.md`](security-model.md).
