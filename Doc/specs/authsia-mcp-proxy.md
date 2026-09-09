# Local Authsia MCP Proxy

Status: release-candidate implementation contract for M14; signed installed-product
validation pending

This document owns wrapping a local stdio MCP server through Authsia and the
app-owned MCP Manager: user flow, company allowlist shape, workspace
`mcpUpstreams`, client launch, admission, catalog discovery, child lifecycle,
detective scan, the local management portal, and validated localhost Streamable
HTTP. The frozen six-tool Authsia catalog remains in
[`authsia-mcp.md`](authsia-mcp.md). JIT grant matching remains in
[`jit-agent-grants.md`](jit-agent-grants.md). Access Center presentation remains
in the private Access Center spec.

## Table Of Contents

- [Purpose](#purpose)
- [Complementary Lanes](#complementary-lanes)
- [User Flow](#user-flow)
  - [Operator Surfaces](#operator-surfaces)
  - [Preconditions](#preconditions)
  - [Find The Server](#find-the-server)
  - [Protect A Listed Server](#protect-a-listed-server)
  - [When Coverage Does Not List The Server](#when-coverage-does-not-list-the-server)
  - [When Protect Is Unavailable](#when-protect-is-unavailable)
  - [After Wrap](#after-wrap)
  - [Remove Protection](#remove-protection)
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
- [MCP Manager And Local Streamable HTTP](#mcp-manager-and-local-streamable-http)
- [Observability](#observability)
- [Errors](#errors)
- [Threat Model](#threat-model)
- [Verification Contract](#verification-contract)

## Purpose

`authsia mcp proxy` is a separate local `stdio` MCP server. It wraps one named
upstream declared by the bound workspace. It does not add tools to
`authsia mcp serve`, change the frozen six-tool Authsia catalog, or make
Authsia an implementation of the upstream service.

`authsia mcp start` opens the app-owned MCP Manager portal. That surface
aggregates workspace declarations and client scans, prepares confirmed
configuration changes, and serves validated localhost Streamable HTTP through
`127.0.0.1:8788`. It does not add tools to `authsia mcp serve`.

There is no client setting that intercepts a server the client already
launches. The client must start Authsia instead of the child command. MCP
Manager **Protect connection** / **Protect a client** and
`authsia mcp wrap --write` may replace a scanned client launch after
confirmation and a checksum check. **Protect a client** may insert the same
proxy launch when that JSON client does not already name the declared server.
Authsia never silent-rewrites. `mcp configure` still prints only. Workspace
Setup does not write `mcpUpstreams`.

Company policy allowlists Authsia. Workspace `mcpUpstreams` names each child.
Admission, redacted call evidence, and revoke-kill apply only on the wrapped
stdio path. Validated localhost Streamable HTTP uses the MCP Manager's
protected endpoint instead of `authsia mcp proxy`.

## Complementary Lanes

The company MCP gateway and Authsia are complementary, not a pipeline. A local
stdio server may never traverse the gateway. Authsia's local lane covers
`authsia mcp proxy` for declared stdio children and the MCP Manager's
validated localhost Streamable HTTP listener. Remote HTTP, HTTPS, SSE, and URL
MCP remain on the company gateway.

```text
                     coding client + model
                               |
              selects a configured MCP server entry
                     /                    \
                    /                      \
         local Authsia lane            remote service lane
    stdio proxy | localhost HTTP       company MCP gateway
                    |                      |
          local admission or JIT       SSO + remote policy
                    |                      |
     declared child | loopback server  remote MCP services
```

Approved wording: preventive for proxy-wrapped local servers, detective for
known direct configuration. Do not claim “all local MCP is blocked,” gateway
parity, executable attestation, or DLP.

## User Flow

MCP Manager **Servers** lists wrap-safe stdio launches already present in a
known client MCP file. **Protect connection** / **Protect a client** exist only
on those rows. A local tool that is not scanned, or that Servers hides, has no
Protect action. Follow [Find The Server](#find-the-server), then the matching
branch. Access Center does not host protection coverage or unowned proxy
decisions.

Managed wrap writes retain validated, credential-free launch metadata in
`AUTHSIA_MCP_LAUNCH`. Manager can use it to prepare a missing workspace
declaration without asking for the original executable. This value is a setup
hint only: the proxy still resolves its launch exclusively from workspace policy.
Recovery copies no credentials, tool permissions, catalog, or grants and requires
the existing declaration preview and native confirmation. Malformed metadata is
not imported. If a legacy wrapper has no saved launch, Manager can prepare its
declaration from an effective, wrap-safe entry for the same upstream in another
client in the same workspace. All eligible matches must agree on the command and
arguments. Disabled, overridden, unsupported, sensitive, and conflicting launches
are not imported. The native preview names the source client and file; both that
file and the target client entry are checked before applying. Environment values,
credentials, tool decisions, catalogs, and grants are not copied. Recoverable
entries offer **Configure** without requiring manual executable entry. An older
Context7 wrapper without saved metadata offers the labeled
[official Context7 preset](https://context7.com/docs/resources/all-clients),
`npx -y @upstash/context7-mcp`, for review. Other unknown launches still require
a matching workspace setup or an explicit command.

Case-insensitive duplicate declarations make a workspace unreadable; they do not
mean its existing servers need new declarations. When duplicate entries differ
only in name casing or `catalogCapturedAt`, Configure on an existing server
prepares a workspace repair instead of importing a preset. Native confirmation
names the redundant entries and retains the first declaration unchanged.
Commands, credentials, policy, catalogs, unknown fields, and unrelated workspace
settings are preserved. The write checks the original file snapshot. Any other
difference remains a `duplicateServerNames` error; Authsia does not merge
conflicting authority or choose a new upstream configuration.

The Servers table shows each effective client's protection badge alongside its
client name, so mixed protected, bypassing, and unconfigured clients are visible
without opening details. Compact layouts retain the client labels with the badges.

```text
 scanned client entry
          |
          v
 MCP Manager → Servers (protection coverage)
          |
          +-- direct / not wrapped ------> Protect connection
          +-- proxy missing policy ------> Configure / Use existing setup
          +-- unsafe launch -------------> fix the client entry, then Protect
          +-- no row --------------------> Add server, then Protect a client
          |
          v
 client launches: authsia mcp proxy
          |
          +-- tools/list ----------------> committed catalog only
          |                                no child, no grant, no prompt
          |
          +-- catalog capture -----------> local admission → short probe
          |                                write catalog → grant ends
          |
          +-- first tools/call
                   |
                   +-- fails before grant -> Manager Activity
                   |                         Grants: None recorded
                   |
                   +-- grant reused or admission / secret JIT approved
                              |
                              v
                       owned active grant → child starts
                              |
                              v
                       Manager Activity + Access Center grant
                              |
                              v
                       revoke / expiry → child stops
```

### Operator Surfaces

These three views are not three names for the same state. Coverage and unowned
call history live in MCP Manager. Access Center keeps runtime grants.

| Surface | Area | What it answers | Does it mean the child is running? |
| --- | --- | --- | --- |
| Access Center → **MCP proxy** | Admission and proxy grants | Which approved proxy sessions are active or retained in grant history? | An active grant is the authority; the proxy stops the child after it observes revoke or expiry. |
| MCP Manager → **Servers** | Protection coverage | Which known client launches are wrapped, bypassing, incomplete, or ready to protect in each workspace? | No. This is configuration state from the read-only client scan. Footer copy: protection describes configuration; runtime access is **Active access**. |
| MCP Manager → **Activity** | Calls, including decisions without a grant | Which proxy or HTTP calls were observed, including those that failed or were rejected before Authsia created an owned grant? | No. An inspector **Grants: None recorded** row is historical evidence, not a grant or server row. |

Access Center’s MCP proxy filter shows a Local MCP status strip and **Open MCP
Manager**. The strip states that server setup, protection status, and catalogs
are managed in MCP Manager, and that Access Center shows runtime grants and
approvals. That strip appears only on **MCP proxy**, not All, Authsia MCP, or
Direct agents.

**Route configured** means the scanned client launch points through Authsia
and its workspace declaration is usable. Per-client status separately shows
**Repair needed**, **Awaiting client connection**, or the latest **Call succeeded** /
**Call failed** result with its time. A configured route does not
mean a child is currently running or that access is already approved. Manager
**Active access** and Access Center list matching grants when runtime use has
been verified. A user-global client entry may represent several workspaces.
Choose the workspace in Manager’s sidebar, or Access Center’s Workspace menu
for grants; a declaration in repository A never authorizes repository B.

**No grant created** means the proxy failed closed before it obtained an owned,
revocable grant. The request may have been denied by settings or tool policy,
or failed because the workspace, upstream, transport, child, or advertised tool
was unavailable. Manager Activity retains that row so a failed attempt does not
disappear from operator visibility. It grants no authority. Export the same
slice with `authsia mcp activity export --json --unowned`.

### Preconditions

- An initialized, validated Authsia workspace.
- **MCP Integrations** enabled under Authsia **Settings > Developer Access**.
  The setting is off by default. Configuring a client does not turn it on.
  The Settings toggle opens Access Center’s **MCP proxy** filter. That strip
  can turn the setting on and offers **Open MCP Manager**. Enabling it
  creates no grant and bypasses no Bridge or JIT check.

MCP setup and launch commands (`configure`, `wrap`, `unwrap`, `declare`, `catalog`, `serve`, `proxy`, `start`, and `restart`) fail while MCP Integrations is off, before starting listeners or changing configuration. The error directs you to enable **MCP Integrations** in **Authsia Settings > Developer Access**, then retry. The CLI never changes the toggle. Help, `status`, `doctor`, `activity export`, `stop`, and portal revocation remain available for inspection and cleanup. Portal changes also recheck the toggle when prepared and confirmed.

### Find The Server

1. Initialize and validate the managed Authsia workspace.
2. Enable **MCP Integrations**.
3. Open MCP Manager (`authsia mcp start`, or Access Center → **MCP proxy** →
   **Open MCP Manager**). The Local MCP status strip lives only on that Access
   Center filter (not All, Authsia MCP, or Direct agents).
4. Choose the workspace that owns the tool in Manager’s sidebar.
5. Review **Servers**. Filter by routing status (**Bypassing Authsia**,
   **Route configured**, **Needs setup or repair**) or client. **Discover
   servers** rescans supported client files; it does not start servers or
   request runtime authority.

Servers shows wrap-eligible **Direct launch** and **Not wrapped** associations
as **Bypassing Authsia** or **Needs setup**, a proxy launch whose upstream is
missing from that workspace, **Pin a PATH binary** rows for shells and
absolute `npx` / `uvx` launchers (no Protect), **Launch setting not carried**
rows for an entry that sets something workspace policy has no field for
(`cwd`; no Protect until it is resolved in the client file), and wrapped
upstreams whose declared env forbids the probe, or whose scanned client entry
set child environment values, and whose policy names no tool. Open the server
to **Record catalog** or name tools in **Edit policy**. A **Protected
configuration** row with no matching active grant is wrapped and awaiting
runtime use; choose the workspace in the sidebar to see where the
configuration applies. It hides a launch the client file marks disabled, an
Authsia proxy launch with no valid upstream name, and does not treat a live
grant as extra coverage. Absolute Homebrew or `/usr/local` binaries wrap as a
PATH basename. Discover and Refresh reload the registry; they do not run on
Access Center.

Supported scanned clients: Codex, Claude Code, Cursor, Devin Desktop (Windsurf
uses the Devin config path), and Visual Studio Code (including Copilot MCP).
User-global files: `~/.codex/config.toml`, `~/.claude.json`,
`~/.cursor/mcp.json`, `~/.config/devin/mcp_config.json`, and VS Code user
`mcp.json`. Project files that outrank those: Claude `.mcp.json`, Cursor
`.cursor/mcp.json`, VS Code `.vscode/mcp.json`, and Codex
`.codex/config.toml`. Devin has no project scope. Codex project
`.codex/config.toml` is enumerated because HTTP enrollment refuses a
user-global write when that file already names the same server. Claude Code's `local` scope, the default for `claude mcp add`,
lives in `~/.claude.json` under `projects[<root>].mcpServers` and outranks
that repository's `.mcp.json`; it is read only for managed workspace roots. A
`.mcp.json` server the human declined, recorded in that project's
`disabledMcpjsonServers`, is not reported; a server in neither the enabled nor
the disabled list has not been answered yet and is still reported.

Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`)
is also scanned. It has no repository of its own, so its rows are **advisory**:
`mcp doctor` lists them and never counts them as violations, since no pilot
repository can close them. Protecting one pins a workspace in the entry's
environment with `WORKSPACE_FOLDER_PATHS`, which the proxy already reads.
Because company allowlists match command plus argv, naming the workspace there
rather than in argv keeps the two-entry allowlist intact. A Desktop row with no
managed workspace selected cannot be protected.

Cursor protection and enrollment write `.cursor/mcp.json` in the selected
project, creating the file when necessary. Generated entries omit
`WORKSPACE_FOLDER_PATHS`: Cursor supplies the actual workspace paths at launch.
An entry-level `${workspaceFolder}` value can overwrite that native hint without
being expanded. No absolute project path is saved in the entry. The proxy still
rejects empty, unresolved, conflicting, or ambiguous supplied hints before startup.
For older entries, Manager detects that exact generated placeholder and offers
**Repair Cursor**. The existing native-confirmation flow removes only the override,
preserves all other settings, and rejects stale file bytes. After applying, Manager
shows **Customize > MCPs > Configure this server**, enable the workspace source,
then Reload and make a permitted call. Manager does not read or change Cursor's
private enablement database or infer a plugin-name collision.

Protecting a user-global Cursor entry prepares two reviewed changes: an unbound
Authsia proxy fallback in the global file and a project override. Both file
checksums are checked before writing; the global pin is cleared first, so a
project write failure cannot leave other projects using the old policy. Existing
global proxy entries can be repaired through **Protect a client > Cursor**.
Devin and VS Code global entries use their launch context without a saved project
pin. Selecting a workspace in Manager never changes another running session.

### Protect A Listed Server

When Servers shows the server and **Protect connection** / **Protect a
client** is available, use it on the winning (usually project) file. Authsia declares command and argv in
`mcpUpstreams` when needed and, after showing the current entry, protected
entry, and a SHA256 checksum, writes the scanned client file. For a
credential-less stdio entry with empty `allow` and `approve`, Protect then
records the tool catalog: local MCP admission, a short-lived child probe, and
names plus sanitized schemas written into `mcpUpstreams`. Absolute Homebrew or
system paths store a PATH basename; committed `workspace.json` still forbids
absolute paths. Keep live credentials and private endpoints out of committed
policy.

Before it writes, Protect names what the diff cannot show: catalog recording
puts every advertised tool in `tools.allow`, which runs under the admission
grant with no per-call prompt, so a tool that should prompt belongs in
`tools.approve`; the wrap does not copy the environment values the client file
set for the child, and states how many there were; and a bare `npx` / `uvx`
launcher pins the launcher rather than what it fetches. Keys the entry sets
that `mcpUpstreams` cannot carry block Protect instead of being dropped. Project-scoped Claude, Cursor, and VS Code entries override matching
user-global entries; an overridden write is refused. Authsia never rewrites a
client file silently. If catalog recording is skipped or declined, the server
detail keeps **Record catalog**. `authsia mcp catalog --write` remains the
terminal equivalent, including after `mcp wrap --write`.

Then continue at [After Wrap](#after-wrap).

### When Coverage Does Not List The Server

There is no Protect action on Servers. Declare policy by hand, then point the
client at the proxy. Details of the `mcpUpstreams` object are in
[Declare The Upstream](#declare-the-upstream). Client file shapes are in
[Print And Apply Client Configuration](#print-and-apply-client-configuration).

1. Add a named `mcpUpstreams` entry to `.authsia/workspace.json`. `command` is
   a PATH basename or workspace-relative executable. Do not commit a shell
   wrapper, live credentials, or a machine-specific absolute path. A bare
   `npx` / `uvx` basename is accepted but pins the launcher rather than what it
   fetches; prefer a local binary where identity matters. Credential-less servers use `"env": {}`. Servers that inject
   `authsia://` references must pin `allow` / `approve` by hand; catalog
   capture is disabled when `env` is non-empty.
2. Replace the client's direct child launch with the installed Authsia binary,
   argv `mcp proxy`, and `AUTHSIA_MCP_UPSTREAM=<name>`. Prefer the project file
   for Claude, Cursor, and VS Code. Restart the client after the edit.
3. For a credential-less entry with empty `allow` and `approve` and no scanned
   child environment, record the
   catalog with `authsia mcp catalog --server <name> --write` and approve the
   Mac admission sheet. Until that write succeeds, `tools/list` is empty and
   agents fall through to the unproxied CLI. If the scanned entry set child
   environment values, name tools under `mcpUpstreams.tools.allow` instead;
   Authsia will not start that child to read a catalog.
4. Continue at [After Wrap](#after-wrap).

`authsia mcp configure --client <codex|claude|cursor|devin|vscode>` prints this
launch; it does not write files. `authsia mcp wrap --write` only wraps a
scanned, wrap-eligible row. It declares the upstream in the resolved workspace
as part of that write, so the wrapped launch resolves and `mcp catalog` can
follow; a name the workspace already declares differently is left alone and
reported.

### When Protect Is Unavailable

**Configure in Authsia** / **Use existing setup** is for a Servers row that
already launches `authsia mcp proxy` but has no matching `mcpUpstreams` entry
in the selected workspace. Wrap cannot infer child argv from a proxy launch.
`authsia mcp declare --server <name> --command <bin>` writes command and argv
into that workspace; it does not require operators to list child tool names.
A credential-less empty `allow` / `approve` entry still needs catalog
recording afterward.

If Servers lists the server as **Pin a PATH binary**, the launch is a shell
or absolute `npx` / `uvx` launcher. Install a PATH basename for that child,
change the client entry to that command, then Protect when the row becomes
wrap-eligible. An Authsia proxy with no valid upstream name stays hidden.

**Copy manual recipe** and `authsia mcp wrap --write --server <name> --yes`
remain fallbacks for wrap-eligible scanned rows. They are not a substitute
when Servers has no row.

### After Wrap

Open the managed workspace. Opening it starts nothing and asks nothing:
`tools/list` is answered from committed policy. A wrapped server with no
recorded catalog advertises nothing, so the client has no MCP tools to call
and agents fall through to the unproxied CLI. The first permitted `tools/call`
requests local MCP admission for a credential-less upstream, or exec JIT for
an upstream with `authsia://` references, before the long-lived child starts;
an existing matching grant is reused. Access Center shows **Access expires in** on an active
admission row. **Renew admission** extends that grant in place. Revoke in
Access Center when done.

### Remove Protection

Protection is reversible. **Remove protection** on a protected Servers
association, and `authsia mcp unwrap --write --server <name>`, restore the
client entry to
the command and argv the workspace declares, after showing the protected entry,
the restored entry, and a SHA256 checksum. The write is refused when the client
file changed underfoot, when that exact workspace no longer declares the
reviewed command and argv, or when project config overrides the row.

A wrap keeps the child argv only in `mcpUpstreams`, so that declaration is the
restore source: a proxy launch no workspace declares as a stdio command reports
that nothing recorded the launch it replaced, and the entry has to be restored
by hand. The restore is not a byte-for-byte undo. Environment values the client
file set for the child were never copied into policy at wrap time and do not
come back, and `authsia://` references a declared upstream carries are not
written into a client file, because only the proxy resolves them. Both are
named before the write.

Workspace policy is left alone. The `mcpUpstreams` entry keeps its recorded
catalog and any hand-placed `allow` / `approve`, so Servers moves the
association to **Bypassing Authsia** and Protect restores protection without
recording the catalog again. Reopen the client afterwards. A restored launch
is a direct launch: its tool calls are no longer admitted, audited, or
revocable.

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
`.authsia/workspace.json`. That array is the admission allowlist. MCP Manager
**Protect connection** / **Protect a client** is the operator action for a
wrap-eligible scanned stdio server: it declares command and argv and writes
the scanned client launch after confirmation. **Configure in Authsia** /
**Use existing setup** remains for a missing declaration when the client
already launches `mcp proxy` and Wrap cannot infer child argv:
`authsia mcp declare --server <name> --command <bin>` writes that child.
`authsia mcp declare --server <name> --url <loopback-http>` declares a
validated localhost Streamable HTTP endpoint instead; that path is served by
the MCP Manager, not by `mcp proxy`. Workspace Setup still does not write
`mcpUpstreams`.

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
  machine-specific paths. Validated loopback `http` URLs are declared with
  `--url` and served by the MCP Manager, not by `authsia mcp proxy`. Remote
  HTTP, HTTPS, SSE, and URL entries remain unsupported.

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

The write path is MCP Manager **Protect connection** / **Protect a client**,
or `authsia mcp wrap --write --server <name>` (prints a plan; `--yes` writes).
`mcp configure` stays print-only.

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

Confirmed **Protect a client** in the MCP Manager may **insert** that proxy
form when the chosen JSON client (Cursor, Claude Code, VS Code, Devin, Claude
Desktop) does not already name the declared STDIO server. VS Code and Devin
appear in Protect and the client filter only when that app is installed on
this Mac (bundle ID or `/Applications` / `~/Applications` app name). Windsurf
does not count as VS Code or Devin. The write prefers an existing project
file; otherwise it uses the user-global JSON config. It does not copy
workspace environment values or secrets. Codex STDIO enroll still requires a
scanned entry. `authsia mcp serve` is not an upstream and is not inserted.
The printed `mcp configure` form remains print-only.

The printed form is a user-global fallback derived from the currently bound
workspace. It is effective only when that workspace declares the named
upstream and no project-scoped entry overrides it. For Claude, Cursor, and VS
Code, prefer Protect on the matching project file. Manager and CLI copy
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
MCP Manager **Protect connection** / `authsia mcp wrap --write` may replace a
scanned server entry after a checksum check; **Protect a client** may insert
the same proxy launch when that client file has no matching key. Authsia does
not silent-rewrite, launch the client, add credentials, or use a shell wrapper.

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
closed with a stable error. Optional `--workspace` is authoritative; otherwise
the proxy uses a safe client workspace hint, then the process working directory.
It accepts `WORKSPACE_FOLDER_PATHS` (one absolute path) and Claude Code's
`CLAUDE_PROJECT_DIR` (one absolute directory, including names with commas).
Unresolved, malformed, or conflicting hints stop proxy startup rather than
falling back to another project's policy. Matching hints are compared after
path normalization and symlink resolution. Explicit `--workspace` overrides hints.
This stricter hint handling applies to `mcp proxy`, not `mcp serve`.

## Runtime Contract

### Global client entries and workspace declarations

Client configuration and Authsia workspace policy are separate layers:

| Layer | Responsibility |
| --- | --- |
| User-global client configuration | Makes an MCP launch available across projects in that client. A wrapped STDIO entry launches `authsia mcp proxy` and names the upstream with `AUTHSIA_MCP_UPSTREAM`. |
| Project client configuration | Supplies project-specific launches. Matching project entries can override global entries according to the client's precedence rules; review the effective, overridden, or conditional label in Manager. |
| Authsia workspace declaration | Defines the actual upstream command and arguments, tool policy, and secret references in that workspace's `.authsia/workspace.json`. |

Global availability does not grant access in every workspace. For STDIO, an
explicit `--workspace` determines the binding; otherwise the proxy uses a safe
`WORKSPACE_FOLDER_PATHS` or `CLAUDE_PROJECT_DIR` hint, then its process working directory. Selecting a
workspace in Manager only changes the management view and the target of setup
actions; it does not retarget a running client or proxy.

Claude Code supplies `CLAUDE_PROJECT_DIR` in the MCP child environment for its
CLI and IDE runtime; Authsia reads it directly, without adding config-time
interpolation or a global project pin. Codex CLI and its VS Code extension use
Codex's own MCP configuration, not VS Code's built-in MCP host. An unpinned
Codex launch uses its session working directory; an explicitly configured MCP
`cwd` or proxy `--workspace` remains fixed. Open a session in the new project
when switching; changing Manager's selected workspace does not move an existing
session. Do not generate global project pins for these clients.

For clients that supply the active repository at launch, an unpinned global
`playwright` proxy entry can be used from both `project-a`
and `project-b`. Each workspace needs its own `playwright` declaration. A
declaration in `project-a` is never implicitly used to authorize `project-b`.
If the second declaration is missing, Manager shows the client entry as
unconfigured there and workspace-dependent calls fail closed.

In Manager, choose **Use existing setup** on that discovered entry, select the
source workspace, and review the launch and tool policy before confirming. This
creates an independent declaration in the target workspace. It is a one-time
copy, not inheritance or synchronization: later changes to either declaration
do not change the other. Secret bindings, runtime grants, and recorded catalogs
are not copied. Add any required secret bindings in the target workspace and
reload the client before making a permitted call. Relative launch paths resolve
in the target workspace. If no matching setup exists, supply the original launch
through Manual setup.

Protected HTTP connections differ: the Manager endpoint and enrolled association
identify a particular server and workspace. They do not select another
workspace's policy from the client's working directory. Configure and enroll
the target workspace's HTTP server separately.

### Upstream selection

The name comes from `--upstream` or from `AUTHSIA_MCP_UPSTREAM`. If both are
set they must name the same upstream. Names match
`[A-Za-z][A-Za-z0-9_-]{0,31}`. The named upstream is resolved after workspace
bind, not as a process-exit condition.

The proxy does not expose the serve-only `authsia_access_status` or
`authsia_access_revoke` tools.

Unknown and denied calls fail before JIT or spawn. Only explicit `allow` or
`approve` decisions permit calls, including on credential-less upstreams with
empty policy. Captured metadata never grants authority. A policy-advertised tool
missing from the child fails closed.

Overlapping forwarded `tools/call` requests are multiplexed against one child.
At most eight calls may be in flight at once; a ninth is rejected with `busy`
rather than queued. Each forwarded call is also bounded by the proxy-side
deadline documented under Errors.

## Catalog Listing And Discovery

Wrap parses launcher command lines such as `npx @playwright/mcp@latest`,
`npm exec`, `pnpm dlx`, and `bunx` into an executable and separate arguments,
preserving quoted arguments without shell execution. Legacy joined launcher
commands are split when policy is read and persisted on the next catalog write.
Malformed command lines require repair of `command` and `args`, rather than a
PATH change. Upstream policy lookup is case-insensitive; `Playwright` and
`playwright` share a declaration while client display names remain unchanged.
Existing case-colliding policy entries must be reconciled explicitly; Authsia
rejects them rather than combining permissions.

Connected stdio proxies advertise `tools.listChanged` and check their visible
policy catalog once per second after the first `tools/list`. Catalog or policy
changes send `notifications/tools/list_changed`, including when tools disappear.
Listing and notification never start the child or request admission. A proxy
started with an older Authsia binary needs one client restart to use this behavior.

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

  tools/call without an explicit allow/approve decision
       +-- deny before admission or spawn (no discovery fallback)
```

Listing is answered from committed policy, so opening a workspace starts no
repository code and asks the human for nothing. Recording the catalog is a
separate, human-initiated step: `authsia mcp catalog` takes `mcp-admission`
before it resolves or spawns the declared child, reads `tools/list` once, kills
and reaps the probe, and drops its grant so the next client call still prompts.

Capture refreshes names, schemas, and capture time. When all policy lists are
empty, every recorded tool defaults to `allow` for both transports. Existing `allow`,
`approve`, and `deny` decisions are preserved, including names absent from the
latest catalog. With an existing policy, newly discovered tools are blocked until a human
assigns policy in **Edit policy**. CLI normalization retains these metadata-only
names. Oversized descriptors fall back to name-only catalog entries with the
same default policy behavior. The first permitted `tools/call` requires admission before
the long-lived child starts; the Bridge can reuse a matching grant.

Any non-empty declared env, whether literal or `authsia://`, disables catalog
capture. Listing must not resolve or forward
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
  actually starts. That argv is stored on the grant. A matching grant is reused
  only when the live `mcpUpstreams` command and args still equal the stored
  value; a changed declaration drops the child and re-prompts. Grants that
  predate this field do not reuse.
- A denied or missing admission grant prevents both capture and the long-lived
  spawn. Unreviewed calls are rejected without requesting admission, including
  repeated and concurrent attempts.
- Local `mcp-admission` grants use the dedicated `mcpAdmissionTTL` preference,
  default 30 minutes, instead of the 15-second CLI session default. The
  `mcpAdmissionMaximumTTL` managed preference can lower the company maximum;
  the product ceiling remains 24 hours. Expiry is absolute and does not slide
  when tools are used.
- On expiry or revocation, the proxy observes the inactive grant within its
  polling interval and terminates the child process group. Access Center revoke
  also kills any recorded child process group when the proxy is already gone
  (`SIGHUP`, crash, or `kill -9`): the proxy writes a sidecar of grant ID,
  child pgid, and proxy pid after spawn, and a snapshot or revoke sweeps rows
  whose proxy pid is dead. A later tool call requests a fresh admission. Access Center shows a live remaining-time label;
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
    |               |  or sidecar pgid if proxy is gone|
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
freshly resolved refs. The allowlist includes basic process variables, the
corporate egress settings `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY` (both
letter cases), and the non-secret TLS trust settings `NODE_EXTRA_CA_CERTS`,
`REQUESTS_CA_BUNDLE`, and
`SSL_CERT_FILE`. `AUTHSIA_AGENT_*`, automation authority, and
`AUTHSIA_MCP_UPSTREAM` are omitted from the child.

The child is associated in memory with the exact Bridge grant IDs that
authorized its environment. The proxy checks those grants on every call and
while the child is live. A Bridge snapshot that throws is not treated as
revocation: the watcher tolerates three consecutive failures (about six
seconds at the two-second poll) and logs once, then stops the child if the
Bridge stays unreachable. Revocation kills the upstream process group and drops
the client, secrets, and grant association; the periodic check may take up to
five seconds after the Bridge snapshot first reports no active associated
grant. `waitpid` starts immediately after `posix_spawn`, so a child that exits
during initialize fails fast with a distinct startup-exit error and a short
negative cache instead of waiting the initialize deadline. A `workspace.json`
that fails validation is reported as such on stderr once and in the client
error, not as an unbound workspace. Graceful proxy shutdown (`SIGINT`, `SIGTERM`, `SIGHUP`) performs the same
child cleanup and revokes active grants owned by that proxy instance. A later
call starts a fresh JIT session when required.

Before forwarding each permitted `tools/call`, Authsia records one redacted
Agent command event and an HMAC-chained `bridge_audit.log` row containing only
the proxy source, grant ID, workspace/runtime correlation, MCP tool name, and
bounded outcome. If that `started` record cannot be persisted, the call fails
before it reaches the upstream (`auditUnavailable`). A lost terminal outcome
is retried once, then reported on stderr; the client still receives the
forwarded result so the tool is not run twice.

## Client Configuration Scan

After printing configuration for a managed workspace, `mcp configure` also
performs a best-effort read-only scan of the known user-global client paths:
Codex `~/.codex/config.toml`, Claude `~/.claude.json`, Cursor
`~/.cursor/mcp.json`, Devin `~/.config/devin/mcp_config.json`, and VS Code's
user `mcp.json`. It also scans the bound workspace root for the project-scoped
files that outrank those: Claude `.mcp.json`, Cursor `.cursor/mcp.json`, VS
Code `.vscode/mcp.json`, and Codex `.codex/config.toml`. Devin has no project
scope. Codex project `.codex/config.toml` is enumerated because HTTP
enrollment refuses a user-global write when that file already names the same
server. Project scanning stays inside managed workspace roots and opens no new discovery
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

Malformed, missing, or oversized config files are skipped, as is any entry the
client file marks disabled (`enabled = false`, `"enabled": false`, or
`"disabled": true`): a launch that cannot run is neither a bypass to report nor
protection debt to work off. The scanner counts how many environment values an
entry sets for its child, never their names or values, so the wrap can say what
it will not copy. Findings from a client with no repository of its own are
advisory and excluded from the doctor verdict. The scanner never edits client
configuration. Confirmed MCP Manager **Protect connection** /
`authsia mcp wrap --write` may replace a scanned launch after a checksum
check; that write is not the scan. A direct or
unadmitted entry is visibility only until wrapped: Authsia cannot audit those
calls, kill them on revoke, or prevent launch. An empty or partial allowlist
therefore fails open and can only affect the displayed finding. Command/argv
matching is an identity hint, not executable attestation; pin a local binary
instead of a drifting package launcher when stronger identity matters.

## Access Center

Access Center remains the operator surface for proxy **grants**. It labels them
as `<client> via Authsia MCP proxy <upstream>`, derives its timeline from
existing grant and activity records without retaining raw frames, and revokes
through the existing Bridge-owned control. A long-lived proxy observes the
revoked snapshot and terminates its child process group; Access Center does
not signal the child directly.

The **MCP proxy** filter lists admission and `proxy:<upstream>` grants first.
Active admission rows show **Access expires in** with a live countdown and an
explicit **Renew admission** action. Renewal extends that grant in place: the
same grant ID, a fresh expiry, and a wrapped server that keeps running. Only
Authsia.app may renew, and only an active admission.

That filter’s Local MCP status strip reports MCP Integrations on/off and
directs setup to MCP Manager. **Open MCP Manager** is the action. The strip
does not host protection coverage or unowned proxy decisions. When no grants
match, the empty-result copy tells the operator to review server setup and
protection in MCP Manager.

The Agent grants Workspace menu filters every source tab; it lists **~** for
grants with no workspace, the same pinned and recent local workspaces
Workspace Center shows that still exist on this Mac, and existing roots of
active proxy grants. It omits historical grant paths even when the folder is
still on disk. Presentation rules live in the Access Center spec; this
document owns the wrap, admission, and revoke-kill contract those grant rows
display. Coverage, Protect, catalog recording, and unowned call history are
owned by [MCP Manager](#mcp-manager-and-local-streamable-http).

## MCP Manager And Local Streamable HTTP

`authsia mcp start` starts the app-owned local manager and opens its portal at
`http://127.0.0.1:8787`. `status`, `stop`, and `restart` use an anonymous XPC
endpoint registered by the signed GUI through `Authsia.Bridge`; the CLI never
owns either listener. The Bridge clears a registration when its owning GUI
connection ends. The manager binds its protected MCP listener at
`http://127.0.0.1:8788`.

The portal aggregates `mcpUpstreams` from pinned and known managed workspaces,
then overlays the existing client-configuration scan. **Servers** is the
protection-coverage surface: declared servers, discovered client entries, and
per-client routing, repair actions, and connection guidance. Configured routes
without call evidence have a neutral **Awaiting client connection** badge and
**View steps**. A green **Call succeeded** badge requires a successful latest
retained tool-call record matching both server identity and client label;
another client's activity cannot satisfy it. A newer failure replaces an older
success. Call timestamps describe history, not a live connection probe.
**Activity** is the call-history surface, including decisions
that never received a grant (inspector **Grants: None recorded**). **Active
access** lists live grants for the selected workspace. The portal exposes only
sanitized launch labels, tool policy/catalog, credential labels, associations,
and redacted STDIO and HTTP activity. A one-use 256-bit fragment capability is
exchanged for an HttpOnly SameSite cookie plus a memory-only request proof.
Both are required for API access; Host is restricted to the exact portal
authority. Mutations require the exact Origin. Authenticated same-origin GETs
may omit Origin and Referer, as browsers do with the portal's no-referrer
policy; cross-site Fetch Metadata is rejected. Scripts are bundled and
authorized by a content hash.

The registry also retains undeclared scan findings as **discovered** entries.
The Client status column lists scanned associations for that server, not a directory of
installed apps. Codex, Claude Code, Cursor, Visual Studio Code, Devin, and Claude
Desktop appear on a row as associations only when that client's configuration names the server.
The client filter and **Protect a client** offer Codex, Claude Code, Cursor, and
Claude Desktop always; Visual Studio Code and Devin only when that app is
installed. The filter also keeps declared servers that are not in that client yet, so
**Protect Cursor** (or another offered client) can insert a proxy launch. Selecting a workspace with no `mcpUpstreams` still shows applicable user-global
and project MCP configurations, with their client, source file, precedence, and
setup action. A declaration in another workspace does not hide those entries.
The portal can filter the list by client. Sidebar **Rows per page** (50 or 100)
paginates Servers, Activity, and Active access.

**Discover servers** rescans the supported client configuration locations; it
does not enumerate every installed package, start an MCP server, or request
runtime authority. The scanner's existing enabled-entry and precedence rules
still apply. Unreadable configurations are reported as diagnostics.

**Configure in Authsia** prepares a declaration from an eligible finding, then
requests native confirmation. It rechecks the finding's workspace and original
client-file bytes before applying. It copies eligible launch command/arguments or
a validated local HTTP endpoint, never client environment values or credentials.
Potentially sensitive arguments and unsafe launches require manual setup. No
client file is changed by this configuration step. Afterwards the managed row
provides policy, credential association, catalog, Protect, Protect a client
(insert when the client has no scanned association), and Remove protection
actions. Disabled client entries must first be enabled in their owning client;
Remove protection is not a generic server disable or uninstall command.

The portal prepares immutable changes for declarations, policy, credential
references, client protection, STDIO and localhost HTTP catalog capture, and grant
revocation. Native confirmation displays the concrete change. Execution rechecks the
browser session, app lock, declaration revision, and original client-file bytes.
Expired, denied, stale, and repeated operations cannot apply again. Credential
options are metadata only. Neither a browser request nor a browser confirmation
grants vault access. Confirmed mutations write a redacted intent record before
apply and an outcome afterwards. If intent cannot be recorded, the change is not
applied. Production recording awaits the signed-app-only Bridge audit endpoint;
it writes the complete redacted management event into the existing HMAC chain
as `mcpManagementActivity`, with the operation ID, phase, result, and context.
The intent is synchronized before acknowledgement. An absent recorder fails
closed. An outcome-write failure after an applied change is reported as applied
with incomplete evidence.

The Activity view merges command history with the management journal using the
operation ID and captured server/workspace metadata. It filters the merged data
before pagination. Older journal entries without identity remain visible under
All workspaces as unknown scope. Each source reports its own read health; a
missing outcome or unreadable source is incomplete evidence, not an empty healthy
history. The local journal is a bounded rolling projection, capped at 30 days,
2,000 events, and 1 MiB. Atomic rollover and a cross-process writer lock prevent
partial snapshots and lost concurrent writes. Reads of legacy oversized journals
use only a bounded tail. Pruning persists a retention marker and Activity reports
the management source as truncated; malformed or partial records are unavailable.
The journal is not itself HMAC-verified. `authsia audit export --verify` verifies
the canonical Bridge records, including new management events; legacy journal
rows are not retroactively certified.

Both loopback listeners impose a 15-second absolute deadline to finish each
incoming HTTP request, including silent sockets, partial headers and trickled
bodies. Completed requests can await native approval or stream responses without
that ingress deadline. Keep-alive connections get a fresh deadline after the
response ends; HTTP pipelining during an outstanding response is not supported.

HTTP tools in `tools.approve` require fresh native approval on every invocation,
even when session admission already exists. Allowed tools retain admission reuse.
Native rejection is recorded as denied and does not dispatch upstream. Terminal
activity writes occur after the terminating HTTP chunk is sent and retry once
with the same execution outcome; evidence failures do
not turn a delivered success into an upstream failure. The app retains a bounded
metadata-only fallback for failed writes until a successful retry or app exit,
and reports overflow as incomplete evidence. After restart, an unmatched started
row remains explicitly pending rather than claiming a complete terminal record.

Server details show independent readiness facts (declaration, launch, catalog,
policy, client route, observed use, and evidence), including catalog quality,
capture time when recorded, and launch revision. One recommended next action is
offered after a change. A detected Cursor repair takes priority. After a client
wrap or repair, the completion view gives client enablement, reload, and call
verification steps instead of ending at a protection-success message.

Disabled client entries remain in the discovery inventory and are excluded from
active coverage denominators. HTTP enrollment remains limited to Claude Code,
Codex, and Cursor; a scanner finding explains the same project-file conflict
the writer rejects. Other discovered HTTP clients explain that manual endpoint
configuration is required.

Active access follows the selected sidebar workspace unless All workspaces is
chosen. Grant rows include workspace/server identity when the native authority
provides it. Unknown legacy scope is labeled explicitly and is not inferred from
the server name.

Activity is a filtered command-history page, not a raw event dump. It includes
calls that never received a grant: the inspector shows **Grants: None
recorded**, with the declared upstream or executable basename, MCP tool name,
coarse outcome, error code, and stage. Those rows grant no authority and are
not server rows. Direct client launches are unobserved, so a supported client
such as Cursor appears in Activity only after a call through Authsia. The
portal discloses source health, retained range, truncation, and an
audit-status summary that reports history completeness. It does not label a
row HMAC-verified because another audit log exists. HTTP call identity is the
invocation UUID (`mcp-call:<uuid>`), never the tool name. Authenticated policy
denials and in-flight busy rejections are recorded before return, with no
upstream dispatch. Server lifecycle outcomes stay distinct from tool-call
failures. A history read failure is an unavailable source, not an empty
healthy window.

Local HTTP catalog capture is a separately confirmed manager capability. It may
initialize and follow bounded `tools/list` pages only; it does not authorize
`tools/call` or impersonate a coding-client session. Capture persists a short-lived
manager grant so revoke, lock, and required admission audit fail closed, including
between initialize and `tools/list`. A leftover `nextCursor` or a catalog larger
than the capture bound is reported incomplete rather than stored as success. New
advertised names still enter Allow while existing Block and Require approval rules
are preserved, which the native preview states.

Lock portal ends the browser session without storing proofs. Run
`authsia mcp start` to reopen; harmless view filters in this tab are restored
and pending mutations are not replayed.

After a declaration or another server change succeeds, the same portal dialog
shows setup actions for that exact server: Edit server, Edit policy, credential
association, eligible catalog recording, and per-client Protect. The user does
not need to return to the row menu or declare the server again in Access Center.
Edit server updates the existing executable or HTTP endpoint; arguments remain
unchanged unless explicitly replaced. Policy and credential references are
preserved. Each subsequent mutation still requires its own native confirmation.

When a discovered entry already launches `authsia mcp proxy` but the selected
workspace has no matching upstream declaration, Manager offers **Use an existing
setup** if another managed workspace has a reusable declaration. The user selects
the source workspace and reviews the launch arguments and tool policy in the
native confirmation. This adds the declaration to the target workspace; it does
not rewrite the already-wrapped client entry or start a server. Credential
bindings, grants, and recorded catalogs are not copied. Relative paths resolve
in the target workspace. Associate any required credentials there, then reload
the client and make a permitted call to request admission.

Reuse requires the same upstream name, a non-disabled/non-overridden proxy
finding, and a valid STDIO command with arguments that pass redaction checks.
The source declaration, target workspace file, and discovered client file are
checked again before applying; a changed file invalidates the prepared operation.
If no reusable setup exists, Manual setup remains available for entering the
original server launch. Authsia does not guess a launch from the server name.

Catalog availability is checked before prompting and again before execution.
Non-empty declared environments or active direct-client environment values disable
Record catalog; they are not a launch failure when the executable or endpoint is
already recorded. Name tools in Edit policy, then protect a client. Missing
standalone executables still require launch correction. The portal displays these
reasons beside the catalog control.
The helper uses the existing MCP PATH overlay so GUI launches can find supported
local runtime dependencies. Helper stderr stays bounded in memory and maps to
fixed, actionable errors; raw upstream diagnostics are never sent to the browser.
Catalog helper execution has a bounded timeout. Capture failures retain the
same-window Edit server and Edit policy recovery actions. Recording preserves
existing Block/Approval rules and adds newly advertised tools to Allow, which is
stated in the native preview.

The credential picker shows the vault folder and environment tags alongside each
name and type. Items with identical display metadata also show an item-ID suffix;
selection always uses the exact item ID. It defaults to the selected server's
workspace vault folder (`workspace.authsiaFolder`) and descendants, using the
existing workspace folder-matching rules. Search matches names, folders, and
environment tags. Users can explicitly include other folders. This is a
presentation filter, not a new credential permission or grant. The native preview
also includes folder and environment context. Add server restricts its workspace
dropdown when a workspace is selected in the sidebar.

The top-right Guide opens bundled, offline help with a setup flow and explanations
of Add server, Protect, Record catalog, policy, credential binding, HTTP enrollment,
prepared changes, removal, activity, grants, revocation, refresh, and portal lock.
It does not perform those actions. In particular, recording a catalog discovers
tool metadata; it is not recording calls, and locking the portal does not revoke
runtime grants or stop the manager.

Declare a local HTTP upstream explicitly:

```text
authsia mcp declare --server internal \
  --url http://127.0.0.1:9000/mcp \
  --allow search --approve create --deny delete --yes
```

The first HTTP declaration advances that workspace to schema version 3. Endpoints
must use `http`, an explicit port, and `localhost`, `127.0.0.1`, or `::1`.
`localhost` is normalized to `127.0.0.1`. Userinfo, query, fragment, redirects,
system proxy routing, Authsia's own ports, and non-loopback hosts are rejected.
Schema versions 1 and 2 continue to load; older software rejects schema 3.

Protected endpoints use `/mcp/<opaque-server-id>`. Every request requires a
32-byte bearer association token. Portal enrollment writes that token only to a
user-local Claude Code, Codex, or Cursor configuration after native confirmation;
the verifier is stored in Keychain. Repository MCP files never receive the token,
and conflicting project entries block enrollment. Preparation does not replace
an existing verifier. Client writes are checked and read back before activating
the staged token. Commit is idempotent and queryable after a lost IPC reply.

HTTP protection is tools-focused. It supports initialization, ping, the initialized
notification, cancellation/progress notifications, `tools/list`, `tools/call`,
POST, GET/SSE, and DELETE. The supported protocol versions are `2025-11-25`,
`2025-06-18`, and `2025-03-26`. Initialization echoes a supported offer or returns
`2025-11-25` as the supported fallback; the client must accept that version before
continuing. An authenticated session supplies the negotiated version when an
older client omits `MCP-Protocol-Version`; duplicate or mismatched headers are
rejected. The tools-only proxy and catalog reader honor a supported version
selected by the upstream independently of the client-facing session. Unknown
upstream versions fail before catalog or tool dispatch.

An upstream returning 405 for its optional GET stream leaves the downstream
session usable for POST tool calls. JSON and SSE initialization are accepted;
SSE decoding handles LF, CRLF, CR, and one leading UTF-8 byte-order mark while
retaining complete-event masking and byte caps. These behaviors follow the
[MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle),
[HTTP transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
and [SSE framing](https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream)
contracts. Loopback fixture tests cover all three negotiated versions, fallback,
header rejection, optional GET, catalog capture, framing, and masking. This is
protocol regression evidence, not certification of installed client versions.

Resources, prompts, sampling, elicitation, and other
methods fail explicitly. Complete SSE messages are decoded, masked, and delivered
incrementally with backpressure. JSON bodies and individual SSE events are capped
at 4 MiB. Event replay is not implemented: Last-Event-ID is rejected. Upstream and
downstream session identifiers are distinct and bound to one association;
a tool call is never automatically replayed after uncertain delivery.

`tools/list` is answered from committed policy and catalog without contacting the
upstream. `deny` overrides `approve`, which overrides `allow`. The first permitted
call presents Bridge-owned native admission. A grant is bound to the association,
authorization generation, downstream session, complete declaration revision, and
resolved credential identities. Absolute expiry follows the Bridge admission or
credential TTL. Each dispatch and delivered message revalidates authority.
Ordinary connection cancellation preserves the session and other calls. App lock,
manager stop, declaration changes, and revocation invalidate affected authority.
HTTP revocation closes affected local streams and blocks further forwarding; Authsia
cannot terminate an independently running HTTP server or undo an accepted call.

Optional `credentialHeaders` entries contain only a header name, an
`authsia://api-key`, password, or note reference, and `raw` or `bearer` formatting.
Resolution happens in Authsia Bridge after checking unique identity, folder,
CLI-access permission, expiry, and native admission. Metadata is checked again
after approval and immediately before reading the secret. Transport/session/framing
headers cannot be configured as credentials. Raw values are absent from the
workspace, portal, verifier store, and activity. Complete JSON messages, including
SSE data and escaped string values, are masked before delivery to the client.

HTTP activity uses the existing HMAC audit and agent command history. Admission
audit must succeed before releasing credentials; a started audit must succeed
before contacting the upstream. Authenticated, well-formed policy denials and
capacity (`busy`) rejections are recorded before return and do not contact the
upstream. Terminal events correlate success, MCP errors, cancellation, and
upstream failure to that invocation. The merge identity is `mcp-call:` plus the
invocation UUID in both `turnID` and `toolUseID`; the tool name is never that
key. Activity retains server, workspace, tool, configured-association
attribution, grant IDs when known, time, event kind, and a coarse outcome. It
never stores arguments, results, protocol frames, headers, tokens, or
credentials. Portal Activity is a command-history projection with completeness
and source-health fields. HMAC chain verification remains a native
`authsia audit export --verify` responsibility and is not implied by a portal
row.

## Observability

The proxy can see wrapped `tools/call` traffic at runtime. Persistence is a
redacted Agent command event plus an HMAC-chained `bridge_audit.log` row:
proxy source, optional grant ID, workspace/runtime correlation, MCP tool name,
and a bounded outcome. The persisted outcome is the coarse capsule
(`denied`, `upstreamUnavailable`, …). Failures also store `mcpProxyErrorCode`
(the protocol error, for example `mcpAccessDisabled`) and `mcpProxyStage`
(`settings`, `binding`, `policy`, `admission`, `spawn`, `forward`). A multi-grant
session records every `session.grantIDs` value on `mcpProxyGrantIDs`; the primary
`agentJITGrantID` remains the sorted-first ID. Attribution never falls back to
an unrelated owned grant. An admitted call is written as `started` before
forwarding, then an appended event with the same invocation merge key records
`succeeded`, `mcpError`, `timedOut`, `cancelled`, or `upstreamUnavailable`.
Policy and lifecycle failures that occur before a grant exists are recorded as
`denied`, `busy`, or `upstreamUnavailable` without a grant when the proxy can
persist them. If the `started` record cannot be saved, the call fails closed
with `auditUnavailable` and its error omits the invocation identifier. A lost
terminal outcome is retried once and named on stderr; it does not fail the
client. Raw JSON-RPC, tool arguments, results, and child stderr are never
written to audit or activity stores.

An error envelope carries the invocation UUID only after the redacted decision
event has been saved. The matching audit row's `turnID` (and `toolUseID`) is
`mcp-call:` followed by that UUID when a Bridge authorization row exists. A
pre-admission decision may have no matching audit row, but remains visible as
an unowned proxy decision in MCP Manager **Activity**.

The compact unowned-decision row still leads with a coarse outcome
(`denied`, `upstreamUnavailable`, `busy`). Manager Activity and Access Center
Commands / Timeline also show the persisted protocol error code and stage
(`settings`, `binding`, `policy`, `admission`, `spawn`, `forward`).
Those fields travel with the command-history export. Do not infer a code from
the coarse capsule alone.

Review an owned call on the grant in Access Center: **MCP proxy** filter →
grant → **Activity** → Timeline or Commands. Timeline titles a wrapped call
**MCP tool called** and shows the child basename, tool name, redacted
outcome, error code, and stage. Decisions without a grant appear in Manager
Activity with **Grants: None recorded**. Direct client launches outside the
proxy produce no call events.

A long-lived child also writes command-history-only rows `childStarted` and
`childExited`. Exit reasons are `exit`, `revoked`, `expired`, `stdinClosed`,
and `timeout`. These rows use a `mcp-child:` turn and never merge with
`mcp-call:` tool rows. They are not HMAC-chained `bridge_audit.log` activity;
that channel remains for `tools/call`. Catalog probes never assign a live
session and therefore write no child rows. On an admission grant, Access
Center hides `lastUsedAt` (the proxy does not refresh it) and shows
**Revoke pending** until a `childExited` row with reason `revoked` arrives,
then **Killed**. Timeline titles those rows **MCP child started** and
**MCP child exited**.

`authsia mcp activity export --json` copies `.mcpProxy` command-history rows
with `--since`, `--upstream`, `--workspace`, and `--unowned` filters.
`authsia audit export --verify` checks the HMAC chain on-box and writes a
manifest (`eventCount`, `headHash`, `deviceID`) wrapping JSON events, or an
NDJSON sidecar `.manifest.json`.

`tools/list`, including the admitted credential-less discovery probe, is not
per-tool command activity. File, network, and Process Tree tabs remain the
existing Authsia-mediated exec stores; they are not a transcript of a generic
MCP child. Access Center labels those three surfaces as unavailable for a
generic proxy grant instead of presenting an empty result as proof of no
activity.

Operator guidance:

1. Wrap every local stdio server that should be auditable. Visibility and
   revoke-kill exist only when the client starts `authsia mcp proxy` with
   `AUTHSIA_MCP_UPSTREAM`. In MCP Manager **Servers**, wrap remaining Direct
   launch and Not wrapped associations. If Servers has no row, follow
   [When Coverage Does Not List The Server](#when-coverage-does-not-list-the-server).
   Review owned grants in Access Center **MCP proxy**.
2. Review by grant. Expect *which tool ran*, not *what it was asked*.
3. Treat the client-config scan as detective. A direct entry is a finding, not
   a block, and is not a call log.
4. Keep remote HTTP, HTTPS, SSE, and URL MCP on the company gateway. Authsia's
   HTTP listener covers validated localhost Streamable HTTP only and does not
   replace gateway audit.
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
| `httpUpstreamUnsupported` | A client launched the STDIO `mcp proxy` for an HTTP declaration. Local HTTP declarations are served through the app-owned protected endpoint instead. SSE and remote URLs remain unsupported. |
| `timedOut` | The child did not answer a forwarded `tools/call` before the proxy's call deadline. The proxy cancels the request upstream and leaves the child running for the next call. |
| `busy` | Too many forwarded `tools/call` requests are already in flight for this upstream. The proxy rejects rather than queues. |
| `auditUnavailable` | The redacted `started` call record could not be persisted, so the proxy did not forward. |

Shared codes such as `mcpAccessDisabled`, `approvalDenied`, and
`workspaceUnavailable` keep the meanings in [`authsia-mcp.md`](authsia-mcp.md#errors-and-output).

## Threat Model

| Threat | Required control |
| --- | --- |
| Proxy policy is mistaken for live upstream authority | Derive `tools/list` from commit-safe policy only, then reject deny and unknown tools before the long-lived spawn, and privately verify advertised names after child initialization. |
| Opening a workspace starts repository code, or trains the human to approve prompts they did not cause | Answer `tools/list` from committed policy without starting the child or requesting admission. Record the catalog in a separate human-initiated `authsia mcp catalog` run, and raise the admission prompt on the first `tools/call`. |
| A catalog probe starts repository code before approval | Require `mcp-admission` before resolving or spawning the declared child for explicit capture, only when declared `env` is entirely empty. Kill the probe after `listTools`; calls never initiate discovery. |
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
  names and sanitized schemas in `mcpUpstreams`, preserves all existing tool
  decisions, and refuses an upstream with any declared env;
- unreviewed calls on credential-less upstreams fail before admission or spawn,
  including empty policy, repeated calls, and concurrent calls;
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
- a child that exits during initialize returns a startup-exit error without
  waiting the initialize deadline, and a short negative cache avoids respawning
  the same command;
- an unreadable `workspace.json` is reported as a validation failure, not as a
  missing workspace;
- a transient Bridge snapshot throw does not kill the wrapped child until three
  consecutive failures;
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
- wrap write shows the current entry, replacement, and checksum, redacts child
  env values in the current snippet, and refuses
  when the file changed underfoot or the row is overridden by project config;
- unwrap write restores the declared command and argv, drops the proxy
  environment, keeps neighbor entries and launch settings Authsia does not
  manage, leaves `mcpUpstreams` declared, never borrows a same-named declaration
  from another workspace, and refuses an undeclared or changed restore command
  and argv, a stale checksum, or an overridden row;
- the scanner reports wrapped, direct bypass, and unadmitted without retaining
  other environment values;
- Access Center presents a wrapped `tools/call` as the child basename plus MCP
  tool name, and does not persist arguments, results, or JSON-RPC;
- HTTP authenticated denials and busy rejections record one terminal activity
  row with zero extra upstream dispatch, and two invocations of the same tool
  remain separate call identities;
- manager Activity distinguishes unavailable history from an empty healthy
  window, filters before pagination, and never presents command-history rows as
  HMAC-verified;
- localhost HTTP catalog capture initializes and lists tools only, and cannot
  execute `tools/call`.

Installed-product validation must exercise at least Codex, Claude Code, Cursor,
and VS Code from a real managed workspace before M14 is marked delivered. A
signed app/helper build with the headless provisioning profile remains a
release gate; packaging without that profile is not an installed-product result.

Related: [`authsia-mcp.md`](authsia-mcp.md) (serve catalog),
[`jit-agent-grants.md`](jit-agent-grants.md) (grant matching),
[`security-model.md`](security-model.md).
