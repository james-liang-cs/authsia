# Authsia Public Specifications

This directory is the canonical home for Authsia security-core contracts:

released CLI behavior, authorization policy, JIT grants, the local MCP tool and
execution contract, storage semantics, privacy posture, Chrome autofill
boundaries, and remote JIT approval protocols.

Local agent-tool integration begins with [`authsia-mcp.md`](authsia-mcp.md);
its authorization rules extend, but do not replace, the JIT and security-model
contracts in this directory.

Private app operations (build, packaging, release, LaunchAgent repair, and
manual verification runbooks) stay in the private application's `Doc/ops/`.
Private-only product surfaces such as Workspace Center UI contracts stay in the
private application's `Doc/specs/`.
