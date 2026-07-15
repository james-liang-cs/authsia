# Trust and verification map

Authsia treats local clients as untrusted until public policy code authorizes a
specific operation. This map identifies the implementation and focused tests
behind each security claim.

| Claim | Public implementation | Focused verification |
| --- | --- | --- |
| XPC callers are validated before receiving a handler | `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/CallerIdentityExtractor.swift`, `XPCListenerManager.swift` | `Packages/AuthsiaBridgeHost/Tests/AuthsiaBridgeHostTests/XPCListenerManagerTests.swift` |
| Direct CLI operations respect global, item, session, and approval policy | `Packages/AuthenticatorBridge/Sources/AuthenticatorBridge/BridgePolicy.swift`, `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/BridgeRequestPolicy.swift` | `Packages/AuthenticatorBridge/Tests/AuthenticatorBridgeTests/BridgePolicyTests.swift`, `Packages/AuthsiaBridgeHost/Tests/AuthsiaBridgeHostTests/BridgeRequestPolicyTests.swift` |
| JIT grants bind caller, workspace, item, field, capability, and expiry | `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/AgentJITGrantAuthorizer.swift`, `XPCRequestHandlerAgentJITPreflight.swift` | `Packages/AuthsiaBridgeHost/Tests/AuthsiaBridgeHostTests/AgentJITGrantAuthorizerTests.swift`, `AgentJITPolicyTests.swift` |
| Automation credentials enforce machine, expiry, scope, and command | `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/AutomationAuthorizationPolicy.swift`, `AutomationCredentialLookup.swift` | `Packages/AuthsiaBridgeHost/Tests/AuthsiaBridgeHostTests/AutomationAuthorizationPolicyTests.swift` |
| Vault persistence uses Keychain-backed stores without plaintext repository files | `Packages/AuthenticatorData/Sources/AuthenticatorData/KeychainStore.swift`, `VaultKeychainStore.swift`, `VaultRepository.swift` | `Packages/AuthenticatorData/Tests/AuthenticatorDataTests/KeychainQueryTests.swift`, `RepositorySavePathSyncPolicyTests.swift` |
| Native messaging validates request shape and host matching | `Tools/AuthsiaNativeHost/Sources/AuthsiaNativeHostCore/NativeMessaging.swift`, `HostMatching.swift`, `CredentialResolver.swift` | `Tools/AuthsiaNativeHost/Tests/AuthsiaNativeHostCoreTests/NativeHostCoreTests.swift`, `HostMatchingTests.swift` |
| SSH signing applies host, automation, item-access, and approval policy | `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/SSHAgentListener.swift`, `SSHAgentAutomationAuthorization.swift` | `Packages/AuthsiaBridgeHost/Tests/AuthsiaBridgeHostTests/SSHAgentListenerAuthorizationTests.swift`, `SSHAgentAutomationAuthorizationTests.swift` |
| Audit and command output omit resolved secret values | `Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost/BridgeAuditLogger.swift`, `Packages/AuthsiaCLI/Sources/authsia/Services/OutputMasker.swift` | `Packages/AuthsiaBridgeHost/Tests/AuthsiaBridgeHostTests/BridgeAuditLoggerTests.swift`, `Packages/AuthsiaCLI/Tests/AuthsiaCLITests/OutputMaskerTests.swift` |
| Official releases pin and verify one public source commit | `scripts/verify-release.sh`, `scripts/generate-sbom.sh`, `.github/workflows/release-source.yml` | `scripts/verify-release.sh --self-test`, tag workflow source/CLI/SBOM checksums, and GitHub artifact attestations |

The private app owns only presentation and lifecycle adapters. A private adapter
cannot grant access by itself; public authorization must succeed first.

Official app provenance names the public `v<app-version>` tag and full commit
SHA pinned by the private app's gitlink. The public workflow attests only the
public CLI and SBOM; it does not claim that the private SwiftUI app is
reproducible from this repository.
