import Testing
import Foundation
import ArgumentParser
import AuthenticatorBridge
@testable import authsia

@Suite("Completion command")
struct CompletionCommandTests {

    @Test("zsh script is non-empty and contains compdef marker")
    func zshScriptContainsCompdef() {
        let script = Completion.completionScript(for: .zsh)
        #expect(!script.isEmpty)
        #expect(script.contains("#compdef") || script.contains("compdef"))
    }

    @Test("zsh script is safe to eval from zshrc")
    func zshScriptIsSafeToEvalFromZshrc() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("compdef _authsia authsia"))
        #expect(!script.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("_authsia"))
    }

    @Test("zsh script uses compadd for plain value completions")
    func zshScriptUsesCompaddForPlainValueCompletions() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("__authsia_complete() {\n    compadd -- \"$@\"\n}"))
        #expect(!script.contains("_describe -V '' non_empty_completions"))
    }

    @Test("zsh script avoids single dash option stacking")
    func zshScriptAvoidsSingleDashOptionStacking() {
        let script = Completion.completionScript(for: .zsh)

        #expect(!script.contains("_arguments -w -s -S"))
        #expect(script.contains("_arguments -w -S :"))
    }

    @Test("zsh script handles lone single dash options directly")
    func zshScriptHandlesLoneSingleDashOptionsDirectly() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("__authsia_complete_lone_dash_options()"))
        #expect(script.contains("option_part=\"${spec%%\\[*}\""))
        #expect(script.contains("__authsia_complete_lone_dash_options \"${arg_specs[@]}\" && return 0"))
        #expect(script.contains("_arguments -w -S : \"${arg_specs[@]}\" && ret=0\n    case \"${state}\" in"))
    }

    @Test("zsh lone single dash completion offers only short options")
    func zshLoneSingleDashCompletionOffersOnlyShortOptions() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("(( ${#short_options[@]} )) || return 0\n    compadd -- \"${short_options[@]}\""))
        #expect(!script.contains("compadd -- \"${long_options[@]}\" \"${short_options[@]}\""))
    }

    @Test("bash script is non-empty")
    func bashScriptIsNonEmpty() {
        let script = Completion.completionScript(for: .bash)
        #expect(!script.isEmpty)
    }

    @Test("fish script is non-empty")
    func fishScriptIsNonEmpty() {
        let script = Completion.completionScript(for: .fish)
        #expect(!script.isEmpty)
    }

    @Test("all shell scripts complete top-level guard commands")
    func allShellScriptsCompleteTopLevelGuardCommands() {
        let zsh = Completion.completionScript(for: .zsh)
        #expect(zsh.contains("'guard:Activate workspace guard in the current shell'"))
        #expect(zsh.contains("'unguard:Restart the current tab in normal terminal mode'"))

        let bash = Completion.completionScript(for: .bash)
        #expect(bash.contains("guard|unguard"))
        #expect(bash.contains(" guard unguard "))

        let fish = Completion.completionScript(for: .fish)
        #expect(fish.contains("-fa 'guard' -d 'Activate workspace guard in the current shell'"))
        #expect(fish.contains("-fa 'unguard' -d 'Restart the current tab in normal terminal mode'"))
    }

    @Test("get query uses dynamic item metadata completion")
    func getQueryUsesDynamicItemMetadataCompletion() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("---completion get -- positional@1"))
    }

    @Test("exec query uses dynamic item metadata completion")
    func execQueryUsesDynamicItemMetadataCompletion() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("---completion exec -- positional@1"))
        #expect(script.contains("---completion exec -- --query"))
    }

    @Test("load query uses dynamic item metadata completion")
    func loadQueryUsesDynamicItemMetadataCompletion() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("---completion load -- positional@1"))
    }

    @Test("folder options use dynamic folder metadata completion")
    func folderOptionsUseDynamicFolderMetadataCompletion() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("---completion get -- --folder"))
        #expect(script.contains("---completion load -- --folder"))
        #expect(script.contains("---completion exec -- --folder"))
        #expect(script.contains("---completion list -- --folder"))
    }

    @Test("field options use dynamic item type completion")
    func fieldOptionsUseDynamicItemTypeCompletion() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("---completion get -- --field"))
        #expect(script.contains("---completion load -- --field"))
        #expect(script.contains("---completion exec -- --field"))
    }

    @Test("zsh script includes complete item type menus")
    func zshScriptIncludesCompleteItemTypeMenus() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("local -ar _type=('password' 'api-key' 'cert' 'note' 'ssh' 'otp')"))
        #expect(script.contains("local -ar _type=('password' 'api-key' 'cert' 'note' 'ssh')"))
        #expect(script.contains("local -ar _type=('password' 'api-key' 'cert' 'note')"))
        #expect(script.contains("local -ar _scope=('otp' 'api-keys' 'passwords' 'certs' 'notes' 'ssh')"))
    }

    @Test("zsh script includes expected setup and agent option menus")
    func zshScriptIncludesExpectedSetupAndAgentOptionMenus() {
        let script = Completion.completionScript(for: .zsh)

        #expect(script.contains("--status[Print setup status without changing files]"))
        #expect(script.contains("--repair[Repair user shell integration]"))
        #expect(script.contains("--uninstall-clean[Remove Authsia-managed shell integration and user symlink]"))
        #expect(script.contains("local -ar ___agent=('claude-code' 'cursor' 'codex' 'windsurf' 'copilot')"))
    }

    @Test("item suggestions show safe metadata only")
    func itemSuggestionsShowSafeMetadataOnly() {
        let suggestions = ShellCompletionMetadata.plainRows(
            from: completionPayload(),
            allowedKinds: nil,
            currentWord: ""
        )

        #expect(suggestions == [
            "GitHub Work\tpassword\tfolder: StackOps",
            "AWS Dev\tpassword\tfolder: Cloud/dev",
            "Stripe\tapi-key\tfolder: Cloud/dev",
            "Release Cert\tcert\tfolder: Release",
            "App Store API Key\tnote\tfolder: Release",
            "Deploy Key\tssh\tfolder: Infra/SSH",
        ])

        let joined = suggestions.joined(separator: "\n")
        #expect(!joined.contains("svc-secret"))
        #expect(!joined.contains("hidden-secret"))
        #expect(!joined.contains("ssh-ed25519"))
        #expect(!joined.contains("SHA256"))
        #expect(!joined.contains("deploy@prod"))
    }

    @Test("item suggestions filter by type and current word")
    func itemSuggestionsFilterByTypeAndCurrentWord() {
        let suggestions = ShellCompletionMetadata.plainRows(
            from: completionPayload(),
            allowedKinds: [.password],
            currentWord: "AWS"
        )

        #expect(suggestions == [
            "AWS Dev\tpassword\tfolder: Cloud/dev",
        ])
    }

    @Test("zsh item suggestions include names only")
    func zshItemSuggestionsIncludeNamesOnly() {
        let suggestions = ShellCompletionMetadata.completions(
            from: completionPayload(),
            allowedKinds: [.password],
            folderPath: nil,
            currentWord: "Git",
            shell: .zsh
        )

        #expect(suggestions == [
            "GitHub Work",
        ])
    }

    @Test("item suggestions filter by exact folder")
    func itemSuggestionsFilterByExactFolder() {
        let suggestions = ShellCompletionMetadata.plainRows(
            from: completionPayload(),
            allowedKinds: [.password],
            folderPath: "StackOps",
            currentWord: ""
        )

        #expect(suggestions == [
            "GitHub Work\tpassword\tfolder: StackOps",
        ])
    }

    @Test("folder filtering applies to cert note and ssh suggestions")
    func folderFilteringAppliesToCertNoteAndSSHSuggestions() {
        let payload = completionPayload()

        #expect(ShellCompletionMetadata.plainRows(
            from: payload,
            allowedKinds: [.cert],
            folderPath: "Release",
            currentWord: ""
        ) == [
            "Release Cert\tcert\tfolder: Release",
        ])
        #expect(ShellCompletionMetadata.plainRows(
            from: payload,
            allowedKinds: [.note],
            folderPath: "Release",
            currentWord: ""
        ) == [
            "App Store API Key\tnote\tfolder: Release",
        ])
        #expect(ShellCompletionMetadata.plainRows(
            from: payload,
            allowedKinds: [.ssh],
            folderPath: "Infra/SSH",
            currentWord: ""
        ) == [
            "Deploy Key\tssh\tfolder: Infra/SSH",
        ])
    }

    @Test("folder suggestions are distinct and filtered by type")
    func folderSuggestionsAreDistinctAndFilteredByType() {
        let payload = completionPayload()

        #expect(ShellCompletionMetadata.folderCompletions(
            from: payload,
            allowedKinds: nil,
            currentWord: "",
            shell: nil
        ) == [
            "StackOps",
            "Cloud",
            "Cloud/dev",
            "Release",
            "Infra",
            "Infra/SSH",
        ])
        #expect(ShellCompletionMetadata.folderCompletions(
            from: payload,
            allowedKinds: [.password],
            currentWord: "",
            shell: .zsh
        ) == [
            "StackOps",
            "Cloud",
            "Cloud/dev",
        ])
        #expect(ShellCompletionMetadata.folderCompletions(
            from: payload,
            allowedKinds: [.cert, .note],
            currentWord: "Rel",
            shell: .zsh
        ) == [
            "Release",
        ])
    }

    @Test("folder completion uses non-interactive metadata client")
    func folderCompletionUsesNonInteractiveMetadataClient() {
        let client = CompletionListClientStub(payload: completionPayload())

        let suggestions = ShellCompletionMetadata.completeFolders(
            arguments: ["authsia", "exec", "password", "--folder"],
            wordIndex: 3,
            currentWord: "Cl",
            client: client,
            shell: nil
        )

        #expect(client.callCount == 1)
        #expect(suggestions == [
            "Cloud",
            "Cloud/dev",
        ])
    }

    @Test("folder completion returns empty when metadata is unavailable")
    func folderCompletionReturnsEmptyWhenMetadataIsUnavailable() {
        let client = CompletionListClientStub(payload: nil)

        let suggestions = ShellCompletionMetadata.completeFolders(
            arguments: ["authsia", "exec", "password", "--folder"],
            wordIndex: 3,
            currentWord: "",
            client: client
        )

        #expect(client.callCount == 1)
        #expect(suggestions == [])
    }

    @Test("item completion uses non-interactive metadata client")
    func itemCompletionUsesNonInteractiveMetadataClient() {
        let client = CompletionListClientStub(payload: completionPayload())

        let suggestions = ShellCompletionMetadata.completeItems(
            arguments: ["authsia", "exec", "password"],
            wordIndex: 2,
            currentWord: "Git",
            client: client,
            shell: .zsh
        )

        #expect(client.callCount == 1)
        #expect(suggestions == [
            "GitHub Work",
        ])
    }

    @Test("folder filter is extracted from completion arguments")
    func folderFilterIsExtractedFromCompletionArguments() {
        #expect(
            ShellCompletionMetadata.folderFilter(from: ["authsia", "get", "password", "--folder", "StackOps"]) ==
                "StackOps"
        )
        #expect(
            ShellCompletionMetadata.folderFilter(from: ["authsia", "get", "password", "--folder=Team/API"]) ==
                "Team/API"
        )
        #expect(
            ShellCompletionMetadata.folderFilter(from: ["authsia", "load", "cert", "-f", "Release"]) ==
                "Release"
        )
        #expect(
            ShellCompletionMetadata.folderFilter(from: ["authsia", "get", "password", "--folder"]) == nil
        )
    }

    @Test("get field suggestions filter by selected item type")
    func getFieldSuggestionsFilterBySelectedItemType() {
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "get", "password"],
            currentWord: ""
        ) == ["username", "password", "all"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "get", "api-key"],
            currentWord: ""
        ) == ["key", "all"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "get", "cert"],
            currentWord: ""
        ) == ["certificate", "privateKey", "all"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "get", "note"],
            currentWord: ""
        ) == ["content", "all"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "get", "ssh"],
            currentWord: ""
        ) == ["publicKey", "privateKey", "comment", "fingerprint", "keyType", "approvalPolicy", "boundHosts", "all"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "get", "otp"],
            currentWord: ""
        ) == [])
    }

    @Test("load and exec field suggestions exclude unsupported fields")
    func loadAndExecFieldSuggestionsExcludeUnsupportedFields() {
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "load", "password"],
            currentWord: ""
        ) == ["username", "password"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "load", "api-key"],
            currentWord: ""
        ) == ["key"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "load", "ssh"],
            currentWord: ""
        ) == [])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "exec", "cert"],
            currentWord: ""
        ) == ["certificate", "privateKey"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "exec", "--type", "note"],
            currentWord: ""
        ) == ["content"])
    }

    @Test("field completion wrappers preserve command context")
    func fieldCompletionWrappersPreserveCommandContext() {
        #expect(ShellCompletionMetadata.completeGetFields(
            arguments: ["ssh"],
            wordIndex: 0,
            currentWord: ""
        ) == ["publicKey", "privateKey", "comment", "fingerprint", "keyType", "approvalPolicy", "boundHosts", "all"])
        #expect(ShellCompletionMetadata.completeLoadFields(
            arguments: ["ssh"],
            wordIndex: 0,
            currentWord: ""
        ) == [])
        #expect(ShellCompletionMetadata.completeExecFields(
            arguments: ["cert"],
            wordIndex: 0,
            currentWord: ""
        ) == ["certificate", "privateKey"])
    }

    @Test("field suggestions filter by current word")
    func fieldSuggestionsFilterByCurrentWord() {
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "get", "cert"],
            currentWord: "cert"
        ) == ["certificate"])
        #expect(ShellCompletionMetadata.fieldCompletions(
            arguments: ["authsia", "get", "password", "ELASTICSEARCH_CLUSTERS", "--field"],
            currentWord: "cert"
        ) == [])
    }

    private func completionPayload() -> BridgeListPayload {
        let date = Date(timeIntervalSince1970: 0)
        return BridgeListPayload(
            accounts: [
                BridgeAccount(
                    id: UUID(uuidString: "11111111-1111-1111-1111-111111111111")!,
                    issuer: "GitHub OTP",
                    label: "alice@example.com",
                    isFavorite: false,
                    isCliEnabled: false,
                    isScraped: false,
                    createdAt: date,
                    updatedAt: date
                ),
            ],
            passwords: [
                BridgePassword(
                    id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!,
                    name: "GitHub Work",
                    username: "svc-secret",
                    website: nil,
                    folderPath: "StackOps",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: date,
                    updatedAt: date
                ),
                BridgePassword(
                    id: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!,
                    name: "AWS Dev",
                    username: "hidden-secret",
                    website: nil,
                    folderPath: "Cloud/dev",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: date,
                    updatedAt: date
                ),
            ],
            apiKeys: [
                BridgeAPIKey(
                    id: UUID(uuidString: "77777777-7777-7777-7777-777777777777")!,
                    name: "Stripe",
                    website: nil,
                    folderPath: "Cloud/dev",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: date,
                    updatedAt: date
                ),
            ],
            certificates: [
                BridgeCertificate(
                    id: UUID(uuidString: "66666666-6666-6666-6666-666666666666")!,
                    name: "Release Cert",
                    issuer: nil,
                    subject: nil,
                    expirationDate: nil,
                    folderPath: "Release",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: date,
                    updatedAt: date
                ),
            ],
            notes: [
                BridgeNote(
                    id: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!,
                    title: "App Store API Key",
                    folderPath: "Release",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: date,
                    updatedAt: date
                ),
            ],
            sshKeys: [
                BridgeSSHKey(
                    id: UUID(uuidString: "55555555-5555-5555-5555-555555555555")!,
                    name: "Deploy Key",
                    comment: "deploy@prod",
                    fingerprint: "SHA256:secret",
                    publicKey: "ssh-ed25519 secret",
                    folderPath: "Infra/SSH",
                    isFavorite: false,
                    isCliEnabled: true,
                    isScraped: false,
                    createdAt: date,
                    updatedAt: date
                ),
            ]
        )
    }
}

private final class CompletionListClientStub: ShellCompletionListClient {
    private let payload: BridgeListPayload?
    private(set) var callCount = 0

    init(payload: BridgeListPayload?) {
        self.payload = payload
    }

    func listForShellCompletion() throws -> BridgeListPayload? {
        callCount += 1
        return payload
    }
}
