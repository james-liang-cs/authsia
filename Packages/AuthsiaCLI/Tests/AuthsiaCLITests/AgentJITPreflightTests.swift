import Testing
import Foundation
import AuthenticatorBridge
@testable import authsia

@Suite("Agent JIT preflight")
struct AgentJITPreflightTests {

    @Test("env reference extraction normalizes folders and sorts deterministically")
    func envReferenceExtractionNormalizesFoldersAndSorts() throws {
        let refs = try SecretReferenceResolver.preflightReferences(
            environment: [
                "PLAIN": "not-a-reference",
                "API_KEY": "authsia://api-key/Stripe/key?folder=Team%2FAPI",
                "PASSWORD": "authsia://password/API%20Token/password?folder=Team%2FAPI",
                "NOTE": "authsia://note/Runbook/content?folder=%20Team%2F%2FOps%20",
                "CERT": "authsia://cert/TLS/certificate?folder=%20%2F%20",
                "SSH": "authsia://ssh/deploy/privateKey?folder=Team/SSH",
                "OTP": "authsia://otp/GitHub/code?folder=Team/OTP",
            ]
        )

        #expect(refs == [
            AgentJITPreflightReference(type: "api-key", query: "Stripe", folderPath: "Team/API"),
            AgentJITPreflightReference(type: "cert", query: "TLS", folderPath: nil, isFolderScoped: true),
            AgentJITPreflightReference(type: "note", query: "Runbook", folderPath: "Team/Ops"),
            AgentJITPreflightReference(type: "password", query: "API Token", folderPath: "Team/API"),
        ])
    }

    @Test("folderless env references are unscoped while explicit root remains scoped")
    func folderlessEnvReferencesAreUnscoped() throws {
        let refs = try SecretReferenceResolver.preflightReferences(
            environment: [
                "ROOT": "authsia://password/Root/password?folder=%20%2F%20",
                "UNSCOPED": "authsia://password/API/password",
            ]
        )

        #expect(refs == [
            AgentJITPreflightReference(type: "password", query: "API", folderPath: nil, isFolderScoped: false),
            AgentJITPreflightReference(type: "password", query: "Root", folderPath: nil, isFolderScoped: true),
        ])
    }

    @Test("invalid env fields fail before preflight metadata is emitted")
    func invalidEnvFieldsFailBeforePreflightMetadata() {
        #expect(throws: (any Error).self) {
            _ = try SecretReferenceResolver.preflightReferences(
                environment: ["BAD": "authsia://password/API/passwrod?folder=Team/API"]
            )
        }
    }

    @Test("agentic ancestry enables preflight only when stdin is not a TTY")
    func agentAncestryEnablesPreflightOnlyWhenStdinIsNotTTY() {
        // Human stdin TTY: never preflight, regardless of ancestry or redirected stdout.
        #expect(!Exec.shouldRunJITPreflight(
            environment: [:], processAncestry: Self.humanTerminalAncestry, stdinIsTTY: true
        ))
        #expect(!Exec.shouldRunJITPreflight(
            environment: [:], processAncestry: Self.codexAncestry, stdinIsTTY: true
        ))
        #expect(!Exec.shouldRunJITPreflight(
            environment: [:], processAncestry: Self.ideExtensionHostAncestry, stdinIsTTY: true
        ))
        // stdin TTY with redirected stdout has isInteractiveSession == false, but must not preflight.
        #expect(!Exec.shouldRunJITPreflight(
            environment: [:], processAncestry: Self.codexAncestry, stdinIsTTY: true
        ))
        // No stdin TTY with agentic ancestry: still preflight.
        #expect(Exec.shouldRunJITPreflight(
            environment: [:], processAncestry: Self.codexAncestry, stdinIsTTY: false
        ))
        #expect(Exec.shouldRunJITPreflight(
            environment: [:], processAncestry: Self.claudeRuntimeAncestry, stdinIsTTY: false
        ))
        #expect(Exec.shouldRunJITPreflight(
            environment: [:], processAncestry: Self.ideExtensionHostAncestry, stdinIsTTY: false
        ))
        // No stdin TTY but no agentic ancestry: no preflight.
        #expect(!Exec.shouldRunJITPreflight(
            environment: [:], processAncestry: Self.humanTerminalAncestry, stdinIsTTY: false
        ))
        // Automation credential always short-circuits to false; SSH-only cred does not.
        #expect(!Exec.shouldRunJITPreflight(
            environment: [AutomationAccessResolver.environmentKey: UUID().uuidString],
            processAncestry: Self.codexAncestry,
            stdinIsTTY: false
        ))
        #expect(Exec.shouldRunJITPreflight(
            environment: [AutomationAccessResolver.sshEnvironmentKey: UUID().uuidString],
            processAncestry: Self.codexAncestry,
            stdinIsTTY: false
        ))
    }

    @Test("explicit agent environment marker enables preflight even at an interactive human terminal")
    func explicitAgentEnvironmentMarkerEnablesPreflight() {
        #expect(Exec.shouldRunJITPreflight(
            environment: [
                AgentRuntimeContextResolver.environmentPlatformKey: "copilot",
                AgentRuntimeContextResolver.environmentInvokesAuthsiaKey: "1",
            ],
            processAncestry: Self.humanTerminalAncestry,
            stdinIsTTY: true
        ))
        #expect(!Exec.shouldRunJITPreflight(
            environment: [
                AgentRuntimeContextResolver.environmentPlatformKey: "copilot",
            ],
            processAncestry: Self.humanTerminalAncestry,
            stdinIsTTY: true
        ))
    }

    @Test("type-loaded references convert ids and normalized folders")
    func typeLoadedReferencesConvertIDsAndFolders() throws {
        let refs = try Exec.jitPreflightReferences(
            type: .password,
            references: [
                Load.ItemReference(
                    id: "root-id",
                    name: "Root",
                    folderPath: nil,
                    isCliEnabled: true,
                    isScraped: false,
                    scrapeMachineName: nil,
                    scrapeMachineId: nil
                ),
                Load.ItemReference(
                    id: "folder-id",
                    name: "Folder",
                    folderPath: " Team//API ",
                    isCliEnabled: true,
                    isScraped: false,
                    scrapeMachineName: nil,
                    scrapeMachineId: nil
                ),
            ]
        )

        #expect(refs == [
            AgentJITPreflightReference(type: "password", query: "root-id", folderPath: nil),
            AgentJITPreflightReference(type: "password", query: "folder-id", folderPath: "Team/API"),
        ])
    }

    @Test("single item type scope can preflight before metadata list")
    func singleItemTypeScopeCanPreflightBeforeMetadataList() throws {
        let single = try Exec.initialJITPreflightReference(
            type: .apiKey,
            scope: .single("SERVICE_ENDPOINT"),
            field: nil
        )
        let folder = try Exec.initialJITPreflightReference(
            type: .apiKey,
            scope: .itemInFolder(query: "SERVICE_ENDPOINT", folderPath: "Team/API"),
            field: nil
        )
        let wholeFolder = try Exec.initialJITPreflightReference(
            type: .apiKey,
            scope: .folder("Team/API"),
            field: nil
        )

        #expect(single == AgentJITPreflightReference(
            type: "api-key",
            query: "SERVICE_ENDPOINT",
            folderPath: nil,
            isFolderScoped: false
        ))
        #expect(folder == AgentJITPreflightReference(
            type: "api-key",
            query: "SERVICE_ENDPOINT",
            folderPath: "Team/API",
            isFolderScoped: true
        ))
        #expect(wholeFolder == AgentJITPreflightReference(
            type: "api-key",
            query: "",
            folderPath: "Team/API",
            isFolderScoped: true
        ))
    }

    @Test("multi-folder type scope preflights each exact folder")
    func multiFolderTypeScopePreflightsEachExactFolder() throws {
        let refs = try Exec.initialJITPreflightReferences(
            type: .password,
            scope: .folders([" Team/API ", "Team/Web"]),
            field: nil
        )

        #expect(refs == [
            AgentJITPreflightReference(type: "password", query: "", folderPath: "Team/API", isFolderScoped: true),
            AgentJITPreflightReference(type: "password", query: "", folderPath: "Team/Web", isFolderScoped: true),
        ])
    }

    @Test("agent env references to otp and ssh are rejected before resolution")
    func agentEnvReferencesToUnsupportedJITTypesAreRejected() throws {
        let environment = [
            "OTP_CODE": "authsia://otp/GitHub/code?folder=Team/OTP",
            "SSH_KEY": "authsia://ssh/deploy/privateKey?folder=Team/SSH",
        ]

        #expect(throws: (any Error).self) {
            try Exec.rejectUnsupportedAgentJITReferences(
                environment: environment,
                parentEnvironment: [:],
                processAncestry: Self.codexAncestry
            )
        }

        try Exec.rejectUnsupportedAgentJITReferences(
            environment: environment,
            parentEnvironment: [:],
            processAncestry: Self.humanTerminalAncestry
        )
    }

    @Test("invalid type load field fails before preflight client call")
    func invalidTypeLoadFieldFailsBeforePreflightClientCall() {
        let client = RecordingJITPreflightClient()
        let references = [
            Load.ItemReference(
                id: "cert-id",
                name: "Cert",
                folderPath: "Team/API",
                isCliEnabled: true,
                isScraped: false,
                scrapeMachineName: nil,
                scrapeMachineId: nil
            ),
        ]

        #expect(throws: (any Error).self) {
            try Exec.runJITPreflight(
                type: .cert,
                references: references,
                field: .content,
                parentEnvironment: [:],
                client: client
            )
        }
        #expect(client.payloads == [])
    }

    @Test("env preflight input excludes loaded secret values")
    func envPreflightInputExcludesLoadedSecretValues() {
        let parentEnvironment = [
            "PATH": "/usr/bin",
            "FROM_PARENT": "authsia://password/Parent/password?folder=Team/API",
        ]
        let envFileVars = [
            "FROM_FILE": "authsia://note/Runbook/content?folder=Team/Ops",
        ]
        let entries = [
            Load.LoadedEntry(
                key: "LOADED_SECRET",
                value: "authsia://password/ShouldNotPreflight/password?folder=Team/Secret",
                itemType: .password,
                sourceName: "Loaded",
                sourceID: "loaded-id",
                folderPath: "Team/Secret",
                scrapeMachineName: nil,
                scrapeMachineId: nil
            ),
        ]

        let finalEnvironment = Exec.finalEnvironment(
            entries: entries,
            parentEnvironment: parentEnvironment,
            envFileVars: envFileVars,
            sshAutomationCredential: nil
        )
        let preflightEnvironment = Exec.jitEnvPreflightEnvironment(from: finalEnvironment, excluding: entries)

        #expect(preflightEnvironment["LOADED_SECRET"] == nil)
        #expect(finalEnvironment["LOADED_SECRET"] == "authsia://password/ShouldNotPreflight/password?folder=Team/Secret")
    }

    @Test("loaded entry keys suppress parent env refs during preflight")
    func loadedEntryKeysSuppressParentEnvRefsDuringPreflight() throws {
        let entries = [
            Load.LoadedEntry(
                key: "API",
                value: "loaded-secret",
                itemType: .password,
                sourceName: "Loaded",
                sourceID: "loaded-id",
                folderPath: "Team/New",
                scrapeMachineName: nil,
                scrapeMachineId: nil
            ),
        ]
        let finalEnvironment = Exec.finalEnvironment(
            entries: entries,
            parentEnvironment: [
                "API": "authsia://password/Old/password?folder=Team/Old",
                "KEEP": "authsia://password/Keep/password?folder=Team/Keep",
            ],
            envFileVars: [:],
            sshAutomationCredential: nil
        )
        let preflightEnvironment = Exec.jitEnvPreflightEnvironment(from: finalEnvironment, excluding: entries)
        let refs = try SecretReferenceResolver.preflightReferences(environment: preflightEnvironment)

        #expect(preflightEnvironment["API"] == nil)
        #expect(finalEnvironment["API"] == "loaded-secret")
        #expect(refs == [
            AgentJITPreflightReference(type: "password", query: "Keep", folderPath: "Team/Keep"),
        ])
    }

    @Test("env file refs still preflight when overriding loaded keys")
    func envFileRefsStillPreflightWhenOverridingLoadedKeys() throws {
        let entries = [
            Load.LoadedEntry(
                key: "API",
                value: "loaded-secret",
                itemType: .password,
                sourceName: "Loaded",
                sourceID: "loaded-id",
                folderPath: "Team/New",
                scrapeMachineName: nil,
                scrapeMachineId: nil
            ),
        ]
        let finalEnvironment = Exec.finalEnvironment(
            entries: entries,
            parentEnvironment: [:],
            envFileVars: ["API": "authsia://password/File/password?folder=Team/File"],
            sshAutomationCredential: nil
        )
        let preflightEnvironment = Exec.jitEnvPreflightEnvironment(from: finalEnvironment, excluding: entries)
        let refs = try SecretReferenceResolver.preflightReferences(environment: preflightEnvironment)

        #expect(finalEnvironment["API"] == "authsia://password/File/password?folder=Team/File")
        #expect(refs == [
            AgentJITPreflightReference(type: "password", query: "File", folderPath: "Team/File"),
        ])
    }

    @Test("preflight helper calls client for agent exec and skips human empty or automation")
    func preflightHelperCallsClientForAgentExecAndSkipsWhenNotNeeded() throws {
        let references = [
            AgentJITPreflightReference(type: "note", query: "note-id", folderPath: "Team/Ops"),
        ]
        let client = RecordingJITPreflightClient()

        try Exec.runJITPreflight(
            references: references,
            parentEnvironment: [:],
            processAncestry: Self.humanTerminalAncestry,
            client: client
        )
        #expect(client.payloads == [])

        try Exec.runJITPreflight(
            references: references,
            parentEnvironment: [:],
            processAncestry: Self.codexAncestry,
            client: client
        )

        #expect(client.payloads == [
            AgentJITPreflightPayload(requestedCommand: "exec", references: references),
        ])

        try Exec.runJITPreflight(
            references: [],
            parentEnvironment: [:],
            processAncestry: Self.codexAncestry,
            client: client
        )
        try Exec.runJITPreflight(
            references: references,
            parentEnvironment: [AutomationAccessResolver.environmentKey: UUID().uuidString],
            processAncestry: Self.codexAncestry,
            client: client
        )

        #expect(client.payloads.count == 1)
    }

    @Test("list preflight helper calls client for agent list and skips human or automation")
    func listPreflightHelperCallsClientForAgentListAndSkipsWhenNotNeeded() throws {
        let client = RecordingJITPreflightClient()

        try List.runJITPreflight(
            scope: .apiKeys,
            folder: " Team//API ",
            parentEnvironment: [:],
            processAncestry: Self.humanTerminalAncestry,
            client: client
        )
        #expect(client.payloads == [])

        try List.runJITPreflight(
            scope: .apiKeys,
            folder: " Team//API ",
            parentEnvironment: [:],
            processAncestry: Self.claudeRuntimeAncestry,
            client: client
        )

        #expect(client.payloads == [
            AgentJITPreflightPayload(
                requestedCommand: "list",
                references: [
                    AgentJITPreflightReference(
                        type: "api-key",
                        query: "",
                        folderPath: "Team/API",
                        isFolderScoped: true
                    ),
                ]
            ),
        ])

        try List.runJITPreflight(
            scope: .ssh,
            folder: nil,
            parentEnvironment: [:],
            processAncestry: Self.claudeRuntimeAncestry,
            client: client
        )

        #expect(client.payloads.last == AgentJITPreflightPayload(
            requestedCommand: "list",
            references: [
                AgentJITPreflightReference(
                    type: "ssh",
                    query: "",
                    folderPath: nil,
                    isFolderScoped: false
                ),
            ]
        ))

        try List.runJITPreflight(
            scope: .passwords,
            folder: nil,
            parentEnvironment: [AutomationAccessResolver.environmentKey: UUID().uuidString],
            processAncestry: Self.claudeRuntimeAncestry,
            client: client
        )

        #expect(client.payloads.count == 2)

        try List.runJITPreflight(
            scope: .passwords,
            folder: nil,
            parentEnvironment: [:],
            processAncestry: Self.claudeRuntimeAncestry,
            chromeNativeHost: true,
            client: client
        )
        #expect(client.payloads.count == 2)
    }

    private static let humanTerminalAncestry = [
        AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
        AgenticProcessReference(processName: "Terminal", bundleIdentifier: "com.apple.Terminal"),
    ]

    private static let codexAncestry = [
        AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
        AgenticProcessReference(processName: "codex", bundleIdentifier: nil),
    ]

    private static let claudeRuntimeAncestry = [
        AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
        AgenticProcessReference(
            processName: "node",
            bundleIdentifier: nil,
            arguments: ["node", "/opt/homebrew/bin/claude", "--output-format", "stream-json"]
        ),
    ]

    private static let ideExtensionHostAncestry = [
        AgenticProcessReference(processName: "authsia", bundleIdentifier: "com.authsia.cli"),
        AgenticProcessReference(processName: "zsh", bundleIdentifier: nil),
        AgenticProcessReference(
            processName: "Cursor Helper",
            bundleIdentifier: "com.todesktop.230313mzl4w4u92",
            arguments: [
                "/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper",
                "--type=extensionHost",
            ]
        ),
    ]
}

private final class RecordingJITPreflightClient: ExecJITPreflightClient {
    private(set) var payloads: [AgentJITPreflightPayload] = []

    func agentJITPreflight(_ payload: AgentJITPreflightPayload) throws -> AgentJITPreflightResultPayload {
        payloads.append(payload)
        return AgentJITPreflightResultPayload(grantIDs: [])
    }
}
