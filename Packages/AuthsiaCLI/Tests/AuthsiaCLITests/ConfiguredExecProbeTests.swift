import Foundation
import Testing
@testable import authsia

@Suite("ConfiguredExecDefaults")
struct ConfiguredExecDefaultsTests {
    /// Programmatic Exec construction bypasses ArgumentParser parsing, so wrapper
    /// defaults are never materialized; reading an unassigned @Option/@Argument/@Flag
    /// traps at runtime. Guard that configuredExec assigns every parsable property.
    @Test("configured exec materializes every parsable property")
    func configuredExecMaterializesEveryParsableProperty() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("configured-exec-defaults-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let config = WorkspaceConfig(
            workspace: WorkspaceConfig.Workspace(
                name: "Agent leak validation",
                authsiaFolder: "AuthsiaValidation/Probe"
            ),
            managedEnvFiles: [],
            agents: WorkspaceConfig.Agents(rules: ["claude-code"]),
            envBindings: [
                WorkspaceConfig.EnvBinding(
                    name: "AUTHSIA_BATCH_ALLOW_A",
                    reference: "authsia://password/ITEM_A/password?folder=AuthsiaValidation%2FProbe%2FParent%2FNested"
                ),
                WorkspaceConfig.EnvBinding(
                    name: "AUTHSIA_BATCH_ALLOW_B",
                    reference: "authsia://password/ITEM_B/password?folder=AuthsiaValidation%2FProbe%2FSeparate"
                ),
            ]
        )
        try WorkspaceConfigStore.write(config, toWorkspaceRoot: root)

        let plan = try WorkspaceRunPlan.build(
            startingAt: root,
            extraEnvFiles: [],
            commandArgs: ["sh", "-c", "printf x"]
        )
        let exec = Workspace.Run.configuredExec(for: plan)

        #expect(exec.type == nil)
        #expect(exec.query == nil)
        #expect(exec.typeOption == nil)
        #expect(exec.queryOption == nil)
        #expect(exec.folder == nil)
        #expect(exec.env == nil)
        #expect(exec.all == false)
        #expect(exec.allMachines == false)
        #expect(exec.outputPolicy == .strict)
        #expect(exec.field == nil)
        #expect(exec.envFile.isEmpty)
        #expect(exec.shellCommandParts.isEmpty)
        #expect(exec.commandArgs == ["sh", "-c", "printf x"])
        #expect(exec.environmentOverrides.count == 2)
        #expect(exec.usesShell == false)
    }
}
