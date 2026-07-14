// Tests/AuthsiaCLITests/LoadCommandSSHAgentTests.swift
import Testing
import Foundation
@testable import authsia

@Suite("Load.validateSSHFlags")
struct LoadCommandSSHAgentTests {

    @Test("field flag rejected for ssh")
    func sshFlagsValidation_fieldFlagRejected() {
        let result = Load.validateSSHFlags(
            field: .privateKey,
            format: .shell,
            silent: false,
            systemAgent: true,
            ttlSeconds: 300
        )
        #expect(!result.isValid)
        #expect(result.errorMessage?.contains("--field") == true)
    }

    @Test("format json rejected for ssh")
    func sshFlagsValidation_formatFlagRejected() {
        let result = Load.validateSSHFlags(
            field: nil,
            format: .json,
            silent: false,
            systemAgent: true,
            ttlSeconds: 300
        )
        #expect(!result.isValid)
        #expect(result.errorMessage?.contains("--format") == true)
    }

    @Test("silent rejected for ssh")
    func sshFlagsValidation_silentFlagRejected() {
        let result = Load.validateSSHFlags(
            field: nil,
            format: .shell,
            silent: true,
            systemAgent: true,
            ttlSeconds: 300
        )
        #expect(!result.isValid)
        #expect(result.errorMessage?.contains("--silent") == true)
    }

    @Test("system agent opt-in is required for ssh")
    func sshFlagsValidation_requiresSystemAgent() {
        let result = Load.validateSSHFlags(
            field: nil,
            format: .shell,
            silent: false,
            systemAgent: false,
            ttlSeconds: 300
        )
        #expect(!result.isValid)
        #expect(result.errorMessage?.contains("--system-agent") == true)
    }

    @Test("system agent opt-in refusal is a runtime error without usage")
    func sshLoadWithoutSystemAgentThrowsRuntimeError() throws {
        let command = try Load.parse(["ssh", "id_ed25519"])

        do {
            try command.run()
            Issue.record("expected CLIError")
        } catch let error as CLIError {
            #expect(error.message.contains("Use the built-in Authsia SSH agent"))
            #expect(error.message.contains("Usage:") == false)
        } catch {
            Issue.record("expected CLIError, got \(error)")
        }
    }

    @Test("ttl is required for system ssh-agent")
    func sshFlagsValidation_requiresTTL() {
        let result = Load.validateSSHFlags(
            field: nil,
            format: .shell,
            silent: false,
            systemAgent: true,
            ttlSeconds: nil
        )
        #expect(!result.isValid)
        #expect(result.errorMessage?.contains("--ttl") == true)
    }

    @Test("system agent with ttl is valid for ssh")
    func sshFlagsValidation_systemAgentWithTTL_isValid() {
        let result = Load.validateSSHFlags(
            field: nil,
            format: .shell,
            silent: false,
            systemAgent: true,
            ttlSeconds: 300
        )
        #expect(result.isValid)
        #expect(result.errorMessage == nil)
    }

    @Test("policy-bound ssh references are rejected for system agent")
    func rejectsPolicyBoundSSHReferenceAsRuntimeError() throws {
        let reference = Load.ItemReference(
            id: UUID().uuidString,
            name: "deploy",
            folderPath: "Team/API",
            isCliEnabled: true,
            isScraped: false,
            scrapeMachineName: nil,
            scrapeMachineId: nil,
            sshApprovalPolicy: "sessionBased",
            sshBoundHosts: ["github.com"]
        )

        do {
            try Load.validateSSHSystemAgentReference(reference)
            Issue.record("expected CLIError")
        } catch let error as CLIError {
            #expect(error.message.contains("Refusing to load policy-bound SSH key 'deploy'"))
            #expect(error.message.contains("Usage:") == false)
        } catch {
            Issue.record("expected CLIError, got \(error)")
        }
    }
}
