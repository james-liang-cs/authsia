import Foundation
import MCP
import Testing
@testable import authsia

@Suite("Local MCP tool contract")
struct MCPToolContractTests {
    @Test("catalog exposes exactly the five frozen tools")
    func catalogExposesExactlyFiveTools() {
        #expect(AuthsiaMCPToolName.allCases.map(\.rawValue) == [
            "authsia_status",
            "authsia_workspace_inspect",
            "authsia_access_status",
            "authsia_exec",
            "authsia_access_revoke",
        ])
        #expect(MCPToolCatalog.descriptors.map(\.name) == AuthsiaMCPToolName.allCases)
        #expect(MCPToolCatalog.tools.map(\.name) == AuthsiaMCPToolName.allCases.map(\.rawValue))
    }

    @Test("tool annotations are conservative")
    func annotationsAreConservative() throws {
        let byName = Dictionary(uniqueKeysWithValues: MCPToolCatalog.descriptors.map { ($0.name, $0) })

        #expect(try #require(byName[.status]).annotations == .readOnly)
        #expect(try #require(byName[.workspaceInspect]).annotations == .readOnly)
        #expect(try #require(byName[.accessStatus]).annotations == .readOnly)
        #expect(try #require(byName[.exec]).annotations == .execution)
        #expect(try #require(byName[.accessRevoke]).annotations == .revocation)
    }

    @Test("exec rejects empty oversized and shell-shaped input")
    func execValidation() throws {
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: []).validated()
        }
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: Array(repeating: "arg", count: 65)).validated()
        }
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: [String(repeating: "x", count: 32_769)]).validated()
        }
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: ["/bin/sh", "-c", "printenv"]).validated()
        }
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: ["tool\0name"]).validated()
        }
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: ["tool"], timeoutSeconds: 0).validated()
        }
        #expect(throws: MCPToolInputError.self) {
            try MCPExecInput(argv: ["tool"], timeoutSeconds: 1_801).validated()
        }

        let input = try MCPExecInput(
            argv: ["swift", "test"],
            environment: "Development",
            envFiles: [".env.local"],
            timeoutSeconds: 30
        ).validated()
        #expect(input.argv == ["swift", "test"])
    }

    @Test("closed decoder rejects unknown fields")
    func closedDecoderRejectsUnknownFields() throws {
        let valid = Data(#"{"argv":["swift","test"]}"#.utf8)
        let decoded: MCPExecInput = try MCPToolInputDecoder.decode(MCPExecInput.self, from: valid)
        #expect(decoded.argv == ["swift", "test"])

        let unknown = Data(#"{"argv":["swift","test"],"shell":"printenv"}"#.utf8)
        #expect(throws: MCPToolInputError.self) {
            let _: MCPExecInput = try MCPToolInputDecoder.decode(MCPExecInput.self, from: unknown)
        }
    }

    @Test("schemas never expose raw-secret shaped output fields")
    func schemasExcludeSecretFields() {
        let forbidden = Set([
            "secret", "value", "token", "environmentValues", "rawRequest", "rawResponse",
        ])
        for descriptor in MCPToolCatalog.descriptors {
            #expect(forbidden.isDisjoint(with: Set(descriptor.outputPropertyNames)))
            #expect(descriptor.description.contains("never returns plaintext secrets"))
            #expect(descriptor.acceptsAdditionalInputProperties == false)
        }

        for tool in MCPToolCatalog.tools {
            #expect(tool.outputSchema != nil)
            #expect(tool.inputSchema.objectValue?["additionalProperties"] == false)
            let variants = tool.outputSchema?.objectValue?["oneOf"]?.arrayValue
            #expect(variants?.count == 2)
            let errorProperties = variants?.last?.objectValue?["properties"]?.objectValue
            #expect(errorProperties?["code"] != nil)
            #expect(errorProperties?["message"] != nil)
            #expect(errorProperties?["invocationID"] != nil)
        }
    }
}
