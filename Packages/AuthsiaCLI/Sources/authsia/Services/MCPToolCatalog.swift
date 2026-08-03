import Foundation
import MCP

struct MCPToolAnnotations: Equatable, Sendable {
    let readOnlyHint: Bool
    let destructiveHint: Bool
    let idempotentHint: Bool
    let openWorldHint: Bool

    static let readOnly = MCPToolAnnotations(
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false
    )
    static let execution = MCPToolAnnotations(
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true
    )
    static let revocation = MCPToolAnnotations(
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: true,
        openWorldHint: false
    )
}

struct MCPToolDescriptor: Equatable, Sendable {
    let name: AuthsiaMCPToolName
    let description: String
    let annotations: MCPToolAnnotations
    let inputPropertyNames: [String]
    let requiredInputPropertyNames: [String]
    let outputPropertyNames: [String]
    let acceptsAdditionalInputProperties: Bool
}

enum MCPToolCatalog {
    private static let noPlaintext = " This tool never returns plaintext secrets."

    static let descriptors: [MCPToolDescriptor] = [
        MCPToolDescriptor(
            name: .status,
            description: "Report local Authsia Bridge and workspace readiness." + noPlaintext,
            annotations: .readOnly,
            inputPropertyNames: [],
            requiredInputPropertyNames: [],
            outputPropertyNames: [
                "serverInstanceID", "protocolRevision", "workspaceName", "workspaceRoot",
                "bridgeState", "ready", "diagnostics",
            ],
            acceptsAdditionalInputProperties: false
        ),
        MCPToolDescriptor(
            name: .workspaceInspect,
            description: "Inspect commit-safe workspace configuration and declared authsia references." + noPlaintext,
            annotations: .readOnly,
            inputPropertyNames: ["environment"],
            requiredInputPropertyNames: [],
            outputPropertyNames: [
                "workspaceName", "workspaceRoot", "schemaVersion", "selectedEnvironment",
                "availableEnvironments", "managedFiles", "references", "referencesTruncated",
                "diagnostics",
            ],
            acceptsAdditionalInputProperties: false
        ),
        MCPToolDescriptor(
            name: .accessStatus,
            description: "Report Agent JIT grants owned by this MCP server instance." + noPlaintext,
            annotations: .readOnly,
            inputPropertyNames: [],
            requiredInputPropertyNames: [],
            outputPropertyNames: ["grants"],
            acceptsAdditionalInputProperties: false
        ),
        MCPToolDescriptor(
            name: .exec,
            description: "Run argv through Authsia Workspace and Agent JIT mediation." + noPlaintext,
            annotations: .execution,
            inputPropertyNames: ["argv", "environment", "defaultOnly", "envFiles", "timeoutSeconds"],
            requiredInputPropertyNames: ["argv"],
            outputPropertyNames: [
                "invocationID", "termination", "exitCode", "stdout", "stderr",
                "stdoutTruncated", "stderrTruncated", "durationMilliseconds",
            ],
            acceptsAdditionalInputProperties: false
        ),
        MCPToolDescriptor(
            name: .accessRevoke,
            description: "Revoke one active Agent JIT grant owned by this MCP server instance." + noPlaintext,
            annotations: .revocation,
            inputPropertyNames: ["grantID"],
            requiredInputPropertyNames: ["grantID"],
            outputPropertyNames: ["grantID", "status", "revokedAt"],
            acceptsAdditionalInputProperties: false
        ),
    ]

    static let tools: [Tool] = descriptors.map { descriptor in
        Tool(
            name: descriptor.name.rawValue,
            description: descriptor.description,
            inputSchema: inputSchema(for: descriptor),
            annotations: Tool.Annotations(
                readOnlyHint: descriptor.annotations.readOnlyHint,
                destructiveHint: descriptor.annotations.destructiveHint,
                idempotentHint: descriptor.annotations.idempotentHint,
                openWorldHint: descriptor.annotations.openWorldHint
            ),
            outputSchema: outputSchema(for: descriptor)
        )
    }

    private static func inputSchema(for descriptor: MCPToolDescriptor) -> Value {
        .object([
            "type": "object",
            "properties": .object(inputProperties(for: descriptor.name)),
            "required": .array(descriptor.requiredInputPropertyNames.map(Value.string)),
            "additionalProperties": .bool(descriptor.acceptsAdditionalInputProperties),
        ])
    }

    private static func inputProperties(for name: AuthsiaMCPToolName) -> [String: Value] {
        switch name {
        case .status, .accessStatus:
            return [:]
        case .workspaceInspect:
            return ["environment": stringSchema]
        case .exec:
            return [
                "argv": .object([
                    "type": "array",
                    "items": stringSchema,
                    "minItems": 1,
                    "maxItems": 64,
                ]),
                "environment": stringSchema,
                "defaultOnly": .object(["type": "boolean"]),
                "envFiles": .object([
                    "type": "array",
                    "items": stringSchema,
                ]),
                "timeoutSeconds": .object([
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1_800,
                ]),
            ]
        case .accessRevoke:
            return ["grantID": stringSchema]
        }
    }

    private static func outputSchema(for descriptor: MCPToolDescriptor) -> Value {
        .object([
            "type": "object",
            "properties": .object(
                Dictionary(uniqueKeysWithValues: descriptor.outputPropertyNames.map {
                    ($0, Value.object([:]))
                })
            ),
            "additionalProperties": false,
        ])
    }

    private static let stringSchema = Value.object(["type": "string"])
}
