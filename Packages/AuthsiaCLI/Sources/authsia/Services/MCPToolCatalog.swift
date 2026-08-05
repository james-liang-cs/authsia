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
    static let mediatedRead = MCPToolAnnotations(
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
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
            name: .list,
            description: "List scoped CLI-enabled Vault item metadata through list-only Agent JIT." + noPlaintext,
            annotations: .mediatedRead,
            inputPropertyNames: ["type", "folder", "environment", "limit", "offset"],
            requiredInputPropertyNames: ["type"],
            outputPropertyNames: [
                "invocationID", "type", "folder", "environment", "items", "totalCount",
                "count", "offset", "hasMore", "nextOffset",
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
        case .list:
            return [
                "type": .object([
                    "type": "string",
                    "enum": .array(MCPListItemType.allCases.map { .string($0.rawValue) }),
                ]),
                "folder": stringSchema,
                "environment": stringSchema,
                "limit": .object([
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                ]),
                "offset": .object([
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100_000,
                ]),
            ]
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
        let successSchema = Value.object([
            "type": "object",
            "properties": .object(successProperties(for: descriptor)),
            "required": .array(requiredSuccessPropertyNames(for: descriptor).map(Value.string)),
            "additionalProperties": false,
        ])
        let errorSchema = Value.object([
            "type": "object",
            "properties": .object([
                "code": .object([
                    "type": "string",
                    "enum": .array(MCPToolErrorCode.allCases.map { .string($0.rawValue) }),
                ]),
                "message": stringSchema,
                "invocationID": .object([
                    "type": .array(["string", "null"]),
                ]),
            ]),
            "required": .array(["code", "message"]),
            "additionalProperties": false,
        ])
        return .object([
            "type": "object",
            "oneOf": .array([successSchema, errorSchema]),
        ])
    }

    private static func successProperties(
        for descriptor: MCPToolDescriptor
    ) -> [String: Value] {
        let nullableString = Value.object(["type": .array(["string", "null"])])
        let nullableInteger = Value.object(["type": .array(["integer", "null"])])
        let nullableNumber = Value.object(["type": .array(["number", "null"])])
        switch descriptor.name {
        case .status:
            return [
                "serverInstanceID": stringSchema,
                "protocolRevision": stringSchema,
                "workspaceName": stringSchema,
                "workspaceRoot": stringSchema,
                "bridgeState": .object([
                    "type": "string",
                    "enum": .array(["ready", "unavailable", "cliAccessDisabled"]),
                ]),
                "ready": booleanSchema,
                "diagnostics": diagnosticsSchema,
            ]
        case .workspaceInspect:
            return [
                "workspaceName": stringSchema,
                "workspaceRoot": stringSchema,
                "schemaVersion": integerSchema,
                "selectedEnvironment": nullableString,
                "availableEnvironments": stringArraySchema,
                "managedFiles": stringArraySchema,
                "references": .object([
                    "type": "array",
                    "items": .object([
                        "type": "object",
                        "properties": .object([
                            "uri": stringSchema,
                            "environmentVariable": nullableString,
                            "sourcePath": stringSchema,
                            "selectedEnvironment": booleanSchema,
                        ]),
                        "required": .array(["uri", "sourcePath", "selectedEnvironment"]),
                        "additionalProperties": false,
                    ]),
                    "maxItems": 1_000,
                ]),
                "referencesTruncated": booleanSchema,
                "diagnostics": diagnosticsSchema,
            ]
        case .list:
            return [
                "invocationID": stringSchema,
                "type": .object([
                    "type": "string",
                    "enum": .array(MCPListItemType.allCases.map { .string($0.rawValue) }),
                ]),
                "folder": stringSchema,
                "environment": nullableString,
                "items": .object([
                    "type": "array",
                    "items": .object([
                        "type": "object",
                        "properties": .object([
                            "id": stringSchema,
                            "name": stringSchema,
                            "folderPath": nullableString,
                            "isFavorite": booleanSchema,
                            "isCliEnabled": booleanSchema,
                            "environments": stringArraySchema,
                        ]),
                        "required": .array([
                            "id", "name", "isFavorite", "isCliEnabled", "environments",
                        ]),
                        "additionalProperties": false,
                    ]),
                    "maxItems": 100,
                ]),
                "totalCount": nonnegativeIntegerSchema,
                "count": .object(["type": "integer", "minimum": 0, "maximum": 100]),
                "offset": nonnegativeIntegerSchema,
                "hasMore": booleanSchema,
                "nextOffset": nullableInteger,
            ]
        case .accessStatus:
            return [
                "grants": .object([
                    "type": "array",
                    "items": .object([
                        "type": "object",
                        "properties": .object([
                            "grantID": stringSchema,
                            "status": .object([
                                "type": "string",
                                "enum": .array(["active", "expired", "revoked"]),
                            ]),
                            "sourceLabel": stringSchema,
                            "scopeSummary": stringSchema,
                            "itemCount": nonnegativeIntegerSchema,
                            "capabilities": stringArraySchema,
                            "environment": nullableString,
                            "createdAt": numberSchema,
                            "expiresAt": numberSchema,
                            "lastUsedAt": nullableNumber,
                            "revokedAt": nullableNumber,
                            "approvedBy": stringSchema,
                            "serverInstanceID": stringSchema,
                            "invocationID": nullableString,
                        ]),
                        "required": .array([
                            "grantID", "status", "sourceLabel", "scopeSummary", "itemCount",
                            "capabilities", "createdAt", "expiresAt", "approvedBy",
                            "serverInstanceID",
                        ]),
                        "additionalProperties": false,
                    ]),
                ]),
            ]
        case .exec:
            return [
                "invocationID": stringSchema,
                "termination": .object([
                    "type": "string",
                    "enum": .array(MCPExecutionTermination.allCases.map { .string($0.rawValue) }),
                ]),
                "exitCode": nullableInteger,
                "stdout": stringSchema,
                "stderr": stringSchema,
                "stdoutTruncated": booleanSchema,
                "stderrTruncated": booleanSchema,
                "durationMilliseconds": nonnegativeIntegerSchema,
            ]
        case .accessRevoke:
            return [
                "grantID": stringSchema,
                "status": .object(["type": "string", "enum": .array(["revoked"])]),
                "revokedAt": nullableNumber,
            ]
        }
    }

    private static func requiredSuccessPropertyNames(
        for descriptor: MCPToolDescriptor
    ) -> [String] {
        switch descriptor.name {
        case .status:
            descriptor.outputPropertyNames
        case .workspaceInspect:
            descriptor.outputPropertyNames.filter { $0 != "selectedEnvironment" }
        case .list:
            descriptor.outputPropertyNames.filter { $0 != "environment" && $0 != "nextOffset" }
        case .accessStatus:
            descriptor.outputPropertyNames
        case .exec:
            descriptor.outputPropertyNames.filter { $0 != "exitCode" }
        case .accessRevoke:
            descriptor.outputPropertyNames.filter { $0 != "revokedAt" }
        }
    }

    private static let stringSchema = Value.object(["type": "string"])
    private static let booleanSchema = Value.object(["type": "boolean"])
    private static let integerSchema = Value.object(["type": "integer"])
    private static let numberSchema = Value.object(["type": "number"])
    private static let nonnegativeIntegerSchema = Value.object(["type": "integer", "minimum": 0])
    private static let stringArraySchema = Value.object([
        "type": "array",
        "items": stringSchema,
    ])
    private static let diagnosticsSchema = Value.object([
        "type": "array",
        "items": .object([
            "type": "object",
            "properties": .object([
                "code": stringSchema,
                "message": stringSchema,
            ]),
            "required": .array(["code", "message"]),
            "additionalProperties": false,
        ]),
        "maxItems": 100,
    ])
}
