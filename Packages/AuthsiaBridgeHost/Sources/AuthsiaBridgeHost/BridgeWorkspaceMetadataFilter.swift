#if os(macOS)
import AuthenticatorBridge
import Foundation

public enum BridgeWorkspaceMetadataFilter {
    public enum Failure: LocalizedError, Equatable {
        case invalidRequest(String)

        public var errorDescription: String? {
            switch self {
            case .invalidRequest(let message):
                return message
            }
        }
    }

    private static let maximumReferenceCount = 512

    public static func filteredPayload(_ source: BridgeListPayload, for request: BridgeRequest) throws -> BridgeListPayload {
        guard request.type == .workspaceMetadata,
              let body = request.body else {
            throw Failure.invalidRequest("Invalid workspace metadata request.")
        }

        let payload: WorkspaceMetadataRequestPayload
        do {
            payload = try BridgeCoder.decode(WorkspaceMetadataRequestPayload.self, from: body)
        } catch {
            throw Failure.invalidRequest("Invalid workspace metadata request payload.")
        }

        let workspaceFolder = try requiredFolder(payload.workspaceFolder)
        guard let contextFolder = normalizeFolderPath(request.context.workspaceContext?.authsiaFolder),
              contextFolder == workspaceFolder else {
            throw Failure.invalidRequest("Workspace metadata scope does not match the active workspace.")
        }

        switch payload.mode {
        case .status:
            guard request.context.requestedCommand == BridgeContext.workspaceStatusRequestedCommand else {
                throw Failure.invalidRequest("Workspace metadata status requires the workspace status command.")
            }
            return try statusPayload(source, references: payload.references)
        case .validate:
            guard request.context.requestedCommand == BridgeContext.workspaceEnvValidateRequestedCommand ||
                    request.context.requestedCommand == BridgeContext.workspaceRunRequestedCommand else {
                throw Failure.invalidRequest("Workspace metadata validation requires a supported workspace command.")
            }
            return try exactReferencePayload(
                source,
                references: payload.references,
                operation: "validation"
            )
        case .syncPreview:
            guard request.context.requestedCommand == BridgeContext.workspaceSyncPreviewRequestedCommand,
                  payload.references.isEmpty else {
                throw Failure.invalidRequest("Workspace metadata sync preview request is invalid.")
            }
            return syncPreviewPayload(source, workspaceFolder: workspaceFolder)
        }
    }

    private static func statusPayload(
        _ source: BridgeListPayload,
        references: [WorkspaceMetadataReference]
    ) throws -> BridgeListPayload {
        try exactReferencePayload(
            source,
            references: references,
            operation: "status"
        )
    }

    private static func exactReferencePayload(
        _ source: BridgeListPayload,
        references: [WorkspaceMetadataReference],
        operation: String
    ) throws -> BridgeListPayload {
        guard references.count <= maximumReferenceCount else {
            throw Failure.invalidRequest("Workspace metadata \(operation) request has too many references.")
        }

        let normalizedReferences = try Set(references.map { reference in
            let itemName = reference.itemName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !itemName.isEmpty,
                  itemName.count <= 512,
                  let folderPath = normalizeFolderPath(reference.folderPath) else {
                throw Failure.invalidRequest("Workspace metadata reference is outside the workspace scope.")
            }
            return WorkspaceMetadataReference(
                itemType: reference.itemType,
                itemName: itemName,
                folderPath: folderPath
            )
        })

        func contains(_ type: WorkspaceMetadataItemType, _ name: String, _ folderPath: String?) -> Bool {
            normalizedReferences.contains(
                WorkspaceMetadataReference(
                    itemType: type,
                    itemName: name,
                    folderPath: normalizeFolderPath(folderPath)
                )
            )
        }

        return BridgeListPayload(
            accounts: [],
            passwords: source.passwords.filter {
                $0.isCliEnabled && contains(.password, $0.name, $0.folderPath)
            },
            apiKeys: source.apiKeys.filter {
                $0.isCliEnabled && contains(.apiKey, $0.name, $0.folderPath)
            },
            certificates: source.certificates.filter {
                $0.isCliEnabled && contains(.certificate, $0.name, $0.folderPath)
            },
            notes: source.notes.filter {
                $0.isCliEnabled && contains(.note, $0.title, $0.folderPath)
            },
            sshKeys: source.sshKeys.filter {
                $0.isCliEnabled && contains(.ssh, $0.name, $0.folderPath)
            }
        )
    }

    private static func syncPreviewPayload(
        _ source: BridgeListPayload,
        workspaceFolder: String
    ) -> BridgeListPayload {
        let matchesWorkspace: (String?) -> Bool = {
            normalizeFolderPath($0) == workspaceFolder
        }
        return BridgeListPayload(
            accounts: [],
            passwords: source.passwords.filter { $0.isCliEnabled && matchesWorkspace($0.folderPath) },
            apiKeys: source.apiKeys.filter { $0.isCliEnabled && matchesWorkspace($0.folderPath) },
            certificates: [],
            notes: [],
            sshKeys: []
        )
    }

    private static func requiredFolder(_ value: String) throws -> String {
        guard let folder = normalizeFolderPath(value) else {
            throw Failure.invalidRequest("Workspace metadata folder is missing.")
        }
        return folder
    }

    private static func normalizeFolderPath(_ value: String?) -> String? {
        guard let value else { return nil }
        let segments = value
            .split(separator: "/")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        return segments.isEmpty ? nil : segments.joined(separator: "/")
    }
}
#endif
