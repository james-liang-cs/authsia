import Darwin
import Foundation
import AuthenticatorBridge

enum InjectedSecretFileScrubOutcome: Equatable, Sendable {
    case scrubbed
    case detected
    case noMatch
    case notFound
    case outsideAllowedRoots
    case verificationFailed
    case remediationFailed
}

enum InjectedSecretFileScrubMode: Equatable, Sendable {
    case detectOnly
    case remediate
}

struct InjectedSecretFileScrubResult: Equatable, Sendable {
    let path: String
    let outcome: InjectedSecretFileScrubOutcome
    let events: [AgentFileActivityEvent]

    init(
        path: String,
        outcome: InjectedSecretFileScrubOutcome,
        event: AgentFileActivityEvent?
    ) {
        self.path = path
        self.outcome = outcome
        events = event.map { [$0] } ?? []
    }

    init(
        path: String,
        outcome: InjectedSecretFileScrubOutcome,
        events: [AgentFileActivityEvent]
    ) {
        self.path = path
        self.outcome = outcome
        self.events = events
    }

    var event: AgentFileActivityEvent? {
        events.count == 1 ? events[0] : nil
    }

    var isIncomplete: Bool {
        outcome == .detected
            || outcome == .outsideAllowedRoots
            || outcome == .verificationFailed
            || outcome == .remediationFailed
    }
}

enum InjectedSecretFileCleanupStatus: Equatable, Sendable {
    case notRequested
    case complete
    case incomplete

    static func forRequestedCleanup(_ results: [InjectedSecretFileScrubResult]) -> Self {
        results.contains { $0.isIncomplete } ? .incomplete : .complete
    }
}

struct InjectedSecretFileScrubContext: Equatable, Sendable {
    let agentJITGrantIDs: [UUID]
    let agentPlatform: String?
    let terminalSessionScope: String?
    let workingDirectory: String?
    let workspaceRoot: String?
}

struct InjectedSecretFileScrubHooks {
    let afterTargetOpened: (() throws -> Void)?
    let targetRead: ((Int) -> Void)?
    let beforeRewrite: (() throws -> Void)?
    let afterRewrite: (() throws -> Void)?

    init(
        afterTargetOpened: (() throws -> Void)? = nil,
        targetRead: ((Int) -> Void)? = nil,
        beforeRewrite: (() throws -> Void)? = nil,
        afterRewrite: (() throws -> Void)? = nil
    ) {
        self.afterTargetOpened = afterTargetOpened
        self.targetRead = targetRead
        self.beforeRewrite = beforeRewrite
        self.afterRewrite = afterRewrite
    }
}

enum InjectedSecretFileScrubber {
    static let defaultMaxBytes = 2 * 1024 * 1024
    static let defaultMaximumPaths = 10_000
    static let defaultMaximumTotalBytes = 32 * 1024 * 1024
    static let defaultMaximumDuration: TimeInterval = 1
    private static let maximumXattrNameListBytes = 64 * 1024
    private static let maximumMetadataBytes = 2 * 1024 * 1024
    private static let maximumACLBytes = 64 * 1024

    static func scrub(
        paths: [String],
        masker: OutputMasker,
        allowedRoots: [String],
        context: InjectedSecretFileScrubContext,
        eventMetadataMasker: OutputMasker? = nil,
        maxBytes: Int = defaultMaxBytes,
        fileManager _: FileManager = .default,
        now: Date = Date(),
        maximumPaths: Int = defaultMaximumPaths,
        maximumTotalBytes: Int = defaultMaximumTotalBytes,
        maximumDuration: TimeInterval = defaultMaximumDuration,
        monotonicNow: () -> TimeInterval = {
            ProcessInfo.processInfo.systemUptime
        },
        mode: InjectedSecretFileScrubMode,
        hooks: InjectedSecretFileScrubHooks = InjectedSecretFileScrubHooks()
    ) -> [InjectedSecretFileScrubResult] {
        scrub(
            paths: paths,
            masker: masker,
            allowedRootBindings: allowedRoots.compactMap {
                InjectedFileTouchRootBinding(path: $0)
            },
            context: context,
            eventMetadataMasker: eventMetadataMasker,
            maxBytes: maxBytes,
            now: now,
            maximumPaths: maximumPaths,
            maximumTotalBytes: maximumTotalBytes,
            maximumDuration: maximumDuration,
            monotonicNow: monotonicNow,
            mode: mode,
            hooks: hooks
        )
    }

    static func scrub(
        paths: [String],
        masker: OutputMasker,
        allowedRootBindings: [InjectedFileTouchRootBinding],
        context: InjectedSecretFileScrubContext,
        eventMetadataMasker: OutputMasker? = nil,
        maxBytes: Int = defaultMaxBytes,
        fileManager _: FileManager = .default,
        now: Date = Date(),
        maximumPaths: Int = defaultMaximumPaths,
        maximumTotalBytes: Int = defaultMaximumTotalBytes,
        maximumDuration: TimeInterval = defaultMaximumDuration,
        monotonicNow: () -> TimeInterval = {
            ProcessInfo.processInfo.systemUptime
        },
        mode: InjectedSecretFileScrubMode,
        hooks: InjectedSecretFileScrubHooks = InjectedSecretFileScrubHooks()
    ) -> [InjectedSecretFileScrubResult] {
        var seen = Set<String>()
        var results: [InjectedSecretFileScrubResult] = []
        var inspectedPaths = 0
        var totalBytesRead = 0
        let deadline = monotonicNow() + maximumDuration

        for rawPath in paths {
            let path = URL(fileURLWithPath: rawPath).standardizedFileURL.path
            guard seen.insert(path).inserted else { continue }
            guard inspectedPaths < maximumPaths,
                  maximumDuration > 0,
                  monotonicNow() < deadline else {
                results.append(budgetExceededResult(path: path))
                break
            }
            inspectedPaths += 1
            let containmentPath = canonicalContainmentPath(for: path)
            let containingRootBindings = allowedRootBindings.filter {
                isUnderAllowedRoot(containmentPath, roots: [$0.path])
            }
            guard !containingRootBindings.isEmpty else {
                results.append(
                    InjectedSecretFileScrubResult(
                        path: path,
                        outcome: .outsideAllowedRoots,
                        event: nil
                    )
                )
                continue
            }
            guard containingRootBindings.contains(where: {
                $0.matchesCurrentIdentity()
            }) else {
                results.append(
                    verificationFailedResult(
                        path: path,
                        masker: eventMetadataMasker ?? masker,
                        context: context,
                        mode: mode,
                        now: now
                    )
                )
                continue
            }

            guard maximumTotalBytes > totalBytesRead else {
                results.append(budgetExceededResult(path: path))
                break
            }
            let remainingBytes = maximumTotalBytes - totalBytesRead
            let budgetedMaxBytes = remainingBytes <= maxBytes
                ? max(0, remainingBytes - 1)
                : maxBytes
            var bytesRead = 0
            let budgetedHooks = InjectedSecretFileScrubHooks(
                afterTargetOpened: hooks.afterTargetOpened,
                targetRead: { count in
                    bytesRead = count
                    hooks.targetRead?(count)
                },
                beforeRewrite: hooks.beforeRewrite,
                afterRewrite: hooks.afterRewrite
            )
            let result = scrubOne(
                path: path,
                masker: eventMetadataMasker ?? masker,
                contentMasker: masker,
                context: context,
                maxBytes: budgetedMaxBytes,
                allowedRootBindings: allowedRootBindings,
                now: now,
                mode: mode,
                hooks: budgetedHooks
            )
            totalBytesRead += bytesRead
            if budgetedMaxBytes < maxBytes,
               result.outcome == .verificationFailed {
                results.append(budgetExceededResult(path: path))
                break
            }
            results.append(result)
        }

        return results
    }

    static func record(
        results: [InjectedSecretFileScrubResult],
        store: AgentFileActivityStore
    ) {
        for result in results {
            for event in result.events {
                try? store.record(event)
            }
        }
    }

    private static func budgetExceededResult(
        path: String
    ) -> InjectedSecretFileScrubResult {
        InjectedSecretFileScrubResult(
            path: path,
            outcome: .verificationFailed,
            event: nil
        )
    }

    private static func scrubOne(
        path: String,
        masker: OutputMasker,
        contentMasker: OutputMasker,
        context: InjectedSecretFileScrubContext,
        maxBytes: Int,
        allowedRootBindings: [InjectedFileTouchRootBinding],
        now: Date,
        mode: InjectedSecretFileScrubMode,
        hooks: InjectedSecretFileScrubHooks
    ) -> InjectedSecretFileScrubResult {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        let targetName = url.lastPathComponent
        let canonicalParent = url
            .deletingLastPathComponent()
            .resolvingSymlinksInPath()
            .path
        let directoryDescriptor = Darwin.open(
            canonicalParent,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard directoryDescriptor >= 0 else {
            if errno == ENOENT {
                return InjectedSecretFileScrubResult(path: path, outcome: .notFound, event: nil)
            }
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }
        defer { Darwin.close(directoryDescriptor) }

        guard directoryIsUnderValidatedRoot(
            directoryDescriptor,
            allowedRootBindings: allowedRootBindings
        ) else {
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }

        var initialEntryMetadata = stat()
        guard Darwin.fstatat(
            directoryDescriptor,
            targetName,
            &initialEntryMetadata,
            AT_SYMLINK_NOFOLLOW
        ) == 0 else {
            if errno == ENOENT {
                return InjectedSecretFileScrubResult(path: path, outcome: .notFound, event: nil)
            }
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }
        guard metadataIsSafe(initialEntryMetadata, maxBytes: maxBytes) else {
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }

        guard directoryIsUnderValidatedRoot(
            directoryDescriptor,
            allowedRootBindings: allowedRootBindings
        ) else {
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }
        let targetDescriptor = Darwin.openat(
            directoryDescriptor,
            targetName,
            (mode == .detectOnly ? O_RDONLY : O_RDWR) | O_NOFOLLOW | O_CLOEXEC
        )
        guard targetDescriptor >= 0 else {
            if errno == ENOENT {
                return InjectedSecretFileScrubResult(path: path, outcome: .notFound, event: nil)
            }
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }
        defer { Darwin.close(targetDescriptor) }

        var initialTargetMetadata = stat()
        guard directoryIsUnderValidatedRoot(
                directoryDescriptor,
                allowedRootBindings: allowedRootBindings
              ),
              Darwin.fstat(targetDescriptor, &initialTargetMetadata) == 0,
              metadataIsSafe(initialTargetMetadata, maxBytes: maxBytes),
              metadataIsUnchanged(initialEntryMetadata, initialTargetMetadata) else {
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }

        let data: Data
        do {
            try hooks.afterTargetOpened?()
            data = try readCapped(from: targetDescriptor, maxBytes: maxBytes)
            hooks.targetRead?(data.count)
        } catch {
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }

        guard data.count <= maxBytes,
              let content = String(data: data, encoding: .utf8) else {
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }

        let masked = contentMasker.mask(content)
        guard masked != content else {
            return InjectedSecretFileScrubResult(path: path, outcome: .noMatch, event: nil)
        }

        guard targetIsUnchanged(
            directoryDescriptor: directoryDescriptor,
            targetDescriptor: targetDescriptor,
            targetName: targetName,
            initialMetadata: initialTargetMetadata
        ) else {
            return verificationFailedResult(
                path: path,
                masker: masker,
                context: context,
                mode: mode,
                now: now
            )
        }

        if mode == .detectOnly {
            return InjectedSecretFileScrubResult(
                path: path,
                outcome: .detected,
                events: makeEvents(
                    path: path,
                    masker: masker,
                    context: context,
                    detail: InjectedSecretFileActivityDetail.secretDetected,
                    action: .modify,
                    status: .inferred,
                    now: now
                )
            )
        }

        do {
            try rewriteAndVerify(
                directoryDescriptor: directoryDescriptor,
                targetDescriptor: targetDescriptor,
                targetName: targetName,
                originalData: data,
                maskedData: Data(masked.utf8),
                originalMetadata: initialTargetMetadata,
                allowedRootBindings: allowedRootBindings,
                masker: contentMasker,
                hooks: hooks
            )
        } catch {
            return failedResult(
                path: path,
                outcome: .remediationFailed,
                masker: masker,
                context: context,
                detail: InjectedSecretFileActivityDetail.remediationFailed,
                now: now
            )
        }

        return InjectedSecretFileScrubResult(
            path: path,
            outcome: .scrubbed,
            events: makeEvents(
                path: path,
                masker: masker,
                context: context,
                detail: InjectedSecretFileActivityDetail.scrubbed,
                action: .modify,
                status: .succeeded,
                now: now
            )
        )
    }

    private static func verificationFailedResult(
        path: String,
        masker: OutputMasker,
        context: InjectedSecretFileScrubContext,
        mode: InjectedSecretFileScrubMode,
        now: Date
    ) -> InjectedSecretFileScrubResult {
        failedResult(
            path: path,
            outcome: .verificationFailed,
            masker: masker,
            context: context,
            detail: mode == .detectOnly
                ? InjectedSecretFileActivityDetail.inspectionFailed
                : InjectedSecretFileActivityDetail.verificationFailed,
            now: now
        )
    }

    private static func failedResult(
        path: String,
        outcome: InjectedSecretFileScrubOutcome,
        masker: OutputMasker,
        context: InjectedSecretFileScrubContext,
        detail: String,
        now: Date
    ) -> InjectedSecretFileScrubResult {
        InjectedSecretFileScrubResult(
            path: path,
            outcome: outcome,
            events: makeEvents(
                path: path,
                masker: masker,
                context: context,
                detail: detail,
                action: .modify,
                status: .failed,
                now: now
            )
        )
    }

    private static func makeEvents(
        path: String,
        masker: OutputMasker,
        context: InjectedSecretFileScrubContext,
        detail: String,
        action: AgentFileActivityAction,
        status: AgentFileActivityStatus,
        now: Date
    ) -> [AgentFileActivityEvent] {
        let uniqueGrantIDs = Set(context.agentJITGrantIDs)
            .sorted { $0.uuidString < $1.uuidString }
        let grantIDs: [UUID?] = uniqueGrantIDs.isEmpty ? [nil] : uniqueGrantIDs

        return grantIDs.map { grantID in
            AgentFileActivityEvent(
                recordedAt: now,
                agentPlatform: context.agentPlatform,
                agentJITGrantID: grantID,
                captureSource: .injectedExec,
                workingDirectory: context.workingDirectory.map(masker.mask),
                terminalSessionScope: context.terminalSessionScope,
                workspaceRoot: context.workspaceRoot.map(masker.mask),
                path: masker.mask(path),
                kind: .file,
                action: action,
                status: status,
                confidence: .direct,
                detail: detail
            )
        }
    }

    private static func rewriteAndVerify(
        directoryDescriptor: Int32,
        targetDescriptor: Int32,
        targetName: String,
        originalData: Data,
        maskedData: Data,
        originalMetadata: stat,
        allowedRootBindings: [InjectedFileTouchRootBinding],
        masker: OutputMasker,
        hooks: InjectedSecretFileScrubHooks
    ) throws {
        guard targetIsUnchanged(
            directoryDescriptor: directoryDescriptor,
            targetDescriptor: targetDescriptor,
            targetName: targetName,
            initialMetadata: originalMetadata
        ) else {
            throw POSIXFailure.operationFailed
        }
        let originalMetadataSnapshot = try metadataSnapshot(
            of: targetDescriptor,
            timestampSource: originalMetadata
        )

        try hooks.beforeRewrite?()
        guard targetIsUnchanged(
            directoryDescriptor: directoryDescriptor,
            targetDescriptor: targetDescriptor,
            targetName: targetName,
            initialMetadata: originalMetadata
        ) else {
            throw POSIXFailure.operationFailed
        }
        let metadataBeforeRewrite = try metadataSnapshot(
            of: targetDescriptor,
            timestampSource: originalMetadata
        )
        guard metadataBeforeRewrite == originalMetadataSnapshot,
              directoryIsUnderValidatedRoot(
                directoryDescriptor,
                allowedRootBindings: allowedRootBindings
              ) else {
            throw POSIXFailure.operationFailed
        }

        var rewriteStarted = false
        do {
            rewriteStarted = true
            try replaceContents(of: targetDescriptor, with: maskedData)
            guard restoreMetadata(
                originalMetadataSnapshot,
                on: targetDescriptor
            ),
                  Darwin.fsync(targetDescriptor) == 0 else {
                throw POSIXFailure.operationFailed
            }

            try hooks.afterRewrite?()
            guard directoryIsUnderValidatedRoot(
                directoryDescriptor,
                allowedRootBindings: allowedRootBindings
            ) else {
                throw POSIXFailure.operationFailed
            }

            var rewrittenMetadata = stat()
            var rewrittenEntryMetadata = stat()
            guard Darwin.fstat(targetDescriptor, &rewrittenMetadata) == 0,
                  Darwin.fstatat(
                    directoryDescriptor,
                    targetName,
                    &rewrittenEntryMetadata,
                    AT_SYMLINK_NOFOLLOW
                  ) == 0,
                  metadataHasIdentity(rewrittenMetadata, of: originalMetadata),
                  metadataIsUnchanged(rewrittenEntryMetadata, rewrittenMetadata),
                  rewrittenMetadata.st_nlink == originalMetadata.st_nlink,
                  rewrittenMetadata.st_mode == originalMetadata.st_mode,
                  rewrittenMetadata.st_uid == originalMetadata.st_uid,
                  rewrittenMetadata.st_gid == originalMetadata.st_gid,
                  rewrittenMetadata.st_size == off_t(maskedData.count),
                  rewrittenMetadata.st_mtimespec.tv_sec
                    == originalMetadata.st_mtimespec.tv_sec,
                  rewrittenMetadata.st_mtimespec.tv_nsec
                    == originalMetadata.st_mtimespec.tv_nsec else {
                throw POSIXFailure.operationFailed
            }
            let metadataAfterHook = try metadataSnapshot(of: targetDescriptor)
            guard metadataAfterHook == originalMetadataSnapshot else {
                throw POSIXFailure.operationFailed
            }

            let verifiedData = try readCapped(
                from: targetDescriptor,
                maxBytes: maskedData.count
            )
            guard verifiedData == maskedData,
                  let verifiedText = String(data: verifiedData, encoding: .utf8),
                  masker.mask(verifiedText) == verifiedText,
                  restoreTimestamps(
                    on: targetDescriptor,
                    from: originalMetadataSnapshot
                  ),
                  Darwin.fsync(targetDescriptor) == 0 else {
                throw POSIXFailure.operationFailed
            }

            var finalMetadata = stat()
            var finalEntryMetadata = stat()
            guard Darwin.fstat(targetDescriptor, &finalMetadata) == 0,
                  Darwin.fstatat(
                    directoryDescriptor,
                    targetName,
                    &finalEntryMetadata,
                    AT_SYMLINK_NOFOLLOW
                  ) == 0,
                  metadataHasIdentity(finalMetadata, of: originalMetadata),
                  metadataIsUnchanged(finalEntryMetadata, finalMetadata),
                  finalMetadata.st_nlink == originalMetadata.st_nlink,
                  finalMetadata.st_size == off_t(maskedData.count),
                  try metadataSnapshot(of: targetDescriptor)
                    == originalMetadataSnapshot,
                  directoryIsUnderValidatedRoot(
                    directoryDescriptor,
                    allowedRootBindings: allowedRootBindings
                  ) else {
                throw POSIXFailure.operationFailed
            }
        } catch {
            if rewriteStarted {
                _ = restoreOriginal(
                    originalData,
                    metadata: originalMetadataSnapshot,
                    on: targetDescriptor
                )
            }
            throw error
        }
    }

    private static func directoryIsUnderValidatedRoot(
        _ directoryDescriptor: Int32,
        allowedRootBindings: [InjectedFileTouchRootBinding]
    ) -> Bool {
        guard let currentPath = openedPath(for: directoryDescriptor) else {
            return false
        }
        return allowedRootBindings.contains {
            $0.matchesCurrentIdentity()
                && isUnderAllowedRoot(currentPath, roots: [$0.path])
        }
    }

    private static func restoreOriginal(
        _ data: Data,
        metadata: DescriptorMetadataSnapshot,
        on fileDescriptor: Int32
    ) -> Bool {
        do {
            try replaceContents(of: fileDescriptor, with: data)
            return restoreMetadata(metadata, on: fileDescriptor)
                && Darwin.fsync(fileDescriptor) == 0
        } catch {
            return false
        }
    }

    private static func replaceContents(of fileDescriptor: Int32, with data: Data) throws {
        guard Darwin.ftruncate(fileDescriptor, 0) == 0 else {
            throw POSIXFailure.operationFailed
        }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let writeCount = Darwin.pwrite(
                    fileDescriptor,
                    bytes.baseAddress?.advanced(by: offset),
                    bytes.count - offset,
                    off_t(offset)
                )
                if writeCount > 0 {
                    offset += writeCount
                } else if writeCount == 0 || errno != EINTR {
                    throw POSIXFailure.operationFailed
                }
            }
        }
        guard Darwin.ftruncate(fileDescriptor, off_t(data.count)) == 0,
              Darwin.fsync(fileDescriptor) == 0 else {
            throw POSIXFailure.operationFailed
        }
    }

    private static func openedPath(for fileDescriptor: Int32) -> String? {
        var info = vnode_fdinfowithpath()
        let infoSize = MemoryLayout<vnode_fdinfowithpath>.size
        let readSize = withUnsafeMutablePointer(to: &info) {
            proc_pidfdinfo(
                getpid(),
                fileDescriptor,
                PROC_PIDFDVNODEPATHINFO,
                $0,
                Int32(infoSize)
            )
        }
        guard readSize == Int32(infoSize) else { return nil }
        let path = withUnsafePointer(to: &info.pvip.vip_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
                String(cString: $0)
            }
        }
        return URL(fileURLWithPath: path)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
    }

    private static func metadataIsSafe(_ metadata: stat, maxBytes: Int) -> Bool {
        maxBytes >= 0
            && maxBytes < Int.max
            && metadata.st_mode & S_IFMT == S_IFREG
            && metadata.st_nlink == 1
            && metadata.st_size >= 0
            && metadata.st_size <= off_t(maxBytes)
    }

    private static func metadataHasIdentity(_ metadata: stat, of expected: stat) -> Bool {
        metadata.st_dev == expected.st_dev
            && metadata.st_ino == expected.st_ino
            && metadata.st_mode & S_IFMT == expected.st_mode & S_IFMT
    }

    private static func metadataIsUnchanged(_ metadata: stat, _ expected: stat) -> Bool {
        metadataHasIdentity(metadata, of: expected)
            && metadata.st_nlink == expected.st_nlink
            && metadata.st_mode == expected.st_mode
            && metadata.st_uid == expected.st_uid
            && metadata.st_gid == expected.st_gid
            && metadata.st_flags == expected.st_flags
            && metadata.st_size == expected.st_size
            && metadata.st_mtimespec.tv_sec == expected.st_mtimespec.tv_sec
            && metadata.st_mtimespec.tv_nsec == expected.st_mtimespec.tv_nsec
            && metadata.st_ctimespec.tv_sec == expected.st_ctimespec.tv_sec
            && metadata.st_ctimespec.tv_nsec == expected.st_ctimespec.tv_nsec
    }

    private static func restoreTimestamps(on fileDescriptor: Int32, from source: stat) -> Bool {
        restoreTimestamps(
            on: fileDescriptor,
            creation: MetadataTimestamp(source.st_birthtimespec),
            modification: MetadataTimestamp(source.st_mtimespec),
            access: MetadataTimestamp(source.st_atimespec)
        )
    }

    private static func restoreTimestamps(
        on fileDescriptor: Int32,
        from source: DescriptorMetadataSnapshot
    ) -> Bool {
        restoreTimestamps(
            on: fileDescriptor,
            creation: source.creation,
            modification: source.modification,
            access: source.access
        )
    }

    private static func restoreTimestamps(
        on fileDescriptor: Int32,
        creation: MetadataTimestamp,
        modification: MetadataTimestamp,
        access: MetadataTimestamp
    ) -> Bool {
        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.commonattr = attrgroup_t(
            ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME
        )
        var timestamps = FileTimestamps(
            creation: creation.timespec,
            modification: modification.timespec,
            access: access.timespec
        )
        return Darwin.fsetattrlist(
            fileDescriptor,
            &attributes,
            &timestamps,
            MemoryLayout<FileTimestamps>.size,
            0
        ) == 0
    }

    private static func metadataSnapshot(
        of fileDescriptor: Int32,
        timestampSource: stat? = nil
    ) throws -> DescriptorMetadataSnapshot {
        var metadataBefore = stat()
        guard Darwin.fstat(fileDescriptor, &metadataBefore) == 0 else {
            throw POSIXFailure.operationFailed
        }
        let extendedAttributes = try extendedAttributes(of: fileDescriptor)
        let acl = try accessControlList(of: fileDescriptor)
        var metadataAfter = stat()
        guard Darwin.fstat(fileDescriptor, &metadataAfter) == 0,
              metadataIsUnchanged(metadataAfter, metadataBefore) else {
            throw POSIXFailure.operationFailed
        }

        let timestamps = timestampSource ?? metadataAfter
        return DescriptorMetadataSnapshot(
            mode: metadataAfter.st_mode,
            uid: metadataAfter.st_uid,
            gid: metadataAfter.st_gid,
            flags: metadataAfter.st_flags,
            creation: MetadataTimestamp(timestamps.st_birthtimespec),
            modification: MetadataTimestamp(timestamps.st_mtimespec),
            access: MetadataTimestamp(timestamps.st_atimespec),
            extendedAttributes: extendedAttributes,
            acl: acl
        )
    }

    private static func extendedAttributes(
        of fileDescriptor: Int32
    ) throws -> [String: Data] {
        let listSize = Darwin.flistxattr(fileDescriptor, nil, 0, 0)
        guard listSize >= 0,
              listSize <= maximumXattrNameListBytes else {
            throw POSIXFailure.operationFailed
        }
        guard listSize > 0 else { return [:] }

        var nameData = Data(count: listSize)
        let readListSize = nameData.withUnsafeMutableBytes {
            Darwin.flistxattr(fileDescriptor, $0.baseAddress, listSize, 0)
        }
        guard readListSize == listSize else {
            throw POSIXFailure.operationFailed
        }
        let names = try extendedAttributeNames(from: nameData)

        var remainingBytes = maximumMetadataBytes - Int(listSize)
        var attributes: [String: Data] = [:]
        for name in names {
            let valueSize = Darwin.fgetxattr(fileDescriptor, name, nil, 0, 0, 0)
            guard valueSize >= 0,
                  valueSize <= remainingBytes else {
                throw POSIXFailure.operationFailed
            }
            var value = Data(count: valueSize)
            let readValueSize = value.withUnsafeMutableBytes {
                Darwin.fgetxattr(
                    fileDescriptor,
                    name,
                    $0.baseAddress,
                    valueSize,
                    0,
                    0
                )
            }
            guard readValueSize == valueSize,
                  attributes.updateValue(value, forKey: name) == nil else {
                throw POSIXFailure.operationFailed
            }
            remainingBytes -= Int(valueSize)
        }
        return attributes
    }

    private static func extendedAttributeNames(from data: Data) throws -> [String] {
        let bytes = Array(data)
        guard bytes.last == 0 else { throw POSIXFailure.operationFailed }

        var names: [String] = []
        var start = 0
        for index in bytes.indices where bytes[index] == 0 {
            guard index > start,
                  let name = String(bytes: bytes[start..<index], encoding: .utf8) else {
                throw POSIXFailure.operationFailed
            }
            names.append(name)
            start = index + 1
        }
        guard start == bytes.count else { throw POSIXFailure.operationFailed }
        return names
    }

    private static func accessControlList(
        of fileDescriptor: Int32
    ) throws -> AccessControlListSnapshot {
        guard let acl = Darwin.acl_get_fd_np(fileDescriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT {
                return .none
            }
            if errno == ENOTSUP || errno == EOPNOTSUPP {
                return .unsupported
            }
            throw POSIXFailure.operationFailed
        }
        defer { Darwin.acl_free(UnsafeMutableRawPointer(acl)) }

        let size = Darwin.acl_size(acl)
        guard size >= 0, size <= maximumACLBytes else {
            throw POSIXFailure.operationFailed
        }
        var data = Data(count: size)
        let copiedSize = data.withUnsafeMutableBytes {
            Darwin.acl_copy_ext($0.baseAddress, acl, size)
        }
        guard copiedSize == size else { throw POSIXFailure.operationFailed }
        return .data(data)
    }

    private static func restoreMetadata(
        _ metadata: DescriptorMetadataSnapshot,
        on fileDescriptor: Int32
    ) -> Bool {
        guard restoreExtendedAttributes(
            metadata.extendedAttributes,
            on: fileDescriptor
        ),
        restoreAccessControlList(metadata.acl, on: fileDescriptor),
        Darwin.fchown(fileDescriptor, metadata.uid, metadata.gid) == 0,
        Darwin.fchmod(fileDescriptor, metadata.mode & mode_t(0o7777)) == 0,
        restoreTimestamps(on: fileDescriptor, from: metadata),
        Darwin.fchflags(fileDescriptor, metadata.flags) == 0 else {
            return false
        }
        return true
    }

    private static func restoreExtendedAttributes(
        _ expected: [String: Data],
        on fileDescriptor: Int32
    ) -> Bool {
        guard let current = try? extendedAttributes(of: fileDescriptor) else {
            return false
        }
        for name in current.keys where expected[name] == nil {
            guard Darwin.fremovexattr(fileDescriptor, name, 0) == 0 else {
                return false
            }
        }
        for (name, value) in expected {
            let result = value.withUnsafeBytes {
                Darwin.fsetxattr(
                    fileDescriptor,
                    name,
                    $0.baseAddress,
                    value.count,
                    0,
                    0
                )
            }
            guard result == 0 else { return false }
        }
        return true
    }

    private static func restoreAccessControlList(
        _ snapshot: AccessControlListSnapshot,
        on fileDescriptor: Int32
    ) -> Bool {
        switch snapshot {
        case .unsupported:
            return true
        case .none:
            guard let acl = Darwin.acl_init(0) else { return false }
            defer { Darwin.acl_free(UnsafeMutableRawPointer(acl)) }
            return Darwin.acl_set_fd_np(
                fileDescriptor,
                acl,
                ACL_TYPE_EXTENDED
            ) == 0
        case .data(let data):
            return data.withUnsafeBytes { bytes in
                guard let baseAddress = bytes.baseAddress,
                      let acl = Darwin.acl_copy_int(baseAddress) else {
                    return false
                }
                defer { Darwin.acl_free(UnsafeMutableRawPointer(acl)) }
                return Darwin.acl_set_fd_np(
                    fileDescriptor,
                    acl,
                    ACL_TYPE_EXTENDED
                ) == 0
            }
        }
    }

    private static func targetIsUnchanged(
        directoryDescriptor: Int32,
        targetDescriptor: Int32,
        targetName: String,
        initialMetadata: stat
    ) -> Bool {
        var descriptorMetadata = stat()
        var entryMetadata = stat()
        guard Darwin.fstat(targetDescriptor, &descriptorMetadata) == 0,
              Darwin.fstatat(
                directoryDescriptor,
                targetName,
                &entryMetadata,
                AT_SYMLINK_NOFOLLOW
              ) == 0 else {
            return false
        }
        return metadataIsUnchanged(descriptorMetadata, initialMetadata)
            && metadataIsUnchanged(entryMetadata, initialMetadata)
    }

    private static func readCapped(from fileDescriptor: Int32, maxBytes: Int) throws -> Data {
        guard maxBytes >= 0, maxBytes < Int.max else {
            throw POSIXFailure.operationFailed
        }
        let limit = maxBytes + 1
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: min(64 * 1024, limit))

        while data.count < limit {
            let requested = min(buffer.count, limit - data.count)
            let readCount = buffer.withUnsafeMutableBytes {
                Darwin.pread(
                    fileDescriptor,
                    $0.baseAddress,
                    requested,
                    off_t(data.count)
                )
            }
            if readCount > 0 {
                data.append(contentsOf: buffer.prefix(Int(readCount)))
            } else if readCount == 0 {
                break
            } else if errno != EINTR {
                throw POSIXFailure.operationFailed
            }
        }
        return data
    }

    private static func canonicalContainmentPath(for path: String) -> String {
        let url = URL(fileURLWithPath: path).standardizedFileURL
        return url
            .deletingLastPathComponent()
            .resolvingSymlinksInPath()
            .appendingPathComponent(url.lastPathComponent)
            .standardizedFileURL
            .path
    }

    static func isUnderAllowedRoot(_ path: String, roots: [String]) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        let components = URL(fileURLWithPath: standardized).pathComponents
        for root in roots {
            let rootComponents = URL(fileURLWithPath: root).standardizedFileURL.pathComponents
            guard components.count >= rootComponents.count else { continue }
            if Array(components.prefix(rootComponents.count)) == rootComponents {
                return true
            }
        }
        return false
    }

    private enum POSIXFailure: Error {
        case operationFailed
    }

    private struct FileTimestamps {
        var creation: timespec
        var modification: timespec
        var access: timespec
    }

    private struct MetadataTimestamp: Equatable {
        let seconds: Int
        let nanoseconds: Int

        init(_ value: timespec) {
            seconds = value.tv_sec
            nanoseconds = value.tv_nsec
        }

        var timespec: timespec {
            Darwin.timespec(tv_sec: seconds, tv_nsec: nanoseconds)
        }
    }

    private enum AccessControlListSnapshot: Equatable {
        case unsupported
        case none
        case data(Data)
    }

    private struct DescriptorMetadataSnapshot: Equatable {
        let mode: mode_t
        let uid: uid_t
        let gid: gid_t
        let flags: UInt32
        let creation: MetadataTimestamp
        let modification: MetadataTimestamp
        let access: MetadataTimestamp
        let extendedAttributes: [String: Data]
        let acl: AccessControlListSnapshot
    }
}
