import Foundation
import Darwin
#if os(macOS)
import CoreServices
#endif
import AuthenticatorBridge

struct InjectedFileTouchDirectoryIdentity: Equatable, Hashable, Sendable {
    let device: UInt64
    let inode: UInt64
}

struct InjectedFileTouchRootBinding: Equatable, Hashable, Sendable {
    let path: String
    let identity: InjectedFileTouchDirectoryIdentity

    init?(path: String) {
        let canonical = URL(fileURLWithPath: path)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
        guard !canonical.isEmpty,
              let identity = Self.directoryIdentity(at: canonical) else {
            return nil
        }
        self.path = canonical
        self.identity = identity
    }

    func matchesCurrentIdentity() -> Bool {
        Self.directoryIdentity(at: path) == identity
    }

    static func directoryIdentity(
        at path: String
    ) -> InjectedFileTouchDirectoryIdentity? {
        let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFDIR else {
            return nil
        }
        return InjectedFileTouchDirectoryIdentity(
            device: UInt64(bitPattern: Int64(metadata.st_dev)),
            inode: UInt64(metadata.st_ino)
        )
    }
}

struct InjectedFileTouchRootSelection: Equatable, Sendable {
    let roots: [String]
    let isIncomplete: Bool
}

struct InjectedFileTouchWatchResult: Equatable, Sendable {
    let paths: [String]
    let validatedRootBindings: [InjectedFileTouchRootBinding]
    let isIncomplete: Bool
}

struct InjectedFileTouchFallbackResult: Equatable, Sendable {
    let paths: [String]
    let isIncomplete: Bool
}

/// Collects created/modified paths under workspace + temp roots while a secret-injected child runs.
final class InjectedFileTouchWatcher: @unchecked Sendable {
    static let defaultMaximumCandidatePaths = 10_000

    private let roots: [String]
    private let rootBindings: [InjectedFileTouchRootBinding]
    private let rootBindingCaptureIncomplete: Bool
    private let startedAt: Date
    private let startOverride: (@Sendable () -> Bool)?
    private let maximumCandidatePaths: Int
    private let lock = NSLock()
    private var touched = Set<String>()
    private var streamIncomplete = false
    private var eventObservationStarted = false
    #if os(macOS)
    private var stream: FSEventStreamRef?
    private let callbackQueue = DispatchQueue(label: "app.authsia.injected-file-touch", qos: .utility)
    static let streamCreateFlags = UInt32(
        kFSEventStreamCreateFlagUseCFTypes
            | kFSEventStreamCreateFlagWatchRoot
            | kFSEventStreamCreateFlagFileEvents
            | kFSEventStreamCreateFlagNoDefer
    )
    #endif

    init(
        roots: [String],
        startedAt: Date = Date(),
        startOverride: (@Sendable () -> Bool)? = nil,
        maximumCandidatePaths: Int = defaultMaximumCandidatePaths
    ) {
        let requestedRoots = Set(
            roots.map { URL(fileURLWithPath: $0).standardizedFileURL.path }
                .filter { !$0.isEmpty }
        )
        let normalizedRoots = Self.normalizedExistingDirectories(
            roots,
            fileManager: .default
        )
        var bindings: [InjectedFileTouchRootBinding] = []
        var captureIncomplete = normalizedRoots.count != requestedRoots.count
        for path in normalizedRoots {
            guard let binding = InjectedFileTouchRootBinding(path: path) else {
                captureIncomplete = true
                continue
            }
            bindings.append(binding)
        }
        self.roots = bindings.map(\.path)
        self.rootBindings = bindings
        self.rootBindingCaptureIncomplete = captureIncomplete
        self.startedAt = startedAt
        self.startOverride = startOverride
        self.maximumCandidatePaths = max(0, maximumCandidatePaths)
    }

    static func defaultRoots(
        workspaceRoot: String?,
        workingDirectory: String?,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default
    ) -> InjectedFileTouchRootSelection {
        var roots: [String] = []
        var seen = Set<String>()
        var isIncomplete = false

        let requestedWorkingDirectory: String
        if let workingDirectory {
            if workingDirectory.isEmpty {
                isIncomplete = true
                requestedWorkingDirectory = fileManager.currentDirectoryPath
            } else {
                requestedWorkingDirectory = workingDirectory
            }
        } else {
            requestedWorkingDirectory = fileManager.currentDirectoryPath
        }

        let canonicalWorkingDirectory = canonicalExistingDirectory(
            requestedWorkingDirectory,
            fileManager: fileManager
        )
        if let canonicalWorkingDirectory,
           isSafeObservationRoot(canonicalWorkingDirectory, fileManager: fileManager) {
            append(canonicalWorkingDirectory, to: &roots, seen: &seen)
        } else {
            isIncomplete = true
        }

        if let workspaceRoot {
            if !workspaceRoot.isEmpty,
               let canonicalWorkspace = canonicalExistingDirectory(
                   workspaceRoot,
                   fileManager: fileManager
               ),
               isSafeObservationRoot(canonicalWorkspace, fileManager: fileManager),
               let canonicalWorkingDirectory,
               isPath(canonicalWorkingDirectory, under: canonicalWorkspace) {
                append(canonicalWorkspace, to: &roots, seen: &seen)
            } else {
                isIncomplete = true
            }
        }

        if let tmpDir = environment["TMPDIR"] {
            if !tmpDir.isEmpty,
               let canonicalTemp = canonicalExistingDirectory(tmpDir, fileManager: fileManager),
               isTrustedTempRoot(canonicalTemp),
               isSafeObservationRoot(canonicalTemp, fileManager: fileManager) {
                append(canonicalTemp, to: &roots, seen: &seen)
            } else {
                isIncomplete = true
            }
        }

        return addingBuiltInTempRoots(
            to: roots,
            seen: seen,
            isIncomplete: isIncomplete,
            fileManager: fileManager
        )
    }

    func start() -> Bool {
        if let startOverride {
            let started = startOverride()
            lock.lock()
            eventObservationStarted = started
            lock.unlock()
            return started
        }

        #if os(macOS)
        guard stream == nil, !roots.isEmpty else { return false }

        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let pathsToWatch = roots as CFArray
        guard let created = FSEventStreamCreate(
            kCFAllocatorDefault,
            { _, info, numEvents, eventPaths, eventFlags, _ in
                guard let info else { return }
                let watcher = Unmanaged<InjectedFileTouchWatcher>.fromOpaque(info).takeUnretainedValue()
                watcher.handleFSEvents(
                    numEvents: numEvents,
                    eventPaths: eventPaths,
                    eventFlags: eventFlags
                )
            },
            &context,
            pathsToWatch,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            0.2,
            Self.streamCreateFlags
        ) else {
            return false
        }

        FSEventStreamSetDispatchQueue(created, callbackQueue)
        guard FSEventStreamStart(created) else {
            FSEventStreamInvalidate(created)
            FSEventStreamRelease(created)
            return false
        }
        stream = created
        lock.lock()
        eventObservationStarted = true
        lock.unlock()
        return true
        #else
        return false
        #endif
    }

    /// Stops watching and returns candidate paths (FSEvents + high-signal mtime fallback).
    func stop(fileManager: FileManager = .default) -> InjectedFileTouchWatchResult {
        #if os(macOS)
        if let stream {
            FSEventStreamFlushSync(stream)
            FSEventStreamStop(stream)
            FSEventStreamInvalidate(stream)
            FSEventStreamRelease(stream)
            self.stream = nil
        }
        #endif

        lock.lock()
        let touchedPaths = touched
        var isIncomplete = streamIncomplete || rootBindingCaptureIncomplete
        let didStartEventObservation = eventObservationStarted
        lock.unlock()

        let validatedRootBindings = rootBindings.compactMap {
            binding -> InjectedFileTouchRootBinding? in
            guard binding.matchesCurrentIdentity() else {
                isIncomplete = true
                return nil
            }
            return binding
        }
        var paths = Set<String>()
        for path in touchedPaths.sorted() {
            guard validatedRootBindings.contains(where: {
                Self.isPath(path, under: $0.path)
            }) else {
                continue
            }
            guard paths.count < maximumCandidatePaths else {
                isIncomplete = true
                break
            }
            paths.insert(path)
        }
        if !didStartEventObservation {
            let fallback = Self.highSignalModifiedSince(
                startedAt,
                rootBindings: validatedRootBindings,
                fileManager: fileManager
            )
            for path in fallback.paths {
                guard paths.contains(path) || paths.count < maximumCandidatePaths else {
                    isIncomplete = true
                    break
                }
                paths.insert(path)
            }
            isIncomplete = isIncomplete || fallback.isIncomplete
        }
        return InjectedFileTouchWatchResult(
            paths: Array(paths).sorted(),
            validatedRootBindings: validatedRootBindings,
            isIncomplete: isIncomplete
        )
    }

    /// Test helper: record a path as touched without FSEvents.
    func recordForTesting(_ path: String) {
        note(path)
    }

    #if os(macOS)
    func recordEventFlagsForTesting(_ flags: FSEventStreamEventFlags) {
        noteEventFlags(flags)
    }
    #endif

    private func note(_ path: String) {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        guard !standardized.isEmpty else { return }
        lock.lock()
        if !touched.contains(standardized) {
            if touched.count < maximumCandidatePaths {
                touched.insert(standardized)
            } else {
                streamIncomplete = true
            }
        }
        lock.unlock()
    }

    #if os(macOS)
    private func handleFSEvents(
        numEvents: Int,
        eventPaths: UnsafeMutableRawPointer,
        eventFlags: UnsafePointer<FSEventStreamEventFlags>
    ) {
        let paths = Unmanaged<CFArray>.fromOpaque(eventPaths).takeUnretainedValue() as! [String]
        for index in 0..<numEvents {
            let flags = eventFlags[index]
            noteEventFlags(flags)
            guard Self.shouldRecordEvent(flags) else { continue }
            guard index < paths.count else { continue }
            note(paths[index])
        }
    }

    static func shouldRecordEvent(_ flags: FSEventStreamEventFlags) -> Bool {
        let isRemoved = (flags & UInt32(kFSEventStreamEventFlagItemRemoved)) != 0
        let isFile = (flags & UInt32(kFSEventStreamEventFlagItemIsFile)) != 0
        let changed = (
            flags
                & UInt32(
                    kFSEventStreamEventFlagItemCreated
                        | kFSEventStreamEventFlagItemModified
                        | kFSEventStreamEventFlagItemRenamed
                )
        ) != 0
        return !isRemoved && isFile && changed
    }

    static func eventFlagsRequireIncomplete(_ flags: FSEventStreamEventFlags) -> Bool {
        let incompleteFlags = UInt32(
            kFSEventStreamEventFlagMustScanSubDirs
                | kFSEventStreamEventFlagUserDropped
                | kFSEventStreamEventFlagKernelDropped
                | kFSEventStreamEventFlagEventIdsWrapped
                | kFSEventStreamEventFlagRootChanged
                | kFSEventStreamEventFlagMount
                | kFSEventStreamEventFlagUnmount
        )
        return flags & incompleteFlags != 0
    }

    private func noteEventFlags(_ flags: FSEventStreamEventFlags) {
        guard Self.eventFlagsRequireIncomplete(flags) else { return }
        lock.lock()
        streamIncomplete = true
        lock.unlock()
    }
    #endif

    static func highSignalModifiedSince(
        _ startedAt: Date,
        roots: [String],
        fileManager: FileManager = .default,
        maximumEntries: Int = 10_000,
        maximumDuration: TimeInterval = 1,
        now: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) -> InjectedFileTouchFallbackResult {
        let requestedRoots = Set(
            roots.map { URL(fileURLWithPath: $0).standardizedFileURL.path }
                .filter { !$0.isEmpty }
        )
        let rootBindings = requestedRoots.compactMap {
            InjectedFileTouchRootBinding(path: $0)
        }
        let result = highSignalModifiedSince(
            startedAt,
            rootBindings: rootBindings,
            fileManager: fileManager,
            maximumEntries: maximumEntries,
            maximumDuration: maximumDuration,
            now: now
        )
        return InjectedFileTouchFallbackResult(
            paths: result.paths,
            isIncomplete: result.isIncomplete
                || rootBindings.count != requestedRoots.count
        )
    }

    static func highSignalModifiedSince(
        _ startedAt: Date,
        rootBindings: [InjectedFileTouchRootBinding],
        fileManager: FileManager = .default,
        maximumEntries: Int = 10_000,
        maximumDuration: TimeInterval = 1,
        now: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    ) -> InjectedFileTouchFallbackResult {
        guard maximumEntries > 0, maximumDuration > 0 else {
            return InjectedFileTouchFallbackResult(paths: [], isIncomplete: true)
        }

        let deadline = now() + maximumDuration
        let resourceKeys: Set<URLResourceKey> = [
            .isDirectoryKey,
            .isRegularFileKey,
            .contentModificationDateKey,
        ]
        let prunedDirectoryNames: Set<String> = [
            ".git",
            ".build",
            "DerivedData",
            "node_modules",
        ]
        var results = Set<String>()
        var visitedEntries = 0
        var isIncomplete = false
        var reachedLimit = false

        for rootBinding in nonOverlappingRootBindings(rootBindings) {
            guard now() < deadline else {
                isIncomplete = true
                break
            }
            guard rootBinding.matchesCurrentIdentity() else {
                isIncomplete = true
                continue
            }

            let rootURL = URL(fileURLWithPath: rootBinding.path)
            var rootResults = Set<String>()
            var enumerationFailed = false
            guard let enumerator = fileManager.enumerator(
                at: rootURL,
                includingPropertiesForKeys: Array(resourceKeys),
                options: [.skipsPackageDescendants],
                errorHandler: { _, _ in
                    enumerationFailed = true
                    return false
                }
            ) else {
                isIncomplete = true
                continue
            }

            for case let fileURL as URL in enumerator {
                guard now() < deadline else {
                    isIncomplete = true
                    reachedLimit = true
                    break
                }
                guard visitedEntries < maximumEntries else {
                    isIncomplete = true
                    reachedLimit = true
                    break
                }
                visitedEntries += 1

                let values: URLResourceValues
                do {
                    values = try fileURL.resourceValues(forKeys: resourceKeys)
                } catch {
                    isIncomplete = true
                    continue
                }

                if values.isDirectory == true,
                   prunedDirectoryNames.contains(fileURL.lastPathComponent) {
                    enumerator.skipDescendants()
                    continue
                }
                guard values.isRegularFile == true,
                      let modified = values.contentModificationDate,
                      modified >= startedAt,
                      AgentSecretPathPolicy.isHighSignalSecretPath(fileURL.path) else {
                    continue
                }
                rootResults.insert(fileURL.standardizedFileURL.path)
            }
            isIncomplete = isIncomplete || enumerationFailed
            if rootBinding.matchesCurrentIdentity() {
                results.formUnion(rootResults)
            } else {
                isIncomplete = true
            }
            if reachedLimit { break }
        }

        return InjectedFileTouchFallbackResult(
            paths: Array(results).sorted(),
            isIncomplete: isIncomplete
        )
    }

    private static func nonOverlappingRootBindings(
        _ rootBindings: [InjectedFileTouchRootBinding]
    ) -> [InjectedFileTouchRootBinding] {
        let sorted = Set(rootBindings).sorted {
            let lhsDepth = URL(fileURLWithPath: $0.path).pathComponents.count
            let rhsDepth = URL(fileURLWithPath: $1.path).pathComponents.count
            return lhsDepth == rhsDepth
                ? $0.path < $1.path
                : lhsDepth < rhsDepth
        }

        var result: [InjectedFileTouchRootBinding] = []
        for rootBinding in sorted {
            guard !result.contains(where: {
                isPath(rootBinding.path, under: $0.path)
            }) else {
                continue
            }
            result.append(rootBinding)
        }
        return result
    }

    private static func normalizedExistingDirectories(
        _ roots: [String],
        fileManager: FileManager
    ) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for root in roots {
            let path = URL(fileURLWithPath: root).standardizedFileURL.path
            guard !path.isEmpty, seen.insert(path).inserted else { continue }
            var isDirectory: ObjCBool = false
            guard fileManager.fileExists(atPath: path, isDirectory: &isDirectory), isDirectory.boolValue else {
                continue
            }
            result.append(path)
        }
        return result
    }

    private static func addingBuiltInTempRoots(
        to existingRoots: [String],
        seen existingSeen: Set<String>,
        isIncomplete: Bool,
        fileManager: FileManager
    ) -> InjectedFileTouchRootSelection {
        var roots = existingRoots
        var seen = existingSeen
        for candidate in [NSTemporaryDirectory(), "/tmp"] {
            guard let canonical = canonicalExistingDirectory(candidate, fileManager: fileManager),
                  isTrustedTempRoot(canonical),
                  isSafeObservationRoot(canonical, fileManager: fileManager) else {
                continue
            }
            append(canonical, to: &roots, seen: &seen)
        }
        return InjectedFileTouchRootSelection(
            roots: roots,
            isIncomplete: isIncomplete
        )
    }

    private static func canonicalExistingDirectory(
        _ path: String,
        fileManager: FileManager
    ) -> String? {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL
        var isDirectory: ObjCBool = false
        guard !standardized.path.isEmpty,
              fileManager.fileExists(atPath: standardized.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            return nil
        }
        return standardized
            .resolvingSymlinksInPath()
            .standardizedFileURL
            .path
    }

    private static func isPath(_ path: String, under root: String) -> Bool {
        let pathComponents = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        let rootComponents = URL(fileURLWithPath: root).standardizedFileURL.pathComponents
        guard pathComponents.count >= rootComponents.count else { return false }
        return Array(pathComponents.prefix(rootComponents.count)) == rootComponents
    }

    private static func isTrustedTempRoot(_ path: String) -> Bool {
        if isPath(path, under: "/private/tmp") || isPath(path, under: "/tmp") {
            return true
        }
        let components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        let privateFoldersTemp = components.count >= 7
            && components[1] == "private"
            && components[2] == "var"
            && components[3] == "folders"
            && components[6] == "T"
        let foldersTemp = components.count >= 6
            && components[1] == "var"
            && components[2] == "folders"
            && components[5] == "T"
        return privateFoldersTemp || foldersTemp
    }

    private static func isSafeObservationRoot(
        _ path: String,
        fileManager: FileManager
    ) -> Bool {
        guard let home = canonicalExistingDirectory(
            fileManager.homeDirectoryForCurrentUser.path,
            fileManager: fileManager
        ) else {
            return false
        }
        return isSafeObservationRoot(
            path,
            homeDirectory: home,
            identityProvider: InjectedFileTouchRootBinding.directoryIdentity(at:),
            mountPointProvider: fileSystemMountPoint(at:)
        )
    }

    static func isSafeObservationRoot(
        _ path: String,
        homeDirectory: String,
        identityProvider: (String) -> InjectedFileTouchDirectoryIdentity?,
        mountPointProvider: (String) -> String? = { _ in nil }
    ) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        guard standardized != "/" else { return false }
        guard let identity = identityProvider(standardized) else {
            return false
        }
        if let mountPoint = mountPointProvider(standardized) {
            let standardizedMountPoint = URL(fileURLWithPath: mountPoint)
                .standardizedFileURL
                .path
            if standardizedMountPoint == standardized
                || identityProvider(standardizedMountPoint) == identity {
                return false
            }
        }
        if isTrustedTempRoot(standardized) {
            return true
        }

        let parent = URL(fileURLWithPath: standardized)
            .deletingLastPathComponent()
            .standardizedFileURL
            .path
        guard parent != standardized,
              let parentIdentity = identityProvider(parent),
              identity.device == parentIdentity.device,
              identity != parentIdentity,
              !isPath(homeDirectory, under: standardized) else {
            return false
        }

        var homeAncestor = URL(fileURLWithPath: homeDirectory).standardizedFileURL.path
        while true {
            if identityProvider(homeAncestor) == identity {
                return false
            }
            let next = URL(fileURLWithPath: homeAncestor)
                .deletingLastPathComponent()
                .standardizedFileURL
                .path
            guard next != homeAncestor else { break }
            homeAncestor = next
        }
        return true
    }

    static func fileSystemMountPoint(at path: String) -> String? {
        let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }

        var fileSystem = statfs()
        guard Darwin.fstatfs(descriptor, &fileSystem) == 0 else {
            return nil
        }
        let mountPoint = withUnsafeBytes(of: &fileSystem.f_mntonname) { bytes -> String? in
            guard let baseAddress = bytes.bindMemory(to: CChar.self).baseAddress else {
                return nil
            }
            return String(cString: baseAddress)
        }
        guard let mountPoint, !mountPoint.isEmpty else { return nil }
        return URL(fileURLWithPath: mountPoint).standardizedFileURL.path
    }

    private static func append(
        _ path: String,
        to roots: inout [String],
        seen: inout Set<String>
    ) {
        guard seen.insert(path).inserted else { return }
        roots.append(path)
    }
}
