import Darwin
import Foundation
import AuthenticatorBridge

#if canImport(System)
import System
#endif

enum MCPProxySpawnError: Error, Equatable {
    case commandNotFound
    case launchFailed
    /// Refs resolved but no owned grant came back, so revocation would have
    /// nothing to observe and the child could outlive an Access Center revoke.
    case grantUnavailable
}

enum MCPProxyChildEnvironment {
    static func make(
        parent: [String: String],
        declared: [String: String]
    ) -> [String: String] {
        var environment = MCPInheritedEnvironment.filtered(parent)
        for (key, value) in declared {
            environment[key] = value
        }
        return environment
    }
}

enum MCPProxyCommandResolver {
    static func resolve(
        command: String,
        workspaceRoot: URL,
        path: String,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        fileManager: FileManager = .default
    ) throws -> URL {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw MCPProxySpawnError.commandNotFound }
        if trimmed.contains("/") {
            guard WorkspaceConfigStore.isCommitSafeRelativePath(trimmed) else {
                throw MCPProxySpawnError.commandNotFound
            }
            return try containedRegularFile(
                workspaceRoot.appendingPathComponent(trimmed),
                workspaceRoot: workspaceRoot,
                fileManager: fileManager
            )
        }
        let searchPath = MCPProxyPathOverlay.searchPath(
            path: path,
            homeDirectory: homeDirectory
        )
        for directory in searchPath.split(separator: ":") where !directory.isEmpty {
            let candidate = URL(fileURLWithPath: String(directory), isDirectory: true)
                .appendingPathComponent(trimmed)
            var isDirectory: ObjCBool = false
            if fileManager.fileExists(atPath: candidate.path, isDirectory: &isDirectory),
               !isDirectory.boolValue,
               fileManager.isExecutableFile(atPath: candidate.path) {
                return candidate
            }
        }
        throw MCPProxySpawnError.commandNotFound
    }

    private static func containedRegularFile(
        _ url: URL,
        workspaceRoot: URL,
        fileManager: FileManager
    ) throws -> URL {
        var isDirectory: ObjCBool = false
        guard fileManager.fileExists(atPath: url.path, isDirectory: &isDirectory),
              !isDirectory.boolValue else {
            throw MCPProxySpawnError.commandNotFound
        }
        let canonicalRoot = workspaceRoot.resolvingSymlinksInPath().standardizedFileURL.path
        let canonicalFile = url.resolvingSymlinksInPath().standardizedFileURL
        let prefix = canonicalRoot.hasSuffix("/") ? canonicalRoot : canonicalRoot + "/"
        guard canonicalFile.path == canonicalRoot || canonicalFile.path.hasPrefix(prefix) else {
            throw MCPProxySpawnError.commandNotFound
        }
        var directory: ObjCBool = false
        guard fileManager.fileExists(atPath: canonicalFile.path, isDirectory: &directory),
              !directory.boolValue,
              fileManager.isExecutableFile(atPath: canonicalFile.path) else {
            throw MCPProxySpawnError.commandNotFound
        }
        return canonicalFile
    }
}

struct MCPProxySpawnedChild: Sendable {
    let processID: pid_t
    let processGroupID: pid_t
    let stdinWrite: Int32
    let stdoutRead: Int32
    let stderrRead: Int32
}

protocol MCPProxyChildLaunching: Sendable {
    func spawn(
        executable: URL,
        arguments: [String],
        environment: [String: String],
        currentDirectory: URL
    ) throws -> MCPProxySpawnedChild
}

struct MCPProxyPosixLauncher: MCPProxyChildLaunching {
    func spawn(
        executable: URL,
        arguments: [String],
        environment: [String: String],
        currentDirectory: URL
    ) throws -> MCPProxySpawnedChild {
        var stdinPipe = [Int32](repeating: 0, count: 2)
        var stdoutPipe = [Int32](repeating: 0, count: 2)
        var stderrPipe = [Int32](repeating: 0, count: 2)
        guard Darwin.pipe(&stdinPipe) == 0,
              Darwin.pipe(&stdoutPipe) == 0,
              Darwin.pipe(&stderrPipe) == 0 else {
            throw MCPProxySpawnError.launchFailed
        }

        func closeAll() {
            stdinPipe.forEach { _ = Darwin.close($0) }
            stdoutPipe.forEach { _ = Darwin.close($0) }
            stderrPipe.forEach { _ = Darwin.close($0) }
        }

        let allDescriptors = stdinPipe + stdoutPipe + stderrPipe
        for descriptor in allDescriptors {
            _ = Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC)
        }

        var fileActions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&fileActions) == 0 else {
            closeAll()
            throw MCPProxySpawnError.launchFailed
        }
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        let chdirResult = currentDirectory.path.withCString { path in
            posix_spawn_file_actions_addchdir_np(&fileActions, path)
        }
        guard posix_spawn_file_actions_adddup2(&fileActions, stdinPipe[0], STDIN_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&fileActions, stdoutPipe[1], STDOUT_FILENO) == 0,
              posix_spawn_file_actions_adddup2(&fileActions, stderrPipe[1], STDERR_FILENO) == 0,
              chdirResult == 0 else {
            closeAll()
            throw MCPProxySpawnError.launchFailed
        }

        var attributes: posix_spawnattr_t?
        guard posix_spawnattr_init(&attributes) == 0 else {
            closeAll()
            throw MCPProxySpawnError.launchFailed
        }
        defer { posix_spawnattr_destroy(&attributes) }
        var defaultSignals = sigset_t()
        sigemptyset(&defaultSignals)
        sigaddset(&defaultSignals, SIGINT)
        sigaddset(&defaultSignals, SIGTERM)
        // SETSIGDEF resets dispositions but not the mask, and the mask is
        // inherited from whichever thread spawns. A child that starts with
        // SIGTERM blocked cannot shut down gracefully, so clear the mask too.
        var emptyMask = sigset_t()
        sigemptyset(&emptyMask)
        let flags = Int16(
            POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT
                | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK
        )
        guard posix_spawnattr_setflags(&attributes, flags) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaultSignals) == 0,
              posix_spawnattr_setsigmask(&attributes, &emptyMask) == 0 else {
            closeAll()
            throw MCPProxySpawnError.launchFailed
        }

        let argumentStrings = [executable.path] + arguments
        var argv: [UnsafeMutablePointer<CChar>?] = argumentStrings.map { strdup($0) }
        argv.append(nil)
        var envp: [UnsafeMutablePointer<CChar>?] = environment.keys.sorted().map { key in
            strdup("\(key)=\(environment[key] ?? "")")
        }
        envp.append(nil)
        defer {
            argv.compactMap { $0 }.forEach { free($0) }
            envp.compactMap { $0 }.forEach { free($0) }
        }

        var processID: pid_t = 0
        let spawnResult = executable.path.withCString { path in
            argv.withUnsafeMutableBufferPointer { argumentBuffer in
                envp.withUnsafeMutableBufferPointer { environmentBuffer in
                    posix_spawn(
                        &processID,
                        path,
                        &fileActions,
                        &attributes,
                        argumentBuffer.baseAddress,
                        environmentBuffer.baseAddress
                    )
                }
            }
        }
        Darwin.close(stdinPipe[0])
        Darwin.close(stdoutPipe[1])
        Darwin.close(stderrPipe[1])
        guard spawnResult == 0, processID > 0 else {
            Darwin.close(stdinPipe[1])
            Darwin.close(stdoutPipe[0])
            Darwin.close(stderrPipe[0])
            throw MCPProxySpawnError.launchFailed
        }
        return MCPProxySpawnedChild(
            processID: processID,
            processGroupID: processID,
            stdinWrite: stdinPipe[1],
            stdoutRead: stdoutPipe[0],
            stderrRead: stderrPipe[0]
        )
    }
}

enum MCPProxyStderrDrain {
    /// Relay child diagnostics to the proxy's own stderr, concealing injected
    /// values first. The child inherits resolved refs in its environment and a
    /// verbose upstream can echo one in a traceback, so this stream is masked
    /// like any other channel that leaves the child.
    static func start(
        fileDescriptor: Int32,
        secrets: [String] = [],
        limit: Int = MCPSameBinaryRunner.outputLimit,
        output: FileHandle = .standardError
    ) {
        let masker = OutputMasker(exactSecrets: MCPProxyJSONMasker.maskable(secrets))
        Thread.detachNewThread {
            let handle = FileHandle(fileDescriptor: fileDescriptor, closeOnDealloc: true)
            // Streaming hold-back so a value split across two reads still matches.
            var stream = OutputMasker.Stream(masker: masker)
            var retained = 0
            func emit(_ data: Data) {
                let remaining = limit - retained
                guard remaining > 0, !data.isEmpty else { return }
                let prefix = data.prefix(remaining)
                output.write(Data(prefix))
                retained += prefix.count
            }
            while true {
                // availableData returns as soon as the child writes; the
                // fixed-length read it replaces blocked until the buffer filled,
                // so diagnostics only surfaced once the child exited.
                let chunk = handle.availableData
                guard !chunk.isEmpty else { break }
                emit(stream.mask(chunk))
            }
            emit(stream.flush())
        }
    }
}
