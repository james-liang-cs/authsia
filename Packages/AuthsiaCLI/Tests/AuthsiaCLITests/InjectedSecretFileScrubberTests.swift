import Darwin
import Foundation
import Testing
import AuthenticatorBridge
#if os(macOS)
import CoreServices
#endif
@testable import authsia

@Suite("InjectedSecretFileScrubber")
struct InjectedSecretFileScrubberTests {
    @Test("scrubs known secrets in high-signal paths")
    func scrubsHighSignalPaths() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "11111111-1111-4111-8111-111111111111"
        let envPath = directory.appendingPathComponent(".env").path
        try "API_KEY=\(secret)\n".write(toFile: envPath, atomically: true, encoding: .utf8)
        let grantID = UUID()

        let masker = OutputMasker(secrets: [secret])
        let results = InjectedSecretFileScrubber.scrub(
            paths: [envPath],
            masker: masker,
            allowedRoots: [directory.path],
            context: InjectedSecretFileScrubContext(
                agentJITGrantIDs: [grantID],
                agentPlatform: "codex",
                terminalSessionScope: "term",
                workingDirectory: directory.path,
                workspaceRoot: directory.path
            ),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .scrubbed)
        #expect(results[0].events.count == 1)
        #expect(results[0].event?.agentJITGrantID == grantID)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.scrubbed)
        #expect(results[0].event?.captureSource == .injectedExec)

        let contents = try String(contentsOfFile: envPath, encoding: .utf8)
        #expect(contents.contains(OutputMasker.placeholder))
        #expect(!contents.contains(secret))
    }

    @Test("scrubs ordinary filenames containing injected secrets")
    func scrubsOrdinaryFilenames() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "22222222-2222-4222-8222-222222222222"
        let notesPath = directory.appendingPathComponent("notes.txt").path
        try "leak=\(secret)\n".write(toFile: notesPath, atomically: true, encoding: .utf8)

        let masker = OutputMasker(secrets: [secret])
        let results = InjectedSecretFileScrubber.scrub(
            paths: [notesPath],
            masker: masker,
            allowedRoots: [directory.path],
            context: InjectedSecretFileScrubContext(
                agentJITGrantIDs: [],
                agentPlatform: nil,
                terminalSessionScope: nil,
                workingDirectory: directory.path,
                workspaceRoot: directory.path
            ),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .scrubbed)
        #expect(results[0].events.count == 1)
        #expect(results[0].event?.agentJITGrantID == nil)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.scrubbed)

        let contents = try String(contentsOfFile: notesPath, encoding: .utf8)
        #expect(contents.contains(OutputMasker.placeholder))
        #expect(!contents.contains(secret))
    }

    @Test("detect-only reports exact matches without an Authsia rewrite")
    func detectOnlyReportsExactMatchesWithoutAuthsiaRewrite() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "detect-only-secret-value"
        let path = directory.appendingPathComponent("notes.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o640)],
            ofItemAtPath: path
        )
        let originalMetadata = try fileMetadata(atPath: path)
        var reachedBeforeRewrite = false
        var reachedAfterRewrite = false

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(exactSecrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .detectOnly,
            hooks: InjectedSecretFileScrubHooks(
                beforeRewrite: {
                    reachedBeforeRewrite = true
                },
                afterRewrite: {
                    reachedAfterRewrite = true
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .detected)
        #expect(results[0].isIncomplete)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.secretDetected)
        #expect(results[0].event?.action == .modify)
        #expect(results[0].event?.status == .inferred)
        #expect(!reachedBeforeRewrite)
        #expect(!reachedAfterRewrite)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)

        // O_RDONLY inspection may let the filesystem update atime. These assertions
        // cover bytes, rewrite hooks, and metadata Authsia's rewrite path controls.
        let finalMetadata = try fileMetadata(atPath: path)
        #expect(finalMetadata.st_mode == originalMetadata.st_mode)
        #expect(finalMetadata.st_uid == originalMetadata.st_uid)
        #expect(finalMetadata.st_gid == originalMetadata.st_gid)
        #expect(finalMetadata.st_flags == originalMetadata.st_flags)
        #expect(finalMetadata.st_nlink == originalMetadata.st_nlink)
        #expect(finalMetadata.st_size == originalMetadata.st_size)
        #expect(
            finalMetadata.st_mtimespec.tv_sec == originalMetadata.st_mtimespec.tv_sec
                && finalMetadata.st_mtimespec.tv_nsec == originalMetadata.st_mtimespec.tv_nsec
        )
        #expect(
            finalMetadata.st_birthtimespec.tv_sec == originalMetadata.st_birthtimespec.tv_sec
                && finalMetadata.st_birthtimespec.tv_nsec
                    == originalMetadata.st_birthtimespec.tv_nsec
        )
        #expect(
            finalMetadata.st_ctimespec.tv_sec == originalMetadata.st_ctimespec.tv_sec
                && finalMetadata.st_ctimespec.tv_nsec == originalMetadata.st_ctimespec.tv_nsec
        )
    }

    @Test("batch inspection stops at its unique path cap")
    func batchInspectionPathCapMarksIncomplete() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let paths = try ["first.txt", "second.txt", "overflow.txt"].map { name in
            let path = directory.appendingPathComponent(name).path
            try "safe".write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let results = InjectedSecretFileScrubber.scrub(
            paths: [paths[0], paths[0], paths[1], paths[2]],
            masker: OutputMasker(exactSecrets: ["eligible-secret-value"]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            maximumPaths: 2,
            maximumTotalBytes: 1_024,
            maximumDuration: 60,
            mode: .detectOnly
        )

        #expect(results.map(\.outcome) == [.noMatch, .noMatch, .verificationFailed])
        #expect(results.last?.path == paths[2])
        #expect(results.last?.event == nil)
    }

    @Test("batch inspection stops before exceeding its total content budget")
    func batchInspectionByteBudgetMarksIncomplete() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let first = directory.appendingPathComponent("first.txt").path
        let overflow = directory.appendingPathComponent("overflow.txt").path
        try "abc".write(toFile: first, atomically: true, encoding: .utf8)
        try "def".write(toFile: overflow, atomically: true, encoding: .utf8)
        var readCounts: [Int] = []

        let results = InjectedSecretFileScrubber.scrub(
            paths: [first, overflow],
            masker: OutputMasker(exactSecrets: ["eligible-secret-value"]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            maximumPaths: 10,
            maximumTotalBytes: 4,
            maximumDuration: 60,
            mode: .detectOnly,
            hooks: InjectedSecretFileScrubHooks(
                targetRead: { readCounts.append($0) }
            )
        )

        #expect(readCounts == [3])
        #expect(results.map(\.outcome) == [.noMatch, .verificationFailed])
        #expect(results.last?.event == nil)
    }

    @Test("batch inspection stops at its monotonic deadline")
    func batchInspectionDeadlineMarksIncomplete() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let first = directory.appendingPathComponent("first.txt").path
        let overflow = directory.appendingPathComponent("overflow.txt").path
        try "safe".write(toFile: first, atomically: true, encoding: .utf8)
        try "safe".write(toFile: overflow, atomically: true, encoding: .utf8)
        var clockValues = [1_000.0, 1_000.0, 1_002.0].makeIterator()

        let results = InjectedSecretFileScrubber.scrub(
            paths: [first, overflow],
            masker: OutputMasker(exactSecrets: ["eligible-secret-value"]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            maximumPaths: 10,
            maximumTotalBytes: 1_024,
            maximumDuration: 1,
            monotonicNow: { clockValues.next() ?? 1_002 },
            mode: .detectOnly
        )

        #expect(results.map(\.outcome) == [.noMatch, .verificationFailed])
        #expect(results.last?.event == nil)
    }

    @Test("reports paths outside allowed roots without an event")
    func reportsOutsideRoots() throws {
        let allowed = try temporaryDirectory()
        let outside = try temporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: allowed)
            try? FileManager.default.removeItem(at: outside)
        }

        let secret = "33333333-3333-4333-8333-333333333333"
        let path = outside.appendingPathComponent(".env").path
        try "TOKEN=\(secret)\n".write(toFile: path, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [allowed.path],
            context: InjectedSecretFileScrubContext(
                agentJITGrantIDs: [],
                agentPlatform: nil,
                terminalSessionScope: nil,
                workingDirectory: allowed.path,
                workspaceRoot: allowed.path
            ),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .outsideAllowedRoots)
        #expect(results[0].event == nil)
        let contents = try String(contentsOfFile: path, encoding: .utf8)
        #expect(contents.contains(secret))
    }

    @Test("outside-root cleanup results make requested cleanup incomplete")
    func outsideRootResultsMakeRequestedCleanupIncomplete() {
        let outside = InjectedSecretFileScrubResult(
            path: "outside.txt",
            outcome: .outsideAllowedRoots,
            event: nil
        )
        let scrubbed = InjectedSecretFileScrubResult(
            path: "scrubbed.txt",
            outcome: .scrubbed,
            event: nil
        )
        let detected = InjectedSecretFileScrubResult(
            path: "detected.txt",
            outcome: .detected,
            event: nil
        )

        #expect(outside.isIncomplete)
        #expect(detected.isIncomplete)
        #expect(InjectedSecretFileCleanupStatus.forRequestedCleanup([outside]) == .incomplete)
        #expect(InjectedSecretFileCleanupStatus.forRequestedCleanup([detected]) == .incomplete)
        #expect(InjectedSecretFileCleanupStatus.forRequestedCleanup([scrubbed, outside]) == .incomplete)
        #expect(InjectedSecretFileCleanupStatus.forRequestedCleanup([scrubbed]) == .complete)
    }

    @Test("reports a missing outside parent as outside allowed roots")
    func reportsMissingOutsideParentAsOutsideRoots() throws {
        let allowed = try temporaryDirectory()
        let outside = try temporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: allowed)
            try? FileManager.default.removeItem(at: outside)
        }

        let path = outside
            .appendingPathComponent("missing-parent", isDirectory: true)
            .appendingPathComponent("missing.txt")
            .path
        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: ["12121212-1212-4212-8212-121212121212"]),
            allowedRoots: [allowed.path],
            context: scrubContext(directory: allowed),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .outsideAllowedRoots)
        #expect(results[0].event == nil)
    }

    @Test("rejects paths escaping an allowed root through a symlinked parent")
    func rejectsSymlinkedParentEscapes() throws {
        let allowed = try temporaryDirectory()
        let outside = try temporaryDirectory()
        defer {
            try? FileManager.default.removeItem(at: allowed)
            try? FileManager.default.removeItem(at: outside)
        }

        let secret = "CCCCCCCC-CCCC-4CCC-8CCC-CCCCCCCCCCCC"
        let outsidePath = outside.appendingPathComponent("outside.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: outsidePath, atomically: true, encoding: .utf8)

        let linkedDirectory = allowed.appendingPathComponent("linked", isDirectory: true)
        try FileManager.default.createSymbolicLink(
            atPath: linkedDirectory.path,
            withDestinationPath: outside.path
        )
        let candidatePath = linkedDirectory.appendingPathComponent("outside.txt").path

        let results = InjectedSecretFileScrubber.scrub(
            paths: [candidatePath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [allowed.path],
            context: scrubContext(directory: allowed),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .outsideAllowedRoots)
        #expect(results[0].event == nil)
        #expect(try String(contentsOfFile: outsidePath, encoding: .utf8) == original)
    }

    @Test("reports missing paths without an event")
    func reportsMissingPaths() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let missingPath = directory.appendingPathComponent("missing.txt").path
        let results = InjectedSecretFileScrubber.scrub(
            paths: [missingPath],
            masker: OutputMasker(secrets: ["44444444-4444-4444-8444-444444444444"]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .notFound)
        #expect(results[0].event == nil)
    }

    @Test("reports UTF-8 files without an injected token as no match")
    func reportsNoMatch() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let path = directory.appendingPathComponent("notes.txt").path
        try "ordinary text\n".write(toFile: path, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: ["55555555-5555-4555-8555-555555555555"]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .noMatch)
        #expect(results[0].event == nil)
    }

    @Test("does not follow symbolic links")
    func rejectsSymbolicLinks() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "66666666-6666-4666-8666-666666666666"
        let targetPath = directory.appendingPathComponent("target.txt").path
        let linkPath = directory.appendingPathComponent("link.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: targetPath, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: linkPath, withDestinationPath: targetPath)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [linkPath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .verificationFailed)
        #expect(results[0].event?.status == .failed)
        #expect(results[0].event?.action == .modify)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.verificationFailed)
        #expect(try String(contentsOfFile: targetPath, encoding: .utf8) == original)
    }

    @Test("detect-only records unsafe symbolic links as incomplete inspection")
    func detectOnlyRejectsSymbolicLinksAsInspectionFailure() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "detect-only-symlink-secret"
        let targetPath = directory.appendingPathComponent("target.txt").path
        let linkPath = directory.appendingPathComponent("link.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: targetPath, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(
            atPath: linkPath,
            withDestinationPath: targetPath
        )

        let results = InjectedSecretFileScrubber.scrub(
            paths: [linkPath],
            masker: OutputMasker(exactSecrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .detectOnly
        )

        #expect(results.map(\.outcome) == [.verificationFailed])
        #expect(results[0].event?.status == .failed)
        #expect(results[0].event?.detail == "inspection-failed")
        #expect(try String(contentsOfFile: targetPath, encoding: .utf8) == original)
    }

    @Test("does not rewrite hard-linked files")
    func rejectsHardLinkedFiles() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "77777777-7777-4777-8777-777777777777"
        let firstPath = directory.appendingPathComponent("first.txt").path
        let secondPath = directory.appendingPathComponent("second.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: firstPath, atomically: true, encoding: .utf8)
        try FileManager.default.linkItem(
            at: URL(fileURLWithPath: firstPath),
            to: URL(fileURLWithPath: secondPath)
        )

        let results = InjectedSecretFileScrubber.scrub(
            paths: [firstPath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .verificationFailed)
        #expect(results[0].event?.status == .failed)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.verificationFailed)
        #expect(try String(contentsOfFile: firstPath, encoding: .utf8) == original)
        #expect(try String(contentsOfFile: secondPath, encoding: .utf8) == original)
    }

    @Test("does not rewrite oversized files")
    func rejectsOversizedFiles() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "88888888-8888-4888-8888-888888888888"
        let path = directory.appendingPathComponent("oversized.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: path, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            maxBytes: 8,
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .verificationFailed)
        #expect(results[0].event?.status == .failed)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.verificationFailed)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
    }

    @Test("does not rewrite invalid UTF-8 files")
    func rejectsInvalidUTF8Files() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "99999999-9999-4999-8999-999999999999"
        let path = directory.appendingPathComponent("invalid.txt").path
        var original = Data("leak=\(secret)\n".utf8)
        original.append(0xFF)
        try original.write(to: URL(fileURLWithPath: path))

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .verificationFailed)
        #expect(results[0].event?.status == .failed)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.verificationFailed)
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == original)
    }

    @Test("descriptor rewrite preserves ACL, xattrs, flags, and exact timestamps")
    func descriptorRewritePreservesFileMetadata() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "DDDDDDDD-DDDD-4DDD-8DDD-DDDDDDDDDDDD"
        let path = directory.appendingPathComponent("private.txt").path
        let original = "leak=\(secret)\n"
        let extendedAttributeName = "com.authsia.tests.synthetic"
        let extendedAttributeValue = Data("synthetic-metadata".utf8)
        let resourceForkName = "com.apple.ResourceFork"
        let resourceForkValue = Data([0x00, 0x01, 0x02, 0x03])
        try original.write(toFile: path, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o640)],
            ofItemAtPath: path
        )
        try setExtendedAttribute(
            extendedAttributeValue,
            named: extendedAttributeName,
            atPath: path
        )
        try setExtendedAttribute(resourceForkValue, named: resourceForkName, atPath: path)
        #expect(
            Darwin.chflags(path, UInt32(UF_HIDDEN)) == 0
        )
        let expectedTimestamps = TestFileTimestamps(
            creation: timespec(tv_sec: 1_700_000_000, tv_nsec: 123_456_789),
            modification: timespec(tv_sec: 1_700_000_100, tv_nsec: 234_567_890),
            access: timespec(tv_sec: 1_700_000_200, tv_nsec: 345_678_901)
        )
        try setFileTimestamps(expectedTimestamps, atPath: path)
        let aclIsSupported = try addSyntheticACL(atPath: path)
        let originalACL = try accessControlList(atPath: path)
        let originalMetadata = try fileMetadata(atPath: path)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .scrubbed)
        let finalMetadata = try fileMetadata(atPath: path)
        #expect(finalMetadata.st_mode & mode_t(0o7777) == mode_t(0o640))
        #expect(finalMetadata.st_uid == originalMetadata.st_uid)
        #expect(finalMetadata.st_gid == originalMetadata.st_gid)
        #expect(finalMetadata.st_flags == originalMetadata.st_flags)
        #expect(
            finalMetadata.st_atimespec.tv_sec == originalMetadata.st_atimespec.tv_sec
                && finalMetadata.st_atimespec.tv_nsec == originalMetadata.st_atimespec.tv_nsec
        )
        #expect(
            finalMetadata.st_mtimespec.tv_sec == originalMetadata.st_mtimespec.tv_sec
                && finalMetadata.st_mtimespec.tv_nsec == originalMetadata.st_mtimespec.tv_nsec
        )
        #expect(
            finalMetadata.st_birthtimespec.tv_sec == originalMetadata.st_birthtimespec.tv_sec
                && finalMetadata.st_birthtimespec.tv_nsec
                    == originalMetadata.st_birthtimespec.tv_nsec
        )
        #expect(
            try extendedAttribute(named: extendedAttributeName, atPath: path)
                == extendedAttributeValue
        )
        #expect(
            try extendedAttribute(named: resourceForkName, atPath: path)
                == resourceForkValue
        )
        if aclIsSupported {
            #expect(try accessControlList(atPath: path) == originalACL)
        }
        let contents = try String(contentsOfFile: path, encoding: .utf8)
        #expect(contents.contains(OutputMasker.placeholder))
        #expect(!contents.contains(secret))
        #expect(try scrubTemporaryFiles(in: directory).isEmpty)
    }

    @Test("post-rewrite xattr mutation is detected and original metadata is restored")
    func detectsAndRestoresPostRewriteXattrMutation() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "DEDEDEDE-DEDE-4EDE-8EDE-DEDEDEDEDEDE"
        let path = directory.appendingPathComponent("metadata-race.txt").path
        let original = "leak=\(secret)\n"
        let attributeName = "com.authsia.tests.synthetic"
        let originalAttribute = Data("original-metadata".utf8)
        let replacementAttribute = Data("replacement-metadata".utf8)
        try original.write(toFile: path, atomically: true, encoding: .utf8)
        try setExtendedAttribute(originalAttribute, named: attributeName, atPath: path)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                afterRewrite: {
                    try setExtendedAttribute(
                        replacementAttribute,
                        named: attributeName,
                        atPath: path
                    )
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .remediationFailed)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
        #expect(
            try extendedAttribute(named: attributeName, atPath: path)
                == originalAttribute
        )
    }

    @Test("caps reads when a verified file grows after opening")
    func capsReadsAfterTargetGrowth() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "EEEEEEEE-EEEE-4EEE-8EEE-EEEEEEEEEEEE"
        let path = directory.appendingPathComponent("growing.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: path, atomically: true, encoding: .utf8)
        let maxBytes = Data(original.utf8).count
        let appended = Data(repeating: 0x41, count: 1_048_576)
        var observedReadBytes: Int?

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            maxBytes: maxBytes,
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                afterTargetOpened: {
                    let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
                    try handle.seekToEnd()
                    try handle.write(contentsOf: appended)
                    try handle.close()
                },
                targetRead: { byteCount in
                    observedReadBytes = byteCount
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .verificationFailed)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.verificationFailed)
        #expect(observedReadBytes == maxBytes + 1)
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)).count == maxBytes + appended.count)
        #expect(try scrubTemporaryFiles(in: directory).isEmpty)
    }

    @Test("rejects a directory entry swapped after the target is opened")
    func rejectsConcurrentEntrySwap() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "FFFFFFFF-FFFF-4FFF-8FFF-FFFFFFFFFFFF"
        let path = directory.appendingPathComponent("target.txt").path
        let displacedPath = directory.appendingPathComponent("displaced.txt").path
        let original = "leak=\(secret)\n"
        let replacement = "replacement without injected content\n"
        try original.write(toFile: path, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                afterTargetOpened: {
                    try FileManager.default.moveItem(atPath: path, toPath: displacedPath)
                    try replacement.write(toFile: path, atomically: true, encoding: .utf8)
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .verificationFailed)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.verificationFailed)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == replacement)
        #expect(try String(contentsOfFile: displacedPath, encoding: .utf8) == original)
        #expect(try scrubTemporaryFiles(in: directory).isEmpty)
    }

    @Test("preserves a replacement inserted immediately before descriptor rewrite")
    func preservesReplacementInsertedBeforeDescriptorRewrite() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "ABABABAB-ABAB-4BAB-8BAB-ABABABABABAB"
        let path = directory.appendingPathComponent("target.txt").path
        let displacedPath = directory.appendingPathComponent("displaced-original.txt").path
        let original = "leak=\(secret)\n"
        let replacement = "replacement remains authoritative\n"
        try original.write(toFile: path, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                beforeRewrite: {
                    try FileManager.default.moveItem(atPath: path, toPath: displacedPath)
                    try replacement.write(toFile: path, atomically: true, encoding: .utf8)
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .remediationFailed)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.remediationFailed)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == replacement)
        #expect(try String(contentsOfFile: displacedPath, encoding: .utf8) == original)
        #expect(try scrubTemporaryFiles(in: directory).isEmpty)
    }

    @Test("restores a displaced original without unlinking a post-rewrite replacement")
    func restoresDisplacedOriginalAfterDescriptorRewrite() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "ACACACAC-ACAC-4CAC-8CAC-ACACACACACAC"
        let path = directory.appendingPathComponent("target.txt").path
        let displacedPath = directory.appendingPathComponent("displaced-original.txt").path
        let original = "leak=\(secret)\n"
        let replacement = "replacement remains authoritative\n"
        try original.write(toFile: path, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                afterRewrite: {
                    try FileManager.default.moveItem(atPath: path, toPath: displacedPath)
                    try replacement.write(toFile: path, atomically: true, encoding: .utf8)
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .remediationFailed)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.remediationFailed)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == replacement)
        #expect(try String(contentsOfFile: displacedPath, encoding: .utf8) == original)
        #expect(try scrubTemporaryFiles(in: directory).isEmpty)
    }

    @Test("does not rewrite a parent directory relocated outside allowed roots")
    func rejectsParentRelocationBeforeDescriptorRewrite() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let allowedRoot = parent.appendingPathComponent("allowed", isDirectory: true)
        let originalDirectory = allowedRoot.appendingPathComponent("project", isDirectory: true)
        let relocatedDirectory = parent.appendingPathComponent("relocated", isDirectory: true)
        try FileManager.default.createDirectory(
            at: originalDirectory,
            withIntermediateDirectories: true
        )

        let secret = "ADADADAD-ADAD-4DAD-8DAD-ADADADADADAD"
        let originalPath = originalDirectory.appendingPathComponent("target.txt").path
        let relocatedPath = relocatedDirectory.appendingPathComponent("target.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: originalPath, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [originalPath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [allowedRoot.path],
            context: scrubContext(directory: allowedRoot),
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                beforeRewrite: {
                    try FileManager.default.moveItem(
                        at: originalDirectory,
                        to: relocatedDirectory
                    )
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .remediationFailed)
        #expect(!FileManager.default.fileExists(atPath: originalPath))
        #expect(try String(contentsOfFile: relocatedPath, encoding: .utf8) == original)
    }

    @Test("restores a parent directory relocated outside roots after rewrite")
    func restoresParentRelocationAfterDescriptorRewrite() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let allowedRoot = parent.appendingPathComponent("allowed", isDirectory: true)
        let originalDirectory = allowedRoot.appendingPathComponent("project", isDirectory: true)
        let relocatedDirectory = parent.appendingPathComponent("relocated", isDirectory: true)
        try FileManager.default.createDirectory(
            at: originalDirectory,
            withIntermediateDirectories: true
        )

        let secret = "AEAEAEAE-AEAE-4EAE-8EAE-AEAEAEAEAEAE"
        let originalPath = originalDirectory.appendingPathComponent("target.txt").path
        let relocatedPath = relocatedDirectory.appendingPathComponent("target.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: originalPath, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [originalPath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [allowedRoot.path],
            context: scrubContext(directory: allowedRoot),
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                afterRewrite: {
                    try FileManager.default.moveItem(
                        at: originalDirectory,
                        to: relocatedDirectory
                    )
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .remediationFailed)
        #expect(!FileManager.default.fileExists(atPath: originalPath))
        #expect(try String(contentsOfFile: relocatedPath, encoding: .utf8) == original)
    }

    @Test("allows a parent directory rename within an allowed root")
    func allowsParentRelocationWithinAllowedRoot() throws {
        let allowedRoot = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: allowedRoot) }

        let originalDirectory = allowedRoot.appendingPathComponent("before", isDirectory: true)
        let relocatedDirectory = allowedRoot.appendingPathComponent("after", isDirectory: true)
        try FileManager.default.createDirectory(
            at: originalDirectory,
            withIntermediateDirectories: true
        )

        let secret = "AFAFAFAF-AFAF-4FAF-8FAF-AFAFAFAFAFAF"
        let originalPath = originalDirectory.appendingPathComponent("target.txt").path
        let relocatedPath = relocatedDirectory.appendingPathComponent("target.txt").path
        try "leak=\(secret)\n".write(
            toFile: originalPath,
            atomically: true,
            encoding: .utf8
        )

        let results = InjectedSecretFileScrubber.scrub(
            paths: [originalPath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [allowedRoot.path],
            context: scrubContext(directory: allowedRoot),
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                beforeRewrite: {
                    try FileManager.default.moveItem(
                        at: originalDirectory,
                        to: relocatedDirectory
                    )
                }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .scrubbed)
        #expect(!FileManager.default.fileExists(atPath: originalPath))
        let contents = try String(contentsOfFile: relocatedPath, encoding: .utf8)
        #expect(contents.contains(OutputMasker.placeholder))
        #expect(!contents.contains(secret))
    }

    @Test("reports rewrite errors as remediation failures")
    func reportsRewriteErrors() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
        let path = directory.appendingPathComponent("locked.txt").path
        let original = "leak=\(secret)\n"
        try original.write(toFile: path, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [path],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate,
            hooks: InjectedSecretFileScrubHooks(
                beforeRewrite: { throw SyntheticRewriteFailure() }
            )
        )

        #expect(results.count == 1)
        #expect(results[0].outcome == .remediationFailed)
        #expect(results[0].isIncomplete)
        #expect(results[0].event?.status == .failed)
        #expect(results[0].event?.detail == InjectedSecretFileActivityDetail.remediationFailed)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
        #expect(try scrubTemporaryFiles(in: directory).isEmpty)
    }

    @Test("masks secret-bearing event paths and context before persistence")
    func masksEventMetadataBeforePersistence() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let secret = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"
        let directory = parent.appendingPathComponent("workspace-\(secret)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let targetPath = directory.appendingPathComponent("target.txt").path
        let linkPath = directory.appendingPathComponent("link-\(secret).txt").path
        try "leak=\(secret)\n".write(toFile: targetPath, atomically: true, encoding: .utf8)
        try FileManager.default.createSymbolicLink(atPath: linkPath, withDestinationPath: targetPath)
        let storeURL = parent.appendingPathComponent("events.jsonl")
        let store = AgentFileActivityStore(fileURL: storeURL)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [linkPath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: InjectedSecretFileScrubContext(
                agentJITGrantIDs: [],
                agentPlatform: "codex",
                terminalSessionScope: nil,
                workingDirectory: directory.appendingPathComponent("working-\(secret)").path,
                workspaceRoot: directory.path
            ),
            mode: .remediate
        )
        InjectedSecretFileScrubber.record(results: results, store: store)

        #expect(results.count == 1)
        #expect(results[0].path.contains(secret))
        #expect(results[0].outcome == .verificationFailed)
        let persisted = try String(contentsOf: storeURL, encoding: .utf8)
        #expect(!persisted.contains(secret))
        #expect(persisted.contains(OutputMasker.placeholder))
        let events = try store.loadAll()
        #expect(events.count == 1)
        #expect(events[0].path.contains(OutputMasker.placeholder))
        #expect(events[0].workingDirectory?.contains(OutputMasker.placeholder) == true)
        #expect(events[0].workspaceRoot?.contains(OutputMasker.placeholder) == true)
    }

    @Test("records one deterministic event per unique JIT grant")
    func recordsUniqueJITGrantEvents() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "BCBCBCBC-BCBC-4CBC-8CBC-BCBCBCBCBCBC"
        let targetPath = directory.appendingPathComponent("target.txt").path
        let linkPath = directory.appendingPathComponent("link.txt").path
        try "leak=\(secret)\n".write(
            toFile: targetPath,
            atomically: true,
            encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            atPath: linkPath,
            withDestinationPath: targetPath
        )
        let firstGrantID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
        let secondGrantID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
        let store = AgentFileActivityStore(
            fileURL: directory.appendingPathComponent("events.jsonl")
        )

        let results = InjectedSecretFileScrubber.scrub(
            paths: [linkPath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: InjectedSecretFileScrubContext(
                agentJITGrantIDs: [secondGrantID, firstGrantID, secondGrantID],
                agentPlatform: "codex",
                terminalSessionScope: nil,
                workingDirectory: directory.path,
                workspaceRoot: directory.path
            ),
            mode: .remediate
        )
        InjectedSecretFileScrubber.record(results: results, store: store)

        #expect(results.count == 1)
        #expect(results[0].outcome == .verificationFailed)
        #expect(results[0].event == nil)
        let events = try store.loadAll()
        #expect(events.count == 2)
        #expect(events.map(\.agentJITGrantID) == [firstGrantID, secondGrantID])
    }

    @Test("mtime fallback finds modified high-signal files")
    func mtimeFallbackFindsHighSignalFiles() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let startedAt = Date().addingTimeInterval(-1)
        let envPath = directory.appendingPathComponent(".env").path
        try "API_KEY=value\n".write(toFile: envPath, atomically: true, encoding: .utf8)

        let found = InjectedFileTouchWatcher.highSignalModifiedSince(
            startedAt,
            roots: [directory.path]
        )
        #expect(found.paths.contains(URL(fileURLWithPath: envPath).standardizedFileURL.path))
        #expect(!found.isIncomplete)
    }

    @Test("event candidate paths stop at their cap and mark inspection incomplete")
    func eventCandidatePathCapMarksIncomplete() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let first = directory.appendingPathComponent("first.txt").path
        let second = directory.appendingPathComponent("second.txt").path
        let overflow = directory.appendingPathComponent("overflow.txt").path
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true },
            maximumCandidatePaths: 2
        )

        watcher.recordForTesting(first)
        watcher.recordForTesting(first)
        watcher.recordForTesting(second)
        watcher.recordForTesting(overflow)
        let result = watcher.stop()

        #expect(result.paths == [first, second])
        #expect(result.isIncomplete)
    }

    @Test("mtime fallback stops at its entry cap")
    func mtimeFallbackEntryCapMarksIncomplete() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        try "A=value\n".write(
            toFile: directory.appendingPathComponent(".env").path,
            atomically: true,
            encoding: .utf8
        )
        try "B=value\n".write(
            toFile: directory.appendingPathComponent(".env.local").path,
            atomically: true,
            encoding: .utf8
        )

        let result = InjectedFileTouchWatcher.highSignalModifiedSince(
            Date().addingTimeInterval(-1),
            roots: [directory.path],
            maximumEntries: 1,
            maximumDuration: 60
        )

        #expect(result.isIncomplete)
        #expect(result.paths.count <= 1)
    }

    @Test("mtime fallback stops at its deadline")
    func mtimeFallbackDeadlineMarksIncomplete() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        try "A=value\n".write(
            toFile: directory.appendingPathComponent(".env").path,
            atomically: true,
            encoding: .utf8
        )
        let base: TimeInterval = 1_000
        var clockValues = [
            base,
            base + 2,
        ].makeIterator()

        let result = InjectedFileTouchWatcher.highSignalModifiedSince(
            Date().addingTimeInterval(-1),
            roots: [directory.path],
            maximumEntries: 100,
            maximumDuration: 1,
            now: { clockValues.next() ?? base + 2 }
        )

        #expect(result.isIncomplete)
        #expect(result.paths.isEmpty)
    }

    @Test("mtime fallback prunes generated directories")
    func mtimeFallbackPrunesGeneratedDirectories() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        var prunedPaths: [String] = []
        for name in [".git", ".build", "DerivedData", "node_modules"] {
            let generated = directory.appendingPathComponent(name, isDirectory: true)
            try FileManager.default.createDirectory(
                at: generated,
                withIntermediateDirectories: true
            )
            let path = generated.appendingPathComponent(".env").path
            try "GENERATED=value\n".write(
                toFile: path,
                atomically: true,
                encoding: .utf8
            )
            prunedPaths.append(path)
        }
        let source = directory.appendingPathComponent("Sources", isDirectory: true)
        try FileManager.default.createDirectory(
            at: source,
            withIntermediateDirectories: true
        )
        let visiblePath = source.appendingPathComponent(".env").path
        try "VISIBLE=value\n".write(
            toFile: visiblePath,
            atomically: true,
            encoding: .utf8
        )

        let result = InjectedFileTouchWatcher.highSignalModifiedSince(
            Date().addingTimeInterval(-1),
            roots: [directory.path]
        )

        #expect(!result.isIncomplete)
        #expect(result.paths == [visiblePath])
        #expect(prunedPaths.allSatisfy { !result.paths.contains($0) })
    }

    @Test("mtime fallback deduplicates overlapping roots")
    func mtimeFallbackDeduplicatesOverlappingRoots() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let source = directory.appendingPathComponent("Sources", isDirectory: true)
        try FileManager.default.createDirectory(
            at: source,
            withIntermediateDirectories: true
        )
        let envPath = source.appendingPathComponent(".env").path
        try "A=value\n".write(
            toFile: envPath,
            atomically: true,
            encoding: .utf8
        )

        let result = InjectedFileTouchWatcher.highSignalModifiedSince(
            Date().addingTimeInterval(-1),
            roots: [source.path, directory.path, source.path]
        )

        #expect(!result.isIncomplete)
        #expect(result.paths == [envPath])
    }

    @Test("mtime fallback reports enumeration failure")
    func mtimeFallbackEnumerationFailureMarksIncomplete() {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-missing-\(UUID().uuidString)")

        let result = InjectedFileTouchWatcher.highSignalModifiedSince(
            Date().addingTimeInterval(-1),
            roots: [missing.path]
        )

        #expect(result.paths.isEmpty)
        #expect(result.isIncomplete)
    }

    @Test("mtime fallback rejects a replaced captured root")
    func mtimeFallbackRevalidatesCapturedRoot() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let root = parent.appendingPathComponent("workspace", isDirectory: true)
        let relocated = parent.appendingPathComponent("relocated", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        let binding = try #require(InjectedFileTouchRootBinding(path: root.path))
        try FileManager.default.moveItem(at: root, to: relocated)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        try "TOKEN=replacement\n".write(
            to: root.appendingPathComponent(".env"),
            atomically: true,
            encoding: .utf8
        )

        let result = InjectedFileTouchWatcher.highSignalModifiedSince(
            Date().addingTimeInterval(-1),
            rootBindings: [binding]
        )

        #expect(result.paths.isEmpty)
        #expect(result.isIncomplete)
    }

    @Test("default roots reject an unrelated workspace but retain working directory")
    func defaultRootsRejectUnrelatedWorkspace() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let workspaceRoot = directory.appendingPathComponent("workspace", isDirectory: true)
        let workingDirectory = directory.appendingPathComponent("working", isDirectory: true)
        try FileManager.default.createDirectory(at: workspaceRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: workingDirectory, withIntermediateDirectories: true)

        let selection = InjectedFileTouchWatcher.defaultRoots(
            workspaceRoot: workspaceRoot.path,
            workingDirectory: workingDirectory.path,
            environment: [:],
            fileManager: .default
        )

        #expect(!selection.roots.contains(workspaceRoot.resolvingSymlinksInPath().path))
        #expect(selection.roots.contains(workingDirectory.resolvingSymlinksInPath().path))
        #expect(selection.isIncomplete)
    }

    @Test("valid workspace ancestor and working directory are both roots")
    func defaultRootsIncludeWorkspaceAncestorAndWorkingDirectory() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let workspaceRoot = directory.appendingPathComponent("workspace", isDirectory: true)
        let workingDirectory = workspaceRoot.appendingPathComponent("working", isDirectory: true)
        try FileManager.default.createDirectory(at: workingDirectory, withIntermediateDirectories: true)

        let selection = InjectedFileTouchWatcher.defaultRoots(
            workspaceRoot: workspaceRoot.path,
            workingDirectory: workingDirectory.path,
            environment: [:],
            fileManager: .default
        )

        #expect(selection.roots.contains(workspaceRoot.resolvingSymlinksInPath().path))
        #expect(selection.roots.contains(workingDirectory.resolvingSymlinksInPath().path))
        #expect(!selection.isIncomplete)
    }

    @Test("broad home ancestors are rejected as workspace roots")
    func defaultRootsRejectBroadWorkspaceRoots() {
        let workingDirectory = FileManager.default.currentDirectoryPath
        let home = FileManager.default.homeDirectoryForCurrentUser
            .resolvingSymlinksInPath()
            .path
        let homeParent = URL(fileURLWithPath: home)
            .deletingLastPathComponent()
            .path

        for broadRoot in [home, homeParent] {
            let selection = InjectedFileTouchWatcher.defaultRoots(
                workspaceRoot: broadRoot,
                workingDirectory: workingDirectory,
                environment: [:],
                fileManager: .default
            )

            #expect(!selection.roots.contains(broadRoot))
            #expect(selection.isIncomplete)
        }
    }

    @Test("home directory is rejected as the working root while safe temp roots remain")
    func defaultRootsRejectHomeWorkingDirectory() {
        let home = FileManager.default.homeDirectoryForCurrentUser
            .resolvingSymlinksInPath()
            .path
        let trustedTemp = URL(fileURLWithPath: NSTemporaryDirectory())
            .resolvingSymlinksInPath()
            .path

        let selection = InjectedFileTouchWatcher.defaultRoots(
            workspaceRoot: nil,
            workingDirectory: home,
            environment: [:],
            fileManager: .default
        )

        #expect(!selection.roots.contains(home))
        #expect(selection.roots.contains(trustedTemp))
        #expect(selection.isIncomplete)
    }

    @Test("workspace descendants of the working directory are rejected")
    func defaultRootsRejectDescendantWorkspace() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let workingDirectory = directory.appendingPathComponent("project", isDirectory: true)
        let descendantWorkspace = workingDirectory.appendingPathComponent("nested", isDirectory: true)
        try FileManager.default.createDirectory(
            at: descendantWorkspace,
            withIntermediateDirectories: true
        )

        let selection = InjectedFileTouchWatcher.defaultRoots(
            workspaceRoot: descendantWorkspace.path,
            workingDirectory: workingDirectory.path,
            environment: [:],
            fileManager: .default
        )

        #expect(selection.roots.contains(workingDirectory.resolvingSymlinksInPath().path))
        #expect(!selection.roots.contains(descendantWorkspace.resolvingSymlinksInPath().path))
        #expect(selection.isIncomplete)
    }

    @Test("filesystem mount lookup rejects a same-device mount root but accepts its project")
    func filesystemMountLookupRejectsSameDeviceRootButAcceptsProject() {
        let identities: [String: InjectedFileTouchDirectoryIdentity] = [
            "/": InjectedFileTouchDirectoryIdentity(device: 1, inode: 1),
            "/Users": InjectedFileTouchDirectoryIdentity(device: 1, inode: 2),
            "/Users/test": InjectedFileTouchDirectoryIdentity(device: 1, inode: 3),
            "/System": InjectedFileTouchDirectoryIdentity(device: 1, inode: 4),
            "/System/Volumes": InjectedFileTouchDirectoryIdentity(device: 1, inode: 5),
            "/System/Volumes/Data": InjectedFileTouchDirectoryIdentity(device: 1, inode: 6),
            "/System/Volumes/Data/Project": InjectedFileTouchDirectoryIdentity(device: 1, inode: 7),
            "/Mounts": InjectedFileTouchDirectoryIdentity(device: 1, inode: 8),
            "/Mounts/Alias": InjectedFileTouchDirectoryIdentity(device: 1, inode: 9),
            "/ReportedMount": InjectedFileTouchDirectoryIdentity(device: 1, inode: 9),
            "/private": InjectedFileTouchDirectoryIdentity(device: 1, inode: 10),
            "/private/tmp": InjectedFileTouchDirectoryIdentity(device: 1, inode: 11),
        ]
        let mountPoints: [String: String] = [
            "/System/Volumes/Data": "/System/Volumes/Data",
            "/System/Volumes/Data/Project": "/System/Volumes/Data",
            "/Mounts/Alias": "/ReportedMount",
            "/private/tmp": "/private/tmp",
        ]

        #expect(
            !InjectedFileTouchWatcher.isSafeObservationRoot(
                "/System/Volumes/Data",
                homeDirectory: "/Users/test",
                identityProvider: { identities[$0] },
                mountPointProvider: { mountPoints[$0] }
            )
        )
        #expect(
            InjectedFileTouchWatcher.isSafeObservationRoot(
                "/System/Volumes/Data/Project",
                homeDirectory: "/Users/test",
                identityProvider: { identities[$0] },
                mountPointProvider: { mountPoints[$0] }
            )
        )
        #expect(
            !InjectedFileTouchWatcher.isSafeObservationRoot(
                "/Mounts/Alias",
                homeDirectory: "/Users/test",
                identityProvider: { identities[$0] },
                mountPointProvider: { mountPoints[$0] }
            )
        )
        #expect(
            !InjectedFileTouchWatcher.isSafeObservationRoot(
                "/private/tmp",
                homeDirectory: "/Users/test",
                identityProvider: { identities[$0] },
                mountPointProvider: { mountPoints[$0] }
            )
        )
    }

    #if os(macOS)
    @Test("real Data volume root is rejected when mounted separately")
    func realDataVolumeRootIsRejectedWhenMountedSeparately() {
        let dataVolumeRoot = "/System/Volumes/Data"
        guard FileManager.default.fileExists(atPath: dataVolumeRoot),
              InjectedFileTouchWatcher.fileSystemMountPoint(at: dataVolumeRoot)
                == dataVolumeRoot else {
            return
        }

        let selection = InjectedFileTouchWatcher.defaultRoots(
            workspaceRoot: nil,
            workingDirectory: dataVolumeRoot,
            environment: [:],
            fileManager: .default
        )

        #expect(!selection.roots.contains(dataVolumeRoot))
        #expect(selection.isIncomplete)
    }
    #endif

    @Test("filesystem identity rejects a firmlink alias of a broad home ancestor")
    func filesystemIdentityRejectsHomeAncestorAlias() {
        let usersIdentity = InjectedFileTouchDirectoryIdentity(device: 1, inode: 20)
        let identities: [String: InjectedFileTouchDirectoryIdentity] = [
            "/": InjectedFileTouchDirectoryIdentity(device: 1, inode: 1),
            "/Users": usersIdentity,
            "/Users/test": InjectedFileTouchDirectoryIdentity(device: 1, inode: 21),
            "/System/Volumes/Data": InjectedFileTouchDirectoryIdentity(device: 1, inode: 22),
            "/System/Volumes/Data/Users": usersIdentity,
        ]

        #expect(
            !InjectedFileTouchWatcher.isSafeObservationRoot(
                "/System/Volumes/Data/Users",
                homeDirectory: "/Users/test",
                identityProvider: { identities[$0] }
            )
        )
    }

    @Test("filesystem root is never selected")
    func defaultRootsNeverIncludeFilesystemRoot() {
        let selection = InjectedFileTouchWatcher.defaultRoots(
            workspaceRoot: "/",
            workingDirectory: "/",
            environment: ["TMPDIR": "/"],
            fileManager: .default
        )

        #expect(!selection.roots.contains("/"))
        #expect(selection.isIncomplete)
    }

    @Test(
        "untrusted caller temp roots are excluded",
        arguments: ["/", "/Users", FileManager.default.currentDirectoryPath]
    )
    func defaultRootsRejectUntrustedCallerTempRoot(_ tmpDir: String) throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let selection = InjectedFileTouchWatcher.defaultRoots(
            workspaceRoot: directory.path,
            workingDirectory: directory.path,
            environment: ["TMPDIR": tmpDir],
            fileManager: .default
        )
        let canonicalTemp = URL(fileURLWithPath: tmpDir).resolvingSymlinksInPath().path

        #expect(!selection.roots.contains(canonicalTemp))
        #expect(selection.isIncomplete)
    }

    @Test("trusted caller temp root is included")
    func defaultRootsIncludeTrustedCallerTempRoot() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let trustedTemp = URL(fileURLWithPath: NSTemporaryDirectory())
            .resolvingSymlinksInPath()
            .path

        let selection = InjectedFileTouchWatcher.defaultRoots(
            workspaceRoot: directory.path,
            workingDirectory: directory.path,
            environment: ["TMPDIR": trustedTemp],
            fileManager: .default
        )

        #expect(selection.roots.contains(trustedTemp))
        #expect(!selection.isIncomplete)
    }

    @Test("file cleanup ignores output-only transformation tokens")
    func fileCleanupIgnoresOutputTransformationTokens() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "abcd-1234-efgh"
        let ordinaryPath = directory.appendingPathComponent("ordinary.txt").path
        let secretPath = directory.appendingPathComponent("secret.txt").path
        try "ordinary=a length=14\n".write(
            toFile: ordinaryPath,
            atomically: true,
            encoding: .utf8
        )
        try "leak=\(secret)\n".write(toFile: secretPath, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [ordinaryPath, secretPath],
            masker: OutputMasker(secrets: [secret]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate
        )

        #expect(results.map(\.outcome) == [.noMatch, .scrubbed])
        #expect(try String(contentsOfFile: ordinaryPath, encoding: .utf8) == "ordinary=a length=14\n")
        let secretContents = try String(contentsOfFile: secretPath, encoding: .utf8)
        #expect(secretContents.contains(OutputMasker.placeholder))
        #expect(!secretContents.contains(secret))
    }

    @Test("exact file cleanup ignores derived encodings but scrubs the original")
    func exactFileCleanupIgnoresDerivedEncodings() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let encodedPath = directory.appendingPathComponent("encoded.txt").path
        let exactPath = directory.appendingPathComponent("exact.txt").path
        try "base64=YWJjZA== hex=61626364\n".write(
            toFile: encodedPath,
            atomically: true,
            encoding: .utf8
        )
        try "secret=abcd\n".write(toFile: exactPath, atomically: true, encoding: .utf8)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [encodedPath, exactPath],
            masker: OutputMasker(exactSecrets: ["abcd"]),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            mode: .remediate
        )

        #expect(results.map(\.outcome) == [.noMatch, .scrubbed])
        #expect(
            try String(contentsOfFile: encodedPath, encoding: .utf8)
                == "base64=YWJjZA== hex=61626364\n"
        )
        let exactContents = try String(contentsOfFile: exactPath, encoding: .utf8)
        #expect(exactContents.contains(OutputMasker.placeholder))
        #expect(!exactContents.contains("abcd"))

        let outputMasker = OutputMasker(secrets: ["abcd"])
        #expect(outputMasker.mask("YWJjZA==") == OutputMasker.placeholder)
        #expect(outputMasker.mask("61626364") == OutputMasker.placeholder)
    }

    @Test("short injected values remain unchanged while eligible values scrub")
    func shortInjectedValuesRemainUnchangedAndMakeCleanupIncomplete() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let shortSecret = "short-value"
        let eligibleSecret = "eligible-secret-value"
        let shortPath = directory.appendingPathComponent("short.txt").path
        let eligiblePath = directory.appendingPathComponent("eligible.txt").path
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(shortPath)
        watcher.recordForTesting(eligiblePath)
        let cleanupSelection = Exec.fileCleanupSecretSelection(
            exactInjectedSecrets: [shortSecret, eligibleSecret]
        )
        let error = Pipe()
        let quotedDirectory = directory.path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "printf 'short=\(shortSecret)\\n' > '\(quotedDirectory)/short.txt'; "
                    + "printf 'eligible=\(eligibleSecret)\\n' > '\(quotedDirectory)/eligible.txt'",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [shortSecret, eligibleSecret]),
            fileCleanupMasker: OutputMasker(exactSecrets: cleanupSelection.secrets),
            fileCleanupSelectionIncomplete: cleanupSelection.isIncomplete,
            cleanupSecretFiles: true,
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(
                fileURL: directory.appendingPathComponent("files.jsonl")
            ),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.fileCleanupStatus == .incomplete)
        #expect(try String(contentsOfFile: shortPath, encoding: .utf8) == "short=\(shortSecret)\n")
        let eligibleContents = try String(contentsOfFile: eligiblePath, encoding: .utf8)
        #expect(eligibleContents.contains(OutputMasker.placeholder))
        #expect(!eligibleContents.contains(eligibleSecret))
        #expect(
            warning
                == "Warning: Authsia secret-file cleanup was incomplete; review Access Center. "
                    + "The child exit status was preserved.\n"
        )
    }

    @Test("failure event metadata masks every exact injected value")
    func failureEventMetadataMasksShortAndEligibleInjectedValues() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let shortSecret = "short-value"
        let eligibleSecret = "eligible-secret-value"
        let directory = parent.appendingPathComponent(
            "workspace-\(shortSecret)-\(eligibleSecret)",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let targetPath = directory.appendingPathComponent("target.txt").path
        let linkPath = directory.appendingPathComponent(
            "link-\(shortSecret)-\(eligibleSecret).txt"
        ).path
        try "original remains unchanged\n".write(
            toFile: targetPath,
            atomically: true,
            encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            atPath: linkPath,
            withDestinationPath: targetPath
        )
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(linkPath)
        let cleanupSelection = Exec.fileCleanupSecretSelection(
            exactInjectedSecrets: [shortSecret, eligibleSecret]
        )
        let activityURL = parent.appendingPathComponent("files.jsonl")
        let error = Pipe()

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "exit 0"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [shortSecret, eligibleSecret]),
            fileCleanupMasker: OutputMasker(exactSecrets: cleanupSelection.secrets),
            fileEventMetadataMasker: OutputMasker(
                exactSecrets: [shortSecret, eligibleSecret]
            ),
            fileCleanupSelectionIncomplete: cleanupSelection.isIncomplete,
            standardError: error.fileHandleForWriting,
            fileScrubContext: InjectedSecretFileScrubContext(
                agentJITGrantIDs: [],
                agentPlatform: "codex",
                terminalSessionScope: nil,
                workingDirectory: directory.path,
                workspaceRoot: directory.path
            ),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()

        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            try String(contentsOfFile: targetPath, encoding: .utf8)
                == "original remains unchanged\n"
        )
        let persisted = try String(contentsOf: activityURL, encoding: .utf8)
        #expect(!persisted.contains(shortSecret))
        #expect(!persisted.contains(eligibleSecret))
        #expect(persisted.contains(OutputMasker.placeholder))
        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.count == 1)
        #expect(events[0].agentJITGrantID == nil)
    }

    @Test("derived event metadata masking does not expand destructive cleanup")
    func derivedEventMetadataMaskingKeepsDestructiveCleanupExact() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let injectedSecrets = [
            "metadata-secret",
            "token/next-secret",
            "pa'ss word-secret",
        ]
        let derivedTokens = [
            "bWV0YWRhdGEtc2VjcmV0",
            "6d657461646174612d736563726574",
            "token%2Fnext-secret",
            #"pa\'ss\ word-secret"#,
        ]
        let cleanupSelection = Exec.fileCleanupSecretSelection(
            exactInjectedSecrets: injectedSecrets
        )
        #expect(cleanupSelection.secrets == injectedSecrets)
        #expect(derivedTokens.allSatisfy { !cleanupSelection.secrets.contains($0) })

        let encodedContentPath = directory.appendingPathComponent("encoded.txt").path
        try derivedTokens.joined(separator: "\n").write(
            toFile: encodedContentPath,
            atomically: true,
            encoding: .utf8
        )
        let targetPath = directory.appendingPathComponent("target.txt").path
        try "original remains unchanged\n".write(
            toFile: targetPath,
            atomically: true,
            encoding: .utf8
        )
        let failurePaths = derivedTokens.map {
            directory.appendingPathComponent("link-\($0).txt").path
        }
        for path in failurePaths {
            try FileManager.default.createSymbolicLink(
                atPath: path,
                withDestinationPath: targetPath
            )
        }
        let storeURL = directory.appendingPathComponent("files.jsonl")
        let store = AgentFileActivityStore(fileURL: storeURL)

        let results = InjectedSecretFileScrubber.scrub(
            paths: [encodedContentPath] + failurePaths,
            masker: OutputMasker(exactSecrets: cleanupSelection.secrets),
            allowedRoots: [directory.path],
            context: scrubContext(directory: directory),
            eventMetadataMasker: Exec.fileEventMetadataMasker(
                exactInjectedSecrets: injectedSecrets
            ),
            mode: .remediate
        )
        InjectedSecretFileScrubber.record(results: results, store: store)

        #expect(results.first?.outcome == .noMatch)
        #expect(
            try String(contentsOfFile: encodedContentPath, encoding: .utf8)
                == derivedTokens.joined(separator: "\n")
        )
        #expect(results.dropFirst().allSatisfy { $0.outcome == .verificationFailed })
        let persisted = try String(contentsOf: storeURL, encoding: .utf8)
        for token in derivedTokens {
            #expect(!persisted.contains(token))
        }
        #expect(persisted.contains(OutputMasker.placeholder))
    }

    @Test("runChildProcess uses exact cleanup masker instead of output transformations")
    func runChildProcessUsesExactCleanupMasker() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "abcd-1234-efgh"
        let ordinaryPath = directory.appendingPathComponent("ordinary.txt").path
        let secretPath = directory.appendingPathComponent("secret.txt").path
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(ordinaryPath)
        watcher.recordForTesting(secretPath)
        let quotedDirectory = directory.path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "printf 'ordinary=a length=14\\n' > '\(quotedDirectory)/ordinary.txt'; "
                    + "printf 'leak=\(secret)\\n' > '\(quotedDirectory)/secret.txt'",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret, "a", "14"]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            cleanupSecretFiles: true,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(
                fileURL: directory.appendingPathComponent("files.jsonl")
            ),
            fileTouchWatcher: watcher
        )

        #expect(result.fileCleanupStatus == .complete)
        #expect(try String(contentsOfFile: ordinaryPath, encoding: .utf8) == "ordinary=a length=14\n")
        let secretContents = try String(contentsOfFile: secretPath, encoding: .utf8)
        #expect(secretContents.contains(OutputMasker.placeholder))
        #expect(!secretContents.contains(secret))
    }

    @Test("runChildProcess scrubs high-signal secret files after exit")
    func runChildProcessScrubsHighSignalFiles() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let envPath = directory.appendingPathComponent(".env").path
        let secret = UUID().uuidString
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        let context = InjectedSecretFileScrubContext(
            agentJITGrantIDs: [UUID()],
            agentPlatform: "codex",
            terminalSessionScope: "test-scope",
            workingDirectory: directory.path,
            workspaceRoot: directory.path
        )

        let quotedDir = directory.path.replacingOccurrences(of: "'", with: "'\\''")
        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "printf 'API_KEY=\(secret)\\n' > '\(quotedDir)/.env'",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            cleanupSecretFiles: true,
            fileScrubContext: context,
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )

        #expect(result.terminationStatus == 0)
        #expect(result.fileCleanupStatus == .complete)
        let contents = try String(contentsOfFile: envPath, encoding: .utf8)
        #expect(contents.contains(OutputMasker.placeholder))
        #expect(!contents.contains(secret))

        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.contains { $0.detail == InjectedSecretFileActivityDetail.scrubbed })
    }

    @Test("runChildProcess scrubs ordinary secret files after exit")
    func runChildProcessScrubsOrdinaryFiles() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let notesPath = directory.appendingPathComponent("notes.txt").path
        let secret = UUID().uuidString
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(notesPath)
        let context = InjectedSecretFileScrubContext(
            agentJITGrantIDs: [UUID()],
            agentPlatform: "codex",
            terminalSessionScope: "test-scope",
            workingDirectory: directory.path,
            workspaceRoot: directory.path
        )

        let quotedDir = directory.path.replacingOccurrences(of: "'", with: "'\\''")
        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "printf 'leak=\(secret)\\n' > '\(quotedDir)/notes.txt'",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            cleanupSecretFiles: true,
            fileScrubContext: context,
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )

        #expect(result.terminationStatus == 0)
        #expect(result.fileCleanupStatus == .complete)
        let contents = try String(contentsOfFile: notesPath, encoding: .utf8)
        #expect(contents.contains(OutputMasker.placeholder))
        #expect(!contents.contains(secret))

        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.contains { $0.detail == InjectedSecretFileActivityDetail.scrubbed })
    }

    @Test("agent-scoped runs automatically replace only the exact injected secret")
    func agentScopedRunAutomaticallyReplacesOnlyExactInjectedSecret() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let path = directory.appendingPathComponent("agent-output.txt").path
        let secret = "agent-exact-secret-value"
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(path)
        let context = InjectedSecretFileScrubContext(
            agentJITGrantIDs: [],
            agentPlatform: "codex",
            terminalSessionScope: nil,
            workingDirectory: directory.path,
            workspaceRoot: directory.path
        )
        let automaticCleanup = Exec.shouldCleanupSecretFiles(
            explicitlyRequested: false,
            agentPlatform: context.agentPlatform
        )
        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "printf 'prefix=%s\\nnear=%sx\\nsuffix=preserved\\n' "
                    + "'\(secret)' '\(secret)' > '\(quotedPath)'",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            cleanupSecretFiles: automaticCleanup,
            fileScrubContext: context,
            fileActivityStore: AgentFileActivityStore(
                fileURL: directory.appendingPathComponent("files.jsonl")
            ),
            fileTouchWatcher: watcher
        )

        #expect(automaticCleanup)
        #expect(result.fileCleanupStatus == .complete)
        #expect(
            try String(contentsOfFile: path, encoding: .utf8)
                == "prefix=\(OutputMasker.placeholder)\n"
                    + "near=\(OutputMasker.placeholder)x\n"
                    + "suffix=preserved\n"
        )
    }

    @Test("default run detects a high-signal secret file and leaves it unchanged")
    func defaultRunDetectsHighSignalFileWithoutCleanup() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let path = directory.appendingPathComponent(".env").path
        let secret = "default-high-signal-secret"
        let original = "API_KEY=\(secret)\n"
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(path)
        let error = Pipe()
        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "printf 'API_KEY=\(secret)\\n' > '\(quotedPath)'"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
        #expect(
            warning
                == "Warning: Authsia detected an injected secret in an observed file and left "
                    + "it unchanged; review Access Center. Pass --cleanup-secret-files to enable "
                    + "best-effort replacement. The child exit status was preserved.\n"
        )
        #expect(!warning.contains(secret))
        #expect(!warning.contains(path))

        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.count == 1)
        #expect(events[0].detail == InjectedSecretFileActivityDetail.secretDetected)
        #expect(events[0].action == .modify)
        #expect(events[0].status == .inferred)
    }

    @Test("default run detects an ordinary secret file and leaves it unchanged")
    func defaultRunDetectsOrdinaryFileWithoutCleanup() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let path = directory.appendingPathComponent("notes.txt").path
        let secret = "default-ordinary-secret"
        let original = "leak=\(secret)\n"
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(path)
        let error = Pipe()
        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "printf 'leak=\(secret)\\n' > '\(quotedPath)'"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
        #expect(
            warning
                == "Warning: Authsia detected an injected secret in an observed file and left "
                    + "it unchanged; review Access Center. Pass --cleanup-secret-files to enable "
                    + "best-effort replacement. The child exit status was preserved.\n"
        )
        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.map(\.detail) == [InjectedSecretFileActivityDetail.secretDetected])
        #expect(events.map(\.status) == [.inferred])
    }

    @Test("default run does not observe deliberately ineligible short tokens")
    func defaultRunDoesNotObserveShortToken() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "short-value"
        let path = directory.appendingPathComponent("notes.txt").path
        let original = "leak=\(secret)\n"
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcherStartCount = LockedCounter()
        let watcher = InjectedFileTouchWatcher(
            roots: ["/"],
            startOverride: {
                watcherStartCount.increment()
                return false
            }
        )
        watcher.recordForTesting(path)
        let cleanupSelection = Exec.fileCleanupSecretSelection(
            exactInjectedSecrets: [secret]
        )
        let fileScrubContext = Exec.selectedFileScrubContext(
            cleanupSelection: cleanupSelection,
            cleanupSecretFiles: false,
            candidate: InjectedSecretFileScrubContext(
                agentJITGrantIDs: [],
                agentPlatform: "codex",
                terminalSessionScope: nil,
                workingDirectory: "/",
                workspaceRoot: "/"
            )
        )
        let error = Pipe()
        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "printf 'leak=\(secret)\\n' > '\(quotedPath)'"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: cleanupSelection.secrets),
            fileCleanupSelectionIncomplete: cleanupSelection.isIncomplete,
            standardError: error.fileHandleForWriting,
            fileScrubContext: fileScrubContext,
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(cleanupSelection.secrets.isEmpty)
        #expect(cleanupSelection.isIncomplete)
        #expect(watcherStartCount.value == 0)
        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .notRequested)
        #expect(warning.isEmpty)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
        #expect(try AgentFileActivityStore(fileURL: activityURL).loadAll().isEmpty)
    }

    @Test("explicit cleanup observes short tokens and reports incomplete")
    func explicitCleanupObservesShortTokenAndWarns() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "short-value"
        let path = directory.appendingPathComponent("notes.txt").path
        let original = "leak=\(secret)\n"
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcherStartCount = LockedCounter()
        let watcher = InjectedFileTouchWatcher(
            roots: ["/"],
            startOverride: {
                watcherStartCount.increment()
                return false
            }
        )
        watcher.recordForTesting(path)
        let cleanupSelection = Exec.fileCleanupSecretSelection(
            exactInjectedSecrets: [secret]
        )
        let fileScrubContext = Exec.selectedFileScrubContext(
            cleanupSelection: cleanupSelection,
            cleanupSecretFiles: true,
            candidate: InjectedSecretFileScrubContext(
                agentJITGrantIDs: [],
                agentPlatform: "codex",
                terminalSessionScope: nil,
                workingDirectory: "/",
                workspaceRoot: "/"
            )
        )
        let error = Pipe()
        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "printf 'leak=\(secret)\\n' > '\(quotedPath)'"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: cleanupSelection.secrets),
            fileCleanupSelectionIncomplete: cleanupSelection.isIncomplete,
            cleanupSecretFiles: true,
            standardError: error.fileHandleForWriting,
            fileScrubContext: fileScrubContext,
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(watcherStartCount.value == 1)
        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file cleanup was incomplete; review Access Center. "
                    + "The child exit status was preserved.\n"
        )
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
        #expect(try AgentFileActivityStore(fileURL: activityURL).loadAll().isEmpty)
    }

    @Test("default detection is not combined with deliberately ineligible short tokens")
    func defaultDetectionWithShortTokenUsesDetectionWarning() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let shortSecret = "short-value"
        let eligibleSecret = "eligible-secret-value"
        let path = directory.appendingPathComponent("notes.txt").path
        let original = "short=\(shortSecret) eligible=\(eligibleSecret)\n"
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcherStartCount = LockedCounter()
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: {
                watcherStartCount.increment()
                return true
            }
        )
        watcher.recordForTesting(path)
        let cleanupSelection = Exec.fileCleanupSecretSelection(
            exactInjectedSecrets: [shortSecret, eligibleSecret]
        )
        let fileScrubContext = Exec.selectedFileScrubContext(
            cleanupSelection: cleanupSelection,
            cleanupSecretFiles: false,
            candidate: scrubContext(directory: directory)
        )
        let error = Pipe()
        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "printf 'short=\(shortSecret) eligible=\(eligibleSecret)\\n' "
                    + "> '\(quotedPath)'",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [shortSecret, eligibleSecret]),
            fileCleanupMasker: OutputMasker(exactSecrets: cleanupSelection.secrets),
            fileCleanupSelectionIncomplete: cleanupSelection.isIncomplete,
            standardError: error.fileHandleForWriting,
            fileScrubContext: fileScrubContext,
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(cleanupSelection.secrets == [eligibleSecret])
        #expect(cleanupSelection.isIncomplete)
        #expect(watcherStartCount.value == 1)
        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
        #expect(
            warning
                == "Warning: Authsia detected an injected secret in an observed file and left "
                    + "it unchanged; review Access Center. Pass --cleanup-secret-files to enable "
                    + "best-effort replacement. The child exit status was preserved.\n"
        )
        #expect(!warning.contains("inspection was incomplete"))

        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.map(\.detail) == [InjectedSecretFileActivityDetail.secretDetected])
        #expect(events.map(\.status) == [.inferred])
    }

    @Test("default run with no exact match is quiet")
    func defaultRunWithNoExactMatchIsQuiet() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let path = directory.appendingPathComponent("notes.txt").path
        let original = "ordinary text\n"
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(path)
        let error = Pipe()
        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "printf 'ordinary text\\n' > '\(quotedPath)'"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: ["eligible-secret-value"]),
            fileCleanupMasker: OutputMasker(exactSecrets: ["eligible-secret-value"]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .complete)
        #expect(warning.isEmpty)
        #expect(try String(contentsOfFile: path, encoding: .utf8) == original)
        #expect(try AgentFileActivityStore(fileURL: activityURL).loadAll().isEmpty)
    }

    @Test("default detection plus inspection failure emits one combined warning")
    func defaultDetectionAndInspectionFailureEmitCombinedWarning() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "combined-warning-secret"
        let detectedPath = directory.appendingPathComponent("detected.txt").path
        let targetPath = directory.appendingPathComponent("target.txt").path
        let linkPath = directory.appendingPathComponent("link.txt").path
        try "leak=\(secret)\n".write(
            toFile: detectedPath,
            atomically: true,
            encoding: .utf8
        )
        try "ordinary text\n".write(
            toFile: targetPath,
            atomically: true,
            encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            atPath: linkPath,
            withDestinationPath: targetPath
        )
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(detectedPath)
        watcher.recordForTesting(linkPath)
        let error = Pipe()
        let activityURL = directory.appendingPathComponent("files.jsonl")

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "exit 0"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia detected an injected secret in an observed file and left "
                    + "it unchanged, and secret-file inspection was incomplete; review Access "
                    + "Center. Pass --cleanup-secret-files to enable best-effort replacement. "
                    + "The child exit status was preserved.\n"
        )
        #expect(warning.filter { $0 == "\n" }.count == 1)
        #expect(!warning.contains(secret))
        #expect(!warning.contains(detectedPath))
        #expect(!warning.contains(linkPath))
        #expect(
            try String(contentsOfFile: detectedPath, encoding: .utf8)
                == "leak=\(secret)\n"
        )

        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.contains {
            $0.detail == InjectedSecretFileActivityDetail.secretDetected
                && $0.status == .inferred
        })
        #expect(events.contains {
            $0.detail == "inspection-failed"
                && $0.status == .failed
        })
    }

    @Test("default unsafe symlink reports incomplete inspection without confirming a secret")
    func defaultUnsafeSymlinkReportsIncompleteInspection() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "default-symlink-secret"
        let targetPath = directory.appendingPathComponent("target.txt").path
        let linkPath = directory.appendingPathComponent("link.txt").path
        try "ordinary text\n".write(
            toFile: targetPath,
            atomically: true,
            encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            atPath: linkPath,
            withDestinationPath: targetPath
        )
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(linkPath)
        let error = Pipe()
        let activityURL = directory.appendingPathComponent("files.jsonl")

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "exit 0"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file inspection was incomplete; review Access "
                    + "Center. No secret presence was confirmed. Child exit preserved.\n"
        )
        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.map(\.detail) == ["inspection-failed"])
        #expect(events.map(\.status) == [.failed])
    }

    @Test("explicit cleanup keeps unsafe symlink cleanup failure semantics")
    func explicitCleanupUnsafeSymlinkReportsCleanupFailure() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let secret = "explicit-symlink-secret"
        let targetPath = directory.appendingPathComponent("target.txt").path
        let linkPath = directory.appendingPathComponent("link.txt").path
        try "ordinary text\n".write(
            toFile: targetPath,
            atomically: true,
            encoding: .utf8
        )
        try FileManager.default.createSymbolicLink(
            atPath: linkPath,
            withDestinationPath: targetPath
        )
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(linkPath)
        let error = Pipe()
        let activityURL = directory.appendingPathComponent("files.jsonl")

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "exit 0"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            cleanupSecretFiles: true,
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file cleanup was incomplete; review Access Center. "
                    + "The child exit status was preserved.\n"
        )
        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.map(\.detail) == [InjectedSecretFileActivityDetail.verificationFailed])
        #expect(events.map(\.status) == [.failed])
    }

    @Test("explicit cleanup reports a replaced observation root as incomplete cleanup")
    func explicitCleanupReplacementRootIsRejected() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let root = parent.appendingPathComponent("workspace", isDirectory: true)
        let relocated = parent.appendingPathComponent("relocated", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        let secret = "replacement-root-secret"
        let replacementPath = root.appendingPathComponent(".env").path
        let quotedRoot = root.path.replacingOccurrences(of: "'", with: "'\\''")
        let quotedRelocated = relocated.path.replacingOccurrences(of: "'", with: "'\\''")
        let watcher = InjectedFileTouchWatcher(
            roots: [root.path],
            startOverride: { true }
        )
        let error = Pipe()

        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "mv '\(quotedRoot)' '\(quotedRelocated)'; "
                    + "mkdir '\(quotedRoot)'; "
                    + "printf 'TOKEN=\(secret)\\n' > '\(quotedRoot)/.env'",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            cleanupSecretFiles: true,
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: root),
            fileActivityStore: AgentFileActivityStore(
                fileURL: parent.appendingPathComponent("files.jsonl")
            ),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file cleanup was incomplete; review Access Center. "
                    + "The child exit status was preserved.\n"
        )
        #expect(
            try String(contentsOfFile: replacementPath, encoding: .utf8)
                == "TOKEN=\(secret)\n"
        )
    }

    @Test("root swapped after watcher stop is rejected by scrubber")
    func rootSwapAfterWatcherStopIsRejected() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let root = parent.appendingPathComponent("workspace", isDirectory: true)
        let relocated = parent.appendingPathComponent("relocated", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        let secret = "post-stop-root-swap-secret"
        let replacementPath = root.appendingPathComponent(".env").path
        let watcher = InjectedFileTouchWatcher(
            roots: [root.path],
            startOverride: { true }
        )
        watcher.recordForTesting(replacementPath)
        let observation = watcher.stop()
        #expect(!observation.isIncomplete)

        try FileManager.default.moveItem(at: root, to: relocated)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        try "TOKEN=\(secret)\n".write(
            toFile: replacementPath,
            atomically: true,
            encoding: .utf8
        )

        let results = InjectedSecretFileScrubber.scrub(
            paths: observation.paths,
            masker: OutputMasker(exactSecrets: [secret]),
            allowedRootBindings: observation.validatedRootBindings,
            context: scrubContext(directory: root),
            mode: .remediate
        )

        #expect(results.map(\.outcome) == [.verificationFailed])
        #expect(InjectedSecretFileCleanupStatus.forRequestedCleanup(results) == .incomplete)
        #expect(
            try String(contentsOfFile: replacementPath, encoding: .utf8)
                == "TOKEN=\(secret)\n"
        )
    }

    @Test("default missing observation root reports incomplete inspection")
    func defaultMissingObservationRootReportsIncompleteInspection() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let root = parent.appendingPathComponent("workspace", isDirectory: true)
        let relocated = parent.appendingPathComponent("relocated", isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        let quotedRoot = root.path.replacingOccurrences(of: "'", with: "'\\''")
        let quotedRelocated = relocated.path.replacingOccurrences(of: "'", with: "'\\''")
        let watcher = InjectedFileTouchWatcher(
            roots: [root.path],
            startOverride: { true }
        )
        let error = Pipe()

        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "mv '\(quotedRoot)' '\(quotedRelocated)'",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: ["missing-root-secret"]),
            fileCleanupMasker: OutputMasker(exactSecrets: ["missing-root-secret"]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: root),
            fileActivityStore: AgentFileActivityStore(
                fileURL: parent.appendingPathComponent("files.jsonl")
            ),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file inspection was incomplete; review Access "
                    + "Center. No secret presence was confirmed. Child exit preserved.\n"
        )
        #expect(FileManager.default.fileExists(atPath: relocated.path))
        #expect(!FileManager.default.fileExists(atPath: root.path))
    }

    @Test("default oversized file reports incomplete inspection without confirming a secret")
    func defaultOversizedFileReportsIncompleteInspection() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let path = directory.appendingPathComponent("oversized.txt").path
        let secret = UUID().uuidString
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(path)
        let error = Pipe()
        let context = InjectedSecretFileScrubContext(
            agentJITGrantIDs: [UUID()],
            agentPlatform: "codex",
            terminalSessionScope: "test-scope",
            workingDirectory: directory.path,
            workspaceRoot: directory.path
        )

        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")
        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "printf 'TOKEN=\(secret)\\n' > '\(quotedPath)'; "
                    + "/bin/dd if=/dev/zero bs=1048576 count=3 >> '\(quotedPath)' 2>/dev/null",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: context,
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warningData = (try error.fileHandleForReading.readToEnd()) ?? Data()
        let warning = String(decoding: warningData, as: UTF8.self)

        #expect(result.terminationStatus == 0)
        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file inspection was incomplete; review Access "
                    + "Center. No secret presence was confirmed. Child exit preserved.\n"
        )
        #expect(!warning.contains(secret))
        #expect(!warning.contains(path))

        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.contains {
            $0.status == .failed
                && $0.detail == "inspection-failed"
        })
    }

    @Test("explicit cleanup keeps oversized file cleanup failure semantics")
    func explicitCleanupOversizedFileReportsCleanupFailure() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let path = directory.appendingPathComponent("oversized.txt").path
        let secret = UUID().uuidString
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(path)
        let error = Pipe()
        let context = InjectedSecretFileScrubContext(
            agentJITGrantIDs: [UUID()],
            agentPlatform: "codex",
            terminalSessionScope: "test-scope",
            workingDirectory: directory.path,
            workspaceRoot: directory.path
        )

        let quotedPath = path.replacingOccurrences(of: "'", with: "'\\''")
        let result = Exec.runChildProcess(
            command: [
                "/bin/sh",
                "-c",
                "printf 'TOKEN=\(secret)\\n' > '\(quotedPath)'; "
                    + "/bin/dd if=/dev/zero bs=1048576 count=3 >> '\(quotedPath)' 2>/dev/null",
            ],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            cleanupSecretFiles: true,
            standardError: error.fileHandleForWriting,
            fileScrubContext: context,
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file cleanup was incomplete; review Access Center. "
                    + "The child exit status was preserved.\n"
        )
        let events = try AgentFileActivityStore(fileURL: activityURL).loadAll()
        #expect(events.contains {
            $0.status == .failed
                && $0.detail == InjectedSecretFileActivityDetail.verificationFailed
        })
    }

    @Test("default watcher start failure reports incomplete inspection")
    func defaultWatcherStartFailurePreservesChildExitAndWarns() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let error = Pipe()
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { false }
        )
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "exit 7"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: ["expanded-output-token"]),
            fileCleanupMasker: OutputMasker(exactSecrets: ["synthetic-exact-secret"]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.terminationStatus == 7)
        #expect(result.exitCode == 7)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file inspection was incomplete; review Access "
                    + "Center. No secret presence was confirmed. Child exit preserved.\n"
        )
        #expect(try AgentFileActivityStore(fileURL: activityURL).loadAll().isEmpty)
    }

    @Test("explicit cleanup keeps watcher start cleanup failure semantics")
    func explicitCleanupWatcherStartFailureWarns() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let error = Pipe()
        let activityURL = directory.appendingPathComponent("files.jsonl")
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { false }
        )
        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "exit 7"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: ["expanded-output-token"]),
            fileCleanupMasker: OutputMasker(exactSecrets: ["synthetic-exact-secret"]),
            cleanupSecretFiles: true,
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(fileURL: activityURL),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.terminationStatus == 7)
        #expect(result.exitCode == 7)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file cleanup was incomplete; review Access Center. "
                    + "The child exit status was preserved.\n"
        )
        #expect(try AgentFileActivityStore(fileURL: activityURL).loadAll().isEmpty)
    }

    #if os(macOS)
    @Test("FSEvent stream watches roots with file-level no-defer delivery")
    func fseventStreamCreationFlagsIncludeRequiredOptions() {
        let flags = InjectedFileTouchWatcher.streamCreateFlags

        #expect(flags & UInt32(kFSEventStreamCreateFlagWatchRoot) != 0)
        #expect(flags & UInt32(kFSEventStreamCreateFlagFileEvents) != 0)
        #expect(flags & UInt32(kFSEventStreamCreateFlagNoDefer) != 0)
    }

    @Test("FSEvent candidates require a created modified or renamed file")
    func fseventCandidatesExcludeDirectoriesAndRemovedFiles() {
        let file = FSEventStreamEventFlags(kFSEventStreamEventFlagItemIsFile)
        let directory = FSEventStreamEventFlags(kFSEventStreamEventFlagItemIsDir)
        let created = FSEventStreamEventFlags(kFSEventStreamEventFlagItemCreated)
        let modified = FSEventStreamEventFlags(kFSEventStreamEventFlagItemModified)
        let renamed = FSEventStreamEventFlags(kFSEventStreamEventFlagItemRenamed)
        let removed = FSEventStreamEventFlags(kFSEventStreamEventFlagItemRemoved)

        #expect(InjectedFileTouchWatcher.shouldRecordEvent(file | created))
        #expect(InjectedFileTouchWatcher.shouldRecordEvent(file | modified))
        #expect(InjectedFileTouchWatcher.shouldRecordEvent(file | renamed))
        #expect(!InjectedFileTouchWatcher.shouldRecordEvent(directory | created))
        #expect(!InjectedFileTouchWatcher.shouldRecordEvent(directory | modified))
        #expect(!InjectedFileTouchWatcher.shouldRecordEvent(file | removed))
        #expect(!InjectedFileTouchWatcher.shouldRecordEvent(file))
    }

    @Test("FSEvents loss and invalidation flags require incomplete cleanup")
    func fseventLossFlagsRequireIncompleteCleanup() {
        let lossFlags: [FSEventStreamEventFlags] = [
            FSEventStreamEventFlags(kFSEventStreamEventFlagMustScanSubDirs),
            FSEventStreamEventFlags(kFSEventStreamEventFlagUserDropped),
            FSEventStreamEventFlags(kFSEventStreamEventFlagKernelDropped),
            FSEventStreamEventFlags(kFSEventStreamEventFlagEventIdsWrapped),
            FSEventStreamEventFlags(kFSEventStreamEventFlagRootChanged),
            FSEventStreamEventFlags(kFSEventStreamEventFlagMount),
            FSEventStreamEventFlags(kFSEventStreamEventFlagUnmount),
        ]

        for flag in lossFlags {
            #expect(InjectedFileTouchWatcher.eventFlagsRequireIncomplete(flag))
        }
        #expect(
            !InjectedFileTouchWatcher.eventFlagsRequireIncomplete(
                FSEventStreamEventFlags(kFSEventStreamEventFlagItemModified)
            )
        )
    }

    @Test("default FSEvents loss reports incomplete inspection")
    func defaultFSEventLossReportsIncompleteInspection() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordEventFlagsForTesting(
            FSEventStreamEventFlags(kFSEventStreamEventFlagKernelDropped)
        )
        let error = Pipe()
        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "exit 0"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: ["eligible-secret-value"]),
            fileCleanupMasker: OutputMasker(exactSecrets: ["eligible-secret-value"]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(
                fileURL: directory.appendingPathComponent("files.jsonl")
            ),
            fileTouchWatcher: watcher
        )
        try error.fileHandleForWriting.close()
        let warning = String(
            decoding: (try error.fileHandleForReading.readToEnd()) ?? Data(),
            as: UTF8.self
        )

        #expect(result.exitCode == 0)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            warning
                == "Warning: Authsia secret-file inspection was incomplete; review Access "
                    + "Center. No secret presence was confirmed. Child exit preserved.\n"
        )
    }

    @Test("signal defaults are restored once before file cleanup")
    func signalRestorationPrecedesFileCleanupAndIsIdempotent() throws {
        let parent = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: parent) }

        let directory = parent.appendingPathComponent("workspace", isDirectory: true)
        let relocated = parent.appendingPathComponent("relocated", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let secret = "signal-restoration-secret"
        let secretPath = directory.appendingPathComponent(".env").path
        try "TOKEN=\(secret)\n".write(
            toFile: secretPath,
            atomically: true,
            encoding: .utf8
        )
        let watcher = InjectedFileTouchWatcher(
            roots: [directory.path],
            startOverride: { true }
        )
        watcher.recordForTesting(secretPath)
        let signalState = SignalCoordinatorTestState(
            dispositions: [SIGINT: "custom-int"]
        )
        let signalCoordinator = ChildSignalForwardingCoordinator(
            signals: [SIGINT],
            dispositionInstaller: { signal in
                let previous = signalState.replaceDisposition(
                    signal,
                    with: "ignored"
                )
                return ChildSignalDispositionInstallation {
                    signalState.setDisposition(previous, for: signal)
                    signalState.recordRestoration()
                    try? FileManager.default.moveItem(
                        at: directory,
                        to: relocated
                    )
                    try? FileManager.default.createDirectory(
                        at: directory,
                        withIntermediateDirectories: true
                    )
                }
            },
            sourceInstaller: { _, _, _ in
                ChildSignalSourceInstallation {}
            }
        )
        let error = Pipe()

        let result = Exec.runChildProcess(
            command: ["/bin/sh", "-c", "exit 0"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: [secret]),
            fileCleanupMasker: OutputMasker(exactSecrets: [secret]),
            standardError: error.fileHandleForWriting,
            fileScrubContext: scrubContext(directory: directory),
            fileActivityStore: AgentFileActivityStore(
                fileURL: parent.appendingPathComponent("files.jsonl")
            ),
            fileTouchWatcher: watcher,
            signalCoordinator: signalCoordinator
        )
        try error.fileHandleForWriting.close()

        #expect(signalState.restorationCount == 1)
        #expect(result.fileCleanupStatus == .incomplete)
        #expect(
            try String(
                contentsOf: relocated.appendingPathComponent(".env"),
                encoding: .utf8
            ) == "TOKEN=\(secret)\n"
        )
    }

    @Test("concurrent signal registrations restore prior dispositions after the last unregister")
    func concurrentSignalRegistrationsShareProcessWideInstallation() {
        let state = SignalCoordinatorTestState(
            dispositions: [
                SIGINT: "custom-int",
                SIGHUP: "custom-hup",
            ]
        )
        let coordinator = ChildSignalForwardingCoordinator(
            signals: [SIGINT, SIGHUP],
            dispositionInstaller: { signal in
                let previous = state.replaceDisposition(signal, with: "ignored")
                return ChildSignalDispositionInstallation {
                    state.setDisposition(previous, for: signal)
                }
            },
            sourceInstaller: { signal, queue, eventHandler in
                state.installSource(
                    signal: signal,
                    queue: queue,
                    eventHandler: eventHandler
                )
                return ChildSignalSourceInstallation {
                    state.cancelSource(signal: signal)
                }
            }
        )

        DispatchQueue.concurrentPerform(iterations: 2) { _ in
            state.appendRegistration(coordinator.register(Process()))
        }
        let registrations = state.registrations
        #expect(registrations.count == 2)
        #expect(state.installCounts == [SIGINT: 1, SIGHUP: 1])
        #expect(state.dispositions == [SIGINT: "ignored", SIGHUP: "ignored"])

        registrations[0].unregister()
        registrations[0].unregister()
        #expect(state.cancelCounts.isEmpty)
        #expect(state.dispositions == [SIGINT: "ignored", SIGHUP: "ignored"])

        registrations[1].unregister()
        #expect(state.cancelCounts == [SIGINT: 1, SIGHUP: 1])
        #expect(
            state.dispositions
                == [SIGINT: "custom-int", SIGHUP: "custom-hup"]
        )
    }

    @Test("caught signal disposition restores the complete prior sigaction")
    func caughtSignalDispositionRestoresCompletePriorAction() {
        var priorAction = sigaction()
        priorAction.__sigaction_u.__sa_sigaction = syntheticSignalInfoHandler
        priorAction.sa_flags = SA_SIGINFO | SA_RESTART
        sigemptyset(&priorAction.sa_mask)
        sigaddset(&priorAction.sa_mask, SIGUSR1)
        sigaddset(&priorAction.sa_mask, SIGUSR2)
        let expectedPriorBytes = signalActionBytes(priorAction)
        let state = SignalActionTestState(action: priorAction)
        let controller = ChildSignalActionController(apply: state.apply)

        let installation = controller.installCaught(signal: SIGTERM)

        var expectedIgnoredAction = sigaction()
        expectedIgnoredAction.__sigaction_u.__sa_handler = SIG_IGN
        #expect(
            state.handlerBits
                != signalActionHandlerBits(expectedIgnoredAction)
        )
        #expect(state.handlerBits != signalActionHandlerBits(sigaction()))
        #expect(state.flags == 0)
        #expect(state.maskBits == 0)

        installation.restore()

        #expect(state.actionBytes == expectedPriorBytes)
        #expect(state.flags == SA_SIGINFO | SA_RESTART)
        #expect(state.maskContains(SIGUSR1))
        #expect(state.maskContains(SIGUSR2))
    }

    @Test("overlapping unregistered child inherits default forwarded-signal dispositions")
    func overlappingChildInheritsDefaultForwardedSignalDispositions() throws {
        try #require(
            FileManager.default.isExecutableFile(atPath: "/usr/bin/perl")
        )
        let childA = Process()
        childA.executableURL = URL(fileURLWithPath: "/bin/sleep")
        childA.arguments = ["5"]
        try childA.run()

        let registration = ChildSignalForwardingCoordinator.shared.register(childA)
        defer {
            registration.unregister()
            if childA.isRunning {
                _ = Darwin.kill(childA.processIdentifier, SIGKILL)
            }
            childA.waitUntilExit()
        }

        let dispositionReport = try inheritedSignalDispositionReport()

        #expect(
            dispositionReport
                == "INT=DEFAULT\nTERM=DEFAULT\nHUP=DEFAULT\n"
        )
    }

    @Test("production caught action still delivers through DispatchSourceSignal")
    func productionCaughtActionDeliversThroughDispatchSource() throws {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["5"]
        try child.run()

        let received = DispatchSemaphore(value: 0)
        let state = SignalCoordinatorTestState(dispositions: [:])
        let coordinator = ChildSignalForwardingCoordinator(
            signals: [SIGUSR2],
            forwardSignal: { _, signal in
                state.recordForward(
                    signal: signal,
                    isMainThread: Thread.isMainThread
                )
                received.signal()
            }
        )
        let registration = coordinator.register(child)
        defer {
            registration.unregister()
            if child.isRunning {
                _ = Darwin.kill(child.processIdentifier, SIGKILL)
            }
            child.waitUntilExit()
        }

        var activeAction = sigaction()
        try #require(sigaction(SIGUSR2, nil, &activeAction) == 0)
        try #require(
            signalActionHandlerBits(activeAction)
                != signalActionHandlerBits(sigaction())
        )

        #expect(Darwin.kill(getpid(), SIGUSR2) == 0)
        #expect(received.wait(timeout: .now() + 2) == .success)
        #expect(state.forwardedSignals == [SIGUSR2])
    }

    @Test("signal source handler forwards from a non-main queue")
    func signalSourceHandlerForwardsFromDedicatedQueue() throws {
        let state = SignalCoordinatorTestState(
            dispositions: [SIGTERM: "custom-term"]
        )
        let coordinator = ChildSignalForwardingCoordinator(
            signals: [SIGTERM],
            dispositionInstaller: { signal in
                let previous = state.replaceDisposition(signal, with: "ignored")
                return ChildSignalDispositionInstallation {
                    state.setDisposition(previous, for: signal)
                }
            },
            sourceInstaller: { signal, queue, eventHandler in
                state.installSource(
                    signal: signal,
                    queue: queue,
                    eventHandler: eventHandler
                )
                return ChildSignalSourceInstallation {
                    state.cancelSource(signal: signal)
                }
            },
            forwardSignal: { pid, signal in
                state.recordForward(signal: signal, isMainThread: Thread.isMainThread)
                _ = Darwin.kill(pid, signal)
            }
        )
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["5"]
        try process.run()

        let registration = coordinator.register(process)
        defer {
            registration.unregister()
            if process.isRunning {
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
            process.waitUntilExit()
        }

        let source = try #require(state.event(signal: SIGTERM))
        try #require(source.fire())
        process.waitUntilExit()
        registration.unregister()

        #expect(process.terminationReason == .uncaughtSignal)
        #expect(process.terminationStatus == SIGTERM)
        #expect(state.forwardedSignals == [SIGTERM])
        #expect(state.forwardedOnMainThread == [false])
        #expect(state.dispositions == [SIGTERM: "custom-term"])
    }

    @Test("stale signal source event does not reach a later installation")
    func staleSignalSourceEventDoesNotReachLaterInstallation() throws {
        let state = SignalCoordinatorTestState(
            dispositions: [SIGINT: "custom-int"]
        )
        let coordinator = ChildSignalForwardingCoordinator(
            signals: [SIGINT],
            dispositionInstaller: { signal in
                let previous = state.replaceDisposition(signal, with: "ignored")
                return ChildSignalDispositionInstallation {
                    state.setDisposition(previous, for: signal)
                }
            },
            sourceInstaller: { signal, queue, eventHandler in
                state.installSource(
                    signal: signal,
                    queue: queue,
                    eventHandler: eventHandler
                )
                return ChildSignalSourceInstallation {
                    state.cancelSource(signal: signal)
                }
            },
            forwardSignal: { _, signal in
                state.recordForward(
                    signal: signal,
                    isMainThread: Thread.isMainThread
                )
            }
        )
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sleep")
        process.arguments = ["5"]
        try process.run()
        defer {
            if process.isRunning {
                process.terminate()
            }
            process.waitUntilExit()
        }

        let firstRegistration = coordinator.register(process)
        let staleEvent = try #require(state.event(signal: SIGINT))
        firstRegistration.unregister()

        let secondRegistration = coordinator.register(process)
        let currentEvent = try #require(state.event(signal: SIGINT))

        #expect(staleEvent.fire())
        #expect(state.forwardedSignals.isEmpty)
        #expect(currentEvent.fire())
        #expect(state.forwardedSignals == [SIGINT])

        secondRegistration.unregister()
    }

    @Test("signal handling installs only after the child is running")
    func signalHandlingInstallsOnlyAfterChildIsRunning() {
        let process = Process()
        let signalState = SignalCoordinatorTestState(
            dispositions: [SIGINT: "custom-int"]
        )
        let signalCoordinator = ChildSignalForwardingCoordinator(
            signals: [SIGINT],
            dispositionInstaller: { signal in
                signalState.recordInstallation(
                    processIsRunning: process.isRunning
                )
                let previous = signalState.replaceDisposition(
                    signal,
                    with: "ignored"
                )
                return ChildSignalDispositionInstallation {
                    signalState.setDisposition(previous, for: signal)
                    signalState.recordRestoration()
                }
            },
            sourceInstaller: { _, _, _ in
                ChildSignalSourceInstallation {}
            }
        )

        let result = Exec.runChildProcess(
            command: ["/bin/sleep", "0.1"],
            environment: ["PATH": "/usr/bin:/bin"],
            masker: OutputMasker(secrets: []),
            signalCoordinator: signalCoordinator,
            childProcess: process
        )

        #expect(result.terminationStatus == 0)
        #expect(signalState.installationProcessStates == [true])
        #expect(signalState.restorationCount == 1)
    }

    @Test("launch failure does not install signal handling")
    func launchFailureDoesNotInstallSignalHandling() {
        let process = Process()
        let signalState = SignalCoordinatorTestState(
            dispositions: [SIGINT: "custom-int"]
        )
        let signalCoordinator = ChildSignalForwardingCoordinator(
            signals: [SIGINT],
            dispositionInstaller: { signal in
                signalState.recordInstallation(
                    processIsRunning: process.isRunning
                )
                let previous = signalState.replaceDisposition(
                    signal,
                    with: "ignored"
                )
                return ChildSignalDispositionInstallation {
                    signalState.setDisposition(previous, for: signal)
                    signalState.recordRestoration()
                }
            },
            sourceInstaller: { _, _, _ in
                ChildSignalSourceInstallation {}
            }
        )

        let result = Exec.runChildProcess(
            command: ["unused"],
            environment: [:],
            masker: OutputMasker(secrets: []),
            signalCoordinator: signalCoordinator,
            childProcess: process,
            processExecutableURL: URL(
                fileURLWithPath: "/authsia-test-missing-\(UUID().uuidString)"
            )
        )

        #expect(result.terminationStatus == 1)
        #expect(result.fileCleanupStatus == .notRequested)
        #expect(signalState.installationProcessStates.isEmpty)
        #expect(signalState.restorationCount == 0)
        #expect(signalState.dispositions == [SIGINT: "custom-int"])
    }
    #endif

    private func scrubContext(directory: URL) -> InjectedSecretFileScrubContext {
        InjectedSecretFileScrubContext(
            agentJITGrantIDs: [],
            agentPlatform: nil,
            terminalSessionScope: nil,
            workingDirectory: directory.path,
            workspaceRoot: directory.path
        )
    }

    private func posixMode(atPath path: String) throws -> mode_t {
        try fileMetadata(atPath: path).st_mode & mode_t(0o7777)
    }

    private func fileMetadata(atPath path: String) throws -> stat {
        var metadata = stat()
        guard Darwin.lstat(path, &metadata) == 0 else {
            throw CocoaError(.fileReadUnknown)
        }
        return metadata
    }

    private func setExtendedAttribute(
        _ value: Data,
        named name: String,
        atPath path: String
    ) throws {
        let fileDescriptor = Darwin.open(path, O_RDWR | O_CLOEXEC)
        guard fileDescriptor >= 0 else { throw posixError() }
        defer { Darwin.close(fileDescriptor) }

        let result = value.withUnsafeBytes {
            Darwin.fsetxattr(fileDescriptor, name, $0.baseAddress, value.count, 0, 0)
        }
        guard result == 0 else { throw posixError() }
    }

    private func extendedAttribute(named name: String, atPath path: String) throws -> Data {
        let fileDescriptor = Darwin.open(path, O_RDONLY | O_CLOEXEC)
        guard fileDescriptor >= 0 else { throw posixError() }
        defer { Darwin.close(fileDescriptor) }

        let size = Darwin.fgetxattr(fileDescriptor, name, nil, 0, 0, 0)
        guard size >= 0 else { throw posixError() }

        var value = Data(count: size)
        let readSize = value.withUnsafeMutableBytes {
            Darwin.fgetxattr(fileDescriptor, name, $0.baseAddress, size, 0, 0)
        }
        guard readSize == size else { throw posixError() }
        return value
    }

    private func posixError() -> POSIXError {
        POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }

    private func setFileTimestamps(
        _ timestamps: TestFileTimestamps,
        atPath path: String
    ) throws {
        let fileDescriptor = Darwin.open(path, O_RDWR | O_CLOEXEC)
        guard fileDescriptor >= 0 else { throw posixError() }
        defer { Darwin.close(fileDescriptor) }

        var attributes = attrlist()
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.commonattr = attrgroup_t(
            ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME
        )
        var mutableTimestamps = timestamps
        guard Darwin.fsetattrlist(
            fileDescriptor,
            &attributes,
            &mutableTimestamps,
            MemoryLayout<TestFileTimestamps>.size,
            0
        ) == 0 else {
            throw posixError()
        }
    }

    private func addSyntheticACL(atPath path: String) throws -> Bool {
        let process = Process()
        let standardError = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "everyone deny delete", path]
        process.standardError = standardError
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus != 0 else { return true }

        let errorData = try standardError.fileHandleForReading.readToEnd() ?? Data()
        let message = String(decoding: errorData, as: UTF8.self)
        if message.localizedCaseInsensitiveContains("not supported") {
            return false
        }
        throw CocoaError(.fileWriteUnknown)
    }

    private func accessControlList(atPath path: String) throws -> Data? {
        let fileDescriptor = Darwin.open(path, O_RDONLY | O_CLOEXEC)
        guard fileDescriptor >= 0 else { throw posixError() }
        defer { Darwin.close(fileDescriptor) }

        guard let acl = Darwin.acl_get_fd_np(fileDescriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOTSUP || errno == EOPNOTSUPP {
                return nil
            }
            throw posixError()
        }
        defer { Darwin.acl_free(UnsafeMutableRawPointer(acl)) }

        let size = Darwin.acl_size(acl)
        guard size >= 0 else { throw posixError() }
        var data = Data(count: size)
        let copiedSize = data.withUnsafeMutableBytes {
            Darwin.acl_copy_ext($0.baseAddress, acl, size)
        }
        guard copiedSize == size else { throw posixError() }
        return data
    }

    private func scrubTemporaryFiles(in directory: URL) throws -> [String] {
        try FileManager.default
            .contentsOfDirectory(atPath: directory.path)
            .filter { $0.hasPrefix(".authsia-scrub-") }
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("authsia-scrub-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private struct SyntheticRewriteFailure: Error {}

    private struct TestFileTimestamps {
        var creation: timespec
        var modification: timespec
        var access: timespec
    }
}

private struct SignalCoordinatorTestEvent: @unchecked Sendable {
    let queue: DispatchQueue
    let eventHandler: @Sendable () -> Void

    func fire() -> Bool {
        let completed = DispatchSemaphore(value: 0)
        queue.async {
            eventHandler()
            completed.signal()
        }
        return completed.wait(timeout: .now() + 2) == .success
    }
}

private final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var storedValue = 0

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return storedValue
    }

    func increment() {
        lock.lock()
        storedValue += 1
        lock.unlock()
    }
}

private func syntheticSignalInfoHandler(
    _ signal: Int32,
    _ info: UnsafeMutablePointer<siginfo_t>?,
    _ context: UnsafeMutableRawPointer?
) {}

private func signalActionBytes(_ action: sigaction) -> Data {
    var copy = action
    return withUnsafeBytes(of: &copy) { Data($0) }
}

private func signalActionHandlerBits(_ action: sigaction) -> UInt {
    var handler = action.__sigaction_u
    return withUnsafeBytes(of: &handler) { $0.load(as: UInt.self) }
}

private func inheritedSignalDispositionReport() throws -> String {
    let executable = "/usr/bin/perl"
    let script = """
        for my $signal (qw(INT TERM HUP)) {
            my $handler = $SIG{$signal};
            print "$signal=",
                (defined($handler) ? $handler : "DEFAULT"),
                "\\n";
        }
        """
    let argumentStrings: [String] = [executable, "-e", script]
    var arguments: [UnsafeMutablePointer<CChar>?] = argumentStrings.map {
        strdup($0)
    }
    arguments.append(nil)
    defer {
        arguments.compactMap { $0 }.forEach { free($0) }
    }

    let output = Pipe()
    var fileActions: posix_spawn_file_actions_t?
    guard posix_spawn_file_actions_init(&fileActions) == 0 else {
        throw SignalDispositionProbeFailure()
    }
    defer {
        posix_spawn_file_actions_destroy(&fileActions)
    }
    let outputDescriptor = output.fileHandleForWriting.fileDescriptor
    guard posix_spawn_file_actions_adddup2(
        &fileActions,
        outputDescriptor,
        STDOUT_FILENO
    ) == 0,
    posix_spawn_file_actions_addclose(
        &fileActions,
        outputDescriptor
    ) == 0 else {
        throw SignalDispositionProbeFailure()
    }

    var processID: pid_t = 0
    var environment: [UnsafeMutablePointer<CChar>?] = [nil]
    let spawnResult = executable.withCString { executablePath in
        arguments.withUnsafeMutableBufferPointer { argumentBuffer in
            environment.withUnsafeMutableBufferPointer { environmentBuffer in
                posix_spawn(
                    &processID,
                    executablePath,
                    &fileActions,
                    nil,
                    argumentBuffer.baseAddress,
                    environmentBuffer.baseAddress
                )
            }
        }
    }
    try output.fileHandleForWriting.close()
    guard spawnResult == 0 else {
        throw SignalDispositionProbeFailure()
    }

    var status: Int32 = 0
    guard waitpid(processID, &status, 0) == processID, status == 0 else {
        throw SignalDispositionProbeFailure()
    }
    let data = (try output.fileHandleForReading.readToEnd()) ?? Data()
    try output.fileHandleForReading.close()
    return String(
        decoding: data,
        as: UTF8.self
    )
}

private struct SignalDispositionProbeFailure: Error {}

private final class SignalActionTestState: @unchecked Sendable {
    private let lock = NSLock()
    private var storedAction: sigaction

    init(action: sigaction) {
        storedAction = action
    }

    var actionBytes: Data {
        locked { signalActionBytes(storedAction) }
    }

    var flags: Int32 {
        locked { storedAction.sa_flags }
    }

    var handlerBits: UInt {
        locked { signalActionHandlerBits(storedAction) }
    }

    var maskBits: sigset_t {
        locked { storedAction.sa_mask }
    }

    func maskContains(_ signal: Int32) -> Bool {
        locked {
            var mask = storedAction.sa_mask
            return sigismember(&mask, signal) == 1
        }
    }

    func apply(
        signal: Int32,
        action: UnsafePointer<sigaction>?,
        previousAction: UnsafeMutablePointer<sigaction>?
    ) -> Int32 {
        locked {
            previousAction?.pointee = storedAction
            if let action {
                storedAction = action.pointee
            }
            return 0
        }
    }

    private func locked<T>(_ operation: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return operation()
    }
}

private final class SignalCoordinatorTestState: @unchecked Sendable {
    private let lock = NSLock()
    private var storedDispositions: [Int32: String]
    private var storedInstallCounts: [Int32: Int] = [:]
    private var storedCancelCounts: [Int32: Int] = [:]
    private var storedSources: [Int32: SignalCoordinatorTestEvent] = [:]
    private var storedRegistrations: [ChildSignalForwardingRegistration] = []
    private var storedForwardedSignals: [Int32] = []
    private var storedForwardedOnMainThread: [Bool] = []
    private var storedInstallationProcessStates: [Bool] = []
    private var storedRestorationCount = 0

    init(dispositions: [Int32: String]) {
        storedDispositions = dispositions
    }

    var dispositions: [Int32: String] {
        locked { storedDispositions }
    }

    var installCounts: [Int32: Int] {
        locked { storedInstallCounts }
    }

    var cancelCounts: [Int32: Int] {
        locked { storedCancelCounts }
    }

    var registrations: [ChildSignalForwardingRegistration] {
        locked { storedRegistrations }
    }

    var forwardedSignals: [Int32] {
        locked { storedForwardedSignals }
    }

    var forwardedOnMainThread: [Bool] {
        locked { storedForwardedOnMainThread }
    }

    var installationProcessStates: [Bool] {
        locked { storedInstallationProcessStates }
    }

    var restorationCount: Int {
        locked { storedRestorationCount }
    }

    func replaceDisposition(_ signal: Int32, with value: String) -> String {
        locked {
            let previous = storedDispositions[signal] ?? "default"
            storedDispositions[signal] = value
            return previous
        }
    }

    func setDisposition(_ value: String, for signal: Int32) {
        locked {
            storedDispositions[signal] = value
        }
    }

    func installSource(
        signal: Int32,
        queue: DispatchQueue,
        eventHandler: @escaping @Sendable () -> Void
    ) {
        locked {
            storedInstallCounts[signal, default: 0] += 1
            storedSources[signal] = SignalCoordinatorTestEvent(
                queue: queue,
                eventHandler: eventHandler
            )
        }
    }

    func cancelSource(signal: Int32) {
        locked {
            storedCancelCounts[signal, default: 0] += 1
            storedSources[signal] = nil
        }
    }

    func appendRegistration(_ registration: ChildSignalForwardingRegistration) {
        locked {
            storedRegistrations.append(registration)
        }
    }

    func event(signal: Int32) -> SignalCoordinatorTestEvent? {
        locked { storedSources[signal] }
    }

    func recordForward(signal: Int32, isMainThread: Bool) {
        locked {
            storedForwardedSignals.append(signal)
            storedForwardedOnMainThread.append(isMainThread)
        }
    }

    func recordInstallation(processIsRunning: Bool) {
        locked {
            storedInstallationProcessStates.append(processIsRunning)
        }
    }

    func recordRestoration() {
        locked {
            storedRestorationCount += 1
        }
    }

    private func locked<T>(_ operation: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return operation()
    }
}
