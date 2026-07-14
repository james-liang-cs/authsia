// Tests/AuthsiaCLITests/SSHAgentLoaderTests.swift
import Testing
import Foundation
import Darwin
@testable import authsia

struct SSHAgentLoaderTests {

    @Test func isAgentRunning_noSocket_returnsFalse() {
        var env = ProcessInfo.processInfo.environment
        env.removeValue(forKey: "SSH_AUTH_SOCK")
        #expect(!SSHAgentLoader.isAgentRunning(environment: env))
    }

    @Test func isAgentRunning_withSocket_returnsTrue() {
        let env = ["SSH_AUTH_SOCK": "/tmp/ssh-agent.socket"]
        #expect(SSHAgentLoader.isAgentRunning(environment: env))
    }

    @Test func authsiaBuiltInAgentDetection_matchesDefaultSocket() {
        let env = ["SSH_AUTH_SOCK": "/Users/example/.authsia/agent.sock"]
        #expect(SSHAgentLoader.isUsingAuthsiaBuiltInAgent(environment: env))
    }

    @Test func authsiaBuiltInAgentDetection_ignoresExternalAgentSocket() {
        let env = ["SSH_AUTH_SOCK": "/private/tmp/com.apple.launchd.123/Listeners"]
        #expect(!SSHAgentLoader.isUsingAuthsiaBuiltInAgent(environment: env))
    }

    @Test func buildAskPassScript_containsPassphrase() {
        let script = SSHAgentLoader.buildAskPassScript(passphrase: "secret123")
        #expect(script.contains("secret123"))
        #expect(script.hasPrefix("#!/bin/sh"))
    }

    @Test func buildAskPassScript_escapesSingleQuotes() {
        let script = SSHAgentLoader.buildAskPassScript(passphrase: "p'q")
        // Must not contain raw p'q — should be escaped
        #expect(!script.contains("p'q"))
        #expect(script.contains("p'\\'"))
    }

    @Test func formatAddResult_identityAdded() {
        let result = SSHAgentLoader.formatAddResult(
            output: "Identity added: /path/to/key (comment)",
            keyName: "deploy"
        )
        #expect(result == "Added identity: deploy")
    }

    @Test func formatAddResult_alreadyLoaded() {
        let result = SSHAgentLoader.formatAddResult(
            output: "Identity already added: /path (comment)",
            keyName: "deploy"
        )
        #expect(result == "Already loaded: deploy (skipped)")
    }

    @Test func formatAddResult_emptyOutput_returnsDefault() {
        let result = SSHAgentLoader.formatAddResult(output: "", keyName: "my-key")
        #expect(result == "Added identity: my-key")
    }

    // MARK: - Pipe-based askpass tests

    @Test func buildAskPassScript_fd_readsFromFD() {
        let script = SSHAgentLoader.buildAskPassScript(fd: 5)
        #expect(script.hasPrefix("#!/bin/sh"))
        #expect(script.contains("read"))
        #expect(script.contains("5"))
    }

    @Test func buildAskPassScript_fd_doesNotContainPassphrase() {
        // The fd-based script should never embed any passphrase — it reads from an fd.
        let script = SSHAgentLoader.buildAskPassScript(fd: 7)
        #expect(!script.contains("secret"))
        #expect(!script.contains("password"))
    }

    @Test func createAskPassPipe_returnsValidFDAndPath() throws {
        let (helperPath, readFD) = try SSHAgentLoader.createAskPassPipe(passphrase: "test-pass")
        defer {
            close(readFD)
            try? FileManager.default.removeItem(atPath: helperPath)
        }
        #expect(readFD >= 0)
        #expect(FileManager.default.fileExists(atPath: helperPath))
    }

    @Test func createAskPassPipe_passphraseReadableFromFD() throws {
        let passphrase = "my-secret-passphrase"
        let (helperPath, readFD) = try SSHAgentLoader.createAskPassPipe(passphrase: passphrase)
        defer {
            close(readFD)
            try? FileManager.default.removeItem(atPath: helperPath)
        }
        var buffer = [UInt8](repeating: 0, count: 1024)
        let bytesRead = Darwin.read(readFD, &buffer, buffer.count)
        #expect(bytesRead > 0)
        let received = String(bytes: buffer[..<bytesRead], encoding: .utf8)
        #expect(received == passphrase)
    }

    @Test func createAskPassPipe_scriptOnDiskDoesNotContainPassphrase() throws {
        let passphrase = "ultra-secret-value-42"
        let (helperPath, readFD) = try SSHAgentLoader.createAskPassPipe(passphrase: passphrase)
        defer {
            close(readFD)
            try? FileManager.default.removeItem(atPath: helperPath)
        }
        let scriptContents = try String(contentsOfFile: helperPath, encoding: .utf8)
        #expect(!scriptContents.contains(passphrase))
        #expect(scriptContents.hasPrefix("#!/bin/sh"))
    }
}
