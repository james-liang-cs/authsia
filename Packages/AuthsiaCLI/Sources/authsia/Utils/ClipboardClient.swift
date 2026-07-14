import Darwin
import Foundation

struct ClipboardClient: Sendable {
    let copy: @Sendable (String, Int) throws -> Void

    static let system = ClipboardClient { value, clearAfterSeconds in
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pbcopy")
        let input = Pipe()
        process.standardInput = input
        try process.run()
        input.fileHandleForWriting.write(Data(value.utf8))
        input.fileHandleForWriting.closeFile()
        process.waitUntilExit()

        if clearAfterSeconds > 0 {
            let clearProcess = Process()
            clearProcess.executableURL = URL(fileURLWithPath: "/bin/sh")
            clearProcess.arguments = ["-c", "sleep \"$1\" && pbcopy < /dev/null", "authsia-clip", String(clearAfterSeconds)]
            clearProcess.standardOutput = FileHandle.nullDevice
            clearProcess.standardError = FileHandle.nullDevice
            try? clearProcess.run()
            // DO NOT call waitUntilExit() — process runs detached, survives CLI exit
            if isatty(fileno(Darwin.stderr)) != 0 {
                FileHandle.standardError.write(
                    Data("Copied. Clearing in \(clearAfterSeconds)s.\n".utf8)
                )
            }
        } else {
            if isatty(fileno(Darwin.stderr)) != 0 {
                FileHandle.standardError.write(
                    Data("Copied to clipboard. Remember to clear when done.\n".utf8)
                )
            }
        }
    }
}
