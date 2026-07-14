import ArgumentParser
import Foundation

func resolveOutputFormat(
    format: OutputFormat,
    jsonFlag: Bool,
    command: String
) throws -> OutputFormat {
    guard jsonFlag else {
        return format
    }

    guard format == .json else {
        throw ValidationError(
            "Cannot combine --json with --format \(format.rawValue). Remove --json and use --format \(format.rawValue)."
        )
    }

    FileHandle.standardError.write(
        Data("Warning: '--json' is deprecated for '\(command)'; use '--format json'.\n".utf8)
    )
    return .json
}
