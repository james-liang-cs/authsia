import ArgumentParser
import Foundation

/// Parses the `--expires-at` option value for add/edit commands.
/// Accepts a calendar day (`YYYY-MM-DD`, interpreted as local start of day)
/// or a full ISO-8601 timestamp (e.g. `2026-12-31T23:59:59Z`).
enum ExpiryDateParser {
    static func parse(_ string: String) throws -> Date {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)

        if let date = ISO8601DateFormatter().date(from: trimmed) {
            return date
        }

        let dayFormatter = DateFormatter()
        dayFormatter.calendar = Calendar(identifier: .gregorian)
        dayFormatter.locale = Locale(identifier: "en_US_POSIX")
        dayFormatter.timeZone = TimeZone.current
        dayFormatter.dateFormat = "yyyy-MM-dd"
        if let date = dayFormatter.date(from: trimmed) {
            return date
        }

        throw ValidationError(
            "Invalid date '\(string)'. Use YYYY-MM-DD or an ISO-8601 timestamp like 2026-12-31T23:59:59Z."
        )
    }
}
