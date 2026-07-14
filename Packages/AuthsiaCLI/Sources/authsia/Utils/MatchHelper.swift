import Foundation

enum MatchHelper {
    static func findSingle<T>(
        query: String,
        items: [T],
        kind: String,
        id: (T) -> String,
        searchable: (T) -> [String],
        display: (T) -> CLIError.MatchDescriptor
    ) throws -> T {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if let exact = items.first(where: { id($0).caseInsensitiveCompare(trimmed) == .orderedSame }) {
            return exact
        }

        if !trimmed.isEmpty {
            let exactCaseMatches = items.filter { item in
                searchable(item).contains(trimmed)
            }
            if exactCaseMatches.count == 1 {
                return exactCaseMatches[0]
            }
            if exactCaseMatches.count > 1 {
                let descriptors = exactCaseMatches.map(display)
                throw CLIError.multipleMatches(kind: kind, query: trimmed, matches: descriptors)
            }

            let exactSearchableMatches = items.filter { item in
                searchable(item).contains { $0.caseInsensitiveCompare(trimmed) == .orderedSame }
            }
            if exactSearchableMatches.count == 1 {
                return exactSearchableMatches[0]
            }
            if exactSearchableMatches.count > 1 {
                let descriptors = exactSearchableMatches.map(display)
                throw CLIError.multipleMatches(kind: kind, query: trimmed, matches: descriptors)
            }
        }

        let lower = trimmed.lowercased()
        let matches = items.filter { item in
            searchable(item).contains { $0.lowercased().contains(lower) }
        }

        if matches.isEmpty {
            throw CLIError.noMatch(kind: kind, query: trimmed)
        }
        if matches.count > 1 {
            let descriptors = matches.map(display)
            throw CLIError.multipleMatches(kind: kind, query: trimmed, matches: descriptors)
        }
        return matches[0]
    }
}
