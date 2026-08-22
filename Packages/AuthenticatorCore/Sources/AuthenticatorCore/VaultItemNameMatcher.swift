import Foundation

/// The reference-matching tiers `authsia` uses to turn an `authsia://` query
/// into vault items: exact id, then exact-case name, then case-insensitive
/// name.
///
/// There is deliberately no substring tier. The CLI only falls back to
/// substrings when it can report an ambiguity interactively; a surface that
/// merely previews resolution — Workspace Center — must stop here, so a
/// reference `authsia workspace run` cannot resolve never looks effective.
///
/// Shared so the app and the CLI cannot drift apart, as
/// `Doc/specs/workspace-environments.md` requires.
public enum VaultItemNameMatcher {
    public static func matches<Item>(
        query: String,
        in items: [Item],
        id: (Item) -> UUID,
        name: (Item) -> String
    ) -> [Item] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if let idMatch = items.first(where: { id($0).uuidString.caseInsensitiveCompare(trimmed) == .orderedSame }) {
            return [idMatch]
        }
        let exactCaseMatches = items.filter { name($0) == trimmed }
        if !exactCaseMatches.isEmpty { return exactCaseMatches }
        return items.filter { name($0).caseInsensitiveCompare(trimmed) == .orderedSame }
    }
}
