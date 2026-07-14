#if os(macOS)
public enum BridgeQueryMatcher {
    public static func firstMatch<T>(
        query: String,
        in items: [T],
        id: (T) -> String,
        searchable: (T) -> [String]
    ) -> T? {
        let lowercasedQuery = query.lowercased()

        if let exactID = items.first(where: { id($0).lowercased() == lowercasedQuery }) {
            return exactID
        }

        let exactCaseMatches = items.filter {
            searchable($0).contains(query)
        }
        if exactCaseMatches.count == 1, let exactCase = exactCaseMatches.first {
            return exactCase
        }
        if exactCaseMatches.count > 1 {
            return nil
        }

        let exactNameMatches = items.filter {
            searchable($0).contains { $0.lowercased() == lowercasedQuery }
        }
        if exactNameMatches.count == 1, let exactName = exactNameMatches.first {
            return exactName
        }
        if exactNameMatches.count > 1 {
            return nil
        }

        let prefixMatches = items.filter {
            searchable($0).contains { $0.lowercased().hasPrefix(lowercasedQuery) }
        }
        if prefixMatches.count == 1 { return prefixMatches.first }

        let containsMatches = items.filter {
            searchable($0).contains { $0.lowercased().contains(lowercasedQuery) }
        }
        if containsMatches.count == 1 { return containsMatches.first }

        return nil
    }
}
#endif
