enum WorkspaceOutputFormatter {
    static func keyValue(_ pairs: [(String, String)]) -> String {
        TableFormatter.renderTable(
            headers: ["Field", "Value"],
            rows: pairs.map { [$0.0, $0.1] }
        )
    }

    static func section(
        _ title: String,
        headers: [String],
        rows: [[String]],
        empty: String
    ) -> String {
        if rows.isEmpty {
            return "\(title)\n\(empty)"
        }
        return "\(title)\n\(TableFormatter.renderTable(headers: headers, rows: rows))"
    }

    static func append(_ text: String, to lines: inout [String]) {
        guard !text.isEmpty else { return }
        if !lines.isEmpty {
            lines.append("")
        }
        lines.append(text)
    }
}
