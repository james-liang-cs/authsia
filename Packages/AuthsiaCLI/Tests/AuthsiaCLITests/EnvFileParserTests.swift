import Testing
import Foundation
import AuthenticatorCore
@testable import authsia

@Suite("EnvFileParser")
struct EnvFileParserTests {

    private func parse(_ content: String) throws -> [(key: String, value: String)] {
        try EnvFileParser.parse(content: content)
    }

    @Test("parses simple key=value")
    func simpleKeyValue() throws {
        let result = try parse("API_KEY=secret123")
        #expect(result.count == 1)
        #expect(result[0].key == "API_KEY")
        #expect(result[0].value == "secret123")
    }

    @Test("parses multiple lines")
    func multipleLines() throws {
        let result = try parse("A=1\nB=2\nC=3")
        #expect(result.count == 3)
        #expect(result[0].key == "A")
        #expect(result[2].value == "3")
    }

    @Test("skips comments")
    func skipsComments() throws {
        let result = try parse("# This is a comment\nAPI_KEY=value")
        #expect(result.count == 1)
        #expect(result[0].key == "API_KEY")
    }

    @Test("skips empty lines")
    func skipsEmptyLines() throws {
        let result = try parse("A=1\n\n\nB=2\n")
        #expect(result.count == 2)
    }

    @Test("strips double quotes from values")
    func doubleQuotes() throws {
        let result = try parse(#"KEY="quoted value""#)
        #expect(result[0].value == "quoted value")
    }

    @Test("strips single quotes — treats as literal")
    func singleQuotes() throws {
        let result = try parse("KEY='authsia://password/X/y'")
        #expect(result[0].value == "authsia://password/X/y")
    }

    @Test("preserves authsia:// in double-quoted values")
    func doubleQuotedRef() throws {
        let result = try parse(#"KEY="authsia://password/My Service/password""#)
        #expect(result[0].value == "authsia://password/My Service/password")
    }

    @Test("strips inline comments")
    func inlineComments() throws {
        let result = try parse("PORT=8080  # web server port")
        #expect(result[0].value == "8080")
    }

    @Test("does not strip # inside double quotes")
    func hashInQuotes() throws {
        let result = try parse(#"MSG="hello # world""#)
        #expect(result[0].value == "hello # world")
    }

    @Test("last value wins for duplicate keys")
    func duplicateKeys() throws {
        let result = try parse("KEY=first\nKEY=second")
        #expect(result.count == 2)
        #expect(result[1].value == "second")
    }

    @Test("handles value with equals sign")
    func valueWithEquals() throws {
        let result = try parse("URL=https://example.com?foo=bar")
        #expect(result[0].value == "https://example.com?foo=bar")
    }

    @Test("handles empty value")
    func emptyValue() throws {
        let result = try parse("KEY=")
        #expect(result[0].key == "KEY")
        #expect(result[0].value == "")
    }

    @Test("skips lines without equals")
    func noEquals() throws {
        let result = try parse("NOT_A_VALID_LINE\nKEY=value")
        #expect(result.count == 1)
        #expect(result[0].key == "KEY")
    }

    @Test("trims whitespace around key and value")
    func trimWhitespace() throws {
        let result = try parse("  KEY  =  value  ")
        #expect(result[0].key == "KEY")
        #expect(result[0].value == "value")
    }

    @Test("parses file from disk")
    func parseFile() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("test-\(UUID().uuidString).env")
        try "A=1\nB=authsia://password/X/password\n"
            .write(to: tmp, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let result = try EnvFileParser.parse(contentsOf: tmp.path)
        #expect(result.count == 2)
        #expect(result[1].value == "authsia://password/X/password")
    }

    // MARK: - export prefix (fix #4)

    @Test("strips export prefix")
    func exportPrefix() throws {
        let result = try parse("export API_KEY=secret123")
        #expect(result.count == 1)
        #expect(result[0].key == "API_KEY")
        #expect(result[0].value == "secret123")
    }

    @Test("strips export prefix with tab")
    func exportPrefixTab() throws {
        let result = try parse("export\tDB_PASS=hunter2")
        #expect(result[0].key == "DB_PASS")
        #expect(result[0].value == "hunter2")
    }

    @Test("export prefix does not affect keys that start with 'export' in their name")
    func exportInKeyName() throws {
        let result = try parse("EXPORTED_KEY=value")
        #expect(result[0].key == "EXPORTED_KEY")
    }

    // MARK: - Single-quoted value with inline comment (fix #5)

    @Test("single-quoted value with trailing inline comment")
    func singleQuotesWithComment() throws {
        let result = try parse("KEY='myvalue' # this is a comment")
        #expect(result[0].key == "KEY")
        #expect(result[0].value == "myvalue")
    }

    @Test("double-quoted value with trailing inline comment")
    func doubleQuotesWithComment() throws {
        let result = try parse(#"KEY="myvalue" # this is a comment"#)
        #expect(result[0].key == "KEY")
        #expect(result[0].value == "myvalue")
    }
}
