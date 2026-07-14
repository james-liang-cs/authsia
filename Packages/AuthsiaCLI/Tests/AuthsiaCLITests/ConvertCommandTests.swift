import Testing
@testable import authsia

struct ConvertCommandTests {
    @Test func convertPasswordParsesAPIKeyTarget() throws {
        let command = try ConvertPassword.parse(["Stripe", "--to", "api-key", "--format", "table"])

        #expect(command.query == "Stripe")
        #expect(command.to == .apiKey)
        #expect(command.format == .table)
    }
}
