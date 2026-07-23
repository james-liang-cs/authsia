import ArgumentParser

enum OutputDisclosurePolicy: String, CaseIterable, ExpressibleByArgument {
    case strict
    case maskedCompatibility = "masked-compatibility"
}

enum OutputDisclosureFailure: Error, Equatable, Sendable {
    case invalidUTF8
}
