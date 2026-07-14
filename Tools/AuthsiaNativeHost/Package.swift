// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AuthsiaNativeHost",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "AuthsiaNativeHostCore", targets: ["AuthsiaNativeHostCore"]),
        .executable(name: "AuthsiaNativeHost", targets: ["AuthsiaNativeHost"])
    ],
    targets: [
        .target(
            name: "AuthsiaNativeHostCore"
        ),
        .executableTarget(
            name: "AuthsiaNativeHost",
            dependencies: ["AuthsiaNativeHostCore"]
        ),
        .testTarget(
            name: "AuthsiaNativeHostCoreTests",
            dependencies: ["AuthsiaNativeHostCore"]
        )
    ]
)
