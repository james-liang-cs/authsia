// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Authsia",
    platforms: [
        .macOS(.v15),
        .iOS(.v17)
    ],
    products: [
        .library(name: "AuthenticatorCore", targets: ["AuthenticatorCore"]),
        .library(name: "AuthenticatorData", targets: ["AuthenticatorData"]),
        .library(name: "AuthenticatorBridge", targets: ["AuthenticatorBridge"]),
        .library(name: "AuthsiaBridgeHost", targets: ["AuthsiaBridgeHost"]),
        .executable(name: "authsia", targets: ["authsia"])
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-argument-parser",
            exact: "1.7.0"
        ),
        .package(
            url: "https://github.com/modelcontextprotocol/swift-sdk.git",
            exact: "0.12.1"
        ),
        .package(
            url: "https://github.com/apple/swift-nio.git",
            exact: "2.101.3"
        )
    ],
    targets: [
        .target(
            name: "AuthenticatorCore",
            path: "Packages/AuthenticatorCore/Sources/AuthenticatorCore"
        ),
        .testTarget(
            name: "AuthenticatorCoreTests",
            dependencies: ["AuthenticatorCore"],
            path: "Packages/AuthenticatorCore/Tests/AuthenticatorCoreTests"
        ),
        .target(
            name: "AuthenticatorData",
            dependencies: ["AuthenticatorCore"],
            path: "Packages/AuthenticatorData/Sources/AuthenticatorData"
        ),
        .testTarget(
            name: "AuthenticatorDataTests",
            dependencies: ["AuthenticatorData", "AuthenticatorCore"],
            path: "Packages/AuthenticatorData/Tests/AuthenticatorDataTests"
        ),
        .target(
            name: "AuthenticatorBridge",
            dependencies: ["AuthenticatorCore"],
            path: "Packages/AuthenticatorBridge/Sources/AuthenticatorBridge"
        ),
        .testTarget(
            name: "AuthenticatorBridgeTests",
            dependencies: ["AuthenticatorBridge"],
            path: "Packages/AuthenticatorBridge/Tests/AuthenticatorBridgeTests",
            resources: [.process("Fixtures")]
        ),
        .target(
            name: "AuthsiaBridgeHost",
            dependencies: [
                "AuthenticatorBridge",
                "AuthenticatorCore",
                "AuthenticatorData",
                .product(name: "MCP", package: "swift-sdk", condition: .when(platforms: [.macOS])),
                .product(name: "NIOCore", package: "swift-nio", condition: .when(platforms: [.macOS])),
                .product(name: "NIOHTTP1", package: "swift-nio", condition: .when(platforms: [.macOS])),
                .product(name: "NIOPosix", package: "swift-nio", condition: .when(platforms: [.macOS]))
            ],
            path: "Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost",
            linkerSettings: [
                .linkedFramework("Security", .when(platforms: [.macOS]))
            ]
        ),
        .testTarget(
            name: "AuthsiaBridgeHostTests",
            dependencies: [
                "AuthsiaBridgeHost",
                "AuthenticatorBridge",
                "AuthenticatorCore",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio")
            ],
            path: "Packages/AuthsiaBridgeHost/Tests/AuthsiaBridgeHostTests"
        ),
        .executableTarget(
            name: "authsia",
            dependencies: [
                "AuthenticatorBridge",
                "AuthenticatorCore",
                "AuthenticatorData",
                .product(
                    name: "ArgumentParser",
                    package: "swift-argument-parser"
                ),
                .product(
                    name: "MCP",
                    package: "swift-sdk"
                )
            ],
            path: "Packages/AuthsiaCLI/Sources/authsia"
        ),
        .testTarget(
            name: "AuthsiaCLITests",
            dependencies: [
                "authsia",
                "AuthenticatorData",
                .product(
                    name: "ArgumentParser",
                    package: "swift-argument-parser"
                ),
                .product(
                    name: "MCP",
                    package: "swift-sdk"
                )
            ],
            path: "Packages/AuthsiaCLI/Tests/AuthsiaCLITests"
        )
    ]
)
