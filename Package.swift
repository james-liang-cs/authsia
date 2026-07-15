// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "Authsia",
    platforms: [
        .macOS(.v15),
        .iOS(.v16)
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
            path: "Packages/AuthenticatorBridge/Tests/AuthenticatorBridgeTests"
        ),
        .target(
            name: "AuthsiaBridgeHost",
            dependencies: [
                "AuthenticatorBridge",
                "AuthenticatorCore",
                "AuthenticatorData"
            ],
            path: "Packages/AuthsiaBridgeHost/Sources/AuthsiaBridgeHost"
        ),
        .testTarget(
            name: "AuthsiaBridgeHostTests",
            dependencies: [
                "AuthsiaBridgeHost",
                "AuthenticatorBridge",
                "AuthenticatorCore"
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
                )
            ],
            path: "Packages/AuthsiaCLI/Tests/AuthsiaCLITests"
        )
    ]
)
