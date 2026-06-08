// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VaultUI",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "VaultCrypto", targets: ["VaultCrypto"]),
        .library(name: "VaultModels", targets: ["VaultModels"]),
        .library(name: "VaultAPI", targets: ["VaultAPI"]),
        .library(name: "VaultSync", targets: ["VaultSync"]),
        .library(name: "VaultSSH", targets: ["VaultSSH"]),
        .library(name: "VaultServices", targets: ["VaultServices"]),
        .library(name: "VaultAppUI", targets: ["VaultAppUI"]),
        .executable(name: "vaultui", targets: ["VaultCLI"]),
        .executable(name: "VaultUIApp", targets: ["VaultUIApp"]),
        .library(name: "VaultAutoFillExtension", type: .dynamic, targets: ["VaultAutoFillExtension"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
        .package(url: "https://github.com/tmthecoder/Argon2Swift.git", branch: "main"),
    ],
    targets: [
        // MARK: - Core Crypto
        .target(
            name: "VaultCrypto",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Argon2Swift", package: "Argon2Swift"),
            ],
            path: "Sources/VaultCrypto"
        ),

        // MARK: - Data Models
        .target(
            name: "VaultModels",
            dependencies: ["VaultCrypto"],
            path: "Sources/VaultModels"
        ),

        // MARK: - API Client
        .target(
            name: "VaultAPI",
            dependencies: ["VaultModels", "VaultCrypto"],
            path: "Sources/VaultAPI"
        ),

        // MARK: - Sync Engine
        .target(
            name: "VaultSync",
            dependencies: ["VaultAPI", "VaultModels", "VaultCrypto"],
            path: "Sources/VaultSync"
        ),

        // MARK: - SSH Agent
        .target(
            name: "VaultSSH",
            dependencies: [
                "VaultCrypto",
                "VaultModels",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ],
            path: "Sources/VaultSSH"
        ),

        // MARK: - Business Logic Services
        .target(
            name: "VaultServices",
            dependencies: [
                "VaultCrypto",
                "VaultModels",
                "VaultAPI",
                "VaultSync",
                "VaultSSH",
            ],
            path: "Sources/VaultServices"
        ),

        // MARK: - SwiftUI Views
        .target(
            name: "VaultAppUI",
            dependencies: [
                "VaultServices",
                "VaultCrypto",
                "VaultModels",
                "VaultAPI",
                "VaultSync",
            ],
            path: "Sources/VaultAppUI",
            resources: [
                .process("Resources")
            ]
        ),

        // MARK: - CLI Tool
        .executableTarget(
            name: "VaultCLI",
            dependencies: [
                "VaultServices",
                "VaultCrypto",
                "VaultModels",
                "VaultAPI",
                "VaultSSH",
                "VaultSync",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/VaultCLI"
        ),

        // MARK: - App Target
        .executableTarget(
            name: "VaultUIApp",
            dependencies: [
                "VaultAppUI",
                "VaultServices",
                "VaultSSH",
            ],
            path: "Sources/VaultUIApp",
            exclude: ["Info.plist"]
        ),

        // MARK: - AutoFill Extension
        .target(
            name: "VaultAutoFillExtension",
            dependencies: [
                "VaultModels",
                "VaultCrypto",
                "VaultServices",
                "VaultAPI"
            ],
            path: "Sources/VaultAutoFillExtension",
            exclude: ["Info.plist"]
        ),

        // MARK: - Tests
        .testTarget(
            name: "VaultCryptoTests",
            dependencies: ["VaultCrypto"],
            path: "Tests/VaultCryptoTests"
        ),
        .testTarget(
            name: "VaultModelsTests",
            dependencies: ["VaultModels"],
            path: "Tests/VaultModelsTests"
        ),
        .testTarget(
            name: "VaultAPITests",
            dependencies: ["VaultAPI"],
            path: "Tests/VaultAPITests"
        ),
    ]
)
