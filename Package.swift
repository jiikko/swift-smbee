// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SMBee",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SMBee", targets: ["SMBee"]),
        .executable(name: "smbcli", targets: ["smbcli"]),
    ],
    dependencies: [
        // 暗号プリミティブ (AES-GCM / HMAC / SHA) は自作せず swift-crypto に委ねる。
        // SMB protocol / framing は SMBee 自身で実装する (issue 359 の依存方針)。
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
        .package(url: "https://github.com/SimplyDanny/SwiftLintPlugins", from: "0.63.0"),
    ],
    targets: [
        .target(
            name: "SMBee",
            dependencies: [.product(name: "Crypto", package: "swift-crypto")],
            plugins: [.plugin(name: "SwiftLintBuildToolPlugin", package: "SwiftLintPlugins")]
        ),
        .executableTarget(
            name: "smbcli",
            dependencies: [
                "SMBee",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            plugins: [.plugin(name: "SwiftLintBuildToolPlugin", package: "SwiftLintPlugins")]
        ),
        .testTarget(name: "SMBeeTests", dependencies: ["SMBee"]),
    ]
)
