// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "VirgilSDKRatchet",
    platforms: [
        .macOS(.v10_13), .iOS(.v11), .tvOS(.v11), .watchOS(.v4)
    ],
    products: [
        .library(
            name: "VirgilSDKRatchet",
            targets: ["VirgilSDKRatchet"]),
    ],

    dependencies: [
        .package(url: "https://github.com/VirgilSecurity/virgil-sdk-x.git", exact: .init(9, 0, 0)),
        .package(url: "https://github.com/VirgilSecurity/virgil-crypto-c.git", exact: .init(0, 17, 0))
    ],

    targets: [
        .target(
            name: "VirgilSDKRatchet",
            dependencies: [
                .product(name: "VirgilSDK", package: "virgil-sdk-x"),
                .product(name: "VirgilCryptoRatchet", package: "virgil-crypto-c")
            ],
            path: "Source"
        ),
        .testTarget(
            name: "VirgilSDKRatchetTest",
            dependencies: ["VirgilSDKRatchet"],
            path: "Tests",
            resources: [
                .process("Data/TestConfig.plist")
            ],
            swiftSettings: [
                .define("SPM_BUILD")
            ]
        )
    ]
)
