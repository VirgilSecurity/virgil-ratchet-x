// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "VirgilSDKRatchet",
    platforms: [
        .macOS(.v10_11), .iOS(.v9), .tvOS(.v9), .watchOS(.v2)
    ],
    products: [
        .library(
            name: "VirgilSDKRatchet",
            targets: ["VirgilSDKRatchet"]),
    ],

    dependencies: [
        .package(url: "https://github.com/VirgilSecurity/virgil-sdk-x.git",
                 Range(uncheckedBounds: (lower: Version(8, 1, 0), upper: Version(8, 2, 0)))),
        .package(url: "https://github.com/VirgilSecurity/virgil-cryptowrapper-x.git", exact: .init(0, 16, 1))
    ],

    targets: [
        .target(
            name: "VirgilSDKRatchet",
            dependencies: [
                .product(name: "VirgilSDK", package: "virgil-sdk-x"),
                .product(name: "VirgilCryptoRatchet", package: "virgil-cryptowrapper-x")
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
