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
        .package(url: "https://github.com/VirgilSecurity/virgil-sdk-x.git", branch: "develop")
    ],

    targets: [
        .target(
            name: "VirgilSDKRatchet",
            dependencies: [
                .product(name: "VirgilSDK", package: "virgil-sdk-x"),
            ],
            path: "Source"
        )
    ]
)
