// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "hummingbird-signedcookies",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "HummingbirdSignedCookies",
            targets: ["HummingbirdSignedCookies"]),
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.2.0"),
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "5.1.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "HummingbirdSignedCookies",
            dependencies: [
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "JWTKit", package: "jwt-kit"),
            ]
        ),
        .testTarget(
            name: "HummingbirdSignedCookiesTests",
            dependencies: ["HummingbirdSignedCookies"]
        ),
    ]
)
