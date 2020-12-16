// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "TICEAuth",
    platforms: [
        .macOS(.v10_15), .iOS(.v13),
    ],
    products: [
        .library(
            name: "TICEAuth",
            targets: ["TICEAuth"]),
    ],
    dependencies: [
        .package(name: "Sodium", url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1"),
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "TICEAuth",
            dependencies: [
                .product(name: "Sodium", package: "Sodium"),
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources"),
        .testTarget(
            name: "TICEAuthTests",
            dependencies: ["TICEAuth"]),
    ]
)
