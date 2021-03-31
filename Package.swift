// swift-tools-version:5.3

import PackageDescription

let package = Package(
    name: "TICEAuth",
    platforms: [
        .macOS(.v10_15), .iOS(.v13)
    ],
    products: [
        .library(
            name: "TICEAuth",
            targets: ["TICEAuth"])
    ],
    dependencies: [
        .package(name: "jwt-kit", url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0"),
        .package(name: "swift-log", url: "https://github.com/apple/swift-log.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "TICEAuth",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit"),
                .product(name: "Logging", package: "swift-log")
            ],
            path: "Sources"),
        .testTarget(
            name: "TICEAuthTests",
            dependencies: ["TICEAuth"])
    ]
)
