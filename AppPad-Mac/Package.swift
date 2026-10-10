// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "AppPad-Mac",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "AppPad-Mac", targets: ["AppPad-Mac"])
    ],
    targets: [
        // Pure-Swift protocol layer (packet parsing), unit-testable
        .target(name: "AirPadCore"),
        .executableTarget(
            name: "AppPad-Mac",
            dependencies: ["AirPadCore"],
            path: ".",
            exclude: [
                "Info.plist",
                "AppPad-Mac.entitlements",
                "Sources",
                "Tests"
            ]
        ),
        .testTarget(
            name: "AirPadCoreTests",
            dependencies: ["AirPadCore"],
            path: "Tests/AirPadCoreTests"
        )
    ]
)
