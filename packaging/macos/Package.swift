// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "NmapUI",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "NmapUI",
            targets: ["NmapUIApp"]
        ),
        .executable(
            name: "NmapPrivilegedHelper",
            targets: ["NmapPrivilegedHelper"]
        ),
        .executable(
            name: "GoogleDriveHelper",
            targets: ["GoogleDriveHelper"]
        ),
        .executable(
            name: "RuntimeReportHelper",
            targets: ["RuntimeReportHelper"]
        )
    ],
    dependencies: [
        .package(path: "Vendor/SocketIO")
    ],
    targets: [
        .target(name: "SharedEngineCore", dependencies: [.product(name: "SocketIO", package: "SocketIO")], path: "Sources/SharedEngineCore"),
        .testTarget(name: "SharedEngineCoreTests", dependencies: ["SharedEngineCore", .product(name: "SocketIO", package: "SocketIO")], path: "Tests/SharedEngineCoreTests", exclude: ["Fixtures"]),
        .target(name: "GoogleDriveCore", path: "Sources/GoogleDriveCore"),
        .testTarget(name: "GoogleDriveCoreTests", dependencies: ["GoogleDriveCore"], path: "Tests/GoogleDriveCoreTests"),
        .target(
            name: "RuntimeContracts",
            path: "Sources/RuntimeContracts"
        ),
        .executableTarget(
            name: "NmapUIApp",
            dependencies: ["RuntimeContracts", "GoogleDriveCore", "SharedEngineCore"],
            path: "Sources/NmapUIApp",
            exclude: [
                "Resources/Info.plist"
            ],
            resources: [
                .process("Assets")
            ]
        ),
        .executableTarget(
            name: "NmapPrivilegedHelper",
            dependencies: ["RuntimeContracts"],
            path: "Sources/NmapPrivilegedHelper"
        ),
        .executableTarget(
            name: "GoogleDriveHelper",
            dependencies: ["GoogleDriveCore"],
            path: "Sources/GoogleDriveHelper"
        ),
        .executableTarget(
            name: "RuntimeReportHelper",
            dependencies: ["RuntimeContracts"],
            path: "Sources/RuntimeReportHelper"
        ),
        .testTarget(
            name: "NmapUIAppTests",
            dependencies: ["NmapUIApp", "NmapPrivilegedHelper", "RuntimeContracts", "SharedEngineCore"],
            path: "Tests/NmapUIAppTests"
        )
    ]
)
