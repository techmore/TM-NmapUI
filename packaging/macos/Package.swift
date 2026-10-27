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
    targets: [
        .target(
            name: "RuntimeContracts",
            path: "Sources/RuntimeContracts"
        ),
        .executableTarget(
            name: "NmapUIApp",
            dependencies: ["RuntimeContracts"],
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
            path: "Sources/GoogleDriveHelper"
        ),
        .executableTarget(
            name: "RuntimeReportHelper",
            dependencies: ["RuntimeContracts"],
            path: "Sources/RuntimeReportHelper"
        ),
        .testTarget(
            name: "NmapUIAppTests",
            dependencies: ["NmapUIApp", "NmapPrivilegedHelper", "RuntimeContracts"],
            path: "Tests/NmapUIAppTests"
        )
    ]
)
