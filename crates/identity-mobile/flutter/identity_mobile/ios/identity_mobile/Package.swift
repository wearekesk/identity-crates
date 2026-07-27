// swift-tools-version: 5.9
//
// Swift Package Manager, not CocoaPods.
//
// The Rust side ships as a binary target: `identity_mobile.xcframework` is produced by
// release.yml's `flutter-ffi (iOS)` job (device + both simulator slices) and dropped
// beside this manifest. SwiftPM links it into the app, which is why the Dart side
// resolves symbols with `DynamicLibrary.process()` rather than opening anything.

import PackageDescription

let package = Package(
    name: "identity_mobile",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(name: "identity-mobile", targets: ["identity_mobile"])
    ],
    targets: [
        .binaryTarget(
            name: "IdentityMobileFFI",
            path: "identity_mobile.xcframework"
        ),
        .target(
            name: "identity_mobile",
            dependencies: ["IdentityMobileFFI"],
            resources: [],
            // Without this the linker drops the Rust exports: nothing in the Swift or
            // Objective-C world references them, since every call arrives from Dart at
            // runtime, so dead-stripping is free to remove the lot.
            //
            // `-all_load`, not `-Wl,-all_load`: SwiftPM forwards these to the linker,
            // where the clang-driver spelling would not be understood — and the
            // failure mode is a missing symbol at runtime, from Dart, on a device.
            linkerSettings: [
                .unsafeFlags(["-all_load"])
            ]
        )
    ]
)
