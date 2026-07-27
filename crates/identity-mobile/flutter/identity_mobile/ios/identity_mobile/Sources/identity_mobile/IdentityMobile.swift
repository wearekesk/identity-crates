import Foundation

/// This target exists so SwiftPM has something to build; the work is all in Rust.
///
/// Every entry point is called from Dart through `dart:ffi` at runtime, so no Swift or
/// Objective-C code references the Rust symbols — which means the linker would happily
/// discard them. `-all_load` in Package.swift is what stops that: it pulls in every
/// object file from the static archive rather than only the ones something asks for.
///
/// Nothing here needs a bridging header. Dart resolves the symbols out of the process
/// itself, so the C declarations never have to be visible to Swift.
public enum IdentityMobile {
    /// The version of the native library this package expects to be built against.
    public static let nativeVersion = "0.0.0"
}
