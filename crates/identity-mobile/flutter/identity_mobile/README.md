# identity_mobile

Verify **ePassport chips** (ICAO 9303) and **mobile driving licences** (ISO/IEC
18013-5) from Flutter. Both documents return the same result.

The verification is the [`identity-mobile`](../../) Rust crate; this package is the
Dart binding and the NFC plumbing.

## Reading a passport

```dart
final reader = PassportReader(cscaAnchors: anchors);

final result = await reader.read(
  DBAKey('123456789', DateTime(1988, 3, 14), DateTime(2030, 1, 1)),
);

if (result.identity.authenticity.isPresentAndTrustworthy) {
  print(result.identity.displayName);
}
```

`flutter_nfc_kit` polls for the tag; the protocol runs in Rust. See
[How the NFC bridge works](#how-the-nfc-bridge-works) if you want to know why that
combination needs any thought at all.

### When your server is the authority

`read` returns a `PassportRead`: the verdict as `identity`, and — only if you ask for it
— the chip's elementary files as `dataGroups`.

```dart
final reader = PassportReader(cscaAnchors: anchors, retainDataGroups: true);
final result = await reader.read(key);

final groups = result.dataGroups!;   // non-null exactly when retainDataGroups is set

await api.verifyPassport(
  sod: groups.sod,
  dg1: groups.dg1,
  dg2: groups.dg2,
  dg15: groups.dg15,   // send every group that was read, or the server cannot cover it
);
```

Plenty of deployments will not accept a client's verdict however good the local check is
— a phone grading its own document is worth less than a server proving it. These are the
bytes such a server needs to check the signature chain and the hashes itself, and they
go straight into `IdentityMobile.verifyPassportFiles` at the far end, which repeats the
passive-authentication and chain-trust half of what this device did. Without them you
would have to read the chip a second time with a separate Dart eMRTD stack to obtain
bytes the plugin already had.

`sod` and `dg1` are always present; `dg2` and `dg15` are null when they were not read.
Forward all four. Passive authentication vouches for the groups it is given and no
others, so a `dg15` dropped on the way turns into a group the server's result reports as
signed but unverified.

**The server cannot repeat active authentication.** That is a live challenge to the chip,
which by then is back in someone's pocket, so `holderBound` comes back null at the far
end whatever this device saw. Stored bytes prove the data is what the issuer signed; only
the read that challenged the chip can say it is not a copy. If that matters to your
decision, carry it from here — and trust it on the same terms as anything else a client
tells you.

**Off by default**, because DG1 is the MRZ and DG2 is a facial image, and keeping the raw
files is a decision to make rather than one to inherit. They are ordinary `Uint8List`s
copied out of the native result before it was freed — you own them, the garbage collector
reclaims them, and there is nothing to release by hand.

It is not a privacy switch for the read as a whole, though: `result.identity` carries
what was parsed out of those files either way, `portrait` included whenever DG2 was read.
Pass `readPortrait: false` to leave the photograph on the chip.

The cost is on the way out of Rust: the bytes cross as hex, so a retained DG2 roughly
doubles into a few hundred kilobytes of JSON. Leave it off when nothing is going to
consume them.

## Verifying an mDL

```dart
final identity = IdentityMobile.verifyMdl(deviceResponse, iacaAnchors: anchors);
```

`deviceResponse` is the **decrypted** CBOR your proximity or OpenID4VP layer produced.
This package does no session establishment.

That call does issuer authentication only — `holderBound` comes back null and a captured
response can be replayed for as long as the credential stays valid — expiry still
applies, and it is the only thing bounding the replay. To bind the response to your
session, hand over the OpenID4VP
request parameters instead of building a transcript yourself:

```dart
final identity = await IdentityMobile.verifyMdlOpenId4VpAsync(
  deviceResponse,
  nonce: nonce,                 // yours, from the request — not the wallet's
  clientId: clientId,
  responseUri: responseUri,
  mdocGeneratedNonce: walletNonce,   // only if the wallet supplied one
  iacaAnchors: anchors,
);

print(identity.sessionProfile);      // openid4vp-1.0 | iso-18013-7 | openid4vp-dcapi
```

Two profiles are live and they encode the same session inputs differently: OpenID4VP 1.0
(Appendix B.2.6.1), its Digital Credentials API variant (B.2.6.2), and the older ISO/IEC
18013-7 Annex B shape with a wallet nonce. Every candidate your parameters support is
tried, and `sessionProfile` reports which one the holder signed.

Trying several is a question about encoding, not about trust. You supplied every input to
the transcript, and the holder still has to have signed one of them with the device key
the issuer bound into the MSO. What it costs is one signature check per candidate — so
log `sessionProfile`, and once you know what your wallets emit, stop offering the rest.

For the DC API, pass `origin` rather than `clientId`/`responseUri`. Pass `jwkThumbprint`
only when the response was encrypted: an absent thumbprint and an empty one produce
different transcripts, and the spec means the former.

## Already have the passport files?

If your app reads the chip itself — or you are the server receiving `dataGroups` from
one that did — skip the reader:

```dart
final identity = IdentityMobile.verifyPassportFiles(
  sod: sod, dg1: dg1, dg2: dg2, cscaAnchors: anchors,
);
```

Pass `dg2: null` when the photograph was not read. The result then reports the gap —
`signedDataGroups` will list a group `verifiedDataGroups` does not — instead of
implying the photograph was covered.

## What "verified" means

Three separate questions, because they fail independently:

```dart
identity.authenticity.dataAuthentic   // what the issuer signed, unaltered
identity.authenticity.issuerTrusted   // chains to an anchor you supplied
identity.authenticity.holderBound     // the original document, not a copy — nullable
identity.authenticity.notExpired
```

`holderBound` is **three-valued**. `null` means it was not attempted, which is not
`false`. Two helpers bundle the common policies:

```dart
identity.authenticity.isTrustworthy            // genuine, trusted issuer, in date
identity.authenticity.isPresentAndTrustworthy  // ...and provably the original
```

Use the second when the document is in front of you and a copy would not do. There is
no single `isValid`, because a genuine credential from an unknown issuer and a
well-formed forgery are both unusable for completely different reasons.

Read `holderBound` precisely: it binds the **document**, not the person. It proves the
chip or device in front of you holds the private key the issuer signed, so it is not a
copy. It says nothing about whether the person presenting it is the person it was issued
to — that is answered by comparing `portrait` against the face in front of you, and this
package does not do it for you.

## Handling failures

```dart
try {
  final result = await reader.read(key);
} on IdentityException catch (e) {
  switch (e.kind) {
    case IdentityErrorKind.nfc:
      // The phone moved. Retry automatically — e.kind.isRetryable is true.
    case IdentityErrorKind.access:
      // The document is probably fine, the key is wrong. Ask the user to check the
      // document number, date of birth and expiry. Do not retry the same values.
    case IdentityErrorKind.notAuthentic:
      // Stop. This is not a retry, and must not be presented as one.
    default:
      // unreadable, anchor, unsupportedAlgorithm, unknown
  }
}
```

The `nfc` / `access` split exists because those two look identical to the protocol and
need opposite responses from the holder. Retrying a wrong key forever, or telling
someone their genuine passport is fake because they moved their hand, are both
avoidable.

## Trust anchors

Ship them as assets and pass them in:

- **Passports** — DER-encoded CSCA certificates from the ICAO masterlist.
- **mDLs** — DER-encoded IACA certificates.

Verifying with none is allowed and useful in development: the data is still checked
against its signature, and `issuerTrusted` comes back false because nothing attributes
it to an issuer.

## Native libraries

This package ships Dart, not binaries. Put the compiled Rust where each platform
expects it:

| Platform | Artifact | Location |
|---|---|---|
| Android | `libidentity_mobile.so`, one per ABI | `android/src/main/jniLibs/<abi>/` |
| iOS | `identity_mobile.xcframework` | `ios/identity_mobile/`, beside `Package.swift` |

iOS uses **Swift Package Manager**, not CocoaPods. `ios/identity_mobile/Package.swift`
declares the xcframework as a binary target and links it with `-all_load` — without
that the linker discards every Rust symbol, since nothing in Swift references them and
all the calls arrive from Dart at runtime.

Note that SwiftPM validates binary target paths when it resolves, so the package will
not even build until the xcframework is in place. That is a feature: a missing artifact
fails at build time rather than as a missing symbol on a device.

Both are produced by the repository's `release.yml` — the `flutter-ffi (Android)` and
`flutter-ffi (iOS)` jobs — or locally:

```sh
# Android
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o flutter/identity_mobile/android/src/main/jniLibs \
    build -p identity-mobile --release

# iOS — device and both simulator slices, then assemble
for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  cargo rustc -p identity-mobile --release --target "$t" --crate-type staticlib
done
lipo -create target/aarch64-apple-ios-sim/release/libidentity_mobile.a \
             target/x86_64-apple-ios/release/libidentity_mobile.a \
             -output /tmp/libidentity_mobile-sim.a
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libidentity_mobile.a \
  -library /tmp/libidentity_mobile-sim.a \
  -output flutter/identity_mobile/ios/identity_mobile/identity_mobile.xcframework
```

## How the NFC bridge works

Worth understanding before changing it.

`flutter_nfc_kit.transceive` returns a `Future`. The passport protocol is a
conversation — read a file, derive a key, read the next — which `dmrtd` models as
blocking calls. Blocking calls cannot `await`.

So the read runs on a **worker isolate** (`Isolate.run`), where blocking is free. Each
APDU is posted back to the main isolate through a `NativeCallable.listener`, which does
the `await`, then hands the answer to Rust through an exchange id. Neither side blocks
the other, and the whole read stays inside one NFC session.

The alternative — demanding a synchronous transceive — would rule out every Flutter
NFC package there is.

## Platform notes

- **Android** — the plugin declares `android.permission.NFC`. Keep the read on a
  background thread with the tag connected throughout; `flutter_nfc_kit` handles this,
  but do not interleave other tag work.
- **iOS** — add `NFCReaderUsageDescription` and the ISO7816 application identifiers
  (`A0000002471001` for eMRTD) to your `Info.plist`, plus the Near Field Communication
  Tag Reading capability. Without them `poll` fails at runtime with a permissions
  error.
- Tell users to rest the phone on the document rather than hold it. Most "chip failed"
  reports are a moved phone.

## Tests

```sh
flutter test
```

These cover the boundary contract — what Rust emits and what Dart makes of it — without
needing the native library, which is where a mismatch would otherwise surface only on a
device with a passport in hand.
