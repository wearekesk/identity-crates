/// Verify ePassport chips and mobile driving licences from Flutter.
///
/// Both documents return the same [VerifiedIdentity], so an app that accepts either
/// has one result to reason about — and one place where "verified" is defined.
library;

import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'src/bindings.dart';
import 'src/models.dart';

export 'src/models.dart'
    show Authenticity, DocumentKind, IdentityErrorKind, IdentityException, VerifiedIdentity;
export 'src/passport_reader.dart' show DBAKey, PassportReader;

/// Native allocations that live exactly as long as one call.
///
/// The reason this exists rather than freeing inline: a `Struct` obtained through
/// `Pointer.ref` is a *view* onto native memory, not a copy. Passing one by value to an
/// FFI function reads that memory at call time, so anything freed beforehand is read
/// after it is gone. Everything goes in here and is released once the call has
/// returned.
class _Arena {
  final List<Pointer<NativeType>> _allocations = [];

  /// Copy bytes into native memory. Returns `nullptr` for absent or empty input,
  /// which the Rust side reads as "not supplied".
  Pointer<Uint8> bytes(Uint8List? source) {
    if (source == null || source.isEmpty) return nullptr;

    final buffer = calloc<Uint8>(source.length);
    buffer.asTypedList(source.length).setAll(0, source);
    _allocations.add(buffer);
    return buffer;
  }

  /// Copy a string into native memory. `null` stays `nullptr`, which the Rust side
  /// reads as "not supplied" — distinct from an empty string, which is a value.
  Pointer<Utf8> text(String? value) {
    if (value == null) return nullptr;

    final ptr = value.toNativeUtf8(allocator: calloc);
    _allocations.add(ptr);
    return ptr;
  }

  /// An OpenID4VP parameter block whose memory outlives the call that reads it.
  Pointer<NativeOpenId4VpParams> openId4VpParams() {
    final ptr = calloc<NativeOpenId4VpParams>();
    _allocations.add(ptr);
    return ptr;
  }

  /// Build a `NativeBytes` whose backing memory outlives the call that uses it.
  NativeBytes slice(Pointer<Uint8> ptr, int len) {
    final descriptor = calloc<NativeBytes>();
    descriptor.ref
      ..ptr = ptr
      ..len = len;
    _allocations.add(descriptor);
    return descriptor.ref;
  }

  void release() {
    for (final allocation in _allocations) {
      calloc.free(allocation);
    }
    _allocations.clear();
  }
}

/// Verification that needs no NFC: an mDL presentation, or passport files someone else
/// already read.
abstract final class IdentityMobile {
  /// Verify an mDL presentation.
  ///
  /// [deviceResponse] is the **decrypted** CBOR `DeviceResponse` your proximity or
  /// OpenID4VP layer produced; [iacaAnchors] are DER-encoded IACA certificates.
  ///
  /// Pass [sessionTranscript] when you have one. Without it this is issuer
  /// authentication only: [Authenticity.holderBound] comes back null and a captured
  /// response replays forever. [eReaderKey] is the reader's 32-byte ephemeral private
  /// key, required when the holder authenticated with `DeviceMac` — omit it and you
  /// get an error rather than a wrong answer.
  static VerifiedIdentity verifyMdl(
    Uint8List deviceResponse, {
    List<Uint8List> iacaAnchors = const [],
    Uint8List? sessionTranscript,
    Uint8List? eReaderKey,
  }) {
    final bindings = IdentityBindings.instance;
    final arena = _Arena();
    final (anchors, anchorBuffers) = allocateAnchors(iacaAnchors);

    try {
      final response = arena.slice(arena.bytes(deviceResponse), deviceResponse.length);
      final transcript =
          arena.slice(arena.bytes(sessionTranscript), sessionTranscript?.length ?? 0);
      final readerKey = arena.slice(arena.bytes(eReaderKey), eReaderKey?.length ?? 0);

      final result = bindings.verifyMdl(
        response,
        anchors,
        iacaAnchors.length,
        transcript,
        readerKey,
      );

      return VerifiedIdentity.parseResult(bindings.consumeString(result));
    } finally {
      arena.release();
      freeAnchors(anchors, anchorBuffers);
    }
  }

  /// Verify an mDL presented over OpenID4VP, from the request parameters rather than a
  /// transcript you built yourself.
  ///
  /// Two profiles are live and they encode the same session inputs differently:
  /// OpenID4VP 1.0, its Digital Credentials API variant, and the older ISO/IEC 18013-7
  /// Annex B shape with a wallet-supplied [mdocGeneratedNonce]. Every candidate your
  /// parameters support is tried, and [VerifiedIdentity.sessionProfile] reports which
  /// one the holder actually signed.
  ///
  /// That is a question about encoding, not about trust — you supplied every input, and
  /// the holder still has to have signed one of them with the device key the issuer
  /// bound into the MSO. It costs one signature check per candidate.
  ///
  /// Supply [origin] for the DC API, or [clientId] and [responseUri] for the redirect
  /// flow; [nonce] is always required and is *your* nonce, not the wallet's.
  ///
  /// [jwkThumbprint] is the 32-byte RFC 7638 SHA-256 thumbprint of the key the response
  /// was encrypted to, and `null` when it was not encrypted. The spec encodes absent as
  /// a CBOR `null`, which is a different transcript from any byte string — so an empty
  /// list is rejected rather than quietly treated as either one.
  static VerifiedIdentity verifyMdlOpenId4Vp(
    Uint8List deviceResponse, {
    required String nonce,
    List<Uint8List> iacaAnchors = const [],
    String? clientId,
    String? responseUri,
    String? mdocGeneratedNonce,
    String? origin,
    Uint8List? jwkThumbprint,
    Uint8List? eReaderKey,
  }) {
    // The ABI carries bytes as a pointer and a length, and an empty list arrives as a
    // null pointer — indistinguishable from one that was never supplied. Since this API
    // makes a point of absent and empty being different transcripts, an empty list here
    // cannot be honoured and must not be silently read as absent.
    if (jwkThumbprint != null && jwkThumbprint.isEmpty) {
      throw ArgumentError.value(
        jwkThumbprint,
        'jwkThumbprint',
        'an empty thumbprint is not the same as an absent one — pass null when the '
            'response was not encrypted',
      );
    }

    final bindings = IdentityBindings.instance;
    final arena = _Arena();
    final (anchors, anchorBuffers) = allocateAnchors(iacaAnchors);

    try {
      // Allocated through the arena for the same reason as everything else here: the
      // struct is passed by value, so Rust reads this memory during the call.
      final params = arena.openId4VpParams();
      params.ref
        ..clientId = arena.text(clientId)
        ..responseUri = arena.text(responseUri)
        ..nonce = arena.text(nonce)
        ..mdocGeneratedNonce = arena.text(mdocGeneratedNonce)
        ..origin = arena.text(origin)
        ..jwkThumbprint =
            arena.slice(arena.bytes(jwkThumbprint), jwkThumbprint?.length ?? 0);

      final result = bindings.verifyMdlOpenId4Vp(
        arena.slice(arena.bytes(deviceResponse), deviceResponse.length),
        anchors,
        iacaAnchors.length,
        params.ref,
        arena.slice(arena.bytes(eReaderKey), eReaderKey?.length ?? 0),
      );

      return VerifiedIdentity.parseResult(bindings.consumeString(result));
    } finally {
      arena.release();
      freeAnchors(anchors, anchorBuffers);
    }
  }

  /// Verify passport files read by something other than [PassportReader].
  ///
  /// Pass a null [dg2] when the photograph was not read. The result then reports the
  /// gap — `signedDataGroups` will list a group that `verifiedDataGroups` does not —
  /// rather than implying the photograph was covered.
  static VerifiedIdentity verifyPassportFiles({
    required Uint8List sod,
    required Uint8List dg1,
    Uint8List? dg2,
    Uint8List? dg15,
    List<Uint8List> cscaAnchors = const [],
  }) {
    final bindings = IdentityBindings.instance;
    final arena = _Arena();
    final (anchors, anchorBuffers) = allocateAnchors(cscaAnchors);

    try {
      final result = bindings.verifyPassport(
        arena.slice(arena.bytes(sod), sod.length),
        arena.slice(arena.bytes(dg1), dg1.length),
        arena.slice(arena.bytes(dg2), dg2?.length ?? 0),
        arena.slice(arena.bytes(dg15), dg15?.length ?? 0),
        anchors,
        cscaAnchors.length,
      );

      return VerifiedIdentity.parseResult(bindings.consumeString(result));
    } finally {
      arena.release();
      freeAnchors(anchors, anchorBuffers);
    }
  }

  /// [verifyMdl] on a worker isolate.
  ///
  /// Verification is CPU work — signature checks and digests — and on a large response
  /// it is long enough to drop frames. `PassportReader` already keeps its work off the
  /// UI isolate; these do the same for the paths that have no NFC to wait on.
  static Future<VerifiedIdentity> verifyMdlAsync(
    Uint8List deviceResponse, {
    List<Uint8List> iacaAnchors = const [],
    Uint8List? sessionTranscript,
    Uint8List? eReaderKey,
  }) =>
      Isolate.run(() => verifyMdl(
            deviceResponse,
            iacaAnchors: iacaAnchors,
            sessionTranscript: sessionTranscript,
            eReaderKey: eReaderKey,
          ));

  /// [verifyMdlOpenId4Vp] on a worker isolate.
  ///
  /// Worth preferring here: trying several candidates costs a signature check each, so
  /// this is the path most likely to be felt on the UI isolate.
  static Future<VerifiedIdentity> verifyMdlOpenId4VpAsync(
    Uint8List deviceResponse, {
    required String nonce,
    List<Uint8List> iacaAnchors = const [],
    String? clientId,
    String? responseUri,
    String? mdocGeneratedNonce,
    String? origin,
    Uint8List? jwkThumbprint,
    Uint8List? eReaderKey,
  }) =>
      Isolate.run(() => verifyMdlOpenId4Vp(
            deviceResponse,
            nonce: nonce,
            iacaAnchors: iacaAnchors,
            clientId: clientId,
            responseUri: responseUri,
            mdocGeneratedNonce: mdocGeneratedNonce,
            origin: origin,
            jwkThumbprint: jwkThumbprint,
            eReaderKey: eReaderKey,
          ));

  /// [verifyPassportFiles] on a worker isolate.
  static Future<VerifiedIdentity> verifyPassportFilesAsync({
    required Uint8List sod,
    required Uint8List dg1,
    Uint8List? dg2,
    Uint8List? dg15,
    List<Uint8List> cscaAnchors = const [],
  }) =>
      Isolate.run(() => verifyPassportFiles(
            sod: sod,
            dg1: dg1,
            dg2: dg2,
            dg15: dg15,
            cscaAnchors: cscaAnchors,
          ));
}
