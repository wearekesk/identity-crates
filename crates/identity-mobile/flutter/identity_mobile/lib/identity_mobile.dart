/// Verify ePassport chips and mobile driving licences from Flutter.
///
/// Both documents return the same [VerifiedIdentity], so an app that accepts either
/// has one result to reason about — and one place where "verified" is defined.
library;

import 'dart:ffi';
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

  /// Verify passport files read by something other than [PassportReader].
  ///
  /// Pass a null [dg2] when the photograph was not read. The result then reports the
  /// gap — `signedDataGroups` will list a group that `verifiedDataGroups` does not —
  /// rather than implying the photograph was covered.
  static VerifiedIdentity verifyPassportFiles({
    required Uint8List sod,
    required Uint8List dg1,
    Uint8List? dg2,
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
        anchors,
        cscaAnchors.length,
      );

      return VerifiedIdentity.parseResult(bindings.consumeString(result));
    } finally {
      arena.release();
      freeAnchors(anchors, anchorBuffers);
    }
  }
}
