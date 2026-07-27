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

    final response = calloc<Uint8>(deviceResponse.length);
    final transcript = _copy(sessionTranscript);
    final readerKey = _copy(eReaderKey);
    final (anchors, buffers) = allocateAnchors(iacaAnchors);

    try {
      response.asTypedList(deviceResponse.length).setAll(0, deviceResponse);

      final result = bindings.verifyMdl(
        _bytes(response, deviceResponse.length),
        anchors,
        iacaAnchors.length,
        _bytes(transcript, sessionTranscript?.length ?? 0),
        _bytes(readerKey, eReaderKey?.length ?? 0),
      );

      return VerifiedIdentity.parseResult(bindings.consumeString(result));
    } finally {
      calloc.free(response);
      if (transcript != nullptr) calloc.free(transcript);
      if (readerKey != nullptr) calloc.free(readerKey);
      freeAnchors(anchors, buffers);
    }
  }

  /// Copy an optional byte list into native memory, or null for absent.
  static Pointer<Uint8> _copy(Uint8List? bytes) {
    if (bytes == null || bytes.isEmpty) return nullptr;

    final buffer = calloc<Uint8>(bytes.length);
    buffer.asTypedList(bytes.length).setAll(0, bytes);
    return buffer;
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

    final sodBuffer = calloc<Uint8>(sod.length);
    final dg1Buffer = calloc<Uint8>(dg1.length);
    final dg2Buffer = dg2 == null ? nullptr : calloc<Uint8>(dg2.length);
    final (anchors, buffers) = allocateAnchors(cscaAnchors);

    try {
      sodBuffer.asTypedList(sod.length).setAll(0, sod);
      dg1Buffer.asTypedList(dg1.length).setAll(0, dg1);
      if (dg2 != null) {
        dg2Buffer.cast<Uint8>().asTypedList(dg2.length).setAll(0, dg2);
      }

      final result = bindings.verifyPassport(
        _bytes(sodBuffer, sod.length),
        _bytes(dg1Buffer, dg1.length),
        _bytes(dg2Buffer.cast<Uint8>(), dg2?.length ?? 0),
        anchors,
        cscaAnchors.length,
      );

      return VerifiedIdentity.parseResult(bindings.consumeString(result));
    } finally {
      calloc.free(sodBuffer);
      calloc.free(dg1Buffer);
      if (dg2Buffer != nullptr) {
        calloc.free(dg2Buffer);
      }
      freeAnchors(anchors, buffers);
    }
  }

  static NativeBytes _bytes(Pointer<Uint8> ptr, int len) {
    final bytes = calloc<NativeBytes>();
    bytes.ref
      ..ptr = ptr
      ..len = len;
    // Structs pass by value, so the allocation is only needed to build one. Reading it
    // out immediately and freeing keeps this from leaking a struct per call.
    final value = bytes.ref;
    calloc.free(bytes);
    return value;
  }
}
