import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_nfc_kit/flutter_nfc_kit.dart';

import 'bindings.dart';
import 'models.dart';

/// How long one APDU may take before the exchange is called lost.
///
/// Stated rather than left to `flutter_nfc_kit`'s default, because the failure path
/// below depends on it: the Rust bridge waits 30 s for an answer, so this has to expire
/// far enough inside that window for a moved phone to surface as an error while the
/// holder is still holding it. A single exchange is milliseconds of chip time; anything
/// approaching five seconds is a tag that has gone away.
const Duration _apduTimeout = Duration(seconds: 5);

/// The key printed on the document, which unlocks the chip.
///
/// Nothing here is secret — it is all on the page — but the chip will not talk without
/// proof you have physically seen it.
class DBAKey {
  const DBAKey(this.documentNumber, this.dateOfBirth, this.dateOfExpiry);

  final String documentNumber;
  final DateTime dateOfBirth;
  final DateTime dateOfExpiry;

  String get _birth => _iso(dateOfBirth);
  String get _expiry => _iso(dateOfExpiry);

  static String _iso(DateTime date) =>
      '${date.year.toString().padLeft(4, '0')}-'
      '${date.month.toString().padLeft(2, '0')}-'
      '${date.day.toString().padLeft(2, '0')}';
}

/// Reads and verifies an ePassport chip over NFC.
///
/// ```dart
/// final reader = PassportReader(cscaAnchors: anchors);
/// final identity = await reader.read(
///   DBAKey('123456789', DateTime(1988, 3, 14), DateTime(2030, 1, 1)),
/// );
/// ```
///
/// The whole read happens inside one NFC session. `flutter_nfc_kit` polls for the tag,
/// and each APDU is exchanged as the protocol asks for it — the protocol itself runs in
/// Rust, on a worker isolate, so the main isolate stays free to service the exchanges.
class PassportReader {
  PassportReader({
    this.cscaAnchors = const [],
    this.readPortrait = true,
    this.activeAuthentication = true,
    this.iosAlertMessage = 'Hold your phone near the passport',
  });

  /// DER-encoded CSCA certificates from the ICAO masterlist.
  ///
  /// Empty is allowed: the data is still checked against the chip's own signature, and
  /// [Authenticity.issuerTrusted] comes back false because nothing attributes it to a
  /// country.
  final List<Uint8List> cscaAnchors;

  /// Read DG2, the photograph. The largest file on the chip by a wide margin, so
  /// leaving it out makes a read noticeably faster.
  final bool readPortrait;

  /// Prove the chip is not a clone. One extra round trip, and only possible on
  /// documents carrying DG15.
  final bool activeAuthentication;

  final String iosAlertMessage;

  /// Poll for a passport, read it, and verify it.
  ///
  /// Throws [IdentityException]; check `kind` before deciding whether to retry.
  Future<VerifiedIdentity> read(DBAKey key) async {
    await FlutterNfcKit.poll(
      iosAlertMessage: iosAlertMessage,
      readIso14443A: true,
      readIso14443B: true,
      readIso18092: false,
      readIso15693: false,
    );

    try {
      return await _readInSession(key);
    } finally {
      // Always close the session, or iOS leaves the sheet up and Android holds the
      // tag until it is torn away.
      await FlutterNfcKit.finish(iosAlertMessage: 'Done');
    }
  }

  Future<VerifiedIdentity> _readInSession(DBAKey key) async {
    final bindings = IdentityBindings.instance;

    // Exchanges arrive here from the worker isolate. `NativeCallable.listener` is what
    // makes that legal: the Rust thread posts, this isolate answers, and neither
    // blocks the other.
    final exchanges = ReceivePort();

    final callable = NativeCallable<PostApduNative>.listener(
      (Pointer<Void> _, int exchangeId, Pointer<Uint8> apdu, int apduLen) {
        // Rust hands the buffer over rather than lending it, precisely because this
        // callback runs later than the call that posted it — copy, then release.
        final bytes = Uint8List.fromList(apdu.asTypedList(apduLen));
        bindings.freeApdu(apdu, apduLen);
        exchanges.sendPort.send([exchangeId, bytes]);
      },
    );

    final subscription = exchanges.listen((Object? message) async {
      final exchange = message! as List<Object?>;
      await _answer(bindings, exchange[0]! as int, exchange[1]! as Uint8List);
    });

    try {
      // The read blocks for its whole duration, so it runs off the main isolate.
      // Everything it needs is a plain integer or a byte list, which is what makes it
      // sendable in the first place.
      final payload = await Isolate.run(() => _runRead(
            key: key,
            anchors: cscaAnchors,
            readPortrait: readPortrait,
            activeAuthentication: activeAuthentication,
            post: callable.nativeFunction.address,
          ));

      return VerifiedIdentity.parseResult(payload);
    } finally {
      await subscription.cancel();
      exchanges.close();
      callable.close();
    }
  }

  /// Do one exchange with the chip and hand the answer back to Rust.
  static Future<void> _answer(
    IdentityBindings bindings,
    int exchangeId,
    Uint8List apdu,
  ) async {
    try {
      final response = await FlutterNfcKit.transceive<Uint8List>(
        apdu,
        timeout: _apduTimeout,
      );
      final buffer = calloc<Uint8>(response.length);
      try {
        buffer.asTypedList(response.length).setAll(0, response);
        bindings.supplyApdu(exchangeId, buffer, response.length, true);
      } finally {
        calloc.free(buffer);
      }
    } catch (_) {
      // Tell Rust the exchange failed rather than letting it wait out the timeout —
      // a lost tag should surface as an error in a second, not in thirty.
      bindings.supplyApdu(exchangeId, nullptr, 0, false);
    }
  }

  /// Runs on the worker isolate.
  static String _runRead({
    required DBAKey key,
    required List<Uint8List> anchors,
    required bool readPortrait,
    required bool activeAuthentication,
    required int post,
  }) {
    final bindings = IdentityBindings.instance;

    final number = key.documentNumber.toNativeUtf8();
    final birth = key._birth.toNativeUtf8();
    final expiry = key._expiry.toNativeUtf8();
    final (anchorArray, anchorBuffers) = allocateAnchors(anchors);

    try {
      final result = bindings.readPassportAsync(
        number,
        birth,
        expiry,
        anchorArray,
        anchors.length,
        readPortrait,
        activeAuthentication,
        Pointer<NativeFunction<PostApduNative>>.fromAddress(post),
        nullptr,
      );
      return bindings.consumeString(result);
    } finally {
      calloc.free(number);
      calloc.free(birth);
      calloc.free(expiry);
      freeAnchors(anchorArray, anchorBuffers);
    }
  }
}
