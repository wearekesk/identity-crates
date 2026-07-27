import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// Copy anchors into native memory. Returns the array and the buffers behind it, both
/// of which must go to [freeAnchors].
(Pointer<NativeBytes>, List<Pointer<Uint8>>) allocateAnchors(List<Uint8List> anchors) {
  if (anchors.isEmpty) {
    return (nullptr, const []);
  }

  final array = calloc<NativeBytes>(anchors.length);
  final buffers = <Pointer<Uint8>>[];

  for (var i = 0; i < anchors.length; i++) {
    final anchor = anchors[i];
    final buffer = calloc<Uint8>(anchor.length);
    buffer.asTypedList(anchor.length).setAll(0, anchor);
    buffers.add(buffer);

    array[i]
      ..ptr = buffer
      ..len = anchor.length;
  }

  return (array, buffers);
}

void freeAnchors(Pointer<NativeBytes> array, List<Pointer<Uint8>> buffers) {
  for (final buffer in buffers) {
    calloc.free(buffer);
  }
  if (array != nullptr) {
    calloc.free(array);
  }
}

/// A borrowed byte slice, matching `identity_mobile::ffi::Bytes`.
final class NativeBytes extends Struct {
  external Pointer<Uint8> ptr;

  @Size()
  external int len;
}

typedef TransceiveNative = Int32 Function(
  Pointer<Void> context,
  Pointer<Uint8> apdu,
  Size apduLen,
  Pointer<Uint8> response,
  Size responseCapacity,
);

/// How the host sends one APDU to the chip. Returns the number of bytes written, or a
/// negative value if the exchange failed.
typedef TransceiveCallback = int Function(
  Pointer<Void> context,
  Pointer<Uint8> apdu,
  int apduLen,
  Pointer<Uint8> response,
  int responseCapacity,
);

/// How Rust announces an APDU that needs answering, matching
/// `identity_mobile::ffi::PostApduFn`.
typedef PostApduNative = Void Function(
  Pointer<Void> context,
  Uint64 exchangeId,
  Pointer<Uint8> apdu,
  Size apduLen,
);

typedef FreeApduNative = Void Function(Pointer<Uint8> apdu, Size len);
typedef FreeApdu = void Function(Pointer<Uint8> apdu, int len);

typedef ReadPassportAsyncNative = Pointer<Utf8> Function(
  Pointer<Utf8> documentNumber,
  Pointer<Utf8> dateOfBirth,
  Pointer<Utf8> dateOfExpiry,
  Pointer<NativeBytes> anchors,
  Size anchorCount,
  Bool readPortrait,
  Bool activeAuthentication,
  Pointer<NativeFunction<PostApduNative>> post,
  Pointer<Void> context,
);
typedef ReadPassportAsync = Pointer<Utf8> Function(
  Pointer<Utf8> documentNumber,
  Pointer<Utf8> dateOfBirth,
  Pointer<Utf8> dateOfExpiry,
  Pointer<NativeBytes> anchors,
  int anchorCount,
  bool readPortrait,
  bool activeAuthentication,
  Pointer<NativeFunction<PostApduNative>> post,
  Pointer<Void> context,
);

typedef SupplyApduNative = Bool Function(
    Uint64 exchangeId, Pointer<Uint8> response, Size responseLen, Bool ok);
typedef SupplyApdu = bool Function(
    int exchangeId, Pointer<Uint8> response, int responseLen, bool ok);

typedef VerifyMdlNative = Pointer<Utf8> Function(
  NativeBytes deviceResponse,
  Pointer<NativeBytes> anchors,
  Size anchorCount,
  NativeBytes sessionTranscript,
  NativeBytes eReaderKey,
);
typedef VerifyMdl = Pointer<Utf8> Function(
  NativeBytes deviceResponse,
  Pointer<NativeBytes> anchors,
  int anchorCount,
  NativeBytes sessionTranscript,
  NativeBytes eReaderKey,
);

typedef VerifyPassportNative = Pointer<Utf8> Function(
    NativeBytes sod,
    NativeBytes dg1,
    NativeBytes dg2,
    NativeBytes dg15,
    Pointer<NativeBytes> anchors,
    Size anchorCount);
typedef VerifyPassport = Pointer<Utf8> Function(
    NativeBytes sod,
    NativeBytes dg1,
    NativeBytes dg2,
    NativeBytes dg15,
    Pointer<NativeBytes> anchors,
    int anchorCount);

typedef ReadPassportNative = Pointer<Utf8> Function(
  Pointer<Utf8> documentNumber,
  Pointer<Utf8> dateOfBirth,
  Pointer<Utf8> dateOfExpiry,
  Pointer<NativeBytes> anchors,
  Size anchorCount,
  Bool readPortrait,
  Bool activeAuthentication,
  Pointer<NativeFunction<TransceiveNative>> transceive,
  Pointer<Void> context,
);
typedef ReadPassport = Pointer<Utf8> Function(
  Pointer<Utf8> documentNumber,
  Pointer<Utf8> dateOfBirth,
  Pointer<Utf8> dateOfExpiry,
  Pointer<NativeBytes> anchors,
  int anchorCount,
  bool readPortrait,
  bool activeAuthentication,
  Pointer<NativeFunction<TransceiveNative>> transceive,
  Pointer<Void> context,
);

typedef StringFreeNative = Void Function(Pointer<Utf8> value);
typedef StringFree = void Function(Pointer<Utf8> value);

/// The Rust library, resolved once.
class IdentityBindings {
  IdentityBindings._(DynamicLibrary library)
      : verifyMdl =
            library.lookupFunction<VerifyMdlNative, VerifyMdl>('identity_mobile_verify_mdl'),
        verifyPassport = library.lookupFunction<VerifyPassportNative, VerifyPassport>(
            'identity_mobile_verify_passport'),
        readPassport = library.lookupFunction<ReadPassportNative, ReadPassport>(
            'identity_mobile_read_passport'),
        readPassportAsync =
            library.lookupFunction<ReadPassportAsyncNative, ReadPassportAsync>(
                'identity_mobile_read_passport_async'),
        supplyApdu = library
            .lookupFunction<SupplyApduNative, SupplyApdu>('identity_mobile_supply_apdu'),
        freeApdu =
            library.lookupFunction<FreeApduNative, FreeApdu>('identity_mobile_free_apdu'),
        stringFree = library
            .lookupFunction<StringFreeNative, StringFree>('identity_mobile_string_free');

  static IdentityBindings? _instance;

  final VerifyMdl verifyMdl;
  final VerifyPassport verifyPassport;
  final ReadPassport readPassport;
  final ReadPassportAsync readPassportAsync;
  final SupplyApdu supplyApdu;
  final FreeApdu freeApdu;
  final StringFree stringFree;

  static IdentityBindings get instance => _instance ??= IdentityBindings._(_open());

  static DynamicLibrary _open() {
    // Android and iOS are the supported platforms. macOS and Linux resolve the same
    // way as their mobile counterparts, which costs nothing and makes a desktop test
    // harness possible; Windows is not supported and says so rather than failing at
    // link time.
    //
    // On iOS the static library is linked into the application binary, so the symbols
    // are already in the process — there is no separate library to open. On Android
    // the .so ships in jniLibs and is loaded by name.
    if (Platform.isIOS || Platform.isMacOS) {
      return DynamicLibrary.process();
    }
    if (Platform.isAndroid || Platform.isLinux) {
      return DynamicLibrary.open('libidentity_mobile.so');
    }
    throw UnsupportedError('identity_mobile does not support ${Platform.operatingSystem}');
  }

  /// Call a native function that returns an owned string, and always release it.
  ///
  /// Every entry point in the Rust ABI returns memory the caller owns. Forgetting the
  /// free is a leak per scan, which on a kiosk running all day is not a small one, so
  /// no call site is allowed to do this by hand.
  String consumeString(Pointer<Utf8> result) {
    if (result == nullptr) {
      throw StateError('the native library returned no result');
    }
    try {
      return result.toDartString();
    } finally {
      stringFree(result);
    }
  }
}
