import 'dart:convert';
import 'dart:typed_data';

/// Why a verification failed.
///
/// The distinction is the point: [nfc] and [access] are retryable and mean different
/// things to the holder, while [notAuthentic] is a stop.
enum IdentityErrorKind {
  /// The chip could not be talked to. Ask the holder to hold still and try again.
  nfc,

  /// The chip refused the access key — the document is probably fine, the key is
  /// wrong. Do not retry the same values.
  access,

  /// The bytes are not a document this library can read.
  unreadable,

  /// The data does not match what the issuer signed. Not a retry.
  notAuthentic,

  /// The presentation used `DeviceMac`, which needs the reader's ephemeral private
  /// key. The caller can fix this — the key exists, it just was not passed in.
  sessionKeyRequired,

  /// A supplied trust anchor could not be parsed.
  anchor,

  /// The signature algorithm is one this build cannot verify — a refusal to answer,
  /// never a pass.
  unsupportedAlgorithm,

  /// An error kind newer than this Dart code. Treat it as a failure.
  unknown;

  static IdentityErrorKind parse(String? value) => switch (value) {
        'nfc' => IdentityErrorKind.nfc,
        'access' => IdentityErrorKind.access,
        'unreadable' => IdentityErrorKind.unreadable,
        'notAuthentic' => IdentityErrorKind.notAuthentic,
        'sessionKeyRequired' => IdentityErrorKind.sessionKeyRequired,
        'anchor' => IdentityErrorKind.anchor,
        'unsupportedAlgorithm' => IdentityErrorKind.unsupportedAlgorithm,
        _ => IdentityErrorKind.unknown,
      };

  /// Whether trying again with the same inputs could plausibly succeed.
  bool get isRetryable => this == IdentityErrorKind.nfc;
}

/// A verification that did not succeed.
class IdentityException implements Exception {
  const IdentityException(this.kind, this.message);

  final IdentityErrorKind kind;
  final String message;

  @override
  String toString() => 'IdentityException(${kind.name}): $message';
}

/// Which document an identity came from.
enum DocumentKind { passport, mdl, unknown }

/// What was actually proven, as separate questions.
///
/// There is no single "valid" flag because there is no honest one: a genuine
/// credential from an unknown issuer and a well-formed forgery are both unusable, for
/// completely different reasons.
class Authenticity {
  const Authenticity({
    required this.dataAuthentic,
    required this.issuerTrusted,
    required this.holderBound,
    required this.notExpired,
    required this.warnings,
  });

  /// The data is what the issuer signed.
  final bool dataAuthentic;

  /// The issuer chains to a trust anchor you supplied.
  final bool issuerTrusted;

  /// The document proved it is the original rather than a copy — chip active
  /// authentication, or mDL device authentication.
  ///
  /// `null` means it was not attempted, which is **not** the same as `false`.
  final bool? holderBound;

  /// The credential is inside its own validity window.
  final bool notExpired;

  /// Worth showing in a diagnostic view, not to the holder.
  final List<String> warnings;

  /// Genuine, from an issuer you trust, in date.
  ///
  /// Excludes [holderBound] on purpose — whether you need proof of presence depends
  /// on whether the document is in front of you.
  bool get isTrustworthy => dataAuthentic && issuerTrusted && notExpired;

  /// The above, plus proof this is the original document. The in-person bar.
  bool get isPresentAndTrustworthy => isTrustworthy && holderBound == true;

  factory Authenticity.fromJson(Map<String, dynamic> json) => Authenticity(
        dataAuthentic: json['dataAuthentic'] as bool? ?? false,
        issuerTrusted: json['issuerTrusted'] as bool? ?? false,
        holderBound: json['holderBound'] as bool?,
        notExpired: json['notExpired'] as bool? ?? false,
        warnings: (json['warnings'] as List<dynamic>? ?? const [])
            .map((w) => w as String)
            .toList(growable: false),
      );
}

/// A verified person, from a passport chip or an mDL.
///
/// Every field is optional because both document types support partial data — an mDL
/// can disclose an age attestation and nothing else. Absent means "not disclosed or
/// not read", never "rejected": anything rejected arrives as an [IdentityException].
class VerifiedIdentity {
  const VerifiedIdentity({
    required this.authenticity,
    required this.documentKind,
    this.familyName,
    this.givenName,
    this.dateOfBirth,
    this.dateOfExpiry,
    this.documentNumber,
    this.nationality,
    this.sex,
    this.portrait,
    this.issuingAuthority,
    this.sessionProfile,
    this.ageAttestations = const {},
    this.verifiedDataGroups = const [],
    this.signedDataGroups = const [],
  });

  final String? familyName;
  final String? givenName;

  /// `YYYY-MM-DD`.
  final String? dateOfBirth;

  /// `YYYY-MM-DD`.
  final String? dateOfExpiry;

  final String? documentNumber;
  final String? nationality;

  /// `M`, `F`, or whatever the document recorded.
  final String? sex;

  /// The holder's photograph, as the bytes the issuer signed.
  final Uint8List? portrait;

  /// Named on an mDL; absent on a passport.
  final String? issuingAuthority;

  /// Which session transcript the holder signed, when more than one was offered —
  /// `openid4vp-1.0`, `openid4vp-dcapi`, `iso-18013-7`, `cbor`.
  ///
  /// `null` when no session was supplied and device authentication did not happen.
  /// Worth logging: after a day of real traffic this tells you what your wallets emit,
  /// and therefore which profiles you can stop offering.
  final String? sessionProfile;

  /// `age_over_NN` claims the document made. Passports carry none — they carry a date
  /// of birth and leave the arithmetic, and the disclosure, to you.
  final Map<int, bool> ageAttestations;

  /// Passport only: the data groups that were hashed and matched.
  final List<int> verifiedDataGroups;

  /// Passport only: every data group the chip signs. Anything here but not in
  /// [verifiedDataGroups] was not read, and nothing it contains is authenticated.
  final List<int> signedDataGroups;

  final Authenticity authenticity;
  final DocumentKind documentKind;

  /// An `age_over_NN` answer, if the document made that claim.
  bool? ageOver(int years) => ageAttestations[years];

  String? get displayName {
    final parts = [givenName, familyName].whereType<String>();
    return parts.isEmpty ? null : parts.join(' ');
  }

  factory VerifiedIdentity.fromJson(Map<String, dynamic> json) {
    final source = json['source'] as Map<String, dynamic>?;

    return VerifiedIdentity(
      familyName: json['familyName'] as String?,
      givenName: json['givenName'] as String?,
      dateOfBirth: json['dateOfBirth'] as String?,
      dateOfExpiry: json['dateOfExpiry'] as String?,
      documentNumber: json['documentNumber'] as String?,
      nationality: json['nationality'] as String?,
      sex: json['sex'] as String?,
      portrait: _decodeHex(json['portrait'] as String?),
      issuingAuthority: source?['issuingAuthority'] as String?,
      sessionProfile: source?['sessionProfile'] as String?,
      ageAttestations: {
        for (final claim in json['ageAttestations'] as List<dynamic>? ?? const [])
          (claim as Map<String, dynamic>)['years'] as int: claim['answer'] as bool,
      },
      verifiedDataGroups: _intList(source?['verifiedDataGroups']),
      signedDataGroups: _intList(source?['signedDataGroups']),
      authenticity:
          Authenticity.fromJson(json['authenticity'] as Map<String, dynamic>? ?? const {}),
      documentKind: switch (source?['kind']) {
        'passport' => DocumentKind.passport,
        'mdl' => DocumentKind.mdl,
        _ => DocumentKind.unknown,
      },
    );
  }

  /// Parse what the native layer returned, raising the typed error if it failed.
  static VerifiedIdentity parseResult(String payload) {
    final json = jsonDecode(payload) as Map<String, dynamic>;

    final error = json['error'] as Map<String, dynamic>?;
    if (error != null) {
      throw IdentityException(
        IdentityErrorKind.parse(error['kind'] as String?),
        error['message'] as String? ?? 'verification failed',
      );
    }

    final identity = json['identity'] as Map<String, dynamic>?;
    if (identity == null) {
      throw const IdentityException(
        IdentityErrorKind.unknown,
        'the native library returned neither an identity nor an error',
      );
    }

    return VerifiedIdentity.fromJson(identity);
  }

  static List<int> _intList(Object? value) =>
      (value as List<dynamic>? ?? const []).map((v) => v as int).toList(growable: false);

  /// The portrait crosses the boundary as hex, and has to come back as exactly the
  /// bytes the issuer signed.
  ///
  /// An odd length used to lose the trailing nibble to integer division, and a
  /// non-hex character threw from inside a getter. Neither is a shape the native side
  /// can produce, so both mean the payload is not what this code thinks it is —
  /// surfaced as a typed error rather than as quietly different bytes, which for a
  /// photograph someone is compared against is not a small difference.
  static Uint8List? _decodeHex(String? value) {
    if (value == null) return null;

    if (value.length.isOdd) {
      throw IdentityException(
        IdentityErrorKind.unknown,
        'the portrait hex had an odd length (${value.length})',
      );
    }

    final bytes = Uint8List(value.length ~/ 2);
    for (var i = 0; i < bytes.length; i++) {
      final byte = int.tryParse(value.substring(i * 2, i * 2 + 2), radix: 16);
      if (byte == null) {
        throw IdentityException(
          IdentityErrorKind.unknown,
          'the portrait hex was not hexadecimal at byte $i',
        );
      }
      bytes[i] = byte;
    }
    return bytes;
  }
}
