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
      portrait: _decodeHex(json['portrait'] as String?, 'portrait'),
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
  static VerifiedIdentity parseResult(String payload) =>
      VerifiedIdentity.fromJson(_envelope(payload)['identity'] as Map<String, dynamic>);

  static List<int> _intList(Object? value) =>
      (value as List<dynamic>? ?? const []).map((v) => v as int).toList(growable: false);
}

/// The elementary files a read produced, when `PassportReader.retainDataGroups` asked
/// for them.
///
/// This is the input side of `IdentityMobile.verifyPassportFiles`, deliberately: the
/// case these exist for is a device that reads the chip and a server that does the
/// authoritative verification, and the server should be able to run exactly the check
/// this device ran. Send these bytes rather than the verdict — a phone grading its own
/// document is worth less than a server proving it.
///
/// **Lifetime.** These are ordinary Dart [Uint8List]s, copied out of the native result
/// before it was freed. You own them, the garbage collector reclaims them when you drop
/// the last reference, and nothing native is still pointing at them. There is nothing to
/// release by hand.
///
/// They are also the holder's MRZ and photograph. Retention is opt-in for that reason;
/// what happens to them after this point is yours to decide.
class PassportDataGroups {
  const PassportDataGroups({
    required this.sod,
    required this.dg1,
    this.dg2,
    this.dg15,
  });

  /// EF.SOD — the issuer's signature over the data group hashes. Never absent: a read
  /// that could not obtain it fails rather than returning.
  final Uint8List sod;

  /// EF.DG1 — the MRZ, and therefore the identity. Never absent, for the same reason.
  final Uint8List dg1;

  /// EF.DG2 — the photograph. `null` when `readPortrait` was false or the chip had none.
  final Uint8List? dg2;

  /// EF.DG15 — the active-authentication public key. `null` when the document does not
  /// carry one, or the read did not ask for it.
  final Uint8List? dg15;

  factory PassportDataGroups.fromJson(Map<String, dynamic> json) {
    final sod = _decodeHex(json['sod'] as String?, 'EF.SOD');
    final dg1 = _decodeHex(json['dg1'] as String?, 'EF.DG1');

    // A read cannot succeed without these two, so their absence means the payload is not
    // what this code thinks it is — which is a broken contract, not a partial read.
    if (sod == null || dg1 == null) {
      throw const IdentityException(
        IdentityErrorKind.unknown,
        'the native library retained data groups without EF.SOD or EF.DG1',
      );
    }

    return PassportDataGroups(
      sod: sod,
      dg1: dg1,
      dg2: _decodeHex(json['dg2'] as String?, 'EF.DG2'),
      dg15: _decodeHex(json['dg15'] as String?, 'EF.DG15'),
    );
  }
}

/// What a read produced: the verdict, and — only if asked for — the bytes behind it.
class PassportRead {
  const PassportRead({required this.identity, this.dataGroups});

  /// The verified identity. This is what most callers want, and all they need.
  final VerifiedIdentity identity;

  /// The elementary files, when `PassportReader.retainDataGroups` was set. `null`
  /// otherwise — nothing was kept, as opposed to nothing being there.
  final PassportDataGroups? dataGroups;

  /// Parse what the native layer returned, raising the typed error if it failed.
  static PassportRead parseResult(String payload) {
    final json = _envelope(payload);
    final groups = json['dataGroups'] as Map<String, dynamic>?;

    return PassportRead(
      identity: VerifiedIdentity.fromJson(json['identity'] as Map<String, dynamic>),
      dataGroups: groups == null ? null : PassportDataGroups.fromJson(groups),
    );
  }
}

/// Decode a native result, raising the typed error if it carried one.
///
/// Errors arrive as `{"error": {...}}` rather than a null pointer, so a refusal to
/// verify never looks like a crash — and is never mistaken for a result.
Map<String, dynamic> _envelope(String payload) {
  final json = jsonDecode(payload) as Map<String, dynamic>;

  final error = json['error'] as Map<String, dynamic>?;
  if (error != null) {
    throw IdentityException(
      IdentityErrorKind.parse(error['kind'] as String?),
      error['message'] as String? ?? 'verification failed',
    );
  }

  if (json['identity'] is! Map<String, dynamic>) {
    throw const IdentityException(
      IdentityErrorKind.unknown,
      'the native library returned neither an identity nor an error',
    );
  }

  return json;
}

/// Bytes cross the boundary as hex, and have to come back as exactly what the issuer
/// signed.
///
/// An odd length used to lose the trailing nibble to integer division, and a non-hex
/// character threw from inside a getter. Neither is a shape the native side can produce,
/// so both mean the payload is not what this code thinks it is — surfaced as a typed
/// error rather than as quietly different bytes, which for a photograph someone is
/// compared against, or a security object about to be re-verified, is not a small
/// difference.
Uint8List? _decodeHex(String? value, String what) {
  if (value == null) return null;

  if (value.length.isOdd) {
    throw IdentityException(
      IdentityErrorKind.unknown,
      'the $what hex had an odd length (${value.length})',
    );
  }

  final bytes = Uint8List(value.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    final byte = int.tryParse(value.substring(i * 2, i * 2 + 2), radix: 16);
    if (byte == null) {
      throw IdentityException(
        IdentityErrorKind.unknown,
        'the $what hex was not hexadecimal at byte $i',
      );
    }
    bytes[i] = byte;
  }
  return bytes;
}
