import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:identity_mobile/identity_mobile.dart';

/// These run without the native library: they cover the boundary contract — what Rust
/// emits and what Dart makes of it — which is where a mismatch would otherwise show up
/// only on a device, holding a passport.

String _passportPayload({
  bool dataAuthentic = true,
  bool issuerTrusted = true,
  bool? holderBound,
  bool notExpired = true,
  List<String> warnings = const [],
}) =>
    jsonEncode({
      'identity': {
        'familyName': 'SHARMA',
        'givenName': 'PRIYA',
        'dateOfBirth': '1988-03-14',
        'dateOfExpiry': '2030-01-01',
        'documentNumber': '123456789',
        'nationality': 'GBR',
        'sex': 'F',
        'portrait': 'ffd8ffe000',
        'ageAttestations': <Object>[],
        'source': {
          'kind': 'passport',
          'documentCode': 'P',
          'issuingState': 'GBR',
          'verifiedDataGroups': [1, 2],
          'signedDataGroups': [1, 2],
        },
        'authenticity': {
          'dataAuthentic': dataAuthentic,
          'issuerTrusted': issuerTrusted,
          'holderBound': holderBound,
          'notExpired': notExpired,
          'warnings': warnings,
        },
      },
    });

void main() {
  test('a passport result parses into the shared shape', () {
    final identity = VerifiedIdentity.parseResult(_passportPayload());

    expect(identity.familyName, 'SHARMA');
    expect(identity.displayName, 'PRIYA SHARMA');
    expect(identity.documentKind, DocumentKind.passport);
    expect(identity.verifiedDataGroups, [1, 2]);
    // The portrait crosses as hex and has to come back as the signed bytes.
    expect(identity.portrait, [0xFF, 0xD8, 0xFF, 0xE0, 0x00]);
    expect(identity.authenticity.isTrustworthy, isTrue);
  });

  test('an mDL result parses into the same shape', () {
    final payload = jsonEncode({
      'identity': {
        'familyName': 'Sharma',
        'givenName': 'Priya',
        'dateOfBirth': null,
        'portrait': null,
        'ageAttestations': [
          {'years': 21, 'answer': true},
          {'years': 25, 'answer': false},
        ],
        'source': {
          'kind': 'mdl',
          'docType': 'org.iso.18013.5.1.mDL',
          'issuingAuthority': 'NY DMV',
          'sessionProfile': 'openid4vp-1.0',
        },
        'authenticity': {
          'dataAuthentic': true,
          'issuerTrusted': true,
          'holderBound': true,
          'notExpired': true,
          'warnings': <String>[],
        },
      },
    });

    final identity = VerifiedIdentity.parseResult(payload);

    expect(identity.documentKind, DocumentKind.mdl);
    expect(identity.issuingAuthority, 'NY DMV');
    // Which of the offered transcripts the holder actually signed. Reported by name
    // rather than by index, because this is what a deployment reads back to learn what
    // its wallets emit.
    expect(identity.sessionProfile, 'openid4vp-1.0');
    // The mDL's reason for existing: the answer with no date of birth attached.
    expect(identity.ageOver(21), isTrue);
    expect(identity.ageOver(25), isFalse);
    expect(identity.ageOver(65), isNull);
    expect(identity.dateOfBirth, isNull);
  });

  /// The ABI cannot carry "present but empty" — an empty list reaches Rust as a null
  /// pointer. Since absent and present are different transcripts, the ambiguity has to
  /// be refused at this edge rather than resolved by guessing.
  ///
  /// Testable without the native library because the check runs before the library is
  /// opened, which is also why it is a good place for it.
  test('an empty thumbprint is refused rather than read as absent', () {
    expect(
      () => IdentityMobile.verifyMdlOpenId4Vp(
        Uint8List.fromList([0x00]),
        nonce: 'nonce-1',
        origin: 'verifier.example',
        jwkThumbprint: Uint8List(0),
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('an mDL verified without a session reports no profile', () {
    final payload = jsonEncode({
      'identity': {
        'source': {
          'kind': 'mdl',
          'docType': 'org.iso.18013.5.1.mDL',
          'issuingAuthority': 'NY DMV',
          'sessionProfile': null,
        },
        'authenticity': {
          'dataAuthentic': true,
          'issuerTrusted': true,
          'holderBound': null,
          'notExpired': true,
          'warnings': <String>[],
        },
      },
    });

    final identity = VerifiedIdentity.parseResult(payload);

    // No session was offered, so nothing was matched. That has to read as absent rather
    // than as a profile name nobody chose.
    expect(identity.sessionProfile, isNull);
    expect(identity.authenticity.holderBound, isNull);
  });

  group('holderBound is three-valued, and has to stay that way', () {
    test('null means not attempted, which is not a failure', () {
      final identity = VerifiedIdentity.parseResult(_passportPayload());

      expect(identity.authenticity.holderBound, isNull);
      expect(identity.authenticity.isTrustworthy, isTrue);
      // ...but it is not proof the document is the original.
      expect(identity.authenticity.isPresentAndTrustworthy, isFalse);
    });

    test('true is the only thing that clears the in-person bar', () {
      final identity = VerifiedIdentity.parseResult(_passportPayload(holderBound: true));

      expect(identity.authenticity.isPresentAndTrustworthy, isTrue);
    });

    test('false fails it', () {
      final identity = VerifiedIdentity.parseResult(_passportPayload(holderBound: false));

      expect(identity.authenticity.isPresentAndTrustworthy, isFalse);
    });
  });

  test('an untrusted issuer is not trustworthy even with authentic data', () {
    final identity = VerifiedIdentity.parseResult(_passportPayload(issuerTrusted: false));

    expect(identity.authenticity.dataAuthentic, isTrue);
    expect(identity.authenticity.isTrustworthy, isFalse);
  });

  test('an expired document is not trustworthy', () {
    final identity = VerifiedIdentity.parseResult(_passportPayload(notExpired: false));

    expect(identity.authenticity.isTrustworthy, isFalse);
  });

  group('errors arrive typed', () {
    test('a tampered document is not retryable', () {
      final payload = jsonEncode({
        'error': {'kind': 'notAuthentic', 'message': 'DG1 does not match EF.SOD'},
      });

      expect(
        () => VerifiedIdentity.parseResult(payload),
        throwsA(isA<IdentityException>()
            .having((e) => e.kind, 'kind', IdentityErrorKind.notAuthentic)
            .having((e) => e.kind.isRetryable, 'isRetryable', isFalse)),
      );
    });

    test('a lost tag is retryable, a wrong key is not', () {
      expect(IdentityErrorKind.nfc.isRetryable, isTrue);
      // Retrying the same wrong document number forever helps nobody.
      expect(IdentityErrorKind.access.isRetryable, isFalse);
    });

    test('an unfamiliar kind degrades to unknown rather than throwing', () {
      final payload = jsonEncode({
        'error': {'kind': 'somethingNewerThanThisCode', 'message': 'x'},
      });

      expect(
        () => VerifiedIdentity.parseResult(payload),
        throwsA(isA<IdentityException>()
            .having((e) => e.kind, 'kind', IdentityErrorKind.unknown)),
      );
    });
  });

  test('a payload with neither identity nor error is an error, not a null', () {
    expect(
      () => VerifiedIdentity.parseResult('{}'),
      throwsA(isA<IdentityException>()),
    );
  });

  test('warnings survive to the caller', () {
    final identity = VerifiedIdentity.parseResult(
      _passportPayload(warnings: ['the chip signs data groups [3] that were not read']),
    );

    expect(identity.authenticity.warnings, hasLength(1));
    expect(identity.authenticity.warnings.first, contains('not read'));
  });
}
