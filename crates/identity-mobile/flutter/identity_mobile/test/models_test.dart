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

  /// The nonce is the whole of the session binding. An empty one builds a valid
  /// transcript that binds the response to nothing at all, and every presentation ever
  /// signed against an empty nonce would verify against it — reported as holder-bound.
  test('an empty nonce is refused', () {
    expect(
      () => IdentityMobile.verifyMdlOpenId4Vp(
        Uint8List.fromList([0x00]),
        nonce: '',
        origin: 'verifier.example',
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  /// An empty list reaches the ABI as a null pointer, so this would silently become an
  /// issuer-only verification — dropping the very check the caller passed a transcript
  /// to get.
  test('an empty session transcript is refused rather than downgraded', () {
    expect(
      () => IdentityMobile.verifyMdl(
        Uint8List.fromList([0x00]),
        sessionTranscript: Uint8List(0),
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  group('a malformed portrait is an error, not different bytes', () {
    String payloadWithPortrait(String hex) => jsonEncode({
          'identity': {
            'portrait': hex,
            'authenticity': {
              'dataAuthentic': true,
              'issuerTrusted': true,
              'notExpired': true,
              'warnings': <String>[],
            },
          },
        });

    test('an odd length does not lose its last nibble', () {
      expect(
        () => VerifiedIdentity.parseResult(payloadWithPortrait('ffd8ff0')),
        throwsA(isA<IdentityException>()),
      );
    });

    test('a non-hex character does not decode', () {
      expect(
        () => VerifiedIdentity.parseResult(payloadWithPortrait('ffd8zz')),
        throwsA(isA<IdentityException>()),
      );
    });
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

  group('retained data groups', () {
    /// A reader payload with the envelope `identity_mobile_read_passport_async` emits.
    String readPayload(Object? dataGroups) {
      final json = jsonDecode(_passportPayload()) as Map<String, dynamic>;
      json['dataGroups'] = dataGroups;
      return jsonEncode(json);
    }

    test('the bytes survive the call, beside the identity', () {
      final result = PassportRead.parseResult(readPayload({
        'sod': '3082aa',
        'dg1': '615b',
        'dg2': 'ffd8ffe0',
        'dg15': null,
      }));

      // The verdict is unchanged by asking for the bytes.
      expect(result.identity.displayName, 'PRIYA SHARMA');
      expect(result.identity.authenticity.isTrustworthy, isTrue);

      final groups = result.dataGroups!;
      expect(groups.sod, [0x30, 0x82, 0xAA]);
      expect(groups.dg1, [0x61, 0x5B]);
      expect(groups.dg2, [0xFF, 0xD8, 0xFF, 0xE0]);
      // Absent because the document does not carry one — not because it was empty.
      expect(groups.dg15, isNull);
    });

    /// The default, and the one that matters: nothing retained reads as nothing
    /// retained, rather than as an empty set of files.
    test('a read that did not ask for them reports none', () {
      final result = PassportRead.parseResult(readPayload(null));

      expect(result.dataGroups, isNull);
      expect(result.identity.familyName, 'SHARMA');
    });

    /// A read cannot succeed without EF.SOD and EF.DG1, so a payload missing either is a
    /// broken contract rather than a partial read — and must not arrive as empty bytes
    /// that something downstream would try to verify.
    test('data groups without EF.SOD are refused', () {
      expect(
        () => PassportRead.parseResult(readPayload({'dg1': '615b'})),
        throwsA(isA<IdentityException>()),
      );
    });

    test('a malformed EF.SOD hex names the file it could not decode', () {
      expect(
        () => PassportRead.parseResult(readPayload({'sod': '308', 'dg1': '615b'})),
        throwsA(isA<IdentityException>()
            .having((e) => e.message, 'message', contains('EF.SOD'))),
      );
    });

    /// Errors have to reach this path too — a failed read must not look like a read with
    /// nothing retained.
    test('an error still arrives typed', () {
      final payload = jsonEncode({
        'error': {'kind': 'nfc', 'message': 'the chip stopped responding'},
      });

      expect(
        () => PassportRead.parseResult(payload),
        throwsA(isA<IdentityException>()
            .having((e) => e.kind, 'kind', IdentityErrorKind.nfc)),
      );
    });
  });
}
