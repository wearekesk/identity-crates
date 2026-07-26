//! UIDAI signature verification for the **Secure QR v2** payload.
//!
//! The Secure QR blob is signed by the same UIDAI document-signer keys that sign
//! the Paperless Offline e-KYC XML (see [`crate::offline_ekyc`]), but the QR uses
//! a plain detached signature rather than XML-DSig: the last
//! [`SIGNATURE_LEN`] bytes of the **decompressed** payload are an RSASSA-PKCS1-v1_5
//! signature with SHA-256 over everything that precedes them.
//!
//! The certs are pinned public keys, not a validated chain — see the note on
//! [`crate::offline_ekyc`]'s cert list for why validity windows are deliberately
//! not enforced.

use crate::error::AadhaarError;
use crate::offline_ekyc::UIDAI_CERTS;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::signature::Verifier as _;
use rsa::RsaPublicKey;
use sha2::Sha256;

/// Size of the RSA-SHA256 signature at the tail of every Secure QR payload
/// (2048-bit UIDAI signer keys ⇒ 256 bytes).
pub const SIGNATURE_LEN: usize = 256;

/// Verifies a full decompressed Secure-QR payload: splits off the trailing
/// [`SIGNATURE_LEN`] bytes and checks them against the embedded UIDAI keys.
///
/// Returns `Ok(false)` when no pinned UIDAI key validates the signature.
pub fn verify_secure_qr_payload(decompressed: &[u8]) -> Result<bool, AadhaarError> {
    if decompressed.len() <= SIGNATURE_LEN {
        return Err(AadhaarError::PayloadTooShort {
            len: decompressed.len(),
        });
    }
    let (signed, signature) = decompressed.split_at(decompressed.len() - SIGNATURE_LEN);
    verify_uidai_rsa_sha256(signed, signature)
}

/// Verifies a detached RSASSA-PKCS1-v1_5 / SHA-256 `signature` over `signed`
/// against every embedded UIDAI signer certificate.
pub fn verify_uidai_rsa_sha256(signed: &[u8], signature: &[u8]) -> Result<bool, AadhaarError> {
    verify_with_certs(signed, signature, UIDAI_CERTS)
}

/// Core verification against an explicit cert list (the production entry points
/// pass [`UIDAI_CERTS`]; tests pass a locally generated signer).
pub(crate) fn verify_with_certs(
    signed: &[u8],
    signature: &[u8],
    certs: &[&str],
) -> Result<bool, AadhaarError> {
    let sig = Signature::try_from(signature)
        .map_err(|e| AadhaarError::Signature(format!("malformed signature: {e}")))?;
    for cert_pem in certs {
        // A cert we cannot parse is skipped rather than failing the whole check:
        // the remaining pinned keys must still get a chance to verify.
        let Ok(key) = cert_rsa_public_key(cert_pem) else {
            continue;
        };
        if VerifyingKey::<Sha256>::new(key)
            .verify(signed, &sig)
            .is_ok()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Extracts the RSA public key from an X.509 PEM certificate.
fn cert_rsa_public_key(cert_pem: &str) -> Result<RsaPublicKey, AadhaarError> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| AadhaarError::Signature(e.to_string()))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| AadhaarError::Signature(e.to_string()))?;
    RsaPublicKey::from_public_key_der(cert.public_key().raw)
        .map_err(|e| AadhaarError::Signature(e.to_string()))
}

/// A throwaway RSA signer standing in for UIDAI, so the *positive* verification
/// path can be exercised without a real Aadhaar record. Shared with the parser
/// tests, which build a full payload and sign it the way UIDAI would.
#[cfg(test)]
pub(crate) mod test_support {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey as _;
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    /// A locally generated 2048-bit signer used to exercise the *positive* path.
    /// It is a throwaway test key with no relationship to UIDAI.
    pub(crate) const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQChxL0WUENBSvs3\n\
JUIs+V8PWxHYeN+FVj4PD2/bXp3JqAaNSpJRf9QqyZaCXkjmeFDKJ9oN0vpI/YFI\n\
giujetKhtke/Dzd74qdqaeTkHdym71A6zdxj5t/+BRAsyT218AfxG2i/OQhTqi5h\n\
bZW5xixFcQcn8rvt6SFz5Mv8/RV2Q5av1VuvsKxdpHI4ujzSVgQZuI1gXnRiUJOo\n\
A9h2jxJchCr0KDoSHtmAnoLVRFTzRQrihnhNNVORl9qn5PC9mTnfa16Jlo9Vexbr\n\
OvYRM9Tr64H34Sb/zURomXbEkmW9mB7x5LDLHZwLvIoddvejC1MTdG09wHM8YRVs\n\
bNGV/Rf5AgMBAAECggEAS+pbgFK3VTdecFEsXpXCjh7DX67N2rGP2xp3+F9NNhsD\n\
xB/ITbXq+A91cgXUOVAiPdR46L7nVQSevMvVtdkIavpzbg6yj5Fc1rwOPh1jdPXe\n\
1VHRiRKKcJeosRPZwX19BKHDxOV7amP1cyRtvOpq0UXLQWyQ1APxfoVTU4zjmwU6\n\
+m5YdXfTbV/aj3LRue6ad2IC9aL/KoqEDDfz5lJP58o+CVcxbiMt7Fel8dSwy0HX\n\
hFDY6Y7tlPkvagC3BWevsiDAg0tje8NlPxhYYGgP6eI1ti9ilWyFbRXT53xKcCSZ\n\
IZahG6Rz/qmMKlZ/f1/HWYxZe2qBci3Vdq/JG7FrvwKBgQDNEBEoyVteSAMnW8A1\n\
5HRlcJw6ewb1+4sX4XAmmFnGrIBHE6w5VUr+lJOD7pDDmDpQa6QGJXl6TTCSiHJf\n\
sNy+i5M8LkymeSggsgDW6zbG9PPWeB18wHlwo7gZfWcarqrfMFvX2EP3JFoFu25M\n\
liz9bgpAb6/5WP4GiOvifvVbEwKBgQDJ85eCfQ1xbwMNA/Y3ruwTQD+ox1oPITVo\n\
V480AtsRoPkXcQ2LgPABZfKDZfL37vDRi3QeCmtC8RXCnPFuquscQF4B6y+M3Z2B\n\
N5hGjg92xODkKvUUp7j8kA1AUTOkfBRY8BZA1Jr+nJmeDNGHclcxaho6ym1PyQxi\n\
5DWG5vb2QwKBgHyYYpSxo75pauEjMmqMYNyxy3sM/XHAYQclhwssToAUl+yX23EK\n\
jgKZK/hhn7v4ZpYukP7bDjBtbjHajgPuZnGwRMmwKAqOWv9iqHftet7wPqf1W5VN\n\
LXxvPZDfTSI9Nr1dmLBRSxqDD9+jvqTyKmvhzIDSW83ZcJ9v2kNIeLPZAoGBAKz/\n\
c+G/WF28uENVCn2m5eqT1jSyGU7upr6siysF6z4NxHQ1T2Ia4P6Bo562Hc4QLNGE\n\
gcMeL8ZXmcluAlBIMEGyThWcr84fJkbEJjkChvK6MuCif/Hiv8/zYrafGPslo5SQ\n\
jq+YsPG9msbOuksqQtE80B1evQdk9axdTBE1F4fbAoGARHb2aqoRI2OC9QNh0Fte\n\
MLDU/ycWJtos/Vx+AMetUs2FE+wIysKzaSyiHXI82O5HHZhhhbAC7Z5kP1priAE8\n\
OxfpjiM0l3a1Y/FMoaaTMzic2bBjvDYoc0XsB2uzbpCub6zTAbMJKU2Ntyt/RNHE\n\
XLSl/cuSdZdJiYh2ex0SIL4=\n\
-----END PRIVATE KEY-----\n";

    /// Self-signed X.509 cert carrying [`TEST_KEY`]'s public key.
    pub(crate) const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDRTCCAi2gAwIBAgIUE0kNOgo9h5IOeh2I+E6KeZtHFuQwDQYJKoZIhvcNAQEL\n\
BQAwMjELMAkGA1UEBhMCSU4xDTALBgNVBAoMBFRFU1QxFDASBgNVBAMMC1Rlc3Qg\n\
U2lnbmVyMB4XDTI2MDcyNjA5MjQ1OFoXDTM2MDcyMzA5MjQ1OFowMjELMAkGA1UE\n\
BhMCSU4xDTALBgNVBAoMBFRFU1QxFDASBgNVBAMMC1Rlc3QgU2lnbmVyMIIBIjAN\n\
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAocS9FlBDQUr7NyVCLPlfD1sR2Hjf\n\
hVY+Dw9v216dyagGjUqSUX/UKsmWgl5I5nhQyifaDdL6SP2BSIIro3rSobZHvw83\n\
e+Knamnk5B3cpu9QOs3cY+bf/gUQLMk9tfAH8RtovzkIU6ouYW2VucYsRXEHJ/K7\n\
7ekhc+TL/P0VdkOWr9Vbr7CsXaRyOLo80lYEGbiNYF50YlCTqAPYdo8SXIQq9Cg6\n\
Eh7ZgJ6C1URU80UK4oZ4TTVTkZfap+TwvZk532teiZaPVXsW6zr2ETPU6+uB9+Em\n\
/81EaJl2xJJlvZge8eSwyx2cC7yKHXb3owtTE3RtPcBzPGEVbGzRlf0X+QIDAQAB\n\
o1MwUTAdBgNVHQ4EFgQUMIFT+rLJMBTsJHZVDgCqdk4GU2kwHwYDVR0jBBgwFoAU\n\
MIFT+rLJMBTsJHZVDgCqdk4GU2kwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n\
AQsFAAOCAQEAQjAyYkpTLYZwbQOvR2XfnY39qYf3dvH2JgBnIsfr14itYvRB2OiY\n\
UY4A4VmOA86KHr4bdH8vhnsnVtH/YMjmtAn4dKWruu0ZDy3jmXYMX0H1NxDl4DLB\n\
0ZLevGC0GUm8BKR+YbN62U6CERNf9zxqQlzcHbwC3kUHf0Hfo/sKoYhm60m8D8ie\n\
b3P5c0ffUkQBrEEMEhNUCh1f5a/dEta7pAuwXNJZrSibrnw56CC5iiDFy9+HSjzw\n\
4kBTRjOfymtvXGuE0SxLyPqOZHwUBuQMnkhJxCzh2I3IPCctTZPKXCqv53LuZFye\n\
Za+fGZQS8WJ3qLKAz45asuyySsDiRNOmcw==\n\
-----END CERTIFICATE-----\n";

    /// Signs `msg` with [`TEST_KEY`] exactly as UIDAI signs the QR blob
    /// (RSASSA-PKCS1-v1_5 over SHA-256).
    pub(crate) fn test_sign(msg: &[u8]) -> Vec<u8> {
        let key = RsaPrivateKey::from_pkcs8_pem(TEST_KEY).unwrap();
        SigningKey::<Sha256>::new(key).sign(msg).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{test_sign, TEST_CERT};
    use super::*;

    #[test]
    fn uidai_certs_yield_rsa_public_keys() {
        for pem in UIDAI_CERTS {
            let key = cert_rsa_public_key(pem).expect("UIDAI cert -> RSA public key");
            assert_eq!(rsa::traits::PublicKeyParts::size(&key), SIGNATURE_LEN);
        }
    }

    #[test]
    fn valid_signature_verifies() {
        let msg = b"aadhaar secure qr signed region";
        let sig = test_sign(msg);
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify_with_certs(msg, &sig, &[TEST_CERT]).unwrap());
    }

    #[test]
    fn tampered_message_does_not_verify() {
        let sig = test_sign(b"aadhaar secure qr signed region");
        assert!(
            !verify_with_certs(b"aadhaar secure qr signed regioN", &sig, &[TEST_CERT]).unwrap()
        );
    }

    #[test]
    fn signature_from_another_key_does_not_verify() {
        // A well-formed signature made by a key we do not trust must fail.
        let msg = b"aadhaar secure qr signed region";
        let sig = test_sign(msg);
        assert!(!verify_uidai_rsa_sha256(msg, &sig).unwrap());
    }

    #[test]
    fn unparseable_cert_is_skipped_not_fatal() {
        let msg = b"aadhaar secure qr signed region";
        let sig = test_sign(msg);
        assert!(verify_with_certs(msg, &sig, &["not a pem at all", TEST_CERT]).unwrap());
    }

    #[test]
    fn payload_shorter_than_signature_is_rejected() {
        assert!(matches!(
            verify_secure_qr_payload(&[0u8; 100]),
            Err(AadhaarError::PayloadTooShort { len: 100 })
        ));
    }

    #[test]
    fn payload_split_covers_everything_before_the_signature() {
        // verify_secure_qr_payload must sign-check the *whole* prefix, so a
        // payload built as `signed || sig` verifies under the same key.
        let signed = vec![0xABu8; 512];
        let sig = test_sign(&signed);
        let mut payload = signed.clone();
        payload.extend_from_slice(&sig);
        let (prefix, tail) = payload.split_at(payload.len() - SIGNATURE_LEN);
        assert_eq!(prefix, &signed[..]);
        assert!(verify_with_certs(prefix, tail, &[TEST_CERT]).unwrap());
    }
}
