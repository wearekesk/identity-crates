#!/usr/bin/env bash
# Regenerate the test PKI: an IACA root and the Document Signer it issues, both
# conforming to the ISO/IEC 18013-5 Annex B certificate profiles (Tables B.2 / B.4)
# so that chain validation has something real to succeed against.
#
# The DS certificate is deliberately short-lived (Annex B caps it at 457 days), so
# the tests pin their verification time with `VerifyOptions::at` rather than using
# "now" — that keeps the committed fixtures valid forever.
#
# Requires OpenSSL 3.x (LibreSSL, which macOS ships as /usr/bin/openssl on older
# releases, does not handle these extension directives the same way).
#
#   ./generate.sh   # from this directory
set -euo pipefail

cd "$(dirname "$0")"

COUNTRY="US"
STATE="New York"
IAN="URI:https://mdl-verify.invalid/iaca"
CRL="URI:https://mdl-verify.invalid/crl"

cat > openssl.cnf <<EOF
[iaca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
issuerAltName = ${IAN}
crlDistributionPoints = ${CRL}

[ds]
keyUsage = critical, digitalSignature
# id-mdl-ds: the mDL document signer EKU from 18013-5 Annex B.
extendedKeyUsage = critical, 1.0.18013.5.1.2
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
issuerAltName = ${IAN}
crlDistributionPoints = ${CRL}
EOF

# --- IACA root -------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out iaca-key.pem
openssl req -new -x509 -key iaca-key.pem -sha256 -days 7300 \
    -subj "/C=${COUNTRY}/ST=${STATE}/CN=identity-crates test IACA" \
    -extensions iaca -config openssl.cnf \
    -out iaca-cert.pem

# --- Document Signer -------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out ds-key.pem
openssl pkcs8 -topk8 -nocrypt -in ds-key.pem -out ds-key-pkcs8.pem
mv ds-key-pkcs8.pem ds-key.pem

openssl req -new -key ds-key.pem -sha256 \
    -subj "/C=${COUNTRY}/ST=${STATE}/CN=identity-crates test document signer" \
    -out ds.csr

openssl x509 -req -in ds.csr -CA iaca-cert.pem -CAkey iaca-key.pem \
    -CAcreateserial -sha256 -days 400 \
    -extensions ds -extfile openssl.cnf \
    -out ds-cert.pem

# --- An unrelated IACA, for the "wrong anchor" test ------------------------
openssl ecparam -name prime256v1 -genkey -noout -out other-iaca-key.pem
openssl req -new -x509 -key other-iaca-key.pem -sha256 -days 7300 \
    -subj "/C=${COUNTRY}/ST=California/CN=identity-crates unrelated IACA" \
    -extensions iaca -config openssl.cnf \
    -out other-iaca-cert.pem

rm -f ds.csr openssl.cnf iaca-cert.srl other-iaca-key.pem iaca-key.pem

echo "regenerated: iaca-cert.pem, ds-cert.pem, ds-key.pem, other-iaca-cert.pem"
echo "NOTE: the DS certificate is valid for 400 days from today; the tests pin"
echo "      their verification time, so update TEST_TIME in tests/common/mod.rs"
echo "      to a date inside the new window."
