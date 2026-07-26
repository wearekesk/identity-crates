#!/usr/bin/env bash
# Regenerate the test PKI: an IACA root, the Document Signer it issues, and two CRLs
# — one clean, one revoking that Document Signer. All conform to the ISO/IEC 18013-5
# Annex B profiles (certificates: Tables B.2 / B.4; CRLs: Table B.10) so that chain
# validation and revocation checking have something real to succeed and fail against.
#
# The DS certificate is deliberately short-lived (Annex B caps it at 457 days), so
# the tests pin their verification time with `VerifyOptions::at` rather than using
# "now" — that keeps the committed fixtures valid forever.
#
# The CRL distribution point points at a loopback port the revocation tests bind
# themselves; it is baked into the certificate, so changing CRL_PORT here means
# changing it in tests/common/mod.rs too.
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
CRL_PORT="45871"
CRL="URI:http://127.0.0.1:${CRL_PORT}/crl"

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

# --- CA database, used to issue the DS and then to revoke it ---------------
[ca]
default_ca = test_ca

[test_ca]
dir = .
database = \$dir/index.txt
serial = \$dir/serial
crlnumber = \$dir/crlnumber
new_certs_dir = \$dir/newcerts
certificate = \$dir/iaca-cert.pem
private_key = \$dir/iaca-key.pem
default_md = sha256
default_days = 400
default_crl_days = 3650
policy = policy_any
x509_extensions = ds
# Table B.10 allows only Authority Key Identifier and CRL Number on a CRL.
crl_extensions = crl_ext
email_in_dn = no
rand_serial = no
unique_subject = no

[policy_any]
countryName = optional
stateOrProvinceName = optional
commonName = supplied

[crl_ext]
authorityKeyIdentifier = keyid:always
EOF

# --- IACA root -------------------------------------------------------------
openssl ecparam -name prime256v1 -genkey -noout -out iaca-key.pem
openssl req -new -x509 -key iaca-key.pem -sha256 -days 7300 \
    -subj "/C=${COUNTRY}/ST=${STATE}/CN=identity-crates test IACA" \
    -extensions iaca -config openssl.cnf \
    -out iaca-cert.pem

# --- Document Signer, issued through the CA database -----------------------
mkdir -p newcerts
: > index.txt
echo 01 > serial
echo 01 > crlnumber

openssl ecparam -name prime256v1 -genkey -noout -out ds-key.pem
openssl pkcs8 -topk8 -nocrypt -in ds-key.pem -out ds-key-pkcs8.pem
mv ds-key-pkcs8.pem ds-key.pem

openssl req -new -key ds-key.pem -sha256 \
    -subj "/C=${COUNTRY}/ST=${STATE}/CN=identity-crates test document signer" \
    -out ds.csr

openssl ca -batch -config openssl.cnf -in ds.csr -out ds-cert.pem -notext

# --- CRLs: one clean, one revoking the Document Signer ---------------------
openssl ca -batch -config openssl.cnf -gencrl -out crl-clean.pem
openssl crl -in crl-clean.pem -outform DER -out crl-clean.der

openssl ca -batch -config openssl.cnf -revoke ds-cert.pem
openssl ca -batch -config openssl.cnf -gencrl -out crl-revoked.pem
openssl crl -in crl-revoked.pem -outform DER -out crl-revoked.der

# --- An unrelated IACA, for the "wrong anchor" test ------------------------
openssl ecparam -name prime256v1 -genkey -noout -out other-iaca-key.pem
openssl req -new -x509 -key other-iaca-key.pem -sha256 -days 7300 \
    -subj "/C=${COUNTRY}/ST=California/CN=identity-crates unrelated IACA" \
    -extensions iaca -config openssl.cnf \
    -out other-iaca-cert.pem

# The CA private keys are not needed by the tests — the CRLs are already signed.
rm -rf newcerts index.txt index.txt.old index.txt.attr index.txt.attr.old \
       serial serial.old crlnumber crlnumber.old ds.csr openssl.cnf \
       crl-clean.pem crl-revoked.pem other-iaca-key.pem iaca-key.pem

echo "regenerated:"
echo "  iaca-cert.pem, ds-cert.pem, ds-key.pem, other-iaca-cert.pem"
echo "  crl-clean.der, crl-revoked.der"
echo "NOTE: the DS certificate is valid for 400 days from today; the tests pin"
echo "      their verification time, so update TEST_TIME in tests/common/mod.rs"
echo "      to a date inside the new window."
