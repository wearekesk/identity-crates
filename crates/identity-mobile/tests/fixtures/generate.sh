#!/usr/bin/env bash
# Regenerate the passport fixtures: a CSCA, the Document Signer it certifies, the data
# groups, and a real CMS SignedData EF.SOD over their hashes.
#
# The data groups and the LDS security object come from `examples/make_fixtures.rs`,
# which builds them with dmrtd's own TLV encoder so they cannot drift from what the
# parser expects. OpenSSL does the signing, so EF.SOD is a genuine RFC 5652 structure
# rather than something produced by the code under test.
#
# Requires OpenSSL 3.x.
#
#   ./generate.sh   # from this directory
set -euo pipefail

cd "$(dirname "$0")"

# --- data groups + LDS security object -------------------------------------
cargo run --quiet -p identity-mobile --example make_fixtures

# --- CSCA: the country's root ----------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 7300 \
    -subj "/C=GB/O=identity-crates test/CN=Test CSCA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout csca-key.pem -out csca.pem

# --- Document Signer, certified by the CSCA --------------------------------
openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/C=GB/O=identity-crates test/CN=Test Document Signer" \
    -keyout ds-key.pem -out ds.csr

openssl x509 -req -in ds.csr -CA csca.pem -CAkey csca-key.pem -CAcreateserial \
    -sha256 -days 1095 \
    -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n") \
    -out ds.pem

# --- EF.SOD: CMS SignedData over the LDS security object -------------------
# `-econtent_type` is what makes this a passport security object rather than a
# generic signature: 2.23.136.1.1.1 is id-icao-mrtd-security-ldsSecurityObject.
openssl cms -sign -binary -in lds.der -outform DER \
    -signer ds.pem -inkey ds-key.pem \
    -econtent_type 2.23.136.1.1.1 \
    -md sha256 -nodetach -noattr \
    -out efsod.bin

# --- an unrelated CSCA, for the "wrong anchor" test ------------------------
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 7300 \
    -subj "/C=FR/O=identity-crates test/CN=Unrelated CSCA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout other-csca-key.pem -out other-csca.pem

# The tests need the anchors in DER, which is what a masterlist carries.
openssl x509 -in csca.pem -outform DER -out csca.der
openssl x509 -in other-csca.pem -outform DER -out other-csca.der

# Private keys are not needed once everything is signed.
rm -f csca-key.pem ds-key.pem ds.csr csca.srl csca.pem ds.pem \
      other-csca-key.pem other-csca.pem lds.der

echo
echo "regenerated: dg1.bin, dg2.bin, efsod.bin, csca.der, other-csca.der"
