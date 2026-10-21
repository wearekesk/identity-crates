#!/usr/bin/env python3
"""Regenerate the EC passive-authentication fixtures (needs OpenSSL 3).

For each curve, a self-signed CSCA signs a Document Signer, and the Document
Signer signs an EF.SOD hashing ../dg1.bin and ../dg2.bin. Every key is written
with *explicit* curve parameters, as ICAO 9303 part 12 asks, not a named curve;
and the EF.SOD's SignerInfo signatureAlgorithm carries a NULL parameter, as
many issuers' do, although RFC 5758 says ECDSA's should be absent.

    python3 make.py        # from this directory
"""

import hashlib
import os
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CURVES = {
    "p256": "prime256v1",
    "p384": "secp384r1",
    "p521": "secp521r1",
    "bp256": "brainpoolP256r1",
    "bp384": "brainpoolP384r1",
    "bp512": "brainpoolP512r1",
}
SHA256 = bytes.fromhex("608648016503040201")
ECDSA_PREFIX = bytes.fromhex("2a8648ce3d04")  # 1.2.840.10045.4


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        octets = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(octets)]) + octets
    return bytes([tag]) + length + content


def parse(data):
    """A DER string as a list of (tag, contents) — contents a list for constructed tags."""
    nodes = []
    while data:
        tag, first = data[0], data[1]
        if first < 0x80:
            length, start = first, 2
        else:
            count = first & 0x7F
            length, start = int.from_bytes(data[2 : 2 + count], "big"), 2 + count
        body = data[start : start + length]
        nodes.append((tag, parse(body) if tag & 0x20 else body))
        data = data[start + length :]
    return nodes


def encode(nodes):
    return b"".join(tlv(tag, encode(body) if isinstance(body, list) else body) for tag, body in nodes)


def lds(groups):
    hashes = b"".join(tlv(0x30, tlv(0x02, bytes([n])) + tlv(0x04, hashlib.sha256(data).digest())) for n, data in groups)
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x30, tlv(0x06, SHA256)) + tlv(0x30, hashes))


def null_ecdsa_parameter(content_info):
    """Give the SignerInfo's ecdsa-with-SHA* signatureAlgorithm a NULL parameter.

    The signature is over the signed attributes, not this field, so it still verifies.
    """
    [(_, [oid, (_, [signed])])] = parse(content_info)
    for tag, body in signed[1]:
        if tag == 0x31 and body and body[0][0] == 0x30 and isinstance(body[0][1], list):
            signer = body[0][1]
            for i, (field_tag, field) in enumerate(signer):
                if field_tag == 0x30 and isinstance(field, list) and field[0][0] == 0x06 and field[0][1].startswith(ECDSA_PREFIX):
                    signer[i] = (0x30, [field[0], (0x05, b"")])
                    return encode([(0x30, [oid, (0xA0, [signed])])])
    raise SystemExit("no ECDSA signatureAlgorithm in the SignerInfo")


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def main():
    groups = [(n, open(os.path.join(HERE, "..", f"dg{n}.bin"), "rb").read()) for n in (1, 2)]
    for short, curve in CURVES.items():
        with tempfile.TemporaryDirectory() as tmp:
            path = lambda name: os.path.join(tmp, name)
            for who in ("csca", "dsc"):
                openssl("ecparam", "-name", curve, "-param_enc", "explicit", "-genkey", "-noout", "-out", path(f"{who}.key"))
            openssl("req", "-x509", "-new", "-key", path("csca.key"), "-subj", f"/C=UT/O=dmrtd test/CN=CSCA {short}",
                    "-days", "36500", "-sha256", "-out", path("csca.pem"))
            openssl("req", "-new", "-key", path("dsc.key"), "-subj", f"/C=UT/O=dmrtd test/CN=DS {short}", "-out", path("dsc.csr"))
            openssl("x509", "-req", "-in", path("dsc.csr"), "-CA", path("csca.pem"), "-CAkey", path("csca.key"),
                    "-days", "36500", "-sha256", "-out", path("dsc.pem"))
            with open(path("lds.der"), "wb") as f:
                f.write(lds(groups))
            openssl("cms", "-sign", "-binary", "-nodetach", "-nosmimecap", "-md", "sha256", "-econtent_type", "2.23.136.1.1.1",
                    "-in", path("lds.der"), "-signer", path("dsc.pem"), "-inkey", path("dsc.key"), "-outform", "DER",
                    "-out", path("sod.der"))
            openssl("x509", "-in", path("csca.pem"), "-outform", "DER", "-out", os.path.join(HERE, f"{short}_csca.der"))
            sod = null_ecdsa_parameter(open(path("sod.der"), "rb").read())
            with open(os.path.join(HERE, f"{short}_efsod.bin"), "wb") as f:
                f.write(tlv(0x77, sod))


if __name__ == "__main__":
    main()
