#!/usr/bin/env python3
"""Regenerate the RSASSA-PSS passive-authentication fixtures (needs OpenSSL 3).

A self-signed CSCA signs a Document Signer, and the Document Signer signs an
EF.SOD hashing ../dg1.bin and ../dg2.bin — every signature RSASSA-PSS with
SHA-256, MGF1-SHA-256 and a 32-byte salt, as many issuers' are. The Document
Signer's modulus is 2049 bits, so its encoded message is a byte shorter than
the modulus (RFC 8017 §9.1.2's emLen < k case).

    python3 make.py        # from this directory
"""

import hashlib
import os
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SHA256 = bytes.fromhex("608648016503040201")
PSS = ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:32", "-sigopt", "rsa_mgf1_md:sha256"]


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        octets = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(octets)]) + octets
    return bytes([tag]) + length + content


def lds(groups):
    hashes = b"".join(tlv(0x30, tlv(0x02, bytes([n])) + tlv(0x04, hashlib.sha256(data).digest())) for n, data in groups)
    return tlv(0x30, tlv(0x02, b"\x00") + tlv(0x30, tlv(0x06, SHA256)) + tlv(0x30, hashes))


def openssl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def main():
    groups = [(n, open(os.path.join(HERE, "..", f"dg{n}.bin"), "rb").read()) for n in (1, 2)]
    with tempfile.TemporaryDirectory() as tmp:
        path = lambda name: os.path.join(tmp, name)
        for who, bits in (("csca", 3072), ("dsc", 2049)):
            openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{bits}", "-out", path(f"{who}.key"))
        openssl("req", "-x509", "-new", "-key", path("csca.key"), "-subj", "/C=UT/O=dmrtd test/CN=CSCA RSA-PSS",
                "-days", "36500", "-sha256", *PSS, "-out", path("csca.pem"))
        openssl("req", "-new", "-key", path("dsc.key"), "-subj", "/C=UT/O=dmrtd test/CN=DS RSA-PSS", "-out", path("dsc.csr"))
        openssl("x509", "-req", "-in", path("dsc.csr"), "-CA", path("csca.pem"), "-CAkey", path("csca.key"),
                "-days", "36500", "-sha256", *PSS, "-out", path("dsc.pem"))
        with open(path("lds.der"), "wb") as f:
            f.write(lds(groups))
        openssl("cms", "-sign", "-binary", "-nodetach", "-nosmimecap", "-md", "sha256", "-econtent_type", "2.23.136.1.1.1",
                "-in", path("lds.der"), "-signer", path("dsc.pem"), "-inkey", path("dsc.key"),
                "-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:32", "-keyopt", "rsa_mgf1_md:sha256",
                "-outform", "DER", "-out", path("sod.der"))
        openssl("x509", "-in", path("csca.pem"), "-outform", "DER", "-out", os.path.join(HERE, "csca.der"))
        with open(path("sod.der"), "rb") as f, open(os.path.join(HERE, "efsod.bin"), "wb") as out:
            out.write(tlv(0x77, f.read()))


if __name__ == "__main__":
    main()
