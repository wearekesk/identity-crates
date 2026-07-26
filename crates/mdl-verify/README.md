# mdl-verify

ISO/IEC 18013-5 mobile driving licence (mDL / mdoc) verification, server-side.

Give it a decrypted CBOR `DeviceResponse` and a set of IACA trust anchors; get back
the disclosed identity elements plus exactly what was proven about them.

```rust
use mdl_verify::{verify_issuer_auth, IacaAnchor};

let anchors = [IacaAnchor::from_certificate(iaca_root_der)?];
let verification = verify_issuer_auth(device_response, &anchors)?;

let mdl = verification.mdl().ok_or("no mDL in the response")?;
if mdl.is_authentic() && mdl.age_over(21) == Some(true) {
    println!("{} {}", mdl.given_name().unwrap_or(""), mdl.family_name().unwrap_or(""));
}
```

## The two layers

An mdoc presentation carries two independent proofs, and they answer different
questions:

| Layer | Proves | Entry point |
|---|---|---|
| **Issuer data authentication** — `COSE_Sign1` over the MSO, Document Signer chaining to an IACA root, every disclosed element's digest matching `valueDigests` | the data is genuine, issuer-signed and unmodified | `verify_issuer_auth` |
| **Device authentication** — `DeviceSignature` / `DeviceMac` over a transcript carrying the verifier's nonce | this holder controls the device key bound in the MSO, right now | `verify_device_auth` |

Only the first is verifiable from a static blob. Without the second, a genuine
`DeviceResponse` captured once can be replayed forever — fine for some server-side
flows, fatal for others. `verify_presentation` runs both when you have a session
transcript.

## Session transcripts

Device authentication signs over the `SessionTranscript`, whose shape depends on how
the credential was presented and is still moving between drafts. Rather than model
each variant and go stale, `SessionTranscript::from_cbor` adopts the transcript your
session layer already built, and rejects anything it cannot re-encode byte-for-byte —
otherwise a mismatch surfaces later as a signature failure, indistinguishable from a
real one. It checks reproducibility, not canonical form: the transcript comes from
your session layer rather than the holder, and a holder that signed non-canonically
ordered bytes must still verify against exactly those bytes.

`SessionTranscript::openid4vp_handover` (ISO 18013-7 Annex B) and
`SessionTranscript::openid4vp_dcapi_handover` (OpenID4VP 1.0 over the W3C Digital
Credentials API — the browser path for Apple Wallet and Google Wallet) assemble the
two online shapes, taking the hashes as inputs because *what* gets hashed is exactly
the part that differs between drafts.

## Apple Wallet and Google Wallet

Issuer data authentication is wallet-agnostic: it verifies the issuer's signature, so
an mDL from Apple Wallet, Google Wallet or a state app all go through the same path.
Two things to be aware of:

- The input must be the **decrypted** `DeviceResponse`. Session establishment,
  BLE/NFC engagement and response decryption belong to your reader or OpenID4VP
  layer; this crate is no-transport and no-network by design.
- For device authentication you need the transcript that session produced, including
  the reader's ephemeral private key if the holder used `COSE_Mac0`.

## Revocation

A Document Signer certificate can be revoked after issuance, and neither signature
layer notices. The `revocation` module checks the CRL named in the certificate's
distribution point:

```rust
use mdl_verify::revocation::{verify_issuer_auth, CrlChecker};
use mdl_verify::VerifyOptions;

// Build once and share — CRLs are cached, not refetched per presentation.
let crl = CrlChecker::new()?;
let verification =
    verify_issuer_auth(device_response, &anchors, &VerifyOptions::default(), &crl).await?;
```

Two outcomes are deliberately kept apart:

- the signer **is on the CRL** → `issuer_trusted = false`, reason in `trust_errors`;
- the CRL **could not be checked** (host down, bad signature, malformed list) →
  `revocation_errors`, with `issuer_trusted` left to the other chain checks.

Conflating them gives you either a verifier that fails open whenever a DMV's CRL host
has a bad afternoon, or one that rejects every presentation for the same reason.
Which is right depends on your deployment, so the choice stays with you.

These entry points are `async` — fetching is I/O, and the crate would rather say so
than hide a runtime inside a synchronous call. Everything else stays synchronous and
no-network.

Revocation itself is never optional — a verifier that cannot tell you a signer was
revoked last week is doing half the job — and nothing here runs unless you call it, so
the default verification path stays synchronous and makes no requests.

### Bringing your own HTTP client

`CrlChecker` is generic over `HttpClient`, so the fetch can go through whatever the
platform prefers:

```rust
use mdl_verify::revocation::{async_trait, CrlChecker, HttpClient, HttpRequest, HttpResponse};

struct PlatformHttp;   // URLSession, OkHttp, a corporate proxy stack, a test double

#[async_trait]
impl HttpClient for PlatformHttp {
    type Error = std::io::Error;
    async fn request(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> { … }
}

let crl = CrlChecker::with_http_client(PlatformHttp);
```

The bundled reqwest client is the `bundled-http-client` feature, **on by default**.
Switch it off for a mobile build:

```toml
mdl-verify = { version = "0.0.0", default-features = false }
```

That drops reqwest, rustls, tokio's networking and `ring` from the graph — which is
what removes the Android NDK requirement, since `ring` compiles C and assembly and
this crate does not. Verified: with the feature off,
`cargo check --target aarch64-linux-android` succeeds with no NDK present at all.

One behavioural difference: the caching CRL fetcher lives behind the same upstream
feature, so a build without it fetches uncached. Wrap your own client in a cache if
that matters.

`BlockingCrlChecker` exposes the same two calls synchronously for callers with no
runtime — reader apps reaching the crate over FFI. See [docs/flutter.md](docs/flutter.md).

## Trust anchors

IACA roots are per-jurisdiction. Verifying with an empty anchor list is allowed and
useful: signatures and digests are still checked, and the result reports
`issuer_trusted = false`.

For US mDLs you do not have to hand-manage the set. AAMVA's Digital Trust Service
publishes a **VICAL** (ISO/IEC 18013-5 Annex C) — a `COSE_Sign1` over the list of IACA
certificates. Verify it once against their root and use what it vouches for:

```rust
use mdl_verify::{vical, VerifyOptions, MDL_DOC_TYPE};

let authorities = [vical::VicalAuthority::from_pem(aamva_dts_root_pem)?];
let list = vical::verify(vical_bytes, &authorities, &VerifyOptions::default())?;

// Scoped to document type — an entry good for mDLs is not automatically good for
// a photo ID.
let anchors = list.anchors_for(MDL_DOC_TYPE);
let verification = mdl_verify::verify_issuer_auth(device_response, &anchors)?;
```

Verifying a VICAL establishes that the provider signed that list and that their signer
chains to a root you trust. It says nothing about whether an individual IACA in it is
still fit to trust — the per-document chain checks and CRLs still run afterwards.

A VICAL is a snapshot, and serving a stale one is how a removed issuer stays trusted;
`Vical::is_stale_at` answers that against the provider's own `nextUpdate`. Fetching it
is the caller's job, as with the CSCA masterlist in [`dmrtd`](../dmrtd) — this crate
verifies bytes, it does not go to the network for you (except CRLs, on request).

`TrustRules::Iso18013_5` (the default) applies the Annex B profile;
`TrustRules::Aamva` adds the AAMVA-specific constraints on top.

## Which issuers can this verify?

ECDSA over P-256 and P-384. ISO/IEC 18013-5 also permits P-521, Ed25519/Ed448 and the
brainpool curves; those are not implemented, and an mDL signed with one comes back as
`MdlError::UnsupportedAlgorithm` — a refusal to answer, never a pass.

In practice this has never bitten anyone: AAMVA issues with P-256, and the EUDI ARF
mandates ES256 as its floor. To confirm for a specific issuer, read it off a sample
presentation instead of their PKI documentation:

```rust
for key in mdl_verify::preflight::response_signer_keys(sample_response)? {
    println!("{}: {}", key.algorithm, if key.verifiable { "ok" } else { "NOT SUPPORTED" });
}
```

Tracked in [#17](https://github.com/wearekesk/identity-crates/issues/17).

## Failure model

Anything meaning "these bytes are not what the issuer signed" is an error, never a
flag: `MdlError::Tampered` for a bad signature or a digest mismatch,
`MdlError::DeviceAuth` for a failed device signature. There is no way to read element
values out of this crate without that having passed.

Judgements a caller can reasonably disagree about stay as fields —
`issuer_trusted` and `validity.in_window`. `is_authentic()` bundles them.

## Status

`0.0.0`, in-workspace only, `publish = false`.

The crate depends on [`isomdl`](https://github.com/spruceid/isomdl) by **pinned git
revision** rather than the crates.io release. The published 0.2.0 verifies the
`COSE_Sign1` over the MSO but never binds the disclosed elements to `valueDigests`
and never checks the MSO validity window — a holder could disclose arbitrary values
under a genuine issuer signature. Both are fixed upstream (spruceid/isomdl#132, #133)
but unreleased.

The pin is load-bearing. Do not relax it to a version requirement (`isomdl = "0.2"`)
while 0.2.0 is the newest published version: that silently reintroduces a verifier
which accepts forged element values. The consequence is that this crate cannot be
published to crates.io — cargo refuses git dependencies — hence `0.0.0` and
`publish = false`. That is a distribution constraint, not a correctness one; the
verification itself is complete and tested.

The tests here do not take that on faith: they issue real mdocs signed by a fixture
Document Signer and assert that a flipped `age_over_21` is rejected, that a response
replayed into another session fails device authentication, and that a chain only
verifies against its own IACA.

## Tests

```sh
cargo test -p mdl-verify
```

The revocation tests serve the fixture CRLs from a loopback socket, so the real HTTP
client really does fetch and validate them; they share a fixed port (it is baked into
the Document Signer's distribution point) and therefore run one at a time.

The IACA and Document Signer fixtures in `tests/fixtures` are generated by
`tests/fixtures/generate.sh` and conform to the Annex B certificate profiles. The DS
certificate is deliberately short-lived, so the tests pin their verification time
rather than using "now".

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT)
at your option.
