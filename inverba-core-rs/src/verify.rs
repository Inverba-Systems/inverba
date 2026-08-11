//! The verifier. This is the file that matters most.
//!
//! Cardinal rule (audit D13): **there is no path through this module that
//! returns VALID without every required signature having been checked and
//! passed.** Structurally enforced by:
//!
//! * `Verdict` is a two-variant enum, not a `bool`, so no defaulted or
//!   zero-initialised value is truthy.
//! * Every fallible step is `?`-propagated into `Invalid`, and `Invalid`
//!   converts only to `Verdict::Invalid`.
//! * Required algorithms are collected into a satisfied-set and compared for
//!   *full coverage* at the end. Early `return Ok` is impossible because the
//!   coverage check is the last statement.
//! * Unknown algorithm identifiers are `Invalid`, not "skip this signer".
//!   Skipping is how a hybrid policy silently degrades to no policy.
//!
//! Crypto is **not** implemented here. `SignatureVerifier` is a trait the host
//! supplies, backed by OpenSSL 3.5, AWS-LC-FIPS, or another mainstream vetted
//! library. That boundary is deliberate: it keeps this crate free of primitive
//! implementations, so an audit of this code is an audit of *logic*, and the
//! primitives are someone else's validated artefact.
//!
//! On "formally verified" crypto: Kobeissi's *Verification Theatre* (IACR
//! ePrint 2026/192) found a wrong decompression constant, a missing inverse NTT
//! and a false serialisation proof in verified ML-KEM code, plus a wrong
//! multiplication specification that rendered axiomatised AVX2 ML-DSA proofs
//! unsound — because the build admitted proofs by default. Prefer boring and
//! widely deployed over freshly verified, and never build a claim on the word.

use crate::dcbor::{self, Value};
use crate::domain::Domain;
use crate::error::{Invalid, Reason, Verdict};
use crate::preimage::{
    self, alg, FormatVersion, SignaturePolicy, FORMAT_V1, HDR_ALG, HDR_IRF, HDR_KID,
};

/// Signature primitives, supplied by the host.
///
/// Implementations MUST return `false` on any error, including unknown key,
/// malformed key, and internal failure. Returning `true` on an inconclusive
/// result is the fail-open bug this trait exists to make hard to write.
pub trait SignatureVerifier {
    fn verify(&self, alg_id: i64, kid: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Which keys the verifier is willing to believe, and how many witnesses it
/// wants. There is no notion of consensus here and none is claimed: IRF cannot
/// prove that two witness keys are operated by independent parties, so Sybil
/// resistance is a deployment property, not a protocol property. This is a local
/// trust list, in the Certificate Transparency sense.
#[derive(Clone, Debug, Default)]
pub struct TrustPolicy {
    /// Key identifiers accepted as the primary observer. Empty means "accept any
    /// kid", which is only appropriate when the caller has already pinned the
    /// key out of band.
    pub trusted_observers: Vec<Vec<u8>>,
    /// Key identifiers accepted as witnesses.
    pub trusted_witnesses: Vec<Vec<u8>>,
    /// Minimum number of distinct trusted witness keys required. 0 disables.
    pub min_witnesses: usize,
}

impl TrustPolicy {
    fn observer_allowed(&self, kid: &[u8]) -> bool {
        self.trusted_observers.is_empty()
            || self.trusted_observers.iter().any(|k| k.as_slice() == kid)
    }
}

/// One parsed signer entry from a `COSE_Sign` signatures array.
#[derive(Clone, Debug)]
pub struct Signer {
    /// COSE algorithm identifier from the protected header.
    pub alg_id: i64,
    /// Key identifier from the protected header.
    pub kid: Vec<u8>,
    /// Serialised per-signer protected header, as signed.
    pub protected: Vec<u8>,
    /// Raw signature bytes.
    pub signature: Vec<u8>,
}

/// A parsed IRF envelope.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// Format version parsed from the signed body header.
    pub version: FormatVersion,
    /// Serialised body protected header, as signed.
    pub body_protected: Vec<u8>,
    /// Signed payload bytes (a dCBOR claim set).
    pub payload: Vec<u8>,
    /// All signature entries present in the envelope.
    pub signers: Vec<Signer>,
}

/// Maximum signers accepted in one envelope. Bounds verification work so a
/// pathological envelope cannot burn unbounded CPU (audit D9).
pub const MAX_SIGNERS: usize = 64;

/// Parse a `COSE_Sign` envelope. Rejects anything non-canonical, unknown, or
/// structurally surprising.
///
/// ```text
/// COSE_Sign = [ protected: bstr, unprotected: {}, payload: bstr, signatures: [+ COSE_Signature] ]
/// COSE_Signature = [ protected: bstr, unprotected: {}, signature: bstr ]
/// ```
pub fn parse_envelope(bytes: &[u8]) -> Result<Envelope, Invalid> {
    let top = dcbor::decode_canonical(bytes)?;
    let arr = match &top {
        Value::Array(a) => a,
        _ => return Err(Invalid::new(Reason::WrongType)),
    };
    if arr.len() != 4 {
        return Err(Invalid::new(Reason::WrongType));
    }

    let body_protected = arr
        .first()
        .and_then(Value::as_bytes)
        .ok_or(Invalid::new(Reason::WrongType))?
        .to_vec();

    // Unprotected header must be an empty map. IRF signs everything; an
    // unprotected header is by definition unauthenticated, so permitting
    // content there invites a downgrade.
    match arr.get(1) {
        Some(Value::Map(m)) if m.is_empty() => {}
        _ => return Err(Invalid::new(Reason::UnknownField)),
    }

    let payload = arr
        .get(2)
        .and_then(Value::as_bytes)
        .ok_or(Invalid::new(Reason::WrongType))?
        .to_vec();

    let version = parse_version(&body_protected)?;
    if version.major != FORMAT_V1.major {
        // Unknown major: refuse. Do not attempt a best-effort parse of a format
        // this build does not understand.
        return Err(Invalid::new(Reason::UnknownFormatVersion));
    }

    let sig_arr = match arr.get(3) {
        Some(Value::Array(a)) => a,
        _ => return Err(Invalid::new(Reason::WrongType)),
    };
    if sig_arr.is_empty() {
        return Err(Invalid::new(Reason::EmptySignerSet));
    }
    if sig_arr.len() > MAX_SIGNERS {
        return Err(Invalid::new(Reason::WrongType));
    }

    let mut signers = Vec::with_capacity(sig_arr.len());
    for entry in sig_arr {
        signers.push(parse_signer(entry)?);
    }

    Ok(Envelope {
        version,
        body_protected,
        payload,
        signers,
    })
}

fn parse_version(body_protected: &[u8]) -> Result<FormatVersion, Invalid> {
    let m = dcbor::decode_canonical(body_protected)?;
    // The body header must contain exactly the "irf" entry in v1. An unexpected
    // field in a signed header is a format mismatch, not something to ignore.
    match &m {
        Value::Map(entries) if entries.len() == 1 => {}
        _ => return Err(Invalid::new(Reason::UnknownField)),
    }
    let v = m.get(HDR_IRF).ok_or(Invalid::new(Reason::MissingField))?;
    let parts = match v {
        Value::Array(a) if a.len() == 2 => a,
        _ => return Err(Invalid::new(Reason::WrongType)),
    };
    let major = parts
        .first()
        .and_then(Value::as_uint)
        .ok_or(Invalid::new(Reason::WrongType))?;
    let minor = parts
        .get(1)
        .and_then(Value::as_uint)
        .ok_or(Invalid::new(Reason::WrongType))?;
    Ok(FormatVersion { major, minor })
}

fn parse_signer(entry: &Value) -> Result<Signer, Invalid> {
    let a = match entry {
        Value::Array(a) if a.len() == 3 => a,
        _ => return Err(Invalid::new(Reason::WrongType)),
    };
    let protected = a
        .first()
        .and_then(Value::as_bytes)
        .ok_or(Invalid::new(Reason::WrongType))?
        .to_vec();
    match a.get(1) {
        Some(Value::Map(m)) if m.is_empty() => {}
        _ => return Err(Invalid::new(Reason::UnknownField)),
    }
    let signature = a
        .get(2)
        .and_then(Value::as_bytes)
        .ok_or(Invalid::new(Reason::WrongType))?
        .to_vec();
    if signature.is_empty() {
        return Err(Invalid::new(Reason::MissingField));
    }

    let hdr = dcbor::decode_canonical(&protected)?;
    let entries = match &hdr {
        Value::Map(e) if e.len() == 2 => e,
        _ => return Err(Invalid::new(Reason::UnknownField)),
    };
    let _ = entries;

    let alg_id = lookup_int_label(&hdr, HDR_ALG).ok_or(Invalid::new(Reason::MissingField))?;
    if !alg::KNOWN.contains(&alg_id) {
        // An algorithm this build does not implement cannot be verified, and an
        // unverifiable signature must never be quietly dropped from the set the
        // policy is evaluated against.
        return Err(Invalid::new(Reason::UnknownAlgorithm));
    }
    let kid = lookup_bytes_label(&hdr, HDR_KID)
        .ok_or(Invalid::new(Reason::MissingField))?
        .to_vec();
    if kid.is_empty() {
        return Err(Invalid::new(Reason::MissingField));
    }

    Ok(Signer {
        alg_id,
        kid,
        protected,
        signature,
    })
}

fn lookup_int_label(map: &Value, label: i64) -> Option<i64> {
    match map {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| {
            if k.as_int() == Some(label) {
                v.as_int()
            } else {
                None
            }
        }),
        _ => None,
    }
}

fn lookup_bytes_label(map: &Value, label: i64) -> Option<&[u8]> {
    match map {
        Value::Map(entries) => entries.iter().find_map(|(k, v)| {
            if k.as_int() == Some(label) {
                v.as_bytes()
            } else {
                None
            }
        }),
        _ => None,
    }
}

/// Verify an envelope against a domain, a signature policy, and a trust policy.
///
/// Returns `Verdict::Valid` only if the last statement is reached, which
/// requires full policy coverage.
pub fn verify_envelope<V: SignatureVerifier>(
    bytes: &[u8],
    domain: Domain,
    sig_policy: &SignaturePolicy,
    trust: &TrustPolicy,
    backend: &V,
) -> Verdict {
    Verdict::from(verify_envelope_inner(bytes, domain, sig_policy, trust, backend))
}

/// Same as `verify_envelope` but surfaces the local reason. For tests and
/// operator tooling only — never expose the reason across a trust boundary.
pub fn verify_envelope_detailed<V: SignatureVerifier>(
    bytes: &[u8],
    domain: Domain,
    sig_policy: &SignaturePolicy,
    trust: &TrustPolicy,
    backend: &V,
) -> Result<(), Invalid> {
    verify_envelope_inner(bytes, domain, sig_policy, trust, backend)
}

fn verify_envelope_inner<V: SignatureVerifier>(
    bytes: &[u8],
    domain: Domain,
    sig_policy: &SignaturePolicy,
    trust: &TrustPolicy,
    backend: &V,
) -> Result<(), Invalid> {
    sig_policy.validate()?;
    let env = parse_envelope(bytes)?;

    let required = sig_policy.required();
    let mut satisfied: Vec<i64> = Vec::with_capacity(required.len());
    let mut witness_kids: Vec<Vec<u8>> = Vec::new();

    for signer in &env.signers {
        let preimage = preimage::sig_structure(
            &env.body_protected,
            &signer.protected,
            domain,
            &env.payload,
        );

        // Every signature present is checked. A present-but-invalid signature is
        // fatal even if it was not required: an envelope carrying a broken
        // signature is not a valid envelope, and tolerating it would let an
        // attacker append garbage to probe the verifier.
        if !backend.verify(signer.alg_id, &signer.kid, &preimage, &signer.signature) {
            return Err(Invalid::new(Reason::SignatureFailed));
        }

        let is_witness = trust
            .trusted_witnesses
            .iter()
            .any(|k| k.as_slice() == signer.kid.as_slice());

        if is_witness {
            if !witness_kids.iter().any(|k| k.as_slice() == signer.kid.as_slice()) {
                witness_kids.push(signer.kid.clone());
            }
            continue;
        }

        if !trust.observer_allowed(&signer.kid) {
            return Err(Invalid::new(Reason::UntrustedKey));
        }
        if required.contains(&signer.alg_id) && !satisfied.contains(&signer.alg_id) {
            satisfied.push(signer.alg_id);
        }
    }

    // Full coverage of the required algorithm set. `RequireAll` means all.
    for r in &required {
        if !satisfied.contains(r) {
            return Err(Invalid::new(Reason::RequiredAlgorithmAbsent));
        }
    }
    if let SignaturePolicy::RequireExactly(_) = sig_policy {
        if satisfied.len() != 1 {
            return Err(Invalid::new(Reason::RequiredAlgorithmAbsent));
        }
    }

    if witness_kids.len() < trust.min_witnesses {
        return Err(Invalid::new(Reason::WitnessThresholdNotMet));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build;

    /// Backend that accepts a fixed allowlist of (alg, kid, message, sig).
    struct MockBackend {
        good: Vec<(i64, Vec<u8>, Vec<u8>)>, // (alg, kid, signature)
        fail_all: bool,
    }

    impl SignatureVerifier for MockBackend {
        fn verify(&self, alg_id: i64, kid: &[u8], _message: &[u8], signature: &[u8]) -> bool {
            if self.fail_all {
                return false;
            }
            self.good.iter().any(|(a, k, s)| {
                *a == alg_id && k.as_slice() == kid && s.as_slice() == signature
            })
        }
    }

    fn mk(signers: Vec<(i64, &[u8], &[u8])>, payload: &[u8]) -> (Vec<u8>, MockBackend) {
        let parts: Vec<build::SignerInput> = signers
            .iter()
            .map(|(a, k, s)| build::SignerInput {
                alg_id: *a,
                kid: k.to_vec(),
                signature: s.to_vec(),
            })
            .collect();
        let env = build::envelope(FORMAT_V1, payload, &parts).expect("build");
        let backend = MockBackend {
            good: signers
                .iter()
                .map(|(a, k, s)| (*a, k.to_vec(), s.to_vec()))
                .collect(),
            fail_all: false,
        };
        (env, backend)
    }

    fn open_trust() -> TrustPolicy {
        TrustPolicy::default()
    }

    #[test]
    fn hybrid_envelope_verifies() {
        let (env, backend) = mk(
            vec![
                (alg::ED25519, b"obs-1", b"sig-ed"),
                (alg::ML_DSA_65, b"obs-1", b"sig-ml"),
            ],
            b"claims",
        );
        let v = verify_envelope(
            &env,
            Domain::Record,
            &SignaturePolicy::hybrid_default(),
            &open_trust(),
            &backend,
        );
        assert_eq!(v, Verdict::Valid);
    }

    #[test]
    fn hybrid_policy_rejects_classical_only() {
        // This is the core hybrid semantic: half a hybrid pair is not enough.
        let (env, backend) = mk(vec![(alg::ED25519, b"obs-1", b"sig-ed")], b"claims");
        let r = verify_envelope_detailed(
            &env,
            Domain::Record,
            &SignaturePolicy::hybrid_default(),
            &open_trust(),
            &backend,
        );
        assert_eq!(r.expect_err("must fail").reason(), Reason::RequiredAlgorithmAbsent);
    }

    #[test]
    fn hybrid_policy_rejects_pqc_only() {
        let (env, backend) = mk(vec![(alg::ML_DSA_65, b"obs-1", b"sig-ml")], b"claims");
        assert_eq!(
            verify_envelope(
                &env,
                Domain::Record,
                &SignaturePolicy::hybrid_default(),
                &open_trust(),
                &backend
            ),
            Verdict::Invalid
        );
    }

    #[test]
    fn wrong_domain_is_invalid() {
        let (env, backend) = mk(
            vec![
                (alg::ED25519, b"obs-1", b"sig-ed"),
                (alg::ML_DSA_65, b"obs-1", b"sig-ml"),
            ],
            b"claims",
        );
        // Mock accepts any message, so a naive verifier would pass. The real
        // guarantee is that the preimage differs; asserted in preimage tests.
        // Here we confirm the domain is threaded through rather than ignored.
        let a = preimage::sig_structure(
            &parse_envelope(&env).expect("parse").body_protected,
            &parse_envelope(&env).expect("parse").signers.first().expect("s").protected,
            Domain::Record,
            b"claims",
        );
        let b = preimage::sig_structure(
            &parse_envelope(&env).expect("parse").body_protected,
            &parse_envelope(&env).expect("parse").signers.first().expect("s").protected,
            Domain::Manifest,
            b"claims",
        );
        assert_ne!(a, b);
        let _ = backend;
    }

    #[test]
    fn failing_backend_is_invalid() {
        let (env, mut backend) = mk(
            vec![
                (alg::ED25519, b"obs-1", b"sig-ed"),
                (alg::ML_DSA_65, b"obs-1", b"sig-ml"),
            ],
            b"claims",
        );
        backend.fail_all = true;
        assert_eq!(
            verify_envelope(
                &env,
                Domain::Record,
                &SignaturePolicy::hybrid_default(),
                &open_trust(),
                &backend
            ),
            Verdict::Invalid
        );
    }

    #[test]
    fn extra_broken_signature_is_fatal() {
        // A valid hybrid pair plus one bogus signature must NOT verify.
        let parts = vec![
            build::SignerInput { alg_id: alg::ED25519, kid: b"obs-1".to_vec(), signature: b"sig-ed".to_vec() },
            build::SignerInput { alg_id: alg::ML_DSA_65, kid: b"obs-1".to_vec(), signature: b"sig-ml".to_vec() },
            build::SignerInput { alg_id: alg::ML_DSA_44, kid: b"obs-1".to_vec(), signature: b"forged".to_vec() },
        ];
        let env = build::envelope(FORMAT_V1, b"claims", &parts).expect("build");
        let backend = MockBackend {
            good: vec![
                (alg::ED25519, b"obs-1".to_vec(), b"sig-ed".to_vec()),
                (alg::ML_DSA_65, b"obs-1".to_vec(), b"sig-ml".to_vec()),
            ],
            fail_all: false,
        };
        assert_eq!(
            verify_envelope(&env, Domain::Record, &SignaturePolicy::hybrid_default(), &open_trust(), &backend),
            Verdict::Invalid
        );
    }

    #[test]
    fn unknown_algorithm_is_invalid_not_skipped() {
        let parts = vec![
            build::SignerInput { alg_id: alg::ED25519, kid: b"obs-1".to_vec(), signature: b"sig-ed".to_vec() },
            build::SignerInput { alg_id: -9999, kid: b"obs-1".to_vec(), signature: b"whatever".to_vec() },
        ];
        let env = build::envelope(FORMAT_V1, b"claims", &parts).expect("build");
        let backend = MockBackend { good: vec![], fail_all: false };
        let r = verify_envelope_detailed(
            &env,
            Domain::Record,
            &SignaturePolicy::RequireExactly(alg::ED25519),
            &open_trust(),
            &backend,
        );
        assert_eq!(r.expect_err("must fail").reason(), Reason::UnknownAlgorithm);
    }

    #[test]
    fn empty_signer_set_is_invalid() {
        let env = build::envelope(FORMAT_V1, b"claims", &[]);
        assert!(env.is_err());
    }

    #[test]
    fn untrusted_observer_key_is_invalid() {
        let (env, backend) = mk(
            vec![
                (alg::ED25519, b"attacker", b"sig-ed"),
                (alg::ML_DSA_65, b"attacker", b"sig-ml"),
            ],
            b"claims",
        );
        let trust = TrustPolicy {
            trusted_observers: vec![b"obs-1".to_vec()],
            ..TrustPolicy::default()
        };
        let r = verify_envelope_detailed(
            &env,
            Domain::Record,
            &SignaturePolicy::hybrid_default(),
            &trust,
            &backend,
        );
        assert_eq!(r.expect_err("must fail").reason(), Reason::UntrustedKey);
    }

    #[test]
    fn witness_threshold_enforced() {
        let (env, backend) = mk(
            vec![
                (alg::ED25519, b"obs-1", b"sig-ed"),
                (alg::ML_DSA_65, b"obs-1", b"sig-ml"),
                (alg::ML_DSA_65, b"wit-a", b"sig-wa"),
            ],
            b"claims",
        );
        let trust = TrustPolicy {
            trusted_observers: vec![b"obs-1".to_vec()],
            trusted_witnesses: vec![b"wit-a".to_vec(), b"wit-b".to_vec()],
            min_witnesses: 2,
        };
        assert_eq!(
            verify_envelope(&env, Domain::Record, &SignaturePolicy::hybrid_default(), &trust, &backend),
            Verdict::Invalid
        );

        let trust_ok = TrustPolicy { min_witnesses: 1, ..trust };
        assert_eq!(
            verify_envelope(&env, Domain::Record, &SignaturePolicy::hybrid_default(), &trust_ok, &backend),
            Verdict::Valid
        );
    }

    #[test]
    fn duplicate_witness_key_counts_once() {
        // Two signatures from one witness key is not two witnesses.
        let (env, backend) = mk(
            vec![
                (alg::ED25519, b"obs-1", b"sig-ed"),
                (alg::ML_DSA_65, b"obs-1", b"sig-ml"),
                (alg::ED25519, b"wit-a", b"sig-wa1"),
                (alg::ML_DSA_65, b"wit-a", b"sig-wa2"),
            ],
            b"claims",
        );
        let trust = TrustPolicy {
            trusted_observers: vec![b"obs-1".to_vec()],
            trusted_witnesses: vec![b"wit-a".to_vec()],
            min_witnesses: 2,
        };
        assert_eq!(
            verify_envelope(&env, Domain::Record, &SignaturePolicy::hybrid_default(), &trust, &backend),
            Verdict::Invalid
        );
    }

    #[test]
    fn unknown_major_version_is_invalid() {
        let bad = FormatVersion { major: 2, minor: 0 };
        let parts = vec![build::SignerInput {
            alg_id: alg::ED25519,
            kid: b"obs-1".to_vec(),
            signature: b"sig-ed".to_vec(),
        }];
        let env = build::envelope(bad, b"claims", &parts).expect("build");
        let backend = MockBackend { good: vec![], fail_all: false };
        let r = verify_envelope_detailed(
            &env,
            Domain::Record,
            &SignaturePolicy::RequireExactly(alg::ED25519),
            &open_trust(),
            &backend,
        );
        assert_eq!(r.expect_err("must fail").reason(), Reason::UnknownFormatVersion);
    }

    #[test]
    fn non_canonical_envelope_is_invalid() {
        let (env, backend) = mk(vec![(alg::ED25519, b"obs-1", b"sig-ed")], b"claims");
        // Corrupt the outer array head into an indefinite-length array.
        let mut bad = env.clone();
        if let Some(b) = bad.get_mut(0) {
            *b = 0x9f;
        }
        assert_eq!(
            verify_envelope(&bad, Domain::Record, &SignaturePolicy::RequireExactly(alg::ED25519), &open_trust(), &backend),
            Verdict::Invalid
        );
    }

    #[test]
    fn truncated_input_is_invalid_at_every_length() {
        // Exhaustive fail-closed sweep: no prefix of a valid envelope verifies.
        let (env, backend) = mk(
            vec![
                (alg::ED25519, b"obs-1", b"sig-ed"),
                (alg::ML_DSA_65, b"obs-1", b"sig-ml"),
            ],
            b"claims",
        );
        for n in 0..env.len() {
            let prefix = env.get(..n).unwrap_or(&[]);
            assert_eq!(
                verify_envelope(prefix, Domain::Record, &SignaturePolicy::hybrid_default(), &open_trust(), &backend),
                Verdict::Invalid,
                "prefix of length {n} verified"
            );
        }
    }

    #[test]
    fn single_byte_mutation_never_yields_valid_under_real_backend() {
        // With a backend that binds signatures to exact bytes, any mutation of
        // the envelope must be INVALID. Catches accidental fail-open paths in
        // parsing far better than hand-picked cases.
        let (env, backend) = mk(
            vec![
                (alg::ED25519, b"obs-1", b"sig-ed"),
                (alg::ML_DSA_65, b"obs-1", b"sig-ml"),
            ],
            b"claims",
        );
        let policy = SignaturePolicy::hybrid_default();
        for i in 0..env.len() {
            for bit in 0..8u32 {
                let mut m = env.clone();
                if let Some(b) = m.get_mut(i) {
                    *b ^= 1u8 << bit;
                }
                if m == env {
                    continue;
                }
                // The mock binds (alg, kid, signature) triples, so a mutation
                // that changes any of those, or breaks canonical form, must fail.
                // A mutation inside the payload alone would still pass the mock;
                // exclude that region by requiring the parse to be structurally
                // identical before asserting.
                let reparsed = parse_envelope(&m);
                let structurally_same = match (&reparsed, parse_envelope(&env)) {
                    (Ok(a), Ok(b)) => {
                        a.signers.len() == b.signers.len()
                            && a.signers.iter().zip(b.signers.iter()).all(|(x, y)| {
                                x.alg_id == y.alg_id
                                    && x.kid == y.kid
                                    && x.signature == y.signature
                            })
                    }
                    _ => false,
                };
                if structurally_same {
                    continue;
                }
                assert_eq!(
                    verify_envelope(&m, Domain::Record, &policy, &open_trust(), &backend),
                    Verdict::Invalid,
                    "mutation at byte {i} bit {bit} verified"
                );
            }
        }
    }
}
