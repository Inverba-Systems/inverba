//! COSE `Sig_structure` preimage construction (RFC 9052 §4.4).
//!
//! IRF does not invent a signing envelope. It builds `COSE_Sign` — the
//! *multi-signer* variant — even when there is exactly one signature. That
//! uniformity is the whole point: adding a post-quantum co-signature, a
//! third-party witness, or an RFC 4998 renewal timestamp later adds an entry to
//! an array and changes nothing about the preimage shape. A format that starts
//! as `COSE_Sign1` and grows a second signer has to change shape, which means a
//! v1 → v2 break in an archive that is supposed to outlive the break.
//!
//! ```text
//! Sig_structure = [
//!   "Signature",       ; context, fixed for COSE_Sign
//!   body_protected,    ; bstr .cbor { "irf": [major, minor] }
//!   sign_protected,    ; bstr .cbor { 1: alg, 4: kid }
//!   external_aad,      ; bstr, the IRF domain tag
//!   payload            ; bstr, dCBOR claim set
//! ]
//! ```
//!
//! Every field is length-delimited by CBOR itself, so there is no delimiter to
//! inject and no ambiguity about where one field ends and the next begins. This
//! is the structural fix for the "raw delimiter in the preimage" bug class
//! (audit finding D2).

use crate::dcbor::{self, Value};
use crate::domain::Domain;
use crate::error::{Invalid, Reason};

/// COSE header label 1: `alg`.
pub const HDR_ALG: i64 = 1;
/// COSE header label 4: `kid`.
pub const HDR_KID: i64 = 4;
/// IRF-private header label. A text label cannot collide with the IANA COSE
/// integer registry, so no codepoint squatting is needed.
pub const HDR_IRF: &str = "irf";

/// COSE `Sig_structure` context string for the multi-signer variant.
pub const CONTEXT_SIGNATURE: &str = "Signature";

/// IANA COSE Algorithms registry values used by IRF.
///
/// ML-DSA is permanently registered with Recommended status, so these are real
/// codepoints and not private-use placeholders that would need migrating.
pub mod alg {
    /// EdDSA over Ed25519 (RFC 9053).
    pub const ED25519: i64 = -8;
    /// ML-DSA-44 (FIPS 204, NIST security category 2).
    pub const ML_DSA_44: i64 = -48;
    /// ML-DSA-65 (FIPS 204, category 3). IRF's per-record PQC default.
    pub const ML_DSA_65: i64 = -49;
    /// ML-DSA-87 (FIPS 204, category 5). CNSA 2.0's mandated parameter set.
    pub const ML_DSA_87: i64 = -50;

    /// Every algorithm this build understands. Anything absent is INVALID —
    /// never skipped, never treated as "unknown but probably fine".
    pub const KNOWN: [i64; 4] = [ED25519, ML_DSA_44, ML_DSA_65, ML_DSA_87];

    /// True for algorithms whose security does not rest on a classical
    /// assumption broken by a CRQC.
    #[must_use]
    pub const fn is_post_quantum(a: i64) -> bool {
        matches!(a, ML_DSA_44 | ML_DSA_65 | ML_DSA_87)
    }

    #[must_use]
    pub const fn is_classical(a: i64) -> bool {
        matches!(a, ED25519)
    }
}

/// IANA COSE hash algorithm values (RFC 9054) used for content digests.
pub mod hash_alg {
    /// SHA-256, RFC 9054.
    pub const SHA_256: i64 = -16;
    /// SHA-384, RFC 9054.
    pub const SHA_384: i64 = -43;
    /// SHA-512, RFC 9054.
    pub const SHA_512: i64 = -44;
    /// Content-hash algorithms this build accepts.
    pub const KNOWN: [i64; 3] = [SHA_256, SHA_384, SHA_512];
}

/// IRF format version. Major bumps are hard breaks: a verifier MUST refuse an
/// unknown major rather than best-effort parse it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormatVersion {
    /// Breaking version. A verifier MUST refuse an unknown major.
    pub major: u64,
    /// Additive version.
    pub minor: u64,
}

/// The version this build implements.
pub const FORMAT_V1: FormatVersion = FormatVersion { major: 1, minor: 0 };

/// Serialised `body_protected` header: `{ "irf": [major, minor] }`.
pub fn body_protected(v: FormatVersion) -> Result<Vec<u8>, Invalid> {
    let m = Value::map(vec![(
        Value::Text(String::from(HDR_IRF)),
        Value::Array(vec![Value::Uint(v.major), Value::Uint(v.minor)]),
    )])?;
    Ok(dcbor::encode(&m))
}

/// Serialised per-signer `sign_protected` header: `{ 1: alg, 4: kid }`.
pub fn sign_protected(alg_id: i64, kid: &[u8]) -> Result<Vec<u8>, Invalid> {
    if kid.is_empty() {
        return Err(Invalid::new(Reason::MissingField));
    }
    let m = Value::map(vec![
        (
            Value::Uint(u64::try_from(HDR_ALG).unwrap_or(1)),
            alg_v_of(alg_id)?,
        ),
        (
            Value::Uint(u64::try_from(HDR_KID).unwrap_or(4)),
            Value::Bytes(kid.to_vec()),
        ),
    ])?;
    Ok(dcbor::encode(&m))
}

fn alg_v_of(alg_id: i64) -> Result<Value, Invalid> {
    if alg_id < 0 {
        let n = alg_id
            .checked_add(1)
            .and_then(|x| x.checked_neg())
            .ok_or(Invalid::new(Reason::UnknownAlgorithm))?;
        Ok(Value::Nint(
            u64::try_from(n).map_err(|_| Invalid::new(Reason::UnknownAlgorithm))?,
        ))
    } else {
        Ok(Value::Uint(
            u64::try_from(alg_id).map_err(|_| Invalid::new(Reason::UnknownAlgorithm))?,
        ))
    }
}

/// Build the exact byte string that gets signed or verified.
///
/// This is the single place in the codebase where a preimage is constructed.
/// Signer and verifier both call it, so they cannot drift apart — the asymmetry
/// the audit warns about in D8 is impossible if there is only one function.
pub fn sig_structure(
    body_protected_bytes: &[u8],
    sign_protected_bytes: &[u8],
    domain: Domain,
    payload: &[u8],
) -> Vec<u8> {
    let s = Value::Array(vec![
        Value::Text(String::from(CONTEXT_SIGNATURE)),
        Value::Bytes(body_protected_bytes.to_vec()),
        Value::Bytes(sign_protected_bytes.to_vec()),
        Value::Bytes(domain.tag().to_vec()),
        Value::Bytes(payload.to_vec()),
    ]);
    dcbor::encode(&s)
}

/// Which signatures must be present and verify for a record to be VALID.
///
/// The default is **not** "any signature verifies". A verifier that accepts
/// either half of a hybrid pair is *weaker* than either primitive alone, because
/// an attacker picks whichever is broken. `RequireAll` is the ANSSI
/// hybridisation semantic and the only safe default.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignaturePolicy {
    /// Every listed algorithm must be present and verify.
    RequireAll(Vec<i64>),
    /// Exactly one algorithm, present and verifying. For pre-migration archives.
    RequireExactly(i64),
}

impl SignaturePolicy {
    /// IRF v1 recommended default: hybrid Ed25519 + ML-DSA-65, both required.
    #[must_use]
    pub fn hybrid_default() -> Self {
        SignaturePolicy::RequireAll(vec![alg::ED25519, alg::ML_DSA_65])
    }

    /// Algorithms this policy demands.
    #[must_use]
    pub fn required(&self) -> Vec<i64> {
        match self {
            SignaturePolicy::RequireAll(v) => v.clone(),
            SignaturePolicy::RequireExactly(a) => vec![*a],
        }
    }

    /// A policy is only meaningful if it names at least one known algorithm.
    pub fn validate(&self) -> Result<(), Invalid> {
        let req = self.required();
        if req.is_empty() {
            return Err(Invalid::new(Reason::EmptySignerSet));
        }
        for a in &req {
            if !alg::KNOWN.contains(a) {
                return Err(Invalid::new(Reason::UnknownAlgorithm));
            }
        }
        Ok(())
    }

    /// True if satisfying this policy leaves the record verifiable after a
    /// classical break. Informational; surfaced so callers can warn rather than
    /// silently ship a classical-only archive.
    #[must_use]
    pub fn is_quantum_durable(&self) -> bool {
        self.required().iter().copied().any(alg::is_post_quantum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_alg_ids_encode_as_cbor_nint() {
        // -8 encodes as major type 1 with argument 7 => 0x27
        let v = alg_v_of(alg::ED25519).expect("ed25519");
        assert_eq!(dcbor::encode(&v), vec![0x27]);
        // -49 => argument 48 => 0x38 0x30
        let v = alg_v_of(alg::ML_DSA_65).expect("mldsa65");
        assert_eq!(dcbor::encode(&v), vec![0x38, 0x30]);
    }

    #[test]
    fn headers_are_canonical() {
        let bp = body_protected(FORMAT_V1).expect("bp");
        assert_eq!(dcbor::encode(&dcbor::decode_canonical(&bp).expect("dec")), bp);
        let sp = sign_protected(alg::ML_DSA_65, b"key-1").expect("sp");
        assert_eq!(dcbor::encode(&dcbor::decode_canonical(&sp).expect("dec")), sp);
    }

    #[test]
    fn empty_kid_rejected() {
        assert!(sign_protected(alg::ED25519, b"").is_err());
    }

    #[test]
    fn preimage_differs_across_domains() {
        let bp = body_protected(FORMAT_V1).expect("bp");
        let sp = sign_protected(alg::ED25519, b"k").expect("sp");
        let a = sig_structure(&bp, &sp, Domain::Record, b"payload");
        let b = sig_structure(&bp, &sp, Domain::Manifest, b"payload");
        // Identical payload, identical key, identical algorithm: a signature
        // over one must not verify over the other.
        assert_ne!(a, b);
    }

    #[test]
    fn preimage_differs_across_algorithms() {
        let bp = body_protected(FORMAT_V1).expect("bp");
        let a = sig_structure(
            &bp,
            &sign_protected(alg::ED25519, b"k").expect("sp"),
            Domain::Record,
            b"p",
        );
        let b = sig_structure(
            &bp,
            &sign_protected(alg::ML_DSA_65, b"k").expect("sp"),
            Domain::Record,
            b"p",
        );
        assert_ne!(a, b);
    }

    #[test]
    fn preimage_has_no_delimiter_ambiguity() {
        // Two different field splits that would collide under a delimiter-joined
        // preimage must produce different bytes here.
        let bp = body_protected(FORMAT_V1).expect("bp");
        let a = sig_structure(&bp, &sign_protected(alg::ED25519, b"ab").expect("s"), Domain::Record, b"c");
        let b = sig_structure(&bp, &sign_protected(alg::ED25519, b"a").expect("s"), Domain::Record, b"bc");
        assert_ne!(a, b);
    }

    #[test]
    fn hybrid_default_is_quantum_durable() {
        let p = SignaturePolicy::hybrid_default();
        p.validate().expect("valid policy");
        assert!(p.is_quantum_durable());
        assert!(!SignaturePolicy::RequireExactly(alg::ED25519).is_quantum_durable());
    }

    #[test]
    fn empty_or_unknown_policy_rejected() {
        assert!(SignaturePolicy::RequireAll(vec![]).validate().is_err());
        assert!(SignaturePolicy::RequireAll(vec![-9999]).validate().is_err());
    }
}
