//! Envelope construction.
//!
//! Signer and verifier share `preimage::sig_structure`, and this module is the
//! only writer of envelopes, so there is exactly one encoder and one decoder for
//! the format. Differential signer/verifier asymmetry (audit D8) is structurally
//! hard to introduce.
//!
//! Note what is *not* here: no private keys, no signing. The caller signs
//! `preimage_for` with a host-supplied primitive and passes the bytes back. Key
//! material never enters this crate, which is the same boundary decision as
//! `SignatureVerifier` — and it means Python-side key handling (which cannot
//! reliably zeroise, per audit §B) is never the thing holding a signing key
//! during a core operation.

use crate::dcbor::{self, Value};
use crate::domain::Domain;
use crate::error::{Invalid, Reason};
use crate::preimage::{self, alg, FormatVersion};
use crate::verify::MAX_SIGNERS;

/// One signature to place in the envelope.
#[derive(Clone, Debug)]
pub struct SignerInput {
    /// COSE algorithm identifier for this signature.
    pub alg_id: i64,
    /// Key identifier for this signature.
    pub kid: Vec<u8>,
    /// Signature produced by the host over `preimage_for`.
    pub signature: Vec<u8>,
}

/// The exact bytes a host must sign for a given signer slot.
pub fn preimage_for(
    version: FormatVersion,
    alg_id: i64,
    kid: &[u8],
    domain: Domain,
    payload: &[u8],
) -> Result<Vec<u8>, Invalid> {
    if !alg::KNOWN.contains(&alg_id) {
        return Err(Invalid::new(Reason::UnknownAlgorithm));
    }
    let bp = preimage::body_protected(version)?;
    let sp = preimage::sign_protected(alg_id, kid)?;
    Ok(preimage::sig_structure(&bp, &sp, domain, payload))
}

/// Assemble a `COSE_Sign` envelope.
///
/// `version` is not validated against `FORMAT_V1` here — a builder must be able
/// to emit a future version for round-trip tests — but `parse_envelope` will
/// refuse an unknown major, which is where the guarantee belongs.
pub fn envelope(
    version: FormatVersion,
    payload: &[u8],
    signers: &[SignerInput],
) -> Result<Vec<u8>, Invalid> {
    if signers.is_empty() {
        return Err(Invalid::new(Reason::EmptySignerSet));
    }
    if signers.len() > MAX_SIGNERS {
        return Err(Invalid::new(Reason::WrongType));
    }

    let bp = preimage::body_protected(version)?;

    let mut sig_entries = Vec::with_capacity(signers.len());
    for s in signers {
        if s.signature.is_empty() {
            return Err(Invalid::new(Reason::MissingField));
        }
        let sp = preimage::sign_protected(s.alg_id, &s.kid)?;
        sig_entries.push(Value::Array(vec![
            Value::Bytes(sp),
            Value::Map(Vec::new()),
            Value::Bytes(s.signature.clone()),
        ]));
    }

    let top = Value::Array(vec![
        Value::Bytes(bp),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Array(sig_entries),
    ]);
    Ok(dcbor::encode(&top))
}

/// Build a canonical observation claim set.
///
/// The field names encode the honest scope of the claim. `observed_by` saw
/// `content_len` bytes hashing to `content_hash` at `uri` at `observed_at`. That
/// is all a record asserts. It does **not** assert that the origin genuinely
/// served those bytes — no signature can establish that on its own — and the
/// spec says so in the same breath. `scope` carries that limitation inside the
/// signed payload so it travels with the record and cannot be stripped by
/// restating the marketing.
#[allow(clippy::too_many_arguments)]
pub fn observation_payload(
    uri: &str,
    content_hash_alg: i64,
    content_hash: &[u8],
    content_len: u64,
    media_type: &str,
    observed_at: u64,
    observed_by: &[u8],
    scope: &str,
) -> Result<Vec<u8>, Invalid> {
    if content_hash.is_empty() || observed_by.is_empty() || uri.is_empty() {
        return Err(Invalid::new(Reason::MissingField));
    }
    if !preimage::hash_alg::KNOWN.contains(&content_hash_alg) {
        return Err(Invalid::new(Reason::UnknownAlgorithm));
    }
    let alg_v = if content_hash_alg < 0 {
        let n = content_hash_alg
            .checked_add(1)
            .and_then(|x| x.checked_neg())
            .ok_or(Invalid::new(Reason::UnknownAlgorithm))?;
        Value::Nint(u64::try_from(n).map_err(|_| Invalid::new(Reason::UnknownAlgorithm))?)
    } else {
        Value::Uint(u64::try_from(content_hash_alg).unwrap_or(0))
    };

    let m = Value::map(vec![
        (Value::Text(String::from("uri")), Value::Text(String::from(uri))),
        (Value::Text(String::from("hash_alg")), alg_v),
        (Value::Text(String::from("hash")), Value::Bytes(content_hash.to_vec())),
        (Value::Text(String::from("len")), Value::Uint(content_len)),
        (Value::Text(String::from("media_type")), Value::Text(String::from(media_type))),
        (Value::Text(String::from("observed_at")), Value::Uint(observed_at)),
        (Value::Text(String::from("observed_by")), Value::Bytes(observed_by.to_vec())),
        (Value::Text(String::from("scope")), Value::Text(String::from(scope))),
    ])?;
    Ok(dcbor::encode(&m))
}

/// The only scope string IRF v1 defines for a fetch-derived record.
pub const SCOPE_OBSERVATION: &str = "observation";

/// Build a canonical manifest payload. `size` and `root` are bound together
/// inside the signed bytes, which is the other half of the `(size, root)`
/// inseparability the Merkle layer enforces at proof time.
pub fn manifest_payload(root: &[u8; 32], size: u64, created_at: u64) -> Result<Vec<u8>, Invalid> {
    if size == 0 {
        return Err(Invalid::new(Reason::EmptyTree));
    }
    let m = Value::map(vec![
        (Value::Text(String::from("root")), Value::Bytes(root.to_vec())),
        (Value::Text(String::from("size")), Value::Uint(size)),
        (Value::Text(String::from("created_at")), Value::Uint(created_at)),
    ])?;
    Ok(dcbor::encode(&m))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preimage::{hash_alg, FORMAT_V1};

    #[test]
    fn envelope_round_trips_through_parser() {
        let payload = observation_payload(
            "https://example.test/a",
            hash_alg::SHA_256,
            &[0xab; 32],
            1234,
            "text/html",
            1_753_400_000,
            b"node-alpha",
            SCOPE_OBSERVATION,
        )
        .expect("payload");
        let signers = vec![
            SignerInput { alg_id: alg::ED25519, kid: b"node-alpha".to_vec(), signature: vec![1; 64] },
            SignerInput { alg_id: alg::ML_DSA_65, kid: b"node-alpha".to_vec(), signature: vec![2; 3309] },
        ];
        let env = envelope(FORMAT_V1, &payload, &signers).expect("envelope");
        let parsed = crate::verify::parse_envelope(&env).expect("parse");
        assert_eq!(parsed.version, FORMAT_V1);
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.signers.len(), 2);
        // Envelope bytes are canonical.
        assert_eq!(dcbor::encode(&dcbor::decode_canonical(&env).expect("dec")), env);
    }

    #[test]
    fn preimage_for_matches_what_verifier_reconstructs() {
        let payload = b"claims";
        let pre = preimage_for(FORMAT_V1, alg::ED25519, b"k", Domain::Record, payload).expect("pre");
        let signers = vec![SignerInput {
            alg_id: alg::ED25519,
            kid: b"k".to_vec(),
            signature: vec![9; 64],
        }];
        let env = envelope(FORMAT_V1, payload, &signers).expect("env");
        let parsed = crate::verify::parse_envelope(&env).expect("parse");
        let signer = parsed.signers.first().expect("signer");
        let rebuilt = preimage::sig_structure(
            &parsed.body_protected,
            &signer.protected,
            Domain::Record,
            &parsed.payload,
        );
        assert_eq!(pre, rebuilt, "signer and verifier preimages diverged");
    }

    #[test]
    fn observation_rejects_missing_fields() {
        assert!(observation_payload("", hash_alg::SHA_256, &[1; 32], 1, "t", 1, b"n", SCOPE_OBSERVATION).is_err());
        assert!(observation_payload("u", hash_alg::SHA_256, &[], 1, "t", 1, b"n", SCOPE_OBSERVATION).is_err());
        assert!(observation_payload("u", hash_alg::SHA_256, &[1; 32], 1, "t", 1, b"", SCOPE_OBSERVATION).is_err());
        assert!(observation_payload("u", -1234, &[1; 32], 1, "t", 1, b"n", SCOPE_OBSERVATION).is_err());
    }

    #[test]
    fn manifest_rejects_empty_tree() {
        assert!(manifest_payload(&[0; 32], 0, 1).is_err());
    }

    #[test]
    fn unknown_alg_cannot_be_signed() {
        assert!(preimage_for(FORMAT_V1, -9999, b"k", Domain::Record, b"p").is_err());
    }

    #[test]
    fn empty_signature_rejected() {
        let signers = vec![SignerInput { alg_id: alg::ED25519, kid: b"k".to_vec(), signature: vec![] }];
        assert!(envelope(FORMAT_V1, b"p", &signers).is_err());
    }
}
