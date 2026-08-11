//! # inverba-core
//!
//! Trust-critical core for Inverba provenance records.
//!
//! ## What lives here, and why only this
//!
//! Everything in this crate is reachable from the verifier and nothing else is.
//! That is the entire design constraint. A small, network-free, dependency-light
//! core is cheap to audit, and a focused third-party audit of a few thousand
//! lines is the artefact that actually moves an evidentiary buyer. Every feature
//! that does not need to be inside the trust boundary is deliberately outside it.
//!
//! In scope:
//! * deterministic CBOR encode / strict-canonical decode
//! * RFC 6962 Merkle construction, inclusion and consistency proofs
//! * domain-separated COSE `Sig_structure` preimages
//! * envelope construction and fail-closed verification
//! * policy evaluation (hybrid signature requirements, trust list, witness count)
//!
//! Explicitly **out** of scope, by design:
//! * **Network I/O.** No HTTP, no DNS, no sockets. The SSRF class of bug
//!   (audit D1) cannot exist in code that cannot open a connection. The fetcher
//!   is a separate, lower-assurance package whose output is *input* here.
//! * **Signature primitives.** Supplied by the host via
//!   [`verify::SignatureVerifier`], backed by OpenSSL 3.5 or AWS-LC-FIPS. This
//!   crate contains no cryptographic implementation beyond calling SHA-256.
//! * **Private keys.** No key material enters this crate. Hosts sign
//!   [`build::preimage_for`] output externally.
//! * **HTML, PDF, EXIF, or any content parsing.** Those parsers hit C extensions
//!   and belong in the untrusted tier.
//!
//! ## Assurance posture — stated precisely
//!
//! This crate is `#![forbid(unsafe_code)]`, denies panicking constructs by lint,
//! and carries Kani bounded-model-checking harnesses over the decoder and the
//! proof verifier. That supports exactly one honest claim:
//!
//! > The trust-critical core is written in safe Rust with machine-checked
//! > panic-freedom over bounded inputs and property proofs for specific stated
//! > properties. The remainder of the system is conventional Python.
//!
//! It does **not** support "formally verified", "seL4-grade", or "provably
//! correct". Those claims are false at this scale and asserting them converts a
//! product problem into a fraud exposure. See `CLAIMS.md`.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    clippy::todo,
    clippy::unimplemented,
    missing_debug_implementations
)]
#![warn(clippy::pedantic, missing_docs)]
#![allow(clippy::module_name_repetitions)]

// Note on `panic = "abort"`: deliberately NOT set. This crate is embedded in
// CPython via PyO3, and aborting on panic would take the host interpreter down
// with it — a denial-of-service handed to any caller who can reach a panicking
// path. The correct discipline is to make panics unreachable (the lints above)
// and for the PyO3 shim to wrap the FFI boundary in `catch_unwind`. That shim is
// not in this crate yet; it is the next piece of work, and it MUST do this.

pub mod build;
pub mod dcbor;
pub mod domain;
pub mod error;
pub mod merkle;
pub mod preimage;
pub mod verify;

pub use domain::Domain;
pub use error::{Invalid, Reason, Verdict};
pub use preimage::{SignaturePolicy, FORMAT_V1};
pub use verify::{SignatureVerifier, TrustPolicy};

/// Format identifier emitted in diagnostics and documentation.
pub const FORMAT_NAME: &str = "Inverba Record Format v1 (IRF/1)";

// ---------------------------------------------------------------------------
// Kani harnesses
//
// Run with `cargo kani`. These are bounded proofs, not universal ones: Kani
// establishes the property for all inputs up to the stated bound. That is a
// genuine and stateable result, and it is the honest limit of the claim.
//
// Priority order is deliberate. Bounded model checking on the *decoder* and the
// *proof verifier* finds the bugs that actually bite — panics, slice
// out-of-range, arithmetic overflow, and accept-on-malformed. Full functional
// proofs in Verus cost weeks per property and would not have caught any of the
// findings in the audit history.
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod proofs {
    use super::*;

    /// The decoder never panics on arbitrary bytes, and never accepts
    /// non-canonical input. Any input it accepts must re-encode to itself.
    #[kani::proof]
    #[kani::unwind(12)]
    fn decoder_total_and_canonical() {
        const N: usize = 10;
        let input: [u8; N] = kani::any();
        match dcbor::decode_canonical(&input) {
            Ok(v) => {
                // Accepted input is a fixed point of the encoder.
                assert!(dcbor::encode(&v) == input.to_vec());
            }
            Err(_) => {}
        }
    }

    /// Envelope parsing never panics on arbitrary bytes.
    #[kani::proof]
    #[kani::unwind(12)]
    fn parse_envelope_total() {
        const N: usize = 12;
        let input: [u8; N] = kani::any();
        let _ = verify::parse_envelope(&input);
    }

    /// Inclusion verification never panics for arbitrary index, size, and proof
    /// length, including the adversarial `usize::MAX` cases.
    #[kani::proof]
    #[kani::unwind(8)]
    fn verify_inclusion_total() {
        let index: usize = kani::any();
        let size: usize = kani::any();
        let leaf: merkle::Hash = kani::any();
        let root: merkle::Hash = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let proof: Vec<merkle::Hash> = (0..n).map(|_| kani::any()).collect();
        let _ = merkle::verify_inclusion(&leaf, index, size, &proof, &root);
    }

    /// An out-of-range index is always rejected, for every size.
    #[kani::proof]
    fn inclusion_rejects_index_at_or_past_size() {
        let index: usize = kani::any();
        let size: usize = kani::any();
        kani::assume(index >= size);
        let leaf: merkle::Hash = kani::any();
        let root: merkle::Hash = kani::any();
        assert!(merkle::verify_inclusion(&leaf, index, size, &[], &root).is_err());
    }

    /// A size-0 tree is always rejected — an empty commitment is never valid.
    #[kani::proof]
    fn empty_tree_always_rejected() {
        let index: usize = kani::any();
        let leaf: merkle::Hash = kani::any();
        let root: merkle::Hash = kani::any();
        assert!(merkle::verify_inclusion(&leaf, index, 0, &[], &root).is_err());
    }

    /// Domain tags are pairwise distinct, so no signature is replayable across
    /// contexts with an identical payload.
    #[kani::proof]
    fn domain_tags_distinct() {
        let all = [
            Domain::Record,
            Domain::Manifest,
            Domain::Anchor,
            Domain::Witness,
            Domain::Renewal,
        ];
        let i: usize = kani::any();
        let j: usize = kani::any();
        kani::assume(i < all.len() && j < all.len() && i != j);
        // Indexing is bounded by the assumption above.
        assert!(all[i].tag() != all[j].tag());
    }
}
