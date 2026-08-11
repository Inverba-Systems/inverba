//! Domain separation.
//!
//! Every signature IRF produces is bound to exactly one context. The tag is
//! carried in the COSE `external_aad` field of `Sig_structure` (RFC 9052 §4.4),
//! which is the idiomatic COSE mechanism for this and is length-prefixed by
//! CBOR's own bstr encoding — so there is no delimiter-injection surface.
//!
//! Consequence: a signature that verifies over a record cannot be replayed as
//! a manifest signature, an anchor signature, or a witness attestation, even if
//! the payload bytes are identical. This closes the cross-context confusion
//! class (audit finding D2).
//!
//! Tags are versioned with the format. A v2 record cannot collide with a v1
//! record because the tag itself changes.

use crate::error::{Invalid, Reason};

/// A signing context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Domain {
    /// A single observation record: "observer O saw these bytes at U at time T".
    Record,
    /// A signed Merkle root over a set of record hashes.
    Manifest,
    /// A trust-anchor signature over a manifest root (long-lived key tier).
    Anchor,
    /// A third-party witness co-signature over a record payload.
    Witness,
    /// A re-timestamping / hash-tree renewal step (RFC 4998 ERS hook).
    Renewal,
}

impl Domain {
    /// The exact bytes placed in `external_aad`.
    #[must_use]
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Domain::Record => b"inverba/1/record",
            Domain::Manifest => b"inverba/1/manifest",
            Domain::Anchor => b"inverba/1/anchor",
            Domain::Witness => b"inverba/1/witness",
            Domain::Renewal => b"inverba/1/renewal",
        }
    }

    /// Parse a tag back to a domain. Unknown tags are INVALID, never ignored.
    pub fn from_tag(tag: &[u8]) -> Result<Self, Invalid> {
        for d in [
            Domain::Record,
            Domain::Manifest,
            Domain::Anchor,
            Domain::Witness,
            Domain::Renewal,
        ] {
            if d.tag() == tag {
                return Ok(d);
            }
        }
        Err(Invalid::new(Reason::DomainMismatch))
    }
}

/// Merkle leaf prefix (RFC 6962 §2.1).
pub const MERKLE_LEAF_PREFIX: u8 = 0x00;
/// Merkle internal-node prefix (RFC 6962 §2.1).
pub const MERKLE_NODE_PREFIX: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_distinct() {
        let all = [
            Domain::Record,
            Domain::Manifest,
            Domain::Anchor,
            Domain::Witness,
            Domain::Renewal,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a.tag(), b.tag());
                }
            }
        }
    }

    #[test]
    fn no_tag_is_a_prefix_of_another() {
        // Prefix-freeness matters if a tag is ever concatenated rather than
        // length-delimited. Cheap invariant to hold.
        let all = [
            Domain::Record.tag(),
            Domain::Manifest.tag(),
            Domain::Anchor.tag(),
            Domain::Witness.tag(),
            Domain::Renewal.tag(),
        ];
        for a in all {
            for b in all {
                if a != b {
                    assert!(!b.starts_with(a), "prefix collision");
                }
            }
        }
    }

    #[test]
    fn unknown_tag_is_invalid() {
        assert!(Domain::from_tag(b"inverba/1/bogus").is_err());
        assert!(Domain::from_tag(b"").is_err());
        assert!(Domain::from_tag(b"inverba/2/record").is_err());
    }

    #[test]
    fn round_trip() {
        for d in [Domain::Record, Domain::Manifest, Domain::Anchor] {
            assert_eq!(Domain::from_tag(d.tag()).expect("known"), d);
        }
    }
}
