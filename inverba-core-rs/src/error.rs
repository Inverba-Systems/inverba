//! Fail-closed error handling.
//!
//! Design rule (IRF §7, audit finding D13): a verifier has exactly two outcomes,
//! VALID and INVALID. There is no third state, no "valid but", and no default-
//! allow path. Every error constructor in this crate produces INVALID.
//!
//! `Reason` exists for local debugging and for tests. It is deliberately *not*
//! part of the remote-facing surface: returning a distinguishable reason to an
//! untrusted caller turns the verifier into an oracle ("malformed" vs "bad
//! signature" is enough to probe a signing scheme). Hosts MUST map `Invalid` to
//! a single opaque response before it crosses a trust boundary; see
//! `Invalid::opaque`.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)] // variant names are the documentation
pub enum Reason {
    // -- dCBOR layer ------------------------------------------------------
    Truncated,
    TrailingBytes,
    NonCanonicalInt,
    NonCanonicalEncoding,
    ForbiddenCborConstruct,
    DuplicateMapKey,
    UnsortedMapKeys,
    InvalidUtf8,
    DepthLimit,

    // -- structure --------------------------------------------------------
    MissingField,
    WrongType,
    UnknownFormatVersion,
    UnknownField,
    UnknownAlgorithm,
    EmptySignerSet,

    // -- merkle -----------------------------------------------------------
    BadProofLength,
    ProofMismatch,
    IndexOutOfRange,
    EmptyTree,
    SizeMismatch,

    // -- policy / crypto --------------------------------------------------
    SignatureFailed,
    RequiredAlgorithmAbsent,
    UntrustedKey,
    WitnessThresholdNotMet,
    DomainMismatch,
}

/// The only failure type this crate produces. Its existence means INVALID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Invalid {
    reason: Reason,
}

impl Invalid {
    #[must_use]
    pub const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Local-only detail. Never forward this across a trust boundary.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// The only string safe to return to an untrusted caller.
    #[must_use]
    pub const fn opaque(&self) -> &'static str {
        "INVALID"
    }
}

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "INVALID")
    }
}

impl std::error::Error for Invalid {}

/// Verification verdict. Deliberately not `bool`, so that a caller cannot
/// accidentally get a truthy value out of an uninitialised or defaulted field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum Verdict {
    /// Every required signature was present and verified.
    Valid,
    /// Anything else. There is no third state.
    Invalid,
}

impl Verdict {
    #[must_use]
    pub const fn is_valid(self) -> bool {
        matches!(self, Verdict::Valid)
    }
}

impl<T> From<Result<T, Invalid>> for Verdict {
    fn from(r: Result<T, Invalid>) -> Self {
        match r {
            Ok(_) => Verdict::Valid,
            Err(_) => Verdict::Invalid,
        }
    }
}
