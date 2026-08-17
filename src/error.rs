//! Error type for `ahl-core`.

/// Errors produced by `ahl-core` primitives.
///
/// Everything that can be reached with data read at runtime (vector files,
/// committed seeds, receipt content) is surfaced here rather than panicking.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AhlError {
    /// A hex-encoded value could not be decoded.
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] hex::FromHexError),

    /// A base64-encoded value could not be decoded.
    #[error("invalid base64 encoding: {0}")]
    Base64(#[from] base64::DecodeError),

    /// A family string (`sha256:`, `hmac-sha256:`, `base64:`) lacked its prefix.
    #[error("expected a value prefixed with `{expected}`, got `{got}`")]
    MissingPrefix {
        /// The prefix the value was required to carry.
        expected: &'static str,
        /// The value as it was supplied (truncated by the caller if needed).
        got: String,
    },

    /// A decoded byte string had the wrong length.
    #[error("expected {expected} bytes for {what}, got {got}")]
    BadLength {
        /// What was being decoded (`ed25519 seed`, `ed25519 signature`, ...).
        what: &'static str,
        /// The required length in bytes.
        expected: usize,
        /// The length actually decoded.
        got: usize,
    },

    /// A required JSON field was absent or had the wrong JSON type.
    #[error("JSON field `{0}` is missing or has an unexpected type")]
    Field(String),

    /// Duplicate `record` values in a tree whose leaves must be record-sorted.
    ///
    /// Core spec §2.5 prohibits duplicates in AHL trees.
    #[error("duplicate record `{0}` in a record-sorted tree (spec §2.5 prohibits duplicates)")]
    DuplicateRecord(String),

    /// Caller-supplied leaf material does not recompute to the root it claims to open.
    #[error("tree material for `{root}` recomputes to `{recomputed}`")]
    TreeRootMismatch {
        /// The root the leaf set claimed to open.
        root: String,
        /// The root actually recomputed from the supplied leaves.
        recomputed: String,
    },

    /// Caller-supplied leaf material disagrees with the committed leaf count.
    #[error("tree `{root}` commits {declared} leaves, {got} were supplied")]
    TreeCountMismatch {
        /// The root whose count was declared.
        root: String,
        /// The count committed by the anchored statement.
        declared: u64,
        /// The number of leaves actually supplied.
        got: usize,
    },

    /// Leaf material violates the §2.5 ordering rule (ascending, duplicate-free).
    #[error(
        "tree `{root}`: leaf {index} (`{record}`) does not follow its predecessor in ascending \
         UTF-8 byte order (spec §2.5)"
    )]
    TreeUnsorted {
        /// The root whose leaf order is wrong.
        root: String,
        /// Index of the offending leaf.
        index: usize,
        /// The offending leaf's `record` value.
        record: String,
    },

    /// A record commitment is not a well-formed canonical family string (spec §2.5).
    #[error(
        "`{0}` is not a canonical record commitment (`sha256:`/`hmac-sha256:` + lowercase hex)"
    )]
    InvalidCommitment(String),

    /// Committed tree material was required but not supplied (spec §3.5).
    #[error(
        "no leaf material supplied for committed tree `{0}` (spec §3.5 requires retrievability)"
    )]
    MissingTreeMaterial(String),

    /// An RFC 3339 timestamp could not be parsed.
    #[error("`{value}` is not a valid RFC 3339 timestamp in field `{field}`: {source}")]
    Timestamp {
        /// The field the timestamp was read from.
        field: String,
        /// The value as supplied.
        value: String,
        /// The underlying parse failure.
        source: time::error::Parse,
    },

    /// A serialized range proof could not be parsed or did not verify (adaptor profile §8).
    #[error("range proof invalid: {0}")]
    RangeProof(String),

    /// An Ed25519 public key was structurally invalid.
    #[error("invalid ed25519 public key: {0}")]
    PublicKey(ed25519_dalek::SignatureError),

    /// A Merkle operation delegated to `atl-core` failed.
    #[error("merkle operation failed: {0}")]
    Merkle(#[from] atl_core::AtlError),

    /// JSON (de)serialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Convenience alias for results carrying [`AhlError`].
pub type AhlResult<T> = core::result::Result<T, AhlError>;
