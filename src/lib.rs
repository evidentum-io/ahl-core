//! `ahl-core` — reference primitives and the canonical test-vector corpus for the
//! **AHL Protocol** (Anchored History Log).
//!
//! This crate implements exactly the pieces the AHL Internet-Draft draft-zatona-ahl-00
//! revision 0.4 (statements, commitments, tree rules, conformance, and — since revision 0.4 —
//! Evidence Receipts in its own §7) need in order to *produce and re-verify deterministic
//! test vectors*. This document defines revision 0.4 alone: it verifies no material issued
//! under an earlier revision (I-D §2.2, §7.1).
//!
//! * RFC 8785 (JCS) canonicalization and the two AHL identifiers — statement id and entry id
//!   (spec §2.1);
//! * canonicalization descriptors, descriptor digests and dataset id validation, and
//!   descriptor-bound, domain-separated record commitments in `plain` and `keyed` mode (AHL I-D
//!   draft-zatona-ahl-00 revision 0.4 §2.6 — see [`descriptor`]);
//! * Ed25519 statement envelopes and signed checkpoints;
//! * AHL Merkle trees — leaf `0x00 || bytes`, node `0x01 || left || right` (spec §2.5);
//! * validated committed-tree material (spec §2.5, §3.5) and authenticated range proofs
//!   (spec §3 contract item 5);
//! * revocation closure over an anchored statement graph (spec §5.1), including trigger scope
//!   (§2.3.3) and correction supersession;
//! * offline Evidence Receipt verification against the format's §5 algorithm.
//!
//! # Anti-drift
//!
//! Canonicalization, node hashing, root computation, proof generation and — critically —
//! **proof verification** are delegated to [`atl_core`], the audited sibling implementation,
//! rather than reimplemented here. AHL vectors therefore cannot silently diverge from the
//! ATL family's Merkle semantics.
//!
//! # No panic
//!
//! `ahl-core` reaches no panicking construct on any input to its three parsers — the statement
//! envelope (`statement_id`, `entry_id`, `check_envelope`, `verify_envelope`), the Evidence
//! Receipt (`receipt::verify_receipt_report`, `receipt::verify_receipt`), and the governance
//! manifest and key statement schema the §7.5.1 walk applies — under the crate's own
//! `receipt::Limits`. Malformed, hostile or simply absurd input is reported as an error or as a
//! §7.7 finding, never as an abort of the caller's process. The mechanism is the crate-level
//! lints in `Cargo.toml` (`clippy::unwrap_used`, `expect_used`, `indexing_slicing`,
//! `arithmetic_side_effects`, `panic`, `unreachable`, `todo`, `unimplemented`,
//! `missing_panics_doc`, all denied and satisfied in library code rather than allowed at a site);
//! the evidence is the three libFuzzer targets in the `fuzz/` crate. The boundary:
//! allocation failure and stack exhaustion are out of scope, since neither is a panic and neither
//! is something a library can decline; nesting depth is bounded by `serde_json`, which refuses a
//! document nested deeper than 128 levels with an error rather than recursing, so a `Value`
//! obtained by parsing bytes is already bounded when this crate sees it, while a `Value` built
//! programmatically to arbitrary depth is not and is outside the claim; total work is bounded by
//! the I-D §7.8 decoded-size budget (`Limits::max_decoded_bytes`), enforced over the canonical
//! form of the whole receipt ahead of every semantic and cryptographic check; and `atl-core` —
//! the pinned sibling that performs canonicalization, node hashing and proof verification — is
//! not covered, because the claim is about this crate's own code.
//!
//! # Test material only
//!
//! Every key in `test_data/keys/` is a published constant. Nothing in this crate is
//! suitable for production key handling.
//!
//! ```
//! use ahl_core::descriptor::CanonicalizationDescriptor;
//! use ahl_core::{commit_plain, jcs};
//! use serde_json::json;
//!
//! // A `plain` commitment is domain-separated by the dataset id, and bound to the dataset's
//! // canonicalization descriptor through its digest `ddig` (I-D revision 0.4 §2.6).
//! let descriptor = CanonicalizationDescriptor::new("jcs", None).expect("valid identifier");
//! let bytes = jcs(&json!({ "customer_id": "C-1001" }));
//! let commitment =
//!     commit_plain("scores", &descriptor.ddig(), &bytes).expect("valid dataset id");
//! assert!(commitment.starts_with("sha256:"));
//! ```

#![forbid(unsafe_code)]

pub mod bitemporal;
pub mod closure;
pub mod descriptor;
mod error;
pub mod range_proof;
pub mod receipt;
pub mod tree;

use atl_core::core::merkle::{
    compute_root, generate_consistency_proof, generate_inclusion_proof, verify_consistency,
    verify_inclusion,
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use hmac::{Hmac, Mac as _};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

pub use atl_core::core::merkle::{ConsistencyProof, Hash, InclusionProof};
pub use error::{AhlError, AhlResult};

/// The AHL Internet-Draft revision these vectors are generated against (I-D §2.2, §7.1).
///
/// This document defines revision 0.4 alone; no verification of earlier-revision material.
pub const AHL_VERSION: &str = "0.4";

/// Leaf domain-separation prefix for every AHL tree (spec §2.5).
pub const LEAF_PREFIX: u8 = 0x00;

/// Node domain-separation prefix for every AHL tree (spec §2.5).
///
/// Node hashing itself is performed by `atl_core`; the constant is restated so the
/// adaptor profile document and this crate cannot disagree about it.
pub const NODE_PREFIX: u8 = 0x01;

/// Commitment preimage separator (AHL I-D revision 0.4 §2.6).
///
/// The preimage is `dsid || 0x1F || ddig || 0x1F || canonical bytes`: this literal octet
/// separates `dsid` from the descriptor digest `ddig`, and separates `ddig` from the canonical
/// record bytes. A dataset id MUST NOT contain this octet ([`descriptor::validate_dataset_id`]),
/// which is what keeps the first occurrence in the preimage unambiguous.
pub const DATASET_SEPARATOR: u8 = 0x1F;

const SHA256_PREFIX: &str = "sha256:";
const HMAC_PREFIX: &str = "hmac-sha256:";
const BASE64_PREFIX: &str = "base64:";

pub(crate) const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

// ---------------------------------------------------------------------------
// Canonical form and identifiers (spec §2.1)
// ---------------------------------------------------------------------------

/// JCS-canonical bytes of a JSON value (RFC 8785), via `atl-core`.
#[must_use]
pub fn jcs(value: &Value) -> Vec<u8> {
    atl_core::canonicalize(value).into_bytes()
}

/// SHA-256 of `bytes`, rendered as the family string `sha256:<hex>`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{SHA256_PREFIX}{}", hex::encode(Sha256::digest(bytes)))
}

/// Statement id — SHA-256 over `JCS(payload)` (spec §2.1).
///
/// This is the reference used inside the statement graph.
///
/// # Errors
///
/// Returns [`AhlError::Field`] if `envelope` carries no `payload` object.
pub fn statement_id(envelope: &Value) -> AhlResult<String> {
    let payload = envelope
        .get("payload")
        .filter(|p| p.is_object())
        .ok_or_else(|| AhlError::Field("payload".to_owned()))?;
    Ok(sha256_hex(&jcs(payload)))
}

/// Entry id — SHA-256 over `JCS(envelope)` (spec §2.1).
///
/// This is the retrieval key of the anchored entry and the reference used wherever
/// signature or anchoring identity matters (manifest and key statements).
#[must_use]
pub fn entry_id(envelope: &Value) -> String {
    sha256_hex(&jcs(envelope))
}

// ---------------------------------------------------------------------------
// Record commitments (AHL I-D revision 0.4 §2.6)
// ---------------------------------------------------------------------------

/// `dsid || 0x1F || ddig || 0x1F || canonical bytes` — the commitment preimage (I-D §2.6).
///
/// `dsid` is validated here — both the length/printable-ASCII syntax and, as its own check, the
/// dataset id control-octet prohibition ([`descriptor::validate_dataset_id`]) — because an
/// invalid `dsid` would make the preimage's own field boundaries ambiguous.
///
/// # Errors
///
/// Returns [`AhlError::DatasetIdSyntax`] or [`AhlError::DatasetIdControlOctet`] if `dataset` is
/// not a valid dataset id.
fn commitment_input(dataset: &str, ddig: &[u8; 32], canonical: &[u8]) -> AhlResult<Vec<u8>> {
    descriptor::validate_dataset_id(dataset)?;
    // A capacity hint, saturating rather than wrapping: the exact figure is
    // `dataset + 1 + ddig + 1 + canonical`, and a saturated one only under-reserves.
    let capacity =
        dataset.len().saturating_add(ddig.len()).saturating_add(canonical.len()).saturating_add(2);
    let mut buf = Vec::with_capacity(capacity);
    buf.extend_from_slice(dataset.as_bytes());
    buf.push(DATASET_SEPARATOR);
    buf.extend_from_slice(ddig);
    buf.push(DATASET_SEPARATOR);
    buf.extend_from_slice(canonical);
    Ok(buf)
}

/// `plain` commitment — `SHA-256(dsid || 0x1F || ddig || 0x1F || canonical bytes)` (I-D §2.6).
///
/// `ddig` is the dataset's canonicalization descriptor digest
/// ([`descriptor::CanonicalizationDescriptor::ddig`]).
///
/// # Errors
///
/// Returns [`AhlError::DatasetIdSyntax`] or [`AhlError::DatasetIdControlOctet`] if `dataset` is
/// not a valid dataset id.
pub fn commit_plain(dataset: &str, ddig: &[u8; 32], canonical: &[u8]) -> AhlResult<String> {
    Ok(sha256_hex(&commitment_input(dataset, ddig, canonical)?))
}

/// `keyed` commitment —
/// `HMAC-SHA-256(k_dataset, dsid || 0x1F || ddig || 0x1F || canonical bytes)` (I-D §2.6).
///
/// Required for personal or sensitive data. The dataset key is never packaged into a
/// receipt; only an authorized verifier can recompute this value.
///
/// # Errors
///
/// Returns [`AhlError::BadLength`] if `key` cannot be used as an HMAC key, or
/// [`AhlError::DatasetIdSyntax`] / [`AhlError::DatasetIdControlOctet`] if `dataset` is not a
/// valid dataset id.
pub fn commit_keyed(
    key: &[u8],
    dataset: &str,
    ddig: &[u8; 32],
    canonical: &[u8],
) -> AhlResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| AhlError::BadLength {
        what: "hmac dataset key",
        expected: 32,
        got: key.len(),
    })?;
    mac.update(&commitment_input(dataset, ddig, canonical)?);
    Ok(format!("{HMAC_PREFIX}{}", hex::encode(mac.finalize().into_bytes())))
}

// ---------------------------------------------------------------------------
// Keys, envelopes, signatures (spec §2.1, §2.3.6, §7.2)
// ---------------------------------------------------------------------------

/// A deterministic Ed25519 test key derived from a committed 32-byte seed.
///
/// For **producer** keys the derivation is normative: core spec §2.3.6 fixes `key_id` as
/// `sha256:` plus lowercase hex SHA-256 of the raw 32-byte Ed25519 public key. Log and witness
/// key ids are adaptor-defined; the corpus adaptor profile
/// (`test_data/adaptor/ahl-test-log-v1.md` §3) adopts the same rule, and fixes the public-key
/// encoding as `base64:<raw 32 bytes>` for all three roles.
#[derive(Debug, Clone)]
pub struct TestKey {
    name: String,
    signing: SigningKey,
}

impl TestKey {
    /// Build a test key from a 64-character hex seed.
    ///
    /// # Errors
    ///
    /// Returns [`AhlError::Hex`] for non-hex input and [`AhlError::BadLength`] if the
    /// decoded seed is not exactly 32 bytes.
    pub fn from_seed_hex(name: &str, seed_hex: &str) -> AhlResult<Self> {
        let raw = hex::decode(seed_hex.trim())?;
        let seed: [u8; 32] = raw.as_slice().try_into().map_err(|_| AhlError::BadLength {
            what: "ed25519 seed",
            expected: 32,
            got: raw.len(),
        })?;
        Ok(Self { name: name.to_owned(), signing: SigningKey::from_bytes(&seed) })
    }

    /// The human-readable identity this key belongs to (`producer-1`, `log-1`, ...).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The Ed25519 public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// `key_id` as `sha256:<hex>` over the raw 32-byte public key.
    #[must_use]
    pub fn key_id(&self) -> String {
        let id = atl_core::compute_key_id(self.verifying_key().as_bytes());
        format!("{SHA256_PREFIX}{}", hex::encode(id))
    }

    /// Public key as `base64:<raw 32 bytes>`.
    #[must_use]
    pub fn pubkey(&self) -> String {
        format!("{BASE64_PREFIX}{}", B64.encode(self.verifying_key().as_bytes()))
    }

    /// Ed25519 signature over `msg`, as `base64:<raw 64 bytes>`.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> String {
        format!("{BASE64_PREFIX}{}", B64.encode(self.signing.sign(msg).to_bytes()))
    }

    /// A manifest LOG or WITNESS key object `{key_id, pubkey, valid_from_index}` (I-D §6.2).
    #[must_use]
    pub fn key_object(&self, valid_from_index: u64) -> Value {
        json!({
            "key_id": self.key_id(),
            "pubkey": self.pubkey(),
            "valid_from_index": valid_from_index,
        })
    }

    /// A manifest PRODUCER key object `{key_id, pubkey}` (I-D §6.2: "Each entry is a producer
    /// key object `{key_id, pubkey}`... A producer key object carrying any member beyond those
    /// two is a schema failure" — deliberately NOT the log/witness shape `key_object` builds:
    /// the producer array IS the key state at the manifest's entry index, with no per-key
    /// `valid_from_index` of its own).
    #[must_use]
    pub fn producer_key_object(&self) -> Value {
        json!({
            "key_id": self.key_id(),
            "pubkey": self.pubkey(),
        })
    }
}

/// Decode a `base64:<raw 32 bytes>` public key.
///
/// # Errors
///
/// Returns [`AhlError::MissingPrefix`], [`AhlError::Base64`], [`AhlError::BadLength`] or
/// [`AhlError::PublicKey`] depending on which stage rejects the input.
pub fn decode_pubkey(pubkey: &str) -> AhlResult<VerifyingKey> {
    let raw = B64.decode(strip(pubkey, BASE64_PREFIX)?)?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| AhlError::BadLength {
        what: "ed25519 public key",
        expected: 32,
        got: raw.len(),
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(AhlError::PublicKey)
}

/// Verify a `base64:<raw 64 bytes>` Ed25519 signature over `msg`.
///
/// # Errors
///
/// Returns an error when the signature string is malformed. A structurally valid but
/// mathematically wrong signature yields `Ok(false)`.
pub fn verify_signature(key: &VerifyingKey, msg: &[u8], signature: &str) -> AhlResult<bool> {
    let raw = B64.decode(strip(signature, BASE64_PREFIX)?)?;
    let bytes: [u8; 64] = raw.as_slice().try_into().map_err(|_| AhlError::BadLength {
        what: "ed25519 signature",
        expected: 64,
        got: raw.len(),
    })?;
    Ok(key.verify(msg, &ed25519_dalek::Signature::from_bytes(&bytes)).is_ok())
}

/// Build a signed statement envelope `{payload, signatures:[{key_id, sig}]}` (spec §2.1).
///
/// The signature covers `JCS(payload)`. The signature member is spelled `key_id` throughout
/// AHL — envelope, manifest key objects, `key` statements and the receipt keys block all use
/// the same spelling (spec §2.1, errata r1).
#[must_use]
pub fn envelope(payload: Value, key: &TestKey) -> Value {
    let sig = key.sign(&jcs(&payload));
    let mut env = serde_json::Map::new();
    env.insert("payload".to_owned(), payload);
    env.insert("signatures".to_owned(), json!([ { "key_id": key.key_id(), "sig": sig } ]));
    Value::Object(env)
}

/// Why [`check_envelope`] did not accept an envelope — or that it did.
///
/// The two failure variants are the same outcome under spec §2.1's envelope rule and are kept
/// apart because the AHL I-D's §7.4 makes the caller's response to them differ: an envelope
/// naming a key the presented key state does not hold is missing MATERIAL, while an envelope
/// whose signature does not verify under a key that IS held is a demonstrated defect. Which of
/// the two a given resolver reports is a property of what the caller put in the resolver, so
/// only the caller can decide what each one means.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeCheck {
    /// Every signature entry resolved to a key and verified over `JCS(payload)`.
    Verified,
    /// A signature entry did not verify under the key the resolver returned for it, or the
    /// envelope carries no signature entries at all — unsigned objects are not AHL statements
    /// (spec §2.1).
    SignatureInvalid,
    /// A signature entry names a `key_id` the resolver holds no key for, AND every entry that
    /// did resolve verified.
    ///
    /// The second half is the whole of the difference between "the verifier is short of
    /// material" and "the verifier is short of material and has also been handed a forgery".
    /// One resolvable entry that fails to verify makes the envelope [`Self::SignatureInvalid`]
    /// whatever else the array holds (spec §2.1: "invalid regardless of how many other entries
    /// verify").
    KeyNotResolved {
        /// The first `key_id`, in array order, that resolved to nothing.
        key_id: String,
    },
}

/// Verify every signature on an envelope against a `key_id -> pubkey` resolver, reporting
/// WHICH way it failed.
///
/// **Unresolved entries are swept past, and the result does not depend on the order the
/// producer chose: the first resolvable entry that fails to verify ends the sweep with a
/// conclusive `SignatureInvalid`, and an unresolved key is reported only once every
/// resolvable entry has verified.**
/// Spec §2.1 makes envelope validity "the conjunction of all entries", and an envelope
/// "carrying a non-verifying entry, or an entry naming a key that is not active at that index,
/// is invalid regardless of how many other entries verify". The two failures are therefore not
/// alternatives to be raced: an envelope can carry both at once, and the AHL I-D's §7.7
/// reduction fixes which one is reported — "`invalid` if any required finding is `invalid`;
/// otherwise `unverifiable` if any required finding is `unverifiable`… `invalid` dominates
/// `unverifiable` because a demonstrated defect in required material is a fact about the
/// artifact, while a capability gap is not."
///
/// So the precedence is `SignatureInvalid` > `KeyNotResolved` > `Verified`, and it is applied
/// as a sweep rather than an early return: a resolvable entry that fails to verify wins
/// immediately, an unresolved `key_id` is only REMEMBERED, and it is returned only once every
/// resolvable entry has verified. Returning on the first unresolved key instead would let a
/// producer downgrade a demonstrated forgery to a capability gap by ordering the array — a
/// signature the presented key state can prove is bad, reported as material the verifier merely
/// lacks. Where several entries are unresolved, the FIRST is named; they are one finding under
/// §2.1's conjunction, and naming one of them is a message-detail choice, not a verdict.
///
/// # Errors
///
/// Returns an error if the envelope shape is wrong or a resolved key cannot be decoded.
pub fn check_envelope<F>(env: &Value, resolve: F) -> AhlResult<EnvelopeCheck>
where
    F: Fn(&str) -> Option<String>,
{
    let payload = env
        .get("payload")
        .filter(|p| p.is_object())
        .ok_or_else(|| AhlError::Field("payload".to_owned()))?;
    let signatures = env
        .get("signatures")
        .and_then(Value::as_array)
        .ok_or_else(|| AhlError::Field("signatures".to_owned()))?;
    if signatures.is_empty() {
        return Ok(EnvelopeCheck::SignatureInvalid);
    }
    let msg = jcs(payload);
    let mut unresolved: Option<String> = None;
    for entry in signatures {
        let key_id = field_str(entry, "key_id")?;
        let sig = field_str(entry, "sig")?;
        let Some(pubkey) = resolve(key_id) else {
            unresolved.get_or_insert_with(|| key_id.to_owned());
            continue;
        };
        if !verify_signature(&decode_pubkey(&pubkey)?, &msg, sig)? {
            return Ok(EnvelopeCheck::SignatureInvalid);
        }
    }
    Ok(unresolved
        .map_or(EnvelopeCheck::Verified, |key_id| EnvelopeCheck::KeyNotResolved { key_id }))
}

/// Verify every signature on an envelope against a `key_id -> pubkey` resolver.
///
/// Returns `false` for an envelope with no signatures: unsigned objects are not AHL
/// statements (spec §2.1). Callers that need to tell an unresolvable `key_id` from a signature
/// that does not verify use [`check_envelope`].
///
/// # Errors
///
/// Returns an error if the envelope shape is wrong or a resolved key cannot be decoded.
pub fn verify_envelope<F>(env: &Value, resolve: F) -> AhlResult<bool>
where
    F: Fn(&str) -> Option<String>,
{
    Ok(check_envelope(env, resolve)? == EnvelopeCheck::Verified)
}

// ---------------------------------------------------------------------------
// Checkpoints (spec §1.2, §3)
// ---------------------------------------------------------------------------

/// Build a signed checkpoint `{log_id, tree_size, root_hash, checkpoint_time, key_id, signature}`.
///
/// The signature covers `JCS(checkpoint without "signature")`, as pinned by the adaptor
/// profile document.
#[must_use]
pub fn checkpoint(
    log_id: &str,
    tree_size: u64,
    root_hash: &str,
    checkpoint_time: &str,
    key: &TestKey,
) -> Value {
    // Built through the map API rather than by indexing a `Value`: `Value`'s `IndexMut` panics
    // where the target is not an object, and the signature is inserted after the unsigned form
    // has been canonicalized. JCS sorts members, so insertion order does not reach the bytes.
    let mut cp = serde_json::Map::new();
    cp.insert("log_id".to_owned(), Value::String(log_id.to_owned()));
    cp.insert("tree_size".to_owned(), Value::from(tree_size));
    cp.insert("root_hash".to_owned(), Value::String(root_hash.to_owned()));
    cp.insert("checkpoint_time".to_owned(), Value::String(checkpoint_time.to_owned()));
    cp.insert("key_id".to_owned(), Value::String(key.key_id()));
    let sig = key.sign(&jcs(&Value::Object(cp.clone())));
    cp.insert("signature".to_owned(), Value::String(sig));
    Value::Object(cp)
}

/// The bytes a log signs for `cp`: `JCS(cp)` with `signature` removed.
///
/// # Errors
///
/// Returns [`AhlError::Field`] if `cp` is not a JSON object.
pub fn checkpoint_signing_bytes(cp: &Value) -> AhlResult<Vec<u8>> {
    let mut object =
        cp.as_object().cloned().ok_or_else(|| AhlError::Field("checkpoint".to_owned()))?;
    object.remove("signature");
    Ok(jcs(&Value::Object(object)))
}

/// Render a Unix nanosecond timestamp in the exact form adaptor profile `ahl-adaptor-atl-v1`
/// §6.3 requires: UTC, exactly nine fractional-second digits, `Z` suffix.
///
/// A `nanos` value outside the representable instant range renders the Unix epoch rather than
/// aborting: every conversion and the sub-second addition are checked, so the function reaches
/// no panicking construct for any input.
#[must_use]
pub fn atl_checkpoint_time(nanos: u64) -> String {
    let whole = i64::try_from(nanos / 1_000_000_000).unwrap_or(i64::MAX);
    let sub = u32::try_from(nanos % 1_000_000_000).unwrap_or(0);
    let epoch = time::OffsetDateTime::UNIX_EPOCH;
    let instant = time::OffsetDateTime::from_unix_timestamp(whole)
        .unwrap_or(epoch)
        .checked_add(time::Duration::nanoseconds(i64::from(sub)))
        .unwrap_or(epoch);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
        instant.year(),
        u8::from(instant.month()),
        instant.day(),
        instant.hour(),
        instant.minute(),
        instant.second(),
        instant.nanosecond()
    )
}

/// Assemble adaptor profile `ahl-adaptor-atl-v1` §6.1's fixed 98-byte checkpoint blob.
///
/// Built from its plain components — the byte layout a producer signs (§6.1, §6.5) and a
/// verifier both parses `raw` against and reconstructs to check a signature (§6.2, §6.4, §6.5).
///
/// | offset | size | field |
/// | --- | --- | --- |
/// | 0 | 18 | magic `ATL-Protocol-v1-CP` |
/// | 18 | 32 | Origin ID (raw SHA-256 of the log id's hex payload) |
/// | 50 | 8 | tree size, u64 little-endian |
/// | 58 | 8 | timestamp, u64 little-endian Unix nanoseconds |
/// | 66 | 32 | root hash (raw SHA-256) |
#[must_use]
pub fn atl_checkpoint_blob(
    origin: &[u8; 32],
    tree_size: u64,
    timestamp_ns: u64,
    root: &[u8; 32],
) -> [u8; 98] {
    let mut blob = [0u8; 98];
    blob[0..18].copy_from_slice(b"ATL-Protocol-v1-CP");
    blob[18..50].copy_from_slice(origin);
    blob[50..58].copy_from_slice(&tree_size.to_le_bytes());
    blob[58..66].copy_from_slice(&timestamp_ns.to_le_bytes());
    blob[66..98].copy_from_slice(root);
    blob
}

/// Parse an `ahl-adaptor-atl-v1` §6.3 `checkpoint_time` rendering into its exact Unix
/// nanosecond count — the inverse of [`atl_checkpoint_time`].
///
/// §6.3: "`checkpoint_time` MUST be the UTC rendering of the ATL nanosecond timestamp with
/// EXACTLY NINE fractional digits and the `Z` suffix... verifiers MUST parse the nine
/// fractional digits back to the exact u64 nanosecond value and MUST reject a `checkpoint_time`
/// that is not in this form." This is stricter than the generic RFC 3339 grammar
/// [`bitemporal::parse_rfc3339`] accepts elsewhere in this crate (any digit count, any numeric
/// offset) — deliberately: only THIS exact rendering round-trips to the 98-byte blob a producer
/// actually signed (§6.1), so any other rendering is rejected outright here rather than
/// "generously" converted.
///
/// # Errors
///
/// Returns [`AhlError::AtlCheckpoint`] if `value` is not exactly this rendering.
pub fn atl_checkpoint_time_nanos(value: &str) -> AhlResult<u64> {
    let invalid = || {
        AhlError::AtlCheckpoint(format!(
            "checkpoint_time `{value}`: not the required rendering for an ATL-shaped \
             checkpoint — exactly nine fractional-second digits and a literal `Z`"
        ))
    };
    // "YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ" is exactly 30 ASCII bytes: a literal `.` at offset 19
    // and a literal `Z` at the last byte, with nine ASCII digits between them — checked here
    // directly rather than trusted to whatever the generic RFC 3339 parser happens to accept.
    let bytes = value.as_bytes();
    if bytes.len() != 30
        || bytes.get(19) != Some(&b'.')
        || bytes.get(29) != Some(&b'Z')
        || !value.get(20..29).is_some_and(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(invalid());
    }
    let parsed = bitemporal::parse_rfc3339("checkpoint_time", value).map_err(|_| invalid())?;
    let seconds = u64::try_from(parsed.unix_timestamp()).map_err(|_| invalid())?;
    let nanos = u64::from(parsed.nanosecond());
    seconds.checked_mul(1_000_000_000).and_then(|s| s.checked_add(nanos)).ok_or_else(invalid)
}

/// Assemble the `ahl-adaptor-atl-v1` §6.1 98-byte blob FROM a receipt-borne checkpoint's own
/// JSON members — `log_id`, `tree_size`, `checkpoint_time`, `root_hash` — under the §6.2
/// mapping table.
///
/// This is the exact reverse of parsing `raw`: the same layout ([`atl_checkpoint_blob`]), built
/// from the JSON side rather than read from the wire side, so [`reconcile_atl_checkpoint_raw`]
/// (compare a carried `raw` against it) and [`checkpoint_signing_bytes_for`] (the bytes the log
/// actually signs, §6.5 steps 1-2) share one assembler rather than two hand-written copies of
/// the same layout.
///
/// # Errors
///
/// Returns [`AhlError::AtlCheckpoint`] if a required member is absent or malformed.
pub fn atl_checkpoint_blob_from_json(checkpoint: &Value) -> AhlResult<[u8; 98]> {
    let invalid = |detail: String| AhlError::AtlCheckpoint(format!("checkpoint: {detail}"));

    let log_id = checkpoint
        .get("log_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("`log_id` is REQUIRED".to_owned()))?;
    let origin = hex::decode(log_id.strip_prefix(SHA256_PREFIX).unwrap_or(log_id))
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            invalid(
                "`log_id` is not a `sha256:` family string in lowercase hex, so it is not an \
                 Origin ID an ATL-shaped checkpoint blob can carry"
                    .to_owned(),
            )
        })?;
    let tree_size = checkpoint
        .get("tree_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("`tree_size` is REQUIRED, an entry count".to_owned()))?;
    let checkpoint_time = checkpoint
        .get("checkpoint_time")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("`checkpoint_time` is REQUIRED".to_owned()))?;
    let timestamp_ns = atl_checkpoint_time_nanos(checkpoint_time)?;
    let root_hash = checkpoint
        .get("root_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("`root_hash` is REQUIRED".to_owned()))?;
    let root = hex::decode(root_hash.strip_prefix(SHA256_PREFIX).unwrap_or(root_hash))
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            invalid(
                "`root_hash` is not a `sha256:` family string in lowercase hex, so it is not \
                 a root an ATL-shaped checkpoint blob can carry"
                    .to_owned(),
            )
        })?;

    Ok(atl_checkpoint_blob(&origin, tree_size, timestamp_ns, &root))
}

/// The bytes a checkpoint's own log signature is verified over, dispatched on the resolved
/// adaptor profile (I-D §3.2: the checkpoint's signing form is profile-defined).
///
/// `ahl-test-log-v1` signs `JCS(checkpoint minus "signature")` ([`checkpoint_signing_bytes`],
/// its own §5); the ATL-shaped profiles ([`is_atl_shaped`]) sign the 98-byte blob of
/// [`atl_checkpoint_blob_from_json`]. Any other profile id has no procedure here.
///
/// This is a MECHANICAL, profile-string dispatcher: which ARTIFACT a policy must hold under an
/// id is decided elsewhere, and is what separates the two ATL-shaped ids.
///
/// # Errors
///
/// Returns [`AhlError::Field`] for a profile id this crate has no procedure for.
pub fn checkpoint_signing_bytes_for(checkpoint: &Value, profile_id: &str) -> AhlResult<Vec<u8>> {
    if profile_id == TEST_PROFILE_ID {
        return checkpoint_signing_bytes(checkpoint);
    }
    if is_atl_shaped(profile_id) {
        return Ok(atl_checkpoint_blob_from_json(checkpoint)?.to_vec());
    }
    Err(AhlError::Field(format!(
        "no checkpoint signing-bytes procedure for adaptor profile `{profile_id}`"
    )))
}

/// Reconcile a carried `ahl-adaptor-atl-v1` `raw` framing against the assembled blob.
///
/// Compares against the blob assembled from a checkpoint's own JSON members (adaptor §6.4,
/// §6.5 step 3: "compare it byte for byte with the assembled blob; a mismatch is a rejection")
/// — not a looser field-by-field comparison that could accept a `raw` differing only in, say,
/// unused padding no such blob has.
///
/// # Errors
///
/// Returns [`AhlError::AtlCheckpoint`] if `raw` does not decode to exactly 98 octets prefixed
/// `base64:`, does not carry the `ATL-Protocol-v1-CP` magic, or does not equal the blob
/// [`atl_checkpoint_blob_from_json`] assembles from `checkpoint`.
pub fn reconcile_atl_checkpoint_raw(checkpoint: &Value, raw: &str) -> AhlResult<()> {
    let invalid = |detail: String| AhlError::AtlCheckpoint(format!("raw: {detail}"));

    let encoded = raw.strip_prefix(BASE64_PREFIX).ok_or_else(|| {
        invalid("`raw` MUST be `base64:<...>` for an ATL-shaped checkpoint framing".to_owned())
    })?;
    let bytes = B64
        .decode(encoded)
        .map_err(|source| invalid(format!("`raw` does not decode as base64: {source}")))?;
    let Ok(carried): core::result::Result<[u8; 98], _> = bytes.try_into() else {
        return Err(invalid(
            "`raw` MUST decode to exactly 98 octets for an ATL-shaped checkpoint framing"
                .to_owned(),
        ));
    };
    if carried[0..18] != *b"ATL-Protocol-v1-CP" {
        return Err(invalid("`raw`'s magic is not `ATL-Protocol-v1-CP`".to_owned()));
    }
    let assembled = atl_checkpoint_blob_from_json(checkpoint)?;
    if carried != assembled {
        return Err(invalid(
            "`raw` does not equal the blob assembled from the JSON checkpoint members — the \
             JSON members govern"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Build a signed checkpoint under adaptor profile `ahl-adaptor-atl-v1`.
///
/// The Ed25519 signature is over the 98-byte blob of [`atl_checkpoint_blob`] (§6.1, §6.5), not
/// `JCS(cp minus "signature")` — the form [`checkpoint`] builds, which is `ahl-test-log-v1`'s
/// own (its §5).
///
/// # Errors
///
/// Returns [`AhlError::Hex`]/[`AhlError::BadLength`] if `log_id` or `root_hash` are not
/// `sha256:<hex>` family strings over exactly 32 octets.
pub fn atl_checkpoint(
    log_id: &str,
    tree_size: u64,
    root_hash: &str,
    timestamp_ns: u64,
    key: &TestKey,
) -> AhlResult<Value> {
    let origin = parse_hash_hex(log_id)?;
    let root = parse_hash_hex(root_hash)?;
    let blob = atl_checkpoint_blob(&origin, tree_size, timestamp_ns, &root);
    let checkpoint_time = atl_checkpoint_time(timestamp_ns);
    let signature = key.sign(&blob);
    Ok(json!({
        "log_id": log_id,
        "tree_size": tree_size,
        "root_hash": root_hash,
        "checkpoint_time": checkpoint_time,
        "key_id": key.key_id(),
        "signature": signature,
    }))
}

/// The members a cosigned checkpoint object carries, and the only ones (adaptor
/// `ahl-adaptor-atl-v1` §11.1), plus `raw`, which is accepted on the way in and dropped.
const COSIGNED_MEMBERS_AND_RAW: [&str; 7] =
    ["log_id", "tree_size", "root_hash", "checkpoint_time", "key_id", "signature", "raw"];

/// The checkpoint projection a witness cosigns: exactly the six members adaptor
/// `ahl-adaptor-atl-v1` §6.2 defines, and nothing else.
///
/// §11.1: "The cosigned checkpoint object contains exactly `{log_id, tree_size, root_hash,
/// checkpoint_time, key_id, signature}` — the six members §6.2 defines — and nothing else...
/// `raw` (§6.4), where carried in any receipt-borne checkpoint — `anchoring.checkpoint`,
/// `later_checkpoint`, a rotation-proof checkpoint alike — is EXCLUDED from the cosignature
/// preimage; any other checkpoint member is `invalid` (I-D §7.1 permits `raw` alone as
/// optional). A witness therefore cosigns a typed six-member projection of the checkpoint,
/// never the JSON object as received, and a verifier reconstructs the cosigned object from
/// those six members alone."
///
/// The type exists so that the preimage cannot depend on what a checkpoint happened to carry.
/// A `Value` handed straight to a serializer puts every member it holds into the bytes two
/// implementations must agree on, and `raw` is exactly such a member: optional, carried by
/// receipts under a profile that defines a binary framing, and absent from what the witness
/// signed. [`CosignedCheckpoint::project`] is the only way to build one, and
/// [`cosignature_bytes`] takes nothing else, so the two sides cannot drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosignedCheckpoint {
    /// `"sha256:" || hex(Origin ID)` (§6.2).
    log_id: String,
    /// Number of entries the checkpoint commits, `[0, tree_size)`.
    tree_size: u64,
    /// `"sha256:" || hex(root)` (§6.2).
    root_hash: String,
    /// The checkpoint's own time rendering (§6.3 under an ATL-shaped profile).
    checkpoint_time: String,
    /// `"sha256:" || hex(SHA-256(raw pubkey))` of the LOG's signing key.
    key_id: String,
    /// The log's signature over the checkpoint. §11.1 binds it deliberately: "a cosignature
    /// attests to a checkpoint the log actually signed, not merely to values a witness was
    /// shown."
    signature: String,
}

impl CosignedCheckpoint {
    /// Project a receipt-borne checkpoint object onto the six members §11.1 cosigns.
    ///
    /// Accepts `raw` and drops it — I-D §7.1 permits that member alone as optional, and §11.1
    /// excludes it from the preimage — and refuses any other member rather than carrying it
    /// into bytes a second implementation would not reproduce.
    ///
    /// This reads the six members and their JSON types, and nothing more: whether `log_id` is
    /// a well-formed family string, whether `checkpoint_time` renders as §6.3 requires, and
    /// whether the signature verifies are separate questions, answered where each belongs.
    ///
    /// # Errors
    ///
    /// Returns [`AhlError::CosignedCheckpoint`] if the value is not an object, if one of the
    /// six members is absent or has the wrong JSON type, or if it carries a member other than
    /// those six and `raw`.
    pub fn project(checkpoint: &Value) -> AhlResult<Self> {
        let invalid = |detail: String| AhlError::CosignedCheckpoint(detail);
        let members = checkpoint
            .as_object()
            .ok_or_else(|| invalid("a checkpoint MUST be a JSON object (I-D §7.1)".to_owned()))?;
        if let Some(extra) =
            members.keys().find(|member| !COSIGNED_MEMBERS_AND_RAW.contains(&member.as_str()))
        {
            return Err(invalid(format!(
                "checkpoint carries `{extra}`, which is neither one of the six members the \
                 cosigned object contains nor `raw`: adaptor §11.1 makes any other checkpoint \
                 member invalid"
            )));
        }
        let text = |member: &str| -> AhlResult<String> {
            members
                .get(member)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| invalid(format!("`{member}` is REQUIRED, a string")))
        };
        let tree_size = members
            .get("tree_size")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("`tree_size` is REQUIRED, an entry count".to_owned()))?;
        Ok(Self {
            log_id: text("log_id")?,
            tree_size,
            root_hash: text("root_hash")?,
            checkpoint_time: text("checkpoint_time")?,
            key_id: text("key_id")?,
            signature: text("signature")?,
        })
    }

    /// The cosigned checkpoint object itself, as §11.1 draws it.
    ///
    /// Destructured rather than field-accessed so that a member added to the struct without a
    /// decision about the preimage fails to compile instead of silently staying out of it.
    fn object(&self) -> Value {
        let Self { log_id, tree_size, root_hash, checkpoint_time, key_id, signature } = self;
        json!({
            "log_id": log_id,
            "tree_size": tree_size,
            "root_hash": root_hash,
            "checkpoint_time": checkpoint_time,
            "key_id": key_id,
            "signature": signature,
        })
    }
}

/// The bytes a witness cosigns (adaptor `ahl-adaptor-atl-v1` §11.1):
/// `JCS({"checkpoint": <the six-member projection>, "witness_id": <id>})`.
///
/// §11.1 fixes both halves of the preimage. The checkpoint half is the six-member projection
/// of [`CosignedCheckpoint`] — "the cosigned checkpoint object contains exactly `{log_id,
/// tree_size, root_hash, checkpoint_time, key_id, signature}`... and nothing else", with `raw`
/// excluded wherever a receipt carries it. The `witness_id` half binds the cosignature to one
/// identity, "so a cosignature cannot be replayed for another witness".
///
/// Taking the projection rather than a `Value` is what makes the rule hold at every call site:
/// a producer and a verifier reach these bytes through the same constructor, so a checkpoint
/// that carries `raw` cosigns and re-verifies identically to one that does not.
#[must_use]
pub fn cosignature_bytes(checkpoint: &CosignedCheckpoint, witness_id: &str) -> Vec<u8> {
    jcs(&json!({ "checkpoint": checkpoint.object(), "witness_id": witness_id }))
}

// ---------------------------------------------------------------------------
// AHL trees (spec §2.5)
// ---------------------------------------------------------------------------

/// The fixed ATL metadata object adaptor profile `ahl-adaptor-atl-v1` §4.2 pins.
///
/// "The ATL metadata object is FIXED and carries no AHL data... Its JCS form is the 36 bytes
/// shown." Pinning it rather than using it keeps a log leaf a pure function of the anchored
/// entry: ATL metadata is operator-supplied and covered by no AHL signature, so AHL data placed
/// there would make an entry's leaf depend on bytes outside the signed envelope.
pub const ATL_METADATA: &str = r#"{"ahl_adaptor":"ahl-adaptor-atl-v1"}"#;

/// `SHA-256(JCS(ATL metadata))` — the constant second digest of every ATL log leaf (§4.2).
///
/// Recomputed here rather than transcribed; the profile document publishes the same value, and
/// a unit test holds the two together.
#[must_use]
pub fn atl_metadata_hash() -> Hash {
    Sha256::digest(ATL_METADATA.as_bytes()).into()
}

/// Adaptor profile id of the corpus's own minimal test profile.
pub const TEST_PROFILE_ID: &str = "ahl-test-log-v1";

/// Adaptor profile id of the ATL binding.
///
/// The profile is released, and this crate ships its artifact: [`ATL_PROFILE_DOCUMENT`] holds
/// the exact bytes and [`ATL_PROFILE_DIGEST`] the digest they hash to. `ahl-adaptor-atl-v1`
/// §14 makes the profile digest the SHA-256 over the exact bytes of the released artifact and
/// adds that "any change to this document, however small, produces a different hash and
/// therefore a different profile. A changed profile MUST be published under a new id." A
/// profile's identity is therefore its bytes, which is why the artifact is shipped verbatim
/// rather than restated: a client pinning `{id, digest}` under this id takes both from here.
///
/// The conformance corpus is a separate matter. It pins [`TEST_ATL_PROFILE_ID`] throughout and
/// pins this id nowhere, by design — see that constant. For a verifier whose policy holds no
/// artifact under this id the outcome stays I-D §7.5 step 2's `unverifiable`.
pub const ATL_PROFILE_ID: &str = "ahl-adaptor-atl-v1";

/// The released `ahl-adaptor-atl-v1` artifact, verbatim — 110 320 bytes.
///
/// The bytes are what [`ATL_PROFILE_DIGEST`] is the SHA-256 of, and a unit test recomputes the
/// digest over them rather than trusting either transcription. Released at
/// `https://ahl-protocol.org/profiles/ahl-adaptor-atl-v1.md`; the copy shipped here is the same
/// artifact, so a client can pin `{`[`ATL_PROFILE_ID`]`, `[`ATL_PROFILE_DIGEST`]`}` from the
/// crate instead of fetching the document to learn its own digest.
pub const ATL_PROFILE_DOCUMENT: &[u8] =
    include_bytes!("../test_data/profiles/ahl-adaptor-atl-v1.md");

/// Profile digest of the released `ahl-adaptor-atl-v1` artifact.
///
/// The `sha256:` family-string form `anchoring.adaptor.hash` and `log.adaptor.hash` carry, so
/// it is what a manifest or receipt pins directly. Equal to `sha256_hex(ATL_PROFILE_DOCUMENT)`,
/// which a unit test asserts.
pub const ATL_PROFILE_DIGEST: &str =
    "sha256:80a7defdd934242fb4986b2868f4553f0a245995c96ffe543baff59f6bb805aa";

/// Adaptor profile id of the conformance corpus's own ATL-shaped test profile.
///
/// A separate profile with a document of its own, and deliberately not a stand-in for the one
/// above: that document defines the leaf construction, checkpoint blob, `raw` framing,
/// origin-derived log id, tree geometry and range form AS ITS OWN rules, citing the ATL adaptor
/// profile as where the shape comes from and claiming nothing about being that profile. The
/// serialization is identical, which is the point — the corpus exercises those rules under an
/// identity it may actually publish.
///
/// The corpus keeps pinning this id now that [`ATL_PROFILE_ID`]'s artifact is released and
/// shipped, and that is deliberate: a toy log's checkpoints are signed by a toy key over a toy
/// tree, so binding them to the real ATL binding's id would assert a conformance claim the
/// corpus cannot make. What the corpus exercises is the serialization, which both ids share.
pub const TEST_ATL_PROFILE_ID: &str = "ahl-test-atl-leaf-v1";

/// Whether `profile_id` names a profile whose serialization is the ATL-shaped one.
///
/// Two ids reach the same procedures: the ATL binding itself and the corpus's own ATL-shaped
/// test profile. What differs between them is which ARTIFACT a policy must hold, never how a
/// checkpoint is signed or a leaf is built.
#[must_use]
pub const fn is_atl_shaped(profile_id: &str) -> bool {
    matches!(profile_id.as_bytes(), b"ahl-adaptor-atl-v1" | b"ahl-test-atl-leaf-v1")
}

/// `log_id` for an ATL-bound corpus: `"sha256:" || hex(Origin ID)`, where the Origin ID is
/// ATL's SHA-256 over the 16-byte Data Tree UUID (adaptor §7.1).
///
/// A verifier never needs the UUID — the Origin ID is what the 98-byte checkpoint blob binds
/// and what the manifest pins — so this exists for the producer side, and to state in one place
/// that an ATL `log_id` is not a free-form identifier.
#[must_use]
pub fn atl_log_id(tree_uuid: &[u8; 16]) -> String {
    sha256_hex(tree_uuid)
}

/// The leaf PREIMAGE of one anchored log entry under `profile_id` — the bytes
/// [`leaf_hash`] prefixes with `0x00`.
///
/// The two profiles this crate implements build a log leaf differently, and nothing else about
/// a log tree differs:
///
/// * `ahl-test-log-v1` (its §2.1) hashes the anchored entry bytes directly, so the preimage is
///   `JCS(envelope)`;
/// * the ATL-shaped profiles ([`is_atl_shaped`]) combine two digests, so the preimage is
///   `SHA-256(JCS(envelope)) || METADATA_HASH` and the leaf is
///   `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)`. The first digest is the raw
///   form of the AHL entry id, which is why the entry id stays derivable from the entry bytes
///   alone.
///
/// The asymmetry stops at the log tree. Batch output, input-set and disposition trees are AHL
/// constructs the log never sees, so they take plain leaf hashing under BOTH profiles (ATL
/// adaptor §9: "An implementation MUST NOT apply the payload/metadata leaf construction to
/// them").
///
/// # Errors
///
/// Returns [`AhlError::Field`] for a profile id this crate has no log-leaf construction for.
pub fn log_leaf_bytes_for(envelope: &Value, profile_id: &str) -> AhlResult<Vec<u8>> {
    if profile_id == TEST_PROFILE_ID {
        return Ok(jcs(envelope));
    }
    if is_atl_shaped(profile_id) {
        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(&Sha256::digest(jcs(envelope)));
        preimage.extend_from_slice(&atl_metadata_hash());
        return Ok(preimage);
    }
    Err(AhlError::Field(format!("no log-leaf construction for adaptor profile `{profile_id}`")))
}

/// AHL leaf hash — `SHA-256(0x00 || bytes)`.
#[must_use]
pub fn leaf_hash(bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Root over raw leaf byte strings; leaf hashing is applied here, node hashing by `atl-core`.
#[must_use]
pub fn tree_root(leaves: &[Vec<u8>]) -> Hash {
    let hashes: Vec<Hash> = leaves.iter().map(|leaf| leaf_hash(leaf)).collect();
    compute_root(&hashes)
}

/// Inclusion proof for leaf `index`, generated by `atl-core`.
///
/// # Errors
///
/// Returns [`AhlError::Merkle`] if `index` is out of bounds or `leaves` is empty.
pub fn inclusion_proof(leaves: &[Vec<u8>], index: usize) -> AhlResult<InclusionProof> {
    let hashes: Vec<Hash> = leaves.iter().map(|leaf| leaf_hash(leaf)).collect();
    let proof = generate_inclusion_proof(index as u64, hashes.len() as u64, |level, i| {
        if level == 0 {
            hashes.get(usize::try_from(i).ok()?).copied()
        } else {
            None
        }
    })?;
    Ok(proof)
}

/// Verify an inclusion proof for raw leaf bytes.
///
/// The verification step is delegated to [`atl_core::core::merkle::verify_inclusion`] and is
/// never reimplemented locally — this is the anti-drift coupling between AHL and ATL.
///
/// # Errors
///
/// Returns [`AhlError::Merkle`] if the proof is structurally invalid.
pub fn verify_inclusion_proof(leaf: &[u8], proof: &InclusionProof, root: &Hash) -> AhlResult<bool> {
    Ok(verify_inclusion(&leaf_hash(leaf), proof, root)?)
}

/// RFC 9162 §2.1.4 consistency proof between two sizes of one log tree.
///
/// Generation, like inclusion-proof generation, is delegated to [`atl_core`]; only the leaf
/// hashing is local. `leaves` must be the log's leaf byte strings up to at least `to_size`.
///
/// # Errors
///
/// Returns [`AhlError::Merkle`] if `from_size` exceeds `to_size` or `to_size` exceeds the
/// leaf material supplied.
pub fn consistency_proof(
    leaves: &[Vec<u8>],
    from_size: u64,
    to_size: u64,
) -> AhlResult<ConsistencyProof> {
    let hashes: Vec<Hash> = leaves.iter().map(|leaf| leaf_hash(leaf)).collect();
    Ok(generate_consistency_proof(from_size, to_size, |level, index| {
        if level == 0 {
            hashes.get(usize::try_from(index).ok()?).copied()
        } else {
            None
        }
    })?)
}

/// Verify a consistency proof, so an older root is shown to be a prefix of a newer one.
///
/// The verification step is [`atl_core::core::merkle::verify_consistency`], never a local
/// reimplementation — the same anti-drift coupling inclusion proofs use.
///
/// # Errors
///
/// Returns [`AhlError::Merkle`] if the proof is structurally impossible for its declared
/// sizes. A structurally valid proof that simply does not prove consistency yields `Ok(false)`.
pub fn verify_consistency_proof(
    proof: &ConsistencyProof,
    old_root: &Hash,
    new_root: &Hash,
) -> AhlResult<bool> {
    Ok(verify_consistency(proof, old_root, new_root)?)
}

/// A consistency-proof path rendered as `["sha256:<hex>", ...]`, in RFC 9162 order.
#[must_use]
pub fn consistency_path_hex(proof: &ConsistencyProof) -> Vec<String> {
    proof.path.iter().map(hash_hex).collect()
}

/// Rebuild a [`ConsistencyProof`] from its serialized path.
///
/// # Errors
///
/// Returns an error if any path element is not a valid `sha256:<hex>` string.
pub fn consistency_from_hex(
    from_size: u64,
    to_size: u64,
    path: &[String],
) -> AhlResult<ConsistencyProof> {
    let path = path.iter().map(|h| parse_hash_hex(h)).collect::<AhlResult<Vec<Hash>>>()?;
    Ok(ConsistencyProof { from_size, to_size, path })
}

/// Render a tree hash as `sha256:<hex>`.
#[must_use]
pub fn hash_hex(hash: &Hash) -> String {
    format!("{SHA256_PREFIX}{}", hex::encode(hash))
}

/// Parse a `sha256:<hex>` family string back into a tree hash.
///
/// # Errors
///
/// Returns [`AhlError::MissingPrefix`], [`AhlError::Hex`] or [`AhlError::BadLength`].
pub fn parse_hash_hex(value: &str) -> AhlResult<Hash> {
    let raw = hex::decode(strip(value, SHA256_PREFIX)?)?;
    raw.as_slice().try_into().map_err(|_| AhlError::BadLength {
        what: "sha-256 digest",
        expected: 32,
        got: raw.len(),
    })
}

/// An inclusion proof path rendered as `["sha256:<hex>", ...]`, leaf to root.
#[must_use]
pub fn proof_path_hex(proof: &InclusionProof) -> Vec<String> {
    proof.path.iter().map(hash_hex).collect()
}

/// Rebuild an [`InclusionProof`] from its serialized form.
///
/// # Errors
///
/// Returns an error if any path element is not a valid `sha256:<hex>` string.
pub fn proof_from_hex(
    leaf_index: u64,
    tree_size: u64,
    path: &[String],
) -> AhlResult<InclusionProof> {
    let path = path.iter().map(|h| parse_hash_hex(h)).collect::<AhlResult<Vec<Hash>>>()?;
    Ok(InclusionProof { leaf_index, tree_size, path })
}

/// Sort tree leaves ascending by their `record` field and reject duplicates (spec §2.5).
///
/// The comparison is the ascending lexicographic comparison of the **UTF-8 bytes of the
/// canonical commitment string** (`sha256:<hex>` / `hmac-sha256:<hex>`, lowercase hex).
/// Non-canonical commitment strings are rejected rather than ordered.
///
/// # Errors
///
/// Returns [`AhlError::Field`] if a leaf carries no string `record`,
/// [`AhlError::InvalidCommitment`] if a `record` is not a canonical family string, or
/// [`AhlError::DuplicateRecord`] if two leaves name the same record.
pub fn record_sorted(mut leaves: Vec<Value>) -> AhlResult<Vec<Value>> {
    for leaf in &leaves {
        let record = field_str(leaf, "record")?;
        if !tree::is_canonical_commitment(record) {
            return Err(AhlError::InvalidCommitment(record.to_owned()));
        }
    }
    leaves.sort_by_key(record_key);
    for (left, right) in leaves.iter().zip(leaves.iter().skip(1)) {
        if record_key(left) == record_key(right) {
            return Err(AhlError::DuplicateRecord(record_key(left)));
        }
    }
    Ok(leaves)
}

fn record_key(leaf: &Value) -> String {
    leaf.get("record").and_then(Value::as_str).unwrap_or_default().to_owned()
}

// ---------------------------------------------------------------------------
// Small JSON helpers
// ---------------------------------------------------------------------------

/// Read a required string field from a JSON object.
///
/// # Errors
///
/// Returns [`AhlError::Field`] if the field is absent or not a string.
pub fn field_str<'a>(value: &'a Value, field: &str) -> AhlResult<&'a str> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| AhlError::Field(field.to_owned()))
}

fn strip<'a>(value: &'a str, prefix: &'static str) -> AhlResult<&'a str> {
    value.strip_prefix(prefix).ok_or_else(|| AhlError::MissingPrefix {
        expected: prefix,
        got: value.chars().take(24).collect(),
    })
}

/// Crate-internal re-export of [`strip`] for sibling modules.
pub(crate) fn strip_prefix<'a>(value: &'a str, prefix: &'static str) -> AhlResult<&'a str> {
    strip(value, prefix)
}

#[cfg(test)]
#[allow(
    // A test asserts; an assertion that fires IS the failure report. The crate-level no-panic
    // lints are the library's contract, not this module's.
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {

    #[test]
    fn the_atl_metadata_digest_is_the_constant_the_profile_publishes() {
        // Adaptor profile `ahl-adaptor-atl-v1` §4.2 publishes both the object and its digest.
        // Recomputing the digest here is what keeps a transcription error from silently
        // changing every ATL log leaf this crate builds.
        assert_eq!(ATL_METADATA.len(), 36, "§4.2: \"its JCS form is the 36 bytes shown\"");
        assert_eq!(
            hash_hex(&atl_metadata_hash()),
            "sha256:bb4f98461f062d897980c9050f8f859c3b83c84486c5e6857262f6dfa97468a4"
        );
    }

    #[test]
    fn the_shipped_atl_profile_artifact_hashes_to_the_pinned_digest() {
        // `ahl-adaptor-atl-v1` §14: a profile's identity is the SHA-256 over the exact bytes of
        // the released artifact. Recomputing it over the shipped bytes is what makes the
        // constant a fact about the file rather than a transcription a client has to trust.
        assert_eq!(ATL_PROFILE_DOCUMENT.len(), 110_320);
        assert_eq!(sha256_hex(ATL_PROFILE_DOCUMENT), ATL_PROFILE_DIGEST);
        assert!(ATL_PROFILE_DIGEST.starts_with(SHA256_PREFIX));
        // The released artifact is a second document under a second id; it changes nothing
        // about which serialization the id reaches.
        assert!(is_atl_shaped(ATL_PROFILE_ID));
        // And it is NOT the corpus's own profile — different bytes, different digest.
        assert_ne!(sha256_hex(TEST_ATL_PROFILE_DOCUMENT), ATL_PROFILE_DIGEST);
    }

    /// The corpus's own ATL-shaped profile, read for the inequality above only.
    const TEST_ATL_PROFILE_DOCUMENT: &[u8] =
        include_bytes!("../test_data/profiles/ahl-test-atl-leaf-v1.md");

    #[test]
    fn the_two_profiles_build_a_log_leaf_differently() {
        let key = TestKey::from_seed_hex("t", &"01".repeat(32)).expect("seed");
        let env = envelope(json!({ "type": "ingestion" }), &key);

        // `ahl-test-log-v1` §2.1: the preimage IS the anchored entry bytes.
        let test_leaf = log_leaf_bytes_for(&env, TEST_PROFILE_ID).expect("test profile");
        assert_eq!(test_leaf, jcs(&env));

        // `ahl-adaptor-atl-v1` §4.2: `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)`,
        // and the first digest is the raw form of the AHL entry id.
        let atl_leaf = log_leaf_bytes_for(&env, ATL_PROFILE_ID).expect("atl profile");
        // The corpus's own ATL-shaped profile is a DIFFERENT profile with a different artifact,
        // and the same serialization: the two ids reach one procedure, which is what lets the
        // conformance corpus exercise these rules under an identity it may actually publish.
        assert_eq!(
            log_leaf_bytes_for(&env, TEST_ATL_PROFILE_ID).expect("test atl profile"),
            atl_leaf
        );
        assert!(is_atl_shaped(ATL_PROFILE_ID) && is_atl_shaped(TEST_ATL_PROFILE_ID));
        assert!(!is_atl_shaped(TEST_PROFILE_ID));
        assert_eq!(atl_leaf.len(), 64);
        assert_eq!(sha256_hex(&jcs(&env)), entry_id(&env));
        assert_eq!(&atl_leaf[..32], &parse_hash_hex(&entry_id(&env)).expect("entry id")[..]);
        assert_eq!(&atl_leaf[32..], &atl_metadata_hash()[..]);
        assert_ne!(hash_hex(&leaf_hash(&atl_leaf)), hash_hex(&leaf_hash(&test_leaf)));

        assert!(log_leaf_bytes_for(&env, "ahl-adaptor-something-else").is_err());
    }
    use super::*;

    const SEED: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn key() -> TestKey {
        TestKey::from_seed_hex("producer-1", SEED).expect("committed 32-byte test seed")
    }

    #[test]
    fn identifiers_are_distinct_and_stable() {
        let env = envelope(json!({ "type": "ingestion", "record": "sha256:00" }), &key());
        let sid = statement_id(&env).expect("well-formed envelope");
        let eid = entry_id(&env);
        assert_ne!(sid, eid, "statement id (payload) must differ from entry id (envelope)");
        assert_eq!(sid, statement_id(&env).expect("well-formed envelope"));
    }

    fn ddig() -> [u8; 32] {
        descriptor::CanonicalizationDescriptor::new("jcs", None).expect("valid identifier").ddig()
    }

    #[test]
    fn commitments_are_domain_separated_by_dataset() {
        let bytes = jcs(&json!({ "a": 1 }));
        let ddig = ddig();
        assert_ne!(
            commit_plain("customers", &ddig, &bytes).expect("valid dataset id"),
            commit_plain("scores", &ddig, &bytes).expect("valid dataset id")
        );
    }

    #[test]
    fn keyed_commitment_differs_from_plain() {
        let bytes = jcs(&json!({ "a": 1 }));
        let ddig = ddig();
        let keyed = commit_keyed(&[7u8; 32], "customers", &ddig, &bytes).expect("32-byte key");
        assert!(keyed.starts_with("hmac-sha256:"));
        assert_ne!(keyed, commit_plain("customers", &ddig, &bytes).expect("valid dataset id"));
    }

    #[test]
    fn commit_plain_rejects_an_invalid_dataset_id() {
        let bytes = jcs(&json!({ "a": 1 }));
        let bad = format!("bad{}id", '\u{1f}');
        assert!(matches!(
            commit_plain(&bad, &ddig(), &bytes),
            Err(AhlError::DatasetIdControlOctet { .. })
        ));
    }

    #[test]
    fn envelope_signature_round_trips() {
        let k = key();
        let env = envelope(json!({ "type": "key" }), &k);
        let resolve = |id: &str| (id == k.key_id()).then(|| k.pubkey());
        assert!(verify_envelope(&env, resolve).expect("well-formed envelope"));
    }

    #[test]
    fn unsigned_envelope_is_rejected() {
        let env = json!({ "payload": { "type": "key" }, "signatures": [] });
        assert!(!verify_envelope(&env, |_| None).expect("well-formed envelope"));
    }

    /// The two ways a signature check fails are separated, because callers act on them
    /// differently (AHL I-D §7.4). `verify_envelope` collapses both to `false`.
    #[test]
    fn check_envelope_separates_an_unresolvable_key_from_a_bad_signature() {
        let k = key();
        let env = envelope(json!({ "type": "key" }), &k);
        let resolve = |id: &str| (id == k.key_id()).then(|| k.pubkey());

        assert_eq!(check_envelope(&env, resolve).expect("well formed"), EnvelopeCheck::Verified);
        assert_eq!(
            check_envelope(&env, |_| None).expect("well formed"),
            EnvelopeCheck::KeyNotResolved { key_id: k.key_id() }
        );

        // The key resolves; the signature does not verify over this payload.
        let mut tampered = env;
        tampered["payload"]["type"] = json!("manifest");
        assert_eq!(
            check_envelope(&tampered, resolve).expect("well formed"),
            EnvelopeCheck::SignatureInvalid
        );

        let unsigned = json!({ "payload": { "type": "key" }, "signatures": [] });
        assert_eq!(
            check_envelope(&unsigned, |_| None).expect("well formed"),
            EnvelopeCheck::SignatureInvalid
        );
    }

    /// Spec §2.1 makes envelope validity "the conjunction of all entries", so an envelope
    /// carrying BOTH defects is invalid whichever order the producer wrote them in: the AHL
    /// I-D's §7.7 reduction has `invalid` dominate `unverifiable`. Returning on the first
    /// unresolved key would let the array order downgrade a demonstrated forgery to a
    /// capability gap.
    #[test]
    fn a_resolvable_bad_signature_outranks_an_unresolvable_key_in_either_order() {
        let signer = key();
        let payload = json!({ "type": "key" });
        let good = signer.sign(&jcs(&payload));
        let bad = signer.sign(&jcs(&json!({ "type": "manifest" })));
        // Only `signer` resolves; `sha256:00…` is a key the state does not hold.
        let resolve = |id: &str| (id == signer.key_id()).then(|| signer.pubkey());
        let absent = commitment(0);

        let two = |first: Value, second: Value| json!({ "payload": payload, "signatures": [first, second] });
        let uncarried = json!({ "key_id": absent, "sig": good });
        let forged = json!({ "key_id": signer.key_id(), "sig": bad });
        let genuine = json!({ "key_id": signer.key_id(), "sig": good });

        for (env, case) in [
            (two(uncarried.clone(), forged.clone()), "uncarried first"),
            (two(forged, uncarried.clone()), "forged first"),
        ] {
            assert_eq!(
                check_envelope(&env, resolve).expect("well formed"),
                EnvelopeCheck::SignatureInvalid,
                "{case}: a resolvable non-verifying entry is invalid regardless of position"
            );
        }

        // With every resolvable entry verifying, the unresolved key is what is left to report.
        assert_eq!(
            check_envelope(&two(uncarried, genuine), resolve).expect("well formed"),
            EnvelopeCheck::KeyNotResolved { key_id: absent }
        );
    }

    #[test]
    fn inclusion_proofs_verify_through_atl_core() {
        let leaves: Vec<Vec<u8>> = (0u8..7).map(|i| vec![i; 4]).collect();
        let root = tree_root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = inclusion_proof(&leaves, i).expect("index within tree");
            assert!(verify_inclusion_proof(leaf, &proof, &root).expect("valid proof shape"));
        }
    }

    fn commitment(byte: u8) -> String {
        format!("sha256:{}", hex::encode([byte; 32]))
    }

    #[test]
    fn record_sorting_rejects_duplicates() {
        let leaves =
            vec![json!({ "record": commitment(0xaa) }), json!({ "record": commitment(0xaa) })];
        assert!(matches!(record_sorted(leaves), Err(AhlError::DuplicateRecord(_))));
    }

    #[test]
    fn record_sorting_is_ascending() {
        let leaves =
            vec![json!({ "record": commitment(0xbb) }), json!({ "record": commitment(0xaa) })];
        let sorted = record_sorted(leaves).expect("distinct records");
        assert_eq!(record_key(&sorted[0]), commitment(0xaa));
    }

    #[test]
    fn record_sorting_rejects_non_canonical_commitments() {
        let leaves = vec![json!({ "record": "sha256:aa" })];
        assert!(matches!(record_sorted(leaves), Err(AhlError::InvalidCommitment(_))));
    }

    #[test]
    fn keyed_commitments_sort_after_plain_ones() {
        // 'h' (0x68) < 's' (0x73), so every `hmac-sha256:` record precedes every `sha256:` one.
        let hmac = format!("hmac-sha256:{}", hex::encode([0xffu8; 32]));
        let leaves = vec![json!({ "record": commitment(0x00) }), json!({ "record": &hmac })];
        let sorted = record_sorted(leaves).expect("distinct records");
        assert_eq!(record_key(&sorted[0]), hmac);
    }

    #[test]
    fn wrong_length_inputs_are_rejected_with_their_lengths() {
        assert!(matches!(
            TestKey::from_seed_hex("short", "0011"),
            Err(AhlError::BadLength { what: "ed25519 seed", expected: 32, got: 2 })
        ));
        assert!(matches!(TestKey::from_seed_hex("nonhex", "zz"), Err(AhlError::Hex(_))));
        assert!(matches!(
            decode_pubkey(&format!("{BASE64_PREFIX}{}", B64.encode([0u8; 5]))),
            Err(AhlError::BadLength { what: "ed25519 public key", expected: 32, got: 5 })
        ));
        assert!(matches!(decode_pubkey("no-prefix"), Err(AhlError::MissingPrefix { .. })));
        assert!(matches!(
            verify_signature(
                &key().verifying_key(),
                b"msg",
                &format!("{BASE64_PREFIX}{}", B64.encode([0u8; 9])),
            ),
            Err(AhlError::BadLength { what: "ed25519 signature", expected: 64, got: 9 })
        ));
        assert!(matches!(
            parse_hash_hex(&format!("{SHA256_PREFIX}00ff")),
            Err(AhlError::BadLength { what: "sha-256 digest", expected: 32, got: 2 })
        ));
        assert!(matches!(parse_hash_hex("md5:00"), Err(AhlError::MissingPrefix { .. })));
    }

    #[test]
    fn hmac_accepts_any_key_length_so_dataset_keys_are_length_checked_elsewhere() {
        // `Hmac::<Sha256>::new_from_slice` never rejects a length, so `commit_keyed`'s
        // `BadLength` arm is defensive only. The corpus pins 32-byte dataset keys by
        // convention, not by this call rejecting anything else.
        let ddig = ddig();
        assert!(commit_keyed(&[7u8; 8], "customers", &ddig, b"bytes").is_ok());
        assert!(commit_keyed(&[7u8; 64], "customers", &ddig, b"bytes").is_ok());
    }

    #[test]
    fn an_unresolvable_key_id_fails_the_envelope_rather_than_erroring() {
        let env = envelope(json!({ "type": "key" }), &key());
        assert!(!verify_envelope(&env, |_| None).expect("well-formed envelope"));
    }

    #[test]
    fn a_wrong_signature_verifies_as_false_not_as_an_error() {
        let k = key();
        let other = TestKey::from_seed_hex("other", &"02".repeat(32)).expect("32-byte seed");
        let env = envelope(json!({ "type": "key" }), &k);
        let sig = field_str(&env["signatures"][0], "sig").expect("signature");
        assert!(!verify_signature(&other.verifying_key(), &jcs(&env["payload"]), sig)
            .expect("well-formed signature"));
    }

    #[test]
    fn envelope_shape_errors_are_reported_by_field() {
        assert!(matches!(statement_id(&json!({})), Err(AhlError::Field(_))));
        assert!(matches!(verify_envelope(&json!({}), |_| None), Err(AhlError::Field(_))));
        assert!(matches!(
            verify_envelope(&json!({ "payload": {} }), |_| None),
            Err(AhlError::Field(_))
        ));
        assert!(matches!(
            checkpoint_signing_bytes(&json!("not an object")),
            Err(AhlError::Field(_))
        ));
    }

    #[test]
    fn key_metadata_round_trips() {
        let k = key();
        assert_eq!(k.name(), "producer-1");
        let object = k.key_object(7);
        assert_eq!(field_str(&object, "key_id").expect("key_id"), k.key_id());
        assert_eq!(field_str(&object, "pubkey").expect("pubkey"), k.pubkey());
        assert_eq!(object["valid_from_index"].as_u64(), Some(7));
    }

    #[test]
    fn proof_paths_round_trip_through_their_serialization() {
        let leaves: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i; 3]).collect();
        let proof = inclusion_proof(&leaves, 2).expect("index within tree");
        let path = proof_path_hex(&proof);
        assert_eq!(path.len(), proof.path.len());
        assert_eq!(proof_from_hex(2, 5, &path).expect("well-formed path"), proof);
        assert!(inclusion_proof(&leaves, 9).is_err());
    }

    #[test]
    fn consistency_proofs_verify_through_atl_core() {
        let leaves: Vec<Vec<u8>> = (0u8..9).map(|i| vec![i; 4]).collect();
        let root_at = |size: usize| tree_root(&leaves[..size]);
        for from in 1..=9usize {
            for to in from..=9usize {
                let proof =
                    consistency_proof(&leaves, from as u64, to as u64).expect("sizes in range");
                assert!(
                    verify_consistency_proof(&proof, &root_at(from), &root_at(to))
                        .expect("well-formed proof"),
                    "consistency {from} -> {to} did not verify"
                );
                let path = consistency_path_hex(&proof);
                assert_eq!(
                    consistency_from_hex(from as u64, to as u64, &path).expect("valid path"),
                    proof,
                    "the serialized path must round trip"
                );
            }
        }
    }

    #[test]
    fn a_consistency_proof_does_not_verify_for_another_pair_of_sizes() {
        let leaves: Vec<Vec<u8>> = (0u8..9).map(|i| vec![i; 4]).collect();
        let root_at = |size: usize| tree_root(&leaves[..size]);
        // A genuine proof for [3, 9) must not validate the claim [5, 9): the sizes live outside
        // the serialization, so they are what bind a proof to one pair.
        let path = consistency_path_hex(&consistency_proof(&leaves, 3, 9).expect("sizes in range"));
        let mislabelled = consistency_from_hex(5, 9, &path).expect("valid path");
        assert!(!verify_consistency_proof(&mislabelled, &root_at(5), &root_at(9)).unwrap_or(false));

        // An inverted pair is an error, not a quiet `false`.
        assert!(consistency_proof(&leaves, 9, 3).is_err());
        assert!(matches!(
            consistency_from_hex(1, 2, &["nope".to_owned()]),
            Err(AhlError::MissingPrefix { .. })
        ));
    }

    #[test]
    fn checkpoint_signature_covers_everything_but_the_signature() {
        let k = key();
        let cp = checkpoint("sha256:00", 10, "sha256:11", "2026-08-16T12:00:00Z", &k);
        let msg = checkpoint_signing_bytes(&cp).expect("checkpoint object");
        let sig = field_str(&cp, "signature").expect("signed checkpoint");
        assert!(verify_signature(&k.verifying_key(), &msg, sig).expect("well-formed signature"));
    }

    // -----------------------------------------------------------------------------------
    // Adaptor profile `ahl-adaptor-atl-v1` checkpoint-blob mechanism (§6.1-§6.5).
    //
    // Unit-level only, over a synthetic checkpoint: this profile's document is not yet
    // released (adaptor §14: "Until this document is released as an immutable, openly
    // published artifact… no manifest may pin it"), and its leaf construction (§4.2) and
    // origin-derived `log_id` (§7.1) are not implemented anywhere in this crate, so no
    // receipt vector may claim it end to end. These tests preserve the checkpoint-level
    // mechanism — assemble, sign, verify, reconcile `raw` — for a client integrating ATL
    // directly, without a false-positive receipt anywhere in the corpus.
    // -----------------------------------------------------------------------------------

    fn log_key() -> TestKey {
        TestKey::from_seed_hex("log-1", &"11".repeat(32)).expect("valid 32-byte hex seed")
    }

    #[test]
    fn atl_checkpoint_time_round_trips_through_its_own_parser() {
        // The adaptor document's own §6.4 worked example.
        let nanos = 1_767_225_600_123_456_789u64;
        let rendered = atl_checkpoint_time(nanos);
        assert_eq!(rendered, "2026-01-01T00:00:00.123456789Z");
        assert_eq!(atl_checkpoint_time_nanos(&rendered).expect("strict rendering"), nanos);
    }

    #[test]
    fn atl_checkpoint_time_nanos_rejects_anything_but_the_strict_rendering() {
        for bad in ["2026-01-01T00:00:00Z", "2026-01-01T00:00:00.123Z", "not a timestamp"] {
            assert!(
                atl_checkpoint_time_nanos(bad).is_err(),
                "`{bad}` must not parse as the ATL adaptor's nine-digit rendering"
            );
        }
    }

    /// Assemble a blob, sign it with a test log key, verify the signature over the bytes
    /// `checkpoint_signing_bytes_for` computes for `ahl-adaptor-atl-v1`, and confirm a `raw`
    /// built from that same blob reconciles byte-for-byte.
    #[test]
    fn atl_checkpoint_blob_assembles_signs_verifies_and_reconciles() {
        let log_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let root_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let timestamp_ns = 1_767_225_600_123_456_789u64;
        let key = log_key();

        let cp = atl_checkpoint(log_id, 42, root_hash, timestamp_ns, &key)
            .expect("valid family strings");

        // The signature verifies over exactly the dispatched signing-bytes procedure for
        // `ahl-adaptor-atl-v1` (adaptor §6.1, §6.5) — not `ahl-test-log-v1`'s JCS form.
        let signing_bytes =
            checkpoint_signing_bytes_for(&cp, "ahl-adaptor-atl-v1").expect("ATL dispatch");
        let sig = field_str(&cp, "signature").expect("signed checkpoint");
        assert!(verify_signature(&key.verifying_key(), &signing_bytes, sig).expect("valid sig"));

        // A `raw` built from the SAME components reconciles byte-for-byte (adaptor §6.4/§6.5).
        let origin = parse_hash_hex(log_id).expect("valid family string");
        let root = parse_hash_hex(root_hash).expect("valid family string");
        let blob = atl_checkpoint_blob(&origin, 42, timestamp_ns, &root);
        assert_eq!(blob.to_vec(), signing_bytes, "the blob IS the signing bytes");
        let raw = format!("base64:{}", B64.encode(blob));
        reconcile_atl_checkpoint_raw(&cp, &raw).expect("raw matches the assembled blob");

        // And the JSON-driven assembler agrees with the components-driven one.
        assert_eq!(atl_checkpoint_blob_from_json(&cp).expect("well-formed checkpoint"), blob);
    }

    #[test]
    fn atl_checkpoint_raw_mismatch_cases_are_rejected() {
        let log_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let root_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let timestamp_ns = 1_767_225_600_123_456_789u64;
        let cp = atl_checkpoint(log_id, 42, root_hash, timestamp_ns, &log_key())
            .expect("valid family strings");
        let origin = parse_hash_hex(log_id).expect("valid family string");
        let root = parse_hash_hex(root_hash).expect("valid family string");
        let blob = atl_checkpoint_blob(&origin, 42, timestamp_ns, &root);

        // Wrong length.
        assert!(matches!(
            reconcile_atl_checkpoint_raw(&cp, "base64:AAAA"),
            Err(AhlError::AtlCheckpoint(_))
        ));

        // Wrong magic (98 zero bytes: right length, wrong content).
        let wrong_magic = format!("base64:{}", B64.encode([0u8; 98]));
        assert!(matches!(
            reconcile_atl_checkpoint_raw(&cp, &wrong_magic),
            Err(AhlError::AtlCheckpoint(_))
        ));

        // Correct magic and origin, wrong tree size: genuine field-by-field disagreement.
        let mut corrupted = blob;
        corrupted[50] ^= 0x01;
        let raw = format!("base64:{}", B64.encode(corrupted));
        assert!(matches!(reconcile_atl_checkpoint_raw(&cp, &raw), Err(AhlError::AtlCheckpoint(_))));

        // `raw` correctly signed for the ORIGINAL values, but a JSON sibling member is
        // altered afterward — the JSON members govern (I-D §7.5 step 2).
        let genuine_raw = format!("base64:{}", B64.encode(blob));
        let mut altered = cp;
        altered["tree_size"] = json!(43);
        assert!(matches!(
            reconcile_atl_checkpoint_raw(&altered, &genuine_raw),
            Err(AhlError::AtlCheckpoint(_))
        ));
    }

    #[test]
    fn checkpoint_signing_bytes_for_rejects_unknown_profiles() {
        let cp = checkpoint("sha256:00", 10, "sha256:11", "2026-08-16T12:00:00Z", &key());
        assert!(matches!(
            checkpoint_signing_bytes_for(&cp, "some-other-profile"),
            Err(AhlError::Field(_))
        ));
    }

    /// Adaptor §11.1's erratum, as bytes: a checkpoint that carries `raw` cosigns over the
    /// same preimage as the one that does not. This is the end-to-end defect — a producer that
    /// serialised the checkpoint as it stood built different bytes from the witness, and every
    /// cosignature on a receipt carrying `raw` failed.
    #[test]
    fn raw_is_excluded_from_the_cosignature_preimage() {
        let bare = json!({
            "log_id": format!("sha256:{}", "aa".repeat(32)),
            "tree_size": 5,
            "root_hash": format!("sha256:{}", "bb".repeat(32)),
            "checkpoint_time": "2026-08-16T12:00:00.123456789Z",
            "key_id": format!("sha256:{}", "cc".repeat(32)),
            "signature": format!("base64:{}", "d".repeat(86)),
        });
        let mut with_raw = bare.clone();
        with_raw["raw"] = json!(format!("base64:{}", "e".repeat(130)));

        let projected = CosignedCheckpoint::project(&bare).expect("six members");
        let projected_with_raw = CosignedCheckpoint::project(&with_raw).expect("six members, raw");
        assert_eq!(projected, projected_with_raw, "`raw` is not part of the projection");
        assert_eq!(
            cosignature_bytes(&projected, "witness-1"),
            cosignature_bytes(&projected_with_raw, "witness-1"),
        );

        // And the preimage is the object §11.1 draws, not the checkpoint as received: nothing
        // in these bytes mentions `raw`, and the witness identity binds them.
        let bytes = cosignature_bytes(&projected_with_raw, "witness-1");
        let text = String::from_utf8(bytes).expect("JCS output is UTF-8");
        assert!(!text.contains("raw"), "{text}");
        assert!(text.contains("\"witness_id\":\"witness-1\""), "{text}");
    }

    #[test]
    fn a_checkpoint_member_outside_the_six_and_raw_is_refused() {
        let mut checkpoint = json!({
            "log_id": format!("sha256:{}", "aa".repeat(32)),
            "tree_size": 5,
            "root_hash": format!("sha256:{}", "bb".repeat(32)),
            "checkpoint_time": "2026-08-16T12:00:00.123456789Z",
            "key_id": format!("sha256:{}", "cc".repeat(32)),
            "signature": format!("base64:{}", "d".repeat(86)),
        });
        checkpoint["origin_id"] = json!("sha256:whatever");
        assert!(matches!(
            CosignedCheckpoint::project(&checkpoint),
            Err(AhlError::CosignedCheckpoint(detail)) if detail.contains("`origin_id`")
        ));
    }

    #[test]
    fn a_projection_needs_all_six_members_at_their_own_json_types() {
        let full = json!({
            "log_id": format!("sha256:{}", "aa".repeat(32)),
            "tree_size": 5,
            "root_hash": format!("sha256:{}", "bb".repeat(32)),
            "checkpoint_time": "2026-08-16T12:00:00.123456789Z",
            "key_id": format!("sha256:{}", "cc".repeat(32)),
            "signature": format!("base64:{}", "d".repeat(86)),
        });
        for member in ["log_id", "tree_size", "root_hash", "checkpoint_time", "key_id", "signature"]
        {
            let mut short = full.clone();
            short.as_object_mut().expect("object").remove(member);
            assert!(
                CosignedCheckpoint::project(&short).is_err(),
                "`{member}` absent must not project"
            );
        }
        // `tree_size` is an entry count, not its decimal rendering: a string here would let two
        // producers disagree about the preimage while carrying the same value.
        let mut stringly = full;
        stringly["tree_size"] = json!("5");
        assert!(CosignedCheckpoint::project(&stringly).is_err());
        assert!(CosignedCheckpoint::project(&json!("not an object")).is_err());
    }
}
