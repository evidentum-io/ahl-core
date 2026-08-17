//! `ahl-core` — reference primitives and the canonical test-vector corpus for the
//! **AHL Protocol** (Anchored History Log).
//!
//! This crate implements exactly the pieces the AHL Core Specification v0.3-draft and the
//! Evidence Receipt format 1-draft r3 need in order to *produce and re-verify deterministic
//! test vectors*:
//!
//! * RFC 8785 (JCS) canonicalization and the two AHL identifiers — statement id and entry id
//!   (spec §2.1);
//! * domain-separated record commitments in `plain` and `keyed` mode (spec §2.4);
//! * Ed25519 statement envelopes and signed checkpoints;
//! * AHL Merkle trees — leaf `0x00 || bytes`, node `0x01 || left || right` (spec §2.5);
//! * revocation closure over an anchored statement graph (spec §5.1).
//!
//! # Anti-drift
//!
//! Canonicalization, node hashing, root computation, proof generation and — critically —
//! **proof verification** are delegated to [`atl_core`], the audited sibling implementation,
//! rather than reimplemented here. AHL vectors therefore cannot silently diverge from the
//! ATL family's Merkle semantics.
//!
//! # Test material only
//!
//! Every key in `test_data/keys/` is a published constant. Nothing in this crate is
//! suitable for production key handling.
//!
//! ```
//! use ahl_core::{commit_plain, jcs};
//! use serde_json::json;
//!
//! // A `plain` commitment is domain-separated by the dataset id (spec §2.4).
//! let bytes = jcs(&json!({ "customer_id": "C-1001" }));
//! assert!(commit_plain("scores", &bytes).starts_with("sha256:"));
//! ```

#![forbid(unsafe_code)]

pub mod closure;
mod error;

use atl_core::core::merkle::{compute_root, generate_inclusion_proof, verify_inclusion};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use hmac::{Hmac, Mac as _};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

pub use atl_core::core::merkle::{Hash, InclusionProof};
pub use error::{AhlError, AhlResult};

/// The AHL core specification version these vectors are generated against.
pub const AHL_VERSION: &str = "0.3";

/// Leaf domain-separation prefix for every AHL tree (spec §2.5).
pub const LEAF_PREFIX: u8 = 0x00;

/// Node domain-separation prefix for every AHL tree (spec §2.5).
///
/// Node hashing itself is performed by `atl_core`; the constant is restated so the
/// adaptor profile document and this crate cannot disagree about it.
pub const NODE_PREFIX: u8 = 0x01;

/// Separator between the dataset id and the canonical record bytes (spec §2.4).
pub const DATASET_SEPARATOR: u8 = 0x1F;

const SHA256_PREFIX: &str = "sha256:";
const HMAC_PREFIX: &str = "hmac-sha256:";
const BASE64_PREFIX: &str = "base64:";

const B64: base64::engine::general_purpose::GeneralPurpose =
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
// Record commitments (spec §2.4)
// ---------------------------------------------------------------------------

/// `dsid || 0x1F || canonical bytes` — the domain-separated commitment input.
fn commitment_input(dataset: &str, canonical: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(dataset.len() + 1 + canonical.len());
    buf.extend_from_slice(dataset.as_bytes());
    buf.push(DATASET_SEPARATOR);
    buf.extend_from_slice(canonical);
    buf
}

/// `plain` commitment — `SHA-256(dsid || 0x1F || canonical bytes)` (spec §2.4).
#[must_use]
pub fn commit_plain(dataset: &str, canonical: &[u8]) -> String {
    sha256_hex(&commitment_input(dataset, canonical))
}

/// `keyed` commitment — `HMAC-SHA-256(k_dataset, dsid || 0x1F || canonical bytes)` (spec §2.4).
///
/// Required for personal or sensitive data. The dataset key is never packaged into a
/// receipt; only an authorized verifier can recompute this value.
///
/// # Errors
///
/// Returns [`AhlError::BadLength`] if `key` cannot be used as an HMAC key.
pub fn commit_keyed(key: &[u8], dataset: &str, canonical: &[u8]) -> AhlResult<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| AhlError::BadLength {
        what: "hmac dataset key",
        expected: 32,
        got: key.len(),
    })?;
    mac.update(&commitment_input(dataset, canonical));
    Ok(format!("{HMAC_PREFIX}{}", hex::encode(mac.finalize().into_bytes())))
}

// ---------------------------------------------------------------------------
// Keys, envelopes, signatures (spec §2.1, §2.3.6, §7.2)
// ---------------------------------------------------------------------------

/// A deterministic Ed25519 test key derived from a committed 32-byte seed.
///
/// `key_id` and `pubkey` encodings are fixed by the adaptor profile document
/// (`test_data/adaptor/ahl-test-log-v1.md`): `key_id = SHA-256(raw 32-byte public key)`
/// rendered `sha256:<hex>`, public key rendered `base64:<raw 32 bytes>`.
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

    /// A manifest key object `{key_id, pubkey, valid_from_index}` (spec §7.2).
    #[must_use]
    pub fn key_object(&self, valid_from_index: u64) -> Value {
        json!({
            "key_id": self.key_id(),
            "pubkey": self.pubkey(),
            "valid_from_index": valid_from_index,
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

/// Build a signed statement envelope `{payload, signatures:[{keyid, sig}]}` (spec §2.1).
///
/// The signature covers `JCS(payload)`.
#[must_use]
pub fn envelope(payload: Value, key: &TestKey) -> Value {
    let sig = key.sign(&jcs(&payload));
    let mut env = serde_json::Map::new();
    env.insert("payload".to_owned(), payload);
    env.insert("signatures".to_owned(), json!([ { "keyid": key.key_id(), "sig": sig } ]));
    Value::Object(env)
}

/// Verify every signature on an envelope against a `keyid -> pubkey` resolver.
///
/// Returns `false` for an envelope with no signatures: unsigned objects are not AHL
/// statements (spec §2.1).
///
/// # Errors
///
/// Returns an error if the envelope shape is wrong or a resolved key cannot be decoded.
pub fn verify_envelope<F>(env: &Value, resolve: F) -> AhlResult<bool>
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
        return Ok(false);
    }
    let msg = jcs(payload);
    for entry in signatures {
        let keyid = field_str(entry, "keyid")?;
        let sig = field_str(entry, "sig")?;
        let Some(pubkey) = resolve(keyid) else { return Ok(false) };
        if !verify_signature(&decode_pubkey(&pubkey)?, &msg, sig)? {
            return Ok(false);
        }
    }
    Ok(true)
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
    let mut cp = json!({
        "log_id": log_id,
        "tree_size": tree_size,
        "root_hash": root_hash,
        "checkpoint_time": checkpoint_time,
        "key_id": key.key_id(),
    });
    let sig = key.sign(&jcs(&cp));
    cp["signature"] = Value::String(sig);
    cp
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

/// The bytes a witness cosigns: `JCS({"checkpoint": <signed cp>, "witness_id": <id>})`.
#[must_use]
pub fn cosignature_bytes(signed_checkpoint: &Value, witness_id: &str) -> Vec<u8> {
    jcs(&json!({ "checkpoint": signed_checkpoint, "witness_id": witness_id }))
}

// ---------------------------------------------------------------------------
// AHL trees (spec §2.5)
// ---------------------------------------------------------------------------

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
/// The comparison is over the byte sequence of the `record` family string
/// (`sha256:<hex>` / `hmac-sha256:<hex>`), as pinned by the adaptor profile document.
///
/// # Errors
///
/// Returns [`AhlError::Field`] if a leaf carries no string `record`, or
/// [`AhlError::DuplicateRecord`] if two leaves name the same record.
pub fn record_sorted(mut leaves: Vec<Value>) -> AhlResult<Vec<Value>> {
    for leaf in &leaves {
        field_str(leaf, "record")?;
    }
    leaves.sort_by_key(record_key);
    for pair in leaves.windows(2) {
        if record_key(&pair[0]) == record_key(&pair[1]) {
            return Err(AhlError::DuplicateRecord(record_key(&pair[0])));
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

#[cfg(test)]
mod tests {
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

    #[test]
    fn commitments_are_domain_separated_by_dataset() {
        let bytes = jcs(&json!({ "a": 1 }));
        assert_ne!(commit_plain("customers", &bytes), commit_plain("scores", &bytes));
    }

    #[test]
    fn keyed_commitment_differs_from_plain() {
        let bytes = jcs(&json!({ "a": 1 }));
        let keyed = commit_keyed(&[7u8; 32], "customers", &bytes).expect("32-byte key");
        assert!(keyed.starts_with("hmac-sha256:"));
        assert_ne!(keyed, commit_plain("customers", &bytes));
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

    #[test]
    fn inclusion_proofs_verify_through_atl_core() {
        let leaves: Vec<Vec<u8>> = (0u8..7).map(|i| vec![i; 4]).collect();
        let root = tree_root(&leaves);
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = inclusion_proof(&leaves, i).expect("index within tree");
            assert!(verify_inclusion_proof(leaf, &proof, &root).expect("valid proof shape"));
        }
    }

    #[test]
    fn record_sorting_rejects_duplicates() {
        let leaves = vec![json!({ "record": "sha256:aa" }), json!({ "record": "sha256:aa" })];
        assert!(matches!(record_sorted(leaves), Err(AhlError::DuplicateRecord(_))));
    }

    #[test]
    fn record_sorting_is_ascending() {
        let leaves = vec![json!({ "record": "sha256:bb" }), json!({ "record": "sha256:aa" })];
        let sorted = record_sorted(leaves).expect("distinct records");
        assert_eq!(record_key(&sorted[0]), "sha256:aa");
    }

    #[test]
    fn checkpoint_signature_covers_everything_but_the_signature() {
        let k = key();
        let cp = checkpoint("sha256:00", 10, "sha256:11", "2026-08-16T12:00:00Z", &k);
        let msg = checkpoint_signing_bytes(&cp).expect("checkpoint object");
        let sig = field_str(&cp, "signature").expect("signed checkpoint");
        assert!(verify_signature(&k.verifying_key(), &msg, sig).expect("well-formed signature"));
    }
}
