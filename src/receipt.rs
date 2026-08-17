//! Offline verification of AHL Evidence Receipts (`.ahl`).
//!
//! [`verify_receipt`] implements the normative algorithm outline of Evidence Receipt format
//! §5, the assurance semantics of §2.1, the key-binding rules of §2.2, the cross-field
//! consistency rules of §2.3, the claim-type registry of §3, the resource limits of §3.1 and
//! the governance-currency modes of §4.
//!
//! # What "offline" means here
//!
//! The verifier is handed exactly three things: the receipt, the locally possessed adaptor
//! profile hashes, and a [`TrustPolicy`] standing in for the verifier's locally configured
//! trust anchor (format §1 design rule 1). It never consults the producer, the log, or the
//! surrounding corpus — everything else must be carried by the receipt. A receipt that carries
//! its own genesis anchor proves nothing until that anchor matches configured policy, and this
//! implementation compares it explicitly rather than trusting it.
//!
//! # Failing closed
//!
//! Every rejection is a distinct [`ReceiptError`] variant naming the rule that fired, so a test
//! can assert *which* rule rejected a deliberately malformed receipt rather than that "it
//! failed somehow". Resource exhaustion is a rejection, never a degraded acceptance (§3.1).

use std::collections::{BTreeMap, BTreeSet};

use atl_core::core::merkle::Hash;
use base64::Engine as _;
use serde_json::Value;

use crate::bitemporal::Scope;
use crate::closure::{affected_set, TreeMaterial};
use crate::range_proof;
use crate::tree::ValidatedLeafSet;
use crate::{
    checkpoint_signing_bytes, commit_keyed, commit_plain, cosignature_bytes, decode_pubkey,
    entry_id, hash_hex, jcs, parse_hash_hex, proof_from_hex, sha256_hex, statement_id, tree_root,
    verify_signature, AhlError, B64,
};

/// Receipt container version this verifier implements.
pub const RECEIPT_VERSION: &str = "1";

/// Core specification version this verifier implements.
pub const SPEC_VERSION: &str = "0.3.0";

// ---------------------------------------------------------------------------
// Policy and limits
// ---------------------------------------------------------------------------

/// Resource limits (format §3.1). A verifier MUST fail closed on exhaustion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum embedded-receipt nesting depth. Normative maximum: 4.
    pub max_depth: usize,
    /// Maximum embedded receipts per file. Normative maximum: 64.
    pub max_embedded: usize,
    /// Decoded-size budget in bytes, over the JCS serialization of the whole receipt.
    pub max_decoded_bytes: usize,
    /// Verification-work budget: one unit per signature check, proof check or tree opening.
    pub max_work_units: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 4,
            max_embedded: 64,
            max_decoded_bytes: 8 * 1024 * 1024,
            max_work_units: 100_000,
        }
    }
}

/// What a locally possessed adaptor profile document defines.
///
/// Core spec §3 item 6 forbids verification from depending on knowledge outside the profile
/// document, so the *absence* of a definition is a property of the profile, not of the
/// verifier. These flags carry that distinction into the code: a receipt using material the
/// pinned profile never defines is rejected as an adaptor limitation, with the profile named,
/// rather than as though the format itself forbade it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AdaptorCapabilities {
    /// The profile defines a binary checkpoint framing, so `anchoring.checkpoint.raw` can be
    /// parsed and compared against the JSON object (format §5 step 2).
    pub checkpoint_raw: bool,
    /// The profile defines a consistency-proof serialization, so `anchoring.later_checkpoint`
    /// plus `consistency_path` can be verified and `assurance.continued_history` claimed.
    pub consistency_proofs: bool,
}

/// A locally possessed adaptor profile: the hash of the document plus what it defines.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdaptorProfile {
    /// SHA-256 of the published profile document, as `sha256:<hex>`.
    pub hash: String,
    /// What the document defines. Anything not listed here is unusable *under this profile*.
    pub capabilities: AdaptorCapabilities,
}

impl AdaptorProfile {
    /// A profile that defines only what the corpus adaptor `ahl-test-log-v1` defines.
    #[must_use]
    pub const fn minimal(hash: String) -> Self {
        Self {
            hash,
            capabilities: AdaptorCapabilities { checkpoint_raw: false, consistency_proofs: false },
        }
    }
}

/// The verifier's locally configured trust policy (format §1 design rule 1).
///
/// Nothing in this struct may be taken from the receipt: that is the whole point of the trust
/// anchor. A receipt carries a genesis anchor so it is self-describing; policy decides whether
/// that anchor is the right one.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    /// The published genesis entry id of the corpus this verifier accepts.
    pub genesis_entry_id: String,
    /// The published producer key fingerprints of the genesis manifest.
    pub genesis_key_ids: BTreeSet<String>,
    /// Locally possessed adaptor profiles, by profile id.
    pub adaptor_profiles: BTreeMap<String, AdaptorProfile>,
    /// Dataset HMAC keys this verifier is authorized to hold (`keyed-authorized` binding only).
    pub dataset_keys: BTreeMap<String, Vec<u8>>,
    /// Witness key ids trusted by local policy rather than through the manifest chain.
    pub trusted_witness_key_ids: BTreeSet<String>,
    /// Resource limits.
    pub limits: Limits,
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// The structured assurance block of a receipt (format §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assurance {
    /// `declared` or `enumerated`.
    pub governance: String,
    /// `not-checked` or `enumerated`.
    pub competing_triggers: String,
    /// At least one witness cosignature on the inclusion checkpoint verified.
    pub witnessed: bool,
    /// `later_checkpoint` plus a consistency proof verified.
    pub continued_history: bool,
    /// `none`, `plain-verified` or `keyed-authorized`.
    pub content_binding: String,
}

/// An accepted receipt, with the boundary the verifier renders for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The registry id of the proven claim (format §3).
    pub claim_type: String,
    /// Entry index of the subject statement.
    pub subject_entry_index: u64,
    /// Statement id of the subject statement.
    pub subject_statement_id: String,
    /// The verified assurance block.
    pub assurance: Assurance,
    /// The rendered claim boundary — derived from `claim.type` and `assurance` only, never
    /// from the receipt's informative `note` (format §2.1: the verdict is never stronger).
    pub boundary: String,
    /// Number of embedded receipts verified, including duplicates resolved by reference.
    pub embedded_receipts: usize,
}

// ---------------------------------------------------------------------------
// Rejection reasons
// ---------------------------------------------------------------------------

/// Why a receipt was rejected. Each variant names the rule that fired.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    /// The receipt is not structurally a receipt at all.
    #[error("malformed receipt: {0}")]
    Malformed(String),

    /// `ahl_receipt_version` or `spec_version` is not one this verifier implements (§5 step 1).
    #[error("unsupported {field}: expected `{expected}`, got `{got}`")]
    UnsupportedVersion {
        /// The version field.
        field: &'static str,
        /// The version this verifier implements.
        expected: &'static str,
        /// The version carried.
        got: String,
    },

    /// A §3.1 resource limit was exhausted. Rejection, never degradation.
    #[error("resource limit exhausted: {0}")]
    LimitExceeded(&'static str),

    /// `subject.statement_id` or `subject.entry_id` disagrees with `envelope` (§5 step 1).
    #[error("`subject.{field}` does not match the carried envelope")]
    IdentifierMismatch {
        /// `statement_id` or `entry_id`.
        field: &'static str,
    },

    /// The adaptor profile is not locally possessed, or its hash differs (§5 step 2).
    #[error("adaptor profile `{id}` is not locally possessed at the pinned hash")]
    AdaptorUnknown {
        /// The profile id the receipt pins.
        id: String,
    },

    /// The receipt carries material the pinned adaptor profile does not define.
    ///
    /// This is a limitation of the profile, not of the container format: another profile that
    /// defines the capability would make the same receipt verifiable.
    #[error("adaptor profile `{id}` does not define {capability}, which this receipt requires")]
    AdaptorCapabilityUnsupported {
        /// The pinned profile id.
        id: String,
        /// What the receipt needed the profile to define.
        capability: &'static str,
    },

    /// A claim's checkpoint is not the checkpoint the claim is required to rest on (§3).
    ///
    /// For `trigger-effective` that reference is the receipt's own verified
    /// `anchoring.checkpoint`; for `propagation-complete` it is the propagation statement's
    /// declared checkpoint D. Either way a self-supplied checkpoint cannot ground the claim.
    #[error("`{field}` does not match the checkpoint this claim must rest on: `{member}` differs")]
    CheckpointNotBound {
        /// The claim-material member carrying the unverified checkpoint.
        field: &'static str,
        /// The first checkpoint member that differs.
        member: String,
    },

    /// Enumerated governance currency does not cover exactly `[0, tree_size(C))` (§4).
    #[error(
        "enumerated governance covers [{got_from}, {got_to}) but §4 requires exactly \
         [0, {tree_size}) — a narrower range can hide a later governance statement"
    )]
    GovernanceRangeNotComplete {
        /// Lower bound carried.
        got_from: u64,
        /// Upper bound carried.
        got_to: u64,
        /// Tree size of the receipt's verified checkpoint.
        tree_size: u64,
    },

    /// The trigger is not signed by the record's authority, so it is a challenge (spec §2.3.3).
    #[error(
        "trigger at entry index {entry_index} is signed by {signed_by}, which is not the \
         authority for `{record}`; spec §2.3.3 anchors it as a challenge, never traversed"
    )]
    TriggerNotAuthorized {
        /// Entry index of the unauthorized trigger.
        entry_index: u64,
        /// The record whose authority was required.
        record: String,
        /// The key ids that actually signed.
        signed_by: String,
    },

    /// A `governance-state` receipt's subject is not a manifest statement (§3).
    #[error(
        "`governance-state` subject must be a manifest statement, got `{statement_type}` \
         (key state is composed from the manifest plus later key statements)"
    )]
    GovernanceSubjectNotManifest {
        /// The subject statement's type.
        statement_type: String,
    },

    /// The checkpoint signature did not verify (§5 step 3).
    #[error("checkpoint signature did not verify")]
    CheckpointSignatureInvalid,

    /// A key used in verification is not bound to a manifest key object as §2.2 requires.
    #[error("key `{key_id}` is not bound to a manifest key object at entry index {entry_index}")]
    KeyNotBound {
        /// The offending key id.
        key_id: String,
        /// The binding index the receipt claimed.
        entry_index: u64,
    },

    /// A witness cosignature did not verify.
    #[error("witness cosignature for `{witness_id}` did not verify")]
    WitnessCosignatureInvalid {
        /// The witness whose cosignature failed.
        witness_id: String,
    },

    /// `subject.entry_index` is not committed by the checkpoint (§5 step 3).
    #[error("entry index {entry_index} is not committed by a checkpoint of size {tree_size}")]
    EntryIndexBeyondCheckpoint {
        /// The claimed entry index.
        entry_index: u64,
        /// The checkpoint's tree size.
        tree_size: u64,
    },

    /// An inclusion path did not open the root it was checked against.
    #[error("inclusion path for {what} did not verify against the anchored root")]
    InclusionPathInvalid {
        /// Which path failed.
        what: &'static str,
    },

    /// The consistency path for `later_checkpoint` did not verify.
    #[error("consistency path did not verify")]
    ConsistencyPathInvalid,

    /// The receipt's genesis anchor is not the one local policy configures (§5 step 4).
    #[error("genesis anchor does not match locally configured policy")]
    GenesisAnchorMismatch,

    /// The governance chain is not a valid manifest lineage (§2.3.5, §5 step 4).
    #[error("governance chain invalid: {0}")]
    GovernanceChainInvalid(String),

    /// An envelope signature did not verify under the key set as of its entry index.
    #[error("envelope signature at entry index {entry_index} did not verify")]
    EnvelopeSignatureInvalid {
        /// The entry index of the offending envelope.
        entry_index: u64,
    },

    /// A structured assurance field does not match what verification established (§2.3).
    #[error("assurance field `{field}` overstates what the receipt proves")]
    AssuranceMismatch {
        /// The offending assurance field.
        field: &'static str,
    },

    /// `record_subject` is present where §3 requires absence, absent where required, or does
    /// not match the subject envelope's payload (§2.3).
    #[error("`claim.record_subject` is wrong for claim type `{claim_type}`: {detail}")]
    RecordSubjectMismatch {
        /// The claim type whose subject rule was violated.
        claim_type: String,
        /// What exactly was wrong.
        detail: String,
    },

    /// `subject.manifest` is present for a manifest statement or absent for anything else.
    #[error("`subject.manifest` presence is wrong for a `{statement_type}` subject (§2.3)")]
    SubjectManifestPresence {
        /// The subject statement's type.
        statement_type: String,
    },

    /// An embedded receipt's entry index violates the §2.3 ordering rule.
    #[error(
        "ordering violation: {what} at entry index {inner} is not permitted relative to \
         entry index {outer}"
    )]
    EmbeddedOrderingViolation {
        /// Which relationship was violated.
        what: &'static str,
        /// The embedded receipt's subject entry index.
        inner: u64,
        /// The referencing receipt's subject entry index.
        outer: u64,
    },

    /// An embedded receipt is about a different record than the material referencing it (§2.3).
    #[error("embedded {what} receipt is about `{got}`, the referencing material names `{want}`")]
    EmbeddedSubjectMismatch {
        /// Which embedded receipt.
        what: &'static str,
        /// The record the embedded receipt proves.
        got: String,
        /// The record the referencing material names.
        want: String,
    },

    /// An embedded receipt has the wrong claim type for the slot it fills (§3 registry).
    #[error("embedded receipt in `{slot}` must be `{expected}`, got `{got}`")]
    EmbeddedClaimTypeMismatch {
        /// The claim-material member.
        slot: &'static str,
        /// The registry id required by the schema.
        expected: &'static str,
        /// The registry id carried.
        got: String,
    },

    /// The §3 schema for the claim type requires a member the receipt does not carry.
    #[error("claim material for `{claim_type}` is missing `{field}`")]
    ClaimMaterialMissing {
        /// The claim type whose schema was not satisfied.
        claim_type: String,
        /// The missing member.
        field: &'static str,
    },

    /// A claim-material Merkle path did not open the root it is checked against.
    #[error("claim-material path `{what}` did not verify against the anchored root")]
    ClaimMaterialPathInvalid {
        /// Which path failed.
        what: &'static str,
    },

    /// Carried record bytes do not recompute to the claimed commitment (§2.1).
    #[error(
        "content binding `{mode}` failed: carried bytes commit to `{recomputed}`, not `{claimed}`"
    )]
    ContentBindingMismatch {
        /// The declared binding mode.
        mode: String,
        /// What the carried bytes actually commit to.
        recomputed: String,
        /// The commitment the statement anchors.
        claimed: String,
    },

    /// A `trigger-effective` receipt's competing-trigger range is not the required range (§3).
    #[error(
        "competing-trigger range [{got_from}, {got_to}) is not the required \
         [0, {tree_size}) or [{introduction_index}, {tree_size})"
    )]
    CompetingRangeInsufficient {
        /// Lower bound carried.
        got_from: u64,
        /// Upper bound carried.
        got_to: u64,
        /// Tree size of checkpoint C.
        tree_size: u64,
        /// Introduction index fixed by the embedded introduction receipt.
        introduction_index: u64,
    },

    /// An authenticated range proof (§4.2) did not verify against the checkpoint root.
    #[error("range proof for {what} did not verify: {detail}")]
    RangeProofInvalid {
        /// Which enumeration failed.
        what: &'static str,
        /// Why.
        detail: String,
    },

    /// Carried tree material does not open the root it claims (spec §2.5, §3.5).
    #[error("tree material for `{root}` is invalid: {detail}")]
    TreeMaterialInvalid {
        /// The root whose material failed.
        root: String,
        /// Why.
        detail: String,
    },

    /// The recomputed closure disagrees with the anchored disposition set (spec §5.3).
    #[error("recomputed affected set disagrees with the anchored disposition tree: {0}")]
    ClosureMismatch(String),

    /// A manifest or key statement exists in the range a `governance-state` claim asserts is
    /// empty (§3 registry).
    #[error(
        "governance state is not current at index {target_index}: a `{statement_type}` \
         statement is anchored at entry index {entry_index}"
    )]
    GovernanceStateNotCurrent {
        /// The claimed target index.
        target_index: u64,
        /// Where the contradicting statement sits.
        entry_index: u64,
        /// Its type.
        statement_type: String,
    },

    /// A primitive operation failed on data read from the receipt.
    #[error(transparent)]
    Ahl(#[from] AhlError),
}

type Result<T> = core::result::Result<T, ReceiptError>;

// ---------------------------------------------------------------------------
// Small accessors that turn absent/ill-typed members into rejections
// ---------------------------------------------------------------------------

fn obj<'a>(value: &'a Value, path: &str) -> Result<&'a Value> {
    value
        .get(path)
        .filter(|v| v.is_object())
        .ok_or_else(|| ReceiptError::Malformed(format!("`{path}` object")))
}

fn text<'a>(value: &'a Value, path: &str) -> Result<&'a str> {
    value
        .get(path)
        .and_then(Value::as_str)
        .ok_or_else(|| ReceiptError::Malformed(format!("`{path}` string")))
}

fn number(value: &Value, path: &str) -> Result<u64> {
    value
        .get(path)
        .and_then(Value::as_u64)
        .ok_or_else(|| ReceiptError::Malformed(format!("`{path}` integer")))
}

fn flag(value: &Value, path: &str) -> Result<bool> {
    value
        .get(path)
        .and_then(Value::as_bool)
        .ok_or_else(|| ReceiptError::Malformed(format!("`{path}` boolean")))
}

fn array<'a>(value: &'a Value, path: &str) -> Result<&'a Vec<Value>> {
    value
        .get(path)
        .and_then(Value::as_array)
        .ok_or_else(|| ReceiptError::Malformed(format!("`{path}` array")))
}

fn path_strings(value: &Value, path: &str) -> Result<Vec<String>> {
    array(value, path)?
        .iter()
        .map(|h| {
            h.as_str()
                .map(str::to_owned)
                .ok_or_else(|| ReceiptError::Malformed(format!("`{path}` element")))
        })
        .collect()
}

fn payload_of(envelope: &Value) -> Result<&Value> {
    obj(envelope, "payload")
}

fn statement_type(payload: &Value) -> Result<&str> {
    text(payload, "type")
}

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

/// Tracks the §3.1 budgets across a whole receipt tree, including embedded receipts.
#[derive(Debug)]
struct Budget {
    limits: Limits,
    work: u64,
    embedded: usize,
    /// Verdicts of embedded receipts already verified, keyed by the **JCS digest of the whole
    /// embedded receipt object** (format §3.1). The entry id alone is unsound: two embedded
    /// receipts can share a subject statement while carrying different — independently
    /// forgeable — `claim_material`, and keying on the envelope would let the second reuse the
    /// first's verdict. Consulted before recursing, not merely recorded after.
    verified: BTreeMap<String, Verdict>,
}

impl Budget {
    const fn new(limits: Limits) -> Self {
        Self { limits, work: 0, embedded: 0, verified: BTreeMap::new() }
    }

    const fn spend(&mut self, units: u64) -> Result<()> {
        self.work = self.work.saturating_add(units);
        if self.work > self.limits.max_work_units {
            return Err(ReceiptError::LimitExceeded("verification work budget"));
        }
        Ok(())
    }

    const fn enter(&mut self, depth: usize) -> Result<()> {
        if depth > self.limits.max_depth {
            return Err(ReceiptError::LimitExceeded("embedded-receipt nesting depth"));
        }
        if depth > 0 {
            self.embedded += 1;
            if self.embedded > self.limits.max_embedded {
                return Err(ReceiptError::LimitExceeded("embedded receipts per file"));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Governance chain
// ---------------------------------------------------------------------------

/// A producer key-set transition, ordered by the entry index that anchored it.
struct KeyEvent {
    entry_index: u64,
    key_id: String,
    pubkey: String,
    added: bool,
}

/// The verified governance state carried by a receipt.
struct Governance<'a> {
    /// Manifest statements in the chain, ascending by entry index.
    manifests: Vec<(u64, &'a Value)>,
    /// Producer key transitions, ascending by entry index.
    events: Vec<KeyEvent>,
}

/// One producer key in force at some entry index, with the governance statement that put it
/// there — the index a receipt's `keys.producer[].binding` must name (format §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundKey {
    pubkey: String,
    bound_at: u64,
}

impl<'a> Governance<'a> {
    /// The governance statement whose producer-key snapshot is in force *at* `index`.
    ///
    /// Spec §2.2 resolves "the manifest version active at entry index i" as the manifest with
    /// the greatest entry index **smaller** than i — which is also what §2.3.5 needs, since a
    /// manifest statement is signed under its *predecessor*'s state. The genesis manifest is
    /// the one statement validated by its own snapshot, so index 0 falls back to it.
    fn snapshot_manifest(&self, index: u64) -> Option<(u64, &'a Value)> {
        self.manifests
            .iter()
            .rfind(|(mi, _)| *mi < index)
            .or_else(|| self.manifests.first())
            .copied()
    }

    /// The producer key set in force at `index`, with each key's binding index.
    ///
    /// Spec §7.2: "A manifest's producer `keys` array is the complete producer-key snapshot
    /// effective from that manifest's entry index: it discards the prior snapshot; later `key`
    /// statements then modify it in entry order until the next manifest version." So this is
    /// *not* a union across manifest versions — a key a later manifest omits is gone, and a
    /// signature by it no longer validates.
    fn producer_keys_at(&self, index: u64) -> BTreeMap<String, BoundKey> {
        let mut keys = BTreeMap::new();
        let Some((snapshot_index, manifest)) = self.snapshot_manifest(index) else {
            return keys;
        };
        for (key_id, pubkey) in key_objects(manifest).unwrap_or_default() {
            keys.insert(key_id, BoundKey { pubkey, bound_at: snapshot_index });
        }
        // Only transitions anchored after that snapshot and at or before `index` apply; an
        // earlier `key` statement was already folded into (or discarded by) the snapshot.
        for event in
            self.events.iter().filter(|e| e.entry_index > snapshot_index && e.entry_index <= index)
        {
            if event.added {
                keys.insert(
                    event.key_id.clone(),
                    BoundKey { pubkey: event.pubkey.clone(), bound_at: event.entry_index },
                );
            } else {
                keys.remove(&event.key_id);
            }
        }
        keys
    }

    /// `key_id -> pubkey` at `index`, for signature resolution.
    fn producer_pubkeys_at(&self, index: u64) -> BTreeMap<String, String> {
        self.producer_keys_at(index)
            .into_iter()
            .map(|(key_id, bound)| (key_id, bound.pubkey))
            .collect()
    }

    /// The manifest version active for a checkpoint of size `tree_size` (format §2.2: the
    /// manifest statement with the greatest entry index smaller than that tree size).
    fn active_for(&self, tree_size: u64) -> Result<(u64, &'a Value)> {
        self.manifests.iter().rfind(|(index, _)| *index < tree_size).copied().ok_or_else(|| {
            ReceiptError::GovernanceChainInvalid(format!(
                "no manifest version is active for a checkpoint of size {tree_size}"
            ))
        })
    }
}

/// Read the manifest key objects of `group` (`keys`, `log.keys`, `witnesses[].keys`).
fn key_objects(container: &Value) -> Result<Vec<(String, String)>> {
    array(container, "keys")?
        .iter()
        .map(|object| Ok((text(object, "key_id")?.to_owned(), text(object, "pubkey")?.to_owned())))
        .collect()
}

/// Build and structurally validate the governance chain (spec §2.3.5).
fn read_chain<'a>(receipt: &'a Value, policy: &TrustPolicy) -> Result<Governance<'a>> {
    let chain = array(obj(receipt, "governance")?, "chain")?;
    if chain.is_empty() {
        return Err(ReceiptError::GovernanceChainInvalid("chain is empty".to_owned()));
    }

    let mut manifests = Vec::new();
    let mut events = Vec::new();
    let mut previous_index: Option<u64> = None;
    let mut previous_manifest_entry_id: Option<String> = None;

    for hop in chain {
        let index = number(hop, "entry_index")?;
        if previous_index.is_some_and(|prev| prev >= index) {
            return Err(ReceiptError::GovernanceChainInvalid(
                "chain hops must ascend by entry index".to_owned(),
            ));
        }
        previous_index = Some(index);

        let envelope = obj(hop, "envelope")?;
        let payload = payload_of(envelope)?;
        match statement_type(payload)? {
            "manifest" => {
                let predecessor = payload.get("predecessor").and_then(Value::as_str);
                match (&previous_manifest_entry_id, predecessor) {
                    (None, Some(_)) => {
                        return Err(ReceiptError::GovernanceChainInvalid(
                            "the genesis manifest must carry no predecessor reference".to_owned(),
                        ))
                    }
                    (Some(_), None) => {
                        return Err(ReceiptError::GovernanceChainInvalid(
                            "a non-genesis manifest must reference its predecessor".to_owned(),
                        ))
                    }
                    // A non-genesis manifest references its predecessor by *entry* id:
                    // signature identity matters for chain links (spec §2.3.5).
                    (Some(want), Some(got)) if want != got => {
                        return Err(ReceiptError::GovernanceChainInvalid(format!(
                            "manifest at entry index {index} references `{got}`, \
                             its predecessor in the chain is `{want}`"
                        )))
                    }
                    _ => {}
                }
                previous_manifest_entry_id = Some(entry_id(envelope));
                // The manifest's `keys` array is a *snapshot*, not a set of add events
                // (spec §7.2). It is read at resolution time by `producer_keys_at`, which
                // discards whatever the prior manifest declared.
                key_objects(payload)?;
                manifests.push((index, payload));
            }
            "key" => {
                let key = obj(payload, "key")?;
                events.push(KeyEvent {
                    entry_index: index,
                    key_id: text(key, "key_id")?.to_owned(),
                    pubkey: text(key, "pubkey")?.to_owned(),
                    added: match text(payload, "action")? {
                        "add" => true,
                        "retire" => false,
                        other => {
                            return Err(ReceiptError::GovernanceChainInvalid(format!(
                                "unknown key action `{other}`"
                            )))
                        }
                    },
                });
            }
            other => {
                return Err(ReceiptError::GovernanceChainInvalid(format!(
                    "`{other}` is not a governance statement"
                )))
            }
        }
    }

    let genesis = &chain[0];
    let genesis_envelope = obj(genesis, "envelope")?;
    if number(genesis, "entry_index")? != 0
        || statement_type(payload_of(genesis_envelope)?)? != "manifest"
    {
        return Err(ReceiptError::GovernanceChainInvalid(
            "the chain must start at the genesis manifest at entry index 0".to_owned(),
        ));
    }
    let carried_anchor = text(obj(receipt, "governance")?, "genesis_entry_id")?;
    if carried_anchor != entry_id(genesis_envelope) {
        return Err(ReceiptError::GovernanceChainInvalid(
            "`genesis_entry_id` does not digest the carried genesis envelope".to_owned(),
        ));
    }
    if carried_anchor != policy.genesis_entry_id {
        return Err(ReceiptError::GenesisAnchorMismatch);
    }
    let genesis_key_ids: BTreeSet<String> =
        key_objects(payload_of(genesis_envelope)?)?.into_iter().map(|(id, _)| id).collect();
    if genesis_key_ids != policy.genesis_key_ids {
        return Err(ReceiptError::GenesisAnchorMismatch);
    }

    Ok(Governance { manifests, events })
}

// ---------------------------------------------------------------------------
// Anchoring
// ---------------------------------------------------------------------------

/// The verified anchoring context every later step checks material against.
struct Anchoring {
    tree_size: u64,
    root: Hash,
    witnessed: bool,
    continued_history: bool,
}

/// Bind a log or witness key to a key object in the manifest version active for the checkpoint
/// being verified (format §2.2). A key a later manifest replaced cannot validate that
/// checkpoint, because `active_index` is fixed by the checkpoint's `tree_size`.
fn bind_log_or_witness_key(
    governance: &Governance<'_>,
    entry: &Value,
    group: &str,
    active_index: u64,
) -> Result<String> {
    let key_id = text(entry, "key_id")?.to_owned();
    if text(entry, "source")? == "local-policy" {
        // Permitted only for witness keys the verifier already trusts (§2.2).
        return if group == "witness" {
            Ok(text(entry, "pubkey")?.to_owned())
        } else {
            Err(ReceiptError::KeyNotBound { key_id, entry_index: active_index })
        };
    }
    let binding_index = number(obj(entry, "binding")?, "entry_index")?;
    if binding_index != active_index {
        return Err(ReceiptError::KeyNotBound { key_id, entry_index: binding_index });
    }
    let (_, manifest) = governance
        .manifests
        .iter()
        .find(|(index, _)| *index == binding_index)
        .copied()
        .ok_or_else(|| ReceiptError::KeyNotBound {
            key_id: key_id.clone(),
            entry_index: binding_index,
        })?;

    let declared: Vec<(String, String)> = if group == "log" {
        key_objects(obj(manifest, "log")?)?
    } else {
        let mut all = Vec::new();
        for witness in array(manifest, "witnesses")? {
            all.extend(key_objects(witness)?);
        }
        all
    };
    let pubkey = text(entry, "pubkey")?;
    declared
        .into_iter()
        .find(|(id, key)| id == &key_id && key == pubkey)
        .map(|(_, key)| key)
        .ok_or(ReceiptError::KeyNotBound { key_id, entry_index: binding_index })
}

/// Bind every producer key the receipt lists to the key set in force at the subject's entry
/// index, under the §7.2 snapshot rule.
///
/// Format §2 calls the producer block "derived from governance chain; listed for convenience,
/// verified against it" — so the check is against the derived set, not against a manifest key
/// object directly. A key that a later manifest's snapshot dropped is absent from that set, so
/// listing it here fails even though an older manifest once declared it.
fn bind_producer_keys(
    receipt: &Value,
    governance: &Governance<'_>,
    subject_index: u64,
) -> Result<()> {
    let in_force = governance.producer_keys_at(subject_index);
    for entry in array(obj(receipt, "keys")?, "producer")? {
        check_key_id(entry)?;
        let key_id = text(entry, "key_id")?.to_owned();
        let binding_index = number(obj(entry, "binding")?, "entry_index")?;
        match in_force.get(&key_id) {
            Some(bound)
                if bound.pubkey == text(entry, "pubkey")? && bound.bound_at == binding_index => {}
            _ => return Err(ReceiptError::KeyNotBound { key_id, entry_index: binding_index }),
        }
    }
    Ok(())
}

/// Recompute a key id from its public key rather than trusting the carried value
/// (adaptor profile §3; producer keys additionally normative per spec §2.3.6).
fn check_key_id(entry: &Value) -> Result<()> {
    let key_id = text(entry, "key_id")?;
    let pubkey = decode_pubkey(text(entry, "pubkey")?)?;
    if sha256_hex(pubkey.as_bytes()) != key_id {
        return Err(ReceiptError::KeyNotBound { key_id: key_id.to_owned(), entry_index: 0 });
    }
    Ok(())
}

/// `key_id -> pubkey` for `keys.log`/`keys.witness` entries that bound successfully at some
/// checkpoint's active manifest index, plus, for every `key_id` that never did, the binding
/// index its first failing entry actually carried.
type BoundAndAttempted = (BTreeMap<String, String>, BTreeMap<String, u64>);

fn verify_checkpoint(
    receipt: &Value,
    governance: &Governance<'_>,
    profile: &AdaptorProfile,
    profile_id: &str,
    budget: &mut Budget,
) -> Result<Anchoring> {
    let anchoring = obj(receipt, "anchoring")?;
    let checkpoint = obj(anchoring, "checkpoint")?;
    // Whether these are usable is a property of the pinned profile document, not of this
    // verifier: `ahl-test-log-v1` defines neither, so receipts under it may carry neither.
    if checkpoint.get("raw").is_some() && !profile.capabilities.checkpoint_raw {
        return Err(ReceiptError::AdaptorCapabilityUnsupported {
            id: profile_id.to_owned(),
            capability: "a binary checkpoint framing for `anchoring.checkpoint.raw`",
        });
    }
    let tree_size = number(checkpoint, "tree_size")?;
    let root = parse_hash_hex(text(checkpoint, "root_hash")?)?;
    let (active_index, active_manifest) = governance.active_for(tree_size)?;

    // The log id must match the manifest version active for the checkpoint (adaptor §5).
    if text(obj(active_manifest, "log")?, "id")? != text(checkpoint, "log_id")? {
        return Err(ReceiptError::GovernanceChainInvalid(
            "checkpoint `log_id` is not the log the active manifest declares".to_owned(),
        ));
    }

    // A `keys.log`/`keys.witness` entry that fails to bind at `active_index` is not necessarily
    // wrong: a `propagation-complete` receipt legitimately carries entries for TWO checkpoints
    // (A here, and D — authenticated separately, spec §2.2) that can be active under different
    // manifest versions, so the same physical key may appear twice under different bindings.
    // Binding is therefore tolerant per entry rather than all-or-nothing for the whole array:
    // any entry that binds successfully is usable; an entry that doesn't is simply not usable
    // FOR THIS CHECKPOINT, and only becomes an error if no entry for that `key_id` ever bound —
    // in which case the error still names that entry's own (wrong) binding index, not
    // `active_index`, so a genuinely mis-bound single entry is reported precisely.
    let keys = obj(receipt, "keys")?;
    let bind_all = |group: &str| -> Result<BoundAndAttempted> {
        let mut bound = BTreeMap::new();
        let mut attempted_index = BTreeMap::new();
        for entry in array(keys, group)? {
            check_key_id(entry)?;
            let key_id = text(entry, "key_id")?.to_owned();
            match bind_log_or_witness_key(governance, entry, group, active_index) {
                Ok(pubkey) => {
                    bound.insert(key_id, pubkey);
                }
                Err(_) if !bound.contains_key(&key_id) => {
                    let index = obj(entry, "binding")
                        .and_then(|b| number(b, "entry_index"))
                        .unwrap_or(active_index);
                    attempted_index.entry(key_id).or_insert(index);
                }
                Err(_) => {}
            }
        }
        Ok((bound, attempted_index))
    };
    let (log_keys, log_attempted) = bind_all("log")?;
    let (witness_keys, witness_attempted) = bind_all("witness")?;

    let signing_key = log_keys.get(text(checkpoint, "key_id")?).ok_or_else(|| {
        let key_id = text(checkpoint, "key_id").unwrap_or_default().to_owned();
        let entry_index = log_attempted.get(&key_id).copied().unwrap_or(active_index);
        ReceiptError::KeyNotBound { key_id, entry_index }
    })?;
    budget.spend(1)?;
    if !verify_signature(
        &decode_pubkey(signing_key)?,
        &checkpoint_signing_bytes(checkpoint)?,
        text(checkpoint, "signature")?,
    )? {
        return Err(ReceiptError::CheckpointSignatureInvalid);
    }

    let mut witnessed = false;
    for cosignature in anchoring.get("witnesses").and_then(Value::as_array).unwrap_or(&Vec::new()) {
        let witness_id = text(cosignature, "witness_id")?.to_owned();
        let key_id = text(cosignature, "key_id")?;
        let pubkey = witness_keys.get(key_id).ok_or_else(|| ReceiptError::KeyNotBound {
            key_id: key_id.to_owned(),
            entry_index: witness_attempted.get(key_id).copied().unwrap_or(active_index),
        })?;
        budget.spend(1)?;
        if !verify_signature(
            &decode_pubkey(pubkey)?,
            &cosignature_bytes(checkpoint, &witness_id),
            text(cosignature, "cosignature")?,
        )? {
            return Err(ReceiptError::WitnessCosignatureInvalid { witness_id });
        }
        witnessed = true;
    }

    // `continued_history` requires a later checkpoint plus a verifying consistency proof.
    // A profile that defines no consistency-proof serialization cannot supply one, so the
    // claim is unverifiable *under that profile* — reject rather than accept it unchecked.
    let continued_history = anchoring.get("later_checkpoint").is_some();
    if continued_history && !profile.capabilities.consistency_proofs {
        return Err(ReceiptError::AdaptorCapabilityUnsupported {
            id: profile_id.to_owned(),
            capability: "a consistency-proof serialization for `anchoring.later_checkpoint`",
        });
    }
    if continued_history {
        // A profile that does declare the capability still owes an actual verified proof;
        // no such profile exists in this tranche, so nothing can reach acceptance here.
        return Err(ReceiptError::ConsistencyPathInvalid);
    }

    Ok(Anchoring { tree_size, root, witnessed, continued_history })
}

/// Verify an inclusion path carried bare (adaptor profile §2.3) against a root.
fn check_inclusion(
    leaf: &[u8],
    leaf_index: u64,
    tree_size: u64,
    path: &[String],
    root: &Hash,
    what: &'static str,
    budget: &mut Budget,
) -> Result<()> {
    budget.spend(1)?;
    let proof = proof_from_hex(leaf_index, tree_size, path)?;
    if crate::verify_inclusion_proof(leaf, &proof, root)? {
        Ok(())
    } else {
        Err(ReceiptError::InclusionPathInvalid { what })
    }
}

// ---------------------------------------------------------------------------
// Authenticated enumeration (format §4.2)
// ---------------------------------------------------------------------------

/// A verified §4.2 enumeration: the complete, in-order entry set of a range.
struct Enumeration {
    from_index: u64,
    to_index: u64,
    entries: Vec<Value>,
}

impl Enumeration {
    /// The entry at absolute index `index`, if the range covers it.
    fn at(&self, index: u64) -> Option<&Value> {
        index
            .checked_sub(self.from_index)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| self.entries.get(offset))
    }
}

fn verify_enumeration(
    material: &Value,
    root: &Hash,
    tree_size: u64,
    what: &'static str,
    budget: &mut Budget,
) -> Result<Enumeration> {
    let range = obj(material, "range")?;
    let from_index = number(range, "from_index")?;
    let to_index = number(range, "to_index")?;
    let entries = array(material, "entries")?;

    let width = to_index.checked_sub(from_index).filter(|w| *w > 0).ok_or_else(|| {
        ReceiptError::RangeProofInvalid {
            what,
            detail: format!("empty or inverted range [{from_index}, {to_index})"),
        }
    })?;
    if entries.len() as u64 != width {
        return Err(ReceiptError::RangeProofInvalid {
            what,
            detail: format!("range width {width} but {} entries carried", entries.len()),
        });
    }

    let mut envelopes = Vec::with_capacity(entries.len());
    for (offset, entry) in entries.iter().enumerate() {
        let claimed = number(entry, "entry_index")?;
        let expected = from_index + offset as u64;
        if claimed != expected {
            return Err(ReceiptError::RangeProofInvalid {
                what,
                detail: format!("entry {offset} claims index {claimed}, expected {expected}"),
            });
        }
        envelopes.push(obj(entry, "envelope")?.clone());
    }

    let proof = range_proof::decode(text(obj(material, "range_proof")?, "adaptor_form")?)?;
    if proof.tree_size != tree_size || proof.from_index != from_index || proof.to_index != to_index
    {
        return Err(ReceiptError::RangeProofInvalid {
            what,
            detail: format!(
                "proof covers [{}, {}) of a size-{} tree, material declares [{from_index}, \
                 {to_index}) of a size-{tree_size} tree",
                proof.from_index, proof.to_index, proof.tree_size
            ),
        });
    }
    budget.spend(u64::try_from(envelopes.len()).unwrap_or(u64::MAX).saturating_add(1))?;
    let leaves: Vec<Vec<u8>> = envelopes.iter().map(jcs).collect();
    if !range_proof::verify_over_leaves(&proof, &leaves, root)? {
        return Err(ReceiptError::RangeProofInvalid {
            what,
            detail: "recomputed root differs from the checkpoint root".to_owned(),
        });
    }

    Ok(Enumeration { from_index, to_index, entries: envelopes })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Verify an Evidence Receipt against locally configured policy.
///
/// Implements the receipt format's §5 algorithm in order: parse and versions and §3.1 limits;
/// adaptor-profile resolution; checkpoint, key binding, witness cosignatures and inclusion;
/// governance chain from the configured genesis anchor; the §3 claim-material schema; the §2.3
/// cross-field consistency rules; and finally the rendered boundary.
///
/// # Errors
///
/// Returns the [`ReceiptError`] variant naming the first rule that rejected the receipt.
pub fn verify_receipt(receipt: &Value, policy: &TrustPolicy) -> Result<Verdict> {
    let encoded = jcs(receipt);
    if encoded.len() > policy.limits.max_decoded_bytes {
        return Err(ReceiptError::LimitExceeded("decoded size budget"));
    }
    let mut budget = Budget::new(policy.limits);
    let verdict = verify_nested(receipt, policy, &mut budget, 0)?;
    Ok(Verdict { embedded_receipts: budget.embedded, ..verdict })
}

/// Verify a receipt at nesting `depth`, sharing the whole tree's resource budget.
// The §5 algorithm is a fixed ordered sequence of steps; splitting it into helpers that each
// take the growing set of intermediate results would obscure the order the format mandates.
#[allow(clippy::too_many_lines)]
fn verify_nested(
    receipt: &Value,
    policy: &TrustPolicy,
    budget: &mut Budget,
    depth: usize,
) -> Result<Verdict> {
    budget.enter(depth)?;

    // --- §5 step 1: versions, identifiers -------------------------------------------
    for (field, expected) in
        [("ahl_receipt_version", RECEIPT_VERSION), ("spec_version", SPEC_VERSION)]
    {
        let got = text(receipt, field)?;
        if got != expected {
            return Err(ReceiptError::UnsupportedVersion {
                field: if field == "spec_version" { "spec_version" } else { "ahl_receipt_version" },
                expected,
                got: got.to_owned(),
            });
        }
    }

    let envelope = obj(receipt, "envelope")?;
    let subject = obj(receipt, "subject")?;
    if text(subject, "statement_id")? != statement_id(envelope)? {
        return Err(ReceiptError::IdentifierMismatch { field: "statement_id" });
    }
    if text(subject, "entry_id")? != entry_id(envelope) {
        return Err(ReceiptError::IdentifierMismatch { field: "entry_id" });
    }
    let subject_index = number(subject, "entry_index")?;
    let payload = payload_of(envelope)?;
    let subject_type = statement_type(payload)?.to_owned();

    // --- §5 step 2: adaptor profile -------------------------------------------------
    let adaptor = obj(obj(receipt, "anchoring")?, "adaptor")?;
    let adaptor_id = text(adaptor, "id")?;
    let profile = policy
        .adaptor_profiles
        .get(adaptor_id)
        .filter(|profile| profile.hash == text(adaptor, "hash").unwrap_or_default())
        .ok_or_else(|| ReceiptError::AdaptorUnknown { id: adaptor_id.to_owned() })?;

    // --- §5 step 4 (chain structure first: key binding depends on it) ---------------
    let governance = read_chain(receipt, policy)?;

    // --- §5 step 3: checkpoint, keys, cosignatures, inclusion -----------------------
    let anchoring = verify_checkpoint(receipt, &governance, profile, adaptor_id, budget)?;
    if subject_index >= anchoring.tree_size {
        return Err(ReceiptError::EntryIndexBeyondCheckpoint {
            entry_index: subject_index,
            tree_size: anchoring.tree_size,
        });
    }
    check_inclusion(
        &jcs(envelope),
        subject_index,
        anchoring.tree_size,
        &path_strings(obj(receipt, "anchoring")?, "inclusion_path")?,
        &anchoring.root,
        "subject",
        budget,
    )?;

    // --- §5 step 4: chain anchoring and signatures ----------------------------------
    for hop in array(obj(receipt, "governance")?, "chain")? {
        let index = number(hop, "entry_index")?;
        let hop_envelope = obj(hop, "envelope")?;
        check_inclusion(
            &jcs(hop_envelope),
            index,
            anchoring.tree_size,
            &path_strings(hop, "inclusion_path")?,
            &anchoring.root,
            "governance chain hop",
            budget,
        )?;
        verify_envelope_at(hop_envelope, &governance, index, budget)?;
    }
    verify_envelope_at(envelope, &governance, subject_index, budget)?;
    // Every producer key the receipt lists must be in force at the subject's entry index under
    // the §7.2 snapshot rule, bound to the governance statement that put it there (§2.2).
    bind_producer_keys(receipt, &governance, subject_index)?;

    // --- §2.1 / §4: governance currency ---------------------------------------------
    let claim = obj(receipt, "claim")?;
    let assurance_block = obj(claim, "assurance")?;
    let assurance = Assurance {
        governance: text(assurance_block, "governance")?.to_owned(),
        competing_triggers: text(assurance_block, "competing_triggers")?.to_owned(),
        witnessed: flag(assurance_block, "witnessed")?,
        continued_history: flag(assurance_block, "continued_history")?,
        content_binding: text(assurance_block, "content_binding")?.to_owned(),
    };
    let currency = obj(obj(receipt, "governance")?, "currency")?;
    let mode = text(currency, "mode")?;
    if assurance.governance != mode {
        return Err(ReceiptError::AssuranceMismatch { field: "governance" });
    }
    if assurance.witnessed != anchoring.witnessed {
        return Err(ReceiptError::AssuranceMismatch { field: "witnessed" });
    }
    if assurance.continued_history != anchoring.continued_history {
        return Err(ReceiptError::AssuranceMismatch { field: "continued_history" });
    }

    let claim_type = text(claim, "type")?.to_owned();
    let enumeration = match mode {
        "declared" => {
            if !DECLARED_MODE_TYPES.contains(&claim_type.as_str()) {
                return Err(ReceiptError::AssuranceMismatch { field: "governance" });
            }
            None
        }
        "enumerated" => {
            Some(verify_governance_enumeration(currency, &governance, &anchoring, budget)?)
        }
        other => return Err(ReceiptError::Malformed(format!("unknown governance mode `{other}`"))),
    };

    // --- §2.3: subject-level cross-field consistency --------------------------------
    let manifest_declared = subject.get("manifest").is_some();
    if manifest_declared == (subject_type == "manifest") {
        return Err(ReceiptError::SubjectManifestPresence { statement_type: subject_type });
    }
    let record_subject = check_record_subject(claim, payload, &claim_type, &subject_type)?;

    // --- §5 step 5: the §3 claim-material schema ------------------------------------
    let ctx = ClaimCtx {
        receipt,
        policy,
        governance: &governance,
        anchoring_checkpoint: obj(obj(receipt, "anchoring")?, "checkpoint")?,
        payload,
        subject_index,
        claim_type: &claim_type,
        assurance: &assurance,
        record_subject: record_subject.as_ref(),
        enumeration: enumeration.as_ref(),
        depth,
    };
    verify_claim_material(&ctx, budget)?;

    Ok(Verdict {
        boundary: render(&claim_type, &assurance),
        claim_type,
        subject_entry_index: subject_index,
        subject_statement_id: text(subject, "statement_id")?.to_owned(),
        assurance,
        embedded_receipts: budget.embedded,
    })
}

/// Claim types §4 permits in `declared` mode.
const DECLARED_MODE_TYPES: [&str; 5] = [
    "statement-anchored",
    "record-ingested",
    "record-derived",
    "trigger-declared",
    "disposition-declared",
];

fn verify_envelope_at(
    envelope: &Value,
    governance: &Governance<'_>,
    index: u64,
    budget: &mut Budget,
) -> Result<()> {
    let keys = governance.producer_pubkeys_at(index);
    budget.spend(1)?;
    if crate::verify_envelope(envelope, |key_id| keys.get(key_id).cloned())? {
        Ok(())
    } else {
        Err(ReceiptError::EnvelopeSignatureInvalid { entry_index: index })
    }
}

/// Verify enumerated governance currency: the presented chain is the complete set of
/// manifest/key entries in the enumerated range (§4).
fn verify_governance_enumeration(
    currency: &Value,
    governance: &Governance<'_>,
    anchoring: &Anchoring,
    budget: &mut Budget,
) -> Result<Enumeration> {
    let material = obj(currency, "material")?;
    let enumeration =
        verify_enumeration(material, &anchoring.root, anchoring.tree_size, "governance", budget)?;

    // Format §4: enumerated currency is an authenticated range over **exactly**
    // `[0, tree_size(C))`, where C is the receipt's verified checkpoint. Anything narrower
    // proves nothing about authority: a receipt that enumerated only `[0, 1)` could hide a
    // later key retirement and validate a signature with a key the corpus had already retired.
    // Claim types that name a checkpoint bind it field-exact to `anchoring.checkpoint` (§3),
    // so `anchoring.tree_size` is `tree_size(C)` for every enumerated claim type.
    if enumeration.from_index != 0 || enumeration.to_index != anchoring.tree_size {
        return Err(ReceiptError::GovernanceRangeNotComplete {
            got_from: enumeration.from_index,
            got_to: enumeration.to_index,
            tree_size: anchoring.tree_size,
        });
    }

    let presented: BTreeSet<u64> = governance.manifests.iter().map(|(index, _)| *index).collect();
    let mut presented_all = presented;
    presented_all.extend(governance.events.iter().map(|e| e.entry_index));

    for (offset, envelope) in enumeration.entries.iter().enumerate() {
        let index = enumeration.from_index + offset as u64;
        let kind = statement_type(payload_of(envelope)?)?;
        if matches!(kind, "manifest" | "key") && !presented_all.contains(&index) {
            return Err(ReceiptError::GovernanceChainInvalid(format!(
                "enumeration reveals a `{kind}` statement at entry index {index} that the \
                 presented chain omits"
            )));
        }
    }
    Ok(enumeration)
}

/// Enforce the §3 subject rule and the §2.3 `record_subject` match.
fn check_record_subject(
    claim: &Value,
    payload: &Value,
    claim_type: &str,
    subject_type: &str,
) -> Result<Option<(String, String)>> {
    let required = claim_type.starts_with("record-")
        || claim_type.starts_with("trigger-")
        || claim_type.starts_with("disposition-");
    let carried = claim.get("record_subject");

    match (required, carried) {
        (false, Some(_)) => Err(ReceiptError::RecordSubjectMismatch {
            claim_type: claim_type.to_owned(),
            detail: "must be absent for this claim type (§3 subject rule)".to_owned(),
        }),
        (false, None) => Ok(None),
        (true, None) => Err(ReceiptError::RecordSubjectMismatch {
            claim_type: claim_type.to_owned(),
            detail: "is REQUIRED for this claim type (§3 subject rule)".to_owned(),
        }),
        (true, Some(subject)) => {
            let pair = (text(subject, "dataset")?.to_owned(), text(subject, "record")?.to_owned());
            // Types whose subject envelope names the record directly must agree with it.
            if matches!(subject_type, "ingestion" | "retraction" | "correction") {
                let declared =
                    (text(payload, "dataset")?.to_owned(), text(payload, "record")?.to_owned());
                if declared != pair {
                    return Err(ReceiptError::RecordSubjectMismatch {
                        claim_type: claim_type.to_owned(),
                        detail: format!(
                            "names `{}` but the subject envelope names `{}` (§2.3)",
                            pair.1, declared.1
                        ),
                    });
                }
            }
            Ok(Some(pair))
        }
    }
}

// ---------------------------------------------------------------------------
// Claim material (format §3)
// ---------------------------------------------------------------------------

struct ClaimCtx<'a> {
    receipt: &'a Value,
    policy: &'a TrustPolicy,
    governance: &'a Governance<'a>,
    /// The checkpoint this receipt already verified in §5 step 3 — signature, witness
    /// cosignature and inclusion path. Claim checkpoints bind to it (§3).
    anchoring_checkpoint: &'a Value,
    payload: &'a Value,
    subject_index: u64,
    claim_type: &'a str,
    assurance: &'a Assurance,
    record_subject: Option<&'a (String, String)>,
    enumeration: Option<&'a Enumeration>,
    depth: usize,
}

impl ClaimCtx<'_> {
    fn material(&self) -> Result<&Value> {
        obj(self.receipt, "claim_material")
    }

    fn missing(&self, field: &'static str) -> ReceiptError {
        ReceiptError::ClaimMaterialMissing { claim_type: self.claim_type.to_owned(), field }
    }

    fn require_subject_type(&self, expected: &str) -> Result<()> {
        let got = statement_type(self.payload)?;
        if got == expected {
            Ok(())
        } else {
            Err(ReceiptError::Malformed(format!(
                "claim type `{}` requires a `{expected}` subject, got `{got}`",
                self.claim_type
            )))
        }
    }
}

fn verify_claim_material(ctx: &ClaimCtx<'_>, budget: &mut Budget) -> Result<()> {
    match ctx.claim_type {
        "statement-anchored" => Ok(()),
        "record-ingested" => verify_record_ingested(ctx),
        "record-derived" => verify_record_derived(ctx, budget),
        "trigger-declared" => verify_trigger(ctx, budget, "trigger-declared"),
        "trigger-effective" => verify_trigger(ctx, budget, "trigger-effective"),
        "disposition-declared" => verify_disposition(ctx, budget, "trigger-declared"),
        "disposition-effective" => verify_disposition(ctx, budget, "trigger-effective"),
        "propagation-complete" => verify_propagation_complete(ctx, budget),
        "governance-state" => verify_governance_state(ctx),
        other => Err(ReceiptError::Malformed(format!("`{other}` is not a registry claim type"))),
    }
}

/// `record-ingested` (§3): the subject ingestion introduces the record; optional content
/// binding recomputes the commitment from carried canonical bytes.
fn verify_record_ingested(ctx: &ClaimCtx<'_>) -> Result<()> {
    ctx.require_subject_type("ingestion")?;
    let (dataset, record) = ctx.record_subject.ok_or_else(|| ctx.missing("record_subject"))?;
    verify_content_binding(ctx, dataset, record, "record_bytes")
}

/// Recompute a commitment from carried canonical bytes per the dataset's declared mode
/// (§2.1, spec §2.4). `content_binding: "none"` requires the evidence fields to be absent.
fn verify_content_binding(
    ctx: &ClaimCtx<'_>,
    dataset: &str,
    record: &str,
    field: &'static str,
) -> Result<()> {
    let material = ctx.material()?;
    if ctx.assurance.content_binding == "none" {
        return if material.get(field).is_some() {
            Err(ReceiptError::AssuranceMismatch { field: "content_binding" })
        } else {
            Ok(())
        };
    }

    let (_, manifest) = ctx.governance.active_for(ctx.subject_index + 1)?;
    let declared_mode =
        text(obj(obj(manifest, "datasets")?, dataset)?, "commitment_mode")?.to_owned();
    let encoded = material.get(field).and_then(Value::as_str).ok_or_else(|| ctx.missing(field))?;
    let bytes = B64
        .decode(crate::strip_prefix(encoded, "base64:")?)
        .map_err(|source| ReceiptError::Ahl(AhlError::Base64(source)))?;

    let recomputed = match ctx.assurance.content_binding.as_str() {
        "plain-verified" if declared_mode == "plain" => commit_plain(dataset, &bytes),
        "keyed-authorized" if declared_mode == "keyed" => {
            let key = ctx.policy.dataset_keys.get(dataset).ok_or_else(|| {
                ReceiptError::ContentBindingMismatch {
                    mode: "keyed-authorized".to_owned(),
                    recomputed: "<no dataset key held>".to_owned(),
                    claimed: record.to_owned(),
                }
            })?;
            commit_keyed(key, dataset, &bytes)?
        }
        // A binding mode the dataset's declared commitment mode cannot satisfy (§2.1).
        mode => {
            return Err(ReceiptError::ContentBindingMismatch {
                mode: mode.to_owned(),
                recomputed: format!("<dataset `{dataset}` is in `{declared_mode}` mode>"),
                claimed: record.to_owned(),
            })
        }
    };
    if recomputed == record {
        Ok(())
    } else {
        Err(ReceiptError::ContentBindingMismatch {
            mode: ctx.assurance.content_binding.clone(),
            recomputed,
            claimed: record.to_owned(),
        })
    }
}

/// `record-derived` (§3): one output record's derivation, unbatched or through the batch tree.
fn verify_record_derived(ctx: &ClaimCtx<'_>, budget: &mut Budget) -> Result<()> {
    ctx.require_subject_type("derivation")?;
    let material = ctx.material()?;
    let output = obj(material, "output")?;
    let claimed = (text(output, "dataset")?.to_owned(), text(output, "record")?.to_owned());
    if ctx.record_subject != Some(&claimed) {
        return Err(ReceiptError::RecordSubjectMismatch {
            claim_type: ctx.claim_type.to_owned(),
            detail: "does not match `claim_material.output`".to_owned(),
        });
    }

    if let Some(root) = ctx.payload.get("outputs_root").and_then(Value::as_str) {
        let leaf = material.get("batch_leaf").ok_or_else(|| ctx.missing("batch_leaf"))?;
        if (text(leaf, "dataset")?.to_owned(), text(leaf, "record")?.to_owned()) != claimed {
            return Err(ReceiptError::ClaimMaterialPathInvalid { what: "batch_leaf" });
        }
        let count = number(ctx.payload, "outputs_count")?;
        let index = number(material, "leaf_index")?;
        check_inclusion(
            &jcs(leaf),
            index,
            count,
            &path_strings(material, "leaf_path")?,
            &parse_hash_hex(root)?,
            "batch output leaf",
            budget,
        )?;
        verify_input_members(ctx, leaf, budget)?;
    } else {
        let listed = array(ctx.payload, "outputs")?.iter().any(|entry| {
            entry.get("dataset").and_then(Value::as_str) == Some(claimed.0.as_str())
                && entry.get("record").and_then(Value::as_str) == Some(claimed.1.as_str())
        });
        if !listed {
            return Err(ReceiptError::ClaimMaterialPathInvalid { what: "output" });
        }
    }

    verify_content_binding(ctx, &claimed.0, &claimed.1, "output_bytes")
}

/// Optional `input_members` (§3): each proves one input's membership in the leaf's input set.
fn verify_input_members(ctx: &ClaimCtx<'_>, leaf: &Value, budget: &mut Budget) -> Result<()> {
    let material = ctx.material()?;
    let Some(members) = material.get("input_members").and_then(Value::as_array) else {
        return Ok(());
    };
    let inputs = leaf.get("inputs").ok_or_else(|| ctx.missing("batch_leaf.inputs"))?;
    let root = text(inputs, "input_set_root")?;
    let count = number(inputs, "input_set_count")?;
    for member in members {
        let input = obj(member, "input")?;
        check_inclusion(
            &jcs(input),
            number(member, "input_index")?,
            count,
            &path_strings(member, "input_path")?,
            &parse_hash_hex(root)?,
            "input-set member",
            budget,
        )?;
    }
    Ok(())
}

/// An embedded receipt, verified recursively under the shared §3.1 budget.
struct Embedded {
    verdict: Verdict,
    entry_index: u64,
    record: Option<(String, String)>,
}

/// Claim types accepted in an embedded slot. `introduction` slots accept either introduction
/// form, because a record is introduced by an ingestion *or* by a derivation (spec §2.3.1).
const INTRODUCTION_TYPES: [&str; 2] = ["record-ingested", "record-derived"];

/// Verify an embedded receipt and return its verdict, subject index and record subject.
fn verify_embedded(
    ctx: &ClaimCtx<'_>,
    slot: &'static str,
    expected: &'static str,
    permitted: &[&str],
    budget: &mut Budget,
) -> Result<Embedded> {
    let embedded =
        ctx.material()?.get(slot).filter(|v| v.is_object()).ok_or_else(|| ctx.missing(slot))?;
    // Duplicate embedded receipts are verified once and referenced thereafter (§3.1). The key
    // is the digest of the *entire* receipt object, so only byte-identical receipts share a
    // cache entry; two receipts about the same statement with different claim material are
    // each verified in full.
    let key = sha256_hex(&jcs(embedded));
    let verdict = if let Some(cached) = budget.verified.get(&key) {
        cached.clone()
    } else {
        let verdict = verify_nested(embedded, ctx.policy, budget, ctx.depth + 1)?;
        budget.verified.insert(key, verdict.clone());
        verdict
    };

    if !permitted.contains(&verdict.claim_type.as_str()) {
        return Err(ReceiptError::EmbeddedClaimTypeMismatch {
            slot,
            expected,
            got: verdict.claim_type,
        });
    }
    let record = obj(embedded, "claim")?.get("record_subject").map(|subject| {
        (
            subject.get("dataset").and_then(Value::as_str).unwrap_or_default().to_owned(),
            subject.get("record").and_then(Value::as_str).unwrap_or_default().to_owned(),
        )
    });
    Ok(Embedded { verdict, entry_index: number(obj(embedded, "subject")?, "entry_index")?, record })
}

/// `trigger-declared` / `trigger-effective` (§3).
fn verify_trigger(ctx: &ClaimCtx<'_>, budget: &mut Budget, kind: &str) -> Result<()> {
    let subject_type = statement_type(ctx.payload)?;
    if !matches!(subject_type, "retraction" | "correction") {
        return Err(ReceiptError::Malformed(format!(
            "claim type `{}` requires a trigger subject, got `{subject_type}`",
            ctx.claim_type
        )));
    }
    let (_, record) = ctx.record_subject.ok_or_else(|| ctx.missing("record_subject"))?;

    // The introduction proof establishes who may retract (§3 authority note).
    let introduction =
        verify_embedded(ctx, "introduction", "introduction", &INTRODUCTION_TYPES, budget)?;
    // Spec §2.3.3: a trigger anchored at a smaller entry index than the record's introduction
    // is never effective — authority cannot predate the introduction that creates it.
    if introduction.entry_index >= ctx.subject_index {
        return Err(ReceiptError::EmbeddedOrderingViolation {
            what: "introduction",
            inner: introduction.entry_index,
            outer: ctx.subject_index,
        });
    }
    if introduction.record.as_ref().map(|(_, r)| r.as_str()) != Some(record.as_str()) {
        return Err(ReceiptError::EmbeddedSubjectMismatch {
            what: "introduction",
            got: introduction.record.map_or_else(String::new, |(_, r)| r),
            want: record.clone(),
        });
    }

    if subject_type == "correction" {
        let replacement = text(ctx.payload, "replacement")?.to_owned();
        let embedded = verify_embedded(
            ctx,
            "replacement_introduction",
            "introduction",
            &INTRODUCTION_TYPES,
            budget,
        )?;
        // Spec §2.3.3: a correction's replacement must be introduced at an entry index no
        // greater than the correction's.
        if embedded.entry_index > ctx.subject_index {
            return Err(ReceiptError::EmbeddedOrderingViolation {
                what: "replacement introduction",
                inner: embedded.entry_index,
                outer: ctx.subject_index,
            });
        }
        if embedded.record.as_ref().map(|(_, r)| r.as_str()) != Some(replacement.as_str()) {
            return Err(ReceiptError::EmbeddedSubjectMismatch {
                what: "replacement introduction",
                got: embedded.record.map_or_else(String::new, |(_, r)| r),
                want: replacement,
            });
        }
    }

    // Scope is what makes a trigger meaningful at all; a scopeless one is malformed (§2.3.3).
    Scope::from_payload(ctx.payload)?;

    if kind == "trigger-effective" {
        // "Effective" is exactly the authority claim: an unauthorized trigger is a challenge
        // (spec §2.3.3) and can never be effective, however well anchored it is.
        verify_trigger_authority(ctx, &introduction, budget)?;
        verify_competing_triggers(ctx, &introduction, budget)?;
    } else if ctx.assurance.competing_triggers != "not-checked" {
        return Err(ReceiptError::AssuranceMismatch { field: "competing_triggers" });
    }
    Ok(())
}

/// The three members that identify a checkpoint (spec §2.3.4 wire form).
const CHECKPOINT_IDENTITY: [&str; 3] = ["log_id", "tree_size", "root_hash"];

/// Compare two checkpoint objects on the §2.3.4 identity fields.
///
/// Format §3 fixes the comparison as "an identity-field match; extra checkpoint fields are
/// compared when present". So `{log_id, tree_size, root_hash}` are REQUIRED on the carried
/// object and must agree; any other member is compared only when both sides carry it, and is
/// never itself required. That lets a bare §2.3.4 checkpoint reference be compared against a
/// full signed checkpoint object without the missing `signature`/`key_id` counting against it.
fn checkpoints_agree(carried: &Value, reference: &Value, field: &'static str) -> Result<()> {
    let carried =
        carried.as_object().ok_or_else(|| ReceiptError::Malformed(format!("`{field}` object")))?;
    let reference = reference
        .as_object()
        .ok_or_else(|| ReceiptError::Malformed("reference checkpoint object".to_owned()))?;

    for member in CHECKPOINT_IDENTITY {
        match carried.get(member) {
            Some(value) if reference.get(member) == Some(value) => {}
            _ => return Err(ReceiptError::CheckpointNotBound { field, member: member.to_owned() }),
        }
    }
    for (member, value) in carried {
        if reference.get(member).is_some_and(|other| other != value) {
            return Err(ReceiptError::CheckpointNotBound { field, member: member.clone() });
        }
    }
    Ok(())
}

/// Bind `checkpoint_C` to the receipt's own verified `anchoring.checkpoint` (format §3).
///
/// For `trigger-effective` — and, through its embedded trigger, `disposition-effective` — C
/// **is** the anchoring checkpoint: a "governs" claim may only rest on a checkpoint whose
/// signature, witness cosignature and inclusion path this verifier actually checked.
/// `propagation-complete` is the deliberate exception: its `corpus_checkpoint` is the
/// propagation's own declared D, generally *earlier* than A, and is authenticated by
/// [`authenticate_declared_checkpoint`] plus prefix recomputation instead.
fn bind_checkpoint(ctx: &ClaimCtx<'_>, carried: &Value, field: &'static str) -> Result<u64> {
    checkpoints_agree(carried, ctx.anchoring_checkpoint, field)?;
    number(ctx.anchoring_checkpoint, "tree_size")
}

/// Whether the record whose triggers are being judged was introduced by an ingestion.
///
/// Spec §2.3.3 routes authority differently for the two introduction forms, and the embedded
/// introduction receipt is what tells the verifier which one applies.
fn introduced_by_ingestion(introduction: &Embedded) -> bool {
    introduction.verdict.claim_type == "record-ingested"
}

/// The key set entitled to trigger `dataset`'s record, **as of `index`** (spec §2.3.3, §7.2).
///
/// Both branches are resolved at the *trigger's* entry index, never at the introduction's:
///
/// * ingested records — the manifest's declared dataset authority `{producer, key_ids}`,
///   intersected with the producer keys in force at `index`, because §7.2 requires a trigger's
///   signing key to be "in the authority key set AND active at the trigger's entry index";
/// * derived records — the introducing producer's key set as of `index`. §2.3.3 is explicit
///   that this is *not* the introduction index: a key rotation between introduction and
///   trigger applies, so a key added after the derivation may still trigger its output.
fn authority_at(
    ctx: &ClaimCtx<'_>,
    dataset: &str,
    by_ingestion: bool,
    index: u64,
) -> Result<BTreeSet<String>> {
    let in_force: BTreeSet<String> = ctx.governance.producer_keys_at(index).into_keys().collect();
    if !by_ingestion {
        return Ok(in_force);
    }
    let (_, manifest) = ctx.governance.snapshot_manifest(index).ok_or_else(|| {
        ReceiptError::GovernanceChainInvalid("no manifest governs the trigger".to_owned())
    })?;
    let declared = obj(obj(manifest, "datasets")?, dataset)?;
    let authority = declared.get("authority").ok_or_else(|| {
        ReceiptError::GovernanceChainInvalid(format!(
            "dataset `{dataset}` declares no authority, so an ingestion into it is invalid \
             (spec §7.2)"
        ))
    })?;
    let declared_keys: BTreeSet<String> = array(authority, "key_ids")?
        .iter()
        .map(|id| {
            id.as_str()
                .map(str::to_owned)
                .ok_or_else(|| ReceiptError::Malformed("`authority.key_ids` element".to_owned()))
        })
        .collect::<Result<_>>()?;
    Ok(&declared_keys & &in_force)
}

/// Whether the envelope at `index` is a trigger signed — cryptographically, not just by
/// claimed `key_id` — by the record's authority.
///
/// A candidate's `signatures[].key_id` naming an authority key proves nothing on its own: the
/// `sig` bytes are controlled by whoever assembled the statement, who may be a party without
/// authority. Every candidate MUST be checked with the same `verify_envelope` machinery used
/// for real statements, restricted to authority keys so an envelope signed by some *other*
/// valid producer key still correctly fails (that signer isn't this record's authority,
/// whether or not the bytes verify). A non-verifying envelope that reuses a real authority
/// `key_id` with a garbage signature can otherwise displace the genuinely authorized trigger
/// just by anchoring at a later index.
fn is_authorized_trigger(
    ctx: &ClaimCtx<'_>,
    envelope: &Value,
    dataset: &str,
    by_ingestion: bool,
    index: u64,
    budget: &mut Budget,
) -> Result<bool> {
    budget.spend(1)?;
    let authority = authority_at(ctx, dataset, by_ingestion, index)?;
    let pubkeys = ctx.governance.producer_pubkeys_at(index);
    Ok(crate::verify_envelope(envelope, |key_id| {
        if authority.contains(key_id) {
            pubkeys.get(key_id).cloned()
        } else {
            None
        }
    })?)
}

/// Spec §2.3.3: a trigger is effective only if signed by the record's authority. Triggers from
/// any other key anchor as **challenges**: surfaced by verification, never traversed.
///
/// Format §3 requires this to be a real cryptographic check, not a `key_id` name match: a
/// signature entry that merely *names* an authority key proves nothing on its own, since the
/// `sig` bytes are controlled by whoever assembled the envelope. This routes through the same
/// `is_authorized_trigger` machinery `verify_competing_triggers` uses, so the receipt's own
/// envelope must actually verify against an authority key active at `ctx.subject_index`.
fn verify_trigger_authority(
    ctx: &ClaimCtx<'_>,
    introduction: &Embedded,
    budget: &mut Budget,
) -> Result<()> {
    let (dataset, record) = ctx.record_subject.ok_or_else(|| ctx.missing("record_subject"))?;
    let envelope = obj(ctx.receipt, "envelope")?;
    let by_ingestion = introduced_by_ingestion(introduction);
    if !is_authorized_trigger(ctx, envelope, dataset, by_ingestion, ctx.subject_index, budget)? {
        let signers: BTreeSet<String> = array(envelope, "signatures")?
            .iter()
            .map(|signature| Ok(text(signature, "key_id")?.to_owned()))
            .collect::<Result<_>>()?;
        return Err(ReceiptError::TriggerNotAuthorized {
            entry_index: ctx.subject_index,
            record: record.clone(),
            signed_by: signers.into_iter().collect::<Vec<_>>().join(", "),
        });
    }
    Ok(())
}

/// The §3 competing-trigger enumeration required by `trigger-effective`.
fn verify_competing_triggers(
    ctx: &ClaimCtx<'_>,
    introduction: &Embedded,
    budget: &mut Budget,
) -> Result<()> {
    let introduction_index = introduction.entry_index;
    if ctx.assurance.competing_triggers != "enumerated" || ctx.assurance.governance != "enumerated"
    {
        return Err(ReceiptError::AssuranceMismatch { field: "competing_triggers" });
    }
    let material = ctx.material()?;
    // C must be the receipt's own verified checkpoint (§3), not a self-supplied one.
    let tree_size =
        bind_checkpoint(ctx, obj(material, "checkpoint_C")?, "claim_material.checkpoint_C")?;
    let root = parse_hash_hex(text(ctx.anchoring_checkpoint, "root_hash")?)?;
    let competing = obj(material, "competing")?;
    let range_material = obj(competing, "corpus_range")?;

    let enumeration =
        verify_enumeration(range_material, &root, tree_size, "competing triggers", budget)?;

    // The range must be the complete corpus prefix, or the prefix from the record's
    // introduction — sound because a trigger anchored before the introduction is never
    // effective (spec §2.3.3).
    if enumeration.to_index != tree_size
        || (enumeration.from_index != 0 && enumeration.from_index != introduction_index)
    {
        return Err(ReceiptError::CompetingRangeInsufficient {
            got_from: enumeration.from_index,
            got_to: enumeration.to_index,
            tree_size,
            introduction_index,
        });
    }

    // Among the **effective** triggers naming the record, the greatest entry index governs
    // (spec §2.3.3); the subject must be that one.
    //
    // Effectiveness is decided before the index comparison, not after. A trigger signed by a
    // key that is not the record's authority anchors as a challenge and is "never traversed" —
    // so it can never displace an earlier valid trigger, however much later it sits in the
    // log. Selecting by index first and filtering afterwards would let anyone who can get a
    // statement anchored unseat the governing trigger of a record they have no authority over.
    let (dataset, record) = ctx.record_subject.ok_or_else(|| ctx.missing("record_subject"))?;
    let by_ingestion = introduced_by_ingestion(introduction);
    let mut governing = None;
    let mut challenges = Vec::new();
    for (offset, envelope) in enumeration.entries.iter().enumerate() {
        let index = enumeration.from_index + offset as u64;
        let payload = payload_of(envelope)?;
        if !matches!(statement_type(payload)?, "retraction" | "correction")
            || payload.get("dataset").and_then(Value::as_str) != Some(dataset.as_str())
            || payload.get("record").and_then(Value::as_str) != Some(record.as_str())
        {
            continue;
        }
        if is_authorized_trigger(ctx, envelope, dataset, by_ingestion, index, budget)? {
            governing = Some(index);
        } else {
            challenges.push(index);
        }
    }
    if !challenges.is_empty() {
        // Surfaced, as §2.3.3 requires — but not traversed, and not permitted to govern.
        budget.spend(challenges.len() as u64)?;
    }
    if governing != Some(ctx.subject_index) {
        return Err(ReceiptError::ClosureMismatch(format!(
            "the trigger governing `{record}` at tree size {tree_size} is at entry index {}, \
             not {}",
            governing.map_or_else(|| "<none>".to_owned(), |i| i.to_string()),
            ctx.subject_index
        )));
    }
    Ok(())
}

/// `disposition-declared` / `disposition-effective` (§3).
fn verify_disposition(
    ctx: &ClaimCtx<'_>,
    budget: &mut Budget,
    trigger_kind: &'static str,
) -> Result<()> {
    ctx.require_subject_type("propagation")?;
    let material = ctx.material()?;
    let trigger = verify_embedded(ctx, "trigger", trigger_kind, &[trigger_kind], budget)?;

    // The propagation must name the trigger the embedded receipt proves (spec §2.3.4).
    if text(ctx.payload, "trigger")? != trigger.verdict.subject_statement_id {
        return Err(ReceiptError::EmbeddedSubjectMismatch {
            what: "trigger",
            got: trigger.verdict.subject_statement_id,
            want: text(ctx.payload, "trigger")?.to_owned(),
        });
    }
    // §2.3: introduction index < trigger index <= propagation index.
    if trigger.entry_index > ctx.subject_index {
        return Err(ReceiptError::EmbeddedOrderingViolation {
            what: "trigger",
            inner: trigger.entry_index,
            outer: ctx.subject_index,
        });
    }

    let leaf = material.get("disposition_leaf").ok_or_else(|| ctx.missing("disposition_leaf"))?;
    let leaf_record = (text(leaf, "dataset")?.to_owned(), text(leaf, "record")?.to_owned());
    if ctx.record_subject != Some(&leaf_record) {
        return Err(ReceiptError::RecordSubjectMismatch {
            claim_type: ctx.claim_type.to_owned(),
            detail: "does not match the carried disposition leaf".to_owned(),
        });
    }
    // The dispositioned record must not be the trigger's own record: dispositions cover the
    // affected derived records (spec §2.3.4, §5.1).
    if trigger.record.as_ref() == Some(&leaf_record) {
        return Err(ReceiptError::EmbeddedSubjectMismatch {
            what: "disposition leaf",
            got: leaf_record.1,
            want: "a derived record, not the trigger's own".to_owned(),
        });
    }

    check_inclusion(
        &jcs(leaf),
        number(material, "leaf_index")?,
        number(ctx.payload, "affected_count")?,
        &path_strings(material, "leaf_path")?,
        &parse_hash_hex(text(ctx.payload, "affected_root")?)?,
        "disposition leaf",
        budget,
    )
}

/// Authenticate the propagation's declared checkpoint D as a real, log-signed checkpoint.
///
/// D is carried as a full signed checkpoint object (format §3). Its signature is checked
/// against a log key that both appears in the receipt's `keys.log` block *and* is declared by
/// the manifest version active for **D's** own tree size — not A's. The two can differ: a
/// manifest anchored between D and A rotates the log key set, and a checkpoint issued under
/// the earlier state must be validated by the earlier key (format §2.2).
fn authenticate_declared_checkpoint(
    ctx: &ClaimCtx<'_>,
    declared: &Value,
    budget: &mut Budget,
) -> Result<()> {
    let key_id = text(declared, "key_id")?;
    let tree_size = number(declared, "tree_size")?;
    let (active_index, active_manifest) = ctx.governance.active_for(tree_size)?;

    // The log id must match the manifest version active for D, exactly as it must for A
    // (adaptor §5) — D gets no relaxed check just because it is the earlier checkpoint.
    if text(obj(active_manifest, "log")?, "id")? != text(declared, "log_id")? {
        return Err(ReceiptError::GovernanceChainInvalid(
            "checkpoint `log_id` is not the log the active manifest declares".to_owned(),
        ));
    }

    // D's log key resolves against the manifest active for D's *own* tree size, and its
    // `keys.log` entry binds to that same manifest version (format §2.2) — the normal
    // source/binding contract, not a byte-equality shortcut. `active_index` can differ from
    // A's: a manifest anchored between D and A rotates the log key set, and a checkpoint issued
    // under the earlier state must be validated by the earlier key.
    // The same `key_id` may appear more than once in `keys.log` — a receipt authenticating two
    // checkpoints (D here, A elsewhere) can legitimately carry the same physical log key bound
    // to each checkpoint's own active manifest. Take whichever entry actually binds at D's
    // `active_index`, not merely the first entry with a matching `key_id` (that could be the
    // one meant for A).
    let mut last_error = None;
    let mut pubkey = None;
    for entry in array(obj(ctx.receipt, "keys")?, "log")? {
        if text(entry, "key_id").ok() != Some(key_id) {
            continue;
        }
        check_key_id(entry)?;
        match bind_log_or_witness_key(ctx.governance, entry, "log", active_index) {
            Ok(bound) => {
                pubkey = Some(bound);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let pubkey = pubkey.ok_or_else(|| {
        last_error.unwrap_or(ReceiptError::KeyNotBound {
            key_id: key_id.to_owned(),
            entry_index: active_index,
        })
    })?;

    budget.spend(1)?;
    if verify_signature(
        &decode_pubkey(&pubkey)?,
        &checkpoint_signing_bytes(declared)?,
        text(declared, "signature")?,
    )? {
        Ok(())
    } else {
        Err(ReceiptError::CheckpointSignatureInvalid)
    }
}

/// `propagation-complete` (§3): the anchored affected set equals the recomputable closure.
// The completeness claim has the longest precondition list in the registry — checkpoint
// binding, prefix enumeration, tree material, trigger effectiveness, closure — and each step
// consumes the previous one's output; splitting it would only scatter that chain.
#[allow(clippy::too_many_lines)]
fn verify_propagation_complete(ctx: &ClaimCtx<'_>, budget: &mut Budget) -> Result<()> {
    ctx.require_subject_type("propagation")?;
    if ctx.assurance.governance != "enumerated" {
        return Err(ReceiptError::AssuranceMismatch { field: "governance" });
    }
    let material = ctx.material()?;
    let prefix_material = material
        .get("corpus_prefix")
        .filter(|v| v.is_object())
        .ok_or_else(|| ctx.missing("corpus_prefix"))?;

    // Completeness is defined at the propagation's own declared checkpoint D — never at the
    // later checkpoint A the propagation statement is anchored under (spec §2.3.4). The
    // carried `corpus_checkpoint` must therefore BE D, authenticated rather than self-supplied.
    let carried_d =
        material.get("corpus_checkpoint").ok_or_else(|| ctx.missing("corpus_checkpoint"))?;
    checkpoints_agree(
        carried_d,
        obj(ctx.payload, "corpus_checkpoint")?,
        "claim_material.corpus_checkpoint",
    )?;
    let declared_size = number(carried_d, "tree_size")?;
    let anchor_size = number(ctx.anchoring_checkpoint, "tree_size")?;
    if declared_size > anchor_size {
        // D must be committed by A; otherwise the prefix cannot be authenticated under A.
        return Err(ReceiptError::CheckpointNotBound {
            field: "claim_material.corpus_checkpoint",
            member: "tree_size".to_owned(),
        });
    }
    authenticate_declared_checkpoint(ctx, carried_d, budget)?;

    // The prefix is `[0, tree_size(D))`, and its range proof is checked against **A's** root:
    // A is the checkpoint this verifier signature-checked and saw witness-cosigned. Verifying
    // the prefix under A and then recomputing D's root from it is a consistency proof D→A in
    // the range-proof's clothing — it establishes that D is exactly the size-`tree_size(D)`
    // prefix of A, which is what makes D usable without a second proof mechanism.
    let root = parse_hash_hex(text(ctx.anchoring_checkpoint, "root_hash")?)?;
    let tree_size = declared_size;
    let prefix = verify_enumeration(prefix_material, &root, anchor_size, "corpus prefix", budget)?;
    if prefix.from_index != 0 || prefix.to_index != tree_size {
        return Err(ReceiptError::RangeProofInvalid {
            what: "corpus prefix",
            detail: format!(
                "must be the complete prefix [0, {tree_size}) of the declared checkpoint D, \
                 got [{}, {})",
                prefix.from_index, prefix.to_index
            ),
        });
    }
    let recomputed_d = hash_hex(&tree_root(&prefix.entries.iter().map(jcs).collect::<Vec<_>>()));
    if recomputed_d != text(carried_d, "root_hash")? {
        return Err(ReceiptError::CheckpointNotBound {
            field: "claim_material.corpus_checkpoint",
            member: "root_hash".to_owned(),
        });
    }

    // Committed tree material for every root the prefix references, validated against its
    // commitment before a single edge is read from it (spec §2.5, §3.5).
    let trees_block = obj(material, "trees")?;
    let mut trees = TreeMaterial::new();
    for (root_hex, entry) in trees_block.as_object().into_iter().flatten() {
        trees.insert(root_hex.clone(), array(entry, "leaves")?.clone());
    }

    // The disposition tree is validated here so a wrong-root or short leaf set is a typed
    // rejection rather than a closure disagreement.
    let affected_root = text(ctx.payload, "affected_root")?;
    let affected_count = number(ctx.payload, "affected_count")?;
    let dispositions = ValidatedLeafSet::open(
        affected_root,
        affected_count,
        trees.get(affected_root).cloned().ok_or_else(|| ReceiptError::TreeMaterialInvalid {
            root: affected_root.to_owned(),
            detail: "no leaf material carried".to_owned(),
        })?,
    )
    .map_err(|source| ReceiptError::TreeMaterialInvalid {
        root: affected_root.to_owned(),
        detail: source.to_string(),
    })?;

    // §3: an embedded `trigger-effective` receipt is REQUIRED — challenges are never traversed.
    // Locating "some statement with that id" is not enough: a trigger signed by a key that is
    // not the record's authority anchors as a challenge (spec §2.3.3), and a closure seeded
    // from one would be meaningless. Only a receipt that survived the authority and
    // competing-trigger checks establishes that this trigger governs.
    let trigger_statement = text(ctx.payload, "trigger")?.to_owned();
    let trigger =
        verify_embedded(ctx, "trigger", "trigger-effective", &["trigger-effective"], budget)?;
    if trigger.verdict.subject_statement_id != trigger_statement {
        return Err(ReceiptError::EmbeddedSubjectMismatch {
            what: "trigger",
            got: trigger.verdict.subject_statement_id,
            want: trigger_statement,
        });
    }
    // §2.3: trigger index ≤ propagation index.
    if trigger.entry_index > ctx.subject_index {
        return Err(ReceiptError::EmbeddedOrderingViolation {
            what: "trigger",
            inner: trigger.entry_index,
            outer: ctx.subject_index,
        });
    }
    // D must commit the trigger's entry (spec §2.3.4).
    if declared_size <= trigger.entry_index {
        return Err(ReceiptError::CheckpointNotBound {
            field: "envelope.payload.corpus_checkpoint",
            member: "tree_size".to_owned(),
        });
    }

    let trigger_index = usize::try_from(trigger.entry_index)
        .map_err(|_| ReceiptError::Malformed("trigger entry index".to_owned()))?;
    if prefix.entries.get(trigger_index).and_then(|e| statement_id(e).ok()).as_deref()
        != Some(trigger_statement.as_str())
    {
        return Err(ReceiptError::ClosureMismatch(
            "the corpus prefix does not carry the proven trigger at its own entry index".to_owned(),
        ));
    }

    budget.spend(u64::try_from(prefix.entries.len()).unwrap_or(u64::MAX))?;
    let closure = affected_set(&prefix.entries, &trees, trigger_index, prefix.entries.len())
        .map_err(|source| match source {
            AhlError::MissingTreeMaterial(root) => ReceiptError::TreeMaterialInvalid {
                root,
                detail: "no leaf material carried".to_owned(),
            },
            AhlError::TreeRootMismatch { root, recomputed } => ReceiptError::TreeMaterialInvalid {
                root,
                detail: format!("recomputes to {recomputed}"),
            },
            AhlError::TreeCountMismatch { root, declared, got } => {
                ReceiptError::TreeMaterialInvalid {
                    root,
                    detail: format!("commits {declared} leaves, {got} carried"),
                }
            }
            other => ReceiptError::Ahl(other),
        })?;

    let anchored: BTreeSet<(String, String)> = dispositions
        .leaves()
        .iter()
        .map(|leaf| Ok((text(leaf, "dataset")?.to_owned(), text(leaf, "record")?.to_owned())))
        .collect::<Result<_>>()?;
    // Completeness is relative to the declared corpus; nothing here proves the declared corpus
    // is the real corpus (spec §5.3). The rendered boundary says so.
    if anchored == closure.affected {
        Ok(())
    } else {
        Err(ReceiptError::ClosureMismatch(format!(
            "recomputed {} affected records, the disposition tree anchors {}",
            closure.affected.len(),
            anchored.len()
        )))
    }
}

/// `governance-state` (§3): the manifest/key state at a target index is exactly the chain.
///
/// The subject is a **manifest** statement; key state is composed from that manifest plus
/// later `key` statements, so a `key` statement is never a `governance-state` subject.
///
/// Range composition. This claim type carries no schema-local range: its `claim_material` is
/// only `{target_index}`, so the top-level §4 material *is* the absence proof. §4 fixes that
/// material at exactly `[0, tree_size(C))` for the receipt's verified checkpoint C, which is
/// checked once for every enumerated receipt in [`verify_governance_enumeration`]. What
/// remains type-specific is that the range must actually *reach* the target: `target_index`
/// must be committed by C, i.e. `target_index < tree_size(C)`. Otherwise a receipt could
/// enumerate a short prefix and assert a governance state at an index that prefix never
/// covered.
fn verify_governance_state(ctx: &ClaimCtx<'_>) -> Result<()> {
    let subject_type = statement_type(ctx.payload)?;
    if subject_type != "manifest" {
        return Err(ReceiptError::GovernanceSubjectNotManifest {
            statement_type: subject_type.to_owned(),
        });
    }
    if ctx.assurance.governance != "enumerated" {
        return Err(ReceiptError::AssuranceMismatch { field: "governance" });
    }
    let target_index = number(ctx.material()?, "target_index")?;
    if ctx.subject_index > target_index {
        return Err(ReceiptError::EmbeddedOrderingViolation {
            what: "governance subject",
            inner: ctx.subject_index,
            outer: target_index,
        });
    }
    let enumeration = ctx.enumeration.ok_or_else(|| ctx.missing("governance.currency.material"))?;

    // The enumeration is already pinned to `[0, tree_size(C))`; it must cover the target.
    if target_index >= enumeration.to_index {
        return Err(ReceiptError::GovernanceRangeNotComplete {
            got_from: enumeration.from_index,
            got_to: enumeration.to_index,
            tree_size: target_index + 1,
        });
    }
    // Absence of any governance statement in `(subject.entry_index, target_index]`.
    for index in (ctx.subject_index + 1)..=target_index {
        let Some(envelope) = enumeration.at(index) else { continue };
        let kind = statement_type(payload_of(envelope)?)?;
        if matches!(kind, "manifest" | "key") {
            return Err(ReceiptError::GovernanceStateNotCurrent {
                target_index,
                entry_index: index,
                statement_type: kind.to_owned(),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verdict rendering (format §5 step 6)
// ---------------------------------------------------------------------------

/// Render the claim boundary from `claim.type` and `assurance` alone.
///
/// The `-declared` types never use the words "effective", "governs" or "complete"; the
/// `-effective`/`-complete` types do, and only ever reach this function with enumerated
/// governance because verification rejects them otherwise (§3 naming rule).
fn render(claim_type: &str, assurance: &Assurance) -> String {
    let base = match claim_type {
        "statement-anchored" => {
            "the subject envelope is anchored at the stated entry index and signed under the \
             producer-declared manifest chain"
        }
        "record-ingested" => "the subject ingestion introduced the named record into the corpus",
        "record-derived" => "the subject derivation committed the named output record",
        "trigger-declared" => {
            "a trigger naming the record is anchored and signed under the declared chain by the \
             declared issuer"
        }
        "trigger-effective" => {
            "the trigger governs the record at the stated checkpoint, its issuer's authority \
             held under enumerated governance"
        }
        "disposition-declared" => "the subject propagation statement dispositions the named record",
        "disposition-effective" => {
            "the subject propagation statement dispositions the named record under a trigger \
             proven effective at the stated checkpoint"
        }
        "propagation-complete" => {
            "the propagation statement's affected set equals the closure recomputable from the \
             enumerated corpus prefix — complete relative to the declared corpus only"
        }
        "governance-state" => {
            "the manifest and key state active at the target index is exactly the presented chain"
        }
        other => return format!("unknown claim type `{other}`"),
    };
    let mut boundary = base.to_owned();
    boundary.push_str(if assurance.witnessed {
        "; anchored under a witness-cosigned checkpoint"
    } else {
        "; the anchoring checkpoint carries no verified witness cosignature"
    });
    if !assurance.continued_history {
        boundary.push_str("; no claim of continued append-only history beyond that checkpoint");
    }
    boundary.push_str(match assurance.content_binding.as_str() {
        "plain-verified" => "; record content verified against the commitment",
        "keyed-authorized" => {
            "; record content verified against the commitment by an authorized key holder"
        }
        _ => "; record content not verified",
    });
    boundary
}
