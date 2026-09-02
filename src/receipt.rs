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
use crate::descriptor::CanonicalizationDescriptor;
use crate::range_proof;
use crate::tree::ValidatedLeafSet;
use crate::{
    checkpoint_signing_bytes, commit_keyed, commit_plain, cosignature_bytes, decode_pubkey,
    descriptor, entry_id, hash_hex, jcs, parse_hash_hex, proof_from_hex, sha256_hex, statement_id,
    tree_root, verify_signature, AhlError, B64,
};

/// Receipt container version this verifier implements (I-D §7.1: `ahl_receipt_version`).
pub const RECEIPT_VERSION: &str = "2";

/// Core specification version this verifier implements (I-D §7.1: `spec_version`).
pub const SPEC_VERSION: &str = "0.4.0";

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

    /// `ahl_receipt_version`, `spec_version` or a carried statement's `ahl_version` is not one
    /// this verifier implements (I-D §7.1, §7.5 step 1, §2.2).
    ///
    /// This is the I-D's `unverifiable` outcome, not `invalid`: an artifact issued under
    /// earlier rules is not a defective artifact, and this document establishes nothing about
    /// whether it verifies under the rules that produced it (I-D §7.1 "Revision and rule
    /// selection"). `ahl_receipt_version` is read and acted on before any other check,
    /// including schema validation (I-D §7.5 step 1, "Version first, then parse").
    #[error("unsupported {field}: expected `{expected}`, got `{got}` (unverifiable, not invalid)")]
    UnsupportedVersion {
        /// The version field: `ahl_receipt_version`, `spec_version`, or `ahl_version`.
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

    /// A manifest object does not satisfy the schema the specification fixes for it.
    ///
    /// Spec §7.3 states value grammars for the `log` object and requires a malformed value to
    /// be "rejected rather than approximated". The duty is on the value, so a signed manifest
    /// that breaks the schema does not verify here even where this verifier never reads the
    /// offending member — admitting it would leave the corpus verifiable only by
    /// implementations that share this one's tolerances.
    #[error("manifest `{object}` is invalid: {detail}")]
    ManifestSchemaInvalid {
        /// The offending member, as a dotted path from the manifest payload.
        object: String,
        /// Which rule it breaks.
        detail: String,
    },

    /// A carried governance chain rotates a log or witness key set (I-D §7.1 "governance-key
    /// rotation": a manifest whose log checkpoint-signing key objects or whose witness key
    /// objects, compared as SETS, differ from its predecessor's), and either
    /// `governance.rotation_proofs[]` carries no element for it, or the element fails a
    /// requirement I-D §7.1 / §7.5.1 4b(M) states for it.
    ///
    /// I-D §7.1: "A receipt that omits `governance.rotation_proofs[]` where the carried chain
    /// rotates either governance key set, or that carries an element failing any requirement
    /// above, is `invalid`". This is that rule.
    #[error("rotation proof for manifest entry index {manifest_entry_index} is invalid: {detail}")]
    RotationProofInvalid {
        /// Entry index of the rotating manifest.
        manifest_entry_index: u64,
        /// Which requirement failed.
        detail: String,
    },

    /// This build does not implement the canonicalization procedure a dataset's descriptor
    /// names (I-D §2.6): only `jcs` and `exact-bytes` are implemented.
    ///
    /// Per I-D §6.3's conformance table, an identifier this verifier does not implement makes
    /// only THAT dataset's content-binding finding `unverifiable` — never `invalid`, and never
    /// rehabilitated to `content_binding: "none"`.
    #[error(
        "canonicalization identifier `{identifier}` names a procedure this build does not \
         implement; dataset `{dataset}`'s content-binding finding is unverifiable, not invalid \
         (I-D §6.3)"
    )]
    CanonicalizationUnsupported {
        /// The dataset whose content-binding finding is affected.
        dataset: String,
        /// The unimplemented `canonicalization` identifier.
        identifier: String,
    },

    /// Carried record/output bytes did not canonicalize under the dataset's declared procedure
    /// (I-D §2.6, §7.2: the verifier canonicalizes the record AS RECEIVED before recomputing
    /// the commitment).
    ///
    /// Unlike [`Self::CanonicalizationUnsupported`], this is `invalid`: the procedure IS
    /// implemented, and the carried bytes simply fail it (for `jcs`, do not parse as JSON).
    #[error(
        "dataset `{dataset}`: carried bytes do not canonicalize under `{identifier}`: {detail}"
    )]
    CanonicalizationFailed {
        /// The dataset whose content binding failed.
        dataset: String,
        /// The `canonicalization` identifier the bytes failed to satisfy.
        identifier: String,
        /// Why.
        detail: String,
    },

    /// A dataset's declared `media_type` PRESENCE violates the identifier's own rule (I-D
    /// §2.6): `jcs` MUST NOT carry `media_type` (it never reads the media type), `exact-bytes`
    /// MUST carry it (the canonical input is qualified by it).
    ///
    /// Presence is "a producer duty and is never a syntactic matter" (I-D §2.6), so wrong
    /// presence never rejects the manifest — only this dataset's content-binding finding is
    /// `invalid`, and only where this verifier implements the procedure well enough to know the
    /// rule; for an identifier it does not implement at all, that dataset's finding is
    /// [`Self::CanonicalizationUnsupported`], not this variant.
    #[error(
        "dataset `{dataset}` (canonicalization `{identifier}`) has an invalid `media_type` \
         presence: {detail}"
    )]
    MediaTypePresenceInvalid {
        /// The dataset whose content-binding finding is affected.
        dataset: String,
        /// The dataset's `canonicalization` identifier.
        identifier: String,
        /// Which rule it breaks.
        detail: &'static str,
    },

    /// `claim_material`'s descriptor for a dataset does not equal (I-D §2.6 descriptor
    /// equality: identical NORMALIZED forms) the descriptor declared by the manifest version
    /// NAMED BY THE SUBJECT STATEMENT'S `manifest` binding (I-D §2.2, §6.3) — the manifest
    /// statement whose STATEMENT id (I-D §2.4.5) that binding carries, not merely the manifest
    /// active at the subject's entry index.
    #[error(
        "claim material's descriptor for dataset `{dataset}` (`{claimed}`) does not equal the \
         manifest's declared descriptor (`{declared}`) at manifest version \
         `{manifest_version_id}` (I-D §2.6, §6.3)"
    )]
    ClaimDescriptorMismatch {
        /// The dataset the mismatch concerns.
        dataset: String,
        /// The descriptor's normalized form as carried in `claim_material`.
        claimed: String,
        /// The descriptor's normalized form as declared in the governing manifest.
        declared: String,
        /// The governing manifest's version id (I-D §2.4.5: the manifest statement's own
        /// statement id).
        manifest_version_id: String,
    },

    /// The receipt asks for a combination the frozen container format cannot evidence.
    ///
    /// Not a failed rule: a rule that cannot be satisfied at all. Rejecting is the only honest
    /// outcome, because the alternative is to report as verified a coverage requirement no
    /// material in the format can meet.
    #[error("{combination} cannot be evidenced under this format revision: {conflict}")]
    FormatConflict {
        /// The combination of receipt features that cannot be evidenced.
        combination: &'static str,
        /// The conflicting requirements, each named by section.
        conflict: &'static str,
    },

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

    /// `subject.manifest` fails the I-D §7.6 binding rule: it does not equal the subject
    /// envelope's OWN `payload.manifest` (the only thing that authenticates the receipt's
    /// copy, since the copy itself is outside the subject's signature), or the manifest version
    /// it names is absent from `governance.chain`, or that version's `entry_index` is not
    /// STRICTLY SMALLER than `subject.entry_index`.
    #[error("`subject.manifest` binding is invalid: {0}")]
    SubjectManifestBindingInvalid(String),

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

/// Check a carried statement's `ahl_version` before validating anything else about it
/// (I-D §2.2, §7.1, §7.5 step 1).
///
/// An absent `ahl_version` is a schema failure, decidable from the bytes alone, and is
/// `invalid` (`ReceiptError::Malformed`). A present value other than [`crate::AHL_VERSION`] is
/// `unverifiable` — not `invalid` — because this document establishes nothing about whether an
/// earlier-revision artifact verifies under rules it was never issued under.
fn check_ahl_version(payload: &Value) -> Result<()> {
    match payload.get("ahl_version").and_then(Value::as_str) {
        None => Err(ReceiptError::Malformed("statement payload missing `ahl_version`".to_owned())),
        Some(got) if got == crate::AHL_VERSION => Ok(()),
        Some(got) => Err(ReceiptError::UnsupportedVersion {
            field: "ahl_version",
            expected: crate::AHL_VERSION,
            got: got.to_owned(),
        }),
    }
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
    /// Manifest payloads keyed by their MANIFEST VERSION ID — the manifest statement's own
    /// `statement_id` (I-D §2.4.5), which is what a subject statement's `manifest` field
    /// references (I-D §2.2). Distinct from `entry_id`, which `predecessor` references.
    manifest_by_version_id: BTreeMap<String, (u64, &'a Value)>,
}

/// The MANIFEST VERSION ID (I-D §2.4.5: a manifest statement's own `statement_id`) of the
/// manifest ACTIVE at `index` — I-D §2.2: "the manifest version active at the statement's
/// entry index... the manifest statement with the greatest entry index smaller than the
/// statement's own." Free function so `read_chain` can call it mid-induction, with only the
/// manifests known so far, exactly like [`snapshot_manifest_in`].
fn active_manifest_version_id(
    manifests: &[(u64, &Value)],
    manifest_by_version_id: &BTreeMap<String, (u64, &Value)>,
    index: u64,
) -> Option<String> {
    let (active_index, _) = snapshot_manifest_in(manifests, index)?;
    manifest_by_version_id
        .iter()
        .find(|(_, (mi, _))| *mi == active_index)
        .map(|(version_id, _)| version_id.clone())
}

impl<'a> Governance<'a> {
    /// The `(entry_index, payload)` of the manifest named by a statement's `manifest` field
    /// (I-D §2.2, §2.4.5).
    fn manifest_by_version_id(&self, version_id: &str) -> Option<(u64, &'a Value)> {
        self.manifest_by_version_id.get(version_id).copied()
    }

    /// The manifest version id ACTIVE at `index` (I-D §2.2). See [`active_manifest_version_id`].
    fn active_manifest_version_id_at(&self, index: u64) -> Option<String> {
        active_manifest_version_id(&self.manifests, &self.manifest_by_version_id, index)
    }
}

/// One producer key in force at some entry index, with the governance statement that put it
/// there — the index a receipt's `keys.producer[].binding` must name (format §2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundKey {
    pubkey: String,
    bound_at: u64,
}

/// The governance statement whose producer-key snapshot is in force *at* `index`, given the
/// manifests known SO FAR (I-D §7.5.1 4b: "K as established so far" needs only the manifests
/// and events strictly before `index`, so this is safe to call mid-induction, before the hop
/// AT `index` has itself been validated).
///
/// Spec §2.2 resolves "the manifest version active at entry index i" as the manifest with the
/// greatest entry index **smaller** than i — which is also what §2.3.5 needs, since a manifest
/// statement is signed under its *predecessor*'s state. The genesis manifest is the one
/// statement validated by its own snapshot, so index 0 falls back to it.
fn snapshot_manifest_in<'a>(
    manifests: &[(u64, &'a Value)],
    index: u64,
) -> Option<(u64, &'a Value)> {
    manifests.iter().rfind(|(mi, _)| *mi < index).or_else(|| manifests.first()).copied()
}

/// The producer key set in force at `index`, with each key's binding index, given the
/// manifests and events known SO FAR. See [`snapshot_manifest_in`].
///
/// Spec §7.2: "A manifest's producer `keys` array is the complete producer-key snapshot
/// effective from that manifest's entry index: it discards the prior snapshot; later `key`
/// statements then modify it in entry order until the next manifest version." So this is *not*
/// a union across manifest versions — a key a later manifest omits is gone, and a signature by
/// it no longer validates.
fn producer_keys_at_in(
    manifests: &[(u64, &Value)],
    events: &[KeyEvent],
    index: u64,
) -> BTreeMap<String, BoundKey> {
    let mut keys = BTreeMap::new();
    let Some((snapshot_index, manifest)) = snapshot_manifest_in(manifests, index) else {
        return keys;
    };
    for (key_id, pubkey) in key_objects(manifest).unwrap_or_default() {
        keys.insert(key_id, BoundKey { pubkey, bound_at: snapshot_index });
    }
    // Only transitions anchored after that snapshot and at or before `index` apply; an
    // earlier `key` statement was already folded into (or discarded by) the snapshot.
    for event in events.iter().filter(|e| e.entry_index > snapshot_index && e.entry_index <= index)
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

impl<'a> Governance<'a> {
    /// The governance statement whose producer-key snapshot is in force *at* `index`.
    fn snapshot_manifest(&self, index: u64) -> Option<(u64, &'a Value)> {
        snapshot_manifest_in(&self.manifests, index)
    }

    /// The producer key set in force at `index`, with each key's binding index.
    fn producer_keys_at(&self, index: u64) -> BTreeMap<String, BoundKey> {
        producer_keys_at_in(&self.manifests, &self.events, index)
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

// ---------------------------------------------------------------------------
// The manifest `log` object schema (spec §7.3)
// ---------------------------------------------------------------------------

/// A `sha256:` family string: the prefix plus exactly 64 lowercase hex digits.
///
/// Lowercase is not cosmetic. Spec §2.3.6 derives a producer `key_id` as `sha256:` plus
/// *lowercase* hex, and §2.5 says family strings are lowercase hex; two spellings of one digest
/// would compare unequal as strings while naming the same value, and every key lookup and
/// checkpoint binding in this verifier is a string comparison.
fn is_family_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The receipt-borne checkpoint shape (I-D §7.1): `{log_id, tree_size, root_hash,
/// checkpoint_time, key_id, signature}` — every member REQUIRED — plus an optional `raw`.
/// Shared by `anchoring.checkpoint`, `anchoring.later_checkpoint`, and every
/// `governance.rotation_proofs[].checkpoint` (I-D §7.1: rotation-proof checkpoints are "in the
/// receipt-borne form defined above"), so a strict shape check written once cannot drift
/// between the three call sites.
fn checkpoint_object(value: &Value) -> Result<&Value> {
    let invalid = |member: &str, detail: &str| {
        ReceiptError::Malformed(format!("checkpoint {member}: {detail}"))
    };
    if !value.get("log_id").and_then(Value::as_str).is_some_and(is_family_hash) {
        return Err(invalid("log_id", "REQUIRED, a `sha256:` family string in lowercase hex"));
    }
    if value.get("tree_size").and_then(Value::as_u64).is_none() {
        return Err(invalid("tree_size", "REQUIRED, an entry count"));
    }
    if !value.get("root_hash").and_then(Value::as_str).is_some_and(is_family_hash) {
        return Err(invalid("root_hash", "REQUIRED, a `sha256:` family string in lowercase hex"));
    }
    let checkpoint_time = value
        .get("checkpoint_time")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("checkpoint_time", "REQUIRED"))?;
    crate::bitemporal::parse_rfc3339("checkpoint_time", checkpoint_time)
        .map_err(|source| invalid("checkpoint_time", &source.to_string()))?;
    if !value.get("key_id").and_then(Value::as_str).is_some_and(is_family_hash) {
        return Err(invalid("key_id", "REQUIRED, a `sha256:` family string in lowercase hex"));
    }
    if value.get("signature").and_then(Value::as_str).is_none() {
        return Err(invalid("signature", "REQUIRED"));
    }
    Ok(value)
}

/// One witness-cosignature object in the shape of `anchoring.witnesses[]` (I-D §7.1):
/// `{witness_id, key_id, cosignature, cosigned_at}` — every member REQUIRED. Shared by
/// `anchoring.witnesses[]` and every `governance.rotation_proofs[].witnesses[]` element (I-D
/// §7.1: "an array in the shape of `anchoring.witnesses[]`"), so EVERY element of such an array
/// is checked against this shape, not merely the ones whose cosignature happens to verify.
fn witness_cosignature_object(value: &Value) -> Result<&Value> {
    let invalid = |member: &str, detail: &str| {
        ReceiptError::Malformed(format!("witness cosignature {member}: {detail}"))
    };
    if value.get("witness_id").and_then(Value::as_str).is_none() {
        return Err(invalid("witness_id", "REQUIRED"));
    }
    if !value.get("key_id").and_then(Value::as_str).is_some_and(is_family_hash) {
        return Err(invalid("key_id", "REQUIRED, a `sha256:` family string in lowercase hex"));
    }
    if value.get("cosignature").and_then(Value::as_str).is_none() {
        return Err(invalid("cosignature", "REQUIRED"));
    }
    let cosigned_at = value
        .get("cosigned_at")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("cosigned_at", "REQUIRED"))?;
    crate::bitemporal::parse_rfc3339("cosigned_at", cosigned_at)
        .map_err(|source| invalid("cosigned_at", &source.to_string()))?;
    Ok(value)
}

/// Parse the restricted duration grammar of spec §7.3, returning the value in nanoseconds.
///
/// §7.3 admits `P[n]DT[n]H[n]M[n]S` and nothing else: days, hours, minutes and seconds. Years
/// and calendar months are PROHIBITED because their length is context-dependent, and a value
/// carrying `Y`, or `M` in the date part, "is malformed and MUST be rejected rather than
/// approximated". Fractional seconds are capped at nine digits, again with rejection rather than
/// truncation — truncating would make the value implementation-dependent in exactly the way the
/// component restriction exists to prevent.
///
/// The duty is on the *value*, not on the reader's use of it. This verifier computes no cadence
/// or freshness verdict, but a manifest carrying `P1Y` would make those verdicts
/// implementation-dependent for whoever does compute them, and a signed manifest that violates
/// the frozen schema must not verify here merely because this code has no use for the field.
///
/// Returns the offending rule as a message on rejection.
fn duration_nanos(value: &str) -> core::result::Result<u128, &'static str> {
    /// Seconds per unit, in the order the grammar fixes.
    const UNITS: [(char, u128); 3] = [('H', 3_600), ('M', 60), ('S', 1)];

    fn digits(text: &str) -> core::result::Result<u64, &'static str> {
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err("every component is one or more ASCII digits followed by its designator");
        }
        text.parse().map_err(|_| "the component value is too large to represent")
    }

    let rest = value.strip_prefix('P').ok_or("a duration must begin with `P`")?;
    let (date, time) = rest.split_once('T').map_or((rest, None), |(d, t)| (d, Some(t)));

    let mut nanos: u128 = 0;
    let mut components = 0usize;

    if !date.is_empty() {
        // Days are the only date component §7.3 admits: `Y`, and `M` in the date part, are
        // prohibited outright, and no other designator (`W` among them) is in the grammar.
        let day_digits = date.strip_suffix('D').ok_or(
            "the date part admits days only — `Y` and a date-part `M` are prohibited (§7.3)",
        )?;
        nanos = u128::from(digits(day_digits)?) * 86_400 * 1_000_000_000;
        components += 1;
    }

    if let Some(time) = time {
        // A dangling `T` designates a time part that is not there. Admitting it would mean two
        // spellings of one value, which is the class of latitude §7.3 exists to close.
        if time.is_empty() {
            return Err("`T` must be followed by at least one time component");
        }
        let mut cursor = time;
        let mut next_unit = 0usize;
        while !cursor.is_empty() {
            let at = cursor
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .ok_or("a time component must carry a `H`, `M` or `S` designator")?;
            let (number, tail) = cursor.split_at(at);
            let designator = tail.chars().next().ok_or("a truncated time component")?;
            let unit = UNITS
                .iter()
                .position(|(c, _)| *c == designator)
                .ok_or("the time part admits `H`, `M` and `S` only (§7.3)")?;
            if unit < next_unit {
                return Err("time components appear in the order H, M, S, each at most once");
            }
            next_unit = unit + 1;

            let value_nanos = match number.split_once('.') {
                Some((whole, fraction)) => {
                    if designator != 'S' {
                        return Err("only the seconds component may carry a fraction (§7.3)");
                    }
                    if fraction.len() > 9 {
                        return Err(
                            "at most nine fractional digits; a longer value is malformed and is \
                             rejected rather than truncated or rounded (§7.3)",
                        );
                    }
                    let scale = 10u128.pow(9 - u32::try_from(fraction.len()).unwrap_or(9));
                    u128::from(digits(whole)?) * 1_000_000_000
                        + u128::from(digits(fraction)?) * scale
                }
                None => u128::from(digits(number)?) * UNITS[unit].1 * 1_000_000_000,
            };
            nanos =
                nanos.checked_add(value_nanos).ok_or("the duration is too large to represent")?;
            components += 1;
            cursor = &tail[designator.len_utf8()..];
        }
    }

    if components == 0 {
        return Err("a duration carries at least one component");
    }
    Ok(nanos)
}

/// The manifest `log` object, checked against the §7.3 schema before anything reads it.
///
/// Spec §7.3 fixes both the membership and the value grammars, and makes rejection a duty on
/// the value rather than a consequence of computing with it:
///
/// * every member is REQUIRED — `log_id`, `operator`, `adaptor: {id, hash}`,
///   `checkpoint_cadence`, `cadence_epoch`, `witness_grace_period`, `keys`;
/// * `log_id` and each `keys[].key_id` are family strings, as is `adaptor.hash`;
/// * `checkpoint_cadence` and `witness_grace_period` follow the restricted duration grammar of
///   [`duration_nanos`], and `checkpoint_cadence` MUST be greater than zero;
/// * `cadence_epoch` is RFC 3339;
/// * each key object is `{key_id, pubkey, valid_from_index}`, the last an entry index.
///
/// The id member is `log_id`, and there is deliberately no alias for `id`: reading the id under
/// another spelling — or tolerating a manifest that omits `cadence_epoch` — is how two
/// incompatible dialects of one manifest come to coexist, each verifiable only by the
/// implementation that wrote it.
///
/// What this does *not* fix is the encoding of `keys[].pubkey`, which core spec §2.3.6 leaves
/// adaptor-defined; it is decoded where it is used, under the rule of the pinned profile.
fn log_object(manifest: &Value) -> Result<&Value> {
    let invalid = |member: &str, detail: &str| ReceiptError::ManifestSchemaInvalid {
        object: format!("log.{member}"),
        detail: detail.to_owned(),
    };
    let missing = |member: &str| invalid(member, "the member is REQUIRED (spec §7.3)");

    let log = manifest.get("log").filter(|value| value.is_object()).ok_or_else(|| {
        ReceiptError::ManifestSchemaInvalid {
            object: "log".to_owned(),
            detail: "the object is REQUIRED (spec §7.3)".to_owned(),
        }
    })?;

    for member in
        ["log_id", "operator", "checkpoint_cadence", "cadence_epoch", "witness_grace_period"]
    {
        if !log.get(member).is_some_and(Value::is_string) {
            return Err(missing(member));
        }
    }
    if !is_family_hash(text(log, "log_id")?) {
        return Err(invalid("log_id", "not a `sha256:` family string in lowercase hex (§7.3)"));
    }

    // Both durations are restricted to time components. `checkpoint_cadence` additionally MUST
    // be greater than zero: a zero maximum gap could never be met by any published series, so a
    // corpus declaring it would be unjudgeable rather than merely strict.
    let cadence = duration_nanos(text(log, "checkpoint_cadence")?)
        .map_err(|detail| invalid("checkpoint_cadence", detail))?;
    if cadence == 0 {
        return Err(invalid("checkpoint_cadence", "MUST be greater than zero (§7.3)"));
    }
    duration_nanos(text(log, "witness_grace_period")?)
        .map_err(|detail| invalid("witness_grace_period", detail))?;

    crate::bitemporal::parse_rfc3339("log.cadence_epoch", text(log, "cadence_epoch")?)
        .map_err(|source| invalid("cadence_epoch", &source.to_string()))?;

    let adaptor =
        log.get("adaptor").filter(|value| value.is_object()).ok_or_else(|| missing("adaptor"))?;
    for member in ["id", "hash"] {
        if !adaptor.get(member).is_some_and(Value::is_string) {
            return Err(missing(&format!("adaptor.{member}")));
        }
    }
    if !is_family_hash(text(adaptor, "hash")?) {
        return Err(invalid("adaptor.hash", "not a `sha256:` family string in lowercase hex"));
    }

    if !log.get("keys").is_some_and(Value::is_array) {
        return Err(missing("keys"));
    }
    key_objects(log)?;
    Ok(log)
}

/// Read the manifest key objects of `group` (`keys`, `log.keys`, `witnesses[].keys`), checking
/// each against the §7.2 shape every manifest key object shares.
///
/// Spec §7.2 gives producer, log and witness key objects one form —
/// `{key_id, pubkey, valid_from_index}` — so they are validated in one place. `key_id` is a
/// family string (§7.3) and `valid_from_index` is an entry index, which is an unsigned integer:
/// a negative or fractional value is not an index into an append-only log.
fn key_objects(container: &Value) -> Result<Vec<(String, String)>> {
    array(container, "keys")?
        .iter()
        .enumerate()
        .map(|(index, object)| {
            let invalid = |member: &str, detail: &str| ReceiptError::ManifestSchemaInvalid {
                object: format!("keys[{index}].{member}"),
                detail: detail.to_owned(),
            };
            let key_id = object
                .get("key_id")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("key_id", "the member is REQUIRED (spec §7.2)"))?;
            if !is_family_hash(key_id) {
                return Err(invalid("key_id", "not a `sha256:` family string in lowercase hex"));
            }
            let pubkey = object
                .get("pubkey")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("pubkey", "the member is REQUIRED (spec §7.2)"))?;
            if object.get("valid_from_index").and_then(Value::as_u64).is_none() {
                return Err(invalid("valid_from_index", "not an entry index (spec §7.2, §7.3)"));
            }
            Ok((key_id.to_owned(), pubkey.to_owned()))
        })
        .collect()
}

/// Validate the manifest `datasets` object: its own required presence (I-D §6.2), every
/// declared dataset id's syntax, and every declared descriptor's syntax (I-D §2.6, §6.3).
///
/// §6.2 lists `datasets` among what the manifest payload "contains at minimum", so its absence
/// — or a non-object value — is a schema failure exactly like a missing `log` object.
///
/// §6.3's conformance table makes a SYNTACTICALLY INVALID dataset declaration — a dataset id
/// violating the dataset id syntax or containing a control octet; a `canonicalization`
/// identifier that is missing, not a string, or violating the identifier syntax; a `media_type`
/// that is present but not a string or that does not match the descriptor media-type production
/// (duplicate lowercased parameter names and quoted-string parameter values included) — reject
/// the WHOLE manifest, not merely the affected dataset's claims: "A dataset's canonicalization
/// descriptor is a required manifest member (§6.2), and statements derive their governance from
/// that manifest (§2.2)". This checks every declared dataset, key by key, regardless of whether
/// any claim in the receipt ever binds content against it — the same way [`log_object`] and
/// [`key_objects`] check the members they are responsible for, once per manifest, not lazily
/// where a claim happens to need them.
///
/// [`verify_content_binding`] independently reconstructs the descriptor it actually uses, via
/// [`CanonicalizationDescriptor::new`], the moment a claim needs it to recompute a commitment;
/// that is a defensive re-check, not this rule's only enforcement point.
fn datasets_object(manifest: &Value) -> Result<()> {
    let datasets = manifest.get("datasets").and_then(Value::as_object).ok_or_else(|| {
        ReceiptError::ManifestSchemaInvalid {
            object: "datasets".to_owned(),
            detail: "the member is REQUIRED and MUST be an object (I-D §6.2)".to_owned(),
        }
    })?;
    for (dataset_id, declared) in datasets {
        let invalid = |detail: String| ReceiptError::ManifestSchemaInvalid {
            object: format!("datasets.{dataset_id}"),
            detail,
        };
        descriptor::validate_dataset_id(dataset_id)
            .map_err(|source| invalid(source.to_string()))?;

        let declared = declared
            .as_object()
            .ok_or_else(|| invalid("the dataset's declaration MUST be an object".to_owned()))?;
        let canonicalization =
            declared.get("canonicalization").and_then(Value::as_str).ok_or_else(|| {
                invalid("`canonicalization` is REQUIRED and MUST be a string (I-D §2.6)".to_owned())
            })?;
        let media_type = match declared.get("media_type") {
            None => None,
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => {
                return Err(invalid(
                    "`media_type`, where present, MUST be a string (I-D §2.6)".to_owned(),
                ))
            }
        };
        CanonicalizationDescriptor::new(canonicalization, media_type)
            .map_err(|source| invalid(source.to_string()))?;
    }
    Ok(())
}

/// The SET of a manifest's log key objects, normalized for I-D §7.1 governance-key-rotation
/// comparison: `(key_id, pubkey, valid_from_index)` tuples, order-independent (I-D §6.2: "Each
/// manifest version's log and witness key objects replace the prior set in full" — a SET, not a
/// sequence).
///
/// Called only where the manifest schema (`log_object`) has already validated `log.keys`, so
/// every member read here is known present and well typed.
fn log_key_set(payload: &Value) -> BTreeSet<(String, String, u64)> {
    payload
        .get("log")
        .and_then(|log| log.get("keys"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|object| {
            Some((
                object.get("key_id")?.as_str()?.to_owned(),
                object.get("pubkey")?.as_str()?.to_owned(),
                object.get("valid_from_index")?.as_u64()?,
            ))
        })
        .collect()
}

/// The SET of a manifest's witness key objects, normalized the same way, with `witness_id`
/// carried alongside each key object since it is part of the object's identity (I-D §7.1: "A
/// witness key object additionally carries `witness_id`, the identity under which the manifest
/// declares that witness").
fn witness_key_set(payload: &Value) -> BTreeSet<(String, String, String, u64)> {
    payload
        .get("witnesses")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|witness| {
            let witness_id = witness.get("witness_id")?.as_str()?.to_owned();
            let keys = witness.get("keys")?.as_array()?;
            Some(keys.iter().filter_map(move |object| {
                Some((
                    witness_id.clone(),
                    object.get("key_id")?.as_str()?.to_owned(),
                    object.get("pubkey")?.as_str()?.to_owned(),
                    object.get("valid_from_index")?.as_u64()?,
                ))
            }))
        })
        .flatten()
        .collect()
}

/// Verify this manifest's `governance.rotation_proofs[]` element (I-D §7.1; §7.5.1 4b(M) "The
/// rotation-anchoring rule, also phase 2"): a manifest may be trusted to introduce a rotated log
/// or witness key set only where its own anchoring is proven under the OUTGOING states.
///
/// `rotating_manifest`/`rotating_envelope` are this manifest's own payload/envelope;
/// `outgoing_manifest` is its predecessor's payload — the state being retired, which is what the
/// proof must be signed and cosigned under, never the incoming state the rotation installs.
#[allow(clippy::too_many_lines)]
fn verify_rotation_proof(
    receipt: &Value,
    rotating_envelope: &Value,
    manifest_entry_index: u64,
    rotating_manifest: &Value,
    outgoing_manifest: &Value,
    budget: &mut Budget,
) -> Result<()> {
    let invalid =
        |detail: String| ReceiptError::RotationProofInvalid { manifest_entry_index, detail };

    let empty = Vec::new();
    let proofs = receipt
        .get("governance")
        .and_then(|governance| governance.get("rotation_proofs"))
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let element = proofs
        .iter()
        .find(|element| number(element, "manifest_entry_index").ok() == Some(manifest_entry_index))
        .ok_or_else(|| {
            invalid(
                "`governance.rotation_proofs[]` carries no element for this rotation (I-D §7.1: \
                 REQUIRED where the carried chain rotates either governance key set)"
                    .to_owned(),
            )
        })?;

    // I-D §7.1: the element's `checkpoint` is "in the receipt-borne form defined above" — the
    // same strict shape `anchoring.checkpoint` takes, not a looser one.
    let checkpoint = checkpoint_object(obj(element, "checkpoint")?)?;
    let tree_size = number(checkpoint, "tree_size")?;
    if tree_size <= manifest_entry_index {
        return Err(invalid(format!(
            "the element's checkpoint tree_size ({tree_size}) must be GREATER than \
             manifest_entry_index ({manifest_entry_index}) (I-D §7.1)"
        )));
    }

    // The checkpoint MUST verify under a log key of the OUTGOING state — never the incoming
    // manifest's own log keys, which is exactly the substitution this proof exists to rule out.
    let checkpoint_key_id = text(checkpoint, "key_id")?;
    let outgoing_log = log_key_set(outgoing_manifest);
    let signer_pubkey = outgoing_log
        .iter()
        .find(|entry| entry.0.as_str() == checkpoint_key_id)
        .map(|entry| entry.1.clone())
        .ok_or_else(|| {
            invalid(format!(
                "the element's checkpoint `key_id` (`{checkpoint_key_id}`) is not a log key of \
                 the OUTGOING state at manifest entry index {manifest_entry_index} — a \
                 checkpoint signed by the INCOMING key does not attest the transition (I-D §7.1)"
            ))
        })?;
    budget.spend(1)?;
    if !verify_signature(
        &decode_pubkey(&signer_pubkey)?,
        &checkpoint_signing_bytes(checkpoint)?,
        text(checkpoint, "signature")?,
    )? {
        return Err(invalid(
            "the element's checkpoint signature does not verify under the outgoing log key"
                .to_owned(),
        ));
    }

    let root = parse_hash_hex(text(checkpoint, "root_hash")?)?;
    check_inclusion(
        &jcs(rotating_envelope),
        manifest_entry_index,
        tree_size,
        &path_strings(element, "inclusion_path")?,
        &root,
        "rotation-proof manifest inclusion",
        budget,
    )?;

    // AT L3, at least one `witnesses[]` cosignature MUST verify under a witness key of the
    // OUTGOING state, whichever set actually rotated — I-D §7.1: "a change to EITHER set is
    // attested under BOTH outgoing states". This build reads the rotating manifest's OWN
    // declared `level` to decide whether L3 applies going forward.
    if rotating_manifest.get("level").and_then(Value::as_str) == Some("L3") {
        let outgoing_witnesses = witness_key_set(outgoing_manifest);
        let candidates = element.get("witnesses").and_then(Value::as_array).unwrap_or(&empty);
        // I-D §7.1: `witnesses` is "an array in the shape of `anchoring.witnesses[]`" — EVERY
        // element of that array is held to the shape, not merely the ones a match happens to
        // reach; a malformed entry is invalid whether or not some OTHER entry in the array
        // would have cosigned successfully.
        let candidates =
            candidates.iter().map(witness_cosignature_object).collect::<Result<Vec<_>>>()?;
        let mut cosigned = false;
        for witness in &candidates {
            let witness_id = text(witness, "witness_id")?.to_owned();
            let key_id = text(witness, "key_id")?;
            let Some(pubkey) = outgoing_witnesses
                .iter()
                .find(|entry| entry.0 == witness_id && entry.1.as_str() == key_id)
                .map(|entry| entry.2.clone())
            else {
                continue;
            };
            budget.spend(1)?;
            if verify_signature(
                &decode_pubkey(&pubkey)?,
                &cosignature_bytes(checkpoint, &witness_id),
                text(witness, "cosignature")?,
            )? {
                cosigned = true;
                break;
            }
        }
        if !cosigned {
            return Err(invalid(
                "AT L3, at least one `witnesses[]` cosignature must verify under a witness key \
                 of the OUTGOING state (I-D §7.1) — none did"
                    .to_owned(),
            ));
        }
    }

    Ok(())
}

/// The exact ascending sequence of GOVERNANCE-KEY ROTATION entry indices the carried chain
/// contains (I-D §7.1), read structurally: each manifest's log/witness key SETS compared
/// against the immediately preceding MANIFEST's (a `key` statement hop in between does not
/// interrupt the comparison, since only manifests carry log/witness key objects at all).
fn rotating_manifest_indices(chain: &[Value]) -> Result<Vec<u64>> {
    let mut rotations = Vec::new();
    let mut previous_manifest: Option<&Value> = None;
    for hop in chain {
        let envelope = obj(hop, "envelope")?;
        let payload = payload_of(envelope)?;
        if statement_type(payload)? != "manifest" {
            continue;
        }
        if let Some(previous) = previous_manifest {
            let rotated = log_key_set(payload) != log_key_set(previous)
                || witness_key_set(payload) != witness_key_set(previous);
            if rotated {
                rotations.push(number(hop, "entry_index")?);
            }
        }
        previous_manifest = Some(payload);
    }
    Ok(rotations)
}

/// I-D §7.1's collection-level rules for `governance.rotation_proofs[]`, checked BEFORE any
/// element's own content: present with no rotation in the chain is invalid ("the member is
/// ABSENT where the chain rotates neither set"); where rotations exist, the carried
/// `manifest_entry_index` sequence must equal EXACTLY the ascending sequence of rotating
/// manifests' entry indexes — no duplicates, no extras, no missing, no reordering ("one
/// element per rotation, in ascending `manifest_entry_index` order").
fn check_rotation_proofs_sequence(receipt: &Value, chain: &[Value]) -> Result<()> {
    let expected = rotating_manifest_indices(chain)?;
    let carried =
        receipt.get("governance").and_then(|governance| governance.get("rotation_proofs"));
    if expected.is_empty() {
        return if carried.is_some() {
            Err(ReceiptError::GovernanceChainInvalid(
                "`governance.rotation_proofs` is present, but the carried chain rotates neither the log \
                 nor the witness key set — I-D §7.1 requires the member to be ABSENT in that \
                 case"
                    .to_owned(),
            ))
        } else {
            Ok(())
        };
    }
    let carried_array = carried.and_then(Value::as_array).ok_or_else(|| {
        ReceiptError::GovernanceChainInvalid(
            "`governance.rotation_proofs` is REQUIRED: the carried chain contains a governance-key \
             rotation (I-D §7.1)"
                .to_owned(),
        )
    })?;
    let carried_indices: Vec<u64> = carried_array
        .iter()
        .map(|element| number(element, "manifest_entry_index"))
        .collect::<Result<_>>()?;
    if carried_indices != expected {
        return Err(ReceiptError::GovernanceChainInvalid(format!(
            "`governance.rotation_proofs[]`'s manifest_entry_index sequence {carried_indices:?} does \
             not equal EXACTLY the ascending sequence of rotating manifests' entry indexes \
             {expected:?} (I-D §7.1: one element per rotation, ascending order, no duplicates, \
             no extras, no missing)"
        )));
    }
    Ok(())
}

/// Build and structurally validate the governance chain (I-D §7.5.1 4a-4c): the base case,
/// then the induction, each carried statement's SIGNATURE verified against K as established by
/// its predecessors before anything about its own content is trusted.
// The governance-key-rotation check (I-D §7.1, §7.5.1) folds naturally into this same
// per-manifest walk rather than a second pass over the same material.
#[allow(clippy::too_many_lines)]
fn read_chain<'a>(
    receipt: &'a Value,
    policy: &TrustPolicy,
    budget: &mut Budget,
) -> Result<Governance<'a>> {
    let chain = array(obj(receipt, "governance")?, "chain")?;
    if chain.is_empty() {
        return Err(ReceiptError::GovernanceChainInvalid("chain is empty".to_owned()));
    }

    // I-D §7.1: "REQUIRED IF AND ONLY IF the carried governance chain contains a
    // GOVERNANCE-KEY ROTATION"; "The member is ABSENT where the chain rotates neither set";
    // "one element per rotation, in ascending `manifest_entry_index` order." This is a
    // key-independent ARITY/ORDERING check on the CONTAINER — like §7.5 step 3's family-string
    // and ordering checks — so it runs before anything about any individual element's own
    // content, crypto included, and before the induction below even starts.
    check_rotation_proofs_sequence(receipt, chain)?;

    // --- I-D §7.5.1 4a. Base case: the genesis manifest is authenticated WITHOUT any key. ---
    //
    // "An offline verifier cannot authenticate a genesis anchor supplied by the receipt itself;
    // it MUST compare `governance.genesis_entry_id` against independently configured policy...
    // Recompute the entry id of the first element of `governance.chain[]` and require it to
    // equal the configured anchor. That equality alone authenticates the genesis envelope IN
    // FULL, payload and signatures together, because an entry id is SHA-256(JCS(envelope))...
    // no key is needed to establish it, which is what makes the base case genuinely basal
    // rather than one more thing needing a key."
    if number(&chain[0], "entry_index")? != 0 {
        return Err(ReceiptError::GovernanceChainInvalid(
            "the chain must start at entry index 0".to_owned(),
        ));
    }
    let genesis_envelope = obj(&chain[0], "envelope")?;
    let genesis_payload = payload_of(genesis_envelope)?;
    check_ahl_version(genesis_payload)?;
    if statement_type(genesis_payload)? != "manifest" {
        return Err(ReceiptError::GovernanceChainInvalid(
            "the chain must start at the genesis manifest".to_owned(),
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
        key_objects(genesis_payload)?.into_iter().map(|(id, _)| id).collect();
    if genesis_key_ids != policy.genesis_key_ids {
        return Err(ReceiptError::GenesisAnchorMismatch);
    }

    // "The genesis manifest is INSIDE the typed checks, not outside them... It earns exactly
    // two exemptions: it is exempt from the `predecessor` linkage rule... and it is exempt from
    // signature derivation under a prior key state, because there is no prior state to derive
    // from and entry-id equality has already bound its complete bytes, signatures included."
    if genesis_payload.get("predecessor").is_some() {
        return Err(ReceiptError::GovernanceChainInvalid(
            "the genesis manifest must carry no predecessor reference".to_owned(),
        ));
    }
    key_objects(genesis_payload)?;
    log_object(genesis_payload)?;
    datasets_object(genesis_payload)?;
    if let Some(witnesses) = genesis_payload.get("witnesses").and_then(Value::as_array) {
        for witness in witnesses {
            key_objects(witness)?;
        }
    }

    // "Only after ALL of those pass... let K be the key state the genesis manifest declares."
    let mut manifests: Vec<(u64, &Value)> = vec![(0, genesis_payload)];
    let mut events: Vec<KeyEvent> = Vec::new();
    let mut manifest_by_version_id: BTreeMap<String, (u64, &Value)> = BTreeMap::new();
    manifest_by_version_id.insert(statement_id(genesis_envelope)?, (0, genesis_payload));
    let mut previous_index = 0u64;
    let mut previous_manifest_entry_id = entry_id(genesis_envelope);
    let mut previous_manifest_payload = genesis_payload;

    // --- I-D §7.5.1 4b. Inductive step: three phases, in this order, for every later hop. ---
    for hop in &chain[1..] {
        let index = number(hop, "entry_index")?;
        if previous_index >= index {
            return Err(ReceiptError::GovernanceChainInvalid(
                "chain hops must ascend by entry index".to_owned(),
            ));
        }
        previous_index = index;

        let envelope = obj(hop, "envelope")?;
        let payload = payload_of(envelope)?;
        check_ahl_version(payload)?;

        // Phase 1: "Verify the envelope under the envelope signature rule of Section 2.1
        // against K AS ESTABLISHED SO FAR — the governance state in force immediately before
        // this statement's own entry index." `manifests`/`events` so far contain only hops
        // strictly before `index`, so this is exactly that state, computed BEFORE anything
        // about this hop's own content — schema, predecessor linkage, rotation proof — is read.
        let k_so_far = producer_keys_at_in(&manifests, &events, index);
        budget.spend(1)?;
        if !crate::verify_envelope(envelope, |key_id| {
            k_so_far.get(key_id).map(|bound| bound.pubkey.clone())
        })? {
            return Err(ReceiptError::EnvelopeSignatureInvalid { entry_index: index });
        }

        // "A failure at phase 1 or phase 2 is invalid, and the induction does not continue past
        // it. No effect is ever applied to K by a statement that has not completed both
        // earlier phases." Phase 2 (type-specific validation) and phase 3 (effect) follow.
        match statement_type(payload)? {
            "manifest" => {
                // Phase 2, 4b(M): predecessor linkage, then the same §6.2/§6.3 schema every
                // manifest version takes, then the rotation-anchoring rule.
                match payload.get("predecessor").and_then(Value::as_str) {
                    None => {
                        return Err(ReceiptError::GovernanceChainInvalid(
                            "a non-genesis manifest must reference its predecessor".to_owned(),
                        ))
                    }
                    // A non-genesis manifest references its predecessor by *entry* id:
                    // signature identity matters for chain links (spec §2.3.5).
                    Some(got) if got != previous_manifest_entry_id => {
                        return Err(ReceiptError::GovernanceChainInvalid(format!(
                            "manifest at entry index {index} references `{got}`, its \
                             predecessor in the chain is `{previous_manifest_entry_id}`"
                        )))
                    }
                    Some(_) => {}
                }
                // The manifest's `keys` array is a *snapshot*, not a set of add events
                // (spec §7.2). It is read at resolution time by `producer_keys_at`, which
                // discards whatever the prior manifest declared.
                //
                // Schema checking happens here, once per manifest, rather than wherever a
                // member is first read. Key binding downstream is deliberately tolerant — a
                // receipt may carry the same log key bound to two manifest versions, so a
                // single entry that fails to bind is not fatal — and a malformed key object
                // reaching that path would be swallowed by the tolerance and resurface as a
                // missing key. A manifest that breaks the frozen schema must be refused as
                // such, not reported as a key that happens not to resolve.
                key_objects(payload)?;
                log_object(payload)?;
                datasets_object(payload)?;
                if let Some(witnesses) = payload.get("witnesses").and_then(Value::as_array) {
                    for witness in witnesses {
                        key_objects(witness)?;
                    }
                }
                // I-D §7.1 / §7.5.1: a manifest whose log or witness key objects DIFFER, as
                // SETS, from its predecessor's in the chain is a GOVERNANCE-KEY ROTATION (I-D
                // §6.2: "Each manifest version's log and witness key objects replace the prior
                // set in full" — a set, not a sequence, so a harmless reordering is never a
                // rotation) and requires its `governance.rotation_proofs[]` element to verify
                // under the outgoing key state (`verify_rotation_proof`).
                let rotated = log_key_set(payload) != log_key_set(previous_manifest_payload)
                    || witness_key_set(payload) != witness_key_set(previous_manifest_payload);
                if rotated {
                    verify_rotation_proof(
                        receipt,
                        envelope,
                        index,
                        payload,
                        previous_manifest_payload,
                        budget,
                    )?;
                }
                // Phase 3: effect — replaces the log, witness, and producer key state in full.
                previous_manifest_entry_id = entry_id(envelope);
                previous_manifest_payload = payload;
                manifest_by_version_id.insert(statement_id(envelope)?, (index, payload));
                manifests.push((index, payload));
            }
            "key" => {
                // Phase 2, 4b(K): action and shape.
                let key = obj(payload, "key")?;
                let added = match text(payload, "action")? {
                    "add" => true,
                    "retire" => false,
                    other => {
                        return Err(ReceiptError::GovernanceChainInvalid(format!(
                            "unknown key action `{other}`"
                        )))
                    }
                };
                let key_id = text(key, "key_id")?.to_owned();
                let pubkey = text(key, "pubkey")?.to_owned();
                // I-D §2.2: a `key` statement is not a manifest statement, so it carries a
                // `manifest` field of its own, and that field is held to the SAME rule as the
                // subject's copy (§7.6) — it must name the manifest version ACTIVE at THIS
                // statement's own entry index, never a stale one.
                let claimed_manifest = text(payload, "manifest")?;
                let active = active_manifest_version_id(&manifests, &manifest_by_version_id, index)
                    .ok_or_else(|| {
                        ReceiptError::GovernanceChainInvalid(format!(
                            "no manifest version is active at entry index {index} (I-D §2.2)"
                        ))
                    })?;
                if claimed_manifest != active {
                    return Err(ReceiptError::GovernanceChainInvalid(format!(
                        "key statement at entry index {index} names manifest \
                         `{claimed_manifest}`, which is not the manifest version active at \
                         that index (`{active}`) (I-D §2.2)"
                    )));
                }
                // Phase 3: effect — modifies the producer key set only (I-D §6.2: log and
                // witness keys rotate only by anchoring a new manifest version).
                events.push(KeyEvent { entry_index: index, key_id, pubkey, added });
            }
            other => {
                return Err(ReceiptError::GovernanceChainInvalid(format!(
                    "`{other}` is not a governance statement"
                )))
            }
        }
    }

    Ok(Governance { manifests, events, manifest_by_version_id })
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
        key_objects(log_object(manifest)?)?
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
    let checkpoint = checkpoint_object(obj(anchoring, "checkpoint")?)?;
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
    if text(log_object(active_manifest)?, "log_id")? != text(checkpoint, "log_id")? {
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
        let cosignature = witness_cosignature_object(cosignature)?;
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
    if (anchoring.get("later_checkpoint").is_some() || anchoring.get("consistency_path").is_some())
        && !profile.capabilities.consistency_proofs
    {
        return Err(ReceiptError::AdaptorCapabilityUnsupported {
            id: profile_id.to_owned(),
            capability: "a consistency-proof serialization for `anchoring.later_checkpoint`",
        });
    }
    let continued_history =
        verify_continued_history(receipt, governance, anchoring, tree_size, &root, budget)?;

    Ok(Anchoring { tree_size, root, witnessed, continued_history })
}

/// Verify `anchoring.later_checkpoint` plus `anchoring.consistency_path` (format §2.1, §2.3;
/// adaptor profile `ahl-adaptor-atl-v1` §8.3).
///
/// The claim `continued_history` makes is that the log's history continued to be append-only
/// past the checkpoint the subject is included under. Three things have to hold, and each is
/// checked here:
///
/// 1. **Both members are present.** §2.3 states the equivalence — `continued_history` is true
///    *iff* `later_checkpoint` and `consistency_path` verify — so a later checkpoint with no
///    proof, or a proof with no checkpoint, is malformed rather than a weaker claim.
/// 2. **The later checkpoint is authentic on its own terms.** Its log signature is verified
///    against a key declared by the manifest version active for **its** `tree_size`, not the
///    subject checkpoint's (§2.1, §2.2). A key a later manifest replaced must not validate a
///    checkpoint issued under the later state, and the reverse is equally true.
/// 3. **The proof verifies**, as an RFC 9162 §2.1.4 consistency proof from the subject
///    checkpoint's `(tree_size, root_hash)` to the later checkpoint's. A proof that is
///    structurally impossible for that pair of sizes is a failed proof, not a different error:
///    a proof generated for some other pair must never validate a claim about this one.
///
/// The claim's boundary stops there. A consistency proof shows one tree is an append-only
/// extension of another; it does not show that a checkpoint the cadence required was ever
/// published (core spec §7.3), and no verdict rendered from it may say otherwise.
fn verify_continued_history(
    receipt: &Value,
    governance: &Governance<'_>,
    anchoring: &Value,
    from_size: u64,
    from_root: &Hash,
    budget: &mut Budget,
) -> Result<bool> {
    match (anchoring.get("later_checkpoint"), anchoring.get("consistency_path")) {
        (None, None) => return Ok(false),
        (Some(_), None) => {
            return Err(ReceiptError::Malformed(
                "`anchoring.consistency_path` is REQUIRED whenever `later_checkpoint` is \
                 present (§2.1)"
                    .to_owned(),
            ))
        }
        (None, Some(_)) => {
            return Err(ReceiptError::Malformed(
                "`anchoring.later_checkpoint` is REQUIRED whenever `consistency_path` is \
                 present (§2.1)"
                    .to_owned(),
            ))
        }
        (Some(_), Some(_)) => {}
    }

    let later = checkpoint_object(obj(anchoring, "later_checkpoint")?)?;
    let to_size = number(later, "tree_size")?;
    if to_size < from_size {
        // A "later" checkpoint smaller than the one the subject is included under proves no
        // continued history; it is the size regression a witness refuses to cosign over.
        return Err(ReceiptError::ConsistencyPathInvalid);
    }
    authenticate_checkpoint(receipt, governance, later, budget)?;

    let to_root = parse_hash_hex(text(later, "root_hash")?)?;
    let path = path_strings(anchoring, "consistency_path")?;
    let proof = crate::consistency_from_hex(from_size, to_size, &path)?;
    budget.spend(1)?;
    match crate::verify_consistency_proof(&proof, from_root, &to_root) {
        Ok(true) => Ok(true),
        // `Ok(false)` is a proof that does not open the pair; `Err` is a proof that could not
        // exist for these sizes at all. Neither establishes continued history, and reporting
        // them apart would only invite treating the second as a transport problem.
        Ok(false) | Err(_) => Err(ReceiptError::ConsistencyPathInvalid),
    }
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
        let envelope = obj(entry, "envelope")?;
        // I-D §2.2 / §7.1: every carried statement's `ahl_version` is checked before
        // validating that statement — enumerated envelopes included. This is the one choke
        // point every enumerated envelope (governance currency, competing-trigger, and
        // propagation-prefix material alike) passes through before its payload is read
        // anywhere downstream.
        check_ahl_version(payload_of(envelope)?)?;
        envelopes.push(envelope.clone());
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
    // I-D §2.2 / §7.1 / §7.5 step 1: every carried statement's `ahl_version` is checked
    // BEFORE validating that statement — id recomputation and every other per-envelope check
    // included, the subject's own envelope included. Reading `payload_of` needs no trust in
    // `subject`'s own copied fields, so it can run first; checking version on it before
    // touching `subject.statement_id`/`entry_id` is what keeps a foreign-version subject from
    // being reported `invalid` over a copied identifier this document has no rules for.
    let payload = payload_of(envelope)?;
    check_ahl_version(payload)?;
    if text(subject, "statement_id")? != statement_id(envelope)? {
        return Err(ReceiptError::IdentifierMismatch { field: "statement_id" });
    }
    if text(subject, "entry_id")? != entry_id(envelope) {
        return Err(ReceiptError::IdentifierMismatch { field: "entry_id" });
    }
    let subject_index = number(subject, "entry_index")?;
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
    let governance = read_chain(receipt, policy, budget)?;

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

    // --- §5 step 4: chain anchoring (path only — each hop's SIGNATURE was already verified
    // by `read_chain`'s induction, in phase order, before that hop's own schema was even read;
    // re-verifying it here would be both redundant and too late to matter) -----------
    for hop in array(obj(receipt, "governance")?, "chain")? {
        let index = number(hop, "entry_index")?;
        // A hop the checkpoint does not commit cannot be proven against its root, and an
        // unprovable governance statement is a refusal rather than a pass. This is the wall a
        // receipt hits when a manifest version was anchored after its own anchoring checkpoint
        // — the case §2.1 needs for a later checkpoint under a rotated key set. Reporting it as
        // a named refusal keeps it from degrading into "the older key still worked, so accept".
        if index >= anchoring.tree_size {
            return Err(ReceiptError::GovernanceChainInvalid(format!(
                "the chain carries a hop at entry index {index}, which a checkpoint of size {} \
                 does not commit: its inclusion cannot be proven against that root",
                anchoring.tree_size
            )));
        }
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
    }
    // The subject's own envelope is verified separately, against K FINAL at ITS OWN entry
    // index (I-D §7.5.1 4d "remaining carried envelopes") — a later, distinct step from the
    // induction above, not a repetition of it.
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

    // Enumerated currency and a later checkpoint cannot both be evidenced. §2.1 requires the
    // governance material to cover through `later_checkpoint.tree_size`; §4 fixes enumerated
    // material at exactly `[0, tree_size(C))` for the receipt's verified checkpoint, which §3
    // binds to `anchoring.checkpoint`. Since a later checkpoint is at a greater tree size, no
    // range satisfies both rules, and the format defines no second authenticated range.
    //
    // The tempting move is to verify the enumeration through the anchoring checkpoint, accept
    // the later checkpoint separately, and call the receipt good. That reports as established a
    // coverage requirement nothing in the receipt proves: a manifest anchored between the two
    // checkpoints could have rotated the log key set, and the enumeration would never show it.
    // A defective format is a reason not to fabricate evidence; it is not a reason to declare
    // missing evidence verified. So the combination is refused, under an error naming the
    // conflict rather than pretending some rule failed. Declared mode is unaffected: it makes
    // no currency claim in the first place (§2.1).
    if mode == "enumerated" && obj(receipt, "anchoring")?.get("later_checkpoint").is_some() {
        return Err(ReceiptError::FormatConflict {
            combination:
                "enumerated governance currency together with `anchoring.later_checkpoint`",
            conflict: "receipt format §2.1 requires governance material covering through \
                       `later_checkpoint.tree_size`, while §4 fixes enumerated material at \
                       exactly [0, tree_size(anchoring.checkpoint)); no range satisfies both, so \
                       the coverage §2.1 mandates is absent and the receipt is refused rather \
                       than accepted on unproven governance",
        });
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

    // --- §2.3 / I-D §7.6: subject-level cross-field consistency ----------------------
    let manifest_declared = subject.get("manifest").is_some();
    if manifest_declared == (subject_type == "manifest") {
        return Err(ReceiptError::SubjectManifestPresence { statement_type: subject_type });
    }
    // I-D §7.6: "`subject.manifest` equals the subject envelope's `payload.manifest` for
    // every subject other than a manifest statement. The payload's `manifest` member is
    // covered by the subject's signature; the receipt's copy is not, so this equality is the
    // only thing that authenticates the copy. Section 6.3 anchors the descriptor check to the
    // version this member names, and that check establishes nothing without this rule." And:
    // "The manifest version named by `subject.manifest` is PRESENT in `governance.chain`... and
    // that element's `entry_index` is strictly smaller than `subject.entry_index`. A named
    // version absent from the chain, or anchored at or after the subject, cannot have governed
    // the subject."
    if let Some(claimed) = subject.get("manifest").and_then(Value::as_str) {
        let payload_manifest = text(payload, "manifest")?;
        if claimed != payload_manifest {
            return Err(ReceiptError::SubjectManifestBindingInvalid(format!(
                "`subject.manifest` (`{claimed}`) does not equal the subject envelope's own \
                 `payload.manifest` (`{payload_manifest}`) (I-D §7.6)"
            )));
        }
        // I-D §2.2: "the manifest version active at the statement's entry index — that is, the
        // manifest statement with the greatest entry index smaller than the statement's own."
        // Presence in the chain and being strictly before the subject are necessary but NOT
        // sufficient — `payload.manifest` must name exactly THAT manifest, never a stale,
        // superseded one, or content-binding descriptor resolution takes `ddig` from the wrong
        // manifest version (I-D §6.3).
        let active = governance.active_manifest_version_id_at(subject_index).ok_or_else(|| {
            ReceiptError::SubjectManifestBindingInvalid(format!(
                "no manifest version is active at subject.entry_index {subject_index} (I-D §2.2)"
            ))
        })?;
        if claimed != active {
            return Err(ReceiptError::SubjectManifestBindingInvalid(format!(
                "`subject.manifest` (`{claimed}`) is not the manifest version ACTIVE at \
                 subject.entry_index {subject_index} (`{active}`) (I-D §2.2, §7.6)"
            )));
        }
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
///
/// Everything past the `"none"` case is I-D revision 0.4, §2.6 and §6.3:
///
/// 1.  The governing manifest is the one NAMED BY THE SUBJECT STATEMENT's own `manifest`
///     binding (I-D §2.2) — the manifest statement's STATEMENT id (I-D §2.4.5), not its entry
///     id, and not merely whichever manifest happens to be active at the subject's entry
///     index.
/// 2.  `claim_material`'s own `canonicalization`/`media_type` MUST equal (I-D §2.6 descriptor
///     equality — identical normalized forms) that manifest's declared descriptor; a mismatch,
///     or a missing `claim_material.canonicalization`, is `invalid`.
/// 3.  For an identifier this build implements, wrong `media_type` presence is `invalid` for
///     this dataset's binding (I-D §2.6 "Presence is a producer duty and is never a syntactic
///     matter"); for one it does not implement, the finding is `unverifiable`
///     ([`ReceiptError::CanonicalizationUnsupported`]), never `invalid`, and never
///     rehabilitated to `content_binding: "none"`.
/// 4.  The carried bytes are the record AS RECEIVED; this verifier APPLIES the canonicalization
///     procedure (`jcs`: parse then re-serialize through [`crate::jcs`]; `exact-bytes`: the
///     octets unchanged) before recomputing the commitment. Bytes that fail the procedure make
///     this dataset's finding `invalid` ([`ReceiptError::CanonicalizationFailed`]), not a panic
///     and not a run-aborting error unrelated to this binding.
// I-D §2.6/§6.3 fold four checks into one recomputation — descriptor resolution, descriptor
// equality, media-type presence, and the canonicalization procedure — and splitting them into
// helpers each carrying the growing set of intermediate values would obscure the order the I-D
// itself fixes for them.
#[allow(clippy::too_many_lines)]
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

    let manifest_version_id = text(ctx.payload, "manifest")?;
    let (_, manifest) =
        ctx.governance.manifest_by_version_id(manifest_version_id).ok_or_else(|| {
            ReceiptError::GovernanceChainInvalid(format!(
                "manifest version `{manifest_version_id}` named by the subject statement's \
             `manifest` binding is not in the carried governance chain"
            ))
        })?;
    let declared = obj(obj(manifest, "datasets")?, dataset)?;
    let declared_mode = text(declared, "commitment_mode")?.to_owned();
    // `datasets_object` already validated this manifest's descriptor syntax at manifest-schema
    // time (I-D §6.3 row 1); this reconstruction is what actually computes `ddig`.
    let canonicalization = text(declared, "canonicalization")?.to_owned();
    let media_type = declared.get("media_type").and_then(Value::as_str).map(str::to_owned);
    let descriptor = CanonicalizationDescriptor::new(canonicalization, media_type)?;

    // I-D §6.3: claim_material's descriptor MUST equal the manifest's declared one, under the
    // descriptor equality of §2.6 (identical normalized forms — comparing normalized members,
    // never raw declared bytes).
    let claimed_canonicalization = material
        .get("canonicalization")
        .and_then(Value::as_str)
        .ok_or_else(|| ctx.missing("canonicalization"))?
        .to_owned();
    let claimed_media_type = material.get("media_type").and_then(Value::as_str).map(str::to_owned);
    let claimed_descriptor =
        CanonicalizationDescriptor::new(claimed_canonicalization, claimed_media_type)?;
    if claimed_descriptor.canonicalization() != descriptor.canonicalization()
        || claimed_descriptor.media_type() != descriptor.media_type()
    {
        return Err(ReceiptError::ClaimDescriptorMismatch {
            dataset: dataset.to_owned(),
            claimed: describe_descriptor(&claimed_descriptor),
            declared: describe_descriptor(&descriptor),
            manifest_version_id: manifest_version_id.to_owned(),
        });
    }

    // I-D §2.6: presence is capability-gated — `descriptor::media_type_required` returns
    // `None` for an identifier this build does not implement, and that case falls through to
    // the canonicalization step below, which reports it as unverifiable rather than as a
    // presence defect this verifier has no grounds to assert.
    match descriptor::media_type_required(descriptor.canonicalization()) {
        Some(required) if required != descriptor.media_type().is_some() => {
            let detail = if required {
                "MUST carry `media_type` (I-D §2.6)"
            } else {
                "MUST NOT carry `media_type` (I-D §2.6)"
            };
            return Err(ReceiptError::MediaTypePresenceInvalid {
                dataset: dataset.to_owned(),
                identifier: descriptor.canonicalization().to_owned(),
                detail,
            });
        }
        _ => {}
    }

    let ddig = descriptor.ddig();
    let encoded = material.get(field).and_then(Value::as_str).ok_or_else(|| ctx.missing(field))?;
    let received = B64
        .decode(crate::strip_prefix(encoded, "base64:")?)
        .map_err(|source| ReceiptError::Ahl(AhlError::Base64(source)))?;

    // I-D §2.6 / §7.2: `received` is the record AS RECEIVED; the verifier canonicalizes it
    // before recomputing the commitment.
    let bytes = match descriptor.canonicalization() {
        "jcs" => {
            let value: Value = serde_json::from_slice(&received).map_err(|source| {
                ReceiptError::CanonicalizationFailed {
                    dataset: dataset.to_owned(),
                    identifier: "jcs".to_owned(),
                    detail: source.to_string(),
                }
            })?;
            jcs(&value)
        }
        "exact-bytes" => received,
        other => {
            return Err(ReceiptError::CanonicalizationUnsupported {
                dataset: dataset.to_owned(),
                identifier: other.to_owned(),
            })
        }
    };

    let recomputed = match ctx.assurance.content_binding.as_str() {
        "plain-verified" if declared_mode == "plain" => commit_plain(dataset, &ddig, &bytes)?,
        "keyed-authorized" if declared_mode == "keyed" => {
            let key = ctx.policy.dataset_keys.get(dataset).ok_or_else(|| {
                ReceiptError::ContentBindingMismatch {
                    mode: "keyed-authorized".to_owned(),
                    recomputed: "<no dataset key held>".to_owned(),
                    claimed: record.to_owned(),
                }
            })?;
            commit_keyed(key, dataset, &ddig, &bytes)?
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

/// Render a descriptor's normalized form for an error message (I-D §2.6 descriptor equality).
fn describe_descriptor(descriptor: &CanonicalizationDescriptor) -> String {
    descriptor.media_type().map_or_else(
        || format!("{{canonicalization: {}}}", descriptor.canonicalization()),
        |media_type| {
            format!(
                "{{canonicalization: {}, media_type: {media_type}}}",
                descriptor.canonicalization()
            )
        },
    )
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
/// [`authenticate_checkpoint`] plus prefix recomputation instead.
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
/// Receipt format §5 step 3a splits this into two separate tests, in order:
///
/// 1. **Envelope validity**: EVERY entry in `signatures` MUST resolve to a producer key active
///    at `index` and MUST verify (`crate::verify_envelope`'s AND-all semantics). An envelope
///    carrying even one non-verifying or unresolvable entry is invalid outright, regardless of
///    its other entries — a candidate's `signatures[].key_id` naming an authority key proves
///    nothing on its own, since the `sig` bytes are controlled by whoever assembled the
///    statement, who may be a party without authority.
/// 2. **Authorization**, tested only once the envelope is valid: the trigger is authorized iff
///    AT LEAST ONE of those verified signers is in the authority key set active at `index`.
///    Core spec §2.3.3 requires a trigger to be "signed by the record's authority", not signed
///    *exclusively* by authority keys — a trigger genuinely co-signed by the authority AND some
///    other active producer key is still authorized.
///
/// Splitting the two tests this way, rather than restricting step 1's resolver to authority
/// keys, is what makes a legitimately co-signed trigger classify correctly: restricting
/// resolution to authority keys would make ANY additional, genuinely valid co-signer from a
/// non-authority key fail the whole envelope, misclassifying an authorized trigger as a
/// challenge.
fn is_authorized_trigger(
    ctx: &ClaimCtx<'_>,
    envelope: &Value,
    dataset: &str,
    by_ingestion: bool,
    index: u64,
    budget: &mut Budget,
) -> Result<bool> {
    budget.spend(1)?;
    let pubkeys = ctx.governance.producer_pubkeys_at(index);
    if !crate::verify_envelope(envelope, |key_id| pubkeys.get(key_id).cloned())? {
        return Ok(false);
    }
    let authority = authority_at(ctx, dataset, by_ingestion, index)?;
    let signers: BTreeSet<String> = array(envelope, "signatures")?
        .iter()
        .map(|signature| Ok(text(signature, "key_id")?.to_owned()))
        .collect::<Result<_>>()?;
    Ok(!signers.is_disjoint(&authority))
}

/// Spec §2.3.3: a trigger is effective only if signed by the record's authority. Triggers from
/// any other key anchor as **challenges**: surfaced by verification, never traversed.
///
/// Format §5 step 3a requires this to be a real cryptographic check, not a `key_id` name match:
/// a signature entry that merely *names* an authority key proves nothing on its own, since the
/// `sig` bytes are controlled by whoever assembled the envelope. This routes through the same
/// `is_authorized_trigger` machinery `verify_competing_triggers` uses, so the receipt's own
/// envelope must actually verify (every entry, against a key active at `ctx.subject_index`) and
/// at least one of its genuine signers must be the record's authority.
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

/// Authenticate a checkpoint the receipt carries alongside its own anchoring checkpoint.
///
/// Two claim shapes need this: the propagation's declared checkpoint D (format §3) and
/// `anchoring.later_checkpoint` (§2.1). Both are carried as full signed checkpoint objects, and
/// both are validated the same way — the signature is checked against a log key that appears in
/// the receipt's `keys.log` block *and* is declared by the manifest version active for **that
/// checkpoint's own** tree size, never for the anchoring checkpoint's. The two can differ: a
/// manifest anchored between them rotates the log key set, and a checkpoint issued under one
/// state must be validated by that state's key (format §2.2).
fn authenticate_checkpoint(
    receipt: &Value,
    governance: &Governance<'_>,
    declared: &Value,
    budget: &mut Budget,
) -> Result<()> {
    let key_id = text(declared, "key_id")?;
    let tree_size = number(declared, "tree_size")?;
    let (active_index, active_manifest) = governance.active_for(tree_size)?;

    // The log id must match the manifest version active for this checkpoint, exactly as it must
    // for the anchoring one (adaptor §5) — no relaxed check for the second checkpoint.
    if text(log_object(active_manifest)?, "log_id")? != text(declared, "log_id")? {
        return Err(ReceiptError::GovernanceChainInvalid(
            "checkpoint `log_id` is not the log the active manifest declares".to_owned(),
        ));
    }

    // The log key resolves against the manifest active for this checkpoint's *own* tree size,
    // and its `keys.log` entry binds to that same manifest version (format §2.2) — the normal
    // source/binding contract, not a byte-equality shortcut. `active_index` can differ from the
    // anchoring checkpoint's: a manifest anchored between them rotates the log key set, and a
    // checkpoint issued under one state must be validated by that state's key.
    // The same `key_id` may appear more than once in `keys.log` — a receipt authenticating two
    // checkpoints can legitimately carry the same physical log key bound to each checkpoint's
    // own active manifest. Take whichever entry actually binds at this checkpoint's
    // `active_index`, not merely the first entry with a matching `key_id` (that could be the
    // one meant for the other checkpoint).
    let mut last_error = None;
    let mut pubkey = None;
    for entry in array(obj(receipt, "keys")?, "log")? {
        if text(entry, "key_id").ok() != Some(key_id) {
            continue;
        }
        check_key_id(entry)?;
        match bind_log_or_witness_key(governance, entry, "log", active_index) {
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
    authenticate_checkpoint(ctx.receipt, ctx.governance, carried_d, budget)?;

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
    boundary.push_str(if assurance.continued_history {
        "; the log's history continued to be append-only through the later checkpoint carried, \
         which is not evidence that every checkpoint the cadence required was published"
    } else {
        "; no claim of continued append-only history beyond that checkpoint"
    });
    boundary.push_str(match assurance.content_binding.as_str() {
        "plain-verified" => "; record content verified against the commitment",
        "keyed-authorized" => {
            "; record content verified against the commitment by an authorized key holder"
        }
        _ => "; record content not verified",
    });
    boundary
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{log_key_set, witness_key_set};

    /// I-D §6.2: "Each manifest version's log and witness key objects replace the prior set in
    /// full" — a SET, not a sequence, so re-listing the same key objects in a different order
    /// is NOT a governance-key rotation (I-D §7.1). `log_key_set`/`witness_key_set` back the
    /// rotation-detection comparison in `read_chain`, and this is the case a full receipt
    /// vector cannot exercise: reordering a manifest's carried `log`/`witnesses` array changes
    /// that manifest envelope's JCS bytes, and so its leaf hash, invalidating the governance
    /// chain hop's own committed inclusion path before the rotation check is ever reached —
    /// the same structural constraint documented for the `media_type` presence test in
    /// `tests/vectors.rs`.
    #[test]
    fn key_set_comparison_is_order_independent() {
        let forward = json!({
            "log": { "keys": [
                { "key_id": "sha256:aa", "pubkey": "base64:AA==", "valid_from_index": 0 },
                { "key_id": "sha256:bb", "pubkey": "base64:BB==", "valid_from_index": 0 },
            ] },
            "witnesses": [
                { "witness_id": "witness-1", "keys": [
                    { "key_id": "sha256:cc", "pubkey": "base64:CC==", "valid_from_index": 0 },
                ] },
                { "witness_id": "witness-2", "keys": [
                    { "key_id": "sha256:dd", "pubkey": "base64:DD==", "valid_from_index": 0 },
                ] },
            ],
        });
        let reordered = json!({
            "log": { "keys": [
                { "key_id": "sha256:bb", "pubkey": "base64:BB==", "valid_from_index": 0 },
                { "key_id": "sha256:aa", "pubkey": "base64:AA==", "valid_from_index": 0 },
            ] },
            "witnesses": [
                { "witness_id": "witness-2", "keys": [
                    { "key_id": "sha256:dd", "pubkey": "base64:DD==", "valid_from_index": 0 },
                ] },
                { "witness_id": "witness-1", "keys": [
                    { "key_id": "sha256:cc", "pubkey": "base64:CC==", "valid_from_index": 0 },
                ] },
            ],
        });

        assert_eq!(
            log_key_set(&forward),
            log_key_set(&reordered),
            "reordering `log.keys` must not look like a rotation"
        );
        assert_eq!(
            witness_key_set(&forward),
            witness_key_set(&reordered),
            "reordering `witnesses[]`, or the `keys` within one witness, must not look like a \
             rotation"
        );

        let genuinely_different = json!({
            "log": { "keys": [
                { "key_id": "sha256:aa", "pubkey": "base64:AA==", "valid_from_index": 0 },
            ] },
            "witnesses": [],
        });
        assert_ne!(log_key_set(&forward), log_key_set(&genuinely_different));
        assert_ne!(witness_key_set(&forward), witness_key_set(&genuinely_different));
    }
}
