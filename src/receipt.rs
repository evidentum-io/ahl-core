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
    commit_keyed, commit_plain, cosignature_bytes, decode_pubkey, descriptor, entry_id, hash_hex,
    jcs, parse_hash_hex, proof_from_hex, sha256_hex, statement_id, tree_root, verify_signature,
    AhlError, B64,
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

/// A locally possessed adaptor profile: the exact bytes of the held document plus what it
/// defines.
///
/// I-D §3.2, §7.5 step 2: a verifier "MUST recompute the digest over the artifact rather than
/// trusting any value carried with it, and MUST reject a receipt whose pinned digest does not
/// match the artifact held." This crate therefore stores the ARTIFACT itself — never a
/// caller-asserted hash string, which a caller could get wrong (or leave stale after the held
/// document changed) with nothing left to catch it — and computes the digest FROM it at
/// resolution time ([`AdaptorProfile::hash`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdaptorProfile {
    /// The exact bytes of the published profile document, held locally (core spec §3 item 6:
    /// versioned, immutable, content-addressed).
    pub document: Vec<u8>,
    /// What the document defines. Anything not listed here is unusable *under this profile*.
    pub capabilities: AdaptorCapabilities,
}

impl AdaptorProfile {
    /// The SHA-256 digest of the held document, as `sha256:<hex>` — recomputed from
    /// [`Self::document`] every time, never cached from or trusted as a value supplied
    /// alongside it.
    #[must_use]
    pub fn hash(&self) -> String {
        sha256_hex(&self.document)
    }

    /// A profile that defines only what the corpus adaptor `ahl-test-log-v1` defines, over the
    /// given held document.
    #[must_use]
    pub const fn minimal(document: Vec<u8>) -> Self {
        Self {
            document,
            capabilities: AdaptorCapabilities { checkpoint_raw: false, consistency_proofs: false },
        }
    }
}

/// One witness key local policy holds, under the identity it holds it for (I-D §7.1).
///
/// `witness_id` is part of the entry rather than free-standing configuration because the
/// identity is inside the cosignature preimage: a key trusted for one witness is not thereby a
/// key trusted to cosign as another. The identity must ALSO be one the manifest version active
/// for the checkpoint declares — that check is on the receipt's material, not on this entry,
/// and lives in [`ReceiptError::WitnessNotDeclared`]'s call site.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TrustedWitnessKey {
    /// The public key cosignatures under this key are verified with, as a `base64:` family
    /// string in the form the receipt carries it.
    pub pubkey: String,
    /// The witness identity policy trusts this key to cosign under.
    pub witness_id: String,
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
    /// The published producer key fingerprints of the genesis manifest, WHERE local policy
    /// holds them (I-D §7.5.1 4a: "WHERE LOCAL POLICY HOLDS initial key fingerprints... which
    /// is optional... where it holds none, this comparison does not arise and its absence is
    /// not a defect"). `None` — not held, no comparison; `Some(set)` — held, and MUST match.
    pub genesis_key_ids: Option<BTreeSet<String>>,
    /// Locally possessed adaptor profiles, by profile id.
    pub adaptor_profiles: BTreeMap<String, AdaptorProfile>,
    /// Dataset HMAC keys this verifier is authorized to hold (`keyed-authorized` binding only).
    pub dataset_keys: BTreeMap<String, Vec<u8>>,
    /// Witness keys trusted by local policy rather than through the manifest chain, by
    /// `key_id` (I-D §7.1: "`source: \"local-policy\"` is an acceptable source only for
    /// witness keys the verifier ALREADY TRUSTS").
    ///
    /// Every member of the entry is compared, never the id alone: a receipt supplies the
    /// `pubkey` a cosignature is verified under and the `witness_id` that goes into its
    /// preimage, so accepting a trusted `key_id` carrying either of its own would let an
    /// unauthorized party choose the verification key or the identity. A policy holding none —
    /// the default — makes every `local-policy` witness key unacceptable, which is the correct
    /// reading of "already trusts" for a verifier that trusts none.
    pub trusted_witness_keys: BTreeMap<String, TrustedWitnessKey>,
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
    /// `public` or `private-use` (I-D §7.3), present exactly where
    /// [`Self::content_binding`] is not `none`.
    ///
    /// It names the NAMESPACE the dataset's canonicalization identifier is drawn from and
    /// nothing else: `private-use` where that identifier begins `x-`, so the binding "holds
    /// only for a verifier configured for this corpus and never across corpora", and `public`
    /// otherwise. `public` "asserts nothing about registration, and nothing in a receipt
    /// does" — a receipt cannot establish that an identifier was registered, only which
    /// namespace it was taken from, which is computable from the receipt alone.
    pub canonicalization_namespace: Option<String>,
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
// The three-valued result model (I-D §7.7)
// ---------------------------------------------------------------------------

/// One of the three values a completed verification run reaches (I-D §7.7).
///
/// The value is scalar for a whole receipt and it is also the value of each per-assertion
/// [`Finding`]: I-D §7.7 gives the findings "the same meanings as above". A run that does NOT
/// complete yields none of these — see [`ExecutionError`].
///
/// The ordering is the reduction of I-D §7.7: "`invalid` if any required finding is `invalid`;
/// otherwise `unverifiable` if any required finding is `unverifiable`; otherwise `verified`."
/// That is the maximum under `Verified < Unverifiable < Invalid`, and [`Ord`] is derived in
/// that order so the reduction is `max` and cannot drift from the sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// The verifier established the asserted property from the presented material.
    Verified,
    /// The presented material neither establishes the asserted property nor contradicts it:
    /// the verifier lacks material, a capability, a local configuration, or a local budget.
    Unverifiable,
    /// The presented material does not verify.
    Invalid,
}

impl Outcome {
    /// The token this value is reported under, as I-D §7.7 spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverifiable => "unverifiable",
            Self::Invalid => "invalid",
        }
    }
}

impl core::fmt::Display for Outcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// One assertion a receipt requires, as I-D §7.7 defines the required set.
///
/// §7.7: "The required assertions of a receipt are exactly: every assertion its claim type's
/// material requires under Section 7.2, together with the anchoring, envelope-validity,
/// governance, and cross-field checks of Section 7.5 steps 1 through 4 and Section 7.6; its
/// content binding, if and only if its own `assurance.content_binding` is not `none`; and for
/// each embedded receipt, every required assertion of THAT receipt."
///
/// The variants name those assertions at the granularity of the §7.5 algorithm's own steps
/// rather than one per check: every check this crate performs maps to exactly one of them,
/// through [`ReceiptError::assertion`], and every rejection therefore names both the assertion
/// it belongs to and — through [`ReceiptError::class`] — the §7.7 value it produces.
/// The variants are DECLARED in the order the §7.5 algorithm reaches them, so the derived
/// [`Ord`] is that order: an assertion greater than another is settled later, which is what
/// decides how far a prerequisite's `unverifiable` outcome reaches. [`Self::ORDER`] lists them
/// in the same order, and a [`Report`] is sorted by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Assertion {
    /// `ahl_receipt_version`, `spec_version` and every carried statement's `ahl_version`
    /// (I-D §7.5 step 1, §2.2).
    Versions,
    /// The §7.8 resource limits: the fixed limits, and the verifier-local budgets.
    ResourceLimits,
    /// The container schema of §7.1 and the identifier recomputation of §7.5 step 1.
    Structure,
    /// Adaptor-profile resolution from local possession (§7.5 step 2).
    AdaptorProfile,
    /// The key-independent path checks of §7.5 step 3: inclusion, the governance chain's own
    /// paths, and the consistency path where `continued_history` is asserted.
    Anchoring,
    /// The governance bootstrap of §7.5.1 4a-4c: the configured genesis anchor, the manifest
    /// lineage, the key induction, rotation proofs, and enumerated governance currency.
    Governance,
    /// Authenticated checkpoint validation (§7.5.1 4f), witness cosignatures included.
    CheckpointAuthentication,
    /// Envelope validity under §2.1 for the subject and every remaining carried envelope
    /// (§7.5.1 4d).
    EnvelopeValidity,
    /// The cross-field consistency rules of §7.6.
    CrossField,
    /// The claim type's own material under §7.2 (§7.5 step 5), authority under 4e included.
    ClaimMaterial,
    /// This receipt's content binding (§7.3, §6.3, §2.6). Required if and only if its own
    /// `assurance.content_binding` is not `none`, and — for an EMBEDDED receipt — never a
    /// required assertion of the receipt that embeds it (§7.7).
    ContentBinding,
}

impl Assertion {
    /// Every assertion, in the order the §7.5 algorithm reaches it.
    pub const ORDER: [Self; 11] = [
        Self::Versions,
        Self::ResourceLimits,
        Self::Structure,
        Self::AdaptorProfile,
        Self::Anchoring,
        Self::Governance,
        Self::CheckpointAuthentication,
        Self::EnvelopeValidity,
        Self::CrossField,
        Self::ClaimMaterial,
        Self::ContentBinding,
    ];

    /// The name this assertion is reported under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Versions => "versions",
            Self::ResourceLimits => "resource-limits",
            Self::Structure => "structure",
            Self::AdaptorProfile => "adaptor-profile",
            Self::Anchoring => "anchoring",
            Self::Governance => "governance",
            Self::CheckpointAuthentication => "checkpoint-authentication",
            Self::EnvelopeValidity => "envelope-validity",
            Self::CrossField => "cross-field",
            Self::ClaimMaterial => "claim-material",
            Self::ContentBinding => "content-binding",
        }
    }
}

impl core::fmt::Display for Assertion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// The outcome of one required assertion, with what produced it (I-D §7.7).
///
/// I-D §7.7 requires the findings to be reported alongside the scalar result, "because the
/// result alone does not say which assertion produced it, and a reader cannot act on
/// `unverifiable` without knowing what was missing" — and a verifier "MUST NOT present a
/// finding as though it were the result".
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Finding {
    /// The assertion this finding is about.
    pub assertion: Assertion,
    /// Its outcome.
    pub outcome: Outcome,
    /// Where the assertion lives: empty for the receipt itself, otherwise the `claim_material`
    /// member names of the embedded receipts leading to it, outermost first (for example
    /// `["trigger", "introduction"]`).
    pub receipt_path: Vec<String>,
    /// For an outcome other than [`Outcome::Verified`], what produced it: the rendered rule
    /// that fired, or the prerequisite assertion this one rests on.
    pub detail: Option<String>,
}

impl Finding {
    /// Whether this finding enters the reduction of the receipt that was verified.
    ///
    /// Every finding does, with the single exception I-D §7.7 states: "for each embedded
    /// receipt, every required assertion of THAT receipt... with one exception: an embedded
    /// receipt's CONTENT BINDING is never a required assertion of the receipt that embeds it."
    /// The exception holds "because no claim type in Section 7.2 rests on an embedded receipt's
    /// record bytes", and it applies at every level, so a content-binding finding at any
    /// non-empty path is outside the reduction of the receipt the run was over.
    #[must_use]
    pub const fn counts_toward_result(&self) -> bool {
        !matches!(self.assertion, Assertion::ContentBinding) || self.receipt_path.is_empty()
    }
}

/// What a completed verification run produced: one scalar result, and the findings it reduces
/// from (I-D §7.7).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The scalar result: "one receipt, one value."
    pub result: Outcome,
    /// One finding per required assertion the run reached, ordered by receipt path and then by
    /// [`Assertion::ORDER`].
    pub findings: Vec<Finding>,
    /// The rendered claim boundary, present if and only if [`Self::result`] is
    /// [`Outcome::Verified`].
    ///
    /// I-D §7.7: "Only `verified` MAY be rendered in words that assert the property. Neither
    /// `invalid` nor `unverifiable` may be rendered as asserting OR denying it."
    pub verdict: Option<Verdict>,
}

impl Report {
    /// The finding for one assertion of the receipt itself.
    #[must_use]
    pub fn finding(&self, assertion: Assertion) -> Option<&Finding> {
        self.finding_at(&[], assertion)
    }

    /// The finding for one assertion of the embedded receipt reached by `path` — the
    /// `claim_material` member names leading to it, outermost first. An empty path is the
    /// receipt itself.
    #[must_use]
    pub fn finding_at(&self, path: &[&str], assertion: Assertion) -> Option<&Finding> {
        self.findings.iter().find(|finding| {
            finding.assertion == assertion
                && finding.receipt_path.len() == path.len()
                && finding.receipt_path.iter().zip(path).all(|(held, want)| held == want)
        })
    }
}

/// A verification run that did not complete, and therefore produced no result at all
/// (I-D §7.7).
///
/// §7.7: "A run that does not complete — an I/O failure, an exhausted heap, a crash — yields no
/// result in this model. It is a local execution failure, reported as such; it says nothing
/// about the receipt and MUST NOT be rendered as any of the three values." This type is that
/// outcome, kept structurally incapable of carrying one of the three values.
///
/// This crate is handed an already-parsed receipt and an already-loaded policy, performs no
/// I/O, and allocates nothing it does not bound, so it produces this error nowhere today:
/// every rejection it can reach is a completed run with a §7.7 value. The type exists so that
/// the boundary is in the signature of [`verify_receipt_report`] rather than in prose, and so
/// that a caller that adds I/O around it — reading the receipt, fetching a policy — has the
/// one place to report such a failure that is not a statement about the receipt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("verification run did not complete: {detail}")]
pub struct ExecutionError {
    /// What stopped the run, in the verifier's own terms. Never one of the three §7.7 values.
    pub detail: String,
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

    /// A §7.8 FIXED limit was exceeded: the embedded-receipt nesting depth, or the number of
    /// embedded receipts in the file.
    ///
    /// I-D §7.8: the fixed limits "are properties of the artifact, decided identically by every
    /// verifier in every year, so a receipt exceeding either is `invalid`." Kept apart from
    /// [`Self::BudgetExhausted`] for exactly that reason — the two classes of limit produce
    /// different §7.7 results, and one variant for both would make the result depend on a
    /// string.
    #[error("fixed resource limit exceeded: {0}")]
    LimitExceeded(&'static str),

    /// A VERIFIER-LOCAL budget was exhausted: the decoded-size budget, or the
    /// verification-work budget (I-D §7.8).
    ///
    /// This is the I-D's `unverifiable` outcome, not `invalid`: "the artifact has not been
    /// shown defective, and a verifier reporting `invalid` here would contradict a
    /// better-resourced verifier's `verified` over the same bytes, which Section 7.7 forbids."
    ///
    /// Both members are carried because §7.8 requires both to be reported: "A verifier MUST
    /// report WHICH budget was exhausted and the value that was in force, since `unverifiable`
    /// without that is not actionable — the holder of the receipt cannot otherwise tell whether
    /// the remedy is a larger budget or a smaller receipt."
    #[error(
        "verifier-local budget `{budget}` is exhausted; the value in force for this run is \
         {in_force} (I-D §7.8: unverifiable, never invalid)"
    )]
    BudgetExhausted {
        /// Which budget ran out, named as the verifier configures it.
        budget: &'static str,
        /// The value that was in force for this run.
        in_force: u64,
    },

    /// `subject.statement_id` or `subject.entry_id` disagrees with `envelope` (§5 step 1).
    #[error("`subject.{field}` does not match the carried envelope")]
    IdentifierMismatch {
        /// `statement_id` or `entry_id`.
        field: &'static str,
    },

    /// The pinned profile id is not one local policy holds a document for at all (§5 step 2).
    ///
    /// I-D §7.5 step 2 distinguishes this — a capability gap, `unverifiable` — from
    /// [`Self::AdaptorHashMismatch`], where the profile IS held but its recomputed digest
    /// disagrees with what the receipt pins — a stronger, `invalid` claim: the receipt names a
    /// document policy can prove is not the one it trusts, not merely one it has never heard
    /// of.
    #[error("adaptor profile `{id}` is not locally possessed")]
    AdaptorUnknown {
        /// The profile id the receipt pins.
        id: String,
    },

    /// The pinned profile id IS locally held, but `anchoring.adaptor.hash` does not equal the
    /// SHA-256 digest recomputed over the document actually held for it (I-D §3.2, §7.5 step
    /// 2: "MUST recompute the digest over the artifact rather than trusting any value carried
    /// with it, and MUST reject a receipt whose pinned digest does not match the artifact
    /// held").
    ///
    /// Distinct from [`Self::AdaptorUnknown`] — see its own doc comment for why the I-D treats
    /// the two differently.
    #[error(
        "adaptor profile `{id}` is held, but its recomputed digest does not match the hash \
         `anchoring.adaptor` pins"
    )]
    AdaptorHashMismatch {
        /// The profile id the receipt pins.
        id: String,
    },

    /// `anchoring.adaptor` names a different profile than the active manifest's own
    /// `log.adaptor` pins for the checkpoint being verified (I-D §3.2: "the profile id and
    /// hash are pinned in the manifest and carried in every Evidence Receipt" — the two
    /// carriers of the SAME fact, which MUST agree).
    ///
    /// Checked BEFORE any profile-specific parsing or signature rule: a receipt naming one
    /// profile in `anchoring.adaptor` while its governance chain pins another must never reach
    /// that OTHER profile's capabilities merely because local policy happens to recognize it.
    #[error(
        "`anchoring.adaptor` names `{carried}`, but the manifest active for this checkpoint \
         pins `{pinned}` (I-D §3.2)"
    )]
    AdaptorBindingInvalid {
        /// What the active manifest's `log.adaptor` pins, as `id (hash)`.
        pinned: String,
        /// What `anchoring.adaptor` carries, as `id (hash)`.
        carried: String,
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

    /// Locally configured policy claims a capability this build has no implementation for
    /// (I-D §7.1, §7.5 step 2: "WHERE `raw` is carried it MUST parse to the same values as the
    /// JSON members" — a claim this build cannot make good on for an unimplemented wire form).
    ///
    /// This is distinct from [`Self::AdaptorCapabilityUnsupported`], which names a per-receipt
    /// limitation the RECEIPT ran into. This one names a limitation of the POLICY itself,
    /// caught once, before any receipt content is even read: a `TrustPolicy` asserting
    /// `checkpoint_raw: true` for a profile this build has no parser for is a configuration
    /// error, never silently downgraded to "accept `raw` unparsed" or "treat it as false".
    #[error("adaptor profile `{id}` policy claims {capability}, which this build cannot parse")]
    AdaptorProfileMisconfigured {
        /// The pinned profile id.
        id: String,
        /// The capability the policy claims.
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

    /// A `keys.witness[]` entry sourced `local-policy` is not in the verifier's own trusted
    /// witness set (I-D §7.1: admissible only "for witness keys the verifier already trusts").
    ///
    /// Distinct from [`Self::KeyNotBound`], which names a key that failed to bind to a
    /// manifest key object: this key claims no manifest binding at all, and the set it must
    /// appear in is local configuration rather than carried material.
    #[error(
        "witness key `{key_id}` is sourced `local-policy`, but neither it nor its public key \
         is in the verifier's trusted witness set (I-D §7.1)"
    )]
    WitnessKeyNotTrusted {
        /// The offending key id.
        key_id: String,
    },

    /// A cosignature names a witness identity the manifest version active for the checkpoint
    /// does not declare (I-D §7.1: each `anchoring.witnesses[]` element carries "the witness
    /// identity as declared in the manifest").
    ///
    /// Applies whatever the key's source. A `local-policy` key establishes what the verifier
    /// trusts, never what the corpus's governance declared, so an identity absent from the
    /// active manifest is outside the witness set the receipt's own governance defines.
    #[error(
        "cosignature names witness `{witness_id}`, which the manifest version active for the \
         checkpoint of tree_size {tree_size} does not declare (I-D §7.1)"
    )]
    WitnessNotDeclared {
        /// The identity the cosignature carried.
        witness_id: String,
        /// The tree size of the checkpoint being cosigned.
        tree_size: u64,
    },

    /// A cosignature names a `witness_id` other than the identity the manifest declares for
    /// the key it is verified under (I-D §7.1: a witness key object "carries `witness_id`, the
    /// identity under which the manifest declares that witness").
    ///
    /// The identity is part of the cosignature preimage, so this is not a cosmetic label: an
    /// unauthorized party that could name an identity of its own choosing under a key the
    /// manifest declares would cosign bytes no declared witness ever agreed to.
    #[error(
        "cosignature under witness key `{key_id}` names `{carried}`, but the manifest declares \
         that key under `{declared}` (I-D §7.1)"
    )]
    WitnessIdentityMismatch {
        /// The witness key the cosignature names.
        key_id: String,
        /// The identity the manifest declares for that key.
        declared: String,
        /// The identity the cosignature carried.
        carried: String,
    },

    /// AT L3, a checkpoint carries no verifying witness cosignature at all (I-D §3.3, §7.5:
    /// "At L3 a verifier accepts a checkpoint C only with a valid witness cosignature").
    ///
    /// Distinct from [`Self::WitnessCosignatureInvalid`], which names a cosignature that WAS
    /// carried and failed to verify: this is what fires when none verified — zero carried, or
    /// every carried entry failed — under a manifest version that requires one.
    #[error(
        "AT L3, a checkpoint of tree_size {tree_size} carries no verifying witness \
         cosignature under the manifest version active for it"
    )]
    CheckpointUnwitnessed {
        /// The unwitnessed checkpoint's tree size.
        tree_size: u64,
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

    /// Under `declared` governance, an envelope names a producer key the presented material
    /// does not account for (I-D §7.4, "Declared mode and producer-key transitions").
    ///
    /// This is the I-D's `unverifiable` outcome, not `invalid`, and the distinction is
    /// normative: "Such a receipt is `unverifiable` (Section 7.7), for want of material the
    /// mode does not carry. It is NOT `invalid`: the omitted transition is not material this
    /// mode required the receipt to carry, and a verifier holding the enumerated material
    /// would verify the same bytes, so `invalid` would put two verifiers in contradiction over
    /// one artifact. A verifier MUST NOT silently treat the named key as active, and MUST NOT
    /// silently treat the envelope as invalid." Refusing under a variant of its own is how this
    /// crate does neither.
    ///
    /// It arises only under `declared` governance. Producer-key transitions are `key`
    /// statements and reach a verifier through enumeration material alone (§7.4), so declared
    /// mode never sees them; under `enumerated` the range proof over exactly
    /// `[0, tree_size(C))` forecloses omission (§7.5.1 4c), the presented key state IS the
    /// state that was in force, and an unresolvable `key_id` there is a defect —
    /// [`Self::EnvelopeSignatureInvalid`], `invalid`.
    ///
    /// The condition this variant reports is broader than §7.4's own sentence, which describes
    /// a key some `key` statement added or retired. Declared mode cannot tell that key from
    /// one no statement ever mentioned — telling them apart needs exactly the enumerated
    /// material the mode does not carry — so any narrower rule would require a verifier to
    /// decide a question its evidence cannot reach. `unverifiable` is what both cases are.
    ///
    /// Distinct from [`Self::KeyNotBound`], which is about the receipt's own `keys` listing
    /// rather than about a signature: a `manifest-chain` binding naming an entry index that
    /// holds no matching key object is decidable from the presented chain alone, and is
    /// `invalid` in either mode.
    #[error(
        "the envelope at entry index {entry_index} is signed by producer key `{key_id}`, which \
         the presented declared-mode governance material does not carry a transition for \
         (I-D §7.4: unverifiable, not invalid)"
    )]
    ProducerKeyNotCarried {
        /// The entry index of the envelope whose signer could not be resolved.
        entry_index: u64,
        /// The `key_id` the envelope names.
        key_id: String,
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

    /// The receipt asserts a `keyed-authorized` content binding over a dataset this verifier
    /// holds no key for (I-D §7.3, §7.7).
    ///
    /// This is the I-D's `unverifiable` outcome, not `invalid`. §7.7 lists "a dataset key it is
    /// not authorized to hold" among the capability gaps, and §7.3 states the consequence for
    /// this member directly: a `keyed-authorized` binding "whose evidence is present and well
    /// formed but for which the verifier holds no dataset key... MUST NOT be rendered as though
    /// it had been established. Both are capability gaps rather than defects: that content
    /// binding is `unverifiable` (Section 7.7), and the receipt is not thereby invalid."
    ///
    /// Distinct from [`Self::ContentBindingMismatch`], which reports carried bytes that DO
    /// recompute and do not match: that is a cryptographic failure over material in hand, and
    /// is `invalid` in every configuration.
    #[error(
        "dataset `{dataset}` is committed under a keyed mode and this verifier holds no key \
         for it; its content-binding finding is unverifiable, not invalid (I-D §7.3, §7.7)"
    )]
    DatasetKeyNotHeld {
        /// The dataset whose content-binding finding is affected.
        dataset: String,
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

impl ReceiptError {
    /// Which of I-D §7.7's three values this rejection produces.
    ///
    /// §7.7 resolves every rejection site in this document under one principle, and this match
    /// is that principle applied variant by variant, with no wildcard: a variant added later
    /// does not inherit a class by accident.
    ///
    /// *   "Material the receipt MUST carry and does not; a cryptographic check that fails; a
    ///     schema failure; a disagreement among carried fields (Section 7.6) — `invalid`. What
    ///     these share is that they are decidable from the receipt's own bytes, so every
    ///     verifier decides them alike, in every year."
    /// *   "A capability the verifier lacks, a local configuration it has not been given, or a
    ///     local budget it has set — `unverifiable`. What these share is that they are
    ///     properties of the verifier, not of the artifact."
    ///
    /// The division "is not stylistic. A verifier-local condition reported as `invalid` would
    /// let two verifiers make contradictory statements about one artifact."
    #[must_use]
    pub const fn class(&self) -> Outcome {
        match *self {
            // Properties of the verifier, never of the artifact — §7.7's second bullet.
            //
            // "an artifact declaring a revision earlier than the one this document defines
            // (Section 2.2)" (§7.7; §7.5 step 1).
            Self::UnsupportedVersion { .. }
            // §7.8: "Exhaustion of either budget yields `unverifiable`, never `invalid`: the
            // artifact has not been shown defective, and a verifier reporting `invalid` here
            // would contradict a better-resourced verifier's `verified` over the same bytes."
            | Self::BudgetExhausted { .. }
            // "an adaptor profile it does not possess" (§7.7); §7.5 step 2: "If the verifier
            // possesses NO profile under that id, it lacks a capability and the result is
            // `unverifiable`."
            | Self::AdaptorUnknown { .. }
            // A capability the pinned profile does not define, or one this build does not
            // implement for the profile the receipt names: either way the run is short of a
            // capability rather than holding a defect (§7.7 second bullet).
            //
            // AMBIGUITY (I-D §7.5 step 2): the section settles profile POSSESSION and profile
            // HASH, and says nothing about a profile that is possessed at the pinned hash and
            // defines no serialization for material the receipt carries. Read here as a
            // capability gap, the minimal reading: `unverifiable` asserts nothing about the
            // artifact, while `invalid` would assert a defect this verifier has not shown.
            | Self::AdaptorCapabilityUnsupported { .. }
            // "a local configuration it has not been given" (§7.7). A policy asserting a
            // capability this build cannot make good on is a property of the verifier.
            //
            // AMBIGUITY (I-D §7.7): a misconfigured verifier could also be read as the
            // non-completing run §7.7 scopes out. Read as `unverifiable` because the run does
            // complete and reaches a defined stopping point; see [`ExecutionError`].
            | Self::AdaptorProfileMisconfigured { .. }
            // Receipt format §1 rule 1: "its absence — no configured genesis anchor, no dataset
            // key, no adaptor profile — is `unverifiable` and never `invalid`; a configured
            // anchor DIFFERING from the carried one is also `unverifiable`... since the receipt
            // may be a perfectly valid receipt of another corpus."
            | Self::GenesisAnchorMismatch
            // A witness key the receipt sources from local policy that local policy does not
            // hold: the set it must appear in is the verifier's own configuration.
            | Self::WitnessKeyNotTrusted { .. }
            // §6.3, verifier-resolution table: an identifier whose procedure this verifier does
            // not implement makes "the content-binding FINDING for that dataset... unverifiable
            // (Section 7.7)... Nothing else in the receipt is affected, and the receipt is not
            // invalid evidence."
            | Self::CanonicalizationUnsupported { .. }
            // "a dataset key it is not authorized to hold" (§7.7); §7.3 for this member.
            | Self::DatasetKeyNotHeld { .. }
            // §7.4: "Such a receipt is `unverifiable` (Section 7.7), for want of material the
            // mode does not carry. It is NOT `invalid`."
            | Self::ProducerKeyNotCarried { .. } => Outcome::Unverifiable,

            // Decidable from the receipt's own bytes — §7.7's first bullet.
            //
            // "a malformed or non-JCS artifact" (§7.7); a schema failure.
            Self::Malformed(_)
            // §7.8: the fixed limits "are properties of the artifact, decided identically by
            // every verifier in every year, so a receipt exceeding either is `invalid`."
            | Self::LimitExceeded(_)
            // A disagreement among carried fields (§7.6, §7.5 step 1).
            | Self::IdentifierMismatch { .. }
            // §7.5 step 2: "If it possesses a profile under that id whose HASH DIFFERS from the
            // receipt's, the receipt and the profile it names disagree, which is decidable from
            // the bytes in hand, and the result is `invalid`."
            | Self::AdaptorHashMismatch { .. }
            // Two carriers of one pinned fact disagreeing (§3.2) — decidable from the bytes.
            | Self::AdaptorBindingInvalid { .. }
            // Material the claim type requires, absent or not the material it must be (§7.2).
            | Self::CheckpointNotBound { .. }
            | Self::GovernanceRangeNotComplete { .. }
            | Self::CompetingRangeInsufficient { .. }
            | Self::ClaimMaterialMissing { .. }
            | Self::GovernanceSubjectNotManifest { .. }
            | Self::GovernanceStateNotCurrent { .. }
            | Self::TriggerNotAuthorized { .. }
            // Cryptographic checks that fail.
            | Self::CheckpointSignatureInvalid
            | Self::WitnessCosignatureInvalid { .. }
            | Self::CheckpointUnwitnessed { .. }
            | Self::InclusionPathInvalid { .. }
            | Self::ConsistencyPathInvalid
            | Self::ClaimMaterialPathInvalid { .. }
            | Self::RangeProofInvalid { .. }
            | Self::TreeMaterialInvalid { .. }
            | Self::ClosureMismatch(_)
            | Self::EnvelopeSignatureInvalid { .. }
            // §7.5 step 5: "A recomputed commitment differing from the one the subject statement
            // names is a cryptographic failure and the result is `invalid`."
            | Self::ContentBindingMismatch { .. }
            // §6.3: the procedure IS implemented and the carried bytes fail it.
            | Self::CanonicalizationFailed { .. }
            // §6.3: "a verifier that implements the procedure and finds presence wrong reports
            // that dataset's content-binding finding `invalid`."
            | Self::MediaTypePresenceInvalid { .. }
            // §6.3: "A mismatch in either member makes the receipt `invalid`; it is never
            // downgraded."
            | Self::ClaimDescriptorMismatch { .. }
            // Schema and structural failures over carried governance material.
            | Self::EntryIndexBeyondCheckpoint { .. }
            | Self::KeyNotBound { .. }
            | Self::WitnessNotDeclared { .. }
            | Self::WitnessIdentityMismatch { .. }
            | Self::GovernanceChainInvalid(_)
            | Self::ManifestSchemaInvalid { .. }
            // §7.7 names this one expressly: "A missing `governance.rotation_proofs[]` element
            // for a governance-key rotation the carried chain contains... falls squarely in the
            // first of those: the receipt was required to carry it, and its absence is not a
            // capability the verifier lacks."
            | Self::RotationProofInvalid { .. }
            // Disagreements among carried fields (§7.6).
            | Self::AssuranceMismatch { .. }
            | Self::RecordSubjectMismatch { .. }
            | Self::SubjectManifestPresence { .. }
            | Self::SubjectManifestBindingInvalid(_)
            | Self::EmbeddedOrderingViolation { .. }
            | Self::EmbeddedSubjectMismatch { .. }
            | Self::EmbeddedClaimTypeMismatch { .. }
            // A combination the container format leaves no material to evidence: a disagreement
            // between two members of the receipt, decided identically by every verifier.
            //
            // AMBIGUITY (I-D §7.7): the section does not name this case. Read as `invalid`
            // because nothing about the verifier decides it — the same bytes are refused by
            // every verifier in every year, which is §7.7's own test for the first bullet.
            | Self::FormatConflict { .. }
            // A decoding or field failure over the receipt's own bytes.
            | Self::Ahl(_) => Outcome::Invalid,
        }
    }

    /// Which required assertion (I-D §7.7) this rejection belongs to.
    ///
    /// Exhaustive and without a wildcard, for the same reason [`Self::class`] is: every check
    /// this crate performs maps to exactly one assertion, and a variant added later must be
    /// placed deliberately rather than inherit a home.
    #[must_use]
    pub fn assertion(&self) -> Assertion {
        match *self {
            Self::UnsupportedVersion { .. } => Assertion::Versions,
            Self::LimitExceeded(_) | Self::BudgetExhausted { .. } => Assertion::ResourceLimits,
            Self::Malformed(_) | Self::IdentifierMismatch { .. } | Self::Ahl(_) => {
                Assertion::Structure
            }
            Self::AdaptorUnknown { .. }
            | Self::AdaptorHashMismatch { .. }
            | Self::AdaptorBindingInvalid { .. }
            | Self::AdaptorCapabilityUnsupported { .. }
            | Self::AdaptorProfileMisconfigured { .. } => Assertion::AdaptorProfile,
            Self::EntryIndexBeyondCheckpoint { .. }
            | Self::InclusionPathInvalid { .. }
            | Self::ConsistencyPathInvalid => Assertion::Anchoring,
            Self::GenesisAnchorMismatch
            | Self::GovernanceChainInvalid(_)
            | Self::ManifestSchemaInvalid { .. }
            | Self::RotationProofInvalid { .. }
            | Self::GovernanceRangeNotComplete { .. }
            | Self::KeyNotBound { .. } => Assertion::Governance,
            Self::CheckpointSignatureInvalid
            | Self::WitnessCosignatureInvalid { .. }
            | Self::WitnessKeyNotTrusted { .. }
            | Self::WitnessNotDeclared { .. }
            | Self::WitnessIdentityMismatch { .. }
            | Self::CheckpointUnwitnessed { .. } => Assertion::CheckpointAuthentication,
            Self::EnvelopeSignatureInvalid { .. } | Self::ProducerKeyNotCarried { .. } => {
                Assertion::EnvelopeValidity
            }
            Self::AssuranceMismatch { .. }
            | Self::RecordSubjectMismatch { .. }
            | Self::SubjectManifestPresence { .. }
            | Self::SubjectManifestBindingInvalid(_)
            | Self::EmbeddedOrderingViolation { .. }
            | Self::EmbeddedSubjectMismatch { .. }
            | Self::FormatConflict { .. } => Assertion::CrossField,
            // The one variant whose home depends on its own payload: the same range-proof
            // recomputation authenticates governance currency (§7.5.1 4c) and competing-trigger
            // and completeness material (§7.2), and the two are different assertions.
            Self::RangeProofInvalid { what, .. } => {
                if what == "governance" {
                    Assertion::Governance
                } else {
                    Assertion::ClaimMaterial
                }
            }
            Self::CheckpointNotBound { .. }
            | Self::CompetingRangeInsufficient { .. }
            | Self::GovernanceSubjectNotManifest { .. }
            | Self::GovernanceStateNotCurrent { .. }
            | Self::TriggerNotAuthorized { .. }
            | Self::EmbeddedClaimTypeMismatch { .. }
            | Self::ClaimMaterialMissing { .. }
            | Self::ClaimMaterialPathInvalid { .. }
            | Self::TreeMaterialInvalid { .. }
            | Self::ClosureMismatch(_) => Assertion::ClaimMaterial,
            Self::CanonicalizationUnsupported { .. }
            | Self::CanonicalizationFailed { .. }
            | Self::MediaTypePresenceInvalid { .. }
            | Self::ClaimDescriptorMismatch { .. }
            | Self::ContentBindingMismatch { .. }
            | Self::DatasetKeyNotHeld { .. } => Assertion::ContentBinding,
        }
    }
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

/// The literal `type` value of a carried statement, read without validating anything.
///
/// I-D §7.5.1 4b defines the induction over "the manifest statements of `governance.chain[]`,
/// merged in entry-index order with the `key` statements the enumeration material carries", so
/// something has to decide WHICH enumerated statements those are before any signature is
/// verified. That decision is a selection, not the "type-specific validation" 4b's phase 2
/// holds back: it reads one member and compares it to a literal, and it reaches no conclusion
/// about the statement. A payload with no `type`, or a non-string one, is simply not a
/// `manifest` and not a `key` — it takes the non-induction path, where 4d's signature runs
/// first and the missing member is then reported by [`common_payload_fields`] in phase 2,
/// which is the order 4b(K) fixes ("`type` is exactly `key`, and the common payload fields of
/// Section 2.2 are present and well formed" is phase-2 work).
fn statement_type_literal(envelope: &Value) -> Option<&str> {
    envelope.get("payload")?.get("type")?.as_str()
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

/// The seven statement types I-D §2.3 defines: five describe records, two govern the corpus.
const STATEMENT_TYPES: [&str; 7] =
    ["ingestion", "derivation", "retraction", "correction", "propagation", "manifest", "key"];

/// Validate I-D §2.2's common payload fields on a carried statement, before its type-specific
/// content or effect is trusted (§7.5.1 4b(K): "the common payload fields of Section 2.2 are
/// present and well formed" — stated for `key` statements, but §2.2 states the same fields for
/// EVERY statement type, manifest and the five record types included).
///
/// `ahl_version` carries its own distinct "unverifiable, not invalid" semantics and is checked
/// separately by [`check_ahl_version`]; this function does not repeat it. Used for the subject
/// envelope, every governance chain hop, and every enumerated envelope — one validator, so the
/// rule cannot drift between call sites.
fn common_payload_fields(payload: &Value) -> Result<()> {
    let invalid =
        |member: &str, detail: &str| ReceiptError::Malformed(format!("payload {member}: {detail}"));

    let kind = payload
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("type", "the member is REQUIRED (I-D §2.2)"))?;
    if !STATEMENT_TYPES.contains(&kind) {
        return Err(invalid("type", "not one of the seven defined statement types (I-D §2.3)"));
    }

    if !payload.get("producer").is_some_and(Value::is_string) {
        return Err(invalid("producer", "the member is REQUIRED and MUST be a string (I-D §2.2)"));
    }

    // I-D §2.2: "<manifest version id; absent only in manifest statements>"; §2.4.5: "the
    // `manifest` common field is absent" on a manifest statement's own payload.
    match (kind, payload.get("manifest")) {
        ("manifest", Some(_)) => {
            return Err(invalid(
                "manifest",
                "MUST be absent on a manifest statement (I-D §2.2, §2.4.5)",
            ))
        }
        ("manifest", None) => {}
        (_, Some(value)) if value.is_string() => {}
        (_, _) => {
            return Err(invalid(
                "manifest",
                "the member is REQUIRED, and MUST be a string, except on a manifest \
                 statement (I-D §2.2)",
            ))
        }
    }

    // `"<RFC 3339>" | {"from": "<RFC 3339>", "to": "<RFC 3339 or null>"}` — already implements
    // exactly this shape, open interval and all, for trigger scoping; reused here purely for
    // its shape validation.
    crate::bitemporal::ValidTime::from_payload(payload)
        .map_err(|source| invalid("valid_time", &source.to_string()))?;

    let issued_at = payload.get("issued_at").and_then(Value::as_str).ok_or_else(|| {
        invalid("issued_at", "the member is REQUIRED and MUST be a string (I-D §2.2)")
    })?;
    crate::bitemporal::parse_rfc3339("payload.issued_at", issued_at)
        .map_err(|source| invalid("issued_at", &source.to_string()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

/// The verification-work budget, under the name I-D §7.8 requires a verifier to report it by.
const WORK_BUDGET: &str = "verification work units";

/// The decoded-size budget, under the name I-D §7.8 requires a verifier to report it by.
const DECODED_SIZE_BUDGET: &str = "decoded size in bytes";

/// One verification run over one receipt tree: the §7.8 budgets it shares, and the §7.7
/// findings it produces.
///
/// Both live here because both are properties of the RUN rather than of any one receipt in the
/// tree: the budgets are spent across every embedded receipt, and the findings of an embedded
/// receipt are reported alongside the outer receipt's own (§7.7, "for each embedded receipt,
/// every required assertion of THAT receipt").
#[derive(Debug)]
struct Run {
    limits: Limits,
    work: u64,
    embedded: usize,
    /// Verdicts and findings of embedded receipts already verified, keyed by the **JCS digest
    /// of the whole embedded receipt object** (format §3.1). The entry id alone is unsound: two
    /// embedded receipts can share a subject statement while carrying different — independently
    /// forgeable — `claim_material`, and keying on the envelope would let the second reuse the
    /// first's verdict. Consulted before recursing, not merely recorded after.
    ///
    /// The findings are cached with the verdict so that a receipt served from the cache still
    /// reports its own assertions, at its own path, rather than disappearing from the report
    /// because an identical receipt was verified elsewhere in the tree.
    verified: BTreeMap<String, (Verdict, Vec<Finding>)>,
    /// One finding per required assertion the run has settled, in the order it settled them.
    findings: Vec<Finding>,
    /// Where the run currently is: the `claim_material` member names of the embedded receipts
    /// it has descended into, outermost first. Empty while the outermost receipt is being
    /// verified.
    ///
    /// Pushed before descending and popped only when the descent SUCCEEDS: a rejection inside
    /// an embedded receipt is recorded at that receipt's own path as the run unwinds, which is
    /// where a reader has to look for it.
    path: Vec<String>,
    /// The assertion of the receipt currently being verified whose `unverifiable` outcome the
    /// assertions after it rest on, if any (I-D §7.7; see [`Run::pass`]).
    ///
    /// Saved and restored around each embedded receipt, because the dependence is between the
    /// assertions of ONE receipt: an embedded receipt short of material says nothing about the
    /// assertions its parent settled before descending into it.
    blocked: Option<Assertion>,
    /// Rejections recorded as findings and not propagated ([`Run::tolerate`]), so that
    /// [`verify_receipt`] can still return the one that decided the result.
    deferred: Vec<Tolerated>,
}

/// One rejection [`Run::tolerate`] recorded and carried on from: the assertion and receipt path
/// it was recorded under, so that whether it enters the reduction can be decided again later,
/// and the rejection itself.
type Tolerated = (Assertion, Vec<String>, ReceiptError);

/// Whether a finding for `assertion` at `path` enters the reduction of the receipt the run is
/// over — the free-standing form of [`Finding::counts_toward_result`], for deciding it before a
/// [`Finding`] is in hand.
const fn counts_toward_result(assertion: Assertion, path: &[String]) -> bool {
    !matches!(assertion, Assertion::ContentBinding) || path.is_empty()
}

impl Run {
    const fn new(limits: Limits) -> Self {
        Self {
            limits,
            work: 0,
            embedded: 0,
            verified: BTreeMap::new(),
            findings: Vec::new(),
            path: Vec::new(),
            blocked: None,
            deferred: Vec::new(),
        }
    }

    /// Record the outcome of one assertion at the receipt currently being verified.
    ///
    /// One finding per assertion per receipt, and the DOMINATING outcome wins where the same
    /// assertion is settled more than once — a version read that passes for the subject and
    /// then fails for an enumerated statement is one `unverifiable` finding on `versions`, not
    /// two contradictory ones.
    fn record(&mut self, assertion: Assertion, outcome: Outcome, detail: Option<String>) {
        if let Some(existing) = self
            .findings
            .iter_mut()
            .find(|f| f.assertion == assertion && f.receipt_path == self.path)
        {
            if outcome > existing.outcome {
                existing.outcome = outcome;
                existing.detail = detail;
            }
            return;
        }
        self.findings.push(Finding { assertion, outcome, receipt_path: self.path.clone(), detail });
    }

    /// Record one required assertion the algorithm has just settled.
    ///
    /// I-D §7.7 makes a finding rest on the assertions it needs: where an earlier assertion of
    /// THIS receipt was `unverifiable` and the run carried on, an assertion settled after it
    /// rests on material the run never established, and is itself `unverifiable` naming that
    /// prerequisite. Assertions settled BEFORE the prerequisite keep the outcome they reached —
    /// which is what §7.7's own example requires: a receipt whose content binding is
    /// `unverifiable` still reports its anchoring and introduction findings as `verified`.
    fn pass(&mut self, assertion: Assertion) {
        match self.blocked {
            Some(prerequisite) if prerequisite < assertion => self.record(
                assertion,
                Outcome::Unverifiable,
                Some(format!("rests on `{prerequisite}`, which is unverifiable (I-D §7.7)")),
            ),
            _ => self.record(assertion, Outcome::Verified, None),
        }
    }

    /// Record a rejection as a finding and carry on, where the assertions the run has left do
    /// not depend on it.
    ///
    /// I-D §7.7's reduction is over ALL required findings, so a capability gap must not end the
    /// run: `invalid` dominates `unverifiable`, and a run that stopped at the first gap could
    /// never reach the defect that dominates it. Only an `unverifiable` outcome is tolerated
    /// here — an `invalid` one has already decided the result, and the run ends.
    fn tolerate<T>(&mut self, result: Result<T>) -> Result<Option<T>> {
        let error = match result {
            Ok(value) => return Ok(Some(value)),
            Err(error) => error,
        };
        if error.class() != Outcome::Unverifiable {
            return Err(error);
        }
        // Two `unverifiable` conditions end the run even so, and both are ordering rules rather
        // than reductions. I-D §7.5 step 1 puts the version read before every other check and
        // gives an unsupported one "no further processing"; §7.8 requires a verifier to "fail
        // closed — never degrading to a partial check — when either [budget] is exhausted", and
        // continuing on a spent budget is exactly a partial check. Neither can hide an
        // `invalid`: an `invalid` finding ends the run where it is reached, so none can have
        // been recorded before this point and none can be reached after it.
        if matches!(
            error,
            ReceiptError::UnsupportedVersion { .. } | ReceiptError::BudgetExhausted { .. }
        ) {
            return Err(error);
        }
        let settled = error.assertion();
        self.record(settled, Outcome::Unverifiable, Some(error.to_string()));
        self.deferred.push((settled, self.path.clone(), error));
        // A content binding is a leaf: I-D §7.2 rests no other assertion on it, and §7.7's own
        // example has the assertions around it reported `verified`. Every other assertion the
        // algorithm settles later does rest on the material this one was short of.
        if !matches!(settled, Assertion::ContentBinding) {
            self.blocked = Some(settled);
        }
        Ok(None)
    }

    /// Turn the run into the report I-D §7.7 requires: the findings, and the scalar result
    /// they reduce to.
    ///
    /// A rejection that ended the run is recorded here, at the path the run stopped at, so the
    /// report names the assertion that produced the result. What happens to the assertions the
    /// run never reached depends on which value stopped it:
    ///
    /// *   `invalid` — the result is decided, and the remaining assertions are simply not
    ///     reported. Reporting them would mean asserting outcomes for checks that never ran.
    /// *   `unverifiable` — every remaining required assertion of the outermost receipt rests
    ///     on material the run was short of, so each is reported `unverifiable` naming that
    ///     prerequisite. Embedded receipts the run never descended into are not enumerated:
    ///     which receipts a claim embeds is itself read from claim material.
    fn into_report(mut self, outcome: Result<Verdict>, receipt: &Value) -> Report {
        let verdict = match outcome {
            Ok(verdict) => Some(verdict),
            Err(error) => {
                let stopped_at = error.assertion();
                let class = error.class();
                self.record(stopped_at, class, Some(error.to_string()));
                if class == Outcome::Unverifiable {
                    self.fill_unreached(receipt, stopped_at);
                }
                None
            }
        };
        // Report order is the reader's order, not the run's: the outermost receipt's own
        // assertions first, in the order §7.5 settles them, then each embedded receipt's under
        // its path. The run produces them innermost-first, because an embedded receipt is
        // verified inside the outer receipt's claim-material step.
        self.findings.sort_by(|a, b| {
            a.receipt_path.cmp(&b.receipt_path).then_with(|| a.assertion.cmp(&b.assertion))
        });
        let result = reduce(&self.findings);
        Report {
            result,
            findings: self.findings,
            // I-D §7.7: only `verified` may be rendered in words that assert the property, so
            // no boundary is carried for the other two values.
            verdict: if result == Outcome::Verified { verdict } else { None },
        }
    }

    /// Report every required assertion of the outermost receipt the run did not settle as
    /// resting on the one that stopped it.
    fn fill_unreached(&mut self, receipt: &Value, stopped_at: Assertion) {
        // I-D §7.7: the content binding is a required assertion "if and only if its own
        // `assurance.content_binding` is not `none`". Read from the receipt's own bytes, since
        // the run may have stopped before the assurance block was parsed at all.
        let binds_content = receipt
            .get("claim")
            .and_then(|claim| claim.get("assurance"))
            .and_then(|assurance| assurance.get("content_binding"))
            .and_then(Value::as_str)
            .is_some_and(|binding| binding != "none");
        self.path.clear();
        for assertion in Assertion::ORDER {
            if matches!(assertion, Assertion::ContentBinding) && !binds_content {
                continue;
            }
            if self.findings.iter().any(|f| f.assertion == assertion && f.receipt_path.is_empty()) {
                continue;
            }
            self.record(
                assertion,
                Outcome::Unverifiable,
                Some(format!("rests on `{stopped_at}`, which is unverifiable (I-D §7.7)")),
            );
        }
    }

    /// The tolerated rejection that decided the result, for the callers that report one error
    /// rather than a report.
    ///
    /// `invalid` first and `unverifiable` after it, which is the reduction's own order, and
    /// only among findings that enter the reduction: an embedded receipt's content binding
    /// never does (I-D §7.7).
    fn dominating_deferred(self) -> Option<ReceiptError> {
        let mut unverifiable = None;
        for (assertion, path, error) in self.deferred {
            if !counts_toward_result(assertion, &path) {
                continue;
            }
            if error.class() == Outcome::Invalid {
                return Some(error);
            }
            if unverifiable.is_none() {
                unverifiable = Some(error);
            }
        }
        unverifiable
    }

    const fn spend(&mut self, units: u64) -> Result<()> {
        self.work = self.work.saturating_add(units);
        if self.work > self.limits.max_work_units {
            return Err(ReceiptError::BudgetExhausted {
                budget: WORK_BUDGET,
                in_force: self.limits.max_work_units,
            });
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

/// The reduction of I-D §7.7: "`invalid` if any required finding is `invalid`; otherwise
/// `unverifiable` if any required finding is `unverifiable`; otherwise `verified`."
///
/// That is the maximum under [`Outcome`]'s own ordering, over the findings that ENTER the
/// reduction: I-D §7.7 excludes an embedded receipt's content binding from the required
/// assertions of the receipt that embeds it, and nothing else.
fn reduce(findings: &[Finding]) -> Outcome {
    findings
        .iter()
        .filter(|finding| finding.counts_toward_result())
        .map(|finding| finding.outcome)
        .max()
        .unwrap_or(Outcome::Verified)
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
    /// `governance.currency.mode` — one of I-D §7.4's two tokens, already held to that domain
    /// by the caller.
    ///
    /// Carried here because it decides what an unresolvable producer key MEANS: under
    /// `enumerated` the state is the state that was in force (§7.5.1 4c) and an unresolvable
    /// key is a defect, while under `declared` the state is only what the chain implies and
    /// §7.4 makes the same condition `unverifiable`. See [`envelope_outcome`].
    mode: &'a str,
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
    // Every manifest in `manifests` passed [`producer_key_objects`] during `read_chain`'s
    // induction before it was ever pushed there, so this cannot fail; were it ever to, the
    // effect is a key absent from the derived set, which fails closed as `KeyNotBound`.
    for (key_id, pubkey) in producer_key_objects(manifest).unwrap_or_default() {
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

/// Accept a `base64:` family string under I-D §2.1's strict rule: the prefix, the standard
/// alphabet, canonical padding, and no non-zero trailing bits.
///
/// The decoder this crate uses everywhere ([`crate::B64`]) already enforces all three of the
/// encoding conditions — it rejects a wrong-length pad and refuses trailing bits rather than
/// discarding them — so validating a family string is deciding the prefix and then asking it
/// to decode. What this adds over decoding AT THE POINT OF USE is that it can be applied to
/// every carried byte field, including the ones verification never selects (I-D §7.1: "Each is
/// a `base64:` family string… A family string failing those checks is a schema failure and the
/// result is `invalid`").
fn is_family_base64(value: &str) -> bool {
    value.strip_prefix("base64:").is_some_and(|body| B64.decode(body).is_ok())
}

/// Reject any member outside the set I-D §7.1's container fixes for an object.
///
/// "The member shapes shown above are normative", and the container marks its own extension
/// points: an elided body (`{ ... }`) or a trailing `...` says the members are defined
/// elsewhere or by an outside format, and every other object is drawn complete. This closes
/// the complete ones. What it buys is not tidiness: a member no rule compares can be read by
/// a human, or by a second implementation, as though something had checked it — and the one
/// that matters most is the member an object's own MATCH rule deliberately leaves out, such as
/// a receipt-side key entry asserting `valid_from_index` where §7.1 says the match compares
/// only shared members.
///
/// `allowed` lists every member the shape names, REQUIRED or optional alike; presence rules
/// are the callers' own and are checked where they belong.
fn check_closed_members(value: &Value, what: &str, allowed: &[&str]) -> Result<()> {
    let members = value
        .as_object()
        .ok_or_else(|| ReceiptError::Malformed(format!("`{what}` MUST be an object (I-D §7.1)")))?;
    if let Some(extra) = members.keys().find(|member| !allowed.contains(&member.as_str())) {
        return Err(ReceiptError::Malformed(format!(
            "`{what}` carries `{extra}`, which is not a member of that object: I-D §7.1 fixes \
             its shape as {allowed:?}"
        )));
    }
    Ok(())
}

/// Every element of a `sha256:` family-string array member, validated where the member is
/// present (I-D §7.1: inclusion and consistency paths are `sha256:` family-string arrays).
///
/// Absent members are left to the readers that require them; what this rules out is a path
/// carrying an element no verifier could interpret, on any element of any carried path,
/// including one an earlier failure would have short-circuited past.
fn check_family_hash_path(container: &Value, member: &str, what: &str) -> Result<()> {
    let Some(value) = container.get(member) else { return Ok(()) };
    let elements = value.as_array().ok_or_else(|| {
        ReceiptError::Malformed(format!("`{what}` MUST be an array of `sha256:` family strings"))
    })?;
    for (position, element) in elements.iter().enumerate() {
        if !element.as_str().is_some_and(is_family_hash) {
            return Err(ReceiptError::Malformed(format!(
                "`{what}[{position}]` is not a `sha256:` family string in lowercase hex \
                 (I-D §2.1, §7.1)"
            )));
        }
    }
    Ok(())
}

/// Recompute a producer `key_id` from its `pubkey`: I-D §6.2 — "`pubkey` decodes to exactly
/// the 32 octets of an Ed25519 public key; and `key_id` equals `sha256:` followed by the
/// lowercase hex SHA-256 of those octets, so it is recomputable rather than merely declared."
/// Shared by every place a PRODUCER key object's own id is trusted only once recomputed —
/// manifest producer key objects ([`producer_key_objects`]) and `key` statements' own key
/// object (I-D §7.5.1 4b(K)) alike; NOT for log or witness keys, whose id derivation is
/// adaptor-profile-defined rather than this fixed rule (I-D §2.4.6).
///
/// # Errors
///
/// Returns [`AhlError::BadLength`] (via [`decode_pubkey`]) if `pubkey` does not decode to
/// exactly 32 octets.
fn recompute_producer_key_id(pubkey: &str) -> Result<String> {
    Ok(sha256_hex(decode_pubkey(pubkey)?.as_bytes()))
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
    if !value.get("signature").and_then(Value::as_str).is_some_and(is_family_base64) {
        return Err(invalid(
            "signature",
            "REQUIRED, a `base64:` family string under the strict acceptance rule (I-D §2.1)",
        ));
    }
    // I-D §7.1 draws the receipt-borne checkpoint complete: the committed state of §1.5 plus
    // `key_id` and `signature`, and `raw` which it "MAY additionally carry". Being a SUPERSET
    // of §1.5's four members is what that sentence says; it is not licence for members beyond
    // the seven. The signing bytes are `JCS(cp)` minus `signature`, so an extra member would
    // also silently enter the preimage two implementations must agree on.
    check_closed_members(
        value,
        "checkpoint",
        &["log_id", "tree_size", "root_hash", "checkpoint_time", "key_id", "signature", "raw"],
    )?;
    Ok(value)
}

/// The corpus's own minimal test profile — the ONE profile this VERIFIER has a checkpoint
/// signing-bytes procedure for.
///
/// `ahl-adaptor-atl-v1` is deliberately NOT dispatched here even though
/// `ahl_core::checkpoint_signing_bytes_for`/`ahl_core::reconcile_atl_checkpoint_raw` implement
/// its checkpoint-blob mechanism and are unit-tested in `lib.rs`: that profile's leaf
/// construction (adaptor §4.2, `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)`) and
/// origin-derived `log_id` (§7.1, the SHA-256 of a 16-byte Data Tree UUID) are not yet
/// profile-dispatched anywhere ELSE in this crate — inclusion proofs and entry ids still use
/// the one generic form every corpus here shares — so a checkpoint whose SIGNATURE verified
/// correctly would still rest on entries hashed the wrong way. And adaptor §14: "Until this
/// document is released as an immutable, openly published artifact… no manifest may pin it."
/// A receipt naming `ahl-adaptor-atl-v1` is therefore refused as
/// [`ReceiptError::AdaptorCapabilityUnsupported`] — a profile-limitation outcome, never
/// `invalid` — regardless of what local policy holds for it.
const TEST_ADAPTOR_PROFILE_ID: &str = "ahl-test-log-v1";

/// The bytes a checkpoint's own log signature is verified over.
///
/// Narrower than the crate-level, profile-string-dispatched
/// `ahl_core::checkpoint_signing_bytes_for`: this verifier only ever trusts the ONE profile
/// procedure it actually stands behind ([`TEST_ADAPTOR_PROFILE_ID`]'s own, I-D §3.2). Any other
/// profile id — `ahl-adaptor-atl-v1` included — is the profile-limitation outcome rather than
/// a silent fallback to a form this crate cannot yet vouch for end to end (see
/// [`TEST_ADAPTOR_PROFILE_ID`]'s own doc comment).
fn checkpoint_signing_bytes_for(checkpoint: &Value, profile_id: &str) -> Result<Vec<u8>> {
    check_profile_supported(profile_id)?;
    Ok(crate::checkpoint_signing_bytes(checkpoint)?)
}

/// Refuse a profile id this verifier has no checkpoint procedure for, at the point I-D §7.5
/// step 2 resolves the profile — after the recomputed-hash comparison and before any carried
/// material is verified.
///
/// The refusal is a capability outcome about the receipt's own pinned profile, so it is
/// decidable from the id alone and nothing in the receipt can change it. Deciding it here,
/// rather than where the signing bytes are first needed, is what keeps an unsupported-profile
/// receipt from being walked through the governance induction — verifying signatures, resolving
/// keys, checking manifest schemas — on its way to a refusal that was certain from step 2.
/// Ordering that work ahead of a decided refusal would let material this verifier has already
/// declined to interpret drive it.
fn check_profile_supported(profile_id: &str) -> Result<()> {
    if profile_id == TEST_ADAPTOR_PROFILE_ID {
        return Ok(());
    }
    Err(ReceiptError::AdaptorCapabilityUnsupported {
        id: profile_id.to_owned(),
        capability: "a checkpoint signing-bytes procedure",
    })
}

/// Reject a receipt-borne checkpoint's optional `raw` framing (I-D §7.1, §7.5 step 2: "WHERE
/// `raw` is carried it MUST parse to the same values as the JSON members").
///
/// This build wires NO profile's `raw` parser into the verifier — `ahl-test-log-v1` defines no
/// binary framing at all (its own §5), and `ahl-adaptor-atl-v1`'s is deliberately not reachable
/// here either (see [`TEST_ADAPTOR_PROFILE_ID`]'s doc comment: leaf/origin construction for
/// that profile is not yet dispatched anywhere in this crate, and the profile document is not
/// yet released, adaptor §14). So `raw`'s mere presence is always the profile-limitation
/// outcome, unconditionally — `verify_nested`'s policy-level check already refuses a policy
/// that claims `checkpoint_raw: true` for ANY profile before a receipt is even read, so
/// `profile`/`profile_id` are accepted here only to name the profile in the error, never to
/// branch on what the policy claims.
fn reconcile_checkpoint_raw(checkpoint: &Value, profile_id: &str) -> Result<()> {
    if checkpoint.get("raw").is_some() {
        return Err(ReceiptError::AdaptorCapabilityUnsupported {
            id: profile_id.to_owned(),
            capability: "a binary checkpoint framing for `checkpoint.raw`",
        });
    }
    Ok(())
}

/// Reconcile the `raw` form of every checkpoint the `anchoring` block carries (I-D §7.5
/// step 2: "Where a raw checkpoint form is carried (`anchoring.checkpoint.raw`, Section 7.1),
/// verify that it parses to the same values as the JSON members; a mismatch is `invalid`").
///
/// The check is profile-dependent — what `raw` even means is the adaptor's own framing — but
/// it is key-independent, and §7.5 places it in step 2 alongside profile resolution rather
/// than in the authenticated validation of 4f. Presence is read here without requiring the
/// checkpoint object to be otherwise well formed: its shape is step 3's business, and reading
/// one member for presence prejudges none of it.
fn reconcile_anchoring_raw(anchoring: &Value, profile_id: &str) -> Result<()> {
    for member in ["checkpoint", "later_checkpoint"] {
        if let Some(checkpoint) = anchoring.get(member) {
            reconcile_checkpoint_raw(checkpoint, profile_id)?;
        }
    }
    Ok(())
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
    if !value.get("cosignature").and_then(Value::as_str).is_some_and(is_family_base64) {
        return Err(invalid(
            "cosignature",
            "REQUIRED, a `base64:` family string under the strict acceptance rule (I-D §2.1)",
        ));
    }
    let cosigned_at = value
        .get("cosigned_at")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("cosigned_at", "REQUIRED"))?;
    crate::bitemporal::parse_rfc3339("cosigned_at", cosigned_at)
        .map_err(|source| invalid("cosigned_at", &source.to_string()))?;
    check_closed_members(
        value,
        "witness cosignature",
        &["witness_id", "key_id", "cosignature", "cosigned_at"],
    )?;
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

/// I-D §3.2: "the profile id and hash are pinned in the manifest and carried in every Evidence
/// Receipt" — `anchoring.adaptor` (already resolved into `profile_id`/`profile` by
/// `verify_nested`, since policy resolution requires an exact hash match) MUST equal the
/// active manifest's own `log.adaptor` for the checkpoint being verified.
///
/// Checked BEFORE any profile-specific parsing or signature rule, so a receipt cannot borrow a
/// policy-held profile's capabilities merely by NAMING it in `anchoring.adaptor` while the
/// governance chain it actually carries pins a different one.
///
/// `active_log` is the already schema-validated `log` object of the manifest active for this
/// checkpoint ([`log_object`]'s return), so `adaptor.id`/`adaptor.hash` are known present and
/// well typed.
fn check_adaptor_binding(
    active_log: &Value,
    profile_id: &str,
    profile: &AdaptorProfile,
) -> Result<()> {
    let adaptor = obj(active_log, "adaptor")?;
    let pinned_id = text(adaptor, "id")?;
    let pinned_hash = text(adaptor, "hash")?;
    if pinned_id != profile_id || pinned_hash != profile.hash() {
        return Err(ReceiptError::AdaptorBindingInvalid {
            pinned: format!("{pinned_id} ({pinned_hash})"),
            carried: format!("{profile_id} ({})", profile.hash()),
        });
    }
    Ok(())
}

/// Read manifest LOG or WITNESS key objects (`log.keys`, `witnesses[].keys`): the shared shape
/// `{key_id, pubkey, valid_from_index}` (I-D §6.2). `key_id` is a family string and
/// `valid_from_index` is an entry index, which is an unsigned integer: a negative or
/// fractional value is not an index into an append-only log.
///
/// NOT for PRODUCER key objects — those take a stricter, different shape with no
/// `valid_from_index` at all; see [`producer_key_objects`].
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
            // I-D §2.1's strict acceptance rule, on the manifest side of the same comparison
            // the receipt's `keys` entries are held to: a declared key object no verifier could
            // decode is a schema failure of the manifest, not a key that happens not to match.
            if !is_family_base64(pubkey) {
                return Err(invalid(
                    "pubkey",
                    "not a `base64:` family string under the strict acceptance rule (I-D §2.1)",
                ));
            }
            if object.get("valid_from_index").and_then(Value::as_u64).is_none() {
                return Err(invalid("valid_from_index", "not an entry index (spec §7.2, §7.3)"));
            }
            Ok((key_id.to_owned(), pubkey.to_owned()))
        })
        .collect()
}

/// Read manifest PRODUCER key objects (`payload.keys`): I-D §6.2 — "Each entry is a producer
/// key object `{key_id, pubkey}`. Both members are family strings... A producer key object
/// carrying any member beyond those two is a schema failure." Deliberately stricter than
/// [`key_objects`]: no `valid_from_index`, because the array itself IS the producer key state
/// at the manifest's entry index (I-D §6.2), not a set of per-key activation records.
fn producer_key_objects(container: &Value) -> Result<Vec<(String, String)>> {
    const ALLOWED: [&str; 2] = ["key_id", "pubkey"];
    array(container, "keys")?
        .iter()
        .enumerate()
        .map(|(index, object)| {
            let invalid = |member: &str, detail: &str| ReceiptError::ManifestSchemaInvalid {
                object: format!("keys[{index}].{member}"),
                detail: detail.to_owned(),
            };
            let map = object
                .as_object()
                .ok_or_else(|| invalid("", "a producer key object MUST be an object (I-D §6.2)"))?;
            if let Some(extra) = map.keys().find(|member| !ALLOWED.contains(&member.as_str())) {
                return Err(invalid(
                    extra,
                    "a producer key object carries `key_id` and `pubkey` ONLY — any other \
                     member, `valid_from_index` included, is a schema failure (I-D §6.2)",
                ));
            }
            let key_id = object
                .get("key_id")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("key_id", "the member is REQUIRED (I-D §6.2)"))?;
            if !is_family_hash(key_id) {
                return Err(invalid("key_id", "not a `sha256:` family string in lowercase hex"));
            }
            let pubkey = object
                .get("pubkey")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("pubkey", "the member is REQUIRED (I-D §6.2)"))?;
            // "`pubkey` decodes to exactly the 32 octets... `key_id` equals `sha256:` ...of
            // those octets, so it is recomputable rather than merely declared" (I-D §6.2).
            let recomputed = recompute_producer_key_id(pubkey).map_err(|_| {
                invalid("pubkey", "does not decode to exactly 32 octets (I-D §6.2)")
            })?;
            if recomputed != key_id {
                return Err(invalid("key_id", "does not equal `sha256:`-of-`pubkey` (I-D §6.2)"));
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

/// Validate I-D §6.2's remaining manifest-scope members — the ones §6.2 lists as part of what
/// the manifest "contains at minimum" beyond producer/log/witness keys and datasets, which are
/// checked elsewhere ([`producer_key_objects`], [`log_object`], [`datasets_object`]):
/// `pipelines`, `windows`, `retention`, and `level`.
///
/// `level` in particular gates the L3 cosignature requirement in [`verify_rotation_proof`]
/// (`rotating_manifest.get("level") == Some("L3")`); an absent or malformed `level` MUST fail
/// HERE, in schema, rather than be silently read by that later, unrelated `==` comparison as
/// simply "not L3" — this function running before that comparison is what makes the guarantee
/// hold, not any check inside the comparison itself.
fn manifest_scope_fields(manifest: &Value) -> Result<()> {
    let invalid = |object: &str, detail: &str| ReceiptError::ManifestSchemaInvalid {
        object: object.to_owned(),
        detail: detail.to_owned(),
    };

    // `windows.*` and `retention.*` are durations in name and by example ("PT24H", "P30D",
    // "P10Y"), but — unlike `log.checkpoint_cadence`/`log.witness_grace_period` — §6.2 gives
    // NO grammar for them at all, `P`-prefix included; §7.3's restricted grammar (and its
    // `Y`/date-part-`M` prohibition) is stated for those two log-timing fields specifically,
    // not for every duration a manifest carries. Inventing a `P`-prefix requirement §6.2 does
    // not state would reject values the I-D itself leaves unconstrained, so this checks only
    // presence and non-emptiness.
    let duration_shaped = |member: &str, value: &str| -> Result<()> {
        if value.is_empty() {
            Err(invalid(member, "MUST be a non-empty string (I-D §6.2)"))
        } else {
            Ok(())
        }
    };

    match manifest.get("level").and_then(Value::as_str) {
        Some("L1" | "L2" | "L3") => {}
        Some(_) => {
            return Err(invalid("level", "MUST be exactly `L1`, `L2`, or `L3` (I-D §6.1, §6.2)"))
        }
        None => return Err(invalid("level", "the member is REQUIRED (I-D §6.2)")),
    }

    let pipelines = manifest
        .get("pipelines")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("pipelines", "the object is REQUIRED (I-D §6.2)"))?;
    for member in ["include", "exclude"] {
        let list = pipelines.get(member).and_then(Value::as_array).ok_or_else(|| {
            invalid(
                &format!("pipelines.{member}"),
                "the member is REQUIRED and MUST be an array (I-D §6.2)",
            )
        })?;
        if !list.iter().all(Value::is_string) {
            return Err(invalid(
                &format!("pipelines.{member}"),
                "every element MUST be a string (I-D §6.2)",
            ));
        }
    }

    let windows = manifest
        .get("windows")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("windows", "the object is REQUIRED (I-D §6.2)"))?;
    for member in ["anchoring", "propagation"] {
        let value = windows.get(member).and_then(Value::as_str).ok_or_else(|| {
            invalid(
                &format!("windows.{member}"),
                "the member is REQUIRED and MUST be a string (I-D §6.2)",
            )
        })?;
        duration_shaped(&format!("windows.{member}"), value)?;
    }

    let retention = manifest
        .get("retention")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("retention", "the object is REQUIRED (I-D §6.2)"))?;
    let statements = retention.get("statements").and_then(Value::as_str).ok_or_else(|| {
        invalid("retention.statements", "the member is REQUIRED and MUST be a string (I-D §6.2)")
    })?;
    duration_shaped("retention.statements", statements)?;

    // "Retention: for statements, and for artifacts IF REPRODUCIBLE RECONSTRUCTION IS
    // CLAIMED" — the second retention duration is conditionally REQUIRED, exactly when
    // `properties.reproducible_reconstruction` claims true, not merely optional throughout.
    let reproducible = match manifest.get("properties") {
        None => false,
        Some(value) => {
            let properties = value.as_object().ok_or_else(|| {
                invalid("properties", "MUST be an object where present (I-D §6.2)")
            })?;
            match properties.get("reproducible_reconstruction") {
                None => false,
                Some(Value::Bool(claim)) => *claim,
                Some(_) => {
                    return Err(invalid(
                        "properties.reproducible_reconstruction",
                        "MUST be a boolean where present (I-D §6.2)",
                    ))
                }
            }
        }
    };
    match retention.get("artifacts") {
        Some(value) => {
            let duration = value.as_str().ok_or_else(|| {
                invalid("retention.artifacts", "MUST be a string where present (I-D §6.2)")
            })?;
            duration_shaped("retention.artifacts", duration)?;
        }
        None if reproducible => {
            return Err(invalid(
                "retention.artifacts",
                "the member is REQUIRED where `properties.reproducible_reconstruction` is \
                 true (I-D §6.2)",
            ))
        }
        None => {}
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

/// `(witness_id, key_id, pubkey, valid_from_index)` — one witness key object, normalized for
/// set comparison.
type WitnessKeySet = BTreeSet<(String, String, String, u64)>;

/// The SET of a manifest's witness key objects, normalized the same way, with `witness_id`
/// carried alongside each key object since it is part of the object's identity (I-D §7.1: "A
/// witness key object additionally carries `witness_id`, the identity under which the manifest
/// declares that witness").
///
/// Unlike [`log_key_set`] — always reachable only after the UNCONDITIONAL [`log_object`] check
/// — `witnesses` is conditionally required (I-D §6.2: mandatory only AT L3), so this rejects a
/// witness object missing `witness_id` or a malformed `keys` array rather than silently
/// dropping it: a governance-key-rotation comparison must never treat a schema-invalid witness
/// as simply absent from the set.
///
/// # Errors
///
/// Returns [`ReceiptError::ManifestSchemaInvalid`] if `witnesses`, where present, is not an
/// array, or if any entry's `witness_id` or `keys` shape is malformed.
fn witness_key_set(payload: &Value) -> Result<WitnessKeySet> {
    let Some(witnesses) = payload.get("witnesses") else {
        return Ok(BTreeSet::new());
    };
    let witnesses = witnesses.as_array().ok_or_else(|| ReceiptError::ManifestSchemaInvalid {
        object: "witnesses".to_owned(),
        detail: "MUST be an array where present (I-D §6.2)".to_owned(),
    })?;
    let mut set = BTreeSet::new();
    for (index, witness) in witnesses.iter().enumerate() {
        let witness_id = witness.get("witness_id").and_then(Value::as_str).ok_or_else(|| {
            ReceiptError::ManifestSchemaInvalid {
                object: format!("witnesses[{index}].witness_id"),
                detail: "the member is REQUIRED (I-D §7.1: \"A witness key object \
                         additionally carries `witness_id`\")"
                    .to_owned(),
            }
        })?;
        key_objects(witness)?;
        for object in array(witness, "keys")? {
            set.insert((
                witness_id.to_owned(),
                text(object, "key_id")?.to_owned(),
                text(object, "pubkey")?.to_owned(),
                number(object, "valid_from_index")?,
            ));
        }
    }
    Ok(set)
}

/// Validate the manifest `witnesses` member (I-D §6.2: "Witnesses: at L3, witness ids with key
/// objects in the same form"). AT L3 the array is REQUIRED and MUST be non-empty — a schema
/// failure otherwise; below L3 it remains OPTIONAL, present or not.
///
/// Every witness object present, at ANY level, MUST carry `witness_id` (I-D §7.1) and a
/// well-formed `keys` array (the shared log/witness shape, [`key_objects`]) — checked here,
/// once per manifest, the same convention [`log_object`] and [`datasets_object`] set, rather
/// than left to whichever comparison first happens to read a witness object.
///
/// Called only after [`manifest_scope_fields`] has already validated `level` is exactly one of
/// `L1`/`L2`/`L3`.
fn witnesses_object(manifest: &Value) -> Result<()> {
    let level = manifest.get("level").and_then(Value::as_str).unwrap_or_default();
    let witnesses = manifest.get("witnesses");
    if level == "L3" {
        let non_empty = witnesses.and_then(Value::as_array).is_some_and(|list| !list.is_empty());
        if !non_empty {
            return Err(ReceiptError::ManifestSchemaInvalid {
                object: "witnesses".to_owned(),
                detail: "AT L3, the array is REQUIRED and MUST be non-empty (I-D §6.2)".to_owned(),
            });
        }
    }
    // `witness_key_set` already validates shape (including `witness_id`) for every witness
    // present; called here too so a manifest whose ONLY defect is a malformed witness object
    // fails at schema time even where nothing ever compares it against a predecessor (a
    // genesis manifest, for instance, has none to compare against).
    witness_key_set(manifest)?;
    Ok(())
}

/// Require the receipt to LIST a rotation proof's cosigning witness key exactly as I-D §7.1's
/// transition exception describes it: a `manifest-chain` entry whose `binding` names the
/// PREDECESSOR manifest version, and whose `(witness_id, key_id, pubkey)` is that manifest's
/// own witness key object.
///
/// Deliberately not the generic binder. `local-policy` is admissible for the witness keys a
/// verifier already trusts, and such an entry carries no binding at all — so routing rotation
/// material through the generic path would let a trusted local-policy key presented under the
/// outgoing witness's identity and key id satisfy the rotation cosignature requirement, while
/// the outgoing manifest's own public key was never compared. The exception says which entries
/// attest a handover, and they are the retiring manifest's, from the chain, and no others.
///
/// The error names the binding index the entry actually carried where one exists, so a key
/// listed but bound to the INCOMING version is reported as the mis-binding it is rather than
/// as an absence.
fn require_listed_rotation_witness(
    receipt: &Value,
    outgoing_index: u64,
    witness_id: &str,
    key_id: &str,
    pubkey: &str,
) -> Result<()> {
    let mut attempted: Option<u64> = None;
    for entry in array(obj(receipt, "keys")?, "witness")? {
        if entry.get("witness_id").and_then(Value::as_str) != Some(witness_id)
            || entry.get("key_id").and_then(Value::as_str) != Some(key_id)
        {
            continue;
        }
        let binding = entry
            .get("binding")
            .and_then(|binding| binding.get("entry_index"))
            .and_then(Value::as_u64);
        if entry.get("source").and_then(Value::as_str) == Some("manifest-chain")
            && binding == Some(outgoing_index)
            && entry.get("pubkey").and_then(Value::as_str) == Some(pubkey)
        {
            return Ok(());
        }
        attempted = attempted.or(binding);
    }
    Err(ReceiptError::KeyNotBound {
        key_id: key_id.to_owned(),
        entry_index: attempted.unwrap_or(outgoing_index),
    })
}

/// The already-established context one `governance.rotation_proofs[]` element is validated
/// against, gathered so the element's own material can be told apart from it at a glance.
///
/// `manifests` is the induction's key state SO FAR — every manifest version established
/// strictly before the rotating one — and `outgoing` is the last of them: the state being
/// retired, which is what the proof must be signed and cosigned under, and the version the
/// receipt's own `keys` entries for this proof must bind to (I-D §7.1's transition exception).
#[derive(Clone, Copy)]
struct RotationContext<'a> {
    /// The receipt, for the `keys` block every key used in verification must appear in.
    receipt: &'a Value,
    /// Local policy, for the source rules a `keys` entry is bound under.
    policy: &'a TrustPolicy,
    /// The manifest versions established before the rotating one.
    manifests: &'a [(u64, &'a Value)],
    /// Entry index and payload of the OUTGOING manifest version.
    outgoing: (u64, &'a Value),
    /// The pinned adaptor profile, for the §3.2 binding check.
    profile: &'a AdaptorProfile,
    /// The pinned adaptor profile's id.
    profile_id: &'a str,
}

/// Verify this manifest's `governance.rotation_proofs[]` element (I-D §7.1; §7.5.1 4b(M) "The
/// rotation-anchoring rule, also phase 2"): a manifest may be trusted to introduce a rotated log
/// or witness key set only where its own anchoring is proven under the OUTGOING states.
///
/// `rotating_manifest`/`rotating_envelope` are this manifest's own payload/envelope;
/// `outgoing_manifest` is its predecessor's payload — the state being retired, which is what the
/// proof must be signed and cosigned under, never the incoming state the rotation installs.
///
/// `element` is the specific `governance.rotation_proofs[]` element already selected, and its
/// `manifest_entry_index` already matched, by the caller's positional walk (I-D §7.5.1): this
/// function trusts neither the array nor the index — it validates the one element it was
/// handed, nothing more.
// The element and the rotating hop's own material are the arguments; everything already
// established — the induction's key state, the outgoing version, policy, the receipt's `keys`
// block and the pinned profile — travels in [`RotationContext`], so what this function
// VALIDATES stays visible against what it merely CONSULTS.
#[allow(clippy::too_many_lines)]
fn verify_rotation_proof(
    element: &Value,
    rotating_envelope: &Value,
    manifest_entry_index: u64,
    rotating_manifest: &Value,
    context: &RotationContext<'_>,
    run: &mut Run,
) -> Result<()> {
    let RotationContext { receipt, policy, manifests, outgoing, profile, profile_id } = *context;
    let (outgoing_index, outgoing_manifest) = outgoing;
    let invalid =
        |detail: String| ReceiptError::RotationProofInvalid { manifest_entry_index, detail };

    // I-D §7.1: the element's `checkpoint` is "in the receipt-borne form defined above" — the
    // same strict shape `anchoring.checkpoint` takes, not a looser one.
    let checkpoint = checkpoint_object(obj(element, "checkpoint")?)?;
    // I-D §3.2: the same adaptor-binding check every other checkpoint gets — under the
    // OUTGOING manifest here, since that is the state this proof's checkpoint is signed and
    // cosigned under, never the incoming one.
    check_adaptor_binding(log_object(outgoing_manifest)?, profile_id, profile)?;
    // "WHERE `raw` is present, the verifier MUST check that it parses to the same values" —
    // the same reconciliation `verify_checkpoint` applies to `anchoring.checkpoint.raw`
    // applies here, identically (I-D §7.1).
    reconcile_checkpoint_raw(checkpoint, profile_id)?;
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
    if !log_key_set(outgoing_manifest).iter().any(|entry| entry.0.as_str() == checkpoint_key_id) {
        return Err(invalid(format!(
            "the element's checkpoint `key_id` (`{checkpoint_key_id}`) is not a log key of the \
             OUTGOING state at manifest entry index {manifest_entry_index} — a checkpoint \
             signed by the INCOMING key does not attest the transition (I-D §7.1)"
        )));
    }
    // I-D §7.1: "Every key used in verification MUST appear in `keys` with its source and its
    // binding", and under the transition exception "the corresponding `keys.log[]` and
    // `keys.witness[]` entries carry `manifest-chain` bindings naming that predecessor
    // version." The key this signature is verified under is therefore resolved THROUGH the
    // receipt's own `keys` block, bound at the outgoing manifest's entry index, rather than
    // lifted out of the manifest behind the block's back. Where the receipt is well formed the
    // two agree; where they do not, it is verifying under a key it never declared.
    let (outgoing_log_keys, outgoing_log_attempted) =
        bind_keys_by_group(receipt, policy, manifests, outgoing_index, "log")?;
    let signer = outgoing_log_keys.get(checkpoint_key_id).ok_or_else(|| {
        let entry_index =
            outgoing_log_attempted.get(checkpoint_key_id).copied().unwrap_or(outgoing_index);
        ReceiptError::KeyNotBound { key_id: checkpoint_key_id.to_owned(), entry_index }
    })?;
    run.spend(1)?;
    if !verify_signature(
        &decode_pubkey(&signer.pubkey)?,
        &checkpoint_signing_bytes_for(checkpoint, profile_id)?,
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
        run,
    )?;

    // I-D §7.1: `witnesses`, where PRESENT, is "an array in the shape of
    // `anchoring.witnesses[]`" — EVERY element of that array is held to the shape whenever the
    // member is present at all, regardless of level, not merely the ones a match happens to
    // reach and not merely below L3. A malformed entry is invalid whether or not some OTHER
    // entry in the array would have cosigned successfully, and whether or not a cosignature is
    // even required at this level.
    let witness_candidates = match element.get("witnesses") {
        None => Vec::new(),
        Some(value) => {
            let array = value.as_array().ok_or_else(|| {
                invalid(
                    "`witnesses`, where present, MUST be an array in the shape of \
                     `anchoring.witnesses[]` (I-D §7.1)"
                        .to_owned(),
                )
            })?;
            array.iter().map(witness_cosignature_object).collect::<Result<Vec<_>>>()?
        }
    };

    // AT L3, at least one `witnesses[]` cosignature MUST verify under a witness key of the
    // OUTGOING state, whichever set actually rotated — I-D §7.1: "a change to EITHER set is
    // attested under BOTH outgoing states". This build reads the rotating manifest's OWN
    // declared `level` to decide whether L3 applies going forward. Below L3, `witnesses` was
    // already shape-checked above where present, but no cosignature is required from it.
    if rotating_manifest.get("level").and_then(Value::as_str) == Some("L3") {
        let outgoing_witnesses = witness_key_set(outgoing_manifest)?;
        let mut cosigned = false;
        for witness in &witness_candidates {
            let witness_id = text(witness, "witness_id")?.to_owned();
            let key_id = text(witness, "key_id")?;
            // A cosignature by a witness the OUTGOING manifest does not declare under that
            // identity attests nothing about the handover, and is passed over rather than
            // refused: §7.1 asks only that at least one element verify under an outgoing
            // witness key, so an element that is not such a key is simply not that one. The
            // pubkey comes from that manifest object, never from the receipt.
            let Some(pubkey) = outgoing_witnesses
                .iter()
                .find(|entry| entry.0 == witness_id && entry.1.as_str() == key_id)
                .map(|entry| entry.2.clone())
            else {
                continue;
            };
            // Having selected it, the receipt must LIST that key as the transition exception
            // requires — `manifest-chain`, bound to the predecessor version, and carrying that
            // same public key. A `local-policy` entry is not such a listing however trusted it
            // is: it attests what this verifier accepts, not what the retiring authority did.
            require_listed_rotation_witness(receipt, outgoing_index, &witness_id, key_id, &pubkey)?;
            run.spend(1)?;
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

/// I-D §7.5.1 4b's ascending-entry-index requirement over the MERGED induction stream.
///
/// Both sources are internally ascending, so the only thing left to rule out is one entry index
/// arriving twice — once from `governance.chain[]` and once from the enumerated `key`
/// statements. That would be two hash proofs against one root disagreeing about what the log
/// holds at that index, which no conforming material can produce; the walk refuses it rather
/// than choosing an order for the pair.
fn check_merged_order(walked_index: u64, index: u64) -> Result<()> {
    if walked_index >= index {
        return Err(ReceiptError::GovernanceChainInvalid(format!(
            "the merged governance walk reaches entry index {index} after {walked_index}; the \
             manifest chain and the enumerated `key` statements are walked in ascending \
             entry-index order, and no index may be claimed by both (I-D §7.5.1 4b)"
        )));
    }
    Ok(())
}

/// Turn an envelope check into the outcome the receipt's governance MODE fixes for it.
///
/// Every producer-key signature check in this module ends here, so the two conditions
/// [`crate::EnvelopeCheck`] separates cannot be conflated at one call site and kept apart at
/// another. A signature that does not verify under a key the presented state DOES hold is a
/// demonstrated defect and is `invalid` in either mode (I-D §7.5.1 4d: "An envelope carrying a
/// non-verifying entry... is invalid"), and [`crate::check_envelope`] gives it precedence over
/// an unresolved key on the SAME envelope, so a multi-signature envelope carrying both defects
/// arrives here as `SignatureInvalid` whatever order the producer wrote them in. A `key_id` the
/// presented state holds no key for — every resolvable entry on that envelope having verified —
/// is the mode-dependent case: `invalid` under `enumerated`, where 4c's complete range
/// forecloses omission, and [`ReceiptError::ProducerKeyNotCarried`] — the I-D's `unverifiable`
/// — under `declared`, where §7.4 says the verifier is short of material rather than looking at
/// a defect.
fn envelope_outcome(check: &crate::EnvelopeCheck, mode: &str, index: u64) -> Result<()> {
    match check {
        crate::EnvelopeCheck::Verified => Ok(()),
        crate::EnvelopeCheck::KeyNotResolved { key_id } if mode == DECLARED_MODE => {
            Err(ReceiptError::ProducerKeyNotCarried { entry_index: index, key_id: key_id.clone() })
        }
        crate::EnvelopeCheck::SignatureInvalid | crate::EnvelopeCheck::KeyNotResolved { .. } => {
            Err(ReceiptError::EnvelopeSignatureInvalid { entry_index: index })
        }
    }
}

/// I-D §7.5.1 4b phase 1, identical for both induction types: "Verify the envelope under the
/// envelope signature rule of Section 2.1 against K AS ESTABLISHED SO FAR — the governance
/// state in force immediately before this statement's own entry index."
///
/// `manifests` and `events` hold only statements strictly before `index` when this is called,
/// so the state derived from them is exactly that pre-effect state — computed BEFORE anything
/// about this statement's own content (schema, predecessor linkage, rotation proof, `key`
/// object) is read.
fn verify_governance_phase_1(
    envelope: &Value,
    manifests: &[(u64, &Value)],
    events: &[KeyEvent],
    index: u64,
    mode: &str,
    run: &mut Run,
) -> Result<()> {
    let k_so_far = producer_keys_at_in(manifests, events, index);
    run.spend(1)?;
    let check = crate::check_envelope(envelope, |key_id| {
        k_so_far.get(key_id).map(|bound| bound.pubkey.clone())
    })?;
    envelope_outcome(&check, mode, index)
}

/// I-D §7.5.1 4b(K) phase 2: a `key` statement's own form, validated before its effect on K.
///
/// "A statement that verifies under a valid key is thereby authentic, not thereby well formed,
/// and applying an `action` that was never checked would let a malformed statement modify the
/// key set." Returns the phase-3 effect for the caller to apply, so the two phases cannot be
/// reordered by accident: there is no way to reach the [`KeyEvent`] without passing every check
/// here first.
fn validate_key_statement(
    payload: &Value,
    index: u64,
    manifests: &[(u64, &Value)],
    manifest_by_version_id: &BTreeMap<String, (u64, &Value)>,
) -> Result<KeyEvent> {
    // Phase 2, 4b(K): action, key-object shape, key-id/pubkey binding, and
    // `valid_from` (I-D §7.5.1 4b(K)): "before a `key` statement's effect touches
    // K, validate its form... a failure is `invalid`, and the event is NOT
    // applied."
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
    if !is_family_hash(&key_id) {
        return Err(ReceiptError::GovernanceChainInvalid(format!(
            "key statement at entry index {index} carries `key.key_id` that is \
             not a `sha256:` family string in lowercase hex (I-D §7.5.1 4b(K))"
        )));
    }
    let pubkey = text(key, "pubkey")?.to_owned();
    // "`pubkey` decodes to exactly 32 octets" and "`key_id` RECOMPUTED from
    // `pubkey` and equal to the carried one" — the SAME rule and SAME helper I-D
    // §6.2 states for a manifest's own producer key objects
    // ([`recompute_producer_key_id`]), shared rather than re-derived here.
    let recomputed = recompute_producer_key_id(&pubkey).map_err(|_| {
        ReceiptError::GovernanceChainInvalid(format!(
            "key statement at entry index {index} carries `key.pubkey` that does \
             not decode to exactly 32 octets (I-D §7.5.1 4b(K))"
        ))
    })?;
    if recomputed != key_id {
        return Err(ReceiptError::GovernanceChainInvalid(format!(
            "key statement at entry index {index} carries `key.key_id` \
             (`{key_id}`) that does not equal `sha256:`-of-`key.pubkey` \
             (`{recomputed}`) (I-D §7.5.1 4b(K))"
        )));
    }
    // "`valid_from` REQUIRED and well-formed RFC 3339 (informative for ordering,
    // but required)"
    let valid_from = key.get("valid_from").and_then(Value::as_str).ok_or_else(|| {
        ReceiptError::GovernanceChainInvalid(format!(
            "key statement at entry index {index} carries no `key.valid_from` — \
             the member is REQUIRED (I-D §7.5.1 4b(K))"
        ))
    })?;
    crate::bitemporal::parse_rfc3339("key.valid_from", valid_from).map_err(|source| {
        ReceiptError::GovernanceChainInvalid(format!(
            "key statement at entry index {index} carries `key.valid_from` \
                 that is not well-formed RFC 3339 (I-D §7.5.1 4b(K)): {source}"
        ))
    })?;
    // I-D §2.2: a `key` statement is not a manifest statement, so it carries a
    // `manifest` field of its own, and that field is held to the SAME rule as the
    // subject's copy (§7.6) — it must name the manifest version ACTIVE at THIS
    // statement's own entry index, never a stale one.
    let claimed_manifest = text(payload, "manifest")?;
    let active =
        active_manifest_version_id(manifests, manifest_by_version_id, index).ok_or_else(|| {
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
    Ok(KeyEvent { entry_index: index, key_id, pubkey, added })
}

/// Build and structurally validate the governance state (I-D §7.5.1 4a-4c): the base case,
/// then the induction, each carried statement's SIGNATURE verified against K as established by
/// its predecessors before anything about its own content is trusted.
///
/// The induction walks TWO streams merged in ascending entry-index order, which is what I-D
/// §7.5.1 4b states: "the manifest statements of `governance.chain[]`, merged in entry-index
/// order with the `key` statements the enumeration material carries where the mode carries
/// them." `key_statements` is that second stream — empty under `declared` governance, which
/// carries no producer-key transitions at all (§7.4). The chain itself carries manifests and
/// nothing else: §7.1 defines each of its elements as "an anchored MANIFEST statement's
/// complete envelope", and §7.4 says producer-key transitions "reach a verifier only through
/// enumeration material".
// The governance-key-rotation check (I-D §7.1, §7.5.1) folds naturally into this same
// per-manifest walk rather than a second pass over the same material.
#[allow(clippy::too_many_lines)]
fn read_chain<'a>(
    receipt: &'a Value,
    policy: &TrustPolicy,
    profile: &AdaptorProfile,
    profile_id: &str,
    key_statements: &[(u64, &Value)],
    mode: &'a str,
    run: &mut Run,
) -> Result<Governance<'a>> {
    let chain = array(obj(receipt, "governance")?, "chain")?;
    if chain.is_empty() {
        return Err(ReceiptError::GovernanceChainInvalid("chain is empty".to_owned()));
    }

    // I-D §7.1: "REQUIRED IF AND ONLY IF the carried governance chain contains a
    // GOVERNANCE-KEY ROTATION"; "The member is ABSENT where the chain rotates neither set";
    // "one element per rotation, in ascending `manifest_entry_index` order." §7.5.1: "Type
    // specific validation MUST NOT run on material whose signature has not verified" — so
    // WHICH hops rotate can only be decided inside the signed per-hop walk below, never from
    // an unverified pre-scan of the chain's own payloads. What IS safe to read here, before
    // induction starts, is the CONTAINER shape of `governance.rotation_proofs` itself — its
    // presence/absence and, where present, that it is an array — because that is a fact about
    // the receipt's own structure, not a claim about any chain hop's unverified content.
    let rotation_proofs_member =
        receipt.get("governance").and_then(|governance| governance.get("rotation_proofs"));
    let rotation_proofs: &[Value] = match rotation_proofs_member {
        None => &[],
        Some(value) => value.as_array().map(Vec::as_slice).ok_or_else(|| {
            ReceiptError::GovernanceChainInvalid(
                "`governance.rotation_proofs`, where present, MUST be an array (I-D §7.1)"
                    .to_owned(),
            )
        })?,
    };
    let mut rotation_cursor = 0usize;
    let mut saw_rotation = false;

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
    // §2.2's version-first rule runs before anything else, typed content included — an
    // unsupported `ahl_version` is `unverifiable`, decided from the bytes alone, before any
    // trust decision (anchor equality included) is even attempted.
    check_ahl_version(genesis_payload)?;
    // I-D §7.5.1 4a: entry-id equality "authenticates the genesis envelope IN FULL" — and
    // typed checks, `type == "manifest"` among them, FOLLOW that anchor comparison, never
    // precede it. Reading `type` (or anything else typed) before the anchor is verified would
    // let unauthenticated content decide what gets rejected and how, the same ordering fault
    // the induction's phase 1/phase 2 split exists to rule out for every later hop.
    let carried_anchor = text(obj(receipt, "governance")?, "genesis_entry_id")?;
    if carried_anchor != entry_id(genesis_envelope) {
        return Err(ReceiptError::GovernanceChainInvalid(
            "`genesis_entry_id` does not digest the carried genesis envelope".to_owned(),
        ));
    }
    if carried_anchor != policy.genesis_entry_id {
        return Err(ReceiptError::GenesisAnchorMismatch);
    }
    // I-D §7.5.1 4a: the fingerprint comparison is optional local policy — WHERE `policy`
    // holds no configured set, the comparison does not arise at all, and that absence is not
    // itself a defect. WHERE it holds one, the genesis manifest's producer key ids MUST match
    // it exactly. Still part of anchor authentication, so still ahead of the `type` check.
    if let Some(configured) = &policy.genesis_key_ids {
        let genesis_key_ids: BTreeSet<String> =
            producer_key_objects(genesis_payload)?.into_iter().map(|(id, _)| id).collect();
        if &genesis_key_ids != configured {
            return Err(ReceiptError::GenesisAnchorMismatch);
        }
    }
    if statement_type(genesis_payload)? != "manifest" {
        return Err(ReceiptError::GovernanceChainInvalid(
            "the chain must start at the genesis manifest".to_owned(),
        ));
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
    common_payload_fields(genesis_payload)?;
    producer_key_objects(genesis_payload)?;
    log_object(genesis_payload)?;
    datasets_object(genesis_payload)?;
    manifest_scope_fields(genesis_payload)?;
    witnesses_object(genesis_payload)?;

    // "Only after ALL of those pass... let K be the key state the genesis manifest declares."
    let mut manifests: Vec<(u64, &Value)> = vec![(0, genesis_payload)];
    let mut events: Vec<KeyEvent> = Vec::new();
    let mut manifest_by_version_id: BTreeMap<String, (u64, &Value)> = BTreeMap::new();
    manifest_by_version_id.insert(statement_id(genesis_envelope)?, (0, genesis_payload));
    let mut previous_index = 0u64;
    let mut previous_manifest_entry_id = entry_id(genesis_envelope);
    let mut previous_manifest_payload = genesis_payload;
    // The entry index of the manifest version a rotation would be retiring — the OUTGOING
    // version, which I-D §7.1's transition exception says the proof's own `keys` entries bind
    // to. Genesis is anchored at entry index 0.
    let mut previous_manifest_index = 0u64;

    // The chain's own entry indexes, read before the walk. This is a container-level read —
    // an integer per element, no typed content — of exactly the kind I-D §7.5 step 3 already
    // performs over the same member, so it precedes every signature without breaking the
    // phase discipline the induction below keeps.
    let mut chain_hops: Vec<(u64, &Value)> = Vec::with_capacity(chain.len().saturating_sub(1));
    for hop in &chain[1..] {
        let index = number(hop, "entry_index")?;
        if previous_index >= index {
            return Err(ReceiptError::GovernanceChainInvalid(CHAIN_ASCENDING.to_owned()));
        }
        previous_index = index;
        chain_hops.push((index, obj(hop, "envelope")?));
    }

    // --- I-D §7.5.1 4b. Inductive step: three phases, in this order, for every later hop. ---
    //
    // "Walk the carried governance statements after the genesis manifest in ascending
    // ENTRY-INDEX order: the manifest statements of `governance.chain[]`, merged in entry-index
    // order with the `key` statements the enumeration material carries where the mode carries
    // them." Both input streams are already ascending — the chain by the check just made, the
    // enumerated key statements by the range proof's own index continuity — so the merge is a
    // two-cursor walk and needs no sort.
    let mut chain_cursor = 0usize;
    let mut key_cursor = 0usize;
    // The genesis manifest, at entry index 0, is the statement the base case has just walked.
    let mut walked_index = 0u64;
    while chain_cursor < chain_hops.len() || key_cursor < key_statements.len() {
        let take_key = match (chain_hops.get(chain_cursor), key_statements.get(key_cursor)) {
            (Some((chain_index, _)), Some((key_index, _))) => key_index < chain_index,
            (None, Some(_)) => true,
            _ => false,
        };
        // The two streams are processed in separate arms rather than through one merged
        // binding: the chain's envelopes are borrowed from the receipt and outlive this
        // function inside [`Governance`], while the enumerated ones are borrowed from
        // enumeration material the caller owns. Phases 1 and 2 are identical for both, and are
        // shared through [`check_merged_order`], [`verify_governance_phase_1`] and
        // [`validate_key_statement`].
        if take_key {
            let (index, envelope) = key_statements[key_cursor];
            key_cursor += 1;
            check_merged_order(walked_index, index)?;
            walked_index = index;
            let payload = payload_of(envelope)?;
            check_ahl_version(payload)?;
            verify_governance_phase_1(envelope, &manifests, &events, index, mode, run)?;
            common_payload_fields(payload)?;
            // Phase 2 (4b(K)) and phase 3 (the producer-key effect), in that order.
            events.push(validate_key_statement(
                payload,
                index,
                &manifests,
                &manifest_by_version_id,
            )?);
            continue;
        }

        let (index, envelope) = chain_hops[chain_cursor];
        chain_cursor += 1;
        check_merged_order(walked_index, index)?;
        walked_index = index;

        let payload = payload_of(envelope)?;
        check_ahl_version(payload)?;

        verify_governance_phase_1(envelope, &manifests, &events, index, mode, run)?;

        // "A failure at phase 1 or phase 2 is invalid, and the induction does not continue past
        // it. No effect is ever applied to K by a statement that has not completed both
        // earlier phases." Phase 2 (type-specific validation) and phase 3 (effect) follow —
        // starting with the common payload fields I-D §2.2 requires of EVERY statement, before
        // the manifest-specific content below is read.
        common_payload_fields(payload)?;
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
                producer_key_objects(payload)?;
                log_object(payload)?;
                datasets_object(payload)?;
                // §6.2's remaining "contains at minimum" members — `pipelines`, `windows`,
                // `retention`, `level` — validated BEFORE the rotation-anchoring rule below
                // reads `level` to decide whether L3 applies (an absent or malformed `level`
                // must fail HERE, in schema, never be silently read as "not L3").
                manifest_scope_fields(payload)?;
                witnesses_object(payload)?;
                // I-D §7.1 / §7.5.1: a manifest whose log or witness key objects DIFFER, as
                // SETS, from its predecessor's in the chain is a GOVERNANCE-KEY ROTATION (I-D
                // §6.2: "Each manifest version's log and witness key objects replace the prior
                // set in full" — a set, not a sequence, so a harmless reordering is never a
                // rotation) and requires its `governance.rotation_proofs[]` element to verify
                // under the outgoing key state (`verify_rotation_proof`).
                let rotated = log_key_set(payload) != log_key_set(previous_manifest_payload)
                    || witness_key_set(payload)? != witness_key_set(previous_manifest_payload)?;
                if rotated {
                    saw_rotation = true;
                    // "The NEXT unconsumed `rotation_proofs[]` element must have
                    // `manifest_entry_index` equal to this hop's entry index (else invalid),
                    // and is validated then." Positional consumption, decided only now that
                    // this hop's own signature (phase 1) and schema (phase 2, above) have
                    // already passed.
                    let element = rotation_proofs.get(rotation_cursor).ok_or_else(|| {
                        ReceiptError::RotationProofInvalid {
                            manifest_entry_index: index,
                            detail: "the chain rotates the log or witness key set here, but \
                                     `governance.rotation_proofs[]` carries no (further) \
                                     element for it (I-D §7.1)"
                                .to_owned(),
                        }
                    })?;
                    let element_index = number(element, "manifest_entry_index")?;
                    if element_index != index {
                        return Err(ReceiptError::RotationProofInvalid {
                            manifest_entry_index: index,
                            detail: format!(
                                "the next unconsumed `governance.rotation_proofs[]` element \
                                 carries `manifest_entry_index` {element_index}, not {index} \
                                 — one element per rotation, in ascending \
                                 `manifest_entry_index` order (I-D §7.1)"
                            ),
                        });
                    }
                    verify_rotation_proof(
                        element,
                        envelope,
                        index,
                        payload,
                        &RotationContext {
                            receipt,
                            policy,
                            manifests: &manifests,
                            outgoing: (previous_manifest_index, previous_manifest_payload),
                            profile,
                            profile_id,
                        },
                        run,
                    )?;
                    rotation_cursor += 1;
                }
                // Phase 3: effect — replaces the log, witness, and producer key state in full.
                previous_manifest_entry_id = entry_id(envelope);
                previous_manifest_payload = payload;
                previous_manifest_index = index;
                manifest_by_version_id.insert(statement_id(envelope)?, (index, payload));
                manifests.push((index, payload));
            }
            other => {
                // I-D §7.1: each `governance.chain[]` element is "an anchored MANIFEST
                // statement's complete envelope", and §7.4 states where the other governance
                // type travels: "`governance.chain[]` carries manifest statements; producer-key
                // transitions are `key` statements, and those reach a verifier only through
                // enumeration material." A chain element of any other type is a container the
                // format does not define, so it is refused as a shape defect rather than
                // silently walked as though the chain were a second carrier for key
                // transitions. The type is read HERE, after phase 1, so the refusal never rests
                // on bytes no key has vouched for.
                return Err(ReceiptError::GovernanceChainInvalid(format!(
                    "`governance.chain[]` carries a `{other}` statement at entry index \
                     {index}; each element is an anchored MANIFEST statement's envelope (I-D \
                     §7.1), and producer-key transitions reach a verifier only through \
                     enumeration material (I-D §7.4)"
                )));
            }
        }
    }

    // I-D §7.1: "one element per rotation" — an element the walk never had occasion to
    // consume is an extra, exactly as invalid as a missing one.
    if rotation_cursor < rotation_proofs.len() {
        return Err(ReceiptError::GovernanceChainInvalid(format!(
            "`governance.rotation_proofs[]` carries {} element(s) beyond the {} the chain \
             walk actually consumed — I-D §7.1: one element per rotation, no extras",
            rotation_proofs.len(),
            rotation_cursor
        )));
    }
    // "The member is ABSENT where the chain rotates neither set" — so a member present with
    // no rotation ever encountered is invalid too, symmetric with the absent-but-rotated case
    // caught inline above.
    if rotation_proofs_member.is_some() && !saw_rotation {
        return Err(ReceiptError::GovernanceChainInvalid(
            "`governance.rotation_proofs` is present, but the carried chain rotates neither \
             the log nor the witness key set — I-D §7.1 requires the member to be ABSENT in \
             that case"
                .to_owned(),
        ));
    }

    Ok(Governance { mode, manifests, events, manifest_by_version_id })
}

// ---------------------------------------------------------------------------
// Anchoring
// ---------------------------------------------------------------------------

/// What 4f established about the receipt's anchoring, for the §7.3 assurance comparison.
///
/// The checkpoint's own `tree_size` and `root_hash` are read at step 3, where every path and
/// range recomputation that needs them already runs; nothing after 4f reaches for them again,
/// so they are deliberately not carried forward here.
struct Anchoring {
    witnessed: bool,
    continued_history: bool,
}

/// A `keys.log[]`/`keys.witness[]` entry resolved to the public key verification uses.
struct ResolvedKey {
    /// The public key a signature or cosignature is verified under.
    pubkey: String,
    /// For a witness key, the identity it was resolved under (I-D §7.1) — the manifest's own
    /// declaration for a `manifest-chain` key, and the one local policy holds the key for
    /// where the source is `local-policy`. `None` for a log key, which carries no identity
    /// member and has no cosignature to bind one to.
    witness_id: Option<String>,
}

/// Bind a log or witness key to the key object the receipt says it comes from (I-D §7.1
/// "`keys`"), under the one of the two admissible sources the entry declares.
///
/// **`manifest-chain`.** The key object must appear in the manifest version active for the
/// checkpoint being verified, and `active_index` is fixed by that checkpoint's `tree_size`, so
/// a key a later manifest replaced cannot validate it. A log key matches on `(key_id, pubkey)`;
/// a witness key matches on `(witness_id, key_id, pubkey)`, because §7.1 makes `witness_id`
/// part of the witness key object rather than a free-text label — dropping it would let one
/// declared witness's key be presented under another witness's identity.
///
/// **`local-policy`.** Admissible for witness keys only, and only for keys the verifier already
/// trusts: the entry's `key_id` AND `pubkey` must both be what [`TrustPolicy`] holds. Nothing
/// carried in the receipt contributes to that decision, which is the whole point — a policy
/// holding no trusted witness key accepts no `local-policy` witness key at all.
fn bind_log_or_witness_key(
    policy: &TrustPolicy,
    manifests: &[(u64, &Value)],
    entry: &Value,
    group: &str,
    active_index: u64,
) -> Result<ResolvedKey> {
    let key_id = text(entry, "key_id")?.to_owned();
    let pubkey = text(entry, "pubkey")?.to_owned();
    match text(entry, "source")? {
        // I-D §7.1: "`source: \"local-policy\"` is an acceptable source only for witness keys
        // the verifier already trusts, for the genesis anchor, and for authorized dataset
        // keys" — neither of the latter two is a `keys.log[]`/`keys.producer[]` entry, so
        // within this block the source is admissible for the witness group and nowhere else.
        "local-policy" => {
            if group != "witness" {
                return Err(ReceiptError::KeyNotBound { key_id, entry_index: active_index });
            }
            // All three members, and the identity among them: §7.1 gives a witness key object
            // "`witness_id`, the identity under which the manifest declares that witness", and
            // a key policy trusts for one witness is not a key trusted to cosign as another.
            // What policy CANNOT establish is that the identity is a declared one at all —
            // that is a fact about the manifest, checked on the cosignature itself.
            let witness_id = text(entry, "witness_id")?.to_owned();
            let trusted = policy.trusted_witness_keys.get(&key_id);
            if trusted.map(|held| (held.pubkey.as_str(), held.witness_id.as_str()))
                != Some((pubkey.as_str(), witness_id.as_str()))
            {
                return Err(ReceiptError::WitnessKeyNotTrusted { key_id });
            }
            Ok(ResolvedKey { pubkey, witness_id: Some(witness_id) })
        }
        "manifest-chain" => {
            let binding_index = number(obj(entry, "binding")?, "entry_index")?;
            if binding_index != active_index {
                return Err(ReceiptError::KeyNotBound { key_id, entry_index: binding_index });
            }
            let not_bound =
                || ReceiptError::KeyNotBound { key_id: key_id.clone(), entry_index: binding_index };
            let (_, manifest) = manifests
                .iter()
                .find(|(index, _)| *index == binding_index)
                .copied()
                .ok_or_else(not_bound)?;

            // I-D §7.1, keys block: the manifest object is `{key_id, pubkey,
            // valid_from_index}`, "a witness object additionally carrying `witness_id`; the
            // receipt-side entry carries `key_id`, `pubkey`, and for a witness `witness_id`,
            // but not `valid_from_index`, which is a property of the manifest declaration and
            // is read from the manifest object alone. The match is therefore equality of every
            // member the two objects share" (§6.2 fixes the manifest side of that pair). Which
            // is what this compares — the shared members, all of them.
            if group == "log" {
                key_objects(log_object(manifest)?)?
                    .into_iter()
                    .find(|(id, key)| id == &key_id && key == &pubkey)
                    .map(|(_, key)| ResolvedKey { pubkey: key, witness_id: None })
                    .ok_or_else(not_bound)
            } else {
                let witness_id = text(entry, "witness_id")?.to_owned();
                witness_key_set(manifest)?
                    .into_iter()
                    .find(|(declared_id, id, key, _)| {
                        declared_id == &witness_id && id == &key_id && key == &pubkey
                    })
                    .map(|(declared_id, _, key, _)| ResolvedKey {
                        pubkey: key,
                        witness_id: Some(declared_id),
                    })
                    .ok_or_else(not_bound)
            }
        }
        // Unreachable in a receipt that reached this point — [`check_keys_block`] admits only
        // the two tokens above, and runs over the whole `keys` block first — but stated rather
        // than defaulted, so no third source can ever be read as one of the two.
        other => Err(ReceiptError::Malformed(format!(
            "`keys.{group}[]` entry `{key_id}` declares `source` `{other}`: I-D §7.1 admits \
             exactly `manifest-chain` or `local-policy`"
        ))),
    }
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

/// Require a cosignature's `witness_id` to be the identity the manifest declares for the key
/// it is verified under (I-D §7.1: `anchoring.witnesses[]` carries "the witness identity AS
/// DECLARED IN THE MANIFEST", and a witness key object carries "`witness_id`, the identity
/// under which the manifest declares that witness").
///
/// The identity is not decorative: `cosignature_bytes` puts it in the preimage, so a
/// cosignature naming an identity of the presenter's own choosing is a signature over bytes no
/// declared witness ever cosigned. Applied identically to `anchoring.witnesses[]` and
/// `anchoring.later_witnesses[]`; `governance.rotation_proofs[].witnesses[]` resolves its keys
/// straight out of the outgoing manifest by `(witness_id, key_id)` and so is bound to the same
/// identity by construction ([`verify_rotation_proof`]).
///
/// A `local-policy` witness key is held to the same rule from the other side: policy holds the
/// identity alongside the key ([`TrustedWitnessKey`]), so the comparison here is against that
/// held identity, and [`check_witness_declared`] separately requires it to be one the active
/// manifest declares. Neither the receipt nor policy alone can invent a witness.
fn check_witness_identity(resolved: &ResolvedKey, key_id: &str, carried: &str) -> Result<()> {
    match &resolved.witness_id {
        Some(declared) if declared != carried => Err(ReceiptError::WitnessIdentityMismatch {
            key_id: key_id.to_owned(),
            declared: declared.clone(),
            carried: carried.to_owned(),
        }),
        _ => Ok(()),
    }
}

/// The elements of an `anchoring.witnesses[]`-shaped member, or the empty slice where the
/// member is absent.
///
/// A member present under any other JSON type is `invalid` (I-D §7.1: "The member shapes shown
/// above are normative") and is never read as absent: treating `"witnesses": {}` as an empty
/// array would silently turn an L3 receipt's missing cosignature requirement into a receipt
/// that carries none, and treating a string `later_witnesses` the same way would drop the
/// cosignatures that are the only thing establishing a witness saw `later_checkpoint`.
fn cosignature_array<'a>(container: &'a Value, member: &str, what: &str) -> Result<&'a [Value]> {
    match container.get(member) {
        None => Ok(&[]),
        Some(Value::Array(elements)) => Ok(elements),
        Some(_) => Err(ReceiptError::Malformed(format!(
            "`{what}`, where present, MUST be an array in the shape of `anchoring.witnesses[]` \
             (I-D §7.1)"
        ))),
    }
}

/// I-D §7.1: "Elements appear in ascending `entry_index` order."
const CHAIN_ASCENDING: &str = "chain hops must ascend by entry index";

/// I-D §7.5 step 3: "Key-independent structural and path checks. **No signature and no
/// cosignature is verified in this step.**"
///
/// Every check here is an integer comparison or a hash recomputation, and each is therefore
/// decidable before any key state exists. That is why the whole of the carried material's path
/// evidence is proven here and not inside the induction: §7.5.1 walks the governance chain in
/// ascending entry-index order and every activity test in the I-D is "at index i", so an
/// unproven `entry_index` would let a producer present a governance chain in an order the log
/// never had, and a manifest that was never anchored would still derive the key state. "An
/// inclusion path recomputed from an element's entry id at its asserted index is what proves
/// that index, and the two cannot be separated: the path proof IS the index proof."
///
/// `root` is used here as an UNAUTHENTICATED STRUCTURAL COMMITMENT — the medium the presented
/// material is bound to, not yet a value shown to be the log's. Nothing in this function
/// establishes that the log issued that root, and no result may be reported from it alone;
/// 4f ([`verify_checkpoint`]) is what upgrades every path result here from a statement about
/// carried bytes to a statement about the log's state.
fn check_key_independent_paths(
    receipt: &Value,
    envelope: &Value,
    subject_index: u64,
    tree_size: u64,
    root: &Hash,
    run: &mut Run,
) -> Result<()> {
    if subject_index >= tree_size {
        return Err(ReceiptError::EntryIndexBeyondCheckpoint {
            entry_index: subject_index,
            tree_size,
        });
    }
    check_inclusion(
        &jcs(envelope),
        subject_index,
        tree_size,
        &path_strings(obj(receipt, "anchoring")?, "inclusion_path")?,
        root,
        "subject",
        run,
    )?;

    let mut previous: Option<u64> = None;
    for hop in array(obj(receipt, "governance")?, "chain")? {
        let index = number(hop, "entry_index")?;
        if previous.is_some_and(|earlier| earlier >= index) {
            return Err(ReceiptError::GovernanceChainInvalid(CHAIN_ASCENDING.to_owned()));
        }
        previous = Some(index);
        let hop_envelope = obj(hop, "envelope")?;
        // I-D §7.5 step 1: each carried statement's `ahl_version` is checked BEFORE that
        // statement is validated — recomputing a hash over its bytes included.
        check_ahl_version(payload_of(hop_envelope)?)?;
        // A hop the checkpoint does not commit cannot be proven against its root, and an
        // unprovable governance statement is a refusal rather than a pass. This is the wall a
        // receipt hits when a manifest version was anchored after its own anchoring checkpoint
        // — the case §2.1 needs for a later checkpoint under a rotated key set. Reporting it as
        // a named refusal keeps it from degrading into "the older key still worked, so accept".
        if index >= tree_size {
            return Err(ReceiptError::GovernanceChainInvalid(format!(
                "the chain carries a hop at entry index {index}, which a checkpoint of size \
                 {tree_size} does not commit: its inclusion cannot be proven against that root"
            )));
        }
        check_inclusion(
            &jcs(hop_envelope),
            index,
            tree_size,
            &path_strings(hop, "inclusion_path")?,
            root,
            "governance chain hop",
            run,
        )?;
    }
    Ok(())
}

/// The receipt's container shapes (I-D §7.1: "The member shapes shown above are normative"),
/// checked over the whole carried document before any of it is resolved or verified.
///
/// This is §7.5 step 3's "family-string, arity, and ordering checks the container shapes of
/// Section 7.1 require", and it is deliberately independent of what verification later reaches
/// for: an ill-shaped member on a path some earlier failure short-circuits is `invalid` all the
/// same.
fn check_container_shapes(receipt: &Value) -> Result<()> {
    // I-D §7.1 marks its own extension points, and closing what it draws complete is the whole
    // of the rule: an elided body (`{ ... }`) or a trailing `...` says the members are defined
    // elsewhere — `claim.assurance` in §7.3, `governance.currency.material` in §7.4,
    // `claim_material` in §7.2, an envelope's `payload`/`signatures` in §2.1, and an
    // `anchors[]` entry's type-specific members in whatever format it names — and every other
    // object in the container is drawn with its members complete.
    check_closed_members(
        receipt,
        "receipt",
        &[
            "ahl_receipt_version",
            "spec_version",
            "claim",
            "subject",
            "envelope",
            "keys",
            "anchoring",
            "governance",
            "claim_material",
            "anchors",
        ],
    )?;
    let claim = obj(receipt, "claim")?;
    check_closed_members(claim, "claim", &["type", "record_subject", "assurance", "note"])?;
    if let Some(record_subject) = claim.get("record_subject") {
        check_closed_members(record_subject, "claim.record_subject", &["dataset", "record"])?;
    }
    check_closed_members(
        obj(receipt, "subject")?,
        "subject",
        &["statement_id", "entry_id", "entry_index", "manifest"],
    )?;
    check_closed_members(obj(receipt, "envelope")?, "envelope", &["payload", "signatures"])?;

    check_keys_block(receipt)?;
    check_anchoring_shapes(receipt)?;
    check_governance_shapes(receipt)
}

/// The `anchoring` block's own shapes (I-D §7.1), split out of [`check_container_shapes`]
/// only so each block's shape rules read as one piece.
fn check_anchoring_shapes(receipt: &Value) -> Result<()> {
    let anchoring = obj(receipt, "anchoring")?;
    check_closed_members(
        anchoring,
        "anchoring",
        &[
            "adaptor",
            "checkpoint",
            "inclusion_path",
            "witnesses",
            "later_checkpoint",
            "consistency_path",
            "later_witnesses",
        ],
    )?;
    check_closed_members(obj(anchoring, "adaptor")?, "anchoring.adaptor", &["id", "hash"])?;
    for member in ["witnesses", "later_witnesses"] {
        for element in cosignature_array(anchoring, member, &format!("anchoring.{member}"))? {
            witness_cosignature_object(element)?;
        }
    }
    check_family_hash_path(anchoring, "inclusion_path", "anchoring.inclusion_path")?;
    check_family_hash_path(anchoring, "consistency_path", "anchoring.consistency_path")?;
    Ok(())
}

/// The `governance` block's shapes, plus `anchors[]` (I-D §7.1).
fn check_governance_shapes(receipt: &Value) -> Result<()> {
    let governance = obj(receipt, "governance")?;
    check_closed_members(
        governance,
        "governance",
        &["genesis_entry_id", "chain", "rotation_proofs", "currency"],
    )?;
    check_closed_members(
        obj(governance, "currency")?,
        "governance.currency",
        &["mode", "material"],
    )?;
    for (position, hop) in array(governance, "chain")?.iter().enumerate() {
        check_closed_members(
            hop,
            &format!("governance.chain[{position}]"),
            &["envelope", "entry_index", "inclusion_path"],
        )?;
        check_closed_members(
            obj(hop, "envelope")?,
            &format!("governance.chain[{position}].envelope"),
            &["payload", "signatures"],
        )?;
        let what = format!("governance.chain[{position}].inclusion_path");
        check_family_hash_path(hop, "inclusion_path", &what)?;
    }
    // I-D §7.1: `anchors[]` is material this verifier does not otherwise read — it computes
    // no verdict from an external timestamp (§8.3 offers them as evidence a deployment can
    // compose with checkpoints, not as an input to any rule here) — but "the member shapes
    // shown above are normative", and a member no verifier could interpret is a schema failure
    // whether or not THIS one has a use for it.
    //
    // Exactly what the container fixes is enforced, and nothing beyond it. The shape is
    // `{ "type": "rfc3161 | bitcoin_ots", "target": "checkpoint_root", "target_hash":
    // "sha256:<hex>", ... }`: three REQUIRED members, `target_hash` a digest under §2.1's
    // strict rule, and a trailing ellipsis that leaves an anchor format's own type-specific
    // members unconstrained. The example values of `type` and `target` are NOT read as a
    // closed registry — this document registers no anchor types — so those two are held to
    // being strings, which is what the shape states.
    if let Some(value) = receipt.get("anchors") {
        let elements = value.as_array().ok_or_else(|| {
            ReceiptError::Malformed(
                "`anchors`, where present, MUST be an array (I-D §7.1)".to_owned(),
            )
        })?;
        for (position, element) in elements.iter().enumerate() {
            let invalid =
                |detail: &str| ReceiptError::Malformed(format!("`anchors[{position}]`: {detail}"));
            if !element.is_object() {
                return Err(invalid("MUST be an anchor object (I-D §7.1)"));
            }
            for member in ["type", "target"] {
                if !element.get(member).is_some_and(Value::is_string) {
                    return Err(invalid(&format!(
                        "`{member}` is REQUIRED and MUST be a string (I-D §7.1)"
                    )));
                }
            }
            if !element.get("target_hash").and_then(Value::as_str).is_some_and(is_family_hash) {
                return Err(invalid(
                    "`target_hash` is REQUIRED, a `sha256:` family string in lowercase hex \
                     (I-D §2.1, §7.1)",
                ));
            }
        }
    }

    // I-D §7.1: `governance.rotation_proofs[]`'s own `witnesses` is "an array in the shape of
    // `anchoring.witnesses[]`", so it takes the identical treatment — for EVERY element the
    // member carries, including one the chain walk never has occasion to consume.
    if let Some(value) = governance.get("rotation_proofs") {
        let elements = value.as_array().ok_or_else(|| {
            ReceiptError::GovernanceChainInvalid(
                "`governance.rotation_proofs`, where present, MUST be an array (I-D §7.1)"
                    .to_owned(),
            )
        })?;
        for (position, element) in elements.iter().enumerate() {
            check_closed_members(
                element,
                &format!("governance.rotation_proofs[{position}]"),
                &["manifest_entry_index", "checkpoint", "inclusion_path", "witnesses"],
            )?;
            let what = format!("governance.rotation_proofs[{position}].witnesses");
            for cosignature in cosignature_array(element, "witnesses", &what)? {
                witness_cosignature_object(cosignature)?;
            }
            let what = format!("governance.rotation_proofs[{position}].inclusion_path");
            check_family_hash_path(element, "inclusion_path", &what)?;
        }
    }
    Ok(())
}

/// Require a cosignature's `witness_id` to be an identity the manifest version active for the
/// checkpoint actually declares — WHATEVER the key's source (I-D §7.1: each
/// `anchoring.witnesses[]` element carries "the witness identity as declared in the manifest").
///
/// For a `manifest-chain` key this is already implied, since the key bound to a manifest
/// witness object carrying that identity. It is not implied for a `local-policy` key: policy
/// establishes which KEY the verifier trusts, and no policy-side relation can establish that
/// the corpus's own governance ever declared the witness. Without this, a verifier holding one
/// trusted key would accept cosignatures under an identity the log's manifests never named,
/// and the L3 requirement would be satisfied by a witness outside the corpus's governance.
fn check_witness_declared(active_manifest: &Value, witness_id: &str, tree_size: u64) -> Result<()> {
    if witness_key_set(active_manifest)?.iter().any(|(declared, ..)| declared == witness_id) {
        return Ok(());
    }
    Err(ReceiptError::WitnessNotDeclared { witness_id: witness_id.to_owned(), tree_size })
}

/// The two `source` tokens I-D §7.1 admits for a key object, in the order it states them.
const KEY_SOURCES: [&str; 2] = ["manifest-chain", "local-policy"];

/// Validate the `keys` block's container shapes (I-D §7.1 "`keys`"), over EVERY entry the
/// receipt carries, before any key is resolved.
///
/// This belongs to §7.5 step 3 — "the family-string, arity, and ordering checks the container
/// shapes of Section 7.1 require" — and is separate from binding for a reason. Binding is
/// deliberately tolerant per entry ([`bind_keys_by_group`]), because one receipt legitimately
/// carries the same physical key bound to two different manifest versions; a shape defect on an
/// entry no checkpoint happens to reach for would therefore never be reported at all. Shape is
/// not tolerant: an ill-formed key object is `invalid` whether or not verification needs it.
fn check_keys_block(receipt: &Value) -> Result<()> {
    let keys = obj(receipt, "keys")?;
    check_closed_members(keys, "keys", &["log", "witness", "producer"])?;
    for group in ["log", "witness", "producer"] {
        for (position, entry) in array(keys, group)?.iter().enumerate() {
            let invalid = |detail: &str| {
                ReceiptError::Malformed(format!("`keys.{group}[{position}]`: {detail}"))
            };
            if !entry.is_object() {
                return Err(invalid("MUST be a key object (I-D §7.1)"));
            }
            if !entry.get("key_id").and_then(Value::as_str).is_some_and(is_family_hash) {
                return Err(invalid(
                    "`key_id` is REQUIRED, a `sha256:` family string in lowercase hex (I-D §7.1)",
                ));
            }
            if !entry.get("pubkey").and_then(Value::as_str).is_some_and(is_family_base64) {
                return Err(invalid(
                    "`pubkey` is REQUIRED, a `base64:` family string under the strict \
                     acceptance rule of I-D §2.1",
                ));
            }
            // I-D §7.1: "`source` is exactly one of `\"manifest-chain\"` or
            // `\"local-policy\"`." There is no third token and no default — an unrecognized
            // one is a schema failure, never a source the verifier picks on the receipt's
            // behalf. And "`local-policy` is an acceptable source only for witness keys the
            // verifier already trusts, for the genesis anchor, and for authorized dataset
            // keys": neither of the latter two is a `keys[]` entry, so within this block the
            // token is admissible in the witness group and nowhere else.
            let source = entry
                .get("source")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("`source` is REQUIRED (I-D §7.1)"))?;
            if !KEY_SOURCES.contains(&source) {
                return Err(invalid(&format!(
                    "`source` is `{source}`: I-D §7.1 admits exactly `manifest-chain` or \
                     `local-policy`"
                )));
            }
            if source == "local-policy" && group != "witness" {
                return Err(invalid(
                    "`local-policy` is an acceptable source only for witness keys (I-D §7.1)",
                ));
            }
            // "`binding` is the object `{ \"entry_index\": <integer> }`, naming the entry
            // index of the manifest statement the key is drawn from; it is REQUIRED where
            // `source` is `\"manifest-chain\"`." Two rules, and the shape is the wider one:
            // the member is REQUIRED only for one source, but WHEREVER it appears it is that
            // object, because §7.1's member shapes are normative for every member it defines
            // rather than only for the ones a given source obliges.
            match entry.get("binding") {
                None if source == "manifest-chain" => {
                    return Err(invalid(
                        "`binding` is REQUIRED where `source` is `manifest-chain` (I-D §7.1)",
                    ))
                }
                None => {}
                Some(binding) => {
                    // The object has exactly one member, and it is an entry index: a
                    // non-negative integer, so a float, a negative, or a string is not one.
                    if !binding.get("entry_index").is_some_and(Value::is_u64) {
                        return Err(invalid(
                            "`binding.entry_index` is REQUIRED and MUST be a non-negative \
                             integer (I-D §7.1)",
                        ));
                    }
                    check_closed_members(
                        binding,
                        &format!("keys.{group}[{position}].binding"),
                        &["entry_index"],
                    )?;
                }
            }
            // "A witness key object additionally carries `witness_id`, the identity under
            // which the manifest declares that witness" — unconditional about the shape, and
            // the identity it names is a manifest-declared one whatever the key's source: a
            // `local-policy` key supplies the KEY the verifier trusts, never a witness
            // identity of its own ([`check_witness_identity`]).
            if group == "witness" && !entry.get("witness_id").is_some_and(Value::is_string) {
                return Err(invalid("`witness_id` is REQUIRED on a witness key object (I-D §7.1)"));
            }
            // I-D §7.1: "a receipt-side entry carrying any member beyond those and
            // `source`/`binding` is a schema failure." The member set is CLOSED, and closing it
            // is what keeps the match meaningful: the match compares the members the two
            // objects share, so an entry free to carry others could assert alongside the
            // compared ones — `valid_from_index` among them — members nothing compares and a
            // reader might believe. Applied to every entry, selected or not, since a schema
            // failure is a property of the receipt rather than of what verification reached
            // for.
            let allowed: &[&str] = if group == "witness" {
                &["witness_id", "key_id", "pubkey", "source", "binding"]
            } else {
                &["key_id", "pubkey", "source", "binding"]
            };
            check_closed_members(entry, &format!("keys.{group}[{position}]"), allowed)?;
        }
    }
    Ok(())
}

/// `key_id -> ` [`ResolvedKey`] for `keys.log`/`keys.witness` entries that bound successfully
/// at some checkpoint's active manifest index, plus, for every `key_id` that never did, the
/// binding index its first failing entry actually carried.
type BoundAndAttempted = (BTreeMap<String, ResolvedKey>, BTreeMap<String, u64>);

/// Bind every `keys.{group}[]` entry against `active_index`, tolerantly per entry.
///
/// A `keys.log`/`keys.witness` entry that fails to bind at `active_index` is not necessarily
/// wrong: a `propagation-complete` receipt legitimately carries entries for TWO checkpoints (A
/// and D, each authenticated separately, format §2.2) that can be active under different
/// manifest versions, so the same physical key may appear twice under different bindings.
/// Binding is therefore tolerant per entry rather than all-or-nothing for the whole array: any
/// entry that binds successfully is usable; an entry that doesn't is simply not usable FOR THIS
/// CHECKPOINT, and only becomes an error if no entry for that `key_id` ever bound — in which
/// case the error still names that entry's own (wrong) binding index, not `active_index`, so a
/// genuinely mis-bound single entry is reported precisely.
///
/// Shared by [`verify_checkpoint`] (the primary `anchoring.checkpoint`) and
/// [`authenticate_checkpoint`] (`later_checkpoint` and propagation's own declared D) — every
/// receipt-borne checkpoint this crate authenticates resolves its keys the same way.
fn bind_keys_by_group(
    receipt: &Value,
    policy: &TrustPolicy,
    manifests: &[(u64, &Value)],
    active_index: u64,
    group: &str,
) -> Result<BoundAndAttempted> {
    let keys = obj(receipt, "keys")?;
    let mut bound = BTreeMap::new();
    let mut attempted_index = BTreeMap::new();
    for entry in array(keys, group)? {
        check_key_id(entry)?;
        let key_id = text(entry, "key_id")?.to_owned();
        match bind_log_or_witness_key(policy, manifests, entry, group, active_index) {
            Ok(resolved) => {
                bound.insert(key_id, resolved);
            }
            // The tolerance below is for `manifest-chain` entries only, and exists for one
            // reason: a receipt authenticating two checkpoints legitimately carries the same
            // physical key twice, bound to each checkpoint's own manifest version, so a
            // failure at THIS `active_index` is not yet a defect. Neither of these two is of
            // that kind. A `local-policy` key policy does not hold cannot bind at any active
            // index, and an unrecognized `source` is a schema failure of the entry itself;
            // tolerating either would replace a precise report with a missing-key one.
            Err(
                error @ (ReceiptError::WitnessKeyNotTrusted { .. } | ReceiptError::Malformed(_)),
            ) => return Err(error),
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
}

fn verify_checkpoint(
    receipt: &Value,
    policy: &TrustPolicy,
    governance: &Governance<'_>,
    profile: &AdaptorProfile,
    profile_id: &str,
    continued_history: bool,
    run: &mut Run,
) -> Result<Anchoring> {
    let anchoring = obj(receipt, "anchoring")?;
    let checkpoint = checkpoint_object(obj(anchoring, "checkpoint")?)?;
    let tree_size = number(checkpoint, "tree_size")?;
    let (active_index, active_manifest) = governance.active_for(tree_size)?;
    let active_log = log_object(active_manifest)?;

    // I-D §3.2: `anchoring.adaptor` must name the SAME profile the active manifest's own
    // `log.adaptor` pins — checked before ANYTHING profile-specific, `raw` reconciliation and
    // signature verification both included.
    check_adaptor_binding(active_log, profile_id, profile)?;

    // The log id must match the manifest version active for the checkpoint (adaptor §5).
    if text(active_log, "log_id")? != text(checkpoint, "log_id")? {
        return Err(ReceiptError::GovernanceChainInvalid(
            "checkpoint `log_id` is not the log the active manifest declares".to_owned(),
        ));
    }

    let (log_keys, log_attempted) =
        bind_keys_by_group(receipt, policy, &governance.manifests, active_index, "log")?;
    let (witness_keys, witness_attempted) =
        bind_keys_by_group(receipt, policy, &governance.manifests, active_index, "witness")?;

    let signing_key = log_keys.get(text(checkpoint, "key_id")?).ok_or_else(|| {
        let key_id = text(checkpoint, "key_id").unwrap_or_default().to_owned();
        let entry_index = log_attempted.get(&key_id).copied().unwrap_or(active_index);
        ReceiptError::KeyNotBound { key_id, entry_index }
    })?;
    run.spend(1)?;
    if !verify_signature(
        &decode_pubkey(&signing_key.pubkey)?,
        &checkpoint_signing_bytes_for(checkpoint, profile_id)?,
        text(checkpoint, "signature")?,
    )? {
        return Err(ReceiptError::CheckpointSignatureInvalid);
    }

    let mut witnessed = false;
    for cosignature in cosignature_array(anchoring, "witnesses", "anchoring.witnesses")? {
        let cosignature = witness_cosignature_object(cosignature)?;
        let witness_id = text(cosignature, "witness_id")?.to_owned();
        let key_id = text(cosignature, "key_id")?;
        let resolved = witness_keys.get(key_id).ok_or_else(|| ReceiptError::KeyNotBound {
            key_id: key_id.to_owned(),
            entry_index: witness_attempted.get(key_id).copied().unwrap_or(active_index),
        })?;
        check_witness_identity(resolved, key_id, &witness_id)?;
        check_witness_declared(active_manifest, &witness_id, tree_size)?;
        run.spend(1)?;
        if !verify_signature(
            &decode_pubkey(&resolved.pubkey)?,
            &cosignature_bytes(checkpoint, &witness_id),
            text(cosignature, "cosignature")?,
        )? {
            return Err(ReceiptError::WitnessCosignatureInvalid { witness_id });
        }
        witnessed = true;
    }
    // I-D §3.3, §7.5: "At L3 a verifier accepts a checkpoint C only with a valid witness
    // cosignature" — `active_manifest`'s `level` is already known to be exactly one of
    // `L1`/`L2`/`L3` ([`manifest_scope_fields`] ran during `read_chain`), so this reads it
    // rather than re-deriving anything.
    if active_manifest.get("level").and_then(Value::as_str) == Some("L3") && !witnessed {
        return Err(ReceiptError::CheckpointUnwitnessed { tree_size });
    }

    // 4f applies to `later_checkpoint` on the same terms, against the manifest version active
    // for ITS tree size. Its consistency path was recomputed in step 3, unauthenticated; this
    // is what makes both roots the log's.
    if continued_history {
        authenticate_continued_history(
            receipt, policy, governance, anchoring, profile, profile_id, run,
        )?;
    }

    Ok(Anchoring { witnessed, continued_history })
}

/// The key-independent half of `continued_history` (I-D §7.5 step 3: "`consistency_path`
/// recomputes between `anchoring.checkpoint.root_hash` and `later_checkpoint.root_hash` where
/// `continued_history` is asserted"), returning whether a later checkpoint is carried at all.
///
/// Three things have to hold before the claim can be about anything, and each is decidable
/// with no key in hand:
///
/// 1. **Both members are present.** §2.3 states the equivalence — `continued_history` is true
///    *iff* `later_checkpoint` and `consistency_path` verify — so a later checkpoint with no
///    proof, or a proof with no checkpoint, is malformed rather than a weaker claim. §7.1 adds
///    `later_witnesses`, present if and only if `later_checkpoint` is.
/// 2. **The later checkpoint takes the receipt-borne shape**, and is not SMALLER than the one
///    the subject is included under: a "later" checkpoint at a smaller tree size proves no
///    continued history at all; it is the size regression a witness refuses to cosign over.
/// 3. **The proof verifies**, as an RFC 9162 §2.1.4 consistency proof from the subject
///    checkpoint's `(tree_size, root_hash)` to the later checkpoint's. A proof that is
///    structurally impossible for that pair of sizes is a failed proof, not a different error:
///    a proof generated for some other pair must never validate a claim about this one.
///
/// What this establishes is a statement about CARRIED BYTES, exactly as every other step-3
/// path result is: both roots are still unauthenticated structural commitments here.
/// [`authenticate_continued_history`] is what makes them the log's, and only then does the
/// claim's boundary begin. Even then it stops there: a consistency proof shows one tree is an
/// append-only extension of another; it does not show that a checkpoint the cadence required
/// was ever published (core spec §7.3), and no verdict rendered from it may say otherwise.
fn check_continued_history_paths(
    anchoring: &Value,
    from_size: u64,
    from_root: &Hash,
    run: &mut Run,
) -> Result<bool> {
    match (anchoring.get("later_checkpoint"), anchoring.get("consistency_path")) {
        (None, None) => {
            // I-D §7.1: `later_witnesses` is "Present if and only if `later_checkpoint` is
            // carried" — checked here too, before either member's own content is read, so a
            // stray `later_witnesses` with no `later_checkpoint` at all cannot slip past this
            // gate unexamined.
            if anchoring.get("later_witnesses").is_some() {
                return Err(ReceiptError::Malformed(
                    "`anchoring.later_witnesses` is present without `later_checkpoint` (I-D \
                     §7.1: present if and only if `later_checkpoint` is carried)"
                        .to_owned(),
                ));
            }
            return Ok(false);
        }
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
    if anchoring.get("later_witnesses").is_none() {
        return Err(ReceiptError::Malformed(
            "`anchoring.later_witnesses` is REQUIRED whenever `later_checkpoint` is carried \
             (I-D §7.1)"
                .to_owned(),
        ));
    }

    let later = checkpoint_object(obj(anchoring, "later_checkpoint")?)?;
    let to_size = number(later, "tree_size")?;
    if to_size < from_size {
        return Err(ReceiptError::ConsistencyPathInvalid);
    }
    let to_root = parse_hash_hex(text(later, "root_hash")?)?;
    let path = path_strings(anchoring, "consistency_path")?;
    let proof = crate::consistency_from_hex(from_size, to_size, &path)?;
    run.spend(1)?;
    match crate::verify_consistency_proof(&proof, from_root, &to_root) {
        Ok(true) => Ok(true),
        // `Ok(false)` is a proof that does not open the pair; `Err` is a proof that could not
        // exist for these sizes at all. Neither establishes continued history, and reporting
        // them apart would only invite treating the second as a transport problem.
        Ok(false) | Err(_) => Err(ReceiptError::ConsistencyPathInvalid),
    }
}

/// The authenticated half of `continued_history` (I-D §7.5.1 4f: "`later_checkpoint` and its
/// cosignatures in `anchoring.later_witnesses[]` are validated the same way against the
/// manifest version active for ITS tree size").
///
/// Its log signature is verified against a key declared by the manifest version active for
/// **its own** `tree_size`, not the subject checkpoint's (§7.1): a key a later manifest
/// replaced must not validate a checkpoint issued under the later state, and the reverse is
/// equally true. Its cosignatures are validated against that same version's witness set.
///
/// Called only where [`check_continued_history_paths`] has already established that both
/// members are carried and that the consistency path opens the pair.
// `profile`/`profile_id` thread the §7.1 raw-checkpoint reconciliation into
// `authenticate_checkpoint`, identically to every other receipt-borne checkpoint this crate
// reads; bundling them would only rename this list.
#[allow(clippy::too_many_arguments)]
fn authenticate_continued_history(
    receipt: &Value,
    policy: &TrustPolicy,
    governance: &Governance<'_>,
    anchoring: &Value,
    profile: &AdaptorProfile,
    profile_id: &str,
    run: &mut Run,
) -> Result<()> {
    let later = checkpoint_object(obj(anchoring, "later_checkpoint")?)?;
    authenticate_checkpoint(receipt, policy, governance, later, profile, profile_id, run)?;
    verify_later_witnesses(receipt, policy, governance, anchoring, later, run)
}

/// Verify an inclusion path carried bare (adaptor profile §2.3) against a root.
fn check_inclusion(
    leaf: &[u8],
    leaf_index: u64,
    tree_size: u64,
    path: &[String],
    root: &Hash,
    what: &'static str,
    run: &mut Run,
) -> Result<()> {
    run.spend(1)?;
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

/// Decode enumeration material and authenticate it against the checkpoint root.
///
/// This is KEY-INDEPENDENT work of exactly the class I-D §7.5 step 3 collects — "Each is an
/// integer comparison or a hash recomputation" — so it can, and for governance currency MUST,
/// run before any signature is verified: §7.5.1 4b walks "the manifest statements of
/// `governance.chain[]`, merged in entry-index order with the `key` statements the enumeration
/// material carries", which makes those statements an INPUT to the induction rather than
/// something the induction produces. As in step 3, `root` is at this point an unauthenticated
/// structural commitment; 4f is what upgrades every result here from a statement about carried
/// bytes to a statement about the log's state.
fn decode_enumeration(
    material: &Value,
    root: &Hash,
    tree_size: u64,
    what: &'static str,
    run: &mut Run,
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
        // I-D §7.5 step 1 / §7.1: "A verifier MUST likewise check each carried statement's
        // `ahl_version` BEFORE VALIDATING THAT STATEMENT. Any value other than `0.4` yields
        // `unverifiable`." That is a version READ, decided from the bytes alone and reaching
        // no conclusion about the statement, and §7.1 places it ahead of everything the
        // document defines — so it stays here, at the decode, rather than moving behind a
        // signature. Nothing else about the payload is looked at: §2.2's common payload
        // fields are TYPE-SPECIFIC VALIDATION, which 4b's phase discipline forbids on
        // material whose signature has not verified, so they run in phase 2 — inside the
        // induction for a `key` statement, and after 4d for every other enumerated envelope
        // ([`verify_enumerated_envelopes`]).
        let entry_payload = payload_of(envelope)?;
        check_ahl_version(entry_payload)?;
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
    run.spend(u64::try_from(envelopes.len()).unwrap_or(u64::MAX).saturating_add(1))?;
    let leaves: Vec<Vec<u8>> = envelopes.iter().map(jcs).collect();
    if !range_proof::verify_over_leaves(&proof, &leaves, root)? {
        return Err(ReceiptError::RangeProofInvalid {
            what,
            detail: "recomputed root differs from the checkpoint root".to_owned(),
        });
    }

    Ok(Enumeration { from_index, to_index, entries: envelopes })
}

/// I-D §7.5.1 4d over material [`decode_enumeration`] has already authenticated.
fn verify_enumerated_envelopes(
    enumeration: &Enumeration,
    governance: &Governance<'_>,
    run: &mut Run,
) -> Result<()> {
    // I-D §7.5.1 4d: with K established, every carried envelope that is NOT part of the
    // induction is verified under the envelope signature rule of §2.1 at ITS OWN entry index —
    // enumerated material included, and no subset of it. "An envelope carrying a non-verifying
    // entry, or an entry naming a key not active at that index, is invalid however many other
    // entries verify... Failure is `invalid`." So a non-verifying envelope anywhere in an
    // enumerated range invalidates the run; it is never skipped as uninteresting and never
    // downgraded to a challenge. §8.4 puts it as two tests in order — "Validity and
    // authorization are separate tests, applied in that order" — so only a VALID envelope is
    // ever tested for authority, and a challenge is a valid envelope whose signers hold no
    // authority, never an unreadable one.
    //
    // This runs after the range proof, so every envelope verified here has already been shown
    // to be the entry the log committed at that index, rather than carried bytes claiming to
    // be. It is the one choke point all three enumerated forms pass through — governance
    // currency, competing-trigger candidates, and the propagation-completeness prefix.
    for (offset, envelope) in enumeration.entries.iter().enumerate() {
        // 4d's scope is "every carried envelope that is NOT part of the induction", and the
        // exclusion is load-bearing rather than a convenience. A `manifest` or `key` statement
        // was already verified by [`read_chain`] under 4b phase 1, "against K AS ESTABLISHED SO
        // FAR — the governance state in force immediately before this statement's own entry
        // index", and its effect applied only afterwards (phase 3). Verifying it a second time
        // under COMPLETED K at its own index applies a different state to the same envelope: a
        // `key` statement retiring the very key that signed it is conforming — it is signed
        // under the pre-effect state — yet post-effect that key is no longer resolvable at that
        // index, so the second check would reject a statement the induction accepted. Deciding
        // 4d by the state that already includes a statement's own effect is not what 4b/4d
        // ask for.
        //
        // Membership is decided by statement TYPE, not by position in the range: 4b walks
        // exactly the `manifest` and `key` statements, whatever indexes they occupy. The
        // enumerated `key` statements ARE the induction's second stream, so every one of them
        // has been through 4b phase 1 by construction, and [`check_manifest_completeness`]
        // separately requires every enumerated `manifest` to appear in the chain the induction
        // walked — under enumerated mode over `[0, tree_size(C))`, a superset of every other
        // enumerated range, and before 4d runs at all. Nothing is exempted here that the
        // induction has not already verified.
        if matches!(statement_type_literal(envelope), Some("manifest" | "key")) {
            continue;
        }
        let index = enumeration.from_index + offset as u64;
        verify_envelope_at(envelope, governance, index, run)?;
        // Phase 2 for a non-induction enumerated envelope, and strictly after 4d's signature:
        // I-D §7.5.1 4b states the three-phase order "for both types" of governance statement,
        // and the reason it gives is general — "Type-specific validation MUST NOT run on
        // material whose signature has not verified... Running that work first lets anyone able
        // to hand a verifier a receipt drive it." Nothing about that argument is peculiar to
        // governance statements, so §2.2's common payload fields are checked here rather than
        // at the decode. This remains the one choke point all three enumerated forms pass
        // through — governance currency, competing-trigger candidates, and the
        // propagation-completeness prefix — before any claim-specific check reads a payload.
        common_payload_fields(payload_of(envelope)?)?;
    }

    Ok(())
}

/// All three enumerated forms that are read AFTER K exists: decode, authenticate, then 4d.
fn verify_enumeration(
    material: &Value,
    governance: &Governance<'_>,
    root: &Hash,
    tree_size: u64,
    what: &'static str,
    run: &mut Run,
) -> Result<Enumeration> {
    let enumeration = decode_enumeration(material, root, tree_size, what, run)?;
    verify_enumerated_envelopes(&enumeration, governance, run)?;
    Ok(enumeration)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Read the two container versions and act on them, per I-D §7.5 step 1.
///
/// Both are read before anything else because revision 0.4 "verifies no material issued under
/// any earlier revision" (§2.2, §7.1): a version this build does not implement is a capability
/// gap, [`ReceiptError::UnsupportedVersion`] — `unverifiable` under §7.7, never `invalid` —
/// and no rule this document states applies to the rest of the bytes.
fn check_receipt_versions(receipt: &Value) -> Result<()> {
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
    Ok(())
}

/// Verify an Evidence Receipt against locally configured policy, and report the §7.7 result
/// with the findings it reduces from.
///
/// Implements I-D §7.5's algorithm in the order it fixes: step 1, versions before anything
/// else, then parsing, the §7.8 limits and identifier recomputation; step 2, adaptor-profile
/// resolution; step 3, the key-independent structural and path checks over the whole carried
/// document, no signature among them; step 4, the governance bootstrap of §7.5.1 as an
/// induction from the configured genesis anchor, with the authenticated checkpoint validation
/// of 4f; step 5, the claim-material requirements of §7.2; step 6, the cross-field rules of
/// §7.6; and step 7, the result of §7.7 together with the boundary rendered from it, never
/// stronger than what was proven.
///
/// # What the report contains
///
/// [`Report::result`] is the scalar value of §7.7 — one receipt, one value — and
/// [`Report::findings`] is the per-assertion detail §7.7 requires a verifier to report
/// alongside it, since "the result alone does not say which assertion produced it". A finding
/// is never a result: a receipt whose content binding is `unverifiable` reports `unverifiable`
/// as its result AND `verified` on the assertions that did hold.
///
/// How far the findings go depends on what stopped the run. An `invalid` finding decides the
/// result, so the run ends there and the assertions after it are not reported at all. An
/// `unverifiable` finding does not decide it — `invalid` still dominates — so the run carries
/// on wherever the assertions left do not rest on the material it was short of, and where they
/// do, each is reported `unverifiable` naming that prerequisite. Two conditions end the run
/// even so: an unsupported version, which §7.5 step 1 follows with "no further processing", and
/// an exhausted verifier-local budget, which §7.8 requires to fail closed.
///
/// [`Report::verdict`] is present if and only if the result is [`Outcome::Verified`]: §7.7
/// permits only that value to be "rendered in words that assert the property", and no result is
/// ever represented by rewriting the receipt's own assurance fields.
///
/// # Errors
///
/// Returns [`ExecutionError`] for a run that did not COMPLETE, which is not a statement about
/// the receipt and carries none of the three values (§7.7). This build reaches no such
/// condition today: every rejection it can produce is a completed run reported through
/// [`Report::result`].
pub fn verify_receipt_report(
    receipt: &Value,
    policy: &TrustPolicy,
) -> core::result::Result<Report, ExecutionError> {
    let mut run = Run::new(policy.limits);
    let outcome = verify_root(receipt, policy, &mut run);
    Ok(run.into_report(outcome, receipt))
}

/// Verify an Evidence Receipt against locally configured policy.
///
/// The single-value form of [`verify_receipt_report`], for callers that report one rejection
/// rather than a report: `Ok` if and only if the §7.7 result is [`Outcome::Verified`], and
/// otherwise the rejection behind the finding that decided the result — the `invalid` one if
/// there is one, since `invalid` dominates, and otherwise the first `unverifiable` one.
///
/// The findings themselves are not reachable through this signature, so a caller that must
/// distinguish `invalid` from `unverifiable`, or show which assertion produced the result,
/// wants [`verify_receipt_report`]. [`ReceiptError::class`] gives the value of a single
/// rejection.
///
/// # Errors
///
/// Returns the [`ReceiptError`] variant naming the rule that decided the result.
pub fn verify_receipt(receipt: &Value, policy: &TrustPolicy) -> Result<Verdict> {
    let mut run = Run::new(policy.limits);
    let verdict = verify_root(receipt, policy, &mut run)?;
    // A rejection the run recorded and carried on from still decides the result, and this
    // signature has exactly one way to report it.
    run.dominating_deferred().map_or(Ok(verdict), Err)
}

/// The §7.5 algorithm over the outermost receipt, shared by both entry points.
fn verify_root(receipt: &Value, policy: &TrustPolicy, run: &mut Run) -> Result<Verdict> {
    // I-D §7.5 step 1: "Read `ahl_receipt_version` and act on it BEFORE ANY OTHER CHECK,
    // including schema validation... THEN parse the receipt, enforce the resource limits of
    // Section 7.8." The order decides what the holder of a receipt is told. A version this
    // build does not implement is `unverifiable` under §7.7 at ANY size, and reporting the
    // decoded-size budget first would send its holder to produce a smaller receipt that this
    // verifier would refuse just the same — a verifier-local budget presented as the reason a
    // fixed capability gap stopped the run.
    //
    // This crate is handed an ALREADY-PARSED document, so the parse-size cap §7.8 places
    // before that read has no work left to bound here: the decision costs two member lookups
    // on a parsed object, and nothing is decoded, canonicalized or hashed to reach it. The
    // §7.8 decoded-size budget — the verifier-local one, measured over the whole receipt's
    // canonical form — is enforced immediately afterwards, still ahead of every semantic and
    // cryptographic check, which is where the rest of step 1 puts it.
    check_receipt_versions(receipt)?;
    let encoded = jcs(receipt);
    if encoded.len() > policy.limits.max_decoded_bytes {
        return Err(ReceiptError::BudgetExhausted {
            budget: DECODED_SIZE_BUDGET,
            in_force: policy.limits.max_decoded_bytes as u64,
        });
    }
    let verdict = verify_nested(receipt, policy, run, 0)?;
    Ok(Verdict { embedded_receipts: run.embedded, ..verdict })
}

/// Verify a receipt at nesting `depth`, sharing the whole tree's resource budget.
// The §7.5 algorithm is a fixed ordered sequence of steps; splitting it into helpers that each
// take the growing set of intermediate results would obscure the order the I-D mandates.
#[allow(clippy::too_many_lines)]
fn verify_nested(
    receipt: &Value,
    policy: &TrustPolicy,
    run: &mut Run,
    depth: usize,
) -> Result<Verdict> {
    // --- §7.5 step 1: versions, identifiers -----------------------------------------
    // Re-read here rather than assumed from the caller: an embedded receipt reaches this
    // function without passing through [`verify_receipt`], and §7.5 step 1's rule is about
    // every receipt, the embedded ones included (§7.1).
    //
    // It runs BEFORE [`Run::enter`], because §7.5 step 1 is explicit about the order — "Read
    // `ahl_receipt_version` and act on it before any other check, including schema validation.
    // THEN parse the receipt, enforce the resource limits of Section 7.8" — and the two
    // outcomes are not interchangeable at any depth. An unsupported version is a fixed property
    // of the artifact, `unverifiable` under §7.7 for every verifier; the nesting-depth and
    // embedded-count caps are §7.8 limits this verifier reports as `invalid`. Entering first
    // would tell the holder of a deeply nested receipt of an unsupported revision that the
    // nesting is the defect, and a verifier configured with a deeper limit would then report
    // the version instead — two verifiers contradicting each other over one artifact. The read
    // itself is two member lookups on an already-parsed object, so nothing is decoded, hashed
    // or recursed into ahead of the budget it precedes.
    check_receipt_versions(receipt)?;
    run.enter(depth)?;
    // The dependence I-D §7.7 draws between findings is between the assertions of ONE receipt,
    // so each receipt starts with none and the enclosing receipt's state is put back before
    // this one's verdict is returned.
    let enclosing_block = run.blocked.take();

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
    // Step 1 is settled for this receipt. Both assertions stay open to a later rejection —
    // an enumerated statement's own `ahl_version`, or a budget exhausted deeper in the run —
    // and [`Run::record`] keeps the dominating outcome where one arrives.
    run.pass(Assertion::Versions);
    run.pass(Assertion::ResourceLimits);

    // --- §7.5 step 2: adaptor profile ---------------------------------------------
    // I-D §3.2, §7.5 step 2: "MUST recompute the digest over the artifact rather than trusting
    // any value carried with it, and MUST reject a receipt whose pinned digest does not match
    // the artifact held." Two DIFFERENT facts, two DIFFERENT outcomes: the profile id itself
    // not being held at all is `unverifiable` ([`ReceiptError::AdaptorUnknown`]); the profile
    // being held but its RECOMPUTED digest disagreeing with what the receipt pins is `invalid`
    // ([`ReceiptError::AdaptorHashMismatch`]) — the receipt names a document policy can prove
    // is not the one it trusts, never conflated into the same outcome as simply not knowing
    // the profile.
    let adaptor = obj(obj(receipt, "anchoring")?, "adaptor")?;
    let adaptor_id = text(adaptor, "id")?;
    let profile = policy
        .adaptor_profiles
        .get(adaptor_id)
        .ok_or_else(|| ReceiptError::AdaptorUnknown { id: adaptor_id.to_owned() })?;
    if profile.hash() != text(adaptor, "hash")? {
        return Err(ReceiptError::AdaptorHashMismatch { id: adaptor_id.to_owned() });
    }
    // The held document is the one the receipt names; whether this build can INTERPRET a
    // receipt under that profile is the next question, and it is answered from the id alone
    // (see [`check_profile_supported`]) — before the governance induction, never after it.
    check_profile_supported(adaptor_id)?;
    // I-D §7.1, §7.5 step 2: "WHERE `raw` is carried it MUST parse to the same values" — a
    // capability boolean is not itself reconciliation. This build wires NO profile's `raw`
    // parser into the verifier ([`TEST_ADAPTOR_PROFILE_ID`]'s own doc comment), so a policy
    // asserting `checkpoint_raw: true` for ANY profile can never make good on that claim, and
    // is refused here, once, as a POLICY defect — never silently downgraded to "accept `raw`
    // unparsed" for every receipt this policy verifies.
    if profile.capabilities.checkpoint_raw {
        return Err(ReceiptError::AdaptorProfileMisconfigured {
            id: adaptor_id.to_owned(),
            capability: "a binary checkpoint framing for `checkpoint.raw`",
        });
    }

    // I-D §7.1, §7.5 step 2: `continued_history` needs a consistency proof, and a profile
    // that defines no serialization for one cannot supply it. That is a fact about the pinned
    // profile and the receipt's own members, so it belongs to profile resolution — decided
    // before step 3 reads the path it would have to recompute, and reported as unverifiable
    // under that profile rather than as a defect in the proof.
    let anchoring_block = obj(receipt, "anchoring")?;
    if (anchoring_block.get("later_checkpoint").is_some()
        || anchoring_block.get("consistency_path").is_some())
        && !profile.capabilities.consistency_proofs
    {
        return Err(ReceiptError::AdaptorCapabilityUnsupported {
            id: adaptor_id.to_owned(),
            capability: "a consistency-proof serialization for `anchoring.later_checkpoint`",
        });
    }

    // I-D §7.5 step 2: "Where a raw checkpoint form is carried… verify that it parses to the
    // same values as the JSON members." Profile-dependent and key-independent, so it belongs
    // with profile resolution — decided before step 3 reads a path and long before any
    // signature is checked.
    reconcile_anchoring_raw(anchoring_block, adaptor_id)?;
    run.pass(Assertion::AdaptorProfile);

    // --- §7.5 step 3: key-independent structural and path checks --------------------
    // "No signature and no cosignature is verified in this step." The checkpoint's own members
    // are read here only as the structural commitment the carried material is bound to; that
    // the log issued this root is established at 4f and nowhere earlier.
    check_container_shapes(receipt)?;
    run.pass(Assertion::Structure);
    let checkpoint = checkpoint_object(obj(anchoring_block, "checkpoint")?)?;
    let tree_size = number(checkpoint, "tree_size")?;
    let root = parse_hash_hex(text(checkpoint, "root_hash")?)?;
    check_key_independent_paths(receipt, envelope, subject_index, tree_size, &root, run)?;
    let continued_history = check_continued_history_paths(anchoring_block, tree_size, &root, run)?;
    run.pass(Assertion::Anchoring);

    // Still step 3, and the last of it: the governance currency mode, and — under `enumerated`
    // — the currency material itself, decoded and recomputed against `root`.
    //
    // The mode is a container token, and the two facts read from it here are both decidable
    // without a key. The material has to be in hand this early because I-D §7.5.1 4b walks
    // "the manifest statements of `governance.chain[]`, MERGED in entry-index order with the
    // `key` statements the enumeration material carries": those statements are an INPUT to the
    // induction, and §7.4 makes enumeration material their only carrier. What runs here is a
    // range-proof recomputation against the same `root_hash` step 3's inclusion paths run
    // against, on the same terms — an unauthenticated structural commitment, upgraded wholesale
    // by 4f — so it precedes every signature without making any signature's outcome depend on
    // material no key vouches for.
    let currency = obj(obj(receipt, "governance")?, "currency")?;
    let mode = text(currency, "mode")?;
    if !GOVERNANCE_MODES.contains(&mode) {
        return Err(ReceiptError::Malformed(format!("unknown governance mode `{mode}`")));
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
    // conflict rather than pretending some rule failed — and refused BEFORE the material is
    // decoded, since it is a contradiction between two members of the container alone.
    // Declared mode is unaffected: it makes no currency claim in the first place (§2.1).
    if mode == "enumerated" && anchoring_block.get("later_checkpoint").is_some() {
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
    let currency_enumeration = match mode {
        "enumerated" => Some(decode_governance_enumeration(currency, &root, tree_size, run)?),
        // I-D §7.4: "`governance.chain[]` carries manifest statements; producer-key transitions
        // are `key` statements, and those reach a verifier only through enumeration material."
        // Declared mode carries none, so the induction's second stream is empty and the key
        // state is exactly what the presented chain implies (§7.5.1 4c).
        _ => None,
    };
    let key_statements =
        currency_enumeration.as_ref().map_or_else(Vec::new, enumerated_key_statements);

    // --- §7.5 step 4: the governance bootstrap, as an induction (4a-4c) -------------
    let governance = read_chain(receipt, policy, profile, adaptor_id, &key_statements, mode, run)?;
    // 4c under enumerated governance: what the induction walked is everything the range holds.
    if let Some(enumeration) = &currency_enumeration {
        check_manifest_completeness(enumeration, &governance)?;
    }
    run.pass(Assertion::Governance);

    // --- §7.5.1 4f: authenticated checkpoint validation -----------------------------
    // Only on passing this do step 3's path results become claims about the log's state
    // rather than about carried bytes.
    let anchoring = verify_checkpoint(
        receipt,
        policy,
        &governance,
        profile,
        adaptor_id,
        continued_history,
        run,
    )?;
    run.pass(Assertion::CheckpointAuthentication);

    // --- §7.5.1 4d: the remaining carried envelopes ---------------------------------
    // The subject's own envelope is verified separately, against K FINAL at ITS OWN entry
    // index (I-D §7.5.1 4d "remaining carried envelopes") — a later, distinct step from the
    // induction above, not a repetition of it.
    // I-D §7.4 makes one rejection here `unverifiable` rather than `invalid`: a declared-mode
    // envelope naming a producer key that mode does not carry. §7.7's reduction is over every
    // required finding, and `invalid` dominates `unverifiable`, so the run records that finding
    // and carries on — the assertions after it rest on the same unresolved key and are reported
    // as resting on it, while a defect reached later still decides the result.
    let envelope_outcome = verify_envelope_at(envelope, &governance, subject_index, run);
    let envelope_valid = run.tolerate(envelope_outcome)?;
    // I-D §2.2's common payload fields, checked only now that the subject's own signature has
    // verified — the same rule chain hops get, applied to the one carried envelope that is
    // never itself a chain hop.
    common_payload_fields(payload)?;
    // Every producer key the receipt lists must be in force at the subject's entry index under
    // the §7.2 snapshot rule, bound to the governance statement that put it there (§2.2).
    bind_producer_keys(receipt, &governance, subject_index)?;
    if envelope_valid.is_some() {
        run.pass(Assertion::EnvelopeValidity);
    }

    // --- §2.1 / §4: governance currency ---------------------------------------------
    let claim = obj(receipt, "claim")?;
    let claim_type = text(claim, "type")?.to_owned();
    let assurance = read_assurance(obj(claim, "assurance")?, &claim_type)?;
    if assurance.governance != mode {
        return Err(ReceiptError::AssuranceMismatch { field: "governance" });
    }
    if assurance.witnessed != anchoring.witnessed {
        return Err(ReceiptError::AssuranceMismatch { field: "witnessed" });
    }
    if assurance.continued_history != anchoring.continued_history {
        return Err(ReceiptError::AssuranceMismatch { field: "continued_history" });
    }

    // §7.5.1 4d over the currency material. The decode and the range checks already ran at
    // step 3, because the induction consumed the `key` statements they authenticate; what is
    // left is the envelope-signature rule over the enumerated entries the induction did NOT
    // walk, which needs the completed K and therefore belongs here.
    let enumeration = match &currency_enumeration {
        None => {
            if !DECLARED_MODE_TYPES.contains(&claim_type.as_str()) {
                return Err(ReceiptError::AssuranceMismatch { field: "governance" });
            }
            None
        }
        Some(enumeration) => {
            verify_enumerated_envelopes(enumeration, &governance, run)?;
            Some(enumeration)
        }
    };

    // --- §2.3 / I-D §7.6: subject-level cross-field consistency ----------------------
    // I-D §7.1: `subject.manifest` is `"sha256:<manifest version id>"`. Read once, strictly:
    // an ill-typed member read as PRESENT for the presence rule below and then as ABSENT by a
    // later `as_str` would skip the binding check that authenticates the copy entirely.
    let carried_manifest = match subject.get("manifest") {
        None => None,
        Some(Value::String(value)) if is_family_hash(value) => Some(value.as_str()),
        Some(_) => {
            return Err(ReceiptError::Malformed(
                "`subject.manifest`, where present, is a `sha256:` manifest version id under \
                 the strict acceptance rule (I-D §2.1, §7.1)"
                    .to_owned(),
            ))
        }
    };
    let manifest_declared = carried_manifest.is_some();
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
    if let Some(claimed) = carried_manifest {
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
    // The §7.6 rules decidable from the container alone are settled; the ones over embedded
    // material are reached inside step 5 and, where one of them fires, replace this finding.
    run.pass(Assertion::CrossField);

    // --- §7.5 step 5: the §7.2 claim-material requirements --------------------------
    let ctx = ClaimCtx {
        receipt,
        policy,
        governance: &governance,
        anchoring_checkpoint: obj(obj(receipt, "anchoring")?, "checkpoint")?,
        profile,
        profile_id: adaptor_id,
        payload,
        subject_index,
        claim_type: &claim_type,
        assurance: &assurance,
        record_subject: record_subject.as_ref(),
        enumeration,
        depth,
    };
    verify_claim_material(&ctx, run)?;
    run.pass(Assertion::ClaimMaterial);
    // I-D §7.7: the content binding is a required assertion "if and only if its own
    // `assurance.content_binding` is not `none`". Where it is required and the run reached the
    // end of claim material without recording it, it held.
    if assurance.content_binding != "none" {
        run.pass(Assertion::ContentBinding);
    }
    run.blocked = enclosing_block;

    Ok(Verdict {
        boundary: render(&claim_type, &assurance),
        claim_type,
        subject_entry_index: subject_index,
        subject_statement_id: text(subject, "statement_id")?.to_owned(),
        assurance,
        embedded_receipts: run.embedded,
    })
}

/// Claim types whose §7.2 material carries the competing-trigger range.
///
/// `trigger-effective` carries it directly — its row is "`trigger-declared` material plus
/// `{ \"checkpoint_C\", \"competing\": { \"corpus_range\" } }`", and it "REQUIRES
/// `governance: \"enumerated\"` and `competing_triggers: \"enumerated\"`". The other two carry
/// it through the embedded `trigger-effective` receipt §7.2 REQUIRES of them, which is verified
/// in full, range included; §7.2 does not itself require the token of them, so for those two
/// the value is PERMITTED rather than mandatory. Every other type carries no such range in any
/// of its material, so §7.6's "only where the range required by Section 7.2 is present" makes
/// `enumerated` an assertion nothing in the receipt could support.
const COMPETING_RANGE_TYPES: [&str; 3] =
    ["trigger-effective", "disposition-effective", "propagation-complete"];

/// The claim types whose §7.2 material carries record bytes at all — the only two a content
/// binding can be about.
///
/// Both rows carry `record_bytes`/`output_bytes` "if and only if `content_binding` is not
/// `none`". No other row carries content evidence in any form, so a non-`none` binding on one
/// of them is, in §7.6's words, "a combination the type cannot satisfy", and is `invalid`
/// rather than downgraded. A `trigger-*` receipt's content evidence lives in its EMBEDDED
/// `record-*` receipt, which carries its own assurance block and is verified as its own claim.
const CONTENT_EVIDENCE_TYPES: [&str; 2] = ["record-ingested", "record-derived"];

/// The `declared` governance mode of I-D §7.4: chain validity from genesis only, carrying no
/// producer-key transitions.
const DECLARED_MODE: &str = "declared";

/// The two governance modes of I-D §7.4.
const GOVERNANCE_MODES: [&str; 2] = [DECLARED_MODE, "enumerated"];

/// The two competing-trigger values of I-D §7.3.
const COMPETING_TRIGGER_VALUES: [&str; 2] = ["not-checked", "enumerated"];

/// The three content-binding values of I-D §7.3.
const CONTENT_BINDINGS: [&str; 3] = ["none", "plain-verified", "keyed-authorized"];

/// Read `claim.assurance`, holding every member to the domain I-D §7.3 gives it and to the
/// claim types §7.2's material can satisfy (§7.6).
///
/// Centralised deliberately. Each member used to be validated wherever some path first read
/// it, which left the members that path never reaches unchecked: a `statement-anchored` receipt
/// could assert `competing_triggers: \"enumerated\"` or `content_binding: \"plain-verified\"`
/// and be accepted, because nothing in that claim type's verification looks at either. §7.3
/// gives every member a closed domain and §7.6 ties two of them to the claim type, and both are
/// decidable from the receipt's own bytes the moment the block is read.
///
/// `witnessed` and `continued_history` are booleans, so [`flag`] IS their domain check; each is
/// then compared against what verification actually established, which no token check could do.
fn read_assurance(assurance: &Value, claim_type: &str) -> Result<Assurance> {
    let mismatch = |field: &'static str| ReceiptError::AssuranceMismatch { field };

    let governance = text(assurance, "governance")?.to_owned();
    if !GOVERNANCE_MODES.contains(&governance.as_str()) {
        return Err(mismatch("governance"));
    }

    let competing_triggers = text(assurance, "competing_triggers")?.to_owned();
    if !COMPETING_TRIGGER_VALUES.contains(&competing_triggers.as_str()) {
        return Err(mismatch("competing_triggers"));
    }
    match (competing_triggers.as_str(), claim_type) {
        // §7.2: `trigger-effective` "REQUIRES ... `competing_triggers: \"enumerated\"`".
        (value, "trigger-effective") if value != "enumerated" => {
            return Err(mismatch("competing_triggers"))
        }
        ("enumerated", other) if !COMPETING_RANGE_TYPES.contains(&other) => {
            return Err(mismatch("competing_triggers"))
        }
        _ => {}
    }

    let content_binding = text(assurance, "content_binding")?.to_owned();
    if !CONTENT_BINDINGS.contains(&content_binding.as_str()) {
        return Err(mismatch("content_binding"));
    }
    if content_binding != "none" && !CONTENT_EVIDENCE_TYPES.contains(&claim_type) {
        return Err(mismatch("content_binding"));
    }

    Ok(Assurance {
        governance,
        competing_triggers,
        witnessed: flag(assurance, "witnessed")?,
        continued_history: flag(assurance, "continued_history")?,
        canonicalization_namespace: check_canonicalization_namespace(assurance)?,
        content_binding,
    })
}

/// The two namespaces I-D §7.3 defines for a canonicalization identifier.
const CANONICALIZATION_NAMESPACES: [&str; 2] = ["public", "private-use"];

/// Read and validate `assurance.canonicalization_namespace` (I-D §7.3, §7.6).
///
/// §7.3: "REQUIRED where `content_binding` is not `none`, and absent otherwise… `private-use`,
/// where the carried descriptor's `canonicalization` identifier begins `x-`… or `public`
/// otherwise." §7.6 states the same as a cross-field rule: "present if and only if
/// `assurance.content_binding` is not `none`, and is `private-use` if and only if the carried
/// descriptor's `canonicalization` identifier begins `x-`".
///
/// The presence rule and the token set are decidable here, from the assurance block alone. The
/// half that needs the descriptor is checked where the descriptor is parsed
/// ([`check_namespace_matches_descriptor`]) — the receipt has one only where it carries content
/// evidence, which is exactly where this member is required.
fn check_canonicalization_namespace(assurance: &Value) -> Result<Option<String>> {
    let bound = text(assurance, "content_binding")? != "none";
    let mismatch = || ReceiptError::AssuranceMismatch { field: "canonicalization_namespace" };
    match (bound, assurance.get("canonicalization_namespace")) {
        (false, None) => Ok(None),
        (true, Some(value)) => value
            .as_str()
            .filter(|token| CANONICALIZATION_NAMESPACES.contains(token))
            .map(|token| Some(token.to_owned()))
            .ok_or_else(mismatch),
        // A content binding without the member, or the member without a content binding: the
        // same if-and-only-if, read from either side.
        (true, None) | (false, Some(_)) => Err(mismatch()),
    }
}

/// The half of I-D §7.6's namespace rule that needs the carried descriptor: `private-use` if
/// and only if that descriptor's `canonicalization` identifier begins `x-`.
///
/// Checked on the descriptor the receipt CARRIES, which the equality rule of §6.3 has just
/// required to be the manifest's declared one, and before the capability outcome of §6.3 is
/// reached: an `x-` identifier is by construction one this build does not implement, so
/// deciding the namespace afterwards would let an `unverifiable` capability gap mask a
/// disagreement decidable from the receipt's own bytes.
fn check_namespace_matches_descriptor(assurance: &Assurance, canonicalization: &str) -> Result<()> {
    let private_use = canonicalization.starts_with("x-");
    if (assurance.canonicalization_namespace.as_deref() == Some("private-use")) == private_use {
        return Ok(());
    }
    Err(ReceiptError::AssuranceMismatch { field: "canonicalization_namespace" })
}

/// Claim types §4 permits in `declared` mode.
const DECLARED_MODE_TYPES: [&str; 5] = [
    "statement-anchored",
    "record-ingested",
    "record-derived",
    "trigger-declared",
    "disposition-declared",
];

/// I-D §7.5.1 4d for one carried envelope: verified under COMPLETED K, at its OWN entry index.
///
/// A failure is decided by [`envelope_outcome`] under the receipt's governance mode, so a
/// declared-mode receipt naming a producer key the mode does not carry a transition for is
/// reported as §7.4's `unverifiable` rather than as a defect.
fn verify_envelope_at(
    envelope: &Value,
    governance: &Governance<'_>,
    index: u64,
    run: &mut Run,
) -> Result<()> {
    let keys = governance.producer_pubkeys_at(index);
    run.spend(1)?;
    let check = crate::check_envelope(envelope, |key_id| keys.get(key_id).cloned())?;
    envelope_outcome(&check, governance.mode, index)
}

/// Decode and authenticate the `enumerated` governance currency material (I-D §7.4), ahead of
/// the induction that consumes it.
///
/// Two facts are established here, both key-independent. The range proof binds `entries` to the
/// checkpoint root, so the `key` statements the induction is about to walk are the entries the
/// log committed at those indexes rather than bytes the presenter chose. And the range is
/// exactly `[0, tree_size(C))`, which is what §7.4 fixes for enumerated currency and what
/// §7.5.1 4c leans on: "Under `enumerated` governance the range proof over exactly
/// `[0, tree_size(C))` forecloses omission, so K at each index IS the state that was in force."
/// Anything narrower would feed the induction a key stream with holes in it — a receipt
/// enumerating only `[0, 1)` could hide a later key retirement and validate a signature with a
/// key the corpus had already retired — so the width is checked before the stream is used, not
/// after.
fn decode_governance_enumeration(
    currency: &Value,
    root: &Hash,
    tree_size: u64,
    run: &mut Run,
) -> Result<Enumeration> {
    let material = obj(currency, "material")?;
    let enumeration = decode_enumeration(material, root, tree_size, "governance", run)?;
    if enumeration.from_index != 0 || enumeration.to_index != tree_size {
        return Err(ReceiptError::GovernanceRangeNotComplete {
            got_from: enumeration.from_index,
            got_to: enumeration.to_index,
            tree_size,
        });
    }
    Ok(enumeration)
}

/// The `key` statements the enumeration carries, with their entry indexes, ascending.
///
/// I-D §7.5.1 4b's second induction stream. Selecting them by the LITERAL `type` value is not
/// type-specific VALIDATION of unsigned material — 4b(K)'s checks, §2.2's common payload fields
/// among them, still run inside phase 2, after phase 1 — it is the selection the merge is
/// defined in terms of, over bytes the range proof has already bound to the checkpoint root.
/// See [`statement_type_literal`] for why an unreadable `type` is a non-selection rather than
/// an error here.
fn enumerated_key_statements(enumeration: &Enumeration) -> Vec<(u64, &Value)> {
    let mut out = Vec::new();
    for (offset, envelope) in enumeration.entries.iter().enumerate() {
        if statement_type_literal(envelope) == Some("key") {
            out.push((enumeration.from_index + offset as u64, envelope));
        }
    }
    out
}

/// I-D §7.5.1 4c under `enumerated` governance: the carried chain is the complete set of
/// MANIFEST statements in the enumerated range.
///
/// The enumerated `key` statements need no such check — they are the induction's own second
/// stream, so an enumerated `key` statement is walked by construction. A manifest is different:
/// the chain is where manifests travel (§7.1), and one anchored inside the range but absent
/// from the chain would change which version is active at some index while the induction never
/// saw it. This runs immediately after the induction and BEFORE 4f, because 4f resolves its
/// checkpoint key from "the manifest version active for the checkpoint being verified...
/// established under the receipt's governance mode": a chain with a manifest missing has not
/// established that version, and reporting the omission is more honest than reporting the key
/// binding that fails downstream of it.
fn check_manifest_completeness(
    enumeration: &Enumeration,
    governance: &Governance<'_>,
) -> Result<()> {
    let presented: BTreeSet<u64> = governance.manifests.iter().map(|(index, _)| *index).collect();
    for (offset, envelope) in enumeration.entries.iter().enumerate() {
        let index = enumeration.from_index + offset as u64;
        if statement_type_literal(envelope) == Some("manifest") && !presented.contains(&index) {
            return Err(ReceiptError::GovernanceChainInvalid(format!(
                "enumeration reveals a `manifest` statement at entry index {index} that the \
                 presented chain omits"
            )));
        }
    }
    Ok(())
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
    profile: &'a AdaptorProfile,
    profile_id: &'a str,
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

fn verify_claim_material(ctx: &ClaimCtx<'_>, run: &mut Run) -> Result<()> {
    match ctx.claim_type {
        "statement-anchored" => Ok(()),
        "record-ingested" => verify_record_ingested(ctx, run),
        "record-derived" => verify_record_derived(ctx, run),
        "trigger-declared" => verify_trigger(ctx, run, "trigger-declared"),
        "trigger-effective" => verify_trigger(ctx, run, "trigger-effective"),
        "disposition-declared" => verify_disposition(ctx, run, "trigger-declared"),
        "disposition-effective" => verify_disposition(ctx, run, "trigger-effective"),
        "propagation-complete" => verify_propagation_complete(ctx, run),
        "governance-state" => verify_governance_state(ctx),
        other => Err(ReceiptError::Malformed(format!("`{other}` is not a registry claim type"))),
    }
}

/// `record-ingested` (§3): the subject ingestion introduces the record; optional content
/// binding recomputes the commitment from carried canonical bytes.
fn verify_record_ingested(ctx: &ClaimCtx<'_>, run: &mut Run) -> Result<()> {
    ctx.require_subject_type("ingestion")?;
    let (dataset, record) = ctx.record_subject.ok_or_else(|| ctx.missing("record_subject"))?;
    let binding = verify_content_binding(ctx, dataset, record, "record_bytes");
    run.tolerate(binding).map(|_| ())
}

/// Recompute a commitment from carried canonical bytes per the dataset's declared mode
/// (§2.1, spec §2.4). `content_binding: "none"` requires the evidence fields to be absent.
///
/// The callers pass the outcome through [`Run::tolerate`], because a content binding is the one
/// assertion I-D §7.7 has other assertions reported around rather than behind: "A
/// `record-ingested` receipt asserting a content binding the verifier cannot compute has result
/// `unverifiable`... and its report MUST show the anchoring and introduction findings as
/// `verified` and the content-binding finding as `unverifiable`." A capability gap here
/// therefore records its finding and lets the claim-material step finish; a defect still ends
/// the run, since `invalid` has already decided the result.
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
    // I-D §7.2, both record rows: the bytes and `canonicalization` are present "if and only if
    // `content_binding` is not `none`, together with `media_type` if and only if the descriptor
    // requires it". Presence is therefore settled from the assurance field alone, BEFORE any of
    // the three members is read for its value. A descriptor carried under `none` is a receipt
    // asserting evidence its own assurance says it has not got — §7.6: "a combination the type
    // cannot satisfy is `invalid` rather than downgraded" — and ignoring it would let a
    // receipt carry a descriptor that no check ever compares against the manifest's.
    let has_bytes = material.get(field).is_some();
    let has_canonicalization = material.get("canonicalization").is_some();
    if ctx.assurance.content_binding == "none" {
        return if has_bytes || has_canonicalization || material.get("media_type").is_some() {
            Err(ReceiptError::AssuranceMismatch { field: "content_binding" })
        } else {
            Ok(())
        };
    }
    // Neither member is evidence without the other, so they stand or fall together: bytes with
    // no descriptor cannot be canonicalized, and a descriptor with no bytes canonicalizes
    // nothing. Whichever is absent is the one named.
    if has_bytes != has_canonicalization {
        return Err(if has_bytes { ctx.missing("canonicalization") } else { ctx.missing(field) });
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
    // A wrong-typed `media_type` is `invalid`, never read as absent: read as absent it would
    // compare equal to a declared descriptor that carries none (I-D §2.6 descriptor equality).
    let claimed_media_type = match material.get("media_type") {
        None => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => {
            return Err(ReceiptError::Malformed(
                "`claim_material.media_type`, where present, MUST be a string (I-D §2.6)"
                    .to_owned(),
            ))
        }
    };
    let claimed_descriptor =
        CanonicalizationDescriptor::new(claimed_canonicalization, claimed_media_type)?;

    // I-D §7.6: `assurance.canonicalization_namespace` "is `private-use` if and only if the
    // carried descriptor's `canonicalization` identifier begins `x-`", and §7.3 calls the
    // member "computable from the receipt alone". So it is decided HERE — on the carried
    // descriptor, the moment it is parsed — before the descriptor-equality rule below compares
    // it against the manifest's declared one (already read above), and well before §6.3's
    // unsupported-procedure outcome, which an `x-` identifier would otherwise always reach
    // first and report as unverifiable.
    check_namespace_matches_descriptor(ctx.assurance, claimed_descriptor.canonicalization())?;
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
            // I-D §7.3, §7.7: holding no key for the dataset is a capability gap on THIS
            // dataset's content binding, never a demonstrated defect, so it is reported under
            // its own `unverifiable` variant rather than as a commitment that did not match.
            let key =
                ctx.policy.dataset_keys.get(dataset).ok_or_else(|| {
                    ReceiptError::DatasetKeyNotHeld { dataset: dataset.to_owned() }
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
fn verify_record_derived(ctx: &ClaimCtx<'_>, run: &mut Run) -> Result<()> {
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

    // Which branch a derivation takes turns on this member's presence (I-D §2.4.2), so a
    // wrong-typed one is `invalid` rather than a receipt quietly checked under the other
    // branch's rules.
    let outputs_root = match ctx.payload.get("outputs_root") {
        None => None,
        Some(Value::String(value)) => Some(value.as_str()),
        Some(_) => {
            return Err(ReceiptError::Malformed(
                "`outputs_root`, where present, MUST be a string (I-D §2.4.2)".to_owned(),
            ))
        }
    };
    if let Some(root) = outputs_root {
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
            run,
        )?;
        verify_input_members(ctx, leaf, run)?;
    } else {
        let listed = array(ctx.payload, "outputs")?.iter().any(|entry| {
            entry.get("dataset").and_then(Value::as_str) == Some(claimed.0.as_str())
                && entry.get("record").and_then(Value::as_str) == Some(claimed.1.as_str())
        });
        if !listed {
            return Err(ReceiptError::ClaimMaterialPathInvalid { what: "output" });
        }
    }

    let binding = verify_content_binding(ctx, &claimed.0, &claimed.1, "output_bytes");
    run.tolerate(binding).map(|_| ())
}

/// `input_members` (I-D §7.2): each proves one input's membership in the leaf's input set.
///
/// §7.2's `record-derived` row carries the member "only where `batch_leaf.inputs` is the
/// input-set form, proving the listed inputs and no others", and §2.7 gives the two forms
/// `inputs` may take: the full array of input objects, or `{input_set_root, input_set_count}`.
/// So the member is REQUIRED under one form and forbidden under the other, and each direction
/// is its own defect:
///
/// *   Under the input-set form the leaf commits its inputs by ROOT and lists none of them, so
///     without the members the derivation's inputs are not carried at all. Accepting the leaf
///     anyway would let a batch derivation claim outputs while keeping every input unstated —
///     the one thing the input-set form exists to make provable.
/// *   Under the full-array form the leaf lists its inputs itself and commits no root, so
///     there is nothing for a membership path to open; a carried member could only be about
///     some other tree.
///
/// "The listed inputs and no others" is a statement about the WHOLE set, so the members must
/// cover it exactly: one member per committed leaf, at distinct indexes, each opening the
/// committed root. A short list proves a subset and would let a producer disclose the
/// convenient inputs and withhold the rest under a root that says how many there were.
///
/// Once the set is complete it is also a TREE, and §2.7 states one set of rules "identical for
/// every AHL tree — outputs, input sets, and dispositions": ascending order by the UTF-8 bytes
/// of each leaf's canonical commitment string, commitment strings that are family strings under
/// §2.1, and no duplicates. Membership paths do not reach any of that, so the assembled set is
/// validated through [`ValidatedLeafSet::open`] — the same gate every other tree in this crate
/// passes through.
fn verify_input_members(ctx: &ClaimCtx<'_>, leaf: &Value, run: &mut Run) -> Result<()> {
    let material = ctx.material()?;
    // Where present, the member is an array; a wrong type is `invalid` and is never read as
    // absent, which would silently skip every input-membership proof the receipt carries.
    let members = match material.get("input_members") {
        None => None,
        Some(Value::Array(members)) => Some(members),
        Some(_) => {
            return Err(ReceiptError::Malformed(
                "`claim_material.input_members`, where present, MUST be an array (I-D §7.2)"
                    .to_owned(),
            ))
        }
    };
    let inputs = leaf.get("inputs").ok_or_else(|| ctx.missing("batch_leaf.inputs"))?;
    match inputs {
        Value::Array(_) => {
            if members.is_some() {
                return Err(ReceiptError::Malformed(
                    "`claim_material.input_members` is carried ONLY where `batch_leaf.inputs` \
                     is the input-set form; the full-array form of I-D §2.7 lists its inputs in \
                     the leaf and commits no `input_set_root` for a member to open (I-D §7.2)"
                        .to_owned(),
                ));
            }
            Ok(())
        }
        Value::Object(_) => {
            let members = members.ok_or_else(|| ctx.missing("input_members"))?;
            let root = text(inputs, "input_set_root")?;
            let count = number(inputs, "input_set_count")?;
            let mut opened = BTreeMap::new();
            for member in members {
                let input = obj(member, "input")?;
                let index = number(member, "input_index")?;
                check_inclusion(
                    &jcs(input),
                    index,
                    count,
                    &path_strings(member, "input_path")?,
                    &parse_hash_hex(root)?,
                    "input-set member",
                    run,
                )?;
                if opened.insert(index, input.clone()).is_some() {
                    return Err(ReceiptError::TreeMaterialInvalid {
                        root: root.to_owned(),
                        detail: format!(
                            "two `input_members` entries open index {index}; the set is proven \
                             once per committed leaf (I-D §7.2)"
                        ),
                    });
                }
            }
            // Every index opened is distinct and, by `check_inclusion`, smaller than `count`,
            // so an equal cardinality is exactly the committed set.
            if opened.len() as u64 != count {
                return Err(ReceiptError::TreeMaterialInvalid {
                    root: root.to_owned(),
                    detail: format!(
                        "commits {count} input(s), {} proven by `input_members` — I-D §7.2 \
                         requires \"the listed inputs and no others\"",
                        opened.len()
                    ),
                });
            }
            // I-D §2.7 states one set of tree rules, "identical for every AHL tree — outputs,
            // input sets, and dispositions": leaves sorted by `record`, "comparing the UTF-8
            // bytes of the canonical commitment string in ascending lexicographic order",
            // commitment strings that are family strings under §2.1 with "one failing the rules
            // there rejected", and "duplicate leaves are prohibited". Membership paths alone do
            // not reach any of that. They prove each carried input is a committed leaf at the
            // index it claims, but a producer choosing the leaf ORDER decides the tree, so a set
            // built in some other order — or over a leaf whose `record` is not a canonical
            // commitment string — opens its own root perfectly well and is still not an AHL
            // tree. Passing the complete set, ordered by `input_index`, through the same
            // [`ValidatedLeafSet::open`] every other tree in this crate goes through is what
            // applies those rules here rather than restating them; it recomputes the root over
            // the assembled set as well, so the members must be the leaves of THIS tree in the
            // order the rules fix, not merely leaves of some tree with this root.
            ValidatedLeafSet::open(root, count, opened.into_values().collect()).map_err(
                |source| ReceiptError::TreeMaterialInvalid {
                    root: root.to_owned(),
                    detail: source.to_string(),
                },
            )?;
            Ok(())
        }
        _ => Err(ReceiptError::Malformed(
            "`batch_leaf.inputs` is either the full array of input objects or the input-set \
             form `{input_set_root, input_set_count}` (I-D §2.7)"
                .to_owned(),
        )),
    }
}

/// Render a `(dataset, record)` pair for an error message.
///
/// Record identity is the PAIR (I-D §2.4.2, §7.6), so a message naming the commitment alone
/// would print two identical strings for exactly the mismatch this reports.
fn describe_record(pair: Option<&(String, String)>) -> String {
    pair.map_or_else(String::new, |(dataset, record)| format!("{dataset}/{record}"))
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
    run: &mut Run,
) -> Result<Embedded> {
    let embedded =
        ctx.material()?.get(slot).filter(|v| v.is_object()).ok_or_else(|| ctx.missing(slot))?;
    // Duplicate embedded receipts are verified once and referenced thereafter (§3.1). The key
    // is the digest of the *entire* receipt object, so only byte-identical receipts share a
    // cache entry; two receipts about the same statement with different claim material are
    // each verified in full.
    let key = sha256_hex(&jcs(embedded));
    // The path this embedded receipt's findings are recorded under. Pushed before descending
    // and popped only on success: a rejection inside the embedded receipt is recorded at the
    // embedded receipt's own path as the run unwinds.
    run.path.push(slot.to_owned());
    let verdict = if let Some((verdict, findings)) = run.verified.get(&key).cloned() {
        // Served from the cache, and still reported: I-D §7.7 gives the embedding receipt a
        // finding for every required assertion of the receipt it embeds, and a second
        // occurrence of one receipt is a second place a reader looks for them.
        for finding in findings {
            run.record(finding.assertion, finding.outcome, finding.detail);
        }
        verdict
    } else {
        let before = run.findings.len();
        let verdict = verify_nested(embedded, ctx.policy, run, ctx.depth + 1)?;
        let findings = run.findings[before..].to_vec();
        run.verified.insert(key, (verdict.clone(), findings));
        verdict
    };
    run.path.pop();

    if !permitted.contains(&verdict.claim_type.as_str()) {
        return Err(ReceiptError::EmbeddedClaimTypeMismatch {
            slot,
            expected,
            got: verdict.claim_type,
        });
    }
    let record = match obj(embedded, "claim")?.get("record_subject") {
        None => None,
        Some(subject) => {
            Some((text(subject, "dataset")?.to_owned(), text(subject, "record")?.to_owned()))
        }
    };
    Ok(Embedded { verdict, entry_index: number(obj(embedded, "subject")?, "entry_index")?, record })
}

/// `trigger-declared` / `trigger-effective` (§3).
fn verify_trigger(ctx: &ClaimCtx<'_>, run: &mut Run, kind: &str) -> Result<()> {
    let subject_type = statement_type(ctx.payload)?;
    if !matches!(subject_type, "retraction" | "correction") {
        return Err(ReceiptError::Malformed(format!(
            "claim type `{}` requires a trigger subject, got `{subject_type}`",
            ctx.claim_type
        )));
    }
    // I-D §2.4.2: "Closure traversal uses the `(dataset, record)` pair only." Record identity
    // is that PAIR, so every reference below is matched on both members. A commitment string
    // alone is not an identity: §2.6 puts `dsid` in the commitment preimage, which makes the
    // same bytes in two datasets commit differently, but it does not stop a producer NAMING a
    // commitment beside the wrong dataset — and a verifier recomputes the commitment only
    // where content evidence is carried. Comparing the commitment alone would accept an
    // introduction of a different dataset's record as the introduction of this one.
    let subject_record = ctx.record_subject.ok_or_else(|| ctx.missing("record_subject"))?;
    let (dataset, _) = subject_record;

    // The introduction proof establishes who may retract (§3 authority note).
    let introduction =
        verify_embedded(ctx, "introduction", "introduction", &INTRODUCTION_TYPES, run)?;
    // Spec §2.3.3: a trigger anchored at a smaller entry index than the record's introduction
    // is never effective — authority cannot predate the introduction that creates it.
    if introduction.entry_index >= ctx.subject_index {
        return Err(ReceiptError::EmbeddedOrderingViolation {
            what: "introduction",
            inner: introduction.entry_index,
            outer: ctx.subject_index,
        });
    }
    // I-D §7.6: "Every embedded receipt's `record_subject`... match the referencing material —
    // trigger to introduction record".
    if introduction.record.as_ref() != Some(subject_record) {
        return Err(ReceiptError::EmbeddedSubjectMismatch {
            what: "introduction",
            got: describe_record(introduction.record.as_ref()),
            want: describe_record(Some(subject_record)),
        });
    }

    if subject_type == "correction" {
        // I-D §2.4.3: a correction carries ONE `dataset`, governing both `record` and
        // `replacement`, so the replacement's identity is that same dataset paired with the
        // new commitment — never the commitment on its own (I-D §7.6: "correction to
        // replacement introduction").
        let replacement = (dataset.clone(), text(ctx.payload, "replacement")?.to_owned());
        let embedded = verify_embedded(
            ctx,
            "replacement_introduction",
            "introduction",
            &INTRODUCTION_TYPES,
            run,
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
        if embedded.record.as_ref() != Some(&replacement) {
            return Err(ReceiptError::EmbeddedSubjectMismatch {
                what: "replacement introduction",
                got: describe_record(embedded.record.as_ref()),
                want: describe_record(Some(&replacement)),
            });
        }
    }

    // Scope is what makes a trigger meaningful at all; a scopeless one is malformed (§2.3.3).
    Scope::from_payload(ctx.payload)?;

    if kind == "trigger-effective" {
        // "Effective" is exactly the authority claim: an unauthorized trigger is a challenge
        // (spec §2.3.3) and can never be effective, however well anchored it is.
        verify_trigger_authority(ctx, &introduction, run)?;
        verify_competing_triggers(ctx, &introduction, run)?;
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

/// Whether the ALREADY-VALID envelope at `index` is a trigger signed by the record's authority.
///
/// I-D §8.4 fixes two separate tests, in that order — "Validity and authorization are separate
/// tests, applied in that order" — and this function is the SECOND of them only. §7.5.1 4e says
/// so directly: authorization is "applied only to envelopes already valid under 4d". The trigger
/// is authorized if and only if at least one of its signers holds a key in the authority key set
/// active at `index`. Core spec §2.3.3 requires a trigger to be "signed by the record's
/// authority", not signed *exclusively* by authority keys — a trigger genuinely co-signed by the
/// authority AND some other active producer key is still authorized. That is also why the two
/// tests must stay separate rather than being merged into one resolver restricted to authority
/// keys: such a resolver would fail the whole envelope over any additional, genuinely valid
/// co-signer, misclassifying an authorized trigger as a challenge.
///
/// # Precondition
///
/// The envelope has already passed 4d at `index` — every entry in `signatures` resolved to a
/// producer key active there and verified over `JCS(payload)`. Both call sites establish it,
/// and neither can be reached otherwise: [`verify_trigger_authority`] takes the subject's own
/// envelope, which [`verify_nested`] verifies through [`verify_envelope_at`] before any claim
/// material is read, and [`verify_competing_triggers`] takes candidates out of an
/// [`Enumeration`] whose every non-induction envelope [`verify_enumeration`] has verified at its
/// own index. Re-checking the signature here would therefore never reject anything, while
/// leaving the impression that a caller MAY hand this function unvalidated material — the one
/// reading §8.4's ordering rules out. A false return means a valid envelope whose signers hold
/// no authority, which §7.5.1 4e calls a challenge and "not a defect".
fn is_authorized_trigger(
    ctx: &ClaimCtx<'_>,
    envelope: &Value,
    dataset: &str,
    by_ingestion: bool,
    index: u64,
    run: &mut Run,
) -> Result<bool> {
    // The §7.8 budget is charged per candidate examined: resolving the authority key set walks
    // the governance state at `index`, which is per-candidate work whatever it concludes.
    run.spend(1)?;
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
/// `sig` bytes are controlled by whoever assembled the envelope. That check has already run by
/// the time this is reached — [`verify_nested`] verifies the subject's own envelope under I-D
/// §7.5.1 4d, at its own entry index, before any claim material is read — so what remains here
/// is 4e's authority comparison over signers already known genuine, through the same
/// [`is_authorized_trigger`] that `verify_competing_triggers` uses.
fn verify_trigger_authority(
    ctx: &ClaimCtx<'_>,
    introduction: &Embedded,
    run: &mut Run,
) -> Result<()> {
    let (dataset, record) = ctx.record_subject.ok_or_else(|| ctx.missing("record_subject"))?;
    let envelope = obj(ctx.receipt, "envelope")?;
    let by_ingestion = introduced_by_ingestion(introduction);
    if !is_authorized_trigger(ctx, envelope, dataset, by_ingestion, ctx.subject_index, run)? {
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

/// The §7.2 competing-trigger enumeration required by `trigger-effective`.
///
/// Every candidate's envelope has already been verified at its own entry index by
/// [`verify_enumeration`] — §7.2: "Every competing candidate's envelope MUST be verified under
/// Section 2.1 before authority is compared" — so what remains here is purely the §7.5.1 4e
/// authority comparison over envelopes already known valid. A candidate that fails validity
/// never reaches this point: it is `invalid` for the run, not a challenge.
fn verify_competing_triggers(
    ctx: &ClaimCtx<'_>,
    introduction: &Embedded,
    run: &mut Run,
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

    let enumeration = verify_enumeration(
        range_material,
        ctx.governance,
        &root,
        tree_size,
        "competing triggers",
        run,
    )?;

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
    // Effectiveness is decided before the index comparison, not after. A VALID trigger signed
    // by a key that is not the record's authority anchors as a challenge, "never traversed" —
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
        if is_authorized_trigger(ctx, envelope, dataset, by_ingestion, index, run)? {
            governing = Some(index);
        } else {
            challenges.push(index);
        }
    }
    if !challenges.is_empty() {
        // Surfaced, as §2.3.3 requires — but not traversed, and not permitted to govern.
        run.spend(challenges.len() as u64)?;
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
fn verify_disposition(ctx: &ClaimCtx<'_>, run: &mut Run, trigger_kind: &'static str) -> Result<()> {
    ctx.require_subject_type("propagation")?;
    let material = ctx.material()?;
    let trigger = verify_embedded(ctx, "trigger", trigger_kind, &[trigger_kind], run)?;

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
        run,
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
    policy: &TrustPolicy,
    governance: &Governance<'_>,
    declared: &Value,
    profile: &AdaptorProfile,
    profile_id: &str,
    run: &mut Run,
) -> Result<()> {
    let key_id = text(declared, "key_id")?;
    let tree_size = number(declared, "tree_size")?;
    let (active_index, active_manifest) = governance.active_for(tree_size)?;
    let active_log = log_object(active_manifest)?;

    // I-D §3.2: the same adaptor-binding check every other checkpoint gets, applied here
    // under THIS checkpoint's own active manifest — a manifest anchored between the primary
    // checkpoint and this one could in principle pin a different adaptor.
    check_adaptor_binding(active_log, profile_id, profile)?;

    // The log id must match the manifest version active for this checkpoint, exactly as it must
    // for the anchoring one (adaptor §5) — no relaxed check for the second checkpoint.
    if text(active_log, "log_id")? != text(declared, "log_id")? {
        return Err(ReceiptError::GovernanceChainInvalid(
            "checkpoint `log_id` is not the log the active manifest declares".to_owned(),
        ));
    }

    // `declared` is `anchoring.later_checkpoint` or `propagation-complete`'s own declared
    // checkpoint D. The first had its `raw` reconciled at §7.5 step 2 with the rest of the
    // `anchoring` block ([`reconcile_anchoring_raw`]); D is claim material rather than an
    // `anchoring` member, so this is the call that covers it, and repeating the check for
    // `later_checkpoint` costs one absent-member read.
    reconcile_checkpoint_raw(declared, profile_id)?;

    // The log key resolves against the manifest active for this checkpoint's *own* tree size,
    // and its `keys.log` entry binds to that same manifest version (format §2.2) — the normal
    // source/binding contract, not a byte-equality shortcut. `active_index` can differ from the
    // anchoring checkpoint's: a manifest anchored between them rotates the log key set, and a
    // checkpoint issued under one state must be validated by that state's key. The same
    // `key_id` may appear more than once in `keys.log` — a receipt authenticating two
    // checkpoints can legitimately carry the same physical log key bound to each checkpoint's
    // own active manifest — so this resolves against THIS checkpoint's own `active_index`,
    // exactly as [`verify_checkpoint`] does for the primary checkpoint.
    let (log_keys, log_attempted) =
        bind_keys_by_group(receipt, policy, &governance.manifests, active_index, "log")?;
    let signing_key = log_keys.get(key_id).ok_or_else(|| {
        let entry_index = log_attempted.get(key_id).copied().unwrap_or(active_index);
        ReceiptError::KeyNotBound { key_id: key_id.to_owned(), entry_index }
    })?;

    run.spend(1)?;
    if !verify_signature(
        &decode_pubkey(&signing_key.pubkey)?,
        &checkpoint_signing_bytes_for(declared, profile_id)?,
        text(declared, "signature")?,
    )? {
        return Err(ReceiptError::CheckpointSignatureInvalid);
    }

    Ok(())
}

/// Verify `anchoring.later_witnesses[]` against `later_checkpoint` (I-D §7.1: "Present if and
/// only if `later_checkpoint` is carried. An array in the shape of `anchoring.witnesses[]`,
/// each element a cosignature over `later_checkpoint` rather than over `anchoring.checkpoint`,
/// and validated under the manifest version active for `later_checkpoint.tree_size`... At L3…
/// a receipt asserting `continued_history` MUST carry at least one element that verifies, and
/// one that does not is `invalid` for that assertion; below L3 the array MAY be empty").
///
/// Distinct from `anchoring.checkpoint`'s own witnesses in exactly one respect: WHICH bytes a
/// cosignature is computed over (`later_checkpoint`, not the primary checkpoint) and WHICH
/// manifest version's witness key set validates it (the one active for `later_checkpoint`'s
/// own `tree_size`). The cosignatures travel as a SIBLING to `later_checkpoint`, never nested
/// inside it: the log signs `later_checkpoint` itself, and a witness cosigns that SAME signed
/// object verbatim (adaptor §6/§11: "the signed checkpoint object, INCLUDING its signature
/// member") — nesting cosignatures into it would change the very bytes both the log's
/// signature and each cosignature's own preimage are computed over.
///
/// This has NO counterpart for `propagation-complete`'s declared checkpoint D: format §7.2
/// authenticates D "by either a consistency proof from D to the receipt's checkpoint or
/// recomputation of D's prefix root from the enumerated prefix" — no cosignature requirement
/// on D at all, so [`authenticate_checkpoint`] (shared by both D and `later_checkpoint`) never
/// touches witnesses, and this function exists only for `later_checkpoint`.
fn verify_later_witnesses(
    receipt: &Value,
    policy: &TrustPolicy,
    governance: &Governance<'_>,
    anchoring: &Value,
    later_checkpoint: &Value,
    run: &mut Run,
) -> Result<()> {
    let tree_size = number(later_checkpoint, "tree_size")?;
    let (active_index, active_manifest) = governance.active_for(tree_size)?;
    let candidates = cosignature_array(anchoring, "later_witnesses", "anchoring.later_witnesses")?;

    let (witness_keys, witness_attempted) =
        bind_keys_by_group(receipt, policy, &governance.manifests, active_index, "witness")?;
    let mut witnessed = false;
    for cosignature in candidates {
        let cosignature = witness_cosignature_object(cosignature)?;
        let witness_id = text(cosignature, "witness_id")?.to_owned();
        let key_id = text(cosignature, "key_id")?;
        let resolved = witness_keys.get(key_id).ok_or_else(|| ReceiptError::KeyNotBound {
            key_id: key_id.to_owned(),
            entry_index: witness_attempted.get(key_id).copied().unwrap_or(active_index),
        })?;
        check_witness_identity(resolved, key_id, &witness_id)?;
        check_witness_declared(active_manifest, &witness_id, tree_size)?;
        run.spend(1)?;
        if !verify_signature(
            &decode_pubkey(&resolved.pubkey)?,
            &cosignature_bytes(later_checkpoint, &witness_id),
            text(cosignature, "cosignature")?,
        )? {
            return Err(ReceiptError::WitnessCosignatureInvalid { witness_id });
        }
        witnessed = true;
    }
    if active_manifest.get("level").and_then(Value::as_str) == Some("L3") && !witnessed {
        return Err(ReceiptError::CheckpointUnwitnessed { tree_size });
    }
    Ok(())
}

/// `propagation-complete` (§3): the anchored affected set equals the recomputable closure.
// The completeness claim has the longest precondition list in the registry — checkpoint
// binding, prefix enumeration, tree material, trigger effectiveness, closure — and each step
// consumes the previous one's output; splitting it would only scatter that chain.
#[allow(clippy::too_many_lines)]
fn verify_propagation_complete(ctx: &ClaimCtx<'_>, run: &mut Run) -> Result<()> {
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
    // Format §7.2: D is authenticated "by either a consistency proof from D to the receipt's
    // checkpoint or recomputation of D's prefix root from the enumerated prefix" — no
    // cosignature requirement on D at all, unlike `anchoring.later_checkpoint`
    // ([`verify_later_witnesses`]).
    authenticate_checkpoint(
        ctx.receipt,
        ctx.policy,
        ctx.governance,
        carried_d,
        ctx.profile,
        ctx.profile_id,
        run,
    )?;

    // The prefix is `[0, tree_size(D))`, and its range proof is checked against **A's** root:
    // A is the checkpoint this verifier signature-checked and saw witness-cosigned. Verifying
    // the prefix under A and then recomputing D's root from it is a consistency proof D→A in
    // the range-proof's clothing — it establishes that D is exactly the size-`tree_size(D)`
    // prefix of A, which is what makes D usable without a second proof mechanism.
    let root = parse_hash_hex(text(ctx.anchoring_checkpoint, "root_hash")?)?;
    let tree_size = declared_size;
    let prefix = verify_enumeration(
        prefix_material,
        ctx.governance,
        &root,
        anchor_size,
        "corpus prefix",
        run,
    )?;
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
        verify_embedded(ctx, "trigger", "trigger-effective", &["trigger-effective"], run)?;
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

    run.spend(u64::try_from(prefix.entries.len()).unwrap_or(u64::MAX))?;
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

    use super::{
        log_key_set, verify_rotation_proof, witness_key_set, AdaptorCapabilities, AdaptorProfile,
        Limits, ReceiptError, RotationContext, Run, TrustPolicy, TEST_ADAPTOR_PROFILE_ID,
    };
    use crate::{
        checkpoint, cosignature_bytes, hash_hex, inclusion_proof, jcs, sha256_hex, tree_root,
        TestKey,
    };

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
        let aa = format!("sha256:{}", "aa".repeat(32));
        let bb = format!("sha256:{}", "bb".repeat(32));
        let cc = format!("sha256:{}", "cc".repeat(32));
        let dd = format!("sha256:{}", "dd".repeat(32));
        let forward = json!({
            "log": { "keys": [
                { "key_id": aa, "pubkey": "base64:AAAA", "valid_from_index": 0 },
                { "key_id": bb, "pubkey": "base64:AAAB", "valid_from_index": 0 },
            ] },
            "witnesses": [
                { "witness_id": "witness-1", "keys": [
                    { "key_id": cc, "pubkey": "base64:AAAC", "valid_from_index": 0 },
                ] },
                { "witness_id": "witness-2", "keys": [
                    { "key_id": dd, "pubkey": "base64:AAAD", "valid_from_index": 0 },
                ] },
            ],
        });
        let reordered = json!({
            "log": { "keys": [
                { "key_id": bb, "pubkey": "base64:AAAB", "valid_from_index": 0 },
                { "key_id": aa, "pubkey": "base64:AAAA", "valid_from_index": 0 },
            ] },
            "witnesses": [
                { "witness_id": "witness-2", "keys": [
                    { "key_id": dd, "pubkey": "base64:AAAD", "valid_from_index": 0 },
                ] },
                { "witness_id": "witness-1", "keys": [
                    { "key_id": cc, "pubkey": "base64:AAAC", "valid_from_index": 0 },
                ] },
            ],
        });

        assert_eq!(
            log_key_set(&forward),
            log_key_set(&reordered),
            "reordering `log.keys` must not look like a rotation"
        );
        assert_eq!(
            witness_key_set(&forward).expect("well-formed witnesses"),
            witness_key_set(&reordered).expect("well-formed witnesses"),
            "reordering `witnesses[]`, or the `keys` within one witness, must not look like a \
             rotation"
        );

        let genuinely_different = json!({
            "log": { "keys": [
                { "key_id": aa, "pubkey": "base64:AAAA", "valid_from_index": 0 },
            ] },
            "witnesses": [],
        });
        assert_ne!(log_key_set(&forward), log_key_set(&genuinely_different));
        assert_ne!(
            witness_key_set(&forward).expect("well-formed witnesses"),
            witness_key_set(&genuinely_different).expect("well-formed witnesses")
        );
    }

    /// I-D §7.1 / §6.2: a witness object missing `witness_id` is a schema failure, never
    /// silently dropped from the set — a governance-key-rotation comparison must not treat a
    /// malformed witness as simply absent.
    #[test]
    fn witness_key_set_rejects_a_witness_missing_witness_id() {
        let cc = format!("sha256:{}", "cc".repeat(32));
        let payload = json!({
            "witnesses": [
                { "keys": [
                    { "key_id": cc, "pubkey": "base64:AAAC", "valid_from_index": 0 },
                ] },
            ],
        });
        let result = witness_key_set(&payload);
        assert!(
            matches!(result, Err(ReceiptError::ManifestSchemaInvalid { ref object, .. }) if object.contains("witness_id")),
            "a witness object missing `witness_id` must be rejected, not silently dropped: \
             {result:?}"
        );
    }

    /// I-D §7.1: `governance.rotation_proofs[].witnesses[]` is "an array in the shape of
    /// `anchoring.witnesses[]`" whenever PRESENT — every element held to that shape, whatever
    /// the rotating manifest's level, even though a verifying cosignature is only REQUIRED at
    /// L3. The full corpus's only rotation is a genuine L3 one (its manifest's `level` is
    /// baked into signed, anchored bytes that cannot be changed to a lower level without
    /// breaking either that hop's own signature or its own committed inclusion path before
    /// this rule is ever reached — the same structural constraint documented on
    /// `key_set_comparison_is_order_independent` above), so a below-L3 case can only be
    /// exercised here, against `verify_rotation_proof` directly, with a hand-built one-off
    /// checkpoint and a tiny two-leaf tree rather than the shared corpus.
    #[test]
    fn rotation_proof_witnesses_are_shape_checked_below_l3() {
        let log_key = TestKey::from_seed_hex("log-1", &"11".repeat(32)).expect("test key");
        let witness_key = TestKey::from_seed_hex("witness-1", &"22".repeat(32)).expect("test key");

        let document = b"a synthetic adaptor profile document".to_vec();
        let profile_hash = sha256_hex(&document);
        let outgoing_manifest = json!({
            "log": {
                "log_id": format!("sha256:{}", "dd".repeat(32)),
                "operator": "log-operator-1",
                "adaptor": { "id": TEST_ADAPTOR_PROFILE_ID, "hash": profile_hash },
                "checkpoint_cadence": "PT1H",
                "cadence_epoch": "2026-08-16T11:30:00Z",
                "witness_grace_period": "PT15M",
                "keys": [
                    { "key_id": log_key.key_id(), "pubkey": log_key.pubkey(), "valid_from_index": 0 },
                ],
            },
            "witnesses": [
                { "witness_id": "witness-1", "keys": [
                    {
                        "key_id": witness_key.key_id(),
                        "pubkey": witness_key.pubkey(),
                        "valid_from_index": 0,
                    },
                ] },
            ],
        });
        // Below L3: this level never REQUIRES a rotation-proof cosignature, but a `witnesses[]`
        // member that IS present must still be shape-checked regardless.
        let rotating_manifest = json!({ "level": "L1" });
        let rotating_envelope = json!({ "payload": { "type": "manifest" }, "signatures": [] });

        let leaves = vec![jcs(&rotating_envelope), jcs(&json!({ "padding": true }))];
        let root = tree_root(&leaves);
        let proof = inclusion_proof(&leaves, 0).expect("index within tree");
        let inclusion_path: Vec<String> = proof.path.iter().map(hash_hex).collect();

        let log_id = format!("sha256:{}", "aa".repeat(32));
        let cp = checkpoint(&log_id, 2, &hash_hex(&root), "2026-08-16T12:00:00Z", &log_key);
        // A SECOND `witnesses[]` entry, missing `cosigned_at` — malformed shape, present below
        // L3 where no cosignature is required at all.
        let element = json!({
            "manifest_entry_index": 0,
            "checkpoint": cp,
            "inclusion_path": inclusion_path,
            "witnesses": [
                {
                    "witness_id": "witness-1",
                    "key_id": witness_key.key_id(),
                    "cosignature": witness_key.sign(&cosignature_bytes(&cp, "witness-1")),
                },
            ],
        });

        let profile = AdaptorProfile { document, capabilities: AdaptorCapabilities::default() };
        let mut run = Run::new(Limits::default());
        // The element's checkpoint-signing key is resolved through the receipt's own `keys`
        // block (I-D §7.1), bound to the outgoing manifest version, so the surrounding receipt
        // carries that one entry; the witness shape check under test comes after it.
        let receipt = json!({
            "keys": {
                "log": [ {
                    "key_id": log_key.key_id(),
                    "pubkey": log_key.pubkey(),
                    "source": "manifest-chain",
                    "binding": { "entry_index": 0 },
                } ],
                "witness": [],
                "producer": [],
            },
        });
        let policy = TrustPolicy::default();
        let manifests = [(0u64, &outgoing_manifest)];
        let result = verify_rotation_proof(
            &element,
            &rotating_envelope,
            0,
            &rotating_manifest,
            &RotationContext {
                receipt: &receipt,
                policy: &policy,
                manifests: &manifests,
                outgoing: (0, &outgoing_manifest),
                profile: &profile,
                profile_id: TEST_ADAPTOR_PROFILE_ID,
            },
            &mut run,
        );
        assert!(
            matches!(&result, Err(ReceiptError::Malformed(detail)) if detail.contains("cosigned_at")),
            "a malformed `witnesses[]` entry must be rejected below L3 too, not merely at L3: \
             {result:?}"
        );
    }
}
