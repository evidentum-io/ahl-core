//! Documents the generator publishes verbatim: the key README and the adaptor profile.
//!
//! The adaptor profile is content-addressed — the manifest pins the SHA-256 of the bytes
//! written to disk — so it lives here rather than being edited in place, and any change to it
//! changes the corpus.

/// `test_data/keys/README.md`.
pub const KEYS_README: &str = "\
# Test keys — TEST ONLY

Every file in this directory is a **published constant** of the AHL test-vector corpus.
The seeds are deliberately trivial byte patterns so that no one can mistake them for
generated material.

**Never reuse any of these values for anything real.** They are committed to a public
repository; anyone can sign statements, checkpoints, or witness cosignatures with them,
and anyone can recompute every `keyed` commitment in `test_data/`.

| File | Contents |
| --- | --- |
| `producer-1.seed` | Ed25519 seed, 32 bytes hex — the corpus producer |
| `producer-2.seed` | Ed25519 seed, 32 bytes hex — the key added by entry 9 |
| `log-1.seed` | Ed25519 seed, 32 bytes hex — checkpoint-signing key of the test log |
| `witness-1.seed` | Ed25519 seed, 32 bytes hex — the witness of manifest version 1 (spec §3.3) |
| `witness-2.seed` | Ed25519 seed, 32 bytes hex — the witness of manifest version 2, after rotation |
| `dataset_customers.key` | HMAC-SHA-256 key, 32 bytes hex — dataset `customers` (spec §2.4) |

Regenerate the corpus with `cargo run --bin gen_vectors`; the generator rewrites these
files from its own constants, so editing them by hand has no lasting effect.
";

/// `test_data/README.md` — how the corpus is produced and re-checked.
pub const CORPUS_README: &str = r#"# AHL test-vector corpus

The canonical conformance corpus for the AHL Protocol, generated from committed constants and
re-verified from disk on every test run. Everything here is derived; nothing is hand-edited.

Normative sources: **AHL Core Specification** v0.3-draft (statements, tree rules, conformance
levels, corpus manifest) for the pieces revision 0.4 has not restated, and the **AHL
Internet-Draft** draft-zatona-ahl-00 revision 0.4 for everything it does cover — §2.2 (the
`ahl_version`/`ahl_receipt_version`/`spec_version` clean break), §2.6 and §6.3 (canonicalization
descriptors, commitment modes, canonicalization identifier conformance) and, since revision 0.4
folded the receipt container into the core document, its own §7 (claim registry, assurance
semantics, cross-field rules, resource limits, the governance-key rotation rule of §7.1/§7.5.1).
Revision 0.4 verifies no material issued under any earlier revision (I-D §2.2, §7.1); this crate
implements it as a clean break, not a superset.

## The verification result (I-D §7.7)

A run that completes reaches exactly one of three values — `verified`, `invalid`,
`unverifiable` — and `verify_receipt_report` returns it together with the findings it reduces
from. `index.json` records both: every vector's `expect` is one of those three values, and a
non-verified vector also names, in `finding`, the required assertion whose finding produced it.

A **finding** is the outcome of one required assertion, with the same three values. The required
assertions of a receipt are the ones I-D §7.7 lists — the claim type's own §7.2 material, the
anchoring, envelope-validity, governance and cross-field checks of §7.5 steps 1-4 and §7.6, and
its content binding if and only if its own `assurance.content_binding` is not `none` — plus
every required assertion of each embedded receipt, WITH ONE EXCEPTION: an embedded receipt's
content binding is never a required assertion of the receipt that embeds it. This crate names
them `versions`, `resource-limits`, `structure`, `adaptor-profile`, `anchoring`, `governance`,
`checkpoint-authentication`, `witnesses`, `envelope-validity`, `cross-field`, `claim-material`
and `content-binding`, and reports one finding per assertion per receipt, embedded receipts
under the `claim_material` member names that reach them. Which assertion a rejection belongs to
is decided by the PHASE of the §7.5 algorithm that raised it, not by the error type the check
reached for: a malformed member is `structure` in the container, `governance` in a governance
statement's phase-2 validation, and `claim-material` in claim material.

A finding also says whether it is a CAUSE or a DERIVATION. `rests_on` is `None` where the
finding is what its own check produced — the rule that fired, the budget that ran out, the
capability that was missing — and names the prerequisite assertion where the finding merely
inherited that gap. `Report::dominating()` is the finding to lead with: the first `invalid` in
report order, otherwise the first `unverifiable` whose `rests_on` is `None`. Without that
distinction a reader taking the first `unverifiable` finding would be told "`versions` rests on
`resource-limits`" where what it needs — §7.8's "WHICH budget was exhausted and the value that
was in force" — is on the `resource-limits` finding. `verify_receipt`'s single-value form
returns the rejection behind that same finding, so the two APIs name one thing.

The result is the reduction: `invalid` if any required finding is `invalid`, otherwise
`unverifiable` if any is `unverifiable`, otherwise `verified`. An `invalid` finding ends the run
— the result is decided, and the assertions after it are not reported at all — while an
`unverifiable` finding does not: the run carries on with every assertion that does not rest on
the missing material, so that a defect reached later still dominates the gap. What each gap
reaches is fixed rather than left to the order of the algorithm:

| Unverifiable | What rests on it | What is still checked |
| --- | --- | --- |
| `adaptor-profile` (no profile held, one this build cannot interpret, a capability it does not define, a policy claiming one this build cannot parse) | `checkpoint-authentication`, `witnesses` — the profile document fixes the checkpoint serialization the signature is computed over — and, where the chain rotates a governance key set, `governance` too (see below) | structure, paths, the chain walk, envelope validity, claim material, content binding |
| `governance` (the configured genesis anchor differs, the configured genesis key fingerprints do, or the induction stopped at a rotation it could not authenticate) | `envelope-validity`, `checkpoint-authentication`, `witnesses`, and the claim material of the authority-dependent types | structure, paths, the chain walk itself, claim-material shape checks, content binding |
| `witnesses` (a cosignature naming a `local-policy` witness key the verifier does not hold; an entry no cosignature names is not a gap) | `cross-field`, since §7.6's `witnessed` rule is one of its rules | everything else, both checkpoint signatures included |
| `envelope-validity` (a declared-mode producer-key transition the mode does not carry) | the claim material of the authority-dependent types (§7.5.1 4e is applied only to envelopes valid under 4d) | everything else |
| `content-binding` (an unimplemented canonicalization procedure, a dataset key not held) | nothing | everything else |

An assertion resting on an unverifiable one is itself `unverifiable`, with a detail naming that
prerequisite, and dependence is transitive.

Two consequences are worth stating on their own. **A rotation that cannot be authenticated
applies no effect.** I-D §7.5.1 4b(M) proves a rotating manifest's own anchoring under the
OUTGOING key state, and that proof rests on a checkpoint — so without the adaptor profile phase
2 has not passed, and 4b's "No effect is ever applied to K by a statement that has not completed
both earlier phases" governs: the induction stops before that manifest, K stays pre-rotation,
`governance` is `unverifiable` naming the entry index, and every check that would resolve a key
at or after it is skipped rather than run against a superseded state — which is also 4f's own
rule. A chain that rotates nothing is untouched. The same division applies to what the chain
HOLDS rather than to what it establishes: a manifest version the walk reached and does not hold,
or one the chain does not carry at all, is material the receipt owed and is `invalid`, while a
version the chain DOES carry at or after the stop is a capability gap — the content-binding
finding that needed its descriptor is `unverifiable` resting on `governance`, never a defect of
the artifact. One rule sits underneath all of this: I-D §2.1's "If duplicates nevertheless occur, the envelope
with the smallest entry index governs and later ones are void." Every statement-id-keyed lookup
over chain material is FIRST-WINS — the map §7.6's rules read, the map the descriptor and
key-statement checks resolve versions through — and the induction skips a later duplicate as a
GOVERNING statement: it applies no effect, consumes no rotation proof, and never becomes the
version a `subject.manifest` reference resolves to, while the `predecessor` linkage of later
manifests still runs against the governing copy. Void of effect is not void of verification —
§7.5 step 4 says "verify EVERY CARRIED ENVELOPE", and 4d takes "every carried envelope that is
not part of the induction" — so a void duplicate is verified under §2.1 at its own entry index
against completed K, on the `envelope-validity` assertion, exactly like the subject's own
envelope; past an induction stop that check does not run and rests on `governance`. The
enumerated 4d sweep exempts the entry INDEXES the induction walked rather than the statement
types it walks, because a void copy carries the same type — and the same statement id — as the
copy that governs. What the chain CARRIES is counted separately, void copies
included, because §7.5.1 4c asks whether the chain shows every manifest the enumerated range
reveals.

§7.6's own rules about `subject.manifest` are on the other side of that line
entirely and are never downgraded: that the named version is present in `governance.chain` and
anchored strictly before the subject is read off the raw chain, at the entry index step 3 proved
for each element, and is `invalid` on `cross-field` whether or not the induction stopped. Only
the rule that asks which version was ACTIVE — a question the walk answers — is left unevaluated
past a stop. **Each checkpoint's cosignatures are their
own question.** A `local-policy` witness key the verifier does not hold leaves the cosignatures
that NAME it unevaluated and nothing else — and an entry NO cosignature names is not a gap at
all, since I-D §7.1's key obligation is conditional on use ("Every key USED in verification MUST
appear in `keys`"). That conditionality is for `local-policy` alone: a `manifest-chain` entry is
judged against the manifest version its BINDING names whether or not anything selects it, since
"A `manifest-chain` key that matches no object in the manifest version its binding names, or
that differs from the matching object in any compared member, is `invalid`" is a rule about the
entry rather than about the checkpoint. What each checkpoint's cosignatures settle is: the cosignatures under keys that did resolve are
verified, both the primary and the later checkpoint's log signatures are verified, and
`assurance.continued_history` is still evaluated against `later_checkpoint`, `later_witnesses`
and `consistency_path`. A later checkpoint that does not verify is `invalid` and is never hidden
behind an unrelated gap. Where a §7.6 rule COULD not be evaluated — `witnessed` or
`continued_history` — the `cross-field` finding is `unverifiable` naming what blocked it, since
a rule that was skipped is not a rule that held. Two conditions end the run even so, both ordering rules rather than reductions: an
unsupported version, which §7.5 step 1 follows with "no further processing", and an exhausted
verifier-local budget, which §7.8 requires to fail closed. A boundary is rendered only for
`verified`, and no result is ever expressed by rewriting the receipt's own assurance fields.

**Void entries and informative items.** Not every non-verifying envelope is a defect of the
receipt that carries it. I-D §7.5.1 4d decides that by RELIANCE: the subject's envelope, an
embedded receipt's subject and every `governance.chain[]` element are what a receipt rests on,
and a failure there is `invalid`; every other carried envelope — a purported competing-trigger
envelope, an entry of a propagation prefix, any entry an enumeration reveals — is VOID,
"excluded before any authority comparison... never effective and never traversed", and does not
affect the result. Each void entry the run inspected is reported as an informative item carrying
its entry index and reason (`signature-invalid` or `key-not-active`); `index.json` records the
COUNT as `informative` for the vectors that have any. Informative items are not findings: they
belong to no assertion, carry no result value, never enter the reduction and never appear in
`Report::dominating()`. The reason 4d gives is the log contract — a log anchors opaque bytes and
validates none, so were a void entry a defect of every later receipt, any party able to anchor
one envelope could disable every enumerated claim of that log from that index on.

`verify_receipt` remains as the single-value form for callers that report one rejection: `Ok`
if and only if the result is `verified`, and otherwise the rejection behind the finding that
decided it. `ReceiptError::class` gives the §7.7 value of one rejection, exhaustive over the
variants; `ReceiptError::assertion` is the FALLBACK for a rejection examined outside a run,
since inside one the assertion is the phase that raised it.

The §7.8 FIXED limits are constants of the crate — `MAX_EMBEDDED_DEPTH` (4) and
`MAX_EMBEDDED_RECEIPTS` (64) — and not members of the trust policy: they "are properties of the
artifact, decided identically by every verifier in every year", and a verifier that could lower
either would report `invalid` over a receipt another verifier verifies. `index.json`'s
`policy.limits` therefore carries only the two VERIFIER-LOCAL budgets. Exceeding a fixed limit
is `invalid` on the `structure` assertion, since the two "bound a receipt's STRUCTURE and not
its size"; exhausting a budget is `unverifiable` on `resource-limits`, naming the budget and the
value in force.

Which conditions this build reports as `unverifiable` rather than `invalid`, and why:
`UnsupportedVersion` (I-D §2.2, §7.5 step 1), `BudgetExhausted` (§7.8, naming the budget and
the value in force), `AdaptorUnknown` and `AdaptorCapabilityUnsupported` (§7.5 step 2),
`AdaptorProfileMisconfigured` and `GenesisAnchorMismatch` and `WitnessKeyNotTrusted` (local
configuration the verifier was not given), `CanonicalizationUnsupported` (§6.3),
`DatasetKeyNotHeld` (§7.3) and `ProducerKeyNotCarried` (§7.4). Everything else is `invalid`.

`ProducerKeyNotCarried` is the one of these decided by the receipt's governance MODE rather
than by this build's capabilities. Under `declared` governance an envelope naming a producer
key the presented chain holds nothing for is `unverifiable` — the transition is a `key`
statement, and I-D §7.4 carries those in enumeration material alone, so the receipt is short
of material rather than defective. Under `enumerated` the same condition is `invalid`
(`EnvelopeSignatureInvalid`), because the range proof over exactly `[0, tree_size(C))`
forecloses omission (§7.5.1 4c). The pair
`statement-anchored-uncarried-key-transition-must-fail.ahl` and
`trigger-effective-derived-rotated-key.ahl` carry the SAME entry-19 envelope under the two
modes: the first is `unverifiable` — the corpus's one non-`invalid` negative — and the second
verifies.

The capability gaps are exercised by `tests/vectors.rs` rather than by a vector, because what
decides each of them is the verifier's own configuration rather than anything a portable vector
can carry — a policy holding no adaptor profile, another corpus's genesis anchor, no trusted
witness key, no dataset key, or a tightened budget — and each is tested both alone (result
`unverifiable`, the independent assertions `verified`) and together with a byte-decidable defect
elsewhere (result `invalid`, the gap reported beside it). Among them: a `keyed-authorized` binding under a policy holding no dataset key (I-D §7.7's own
worked example — result `unverifiable`, anchoring and claim material still `verified`, the
content binding `unverifiable`), and each of the two verifier-local budgets of §7.8 exhausted
under a tightened policy, which must name the budget and the value in force. The embedded-content
-binding exception is covered the same way, by splicing the content-bound `record-ingested`
vector into the `trigger-declared` vector's `introduction` slot, since every embedded receipt
this corpus carries asserts `content_binding: "none"`.

## Not yet implemented from revision 0.4

This crate's verifier does not yet implement every rule revision 0.4 states, and refuses rather
than silently mis-verifying wherever the gap could otherwise be mistaken for a pass:

*   **Canonicalization procedures beyond `jcs` and `exact-bytes` (I-D §2.6).** These are the
    only two the I-D itself defines, and the only two this crate implements. A dataset declaring
    any other `canonicalization` identifier — a registered one this crate has not implemented,
    or a private-use `x-` one — makes that dataset's content-binding finding `unverifiable`
    (`ReceiptError::CanonicalizationUnsupported`), never `invalid` and never rehabilitated to
    `content_binding: "none"`, exactly as I-D §6.3's conformance table requires. No vector in
    this corpus exercises an unimplemented identifier end to end: the identifier comes from the
    MANIFEST, so carrying one would mean a manifest declaring a dataset this crate cannot
    verify, and every receipt over that dataset would be built on it. The equivalent
    capability gap on the same finding — a dataset key the verifier is not authorized to hold —
    is exercised instead, in `tests/vectors.rs`.
*   **ATL adaptor profile support in the receipt verifier.** Leaf construction (adaptor
    `ahl-adaptor-atl-v1` §4.2: `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)`),
    origin-derived `log_id` (§7.1: `sha256(Origin ID)`, Origin ID the SHA-256 of a 16-byte Data
    Tree UUID), and profile release (§14: "Until this document is released as an immutable,
    openly published artifact… no manifest may pin it") are pending — none is dispatched
    anywhere in this crate today, so a receipt naming that profile is refused as
    `ReceiptError::AdaptorCapabilityUnsupported`, never accepted. The checkpoint-level
    mechanism (§6.1-§6.5: assembling and signing the 98-byte blob, and reconciling a carried
    `raw` byte-for-byte against it) exists as `pub` helpers in `lib.rs` —
    `checkpoint_signing_bytes_for`, `atl_checkpoint_blob`/`atl_checkpoint_blob_from_json`,
    `reconcile_atl_checkpoint_raw`, `atl_checkpoint_time`/`atl_checkpoint_time_nanos` — and is
    unit-tested there over a synthetic checkpoint, for a client integrating ATL directly.

Also not yet in the corpus: no vector carries a witness key sourced `local-policy` (I-D §7.1).
The corpus trust policy holds no trusted witness key at all, so every witness key in every
vector is `manifest-chain`, bound by `(witness_id, key_id, pubkey)` to the manifest version
active for the checkpoint being cosigned. The `local-policy` branch — admissible only for
witness keys the verifier ALREADY TRUSTS, matched on `key_id`, `pubkey` AND the `witness_id`
policy holds the key for, and admissible only under an identity the active manifest itself
declares — is covered by `tests/vectors.rs` instead, since what decides it is the verifier's
own configuration rather than anything a portable vector can carry.

Also not yet in the corpus: this corpus's ONE governance-key rotation (manifest v2, entry 25)
rotates the WITNESS set only — the log checkpoint-signing key never itself rotates anywhere in
this corpus. `governance-key-rotation-proof-incoming-key-must-fail.ahl` therefore substitutes a
witness key for the rotation-proof checkpoint's signer to demonstrate "not a key of the outgoing
set", which exercises the same code path (`log_key_set` membership) a genuine incoming LOG key
would, but is not the same fact: a verifier that wrongly accepted an INCOMING log key
specifically is not what that vector rules out. A second, LOG-rotating manifest version (a
third manifest, or a variant corpus branch) with its own outgoing/incoming-key positive and
negative pair — and, since this corpus would then carry two governance-key rotations, a genuine
"out-of-order pair" `rotation_proofs[]` negative alongside it — is the intended follow-up.

`governance.rotation_proofs[]` verification (I-D §7.1, §7.5.1) IS implemented: a manifest whose
log or witness key objects, compared as sets, differ from its predecessor's is a GOVERNANCE-KEY
ROTATION, and its rotation-proof element is verified under the OUTGOING key state — the
checkpoint signature under the outgoing log key, the manifest's inclusion under that checkpoint,
and, AT L3, a cosignature under the outgoing witness set. The corpus's manifest version 2 (entry
25) rotates the witness key set, and every vector whose chain carries it now carries a genuine
`governance.rotation_proofs[]` element proving that transition; the eleven
`governance-key-rotation-proof-*-must-fail.ahl` vectors cover the collection-level rules (I-D
§7.1: required iff a rotation is present, one element per rotation, ascending order, no
duplicates, no extras) and the per-element ones (checkpoint and witness shape, the outgoing-key
requirement, and — since "every key used in verification MUST appear in `keys` with its source
and its binding" — that the element's log and witness keys are LISTED in `keys.log[]` and
`keys.witness[]` bound to the OUTGOING manifest version, per §7.1's transition exception).
Every receipt whose chain carries the rotation therefore lists the outgoing log key and the
outgoing witness alongside the keys its own checkpoint uses: the log key appears twice, under
two different bindings, which is the case receipt key binding is tolerant for.

## Layout

| Path | Contents |
| --- | --- |
| `adaptor/` | The test adaptor profile document, content-addressed and pinned in both manifest versions |
| `vectors/statements/` | The 41-entry toy corpus, plus malformed statements naming the rule each violates |
| `vectors/merkle/` | Log tree (entry-index order, never sorted), the record-sorted batch, wide-outputs, input-set and disposition trees, and authenticated range proofs |
| `vectors/checkpoints/` | Signed checkpoints at tree sizes 8, 13, 20, 24, 25, 26, 28, 29, 30, 32, 34, 35, 37 and 38, each cosigned by the witness its active manifest version declares — EXCEPT cp26, deliberately cosigned by the OUTGOING witness-1 for the I-D §7.1 rotation-anchoring proof at manifest v2 (see "Governance-key rotation" below) |
| `vectors/closure/` | Six closure scenarios (see below) |
| `vectors/witness/` | Signed witness refusal evidence carrying two conflicting checkpoints (spec §3.3 step 3) |
| `receipts/` | One positive and at least one negative receipt per claim-type registry entry, plus `index.json` naming the I-D §7.7 result each must reach, the assertion whose finding produces a non-verified one, the rule each negative must trip, and the trust policy those outcomes assume |
| `keys/` | Committed test key seeds — **see the warning below** |

## The scenarios

The corpus is 41 anchored entries carrying these interlocking scenarios:

1. **Propagation.** A retroactive correction at entry 6 affects four derived records; the
   successor derivation consuming the *replacement* is correctly outside the affected set.
   Entry 8 anchors the disposition tree, and `propagation-complete` proves it equals the
   closure recomputed from the enumerated corpus prefix.
2. **Correction supersession.** Entry 12 corrects the same original record again, superseding
   entry 6. Its closure seeds are the original *and* the superseded replacement — never its own
   replacement (spec §5.1). That is what pulls in the successor derivation and the batch at
   entry 10, whose outputs are reachable only by walking two committed trees: the batch outputs
   tree, and the input-set tree its leaves commit by root.
3. **Retraction after correction.** Entry 18 retracts the *original* record outright, after two
   corrections of it. A retraction seeds exactly its own record (spec §5.1), so the consumers of
   the replacements stay out of the affected set — the opposite of scenario 2, and the reason
   the two rules are not one rule.
4. **Non-retroactive scope.** Entries 14–16 derive from one record with a point valid time
   before the boundary, an open interval, and a closed interval ending before the boundary. The
   retraction at entry 17 (`retroactive: false`) affects exactly one of them. Scope is evaluated
   as an interval intersection over parsed instants, never as string comparison.
5. **Challenge.** Entry 23 retracts a record under a key that is *not* the dataset authority, so
   it anchors as a challenge (spec §2.3.3); entry 24 propagates over it anyway. No
   `propagation-complete` receipt over that propagation can verify, which is the point.
6. **Signature handling on competing triggers.** Entries 29, 32 and 33 all retract record F.
   Entry 29 is genuinely co-signed by the authority and a second active producer key (entry 28
   re-adds it after manifest v2 dropped it); entry 32 names the real authority's `key_id` with a
   signature that does not verify; entry 33 carries a genuine signature from a non-authority key
   alongside a non-verifying one that names the authority. Spec §2.1 forbids two envelopes
   sharing a statement id, and the statement id digests the payload alone, so the three carry
   different `reason_code` values — otherwise they would be one statement anchored three times,
   of which only entry 29 would govern and the other two would be void.

   What a non-verifying carried envelope MEANS is decided by reliance (I-D §7.5.1 4d). Neither
   of these is an envelope a receipt over another subject rests on, so each is VOID: "excluded
   before any authority comparison... never effective and never traversed", reported as an
   informative item naming its entry index, and leaving the result alone.
   `trigger-effective-void-candidate.ahl` carries them as competing candidates for the subject
   record and `governance-state-void-entry.ahl` carries them where no claim-specific rule looks
   at them at all; both VERIFY, each reporting two informative items. What is still `invalid` is
   a receipt that rests on such an envelope:
   `trigger-effective-unverified-authority-signature-must-fail.ahl` makes entry 33 its own
   subject and is refused.
7. **A `key` statement that retires its own signing key.** Entry 30 retires `producer-2` under
   `producer-2`'s own signature; entry 31 re-adds the key, so the fixture at entry 33 keeps a
   genuine signature from a key in force. Governance statements are verified by the induction of
   I-D §7.5.1 4b — "against K AS ESTABLISHED SO FAR, the governance state in force immediately
   before this statement's own entry index" — and their effect applied only afterwards, which is
   why a self-retirement is conforming. 4d's remaining-envelope check is scoped to "every
   carried envelope that is NOT part of the induction" for the same reason: re-checking entry 30
   under the completed key state at its own index would resolve `producer-2` after its own
   retirement had taken effect. `governance-state-self-retiring-key.ahl` enumerates `[0, 32)`,
   which reaches both statements, and must be accepted.
8. **Record identity is a pair.** Entries 35 and 36 name a commitment beside the wrong
   dataset: entry 35 corrects `customers`/A to S1, a record that exists only in `scores`, and
   entry 36 retracts `scores`/A using record A's `customers` commitment. Neither is a mutated
   fixture — both are genuinely signed and genuinely anchored — because §2.6's domain
   separation makes such a pair impossible to reach through CONTENT while leaving a producer
   free to NAME one, and a verifier recomputes a commitment only where content evidence is
   carried. `trigger-declared-cross-dataset-introduction-must-fail.ahl` and
   `trigger-declared-cross-dataset-replacement-must-fail.ahl` embed introduction proofs whose
   commitment matches exactly and whose dataset does not; both must be refused (I-D §2.4.2,
   §2.4.3, §7.6).
9. **Continued history.** A consistency proof from cp20 to cp24 backs
   `assurance.continued_history` on a receipt, and a proof generated for a different pair of
   sizes — genuine, correctly built, about the wrong fact — is rejected. `anchoring.checkpoint`
   and `anchoring.later_checkpoint` each carry their OWN witness cosignatures — the primary
   one's in the sibling `anchoring.witnesses[]`, cp24's own in `anchoring.later_witnesses[]`
   (I-D §7.1: present if and only if `later_checkpoint` is carried; at L3, at least one element
   MUST verify, cosigning `later_checkpoint` itself rather than `anchoring.checkpoint`). A third
   vector pairs
   enumerated governance currency with a later checkpoint: every piece of it is individually
   valid, and it is still refused, because receipt format §2.1 wants governance coverage through
   the later checkpoint's tree size while §4 fixes enumerated material at the anchoring
   checkpoint's, and no range satisfies both. A format that cannot express the evidence is a
   reason to refuse, never a reason to report missing evidence as verified.

Entry 25 anchors a second manifest version that rotates the witness key set in full and drops a
producer key from its snapshot, chained to its predecessor by *entry* id; entries 26 onward are
anchored under it. I-D §7.1 requires a `governance.rotation_proofs[]` element proving this
transition under the OUTGOING witness state (witness-1): `cp26` (tree size 26) is that proof's
own checkpoint, deliberately cosigned by witness-1 even though it postdates entry 25, exactly
the "operator kept signing under the outgoing key until cutover" case I-D §7.1 describes as an
ordinary artifact of a real log rather than something a producer must manufacture.

10. **Stale manifest binding.** Entry 34 is a genuine, fully anchored, genuinely signed ingestion
   whose payload nonetheless names manifest v1 (genesis) as governing it, even though v2 (entry
   25) is the manifest ACTIVE at entry 34 (I-D §2.2). `record-ingested-stale-manifest-must-fail.ahl`
   proves this is `invalid` however genuine the rest of the statement is — real signature, real
   inclusion, real record — and needs a genuinely anchored statement rather than a mutated
   fixture, because mutating any already-anchored envelope invalidates its own inclusion path
   before the rule under test is ever reached.
11. **Void governance material, and the reliance rule.** Entries 38 and 39 are a purported
   `key` statement and a purported manifest version whose envelopes do not verify — a log
   anchors opaque bytes and validates none, so both really can be anchored — and entry 40 is a
   `key` statement that DOES verify while declaring `ahl_version: "0.5"`. I-D §7.5.1 4b selects
   an enumeration-only entry for the induction by its purported `type` but admits it "only if
   its envelope verifies in phase 1": 38 and 39 are void, not inducted, with no effect on the
   key state and no type-specific validation at all (§7.5 step 1 exempts a non-verifying
   enumeration-only entry from the version read too), while §7.4 adds that a void entry's
   absence from `governance.chain[]` is not an omission. Entry 40 is the other case: verifying,
   so K is unestablished from its index and the `governance` finding is `unverifiable`.
   `governance-state-void-governance-entries.ahl` (over cp40) verifies with four informative
   items; `governance-state-foreign-revision-key-must-fail.ahl` (over cp41) is `unverifiable`.
   All three sit past every checkpoint the rest of the corpus anchors at, so no other vector's
   range reaches them.

12. **Input-set trees take the §2.7 tree rules.** I-D §2.7 states one set of rules, "identical
   for every AHL tree — outputs, input sets, and dispositions". Entry 37 is a batch whose three
   output leaves each commit an input-set tree breaking exactly one of them: leaves out of
   ascending `record` order, a record repeated under two roles, and a `record` that is not a
   family string under §2.1. The three `record-derived-input-set-*-must-fail.ahl` vectors carry
   the COMPLETE committed set for their tree, with genuine membership paths at genuine indexes,
   so nothing about paths, indexes or cardinality is wrong — only the tree is, which is the
   point: the producer who chooses the leaf order chooses the tree, so a set assembled in any
   other order opens a root of its own and is still not an AHL tree. These have to be genuinely
   anchored for the same reason the entries above do; mutating an anchored leaf's
   `input_set_root` breaks the outputs path before the rule under test is reached.

   The cost is stated rather than hidden: closure traversal opens every committed tree it
   reaches and validates it against these same rules before reading an edge, so a closure walk
   reaching entry 37 fails by §2.7. Every closure scenario this corpus publishes stops at tree
   size 28 or below, and the three defective trees are deliberately absent from
   `vectors/merkle/`, where they would be read as conforming material. That rejection is
   asserted rather than assumed: `tests/vectors.rs` reassembles the defective material from
   the three receipt vectors that carry it and runs a traversal one entry PAST the conforming
   prefix, which must stop on the tree rule the material breaks.
13. **Where governance material travels.** I-D §7.1 defines every `governance.chain[]` element
   as "an anchored manifest statement's complete envelope", and §7.4 says the other governance
   type travels elsewhere: "`governance.chain[]` carries manifest statements; producer-key
   transitions are `key` statements, and those reach a verifier only through enumeration
   material." Every chain in this corpus therefore carries manifests and nothing else — `[0]`
   or `[0, 25]` — while the `key` statements at entries 9, 28, 30 and 31 reach a verifier
   through the enumerated range, which §7.5.1 4b merges with the chain in entry-index order to
   form one induction. Two negatives police the two halves of that split.
   `governance-chain-key-statement-element-must-fail.ahl` carries the genuine entry-9 `key`
   statement as a chain element — real envelope, real signature, real inclusion path — and is
   refused as a container the format does not define, because a chain that may carry key
   transitions is a second, unenumerated carrier for them.
   `governance-enumerated-manifest-omitted-must-fail.ahl` omits manifest v2's chain element
   from a receipt whose own enumeration proves v2 anchored at entry 25, and is refused because
   §7.5.1 4c's "the range proof forecloses omission" holds only if the induction walked every
   manifest the range reveals.

   One consequence follows for declared mode and is worth stating: a declared-mode receipt
   carries no `key` statement at all, so a subject signed by a key some `key` statement added
   after the manifest version the subject binds to is not verifiable in that mode. I-D §7.4
   governs, and puts the obligation on the producer: "A producer intending its receipts to be
   verifiable in declared mode MUST anchor a manifest version snapshotting the current producer
   key set before issuing them." Every declared-mode vector in this corpus satisfies that: its
   subject resolves against the manifest snapshot in force at its own entry index.

## Regenerating

```
cargo run --bin gen_vectors
```

The generator has no wall-clock read and no randomness: every timestamp is a fixed constant,
every key comes from a committed seed, and every record is committed content. Two consecutive
runs must leave `test_data/` byte-identical — if they do not, that is a bug.

Before writing anything the generator verifies its own output and aborts on any mismatch:
statement-id and entry-id uniqueness (spec §2.1), every envelope signature — including that the
two deliberately non-verifying fixtures really do not verify — the manifest lineage and
key-snapshot semantics, the challenge's authority status, every checkpoint signature and witness
cosignature, every inclusion proof, every range proof (including that it rejects substitution),
every consistency proof between published checkpoints (including that a proof for the wrong pair
of sizes is rejected), the witness refusal evidence, and an independent recomputation of every
revocation closure. It then runs every receipt vector
through `verify_receipt_report` and requires each positive one to reach `verified` and each
negative one to reach the §7.7 result of the rejection it names, *by the specific rule it
names*. A vector that cannot be self-verified never reaches
the repository.

## Checking

```
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo llvm-cov --all-features --fail-under-lines 90
```

`tests/vectors.rs` reads only the files on disk, exactly as a foreign implementation would.

## Anti-drift with atl-core

AHL is a sibling of ATL (Anchored Transparency Log), and their Merkle semantics must not drift
apart. The crate depends on [`atl-core`](https://github.com/evidentum-io/atl-core) pinned to an
exact revision and — normatively — **verifies every inclusion proof through
`atl_core::core::merkle::verify_inclusion`**, never through a local reimplementation.
Canonicalization (RFC 8785 JCS), node hashing, root computation and proof generation come from
the same place.

Consistency proofs come from `atl-core` too — `generate_consistency_proof` and, for
verification, `verify_consistency` — so AHL's `continued_history` evidence is the RFC 9162
construction the ATL family already implements, not a second one.

Range proofs are the one construction `atl-core` has no primitive for, so the combining
recursion is local. Every hash it computes is still `atl-core`'s: subtree roots from
`compute_root`, interior nodes from `hash_children`, the split point from
`largest_power_of_2_less_than`. A width-1 range is an inclusion proof in a different
serialization, and the verifier cross-checks it through `verify_inclusion` so the two
constructions cannot diverge.

## Test keys — never reuse

Every seed in `keys/` is a **published constant** committed to a public repository,
deliberately made of trivial repeating bytes so it cannot be mistaken for generated material.
Anyone can sign statements, checkpoints and cosignatures with these keys, and anyone can
recompute every `keyed` commitment in the corpus. They exist so the vectors are reproducible.
**Never use them for anything real.**

## Status

Working draft, tracking AHL Internet-Draft draft-zatona-ahl-00 revision 0.4 (which now defines
both the core protocol and, in its own §7, the Evidence Receipt container) for everything it
covers, and spec v0.3-draft for the rest. All are drafts, so the corpus is expected to change
with them; the intended stable contract is the *shape* of the corpus, not yet its digests. See
"Not yet implemented from revision 0.4" above for what `verify_receipt_report` does not yet
check.
"#;

/// `test_data/adaptor/ahl-test-log-v1.md` — the content-addressed adaptor profile.
pub const ADAPTOR_DOC: &str = r#"# Adaptor profile `ahl-test-log-v1`

**Status:** test profile for the AHL Protocol conformance corpus.
**Profile id:** `ahl-test-log-v1`
**Profile hash:** `sha256:<SHA-256 over the exact bytes of this file>`, pinned in the corpus
manifest (`log.adaptor.hash`) and carried in every Evidence Receipt (`anchoring.adaptor.hash`).

This document is the whole of what a verifier needs in order to check the vectors in
`test_data/`. Core specification §3 item 6 requires adaptor profiles to be versioned,
immutable, content-addressed, openly published and independently implementable, and forbids
verification from depending on knowledge outside the profile document. This profile is
deliberately minimal and is **not** a production log binding: it defines serialization only,
and says nothing about availability, cadence enforcement, or operator conduct.

## 1. Hashing

SHA-256 throughout. Family strings follow the receipt format §1.4 conventions:
`"sha256:<lowercase hex>"`, `"hmac-sha256:<lowercase hex>"`, `"base64:<standard base64,
with padding>"`.

## 2. Trees

All AHL trees under this profile — the log tree, batch output trees, input-set trees and
disposition trees — are RFC 6962-style binary Merkle trees over SHA-256 with the domain
separation of core spec §2.5:

```
leaf_hash(b) = SHA-256( 0x00 || b )
node_hash(l, r) = SHA-256( 0x01 || l || r )
```

The root of a tree over `n > 1` leaf hashes splits at `k`, the largest power of two strictly
less than `n`: `root = node_hash(root(leaves[0..k]), root(leaves[k..n]))`. A one-leaf tree's
root is its leaf hash. Empty trees do not occur in this corpus.

### 2.1 Log tree

Leaf bytes are the anchored entry bytes: `JCS(envelope)`, the same bytes the entry id digests.

```
log leaf_hash(i) = SHA-256( 0x00 || JCS(envelope_i) )
```

Log leaves are in **entry-index order** and are never sorted: the entry index is the
position of the entry in the append-only log and is AHL's only ordering primitive
(core spec §1.2, constitution art. 9).

### 2.2 Record-sorted trees

Batch output trees, input-set trees and disposition trees carry leaf **objects**; the leaf
bytes are `JCS(leaf object)`. Their leaves are sorted and duplicate-free per core spec §2.5:

- sort key: the value of the leaf's `record` field, compared as the ascending lexicographic
  order of the **UTF-8 bytes of the canonical commitment string** (`"sha256:<hex>"` or
  `"hmac-sha256:<hex>"`, lowercase hex);
- a `record` value that is not a canonical commitment string makes the tree invalid, rather
  than being ordered by some fallback rule;
- two leaves with equal `record` values make the tree invalid.

Because the sort key is the family string rather than the raw digest, a tree whose leaves mix
commitment modes orders all `hmac-sha256:` records before all `sha256:` records (`h` < `s`).
This profile does not restrict such trees; it only fixes the ordering so two implementations
agree. `test_data/vectors/merkle/input-set-tree.json` is such a mixed tree.

Batch output leaves use `leaf_format` `ahl-leaf-v2` (core spec §2.5):
`{ "dataset", "record", "inputs": [ full derivation input objects ] }`. A leaf's `inputs` MAY
instead be the wide-input form `{ "input_set_root", "input_set_count" }` (core spec §2.5), in
which case the leaf commits its input set by root and the input-set tree is a second committed
tree that must be published under §3.5. Receipt format §3 depends on this composition:
`record-derived`'s `input_members` "applies ONLY when `batch_leaf.inputs` is the input-set
form". The batch at entry 10 of the corpus is exactly that shape.

Input-set leaves are full derivation input objects (core spec §2.3.2), carrying at least
`dataset` and `record`.

Disposition leaves use the shape of core spec §2.3.4.

### 2.3 Inclusion proofs

A proof is serialized as a JSON array of family strings, ordered **leaf to root**:

```json
{ "leaf_index": 3, "tree_size": 10, "path": [ "sha256:<hex>", "sha256:<hex>", ... ] }
```

In an Evidence Receipt the same array appears bare as `anchoring.inclusion_path`,
`governance.chain[].inclusion_path`, `claim_material.leaf_path` and
`claim_material.input_members[].input_path`. The tree size is then taken from the checkpoint's
`tree_size` or from the corresponding tree's committed count (`outputs_count`,
`input_set_count`, `affected_count`). The **leaf index** is taken from `subject.entry_index`
and `governance.chain[].entry_index` where those exist; where they do not, this profile fixes
the sibling member that carries it:

| bare path | leaf index carried as | tree size taken from |
| --- | --- | --- |
| `anchoring.inclusion_path` | `subject.entry_index` | `anchoring.checkpoint.tree_size` |
| `governance.chain[].inclusion_path` | `governance.chain[].entry_index` | `anchoring.checkpoint.tree_size` |
| `claim_material.leaf_path` | `claim_material.leaf_index` | `outputs_count` / `affected_count` of the subject payload |
| `claim_material.input_members[].input_path` | `claim_material.input_members[].input_index` | `input_set_count` of the leaf's `inputs` |

Receipt format §3 has since ratified `leaf_index` and `input_index` as members of the
`record-derived` schema itself; the table above is retained because it also covers
`disposition-declared`/`disposition-effective`, whose `leaf_path` opens `affected_root`.

Verification is the standard RFC 6962 recomputation of the root from the leaf hash and the
path, compared against the anchored root.

## 3. Keys

- **Public key encoding**: `"base64:<raw 32-byte Ed25519 public key>"`. No SPKI, no PEM.
- **Key id**: `"sha256:<hex of SHA-256 over the raw 32-byte public key>"`. For producer keys
  this is normative at core-spec level (§2.3.6); this profile adopts the identical rule for
  log and witness keys, whose derivation core spec §2.3.6 leaves adaptor-defined. The key id
  is a fingerprint, not a signature input; a verifier resolves it against key objects
  `{key_id, pubkey, valid_from_index}` in the manifest (core spec §7.2) and MUST recompute it
  from `pubkey` rather than trusting the carried value.
- **Signature encoding**: `"base64:<raw 64-byte Ed25519 signature>"`, Ed25519 per RFC 8032.

## 4. Statement envelopes

```json
{ "payload": { ... }, "signatures": [ { "key_id": "sha256:<hex>", "sig": "base64:<...>" } ] }
```

The signature member is spelled `key_id` — the same spelling as manifest key objects, `key`
statement key objects, and the receipt `keys` block. The signature covers `JCS(payload)`
exactly (core spec §2.1). An envelope with an empty `signatures` array is not an AHL
statement. Consequently:

- **statement id** = `"sha256:" || hex(SHA-256(JCS(payload)))`
- **entry id** = `"sha256:" || hex(SHA-256(JCS(envelope)))`

A non-genesis `manifest` statement references its predecessor manifest by **entry id** in the
member `predecessor` (core spec §2.3.5, which now names the member and makes it REQUIRED for
non-genesis manifests and forbidden for the genesis manifest).

### 4.1 Dataset authority

Core spec §7.2 now fixes the shape, and this profile carries it verbatim:

```json
"authority": { "producer": "<producer id>", "key_ids": [ "sha256:<hex>", ... ] }
```

`producer` MUST equal the manifest producer in core. A trigger for an ingested record of that
dataset is **effective** only if at least one of its signatures is by a key id that is in
`key_ids` **and** active at the trigger's own entry index (core spec §2.3.3, §7.2) — so a key
the authority list names but a later manifest snapshot dropped no longer triggers.

A trigger signed by any other key — including another valid key of the same producer — anchors
as a **challenge**: surfaced by verification, never traversed by closure, and never permitted
to govern. Effectiveness is decided *before* the greatest-entry-index rule of core spec §2.3.3
selects among competing triggers; a challenge at a greater entry index therefore cannot unseat
an earlier authorized trigger. `test_data/vectors/statements/23-*.json` is such a challenge,
sitting one index after the authorized retraction at entry 22:
`trigger-effective-later-challenge-ignored.ahl` shows entry 22 still governing, and
`propagation-complete-challenge-trigger-must-fail.ahl` shows a completeness claim over the
challenge being rejected.

For a *derived* record the authority is the introducing producer's key set **as of the
trigger's entry index** — not the introduction index, so a key rotation between the two applies
(core spec §2.3.3). `trigger-effective-derived-rotated-key.ahl` exercises exactly that: S1' is
introduced at entry 7, `producer-2` is added at entry 9, and the retraction at entry 19 signed
by `producer-2` is effective.

## 5. Checkpoints

```json
{ "log_id": "sha256:<hex>", "tree_size": 10, "root_hash": "sha256:<hex>",
  "checkpoint_time": "<RFC 3339>", "key_id": "sha256:<hex>", "signature": "base64:<...>" }
```

The log signs `JCS(checkpoint object with the "signature" member removed)`. `log_id` is
`"sha256:" || hex(SHA-256("ahl-test-log-1"))` for the corpus log and MUST match
`log.log_id` in the manifest version active for the checkpoint's `tree_size` — the manifest
member is spelled `log_id`, exactly as the checkpoint member is, and this profile defines no
alias for it. A checkpoint commits exactly the entries with index in `[0, tree_size)`.

The manifest `log` object of core spec §7.3 is
`{ log_id, operator, adaptor: {id, hash}, checkpoint_cadence, cadence_epoch,
witness_grace_period, keys }`, and **every member is REQUIRED**. `cadence_epoch` is the single
start of the checkpoint-series obligation: it is declared by the genesis manifest, repeated
unchanged by every later version, and the earliest checkpoint committing the genesis manifest
must fall in `[cadence_epoch, cadence_epoch + checkpoint_cadence]`. This profile defines no
cadence *enforcement* — the corpus publishes checkpoints for the scenarios its vectors need,
not on a schedule — but the members are carried because a manifest missing one is malformed.

The value grammars are core spec §7.3's, restated here so a verifier implemented from this
document alone is complete:

| member | grammar |
| --- | --- |
| `log_id`, `keys[].key_id`, `adaptor.hash` | family strings: `"sha256:"` plus 64 lowercase hex digits (§3) |
| `checkpoint_cadence`, `witness_grace_period` | `P[n]DT[n]H[n]M[n]S` — days, hours, minutes, seconds. `Y`, and `M` in the date part, are PROHIBITED; at most nine fractional digits, on the seconds component only |
| `checkpoint_cadence` | additionally MUST be greater than zero |
| `cadence_epoch` | RFC 3339 |
| `keys[]` | `{ key_id, pubkey, valid_from_index }`, the last an entry index |

A malformed value MUST be **rejected rather than approximated**, and rejection is a duty on the
value rather than a consequence of computing with it. A verifier that reads no cadence still
refuses a manifest declaring `P1Y`: admitting it would leave the corpus verifiable only by
implementations sharing that tolerance, and would make cadence, frontier and completeness bounds
implementation-dependent for every party that does compute with the value. Truncating an
over-long fraction is the same error in a quieter form.

This profile defines no binary checkpoint framing, so receipts under it MUST NOT carry
`anchoring.checkpoint.raw`.

## 6. Witness cosignatures

A witness (core spec §3.3) cosigns the **signed** checkpoint object, bound to its own
identity so a cosignature cannot be replayed for another witness:

```
cosignature = Ed25519( JCS( { "checkpoint": <signed checkpoint object>,
                              "witness_id": "<witness id>" } ) )
```

Serialized in a receipt as
`{ "witness_id", "key_id", "cosignature": "base64:<...>", "cosigned_at": "<RFC 3339>" }`.

### 6.1 Refusal evidence

Core spec §3.3 step 3: a witness that observes a fault MUST refuse to cosign and MUST publish
signed refusal evidence containing both conflicting checkpoints. Under this profile that
evidence is:

```json
{ "type": "witness-refusal",
  "witness_id": "<id>",
  "log_id": "sha256:<hex>",
  "reason": "equivocation | size-regression | extension-failed",
  "retained": { ...signed checkpoint the witness had already cosigned... },
  "offered":  { ...signed checkpoint the witness refused... },
  "proof": { "from_size": 13, "to_size": 20, "path": [ "sha256:<hex>", ... ] },
  "detail": "<informative text; never normative>",
  "refused_at": "<RFC 3339>",
  "key_id": "sha256:<hex>",
  "signature": "base64:<...>" }
```

`retained` and `offered` are REQUIRED in **every** refusal, each a complete signed checkpoint
object of §5 including its `signature` member. `proof` is REQUIRED for `extension-failed` and
MUST be absent for the other two reasons: a carried proof that no reason directs a verifier to
check is unverified material inviting misreading. The witness signs `JCS(refusal object with
the "signature" member removed)` — the same rule as §5, so one signing routine serves both.

Every reason is independently recheckable from the evidence the refusal itself carries. A
verifier never has to consult the log, the producer or the witness to decide whether a refusal
is supported:

| `reason` | emitted when | what a verifier rechecks from the carried evidence |
| --- | --- | --- |
| `equivocation` | the offered checkpoint shares a `tree_size` with a cosigned one and carries a different `root_hash` | `retained.tree_size == offered.tree_size` **and** `retained.root_hash != offered.root_hash`, both checkpoints carried and log-signed |
| `size-regression` | the offered `tree_size` is smaller than an already-cosigned size, and no history exists at the offered size | `offered.tree_size < retained.tree_size` over the two carried checkpoints |
| `extension-failed` | the offered checkpoint is larger and the consistency proof from the retained one to it fails verification | re-run the §9 consistency verification over the **carried proof**, after checking `proof.from_size == retained.tree_size` and `proof.to_size == offered.tree_size` |

The two binding equalities for `extension-failed` MUST be checked **before** the proof is
verified, and the refusal rejected as unsupported if either fails — otherwise a structurally
valid proof that fails for some unrelated pair of sizes would validate a refusal about this
pair, and the refusal would be baseless while the failure was real.

There is no reason for "the log supplied no proof". Absence of a proof is not recheckable from
a signed refusal — the evidence would carry nothing a verifier could examine, so a witness could
emit it at will and a verifier could neither confirm nor refute it. A witness that derives
consistency proofs itself, which is the arrangement this profile assumes, treats its own
inability to compute one as an internal error: it declines to cosign and reports operationally,
but publishes no refusal, because it has no evidence of log misbehaviour.

Refusal evidence is **self-authenticating**: a verifier needs only the witness public key from
the manifest (core spec §7.2) plus the log public key. It is not an AHL statement, is not
anchored, and carries no `payload`/`signatures` envelope.

Checking refusal evidence:

1. verify the witness signature over the refusal object;
2. verify the log signature on **both** carried checkpoints — an unsigned or badly signed
   checkpoint proves nothing about the log — and confirm both carry the named `log_id`;
3. apply the recheck for the declared `reason` from the table above. A refusal whose evidence
   does not support its declared reason is **unsupported** and MUST be reported as such; a
   verifier MUST NOT substitute a different reason the evidence would have supported;
4. treat a verified refusal as evidence about the log's conduct within the boundary of its
   reason, not as a verdict about any particular statement (core spec §3.3 claim discipline).
   A verified `equivocation` ends the canonical series from that `tree_size` onward; a verified
   `size-regression` or `extension-failed` is a finding about what the log offered this witness
   and by itself establishes no divergence.

## 7. Capabilities

Core spec §3 item 6 forbids verification from depending on knowledge outside the profile
document, so the absence of a definition here is a **property of this profile**, not of the
container format or of any verifier:

| capability | status under `ahl-test-log-v1` | consequence |
| --- | --- | --- |
| binary checkpoint framing (`anchoring.checkpoint.raw`) | **not defined** | a receipt carrying `raw` under this profile MUST be rejected — there is no framing to parse it against, so the §5-step-2 "parses to the same values" check cannot be performed |
| consistency-proof serialization (`anchoring.later_checkpoint` + `consistency_path`) | **defined** (§9) | `assurance.continued_history: true` is reachable under this profile; a receipt claiming it MUST carry both members and both MUST verify |
| authenticated range enumeration | **defined** (§8) | enumerated governance currency and every claim type requiring it are available |
| typed-subset (governance) proofs | **not defined** (§8.4) | enumerated governance carries the full entry range |

A conformant verifier reports an absent capability as a limitation of the pinned profile,
naming it — another profile that defined it would make the same receipt verifiable without any
change to the verifier. The binary framing is a candidate for a future revision of this
document, which would carry a new profile hash and therefore a new manifest version.

### 7.1 Authenticating an earlier checkpoint without a consistency proof

Receipt format §3 lets `propagation-complete` authenticate the propagation's declared
checkpoint D "EITHER [by] a consistency proof D→`anchoring.checkpoint` OR [by] recomputation of
D's prefix root from the enumerated prefix". Both paths exist under this profile; the corpus
uses the second, and it is sufficient on its own:

1. the receipt carries D as a full signed checkpoint object; its log signature is verified
   against a key declared by the manifest version active for **D's** `tree_size` (§2.2), which
   may be an earlier manifest version than the one active for A;
2. the enumerated `corpus_prefix` covers `[0, tree_size(D))` and its §8 range proof is verified
   against **A's** root at A's `tree_size` — so the entries are authenticated under the
   checkpoint the verifier actually signature-checked and saw witness-cosigned;
3. the root of those `tree_size(D)` leaves is recomputed by the §2 rule and compared to D's
   `root_hash`.

Steps 2 and 3 together establish that D is exactly the size-`tree_size(D)` prefix of A, which
is precisely what an RFC 9162 consistency proof D→A asserts. The prefix is carried in full
regardless — receipt format §3 states there is no compact completeness form — so a separate
consistency proof would restate an already-proven fact in a second encoding.

## 8. Authenticated enumeration

Core spec §3 contract item 5 requires the log to serve entries `[i, j)` under a checkpoint
"with proof of completeness and order", and receipt format §4.2 carries that proof as
`range_proof.adaptor_form`. This profile defines the proof as follows.

### 8.1 What is proven

Given a checkpoint `C` over a log of `N = tree_size(C)` entries, a range `[i, j)` with
`0 <= i < j <= N`, and an ordered list of `j - i` entry envelopes, the proof establishes that
the carried list is **exactly and completely** the leaf set of `[i, j)` under `C.root_hash`:
no gaps, no reordering, no omissions, no insertions.

### 8.2 Construction

The proof is the minimal set of RFC 6962 subtree hashes covering everything *outside* the
range. Define, over the standard RFC 6962 decomposition of `[0, N)`:

```
recompute(offset, size):
    let end = offset + size
    if end <= i or offset >= j:                     # subtree entirely outside the range
        return the next unconsumed proof node
    if offset >= i and end <= j:                    # subtree entirely inside the range
        return root of the carried leaf hashes for [offset, end)
    k = largest power of two strictly less than size
    return node_hash( recompute(offset, k), recompute(offset + k, size - k) )
```

The proof node list is produced by the same recursion at generation time: walk the
decomposition of `[0, N)` and, for every maximal subtree entirely outside `[i, j)`, emit that
subtree's root hash. Nodes are therefore in left-to-right order.

The leaf hash of an entry is `SHA-256(0x00 || JCS(envelope))` (§2.1), and the root of a span
of leaf hashes is computed by the §2 splitting rule.

### 8.3 Verification

1. Reject unless `0 <= i < j <= N`.
2. Reject unless exactly `j - i` entry envelopes were carried, with `entry_index` values
   `i, i+1, ..., j-1` in that order.
3. Compute the leaf hash of each carried envelope.
4. Run `recompute(0, N)`. Reject if the node list is exhausted early.
5. Reject unless every proof node was consumed.
6. Accept iff `recompute(0, N) == C.root_hash`.

Soundness: the recursion is a pure function of `(N, i, j)`, so the position at which each
proof node is consumed is fixed before any of them is read — a prover cannot choose where to
spend a node. The carried leaves are placed positionally, so any gap, reordering, omission or
insertion changes `recompute(0, N)`. Under collision resistance of SHA-256, only the true leaf
set of `[i, j)` opens the checkpoint root.

A range of width 1 is an inclusion proof in a different serialization: its node list, sorted
by decreasing depth in the recursion, is exactly the §2.3 inclusion path for leaf `i`. A
conformant verifier MAY cross-check it that way; the reference implementation does.

### 8.4 Serialization

`range_proof.adaptor_form` is `"base64:" || base64(bytes)` with the byte layout below. All
integers are **big-endian**; there is no padding and no alignment.

| offset | size | field |
| --- | --- | --- |
| 0 | 6 | magic, ASCII `AHLRP1` |
| 6 | 8 | `tree_size` (u64) |
| 14 | 8 | `from_index` (u64) |
| 22 | 8 | `to_index` (u64) |
| 30 | 4 | `node_count` (u32) |
| 34 | 32 × `node_count` | subtree hashes, raw 32-byte SHA-256 values, in consumption order |

The total length is therefore `34 + 32 * node_count`; any other length is a rejection. A proof
whose `tree_size`, `from_index` or `to_index` disagrees with the enclosing §4.2
`range` object or with the checkpoint is a rejection.

Because this profile provides **no typed-subset proofs** (core spec §10.9), receipt format §4.2
filtering of `entries` to manifest/key statements is NOT available under it: enumerated
governance currency must carry the full entry range. That is the honest cost until a typed
governance sub-tree exists.

## 9. Consistency proofs

Core spec §3 contract item 3 requires the log to serve consistency proofs between checkpoints,
and receipt format §2.1 makes them the evidence behind `assurance.continued_history`. This
profile defines them.

### 9.1 Construction and serialization

A consistency proof is an RFC 9162 §2.1.4 proof between two tree sizes of the **same** log,
over the log tree of §2.1. It is serialized as a JSON array of `"sha256:<hex>"` family strings
in the order produced by the RFC 9162 algorithm — the same shape as an inclusion path (§2.3),
and, like it, carried bare:

```json
"consistency_path": [ "sha256:<hex>", "sha256:<hex>", ... ]
```

The two sizes are not carried inside the array. They come from the checkpoints the proof runs
between, which is what binds the proof to a specific pair:

| member | from size | to size |
| --- | --- | --- |
| `anchoring.consistency_path` | `anchoring.checkpoint.tree_size` | `anchoring.later_checkpoint.tree_size` |

`anchoring.later_checkpoint` is a complete signed checkpoint object of §5, including its
`signature` member.

### 9.2 Verification

1. Reject unless **both** `later_checkpoint` and `consistency_path` are present. Receipt format
   §2.3 states the equivalence — `assurance.continued_history` is true *iff* both are present
   and verify — so one without the other is malformed, not a weaker claim.
2. Reject unless `later_checkpoint.tree_size >= anchoring.checkpoint.tree_size`. A "later"
   checkpoint of smaller size proves no continued history; it is the size regression a witness
   refuses to cosign over (§6.1).
3. Verify `later_checkpoint`'s own log signature by §5, against a key declared by the manifest
   version active for **its** `tree_size` — which may be a later manifest version than the one
   active for `anchoring.checkpoint` (receipt format §2.2). A key one manifest version replaced
   must not validate a checkpoint issued under another.
4. Run the RFC 9162 §2.1.4 verification over the carried path, from
   `anchoring.checkpoint.root_hash` at its `tree_size` to `later_checkpoint.root_hash` at its
   own. Accept only on success; a path that is structurally impossible for that pair of sizes is
   a failed proof, exactly like one that simply does not open the pair.

### 9.3 What the proof does and does not establish

A consistency proof establishes that the later checkpoint's tree is an append-only extension of
the earlier one's: no entry the earlier checkpoint committed was removed, reordered or altered.

It does **not** establish that a checkpoint the cadence required was ever published — omission
is invisible to it (core spec §7.3) — and it says nothing about whether the operator showed the
same log to everyone, which is what the witness protocol of §6 exists for. A verdict rendered
from `continued_history` must not be stated more strongly than "the log's history continued to
be append-only through the later checkpoint carried here".
"#;
