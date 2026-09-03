# AHL test-vector corpus

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
a rule that was skipped is not a rule that held. Two conditions end the run even so, both ordering rules rather
than reductions: the RECEIPT's own unsupported version, which §7.5 step 1 follows with "no
further processing", and an exhausted verifier-local budget, which §7.8 requires to fail closed.
A CARRIED statement of an unsupported revision is neither: §7.1 makes it "`unverifiable` as for
any carried statement", so it is recorded as a gap on the assertion of the phase that met it and
the run goes on — 4b closes that rule with "a later required `invalid` still dominates". A boundary is rendered only for
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
*   **Adaptor profiles beyond the two this build implements.** A receipt pinning any profile
    id other than `ahl-test-log-v1` or `ahl-adaptor-atl-v1` is refused as
    `ReceiptError::AdaptorCapabilityUnsupported` — a limitation of this BUILD, named as such,
    never `invalid`. Core spec §3 item 6 makes that the right shape: another verifier holding
    that profile's document would verify the same receipt without any change to the format.

Also not yet in the corpus: no vector carries a witness key sourced `local-policy` (I-D §7.1).
The corpus trust policy holds no trusted witness key at all, so every witness key in every
vector is `manifest-chain`, bound by `(witness_id, key_id, pubkey)` to the manifest version
active for the checkpoint being cosigned. The `local-policy` branch — admissible only for
witness keys the verifier ALREADY TRUSTS, matched on `key_id`, `pubkey` AND the `witness_id`
policy holds the key for, and admissible only under an identity the active manifest itself
declares — is covered by `tests/vectors.rs` instead, since what decides it is the verifier's
own configuration rather than anything a portable vector can carry.

The corpus carries TWO governance-key rotations, one per side. Manifest v2 (entry 25) rotates
the WITNESS set; manifest v4 (entry 55) replaces `log-1` with `log-2` in `log.keys` and changes
nothing else. A chain over both therefore needs two `rotation_proofs[]` elements in ascending
`manifest_entry_index` order, and the corpus publishes one checkpoint per rotation whose declared
active manifest version is deliberately the version BEFORE its own tree size's — cp26 for the
witness rotation and cp56 for the log one — because §7.5.1 4b(M) proves a rotating manifest's
anchoring under the state it retires.

`statement-anchored-log-key-rotation.ahl` is the positive, over a subject anchored after the
rotation under cp57, which the INCOMING key signs. Four negatives police the rules only a second
log key can exercise:
`governance-key-rotation-proof-incoming-log-key-must-fail.ahl` re-signs the v4 proof under
`log-2` — "exactly the key an attacker installs, whereas the exception accepts only the key
being retired";
`governance-key-rotation-proofs-out-of-order-must-fail.ahl` carries two otherwise-correct
elements in descending order, which offers each rotation the other's proof;
`governance-key-rotation-proof-incoming-witness-must-fail.ahl` cosigns the v2 proof under
witness-2, the witness that rotation installs, with a genuine cosignature over the right
checkpoint — a cosignature by a witness the outgoing manifest does not declare attests nothing
about the handover, so it is passed over and the element is left with none;
and `statement-anchored-outgoing-log-key-after-rotation-must-fail.ahl` anchors a subject under
cp56 itself, a real correctly signed checkpoint of this log whose signer the version active for
its own tree size no longer declares (§7.5.1 4f).
`governance-key-rotation-proof-incoming-key-must-fail.ahl` is KEPT beside the first of those: it
substitutes a witness key for the v2 proof's signer, which rules out any non-member of the
outgoing log set, while the new vector rules out the incoming key specifically. The two are
different facts about the same check.

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
| `adaptor/` | Both adaptor profile documents, content-addressed: `ahl-test-log-v1.md`, pinned by the main corpus's manifest versions, and `ahl-adaptor-atl-v1.md`, pinned by the ATL-bound corpus's — see the release note below |
| `vectors/statements/` | The toy corpus's anchored envelopes, plus malformed statements naming the rule each violates |
| `vectors/merkle/` | Log tree (entry-index order, never sorted), the record-sorted batch, wide-outputs, input-set and disposition trees, and authenticated range proofs |
| `vectors/checkpoints/` | Signed checkpoints at tree sizes 8, 13, 20, 24, 25, 26, 28, 29, 30, 32, 34, 35, 37 and 38, each cosigned by the witness its active manifest version declares — EXCEPT cp26, deliberately cosigned by the OUTGOING witness-1 for the I-D §7.1 rotation-anchoring proof at manifest v2 (see "Governance-key rotation" below) |
| `vectors/closure/` | Six closure scenarios (see below) |
| `vectors/witness/` | Signed witness refusal evidence carrying two conflicting checkpoints (spec §3.3 step 3) |
| `receipts/` | One positive and at least one negative receipt per claim-type registry entry, plus `index.json` naming the I-D §7.7 result each must reach, the assertion whose finding produces a non-verified one, the rule each negative must trip, and the trust policy those outcomes assume |
| `vectors/atl/` | The ATL-bound toy corpus: its four anchored envelopes and its log tree, whose leaves are adaptor §4.2's two-digest construction |
| `receipts/atl/` | Receipt vectors over that corpus, with an `index.json` of their own — a trust policy names ONE published genesis anchor (I-D §7.5.1 4a) and this is a second log |
| `keys/` | Committed test key seeds — **see the warning below** |

## The scenarios

The corpus is 57 anchored entries carrying these interlocking scenarios:

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
   anchors opaque bytes and validates none, so both really can be anchored. I-D §7.5.1 4b
   selects an enumeration-only entry for the induction by its purported `type` but admits it
   "only if its envelope verifies in phase 1": both are void, not inducted, with no effect on
   the key state and no type-specific validation at all (§7.5 step 1 exempts a non-verifying
   enumeration-only entry from the version read too), while §7.4 adds that a void entry's
   absence from `governance.chain[]` is not an omission.
   `governance-state-void-governance-entries.ahl` (over cp40) verifies with five informative
   items — the void derivation at entry 37 is inside that range too.

   A void entry occupies no statement id either, because §2.1's first-wins rule is about
   GOVERNING statements and a void entry never becomes one. Entry 41 is BYTE-FOR-BYTE the
   statement anchored at entry 38 — one statement id, two entry ids — genuinely signed this
   time, with entry 40 retiring `producer-2` in between and entry 42 an ingestion signed by that
   key. `statement-anchored-void-then-verifying-key.ahl` verifies only if the copy at 41 was
   inducted; a verifier that claimed the id when it voided the first copy would leave the key
   retired and refuse the subject.

   Entries 51, 52 and 53 are the other half of 4b's rule: an ingestion, a manifest version and
   a `key` statement that all DO verify while declaring `ahl_version: "0.5"`. A carried
   statement of a revision this document does not define is "`unverifiable` as for any carried
   statement" (§7.1); only the RECEIPT's own `ahl_receipt_version` ends the run (§7.5 step 1).
   So each is set aside rather than validated under rules this revision does not have — not
   inducted, not a competing candidate, never traversed — and each is reported as a FINDING,
   which is what separates it from a void entry: nothing here says the artifact is defective,
   only that this verifier cannot read it.

   The four paths a foreign revision reaches a verifier by each have a vector, and all four are
   `unverifiable`: the governing `key` statement through the induction (4b) and the manifest
   through the completeness check (4c), which must read the revision before calling its absence
   from the chain an omission — `governance-state-foreign-revision-key-must-fail.ahl` (over
   cp54) and `governance-state-foreign-revision-manifest-must-fail.ahl` (over cp53), both on
   `governance`; a `governance.chain[]` hop the step-3 walk cannot interpret —
   `statement-anchored-foreign-revision-chain-hop-must-fail.ahl`, on `governance`, where the
   stop lands at the hop's own index; and a non-governance entry an enumerated sweep meets —
   `governance-state-foreign-revision-entry-must-fail.ahl` (over cp52), on `envelope-validity`,
   the assertion of the sweep that met it. In each case the run continues: 4b ends "a later
   required `invalid` still dominates", and the tests pair every path with a §7.6 disagreement
   that does exactly that while the gap stays reported beside it.

   Which of 4b's two rules applies is settled by the ORDER they are stated in. A
   `governance.chain[]` element "is different: the receipt presents it as its own lineage, so
   its phase-1 failure is `invalid`", and only then does the foreign-revision rule apply — to "A
   VERIFYING purported governance entry". Entry 54 is the pair to entry 52 that shows it: the
   same manifest shape at the same declared revision, carrying a signature no key produced.
   `statement-anchored-broken-foreign-revision-chain-hop-must-fail.ahl` hangs it off the same
   chain position and is `invalid` on `governance`, naming the signature at entry 54 — a
   verifier that read the revision member first would report a broken lineage as its own
   capability gap, and any unsigned chain element could then hide behind a version its receipt
   made up.

12. **Input-set trees take the §2.7 tree rules.** I-D §2.7 states one set of rules, "identical
   for every AHL tree — outputs, input sets, and dispositions". Entry 50 is a batch whose three
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
   reaching entry 50 fails by §2.7. That is why the batch sits at entry 50 rather than earlier:
   every propagation prefix this corpus declares stops below it. The three defective trees are
   deliberately absent from
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
14. **A void entry inside a propagation prefix.** I-D §7.5.1 4d names "an entry of a
   propagation prefix" among the carried envelopes reliance excludes, and §2.1 adds that a void
   entry is "never traversed by closure". Entry 37 is a derivation of a `scores` record from H —
   the one derived record the retraction of record F at entry 29 reaches — carrying a `sig` no
   key produced; entry 43 is byte for byte the same payload, genuinely signed. Entries 44 and 45
   are two propagation statements over that trigger, anchoring the SAME one-member affected set
   and declaring D at cp38 and cp44 respectively.

   `propagation-complete-void-prefix-entry.ahl` proves the first: the prefix [0, 38) reaches the
   void copy, which contributes no edge and no seed, so the closure has one member and the
   anchored disposition tree agrees — `verified`, with entry 37 among the informative items.
   Positions are preserved rather than dropped, since an entry index IS a position in the
   prefix, and the prefix's own root is recomputed over the CARRIED bytes: voiding is about
   traversal, not about what the log anchored.
   `propagation-complete-void-prefix-entry-control-must-fail.ahl` is the control, and it is a
   propagation statement of its own rather than a mutation: the prefix [0, 44) reaches the
   VERIFYING copy at entry 43, which §2.1 leaves governing because a void entry never becomes a
   governing statement and so occupies no statement id, the closure grows to two members, and
   the same anchored set is now incomplete — `invalid` on `claim-material`. The two prefixes
   differ by exactly which envelope over one payload they reach, which is what shows the
   exclusion to be the signature's doing rather than an artifact of prefix length.

   This is why the batch with the deliberately non-conforming input-set trees sits at entry 50
   and not earlier: a propagation prefix is walked in full, and a prefix reaching that batch
   cannot be opened at all.
15. **One statement id, three anchored entries.** I-D §2.1's duplicate rule is reachable
   without any fabrication, because the statement id digests the PAYLOAD while the entry id
   digests the ENVELOPE: one payload under three signature sets is one statement anchored three
   times. Manifest version 3 is that payload — predecessor v2, the same log and witness key
   objects so it rotates no governance key, a producer snapshot restating the key entry 41 put
   back in force — and entries 46, 47 and 48 are its three envelopes: `producer-1` alone,
   `producer-1` and `producer-2` together, and a `sig` no key produced. Entry 49 is an
   ordinary ingestion bound to version 3.

   The two questions §7.5.1 asks about a duplicate get different answers, and the vectors keep
   them apart. The induction (4b) claims the statement id once, at the smallest entry index, so
   entry 46 governs and 47 applies no effect, consumes no rotation proof and never becomes the
   version a `subject.manifest` reference resolves to
   (`statement-anchored-duplicate-manifest.ahl`, `verified`). Verification is not waived with
   effect: §7.5 step 4 verifies every carried envelope and 4d puts a `governance.chain[]`
   element among the three kinds a receipt RESTS ON, so the third envelope in that chain
   position is `invalid` on `envelope-validity` at its own index
   (`statement-anchored-duplicate-manifest-unsigned-must-fail.ahl`). A void duplicate that
   VERIFIES produces no informative item — an informative item reports a void entry the run
   inspected and found wanting, which a verifying one is not. Completeness (4c) asks what the
   CHAIN CARRIES, so under enumerated currency both verifying copies must be present and the
   non-verifying one is not an omission (`governance-state-duplicate-manifest.ahl`, `verified`).

   One rule elsewhere had to follow. `governance-state`'s absence check — no governance
   statement in `(subject.entry_index, target_index]` — asks what CHANGED the state, so it
   passes over a void entry and over a later duplicate of a governing statement. Counting
   either would report a current state as stale, which is the opposite of what first-wins says.

## The ATL-bound corpus

`ahl-test-log-v1` and `ahl-adaptor-atl-v1` differ in exactly three serializations, and
`vectors/atl/` exists so each is dispatched end to end rather than assumed. Everything else
about a log tree — node hashing, the splitting rule, inclusion and consistency proofs, the
range-proof byte layout, the receipt container, the governance rules — is shared, and the AHL
trees the log never sees (batch outputs, input sets, dispositions) take plain leaf hashing under
both, which adaptor §9 states expressly: an implementation "MUST NOT apply the payload/metadata
leaf construction to them".

1.  **The log leaf** (adaptor §4.2). ATL combines two digests, so the leaf is
    `SHA-256(0x00 || SHA-256(JCS(envelope)) || METADATA_HASH)` where the metadata object is the
    fixed `{"ahl_adaptor":"ahl-adaptor-atl-v1"}` and the first digest is the raw form of the AHL
    entry id — which is what keeps the entry id derivable from the entry bytes alone. The
    constant is recomputed in `lib.rs` rather than transcribed, and
    `statement-anchored-atl-metadata-hash-must-fail.ahl` is a genuinely signed, genuinely
    cosigned checkpoint over the same entries hashed with a metadata digest the profile does not
    pin: every signature verifies and the inclusion path is correct in THAT geometry, so only a
    verifier using the pinned constant rejects it.
2.  **The checkpoint signing bytes** (§6.1, §6.5). The log signs the fixed 98-byte blob, not
    `JCS(cp minus "signature")`, and `checkpoint_time` renders the exact nanosecond value with
    exactly nine fractional digits (§6.3) because the blob binds it. `log_id` is origin-derived
    (§7.1): its 32 octets ARE the Origin ID the blob carries at offset 18, so the corpus states
    the 16-byte Data Tree UUID it came from rather than treating the identifier as free-form.
3.  **`checkpoint.raw`** (§6.4). This profile DEFINES a binary framing, so receipts under it MAY
    carry `raw` — and where they do it "MUST parse to the same values as the JSON members, the
    JSON members govern, and a mismatch is `invalid`".
    `statement-anchored-atl-raw-mismatch-must-fail.ahl` carries a well-formed blob of a
    different tree size: the checkpoint's own signature still verifies, since it is computed over
    the blob assembled from the JSON members, which is exactly why an unreconciled `raw` could
    present values the log never signed. `ahl-test-log-v1` defines no framing at all, so `raw`
    under it stays a profile limitation and a policy claiming `checkpoint_raw` for it is still a
    configuration error.

`statement-anchored-atl-profile.ahl` and `record-ingested-atl-profile.ahl` are the positives.
`statement-anchored-atl-profile-digest-must-fail.ahl` pins a digest the held document does not
recompute to — §14 requires resolution by `{id, digest}` with the digest recomputed over the
artifact, and I-D §7.5 step 2 makes that disagreement `invalid` rather than a capability gap.
The gap itself — a verifier holding NO document under that id, which is `unverifiable` — is
exercised in `tests/vectors.rs`, since what decides it is the verifier's configuration rather
than anything a portable vector can carry.

**The ATL profile is PRE-RELEASE, and the pin here is test-only.** Adaptor §14: "Until this
document is released as an immutable, openly published artifact at a stable location, its digest
is not stable and no manifest may pin it." The digest this corpus pins is the CURRENT DRAFT's,
held so the serialization can be exercised; a production manifest MUST NOT pin the profile until
that release obligation is met, and the digest will change when it is. `receipts/atl/index.json`
records the same caveat beside the pin.

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
