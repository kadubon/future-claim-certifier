# Protocol Mapping

This document maps the DFCC paper terms to the reference implementation. The
package implements the protocol and a finite exact backend. It does not bundle
SMT or reachability solvers; those are pluggable through `DFCCBackend` and
`DFCCChecker`, and unresolved obligations produce `checker_unknown`.

New readers should start with [the docs index](index.md) and
[architecture overview](architecture.md). Use this file when you need the exact
connection between a paper term, a Python API, a JSON Schema, a failure code,
and a conformance case.

## How To Read This File

- Paper term: the name used by the DFCC paper.
- Implementation API: the public function, type, or CLI path in this package.
- Schema: the JSON Schema that validates the protocol record.
- Failure code: the typed blocker returned when a requirement is not met.
- Conformance case: a packaged case that fixes the expected behavior.

The protocol is conservative. A missing artifact, proof, reason path,
obligation, schema, or profile rule is never treated as accepted evidence. It
becomes `missing_ref`, `checker_unknown`, `artifact_conflict`,
`schema_invalid`, or another typed blocker.

## Glossary

- Artifact: canonical JSON with a stable digest and role.
- Bundle: a set of artifacts plus a manifest and reference context.
- Ledger: the resolved list of references used by replay.
- Accepted clause: evidence that passed admission and may affect semantics.
- Raw evidence: stored for audit; it does not affect semantics by itself.
- Replay trace: generated records for each validation and authority stage.
- Authority outcome: the final typed answer plus blocking and reason records.

## Kernel API

| Paper API | Implementation |
| --- | --- |
| `ValidateArtifactRef` | `dfcc.api.validate_artifact_ref` |
| `ManifestDigest` | `dfcc.api.manifest_digest` |
| `ResolveReference`, reason paths | `dfcc.api.resolve_reference`, `dfcc.api.resolve_reason_path` |
| `ProfileResolution` | `dfcc.api.profile_resolution` |
| `ScalarRecord`, `IntervalRecord`, `TimestampRecord`, `SetRef` | `dfcc.api.scalar_record`, `interval_record`, `timestamp_record`, `set_ref` |
| `CompileClaim` | `dfcc.api.compile_claim` |
| `DefineAssessmentFrame` | `dfcc.api.define_assessment_frame` |
| `DefineTimeBasis`, `DefineEventOrder` | `dfcc.api.define_time_basis`, `define_event_order` |
| `AdmitEvidence`, `ValidityView` | `dfcc.api.admit_evidence`, `validity_view` |
| `CompileBundle`, `InitialContext` | `dfcc.api.compile_bundle`, `initial_context` |
| Artifact-bundle issuance | `dfcc.api.certify_claim_from_artifact_bundle` |
| `RepresentationInterface`, `CompletionAdmission` | `dfcc.api.representation_interface`, `completion_admission` |
| `MakeObservationCut`, `StatusObservationContext` | `dfcc.api.make_observation_cut`, `status_observation_context` |
| `OperationalPrefixFiber`, `OperationalCompletionFiber` | `dfcc.api.operational_prefix_fiber`, `operational_completion_fiber` |
| `ExactPrefixSet`, `AdmitPrefix`, `ResidualContext` | `dfcc.api.exact_prefix_set`, `admit_prefix`, `residual_context` |
| `KernelVerdict` | `dfcc.api.kernel_verdict` |
| `CheckedAssocView`, `ExactFiberAssoc`, `FiberAssocView` | `dfcc.api.checked_assoc_view`, `exact_fiber_assoc`, `fiber_assoc_view` |
| `PrefixAdjudication`, `UsageAdjudication`, `TargetAdjudication` | `dfcc.api.prefix_adjudication`, `usage_adjudication`, `target_adjudication` |
| `Agreement`, `GateDecision`, `TypedAuthorityOutcome` | `dfcc.api.agreement`, `gate_decision`, `typed_authority_outcome` |
| `ArtifactBundle`, `ValidateArtifactBundle` | `dfcc.api.ArtifactBundle`, `artifact_bundle_from_json`, `validate_artifact_bundle` |
| `FoldStatus`, `CheckAuthority`, `AuthorityReplay`, `ValidatePipeline` | `dfcc.api.fold_status`, `check_authority`, `replay_authority_from_bundle`, `validate_pipeline` |
| `UpdateCertificate`, `TransferAuthority` | `dfcc.api.update_certificate`, `transfer_authority` |

The public API wrappers preserve the paper's authority-relevant coordinates.
`define_event_order` carries `accepted_event_ids`, `trace_class`, `causal_cut`,
confluence proof, conflict policy, and log-root commitments into
`EventOrder`; `residual_context` uses the caller-supplied
`exact_prefix_set` as `P_star` rather than silently substituting the outer
prefix view.

## Checker Contract

`DFCCChecker` exposes the protocol checker contract. `ReferenceChecker` is a
finite, conservative implementation: unsupported checks return `unknown` with
`FailureCode.CHECKER_UNKNOWN` instead of silently passing.
Schema, reason-path, frame, observation-cut, status-observation, agreement, and
typed-outcome checks require accepted checker evidence records such as
`checker_status: pass`, `proof_status: accepted`, or typed artifact-pointer
reason refs. A bare string reference is treated as an unresolved hint, not
proof of acceptance. Evidence records are considered bound only when they carry
an `artifact:` reference, a `sha256:`/`sha384:`/`sha512:` digest, or an
`artifact:` source plus JSON Pointer path; local labels such as `checker:*`,
`calibration:*`, or `event-order:*` do not satisfy checker evidence. Operational usage adjudication, prefix/target
adjudication, and frame adequacy follow the same rule: declared directions do
not pass unless the proposed use, observation record, or frame policy carries
accepted proof or transcript evidence for that checker contract.
Schema checker evidence is purpose-bound: `schema()` accepts only bound
evidence whose `proof_kind`, `checker_kind`, `kind`, or `evidence_kind` is
`schema_validation` or `schema`. The evidence payload must bind at least one
target coordinate from the artifact being checked, such as `artifact_id`,
`schema_name`, `schema_profile_ref`, `canonicalization_profile_ref`, or
`schema_digest`; otherwise it is `checker_unknown`, and a mismatched coordinate
is `artifact_conflict`.
Reason-path, assessment-frame, and status-observation checks use the same
purpose binding: their accepted evidence must be marked respectively as
`reason_path`, `assessment_frame`/`frame`, or `status_observation_context`.
Reason-path evidence must also bind the requested JSON Pointer in payload field
`json_pointer`, `reason_path`, `source_path`, or `pointer`; pointer mismatch is
`artifact_conflict`.
Profile resolution is likewise explicit: when callers provide
`implemented_profiles`, only that declared implementation set is authoritative.
A requested profile absent from the set is `unsupported_profile`, and compatible
profiles must expose their `compatibility_rule` and `extension_mapping` in the
returned `ProfileResolution`; those extension mappings remain annotations
unless later transfer/proof obligations admit their semantic effect.
Compatibility profiles also must map every non-base failure code in their
`failure_code_set` to a normative DFCC base failure code. An unmapped extension
failure code is rejected during `ProfileResolve` as `unsupported_profile`, with
a reason ref naming the unmapped code and a checker reason path under
`/implemented_profiles/<profile>`.
`status_confluence` likewise requires accepted confluence proof evidence
purpose-bound as `confluence`, `status_confluence`, or `trace_confluence`; a
bare proof id or unrelated accepted proof does not discharge trace disagreement.
For `initial_context`, raw admission strings are annotations only. The checker
requires accepted admission or initial-context evidence in the bundle, or a
policy-level accepted transcript/trust-assumption record; the mere presence of a
trust ref is not enough. That evidence must also bind the replay coordinates
that are present in the runtime input, including bundle id, anchor fields,
frame id, and policy identity/version. A digest-bound proof without coordinate
payload is `checker_unknown`; a coordinate mismatch is `artifact_conflict`.

| Contract group | Methods |
| --- | --- |
| Interop/schema | `schema`, `artifact_ref`, `manifest_digest`, `reference_resolution`, `profile_resolution`, `reason_path` |
| Wire records | `scalar_record`, `interval_record`, `timestamp_record`, `set_ref` |
| Issue/admission | `assessment_frame`, `admission`, `initial_context`, `representation_interface`, `time_basis`, `event_order` |
| Observation/status | `observation_cut`, `status_observation_context`, `status_confluence` |
| Prefix/completion/fiber | `operational_prefix_fiber`, `operational_completion_fiber`, `completion_admission`, `prefix_admission`, `prefix_soundness`, `residual_context`, `checked_assoc_view`, `exact_fiber_assoc`, `fiber_assoc_view` |
| Operational authority | `prefix_adjudication`, `usage_adjudication`, `target_adjudication`, `frame_adequacy`, `agreement`, `typed_authority_outcome` |
| Kernel proof obligations | `enclosure_soundness`, `witness`, `infeasibility`, `inclusion`, `disjointness`, `artifact_conflict` |

The checker contract is intentionally evidence-bound. For example,
`time_basis` no longer passes merely because a clock record parses: it requires
an accepted `time_basis_proof`, `time_basis_proof_ref`, `checker_transcript`, or
`checker_transcript_ref` on the clock record or timestamp policy. That proof
must bind the parsed `clock_id`, `time_scale`, `uncertainty_seconds`, source,
and timestamp policy coordinates. Missing proof is `checker_unknown`; a
conflicting proof payload is `artifact_conflict`.

## Validation Stages And Failure Codes

`validate_pipeline` keeps the legacy single-artifact path for direct schema and
digest checks. When the input is an `ArtifactBundle`, it returns a
`PipelineReport` containing every stage result, resolved reference digests,
failure records, reason refs, proof refs, typed `proof_ref_records`, stage blockers, and, when replay
artifacts are present, accepted clause records, trust assumptions, guard
records, compiled bundle ref, unresolved refs, the resolved authority runtime
summary, replay stage artifacts, kernel/observation/agreement refs, a runtime
summary digest, a recomputed `StatusAuthorityView`, and its canonical
`authority_outcome_digest`. With `full_replay=True`, the `Replay`,
`GuardEvaluate`, `KernelCheck`, and `AuthorityEmit` stage results are derived
from `ReplayTrace`, not the shallow preflight checks. The bundle path follows
the paper stage order:

`full_replay=True` is bundle-only. A single-artifact compatibility input cannot
provide the paper's replay context, accepted clauses, status context, guards, or
proof ledger, so it fails at `Replay` with `missing_ref` instead of falling
through the legacy direct schema/digest path.

`Parse -> Canonicalize -> SchemaValidate -> DigestCheck -> ReferenceResolve -> ProfileResolve -> Replay -> GuardEvaluate -> KernelCheck -> AuthorityEmit`.

Replay trace stages keep valid authority non-allow outcomes, such as policy or
status-time unknowns, as stage evidence without turning the validation pipeline
itself into a failure. Evidence/proof defects remain blocking stage failures:
`missing_ref`, `checker_unknown`, `artifact_conflict`, `schema_invalid`,
`digest_mismatch`, `trace_conflict`, and related protocol-inconsistency codes
are reflected in the corresponding `Replay`, `GuardEvaluate`, `KernelCheck`,
or `AuthorityEmit` `ValidationResult`.

`SchemaValidate` applies explicit `schema_name` values and the built-in role
schemas for semantics-admission and operational replay artifacts:
`IssueCertificate`, `EvidenceArtifact`, `AdmissionContract`, `AcceptedClause`,
`TrustAssumption`, `StatusAuthorityView`, `LifecycleEvent`, `ObservationCut`,
`ProposedUse`, `StatusContext`, `DependencyGraph`, `SetRef`,
`ScalarRecord`, `IntervalRecord`, `TimestampRecord`, `GuardRecord`,
`PrefixView`, `CompletionAdmission`, `FiberAssocView`, `Agreement`,
`MeasurementRelationArtifact`, `RepresentationRelationArtifact`, and
`KernelProofArtifact`. Replay/conformance output records are also role-gated:
`ProtocolRecordArtifact`, `ReplayStageTrace`, `ReplayTrace`, `PipelineReport`,
`LifecycleDecision`, `ResolvedAuthorityRuntime`, and `ValidationResult`. These records are
validated before digest/reference checks and before an issue certificate can
enter replay, any proposed use or status context can drive `CheckAuthority`,
any accepted clause can reach bundle compilation, any emitted status authority
view can be re-ingested for conformance comparison, any lifecycle event can
reach status folding, any dependency graph or set reference can support
compiled semantics, any observation cut can reach guard evaluation, or any
guard, prefix, completion, fiber, agreement, relation, or proof artifact can
support operational or kernel replay, or any generated replay report can be
used as a conformance artifact. `SetRef` artifacts also run digest soundness
during `DigestCheck`. The issue-certificate schema forbids a status-time
`authority_outcome`; authority outcomes are emitted only by recomputed
`StatusAuthorityView` records. `IssueCertificate.minimum_profile()` keeps
legacy `proof_refs` and `obligation_refs` for compatibility, but also emits
typed `proof_ref_records` and `obligation_ref_records` so issue-time proof and
admission obligations are not reduced to string labels before bundle replay.
It also emits typed `set_ref_records`; `set_refs` remains a compatibility index,
not the soundness evidence itself. Likewise, `artifact_refs` remains an index,
while `artifact_ref_records` carries schema/canonicalization/digest/role
coordinates for audit and canonical equality.
Issue certificates require at least one issue-time proof ref and matching typed
proof record. Issue proof records must be accepted/pass, digest-bound, and
source-artifact/JSON-Pointer bound; empty or `unknown` proof evidence is
`schema_invalid`.
`StatusAuthorityView` enforces the use/profile field policy in schema as well
as replay: non-operational uses must carry `not-applicable` operational refs,
while operational `accept`/`reject` outcomes must carry concrete completion,
fiber, adjudication, and agreement refs. Violations are `schema_invalid`, not
annotation-level warnings.

The bundle-centered records are:

| Paper record | Implementation | JSON Schema |
| --- | --- | --- |
| Artifact bundle | `ArtifactBundle`, `ManifestRecord`, `ArtifactEntry` | `artifact-bundle.schema.json`, `manifest-record.schema.json` |
| Artifact reference | `ArtifactRef` with schema digest, canonicalization digest, semantic role, dependency labels | `artifact-ref.schema.json` |
| Reference context | `ReferenceResolutionContext`, `ResolvedReference`, `ReferenceLedger`, `ReferenceLedgerEntry` | embedded in `artifact-bundle.schema.json`, `reference-ledger-entry.schema.json` |
| Profile resolution | `ProfileResolution` with closed-world and extension mapping state | `profile-resolution.schema.json` |
| Typed refs | `ReasonRefRecord`, `ObligationRefRecord`, `ProofRefRecord`, `SetRefRecord` | `reason-ref.schema.json`, `obligation-ref.schema.json`, `proof-ref.schema.json`, `set-ref.schema.json` |
| Evidence/admission | `EvidenceArtifact`, `AdmissionContract`, `AcceptedClause`, `AdmissionResult`, `TrustAssumption` | `evidence-artifact.schema.json`, `admission-contract.schema.json`, `accepted-clause.schema.json`, `trust-assumption.schema.json` |
| Authority inputs | `ProposedUse`, `StatusContext` | `proposed-use.schema.json`, `status-context.schema.json` |
| Dependency graph | `DependencyGraph`, `DependencyEdge` | `dependency-graph.schema.json` |
| Observation/prefix/completion/fiber | `ObservationCut`, `MeasurementRelation`, `MeasurementRelationArtifact`, `RepresentationRelation`, `RepresentationRelationArtifact`, `PrefixView`, `CompletionAdmission`, `FiberAssocView` | `observation-cut.schema.json`, `measurement-relation.schema.json`, `measurement-relation-artifact.schema.json`, `representation-relation.schema.json`, `representation-relation-artifact.schema.json`, `prefix-view.schema.json`, `completion-admission.schema.json`, `fiber-assoc-view.schema.json` |
| Agreement/guard | `Agreement`, `GuardRecord` | `agreement.schema.json`, `guard-record.schema.json` |
| Kernel proof | `KernelProof`, `KernelProofArtifact`, `ProofRef`, finite backend proof metadata | `kernel-proof.schema.json`, `kernel-proof-artifact.schema.json`, `proof-ref.schema.json` |
| Authority runtime | `ResolvedAuthorityRuntime` summary built by bundle replay | `resolved-authority-runtime.schema.json` |
| Replay trace | `ProtocolRecordArtifact`, `ReplayTrace`, `ReplayStageTrace`, `PipelineReport` trace fields | `protocol-record-artifact.schema.json`, `replay-trace.schema.json`, `replay-stage-trace.schema.json`, `pipeline-report.schema.json` |
| Lifecycle update | `LifecycleDecision`, `LifecycleEvent`, `FoldResult` | `lifecycle-decision.schema.json`, `lifecycle-event.schema.json` |

`ProfileResolution` is itself evidence-bearing: unsupported, schema-invalid, or
checker-unknown profile records must include non-empty `reason_refs`, while
pass records may leave them empty. This prevents an unsupported extension or
profile downgrade from being represented as a bare status string.

The main failure codes are:

| Failure code | Typical source |
| --- | --- |
| `canonicalization_mismatch` | non-canonical JSON values such as floats or unsupported canonicalization profiles |
| `schema_invalid` | JSON Schema, field presence, closed-world, or conditional field failures |
| `digest_mismatch` | artifact or `SetRef` canonical digest mismatch |
| `missing_ref` | unresolved artifact, JSON Pointer, reason, obligation, or set reference |
| `artifact_conflict` | dependency cycle, retrieval-policy conflict, immutability conflict, or conflicting artifact identity |
| `unsupported_profile` | profile not implemented by the runtime |
| `trace_conflict` | lifecycle duplicate, ancestry, log-root, or trace disagreement failures |
| `clock_boundary_unknown`, `expired` | status-time clock outside a strict active coordinate |
| `completion_missing`, `prefix_unsound`, `exact_prefix_empty` | operational prefix/completion admission failures |
| `assoc_empty`, `assoc_mixed`, `checker_unknown` | fiber/checker obligation failures |
| `policy_block`, `out_of_frame`, `revoked`, `superseded` | policy/status lifecycle gates |

## Claim JSON AST

The bounded claim language is represented as JSON:

```json
{
  "op": "G",
  "a": 0,
  "b": 2,
  "child": {
    "op": "atom",
    "name": "field_cmp",
    "args": { "field": "temp", "op": "lte", "value": "80" }
  }
}
```

Supported operators are `atom`, `not`, `and`, `or`, `G`, `F`, and `U`.
Built-in predicates include `field_cmp`, `field_eq`, `state_in`, `true`, and
`false`.

## Kernel Rule

The checked kernel follows the paper:

- `infeasible` when accepted residual infeasibility evidence exists.
- `assert` when nonempty feasibility exists and the outer enclosure is included
  in the satisfaction set.
- `deny` when nonempty feasibility exists and the outer enclosure is disjoint
  from the satisfaction set.
- `abstain` otherwise.

Operational `accept`/`reject` is emitted only when kernel direction, fiber
direction, target adjudication, adequacy, empty blocking set, and policy allow
all agree.

## Bundle Replay Semantics

Raw evidence is audit-only. `admit_evidence` creates `AcceptedClause` records
only when evidence identity, kind, checker status, checker transcript,
reference digest, validity, expiry policy, and monitor status pass.
Admission checker transcripts in the standalone checker contract must be bound
to an artifact JSON Pointer or a cryptographic digest; a bare `artifact:` id is
an audit label until ledger replay resolves it to typed transcript evidence.
Local labels such as `checker:model` are `checker_unknown` and cannot create
accepted clauses.
When an admission contract or direct accepted-clause artifact carries monitor
obligations, `monitor_status: pass` also requires a resolved
`monitor_evidence_ref` or `monitor_completeness_ref`; monitor silence or an
unbacked pass produces `validity_unknown`. In formal issuance and full replay,
`monitor_evidence_ref` must resolve to an evidence artifact, while
`monitor_completeness_ref` must resolve to a proof-role artifact; role
mismatches are `artifact_conflict`.
Formal issuance and full replay also validate `AdmissionContract` artifacts
before they can generate accepted clauses. The contract must satisfy the
schema-required fields (`kind`, `source`, `target`, `clause`, and
`checker_transcript_ref`), the transcript ref must be ledger-addressed and
resolve to transcript evidence, and `obligation_refs` must be non-empty
artifact refs resolving to obligation artifacts with active scope `pass` or
reason-backed `waived`. Symbolic obligations such as local `obligation:*`
labels are retained only as annotations and produce `checker_unknown` in the
strict path.
`compile_bundle_from_accepted_clauses` constructs finite semantics from
accepted clauses only; raw evidence fields are never read by the compiler.
Legacy raw bundle issuance remains available as a compatibility path, but the
certificate records a `TrustAssumption` obligation rather than treating raw
semantics as unqualified evidence.

`ReferenceLedger` resolves refs into typed `ReferenceLedgerEntry` rows. Each row
records the ref kind (`artifact`, `reason`, `obligation`, `set`, `profile`,
`schema`, `transcript`, or `proof`), owner artifact/path, target pointer,
target digest, actual semantic role, expected kind, expected semantic role,
expected digest, required stage, active-scope status, required flag, and
resolved flag. Symbolic protocol refs are retained as non-semantic annotations
unless a bundle supplies an artifact-addressed target. In full replay,
unresolved required ledger entries, role/digest mismatches, and inactive
obligation scopes, and non-accepted proof artifacts become `missing_ref`,
`digest_mismatch`, `artifact_conflict`, or `checker_unknown` before authority
emission. For typed mapping refs, a supplied `digest` is normalized into the
ledger `expected_digest` and compared against the canonical digest of the
resolved JSON Pointer target; mismatch is `digest_mismatch`. A waived obligation
is not a bare override: it is accepted only when
its `reason_refs` are non-empty artifact JSON Pointers that resolve inside the
same reference context; otherwise the waiver is `checker_unknown`. If an
obligation carries an `expiry`, `reference_context.status_time` is the active
scope evaluation time. Expired obligations, malformed expiry values, and
expiring obligations without an evaluation time are classified as inactive
evidence and block strict replay with `checker_unknown`.
When an artifact bundle gives an entry-level `role`, it is normalized into the
entry `ArtifactRef` if that ref omitted `semantic_role`. In strict replay,
authority-relevant refs (`reason`, `obligation`, `set`, `profile`, `schema`,
`proof`) must resolve to artifacts whose semantic role matches the expected
role; missing or conflicting roles are `artifact_conflict`.
`validate_set_ref` remains the wire-level digest check for a `SetRef`, while
`ReferenceChecker.set_ref` is stricter: `soundness_ref` must be bound to an
artifact-addressed proof or a content digest. A set ref with a valid digest but
only a symbolic soundness label is `checker_unknown` and cannot satisfy the
checker contract. Full authority replay now carries bundled SetRef artifacts in
`ResolvedAuthorityRuntime.set_ref_records`; when such artifacts are present,
the `SetRefSound` guard runs the checker on each record instead of treating the
presence of `certificate.set_refs` as sufficient evidence. Issue and status
schemas both require `set_ref_records`, so this evidence remains visible in the
canonical authority profile.
Direct `AcceptedClause` artifacts are admitted into semantics only
when evidence, contract, transcript, obligation, and reason provenance are
ledger-valid. Formal issuance and full authority replay both use role-aware
checks: evidence refs must resolve to evidence artifacts, contract refs to
admission-contract artifacts, obligations to obligation artifacts, and reason
refs to reason artifacts. Role mismatches are `artifact_conflict` and cannot
reach the bundle compiler.
Direct accepted-clause `reason_refs` are typed reason records, not string
labels. Each reason record must carry a non-empty artifact id, JSON Pointer
`source_path`, and SHA-family `digest`; replay compares that digest with the
resolved reason artifact target and emits `missing_ref`, `digest_mismatch`, or
`artifact_conflict` before any accepted clause reaches compilation. The
compatibility `AcceptedClause.from_json` helper may still normalize legacy
string reasons for callers, but formal artifact-bundle replay rejects them.
Direct accepted clauses are also provenance-checked against the referenced
admission contract and evidence payload. The accepted `target`, semantic
`clause`, and `checker_transcript_ref` must match the contract, the evidence
artifact id and kind must match the contract source and kind, and any contract
`reference_digest` must be present in the evidence payload or artifact refs.
Mismatches are reported as `artifact_conflict` or `digest_mismatch` before the
clause can influence compiled semantics.
`AcceptedClause` now also carries typed `obligation_ref_records`. Direct
accepted-clause artifacts must provide typed records for their `obligation_refs`;
otherwise replay reports `missing_ref` before the clause can affect semantics.
Formal issuance and full replay evaluate each record's active-scope status and
require `pass` or a reason-backed `waived` status. A `pass` obligation record
must carry an artifact-bound `source_artifact`, JSON Pointer `source_path`, and
SHA-family `digest`; these are checked against the same reference ledger used
for artifact refs, so stale or digest-mismatched obligation evidence is rejected
before compilation. Internally generated accepted records from an
evidence/contract pair may still carry an empty typed-record tuple because their
contract path records obligations separately; direct artifact ingestion is the
strict ledger-validated path.
Direct `TrustAssumption` artifacts are also ledger-validated. A trust assumption
must carry artifact JSON Pointer `reason_refs`, digest-bound typed
`reason_ref_records`, and `obligation_refs`, and its `checker_transcript_ref`
must resolve to an accepted transcript in the same bundle. Each typed trust
reason record is resolved through the ledger by `source_artifact`, JSON Pointer
`source_path`, semantic role, and digest before the trust assumption can affect
semantics. Trust obligations must resolve to obligation artifacts whose active
scope is `pass` or reason-backed `waived`; symbolic migration notes, missing
typed reason evidence, or unresolved trust obligations produce
`checker_unknown`, `missing_ref`, or `validity_unknown` before raw bundle
semantics can be trusted.
Checker transcript refs must resolve to transcript records with `status`,
`checker_status`, `result`, or `transcript` equal to `pass` or `accepted`.
Rejected, unknown, malformed, or non-record transcript targets are
`checker_unknown` in strict replay.
Accepted-clause targets are semantic binding fields, not annotations.
`semantics` is the portable target; concrete targets must match the current
base bundle id or its `bundle:`, `compiled:`, or `accepted-bundle:` form. A
clause admitted for another semantic target is `artifact_conflict` in both
formal issuance and full authority replay.
Accepted-clause reason refs are typed records; the runtime
preserves failure code, layer, source artifact, JSON Pointer, message, and
digest instead of collapsing provenance to a string. The
`accepted-clause.schema.json` profile rejects empty reason or obligation ref
sets, and formal artifact-bundle issuance validates direct accepted-clause
artifacts against that schema before compiling semantics. Authority replay uses
the same schema gate, so schema-invalid direct accepted-clause artifacts cannot
reach `compile_bundle_from_accepted_clauses`.

For strict full replay, kernel acceptance also requires a resolved
`KernelProofArtifact`. The artifact must carry accepted/pass proof metadata and
a resolved checker transcript. Feasible kernel candidates require resolved
witness provenance refs; `assert` candidates require an inclusion proof ref;
`deny` candidates require a disjointness proof ref; and `infeasible` candidates
require an infeasibility proof ref. Artifact-conflict, evidence, and reason
proof refs are checked through the same ledger when present. In strict replay,
kernel checker transcripts, witness provenance refs, inclusion/disjointness/
infeasibility proof refs, artifact-conflict refs, and evidence refs must be
artifact- or digest-bound (`artifact:...`, `sha256:...`, `sha384:...`, or
`sha512:...`). Local labels such as `checker:kernel` or `proof:inclusion`
are audit annotations only and fail schema/runtime ingestion as authority
evidence.
`KernelProof` and `KernelProofArtifact` preserve compatibility
`reason_refs`, but public JSON also carries typed `reason_ref_records`. A
kernel proof artifact can therefore keep proof-local reason provenance with
`reason_id`, failure code, layer, source artifact/path, message, and optional
digest instead of flattening proof reasons into string ids. Backend-generated
finite proof metadata may still emit string ids, but artifact-bundle proof
records use the typed field for protocol evidence.
The reference checker's `artifact_conflict` contract compares both typed
artifact objects and JSON bundle shapes, including nested `artifact_ref`
records. Two accepted artifacts with the same `(artifact_type, artifact_id)` but
different digest values are a protocol conflict, regardless of whether they
arrive as dataclasses or manifest JSON.
In strict replay,
the proof payload must also bind to the computed `KernelView`:
`expected_verdict`, `feasibility`, `inclusion`, `disjointness`, and
`backend_identity` are compared with the finite backend result. Missing
coordinates or required proof refs are `checker_unknown`; conflicting
coordinates are `artifact_conflict` and downgrade authority to `unknown`. If no
kernel proof artifact is available after status and guard replay, `KernelCheck`
emits `checker_unknown` and the authority outcome is `unknown`. If a kernel
proof artifact is present but rejected, missing its transcript, or referring to
unresolved proof artifacts, replay stops with `checker_unknown` or `missing_ref`
before authority emission. Resolved kernel proof refs are content-checked as
well: witness refs must point to accepted witness or witness-provenance proof
artifacts, inclusion refs to inclusion proofs, disjointness refs to disjointness
proofs, and infeasibility refs to infeasibility proofs. A resolved proof artifact
with the wrong `proof_kind` is `artifact_conflict`; an unaccepted or
content-unresolvable proof target is `checker_unknown`. Target proof payloads
must bind back to the parent `KernelProofArtifact` with `kernel_proof_ref` and
must match the parent `backend_identity` and `expected_verdict`. Inclusion,
disjointness, and infeasibility targets must also expose the corresponding
`inclusion`, `disjointness`, or `feasibility` coordinate. Missing payload
coordinates are `checker_unknown`; conflicting coordinates are
`artifact_conflict`.

`AuthorityReplayContext` is the canonical bridge from an `ArtifactBundle` to
authority recomputation. It now carries a `ResolvedAuthorityRuntime`; the
authority core reads claim, compiled semantics, anchor, time basis, artifact
refs, accepted clause refs, proof refs, ledger entries, and resolved
reason/obligation refs from that runtime instead of re-reading embedded
certificate sources. The runtime summary preserves both legacy id lists and
typed `resolved_obligation_records`, `resolved_reason_ref_records`, and
`proof_ref_records`; these records participate in the runtime summary digest
used by replay and conformance output.
`check_authority` is a public wrapper. Direct dict or
dataclass inputs are first normalized into a synthetic local bundle with
artifact refs and marked synthetic-trust. Replay resolves issue certificate or
claim/bundle/anchor/time-basis artifacts, proposed use, status context,
lifecycle event artifacts, observation artifacts, accepted evidence clauses,
trust assumptions, obligation refs, reason refs, artifact refs, ledger entries,
proof refs, and guard records. In strict full replay, a
certificate artifact must be accompanied by explicit artifacts matching its
`claim_ref`, `assumption_bundle_ref`, `anchor_ref`, and `time_basis_ref`;
embedded sources are compatibility data, not the authority source of truth. If
accepted clauses are present, the replay path replaces certificate semantics
with the accepted-clause bundle before calling `check_authority`.
The resulting `ReplayTrace` records the protocol records and proof refs created
at `Replay`, `GuardEvaluate`, `KernelCheck`, and `AuthorityEmit`; the same refs
are copied into `PipelineReport.stage_artifacts` for CLI and conformance use.
Full replay now materializes the paper-level intermediate records that the
finite engine can construct without an external solver: `StatusObservationContext`,
`ObservationCut`, `PrefixView`, `ResidualContext`, `CompletionAdmission`,
`FiberAssocView`, `AdjudicationViews`, `KernelView`, and `Agreement`. Missing
or unresolved proof-bearing records are carried as blockers instead of being
collapsed into a summary reference.
Each generated record is represented as a `ProtocolRecordArtifact` carrying a
stable record id, stage, payload, artifact refs, typed artifact ref records,
proof refs, typed proof ref records, reason refs, typed reason ref records, and
canonical digest. The typed records are part of the digest material, so a stage
record cannot silently collapse accepted artifact, proof, or reason evidence to
string ids.
The payload is preserved in `PipelineReport`/`ReplayTrace`, so stage records can
be audited without reconstructing them from summary refs.
Generated protocol-record payloads now include `construction_sources` for the
record's replay stage. That object lists the resolved ledger entries, typed
proof records, accepted clause refs, and compiled bundle ref that were used to
materialize records such as `ObservationCut`, `PrefixView`,
`CompletionAdmission`, `FiberAssocView`, `KernelView`, and `Agreement`.
Consequently a full-replay stage record is not only a summary of declared
status-context fields; it preserves the artifact/proof/checker-transcript
inputs that licensed the construction.
`ProtocolRecordArtifact` is schema-valid only when it carries the canonical
record digest and a normative validation stage name; digest-free records or
ad-hoc stage labels are rejected rather than accepted as replay evidence.
`ReplayStageTrace.record_refs` contains only generated
`ProtocolRecordArtifact.record_id` values. Broader audit references such as
lifecycle artifact ids, guard names, proof ids, accepted clause ids, authority
outcome digests, and runtime digests remain in `stage_artifacts`; they are not
mixed into `record_refs`. `stage_artifacts` itself is keyed only by normative
validation stage names; ad-hoc stage keys are schema-invalid in both
`ReplayTrace` and `PipelineReport`.
For full replay, `StatusAuthorityView.minimum_profile().kernel_view_ref` points
to the generated `KernelView` protocol record id from the trace; it is not the
kernel verdict string. This keeps the authority view tied to replayed proof
material instead of a summary outcome label.
Each `ReplayStageTrace` now carries typed blocking records, typed reason
records, typed artifact records, and typed proof records for the stage.
`artifact_refs` and `proof_refs` remain stable identifier lists, while
`artifact_ref_records` preserves schema/canonicalization/digest/role
coordinates and `proof_ref_records` preserves proof kind, artifact pointer,
digest, and checker status. A stage trace can therefore be audited without
opening every generated `ProtocolRecordArtifact`.
refs in addition to legacy id lists, so stage-level failures can be audited
without dereferencing a side channel. The schema rejects non-pass stage traces
that do not include non-empty typed blockers and reasons.
If authority replay stops before a `StatusAuthorityView` can be emitted, the
reference engine still returns a `ReplayFailure` protocol record and a
stage-level `ReplayTrace`. `PipelineReport` preserves that trace even when the
replay context is unavailable, including typed failure, blocker, reason,
artifact, unresolved-reference, and proof evidence.

Status failure views preserve the same replay evidence as successful views:
artifact refs, ledger entries, proof refs, resolved obligations/reasons, and
stage blockers remain attached to `StatusAuthorityView` so non-allow outcomes
are auditable without consulting the `PipelineReport` side channel.
`StatusAuthorityView.minimum_profile()` also emits schema-valid
`reason_ref_records`, `obligation_ref_records`, `proof_ref_records`,
`set_ref_records`, `artifact_ref_records`, and `blocking_records` at the view
level, plus typed reason and blocking records inside `authority_outcome`;
packaged conformance digests include those typed records, not free-form human
messages.
`proof-ref.schema.json` requires a
SHA-family digest whenever a proof ref record has `status: accepted` or
`status: pass`; digest-free accepted proof records are not schema-valid
protocol evidence. If a view is constructed directly with
raw `BlockingRecord` evidence, blocker reason refs are normalized into
artifact-bound JSON Pointer records with canonical digests before the profile
is emitted. Ledger-backed obligation records retain
active-scope status and proof records retain artifact, JSON Pointer, digest,
and acceptance status when replay resolved them. Proof refs that name an
artifact present in the full replay bundle are also materialized as typed proof
records with `source_artifact`, `/` source path, artifact digest, and accepted
status; unresolved internal finite-backend metadata remains explicit `unknown`
instead of being promoted to accepted proof evidence. Direct `ProofRefRecord`
construction follows the same schema rule: `accepted` or `pass` proof records
require a SHA-family digest, and proof source paths must be JSON Pointers. The
`status-authority-view.schema.json` profile requires the typed
obligation/proof sections and requires non-empty typed reason and blocking
records whenever the authority gate is `block` or `unknown`. The reference
checker mirrors that rule: a non-allow `typed_authority_outcome` cannot pass
from a bare outcome code, string-only reason pointer, missing digest, or
untyped blocking entry. Non-decisive outcomes such as `unknown` must also carry
typed blocking records; a typed reason record alone is insufficient authority
evidence.
Authority obligation references follow the same evidence discipline:
`obligation_refs` must be accompanied by typed `obligation_ref_records`.
`ReferenceChecker.typed_authority_outcome` accepts only active `pass` obligation
records or explicit reason-backed `waived` records. A waived authority
obligation with empty or malformed `reason_refs` is not accepted as evidence;
unresolved `unknown`, `inactive`, or `not_checked` obligation records are
`checker_unknown`, not authority evidence. A `pass` obligation record must also
carry an artifact-bound `source_artifact`, JSON Pointer `source_path`, and
SHA-family `digest`; otherwise AuthorityEmit reports `missing_ref` instead of
treating the obligation id as proof evidence. Expired or invalid obligation
scope at the outcome status time is `validity_unknown`.
Authority proof references are checked by the same AuthorityEmit contract:
non-empty `proof_refs` must be covered by typed `proof_ref_records`, and
accepted/pass proof records must carry digest-bound proof evidence. A proof id
without a typed record, a record id that does not cover the referenced proof, or
an accepted proof record without a SHA-family digest is `missing_ref`, not
authority evidence.
The outcome schema reference is also checked: the built-in
`status-authority-view` schema name is accepted for local protocol output, but
unknown bare schema labels are not authority evidence. External outcome schema
evidence must be a SHA digest, an artifact JSON Pointer, or an accepted
`authority_outcome_schema`/`schema_validation` checker transcript.
The paper's normative `layer`/`code`/`direction` table is enforced in both
`status-authority-view.schema.json`, `ReferenceChecker.typed_authority_outcome`,
and the `AuthorityOutcome` runtime validator. The runtime validator also
rejects allow-like outcomes carrying blockers, non-allow outcomes without
reason refs, and non-decisive outcomes without blocking records.
For example, `policy/allow/none` and `operational/accept/positive` are valid
combinations, while `operational/allow/none` or `operational/accept/none` are
rejected as authority conflicts.
Dominant status routing is also enforced. If the folded status is `expired`,
`revoked`, `superseded`, `invalid`, `conflict`, `out_of_frame`, or `unknown`,
the authority outcome must be the corresponding status-layer outcome with
direction `none`; a policy `allow`, represented `assert`, or operational
`accept` is rejected before it can upgrade the status result.
Both legacy status artifacts and first-class `status_authority_view` artifacts
are passed through the AuthorityEmit checker contract after schema validation.
This catches semantically inconsistent but schema-valid outcomes, such as an
allow outcome that still carries blocking records.
Operational `accept` and `reject` outcomes are also tied back to the computed
`Agreement`: `accept` requires positive agreement evidence, and `reject`
requires negative agreement evidence. A typed outcome schema reference alone is
not enough to emit frame-relative operational authority; missing agreement is
`checker_unknown`, while a mismatched agreement direction is `artifact_conflict`.
Accepted checker evidence is also required to be artifact-bound. A bare
`checker_status: pass`, `proof_status: pass`, or equivalent status flag does
not pass schema, frame, observation, agreement, or status-context checks unless
it is accompanied by an artifact ref, digest, or typed artifact JSON Pointer.
Schema validation evidence is stricter than a generic artifact reference:
`ReferenceChecker.schema` requires an accepted `schema_validation` or `schema`
transcript that is digest-bound, source-pointer-bound with a digest, or carried
by an `ArtifactRef` object with its own digest. An artifact id plus
`checker_status: pass` remains `checker_unknown`. When the artifact declares
`schema_name` or `artifact_id`, the schema transcript payload must bind the same
schema or target artifact id; a missing payload remains `checker_unknown`, and a
different target is `artifact_conflict`.
The same digest-bound rule is applied to reason-path, initial-context,
assessment-frame, observation-cut, and status-observation-context checker
evidence because those records define the reference and frame replay surface
used by authority. Assessment-frame evidence also binds the frame id in its
payload; missing frame identity remains `checker_unknown`, and a different
target frame is `artifact_conflict`. Observation-cut proof evidence binds the
status time, time basis, event-order coordinate, and frame id; otherwise the cut
must be supported by separate calibration, latency, dependency, and event-order
refs. Status-observation-context evidence binds the residual/prefix index `r`;
when the observation cut carries status time, time-basis, event-order, or frame
coordinates, the transcript payload must bind those coordinates as well.
Missing coordinates remain `checker_unknown`, and mismatched coordinates are
`artifact_conflict`. A proof kind and an artifact id without digest or typed
pointer evidence remains `checker_unknown`.
Set reference soundness is stricter: `SetRef.soundness_ref` must be a digest or
an artifact JSON Pointer such as `artifact:set-soundness-proof#/proof`; a bare
artifact id remains `checker_unknown` because it does not identify the proof
record that establishes soundness.
The same rule applies to external residual-infeasibility proofs: a proof object
with only `proof_status` and `proof_kind` is not accepted. The bundled finite
`EnumeratingBackend` may emit exact internal proof metadata, but that metadata
must still carry a digest-bound `proof_ref` generated from the proof material.
External solver/prover evidence must carry a digest, an artifact JSON Pointer
such as `artifact:proof#/infeasibility`, or accepted checker evidence. A bare
`artifact:proof` label is only a locator and does not discharge infeasibility
by itself.
Witness admissibility is likewise provenance-bound: empty witness sets require
only subset validity, but a nonempty satisfying or nonsatisfying witness set
must also carry a digest, artifact pointer, witness provenance ref, or accepted
checker transcript. The finite backend derives its witness `proof_ref` from the
canonical satisfying/nonsatisfying witness payload.
Finite inclusion and disjointness checks also produce deterministic digest
proof refs from the canonical outer-enclosure and satisfaction-set payloads, so
`StatusAuthorityView.proof_ref_records` records the represented-kernel evidence
instead of only the boolean checker result.

Lifecycle replay checks duplicate event ids, ancestry, trace class, causal cut,
log root, canonical event hash, previous hash, manifest digest commitments, and
signature policy. Signature cryptography is intentionally an interface
boundary through `SignatureVerifier`; the default verifier returns unknown for
required signatures unless accepted verification evidence is supplied. In full
replay, lifecycle proof references such as confluence proof, signature verifier
result, log root, causal cut, trace class, and event-manifest refs must resolve
through the typed ledger when they are present; unresolved proof references
block authority emission with `missing_ref`. Top-level `confluence_proof` is
treated as a proof reference in strict replay. Required-signature verifier
results and lifecycle event manifest digests cannot license replay as direct
declarations without the corresponding ledger-resolved refs.
The direct `ReferenceChecker.event_order` contract follows the same rule for
logs: after replaying the fold and detecting trace conflicts, it requires
accepted, digest-bound evidence purpose-bound as `event_order`,
`accepted_event_set`, `causal_cut`, `trace_class`, or `log_root` before
returning pass. Empty logs are not accepted by `allow_empty` alone; they require
an accepted `empty_event_set_proof_ref`, event-order proof, causal-cut proof, or
log-root proof. `accepted_event_ids` by itself is only a proposed cut and returns
`checker_unknown`.
Lifecycle proof refs must be artifact- or digest-bound (`artifact:...`,
`sha256:...`, `sha384:...`, or `sha512:...`). Local labels such as
`proof:signature` or `proof:confluence` are audit annotations only; strict
replay reports them as `checker_unknown`, and lifecycle/status schemas reject
them for authority-relevant proof-ref fields. The standalone `LifecycleEvent`
schema and the embedded `StatusContext.event_log[*]` schema expose the same
authority-relevant proof-ref surface for signature verifier results, log roots,
causal cuts, trace classes, event-manifest proofs, manifest-digest proofs, and
confluence proofs, so lifecycle events can be validated as first-class
artifacts or as status-context entries without losing replay evidence.
Direct `fold_status` follows the same conservative rule for confluence:
bare proof ids are annotations only, while accepted artifact-bound and
purpose-bound confluence evidence is required before ancestry gaps, payload
conflicts, or trace disagreement can be discharged. The proof must identify the
event ids it covers; direct `status_confluence` additionally requires the proof
payload to cover the blocking trace sets it discharges.
Artifact-bundle full replay now resolves lifecycle proof refs into proof
payloads before status folding. A confluence proof must be purpose-bound and
cover the event ids it discharges; event-level confluence proof refs are
promoted into the fold context only after ledger and payload validation.
Signature verifier proofs must bind the verifier result used by the event,
event-manifest proofs must bind the declared digest, trace-class proofs must
admit the event kind, causal-cut proofs must cover the event ancestry, and
log-root proofs must be committed by the event hashes. Missing or non-matching
payload content is not a pass-by-reference shortcut: it becomes
`checker_unknown`, `digest_mismatch`, or `trace_conflict` before authority
emission.

`update_certificate` returns a typed `LifecycleDecision`. It records the
accepted causal cut, trace class, event manifest digest, dependency updates,
log root, frame transfer proof ref, proof-preservation refs, blocking set, and reason
refs. The decision also preserves the artifact-bound refs that justify the
event-manifest digest, signature verifier result, accepted event set, trace
class, causal cut, and log root. Dependency graph or frame changes without accepted transfer/proof
preservation evidence produce blocking `checker_unknown` or `out_of_frame`
decisions instead of a bare maintain/recompute string.
The lifecycle-decision schema requires the same trace/proof surface emitted by
the implementation, including accepted event ids and their ref, trace class and
its ref, causal cut and its ref, event-manifest digest ref, signature verifier
result ref, log root and its ref, dependency updates, frame transfer ref,
proof-preservation refs, blocking records, and typed reason refs. Legacy
maintain/recompute JSON that omits these fields is rejected instead of being
treated as a complete UpdateCertificate decision.
Accepted transfer and proof-preservation evidence must be artifact-bound; an
`accepted` status flag attached only to a symbolic proof id or a bare
`artifact:` ref is recorded as `checker_unknown`. Accepted update proofs must
also be purpose-bound to the field they discharge and carry a payload binding
the proof to the event id and the authority-relevant field: event-manifest
proofs bind `event_manifest_digest`, dependency transfer proofs bind
`dependency_updates`, frame transfer proofs bind `frame_digest`, and
proof-preservation evidence binds `proof_preservation_refs`.
The public `transfer_authority` compatibility API follows the same conservative
rule: `checker_status: pass` is not enough. The proof must be digest-bound,
purpose-bound as transfer authority evidence, and its payload must bind the
certificate id and target claim id, plus target frame or policy identifiers
when those are supplied. Missing or mismatched bindings return `block` with
`checker_unknown`.
Required signature verification follows the same rule in direct
`update_certificate`: `signature_verifier_result: pass` is only a declaration
unless `signature_verifier_result_ref` and an accepted, purpose-bound
`signature_verifier_result_status` bind the same lifecycle `event_id` and
verifier result. Missing, shallow, or payload-mismatched signature proofs
produce `checker_unknown`; an accepted artifact-bound status with the wrong
proof kind is `artifact_conflict`.
If the event omits the top-level `signature_verifier_result`,
`update_certificate` derives it from the accepted
`signature_verifier_result_status.payload.signature_verifier_result` before
folding. A bare declaration is still insufficient; only the artifact-bound
proof payload can supply the missing verifier result.
Direct lifecycle updates now apply the same rule to event-manifest digest
commitments on the event itself: `manifest_digest` requires
`manifest_digest_ref` or `event_manifest_ref` plus an accepted
`manifest_digest_status` / `event_manifest_digest_status` payload that binds
the same `event_id` and digest. A matching update-policy proof may discharge
the event-level requirement, but bare hashes or a shallow status object without
an artifact digest remain blockers rather than proof evidence.
When update policy supplies an accepted `trace_class` or `causal_cut`, those
coordinates also require artifact-bound proof records. The proof payload must
bind the same lifecycle `event_id` and the exact `trace_class` or `causal_cut`
used by the fold; otherwise the lifecycle decision is blocked with
`checker_unknown`, or `artifact_conflict` when an accepted proof artifact has
the wrong proof kind, points at a different artifact ref, or binds a different
event id / authority-relevant payload value.
When update policy supplies `accepted_event_ids`, the updated event must be a
member of that set and the set itself must have an artifact-bound accepted proof
whose purpose and payload bind the lifecycle `event_id` and the exact event-id
list used by the fold. Missing or payload-mismatched proof records are
`checker_unknown` unless an accepted proof artifact explicitly binds a
different event id or event-id list, in which case the mismatch is
`artifact_conflict`; wrong-kind accepted proof records are `artifact_conflict`;
an accepted set that omits the event is a `trace_conflict` blocker rather than
a silent no-op update.
Likewise, every id in `EventOrder.accepted_event_ids` must be replayed from the
event log for the same certificate. An accepted event id that is absent from
the log is a `trace_conflict` blocker at `/accepted_event_ids`; it is not
treated as an empty or filtered cut.
The accepted event set must also be coherent with the accepted causal cut: the
new event may be inserted, but any other accepted event id must already be in
the cut. A mismatch is `trace_conflict` even when the two proof records are
individually accepted.
Lifecycle event schema, canonicalization, and parse failures are converted into
typed reject decisions rather than escaping as exceptions. Update policy can
also require a concrete event-manifest digest and `policy_version`; mismatches,
missing event-manifest proof records, unsupported digest bindings, and
unaccepted dependency/frame/proof-preservation status values are preserved as
typed blockers in the decision JSON.
The `lifecycle-decision.schema.json` profile now requires non-accepted
decisions to include non-empty typed `blocking_records` and
`reason_ref_records`; each reason record must carry an `artifact:*` source,
JSON Pointer source path, and SHA-family digest. String-only legacy blocker ids
or digest-free lifecycle reasons are not sufficient for a blocking lifecycle
artifact.
`update_certificate` blockers emitted by the reference engine also carry the
lifecycle event id and a JSON Pointer to the policy, manifest, dependency,
frame-transfer, or proof-preservation field that blocked the update.

Operational authority reconstructs prefix and fiber records from accepted
observation records when they are present in `StatusContext`. In strict replay,
measurement evidence (`calibration_ref`, `latency_ref`, `dependency_ref`,
`event_order_ref`), representation proof, completion transcript, adjudication
proof, and adequacy proof must resolve through the ledger. Record declarations
without those resolved proofs are fallback audit data and add
`checker_unknown` blockers, so they cannot license operational `accept` or
`reject`. Formal observation replay also resolves `measurement_relation_ref`
and `representation_relation_ref` to `MeasurementRelationArtifact` and
`RepresentationRelationArtifact` payloads before constructing the exact prefix;
the implementation constructors follow the artifact schemas here: measurement
relation artifacts require at least one bound `proof_refs` entry and
representation relation artifacts require at least one relation with a bound
`proof_ref` and represented prefix. Direct constructor paths no longer treat
calibration, latency, dependency, and event-order labels as an accepted
measurement relation by themselves; a bound `measurement_proof_ref`,
`measurement_relation_proof_ref`, or relation-artifact `proof_refs` entry is
required before an operational prefix fiber can be constructed as `pass`.
Likewise, legacy `represented_prefix` plus `representation_proof_ref` fields are
audit annotations for direct constructors; exact prefix construction requires a
structured `representation_relation` record or a resolved
`RepresentationRelationArtifact`.
The reference checker also purpose-binds direct measurement evidence, requiring
accepted `calibration`, `latency`, `dependency`, and `event_order` evidence for
the corresponding field, or an accepted `observation_cut`/`observation` proof
for the whole record. Direct measurement evidence is not accepted by presence
alone: each calibration, latency, dependency, and event-order proof must bind
the observation-cut coordinates (`status_time`, `time_basis`, `event_order`,
and `frame_id`) in its payload. Missing coordinate payloads are
`checker_unknown`; coordinate conflicts are `artifact_conflict`.
When those artifacts resolve, their payloads override stale status-context
declarations for measurement evidence, operational prefix, represented prefix,
and representation proof. Nested relation refs and `relations[*].proof_ref` are
included in the typed ledger. In strict replay, relation artifacts must also be
accepted by checker status, measurement relation artifacts must carry resolved
proof refs, and representation relation proof refs must resolve before the
relation payload can construct prefix or fiber records. Resolved relation proof
payloads must also bind the relation content: measurement proof artifacts carry
the `relation_id`, `calibration_ref`, `latency_ref`, `dependency_ref`, and
`event_order_ref` that they admit, and representation proof artifacts carry the
`relation_id`, `operational_prefix`, and `represented_prefix` they admit. A
missing binding is `checker_unknown`; a binding that disagrees with the relation
artifact is `artifact_conflict`. Measurement relation refs, measurement proof
refs, representation relation proof refs, and
operational adjudication/adequacy proof refs must be artifact- or digest-bound
(`artifact:...`, `sha256:...`, `sha384:...`, or `sha512:...`). Local labels
such as `representation-proof:demo` or `proof:measurement` are audit
annotations only and become `checker_unknown` in strict replay.
The direct `ReferenceChecker.representation_interface` contract also requires
accepted projection-coherence evidence purpose-bound as
`projection_coherence`, `representation_projection_coherence`, or
`representation_interface`; a `projection_coherence: true` declaration alone is
not enough to pass the checker contract.
`status-context.schema.json` applies the same bound-ref rule to known
`observation_records[*]` fields: measurement and representation relation refs,
calibration/latency/dependency/event-order evidence, representation proof,
adjudication proof, and adequacy proof. Direct compatibility APIs may still
parse legacy declaration-shaped records outside the formal artifact-bundle
path, but the frame constructors no longer use local labels such as
`calibration:demo` or `representation-proof:demo` to construct operational
prefix fibers or exact represented prefix sets. Those declarations remain
audit annotations until artifact- or digest-bound evidence is supplied.
Prefix admission must
also carry accepted `prefix_admission` proof or transcript evidence on the
observation record before a computed exact prefix can pass. Prefix soundness and
residual context checker contracts require their own purpose-bound accepted
proof/transcript records; a `prefix_status=pass` declaration alone is not a
protocol proof. Operational prefix and completion fiber checker contracts
likewise require accepted evidence purpose-bound as
`operational_prefix_fiber`/`prefix_fiber` or
`operational_completion_fiber`/`completion_fiber`; a finite fiber computed from
record declarations alone remains audit data. Positive or negative association
checker outcomes (`checked_assoc_view`, `exact_fiber_assoc`, `fiber_assoc`) also
need purpose-bound accepted proof/transcript evidence; empty or mixed
associations remain blocking failures. Completion admission requires
`admission_source`, `expiry`, `uncertainty_model`, `reference_digest`,
`checker_result`, and `checker_transcript_ref` before a `pass` status is
accepted. The checker contract requires that transcript or completion-admission
proof to be accepted and purpose-bound as `completion_admission`, `completion`,
or `checker_transcript`, and the accepted payload must bind the admission
identity: `completion_status`, `admission_source`, `expiry`,
`uncertainty_model`, `reference_digest`, and `checker_result` must match the
recomputed admission record. When a status-time completion set is used, strict
replay also requires the accepted payload to bind `c_out_ref` (and `c_in_ref`
when present) plus the status time, so a transcript cannot be replayed against a
different completion fiber. Completion admission records preserve only transcript
refs bound to an `artifact:` ref or cryptographic digest; local labels such as
`checker:completion` downgrade the admission to `unknown`. Strict operational replay additionally requires a
resolved `c_out_ref` set for the admitted completion outer fiber. The reference engine treats status-context
`operational_completions` as audit-only in strict replay unless they were
populated from the resolved `c_out_ref` set artifact; concrete finite
completion members are carried in the SetRef artifact's optional `members`
field. Expired admissions, missing completion sets, missing completion
members, or unsupported digest bindings do not license operational use. Prefix/target
adjudication and adequacy directions are reconstructed from accepted proof
artifact payloads (`prefix_adjudication`, `target_adjudication`, or
`adequacy_direction`); missing proof content is `checker_unknown`, and proof
content that conflicts with a status-context declaration is `artifact_conflict`.
`adequacy_proof_ref` may be supplied on an observation record or on
`status_context.frame.policy`. In both locations strict replay reads the proof
payload and uses it as the source of `adequacy_direction`; a declared frame
policy direction that disagrees with the proof payload blocks with operational
`artifact_conflict`.
The checker contract also purpose-binds adjudication and adequacy evidence:
prefix, usage, target adjudication, and frame adequacy require accepted evidence
marked respectively as `prefix_adjudication`, `usage_adjudication`,
`target_adjudication`, or `frame_adequacy`/`adequacy`. Operational prefix
fiber, completion fiber, completion admission, prefix admission, prefix
soundness, residual context, fiber association, adjudication, and frame
adequacy evidence must also be digest-bound; a bare `artifact:` reference with
accepted status is `checker_unknown`.
For direct checker calls, prefix, usage, target adjudication, and frame
adequacy proofs must also carry payload content that binds the computed
adjudication or adequacy direction. When the frame id, proposed-use mode, or
target id is present in the checker input, the proof payload must bind those
identities too; direction-only payloads are audit evidence, not authority
evidence. A missing payload leaves the checker result `checker_unknown`; a
payload that disagrees with the computed direction or identity is
`artifact_conflict`.
The same payload-binding rule applies to direct association checks:
`checked_assoc_view` proof must bind the computed `assoc_status` or
`fiber_status`, and `exact_fiber_assoc` proof must bind a nonempty exact
association. Missing association payloads remain `checker_unknown`; direction
or emptiness mismatch is `artifact_conflict`.
Direct operational prefix fiber, operational completion fiber, prefix
soundness, and residual context checks also require digest-bound proof payloads
that bind the computed `fiber_status`, `prefix_status`, or
`residual_context_status` to `pass`. A proof ref with accepted status but no
payload remains `checker_unknown`; a payload that disagrees with the computed
record status is `artifact_conflict`.
Artifact-bundle replay resolves proof references with their JSON Pointer before
reading proof content. A reference such as `artifact:proof#/nested` can only use
the object at `/nested`; accepted fields at the artifact root do not discharge
that pointed proof obligation.
Operational or lifecycle proof evidence supplied as an object follows the same
rule: the object must carry accepted status, a purpose/kind field, and a
SHA-family `artifact_digest`, `digest`, or `reference_digest`. An object with
only `artifact_ref` and `proof_status: accepted` is schema-invalid for
status-context and lifecycle-event inputs, and remains `checker_unknown` if
supplied through a compatibility path.
Agreement and the final operational outcome are then computed through the
checker path instead of trusting status-context declarations. `ReferenceChecker`
does not accept an agreement proof by presence alone: the proof ref must be
accepted, digest-bound, and purpose-bound as `agreement`/`agreement_proof`,
and its payload must bind the kernel direction, fiber association direction,
prefix/use/target adjudication, adequacy direction, and policy gate used by the
checker. Those bound coordinates must match the positive or negative pattern
together with an empty blocking set and `allow` gate.
Directional mismatch with accepted agreement evidence is an operational
`artifact_conflict`; missing coordinates remain `checker_unknown`. Typed
authority outcomes are also consistency-checked: an allow-like code cannot carry
blocking records, cannot override a blocked policy gate, and cannot conflict
with a positive or negative agreement record. For non-allow outcomes, typed
reason evidence must satisfy the same minimum record profile as
`reason-ref.schema.json`: `reason_id`, `failure_code`, `layer`,
`source_artifact`, `source_path`, `message`, and a SHA-family digest for
authority evidence. Negative decisive outcomes such as represented `deny`,
represented `infeasible`, and operational `reject` are still non-allowing
outcomes and therefore must preserve typed reason refs even when their blocking
set is empty. An artifact/path/digest tuple without the reason identity and
failure metadata is treated as `missing_ref`, not as a complete reason ref.
Authority blocking records must likewise carry `block_id`, `failure_code`,
`layer`, `severity`, non-empty `reason_refs`, and non-empty
`reason_ref_records`; the listed reason ids must match the typed reason records
so canonical equality cannot be driven by an unbound blocker id.
The `status-authority-view.schema.json` conditional profile enforces this both
when the policy gate is `block`/`unknown` and for every code outside the
allow-like set (`allow`, `accept`, `assert`, `active`). Non-decisive outcomes
still require typed blocking records, so `unknown` outcomes cannot be
schema-valid merely because their gate is `allow`. The represented authority
path emits a `checker_unknown` blocker when the kernel verdict is not decisive
and no stronger blocker exists.
The same decisive-code set is used by `ReferenceChecker.typed_authority_outcome`
and the shallow compatibility authority stage, avoiding a schema/runtime split
where `reject`, `deny`, or `infeasible` would be schema-valid but checker-invalid.
When the direct checker is called without an explicit `gate_decision` argument,
it reads the typed outcome's own `gate_decision`; an artifact cannot bypass a
blocked or unknown policy gate by omitting the external checker argument.

## CLI And Conformance

`dfcc validate-bundle` accepts either a finite assumption bundle or an
`ArtifactBundle`. `--horizon` is required only for finite assumption bundles.
Artifact bundle validation emits a `PipelineReport`; with
`--full-replay`, missing issue/proposed-use/status artifacts are blocking
`AuthorityEmit` failures instead of ignored optional context. Full replay
reports include a schema-valid `replay_trace` object with typed stage blockers,
reason refs, protocol records, and the runtime summary digest, so CLI output is
auditable without reconstructing trace data from side fields. Finite bundle
validation emits a compile summary. `dfcc replay-status --bundle` runs full
artifact-bundle replay and emits the same `PipelineReport.replay_trace`; the
three-file form remains available for compatibility.
Direct dict/dataclass `check_authority` compatibility is normalized through a
synthetic artifact bundle. That path is non-strict for backwards compatibility,
but the returned `StatusAuthorityView` records
`trust-assumption:synthetic-authority-input` and a typed
`reason:synthetic-authority-input` reason ref so callers can distinguish it
from strict artifact-bundle replay.
`PipelineReport` and standalone `ValidationResult` JSON emit typed
`FailureRecord` and `ReasonRef` records. Non-pass validation results require
non-empty typed failure/reason evidence under schema validation. During
artifact-bundle validation, reason refs whose `source_artifact` resolves to the
bundle, manifest, artifact id, certificate id, claim id, bundle id, or event id
are enriched with that source artifact digest before the report is emitted.
`StatusAuthorityView` applies the same requirement at schema level for authority
evidence: top-level and outcome-level `reason_ref_records`, plus nested blocking
record reasons, must carry an `artifact:*` source, a JSON Pointer source path,
and a SHA-family digest. Event-local lifecycle reasons keep their JSON Pointer
field path and are normalized to artifact-bound source identifiers before the
authority view is emitted.
Primary conformance cases fail if a blocking or non-pass reason ref lacks a
single canonical source key: an `artifact:*` source, a JSON Pointer source path,
and a canonical SHA-family digest on the same typed reason record after this
enrichment.
`dfcc conformance run --case-dir` loads `*.json` cases or a single JSON case
file and requires canonical equality by default. `--suite primary` runs only
protocol artifact-bundle fixtures; `--suite legacy` runs the compatibility
suites whose names start with `legacy`. A primary case without
`expected_digest`, or with an `expected_digest` that is not a canonical
SHA-family hex digest (`sha256`, `sha384`, or `sha512`), is a conformance
failure. A primary case must be
`kind: artifact-bundle` and must not disable `full_replay`; synthetic validation
or authority cases must be marked with a `suite` whose name starts with
`legacy`. `kind: artifact-bundle` cases run `full_replay` by default, so they
exercise authority recomputation unless a legacy fixture explicitly opts out.
The bundled golden suite now contains primary artifact-bundle replay fixtures
for canonicalization mismatch, schema invalid, digest mismatch, missing ref,
missing authority artifacts, missing kernel proof, policy block, expired clock,
boundary-unknown clock, conflicting traces, operational accept/reject,
accepted-clause provenance, stale embedded source override, raw-evidence-only
semantics, missing completion proof, missing confluence proof, and manifest
order conflict. Older direct validation/authority cases remain in legacy
suites. The equality key is derived from the `AuthorityOutcome` digest,
blocking records sorted by stable `block_id`, artifact digests sorted
canonically, and reason refs sorted by artifact source, JSON Pointer path, and
reason digest.
For non-pass `PipelineReport` results without an authority view, the canonical
key also includes stage results, unresolved refs, stage artifacts, protocol
record digests, and replay/runtime summary digests, so two failures with the
same final code but different replay evidence do not collapse to one case.
