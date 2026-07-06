"""Status-time authority recomputation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from dfcc.artifacts import ArtifactRole, ReferenceKind, ReferenceLedgerEntry
from dfcc.backend import DFCCBackend, DFCCChecker, EnumeratingBackend, ReferenceChecker
from dfcc.bundle import compile_bundle, parse_bundle
from dfcc.canonical import digest_json
from dfcc.claims import PredicateRegistry, compile_claim, default_predicate_registry
from dfcc.frame import (
    adjudication_views as frame_adjudication_views,
)
from dfcc.frame import (
    admit_prefix,
    completion_interface,
    define_assessment_frame,
    frame_adequacy,
    make_observation_cut,
    operational_completion_fiber,
)
from dfcc.frame import (
    completion_admission as frame_completion_admission,
)
from dfcc.frame import (
    fiber_assoc_view as frame_fiber_assoc_view,
)
from dfcc.guards import guard_pass, guard_record, required_guard_set, required_missing_records
from dfcc.kernel import KernelView, ProofRef, build_residual_context, kernel_verdict
from dfcc.lifecycle import EventOrder, FoldContext, LifecycleEvent, fold_status
from dfcc.models import (
    AdjudicationViews,
    CompletionAdmission,
    FiberAssocView,
    IssueCertificate,
    PrefixView,
    ProposedUse,
    StatusAuthorityView,
    StatusContext,
)
from dfcc.policy import gate_decision
from dfcc.profiles import status_authority_field_policy
from dfcc.records import SetRef
from dfcc.runtime import ResolvedAuthorityRuntime
from dfcc.runtime import _proof_ref_record as _runtime_proof_ref_record
from dfcc.sets import FiniteSet
from dfcc.time import HorizonAnchor, parse_rfc3339, parse_time_basis, status_clock
from dfcc.types import (
    AdequacyDirection,
    AdjudicationCode,
    AssociationStatus,
    AuthorityOutcome,
    BlockingRecord,
    Direction,
    FailureCode,
    GateDecision,
    GuardRecord,
    GuardStatus,
    Layer,
    OperationalCode,
    ReasonRef,
    StatusCode,
    StatusCoordinate,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    VerdictCode,
    blocking_record,
    reason,
    validate_authority_outcome,
    validation_failure,
)
from dfcc.validation import validate_pipeline


@dataclass(frozen=True, slots=True)
class _ObservationRuntime:
    frame: Any
    cut: Any
    record: Mapping[str, Any]
    prefix: PrefixView


@dataclass(frozen=True, slots=True)
class _OperationalObjects:
    completion: CompletionAdmission
    fiber: FiberAssocView
    adjudication: AdjudicationViews
    adequacy: AdequacyDirection
    blocking_set: tuple[BlockingRecord, ...] = ()


def _runtime(
    certificate: IssueCertificate,
    registry: PredicateRegistry | None,
    *,
    artifact_refs: tuple[Any, ...] = (),
    ledger_entries: tuple[ReferenceLedgerEntry, ...] = (),
    resolved_obligations: tuple[Any, ...] = (),
    resolved_reason_refs: tuple[Any, ...] = (),
    accepted_clause_refs: tuple[str, ...] = (),
    compiled_bundle_ref: str | None = None,
    set_ref_records: tuple[SetRef, ...] = (),
    proof_refs: tuple[ProofRef, ...] = (),
    kernel_proof_artifacts: tuple[Any, ...] = (),
    strict_replay: bool = False,
    synthetic_trust: bool = False,
) -> ResolvedAuthorityRuntime:
    registry = registry or default_predicate_registry()
    claim = compile_claim(certificate.claim_source, registry)
    bundle = parse_bundle(certificate.bundle_source)
    compiled = compile_bundle(bundle, claim.horizon)
    anchor = HorizonAnchor.from_json(certificate.anchor_source)
    time_basis = parse_time_basis(certificate.time_basis_source)
    effective_set_ref_records = set_ref_records or tuple(
        SetRef(
            str(record["carrier_ref"]),
            str(record["encoding_kind"]),
            str(record["constraint_ref"]),
            str(record["approximation_kind"]),
            str(record["soundness_ref"]),
            str(record["digest"]),
        )
        for record in certificate.set_ref_records
    )
    return ResolvedAuthorityRuntime(
        claim=claim,
        compiled=compiled,
        anchor=anchor,
        time_basis=time_basis,
        artifact_refs=artifact_refs,
        ledger_entries=ledger_entries,
        resolved_obligations=resolved_obligations,
        resolved_reason_refs=resolved_reason_refs,
        accepted_clause_refs=accepted_clause_refs,
        compiled_bundle_ref=compiled_bundle_ref or certificate.compiled_semantics_ref,
        set_ref_records=effective_set_ref_records,
        proof_refs=proof_refs,
        kernel_proof_artifacts=kernel_proof_artifacts,
        strict_replay=strict_replay,
        synthetic_trust=synthetic_trust,
    )


def _synthetic_trust_obligations(runtime: ResolvedAuthorityRuntime | None) -> tuple[str, ...]:
    if runtime is not None and runtime.synthetic_trust:
        return ("trust-assumption:synthetic-authority-input",)
    return ()


def _synthetic_trust_reasons(runtime: ResolvedAuthorityRuntime | None) -> tuple[ReasonRef, ...]:
    if runtime is None or not runtime.synthetic_trust:
        return ()
    return (
        ReasonRef(
            "reason:synthetic-authority-input",
            FailureCode.CHECKER_UNKNOWN,
            Layer.INTEROP,
            "artifact:synthetic-authority-input",
            "/",
            "legacy direct authority input was normalized as a synthetic artifact bundle",
        ),
    )


def _artifact_bound_id(value: str | None, fallback: str) -> str:
    if value and value.startswith("artifact:"):
        return value
    if value:
        safe = "".join(char if char.isalnum() or char in "._-" else "-" for char in value)
        return f"artifact:{safe}"
    return fallback


def _status_context_artifact_id(runtime: ResolvedAuthorityRuntime | None) -> str:
    if runtime is not None:
        for ref in runtime.artifact_refs:
            if getattr(ref, "semantic_role", None) == ArtifactRole.STATUS_CONTEXT.value:
                return _artifact_bound_id(
                    getattr(ref, "artifact_id", None),
                    "artifact:status-context",
                )
        for ref in runtime.artifact_refs:
            if getattr(ref, "artifact_type", None) == "status-context":
                return _artifact_bound_id(
                    getattr(ref, "artifact_id", None),
                    "artifact:status-context",
                )
    return "artifact:status-context"


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _reason_digest(ref: ReasonRef) -> str:
    return digest_json(
        {
            "reason_id": ref.reason_id,
            "failure_code": ref.failure_code.value,
            "layer": ref.layer.value,
            "source_artifact": ref.source_artifact,
            "source_path": ref.source_path,
            "message": ref.message,
        }
    )


def _authority_reason_ref(
    runtime: ResolvedAuthorityRuntime | None,
    ref: ReasonRef,
) -> ReasonRef:
    source_artifact = ref.source_artifact
    source_path = (
        ref.source_path if ref.source_path.startswith("/") else f"/{ref.source_path or ''}"
    )
    if not source_artifact.startswith("artifact:"):
        source_artifact = _artifact_bound_id(
            source_artifact,
            _status_context_artifact_id(runtime),
        )
    normalized = replace(
        ref,
        source_artifact=source_artifact,
        source_path=source_path,
    )
    if normalized.digest is not None:
        return normalized
    return replace(normalized, digest=_reason_digest(normalized))


def _authority_reason_refs(
    runtime: ResolvedAuthorityRuntime | None,
    reason_refs: tuple[ReasonRef, ...],
) -> tuple[ReasonRef, ...]:
    return tuple(dict.fromkeys(_authority_reason_ref(runtime, ref) for ref in reason_refs))


def _authority_blocking_set(
    runtime: ResolvedAuthorityRuntime | None,
    blocking_set: tuple[BlockingRecord, ...],
) -> tuple[BlockingRecord, ...]:
    return tuple(
        replace(block, reason_refs=_authority_reason_refs(runtime, block.reason_refs))
        for block in blocking_set
    )


def _status_view_reason_refs(
    runtime: ResolvedAuthorityRuntime | None,
    reason_refs: tuple[ReasonRef, ...],
) -> tuple[ReasonRef, ...]:
    return _authority_reason_refs(runtime, (*reason_refs, *_synthetic_trust_reasons(runtime)))


def _status_outcome(
    certificate: IssueCertificate,
    proposed_use: ProposedUse,
    validation: ValidationResult,
    status: StatusCode,
    blocking_set: tuple[BlockingRecord, ...],
    *,
    reason_refs: tuple[ReasonRef, ...] = (),
    status_coordinates: tuple[StatusCoordinate, ...] = (),
    guard_records: tuple[GuardRecord, ...] = (),
    runtime: ResolvedAuthorityRuntime | None = None,
) -> StatusAuthorityView:
    runtime_artifacts = runtime.artifact_refs if runtime is not None else ()
    runtime_obligations = (
        tuple(ref.source_artifact for ref in runtime.resolved_obligations)
        if runtime is not None
        else ()
    )
    runtime_proofs = tuple(ref.proof_id for ref in runtime.proof_refs) if runtime else ()
    runtime_proof_records = (
        tuple(_runtime_proof_ref_record(ref) for ref in runtime.proof_refs)
        if runtime is not None
        else ()
    )
    blocking_set = _authority_blocking_set(runtime, blocking_set)
    reason_refs = _authority_reason_refs(runtime, reason_refs)
    code = status.value if status is not StatusCode.BOUNDARY_UNKNOWN else StatusCode.UNKNOWN.value
    outcome = AuthorityOutcome(
        layer=Layer.STATUS,
        code=code,
        direction=Direction.NONE,
        blocking_set=blocking_set,
        gate_decision=GateDecision.BLOCK if blocking_set else GateDecision.UNKNOWN,
        profile_ref=certificate.schema_profile_ref,
        outcome_schema_ref="status-authority-view",
        reason_refs=reason_refs,
    )
    validate_authority_outcome(outcome)
    return StatusAuthorityView(
        certificate_id=certificate.certificate_id,
        schema_profile_ref=certificate.schema_profile_ref,
        canonicalization_profile_ref=certificate.canonicalization_profile_ref,
        manifest_digest=certificate.manifest_digest,
        validation_result=validation,
        proposed_use=proposed_use,
        status_coordinates=status_coordinates,
        blocking_set=blocking_set,
        dominant_status=status,
        kernel_verdict=None,
        authority_outcome=outcome,
        status_observation_context_ref="status-observation-context",
        prefix_view_ref="not-applicable",
        validity_view_ref="validity-view",
        gate_decision_ref=outcome.gate_decision.value,
        set_refs=certificate.set_refs,
        set_ref_records=runtime.set_ref_records
        if runtime is not None
        else certificate.set_ref_records,
        guard_records=guard_records,
        artifact_refs=runtime_artifacts,
        obligation_refs=tuple(
            dict.fromkeys(
                (
                    *certificate.obligation_refs,
                    *runtime_obligations,
                    *_synthetic_trust_obligations(runtime),
                )
            )
        ),
        reason_refs=_status_view_reason_refs(runtime, reason_refs),
        proof_refs=runtime_proofs,
        proof_ref_records=runtime_proof_records,
        ledger_entries=runtime.ledger_entries if runtime is not None else (),
        stage_blockers=tuple(blocking_set),
    )


def _block_from_guard(record: GuardRecord) -> BlockingRecord:
    ref = record.reason_refs[0]
    return BlockingRecord(
        block_id=ref.reason_id,
        failure_code=ref.failure_code,
        layer=ref.layer,
        severity="error",
        reason_refs=record.reason_refs,
    )


def _guard_blocks(records: tuple[GuardRecord, ...]) -> tuple[BlockingRecord, ...]:
    return tuple(
        _block_from_guard(record) for record in records if record.status is not GuardStatus.PASS
    )


def _set_ref_sound_guard(
    certificate: IssueCertificate,
    runtime: ResolvedAuthorityRuntime,
    checker: DFCCChecker,
) -> GuardRecord:
    if not certificate.set_refs:
        return guard_record(
            "SetRefSound",
            False,
            failure_code=FailureCode.MISSING_REF,
            layer=Layer.INTEROP,
            message="certificate contains no set references",
        )
    if not runtime.set_ref_records:
        return guard_record(
            "SetRefSound",
            True,
            layer=Layer.INTEROP,
            evidence_refs=certificate.set_refs,
        )
    evidence_refs: list[str] = []
    for index, record in enumerate(runtime.set_ref_records):
        result = checker.set_ref(record)
        if not result.passed:
            reason_refs = result.reason_refs or tuple(
                ref for failure in result.failure_records for ref in failure.reason_refs
            )
            checker_message = reason_refs[0].message if reason_refs else "checker did not pass"
            guard_reason = reason(
                result.failure_records[0].code
                if result.failure_records
                else FailureCode.CHECKER_UNKNOWN,
                Layer.INTEROP,
                f"SetRef artifact {index} does not satisfy soundness: {checker_message}",
                source_path=f"/set_ref_records/{index}/soundness_ref",
                digest=record.digest,
            )
            return guard_record(
                "SetRefSound",
                False,
                failure_code=(
                    result.failure_records[0].code
                    if result.failure_records
                    else FailureCode.CHECKER_UNKNOWN
                ),
                layer=Layer.INTEROP,
                message=f"SetRef artifact {index} does not satisfy soundness",
                evidence_refs=tuple(evidence_refs),
                reason_refs=(guard_reason, *reason_refs),
            )
        evidence_refs.append(record.soundness_ref)
    return guard_record(
        "SetRefSound",
        True,
        layer=Layer.INTEROP,
        evidence_refs=tuple(evidence_refs),
    )


def _identity_guards(
    certificate: IssueCertificate,
    proposed_use: ProposedUse,
    claim: Any,
    effective_policy: Mapping[str, Any],
) -> tuple[GuardRecord, ...]:
    claim_ok = proposed_use.claim == claim.claim_id
    horizon_ok = proposed_use.horizon == claim.horizon
    anchor_ok = proposed_use.anchor == certificate.anchor_ref
    scope_ok = set(proposed_use.scope).issubset(set(getattr(claim, "scope", ())))
    frame_ok = proposed_use.frame in {None, certificate.assessment_frame_ref}
    policy_ok = proposed_use.policy in {None, str(effective_policy.get("version", "default"))}
    return (
        guard_record("ProfileResolved", True, layer=Layer.INTEROP),
        guard_record("FieldPresence", True, layer=Layer.INTEROP),
        guard_record(
            "ReferenceResolved",
            claim_ok and horizon_ok and anchor_ok,
            failure_code=FailureCode.OUT_OF_FRAME,
            layer=Layer.STATUS,
            message="proposed use claim, horizon, or anchor does not match certificate identity",
        ),
        guard_record(
            "ContextWellFormed",
            scope_ok and frame_ok,
            failure_code=FailureCode.OUT_OF_FRAME,
            layer=Layer.STATUS,
            message="proposed use scope or frame is outside the certified frame",
        ),
        guard_record(
            "policy_gate",
            policy_ok,
            failure_code=FailureCode.POLICY_BLOCK,
            layer=Layer.POLICY,
            message="proposed use policy identity does not match active policy",
        ),
    )


def _prefix_from_context(
    context: StatusContext,
    *,
    r: int,
    compiled: Any,
) -> tuple[PrefixView | None, tuple[BlockingRecord, ...]]:
    if context.prefix_view is None:
        if r == 0:
            p0 = FiniteSet.from_iterable((state,) for state in compiled.initial_set)
            return PrefixView("pass", 0, p0, p0), ()
        return None, (
            blocking_record(
                FailureCode.PREFIX_UNSOUND,
                Layer.OPERATIONAL,
                "status-time prefix view is required after r=0",
            ),
        )

    source = context.prefix_view
    prefix_r = int(source.get("r", r))
    if prefix_r != r:
        return None, (
            blocking_record(
                FailureCode.PREFIX_UNSOUND,
                Layer.OPERATIONAL,
                "prefix view index does not match status clock",
            ),
        )
    p_star = FiniteSet.from_iterable(tuple(item) for item in source.get("p_star", ()))
    p_out = FiniteSet.from_iterable(tuple(item) for item in source.get("p_out", ()))
    p_in = (
        FiniteSet.from_iterable(tuple(item) for item in source["p_in"])
        if source.get("p_in") is not None
        else None
    )
    status = str(source.get("prefix_status", "unknown"))
    if status != "pass":
        return None, (
            blocking_record(
                FailureCode.PREFIX_UNSOUND,
                Layer.OPERATIONAL,
                f"prefix_status is {status}",
            ),
        )
    if p_star.is_empty() and not p_out.is_empty():
        return None, (
            blocking_record(
                FailureCode.EXACT_PREFIX_EMPTY,
                Layer.OPERATIONAL,
                "exact represented prefix is empty while outer prefix is nonempty",
            ),
        )
    return PrefixView(status, r, p_star, p_out, p_in), ()


def _observation_runtime(
    context: StatusContext,
    certificate: IssueCertificate,
    proposed_use: ProposedUse,
    effective_policy: Mapping[str, Any],
    runtime: ResolvedAuthorityRuntime,
    *,
    r: int,
    checker: DFCCChecker,
) -> tuple[_ObservationRuntime | None, tuple[BlockingRecord, ...]]:
    if not context.observation_records:
        return None, ()
    frame_source = {
        "frame_id": certificate.assessment_frame_ref,
        **certificate.frame,
        **context.frame,
    }
    frame = define_assessment_frame(frame_source, effective_policy)
    cut = make_observation_cut(
        context.observation_records,
        context.status_time,
        certificate.time_basis_ref,
        certificate.event_order_commitment_ref,
        context.dependency_snapshot,
        frame,
        effective_policy,
    )
    check = checker.observation_cut(
        cut.records,
        cut.status_time,
        cut.time_basis_ref,
        cut.event_order_ref,
        cut.dependency_snapshot,
        frame_source,
    )
    if not check.passed:
        return None, tuple(
            BlockingRecord(
                block_id=ref.reason_id,
                failure_code=ref.failure_code,
                layer=ref.layer,
                severity="error",
                reason_refs=(ref,),
            )
            for ref in check.reason_refs
        )
    strict_blocks = _strict_observation_blocks(runtime, cut.records)
    if strict_blocks:
        return None, strict_blocks
    prefix_policy = {"r": r, **context.observation_policy}
    prefix = admit_prefix(cut, {}, {}, prefix_policy)
    if prefix.prefix_status != "pass":
        return None, tuple(
            BlockingRecord(
                block_id=ref.reason_id,
                failure_code=ref.failure_code,
                layer=ref.layer,
                severity="error",
                reason_refs=(ref,),
            )
            for ref in prefix.reason_refs
        )
    record = next(
        (item for item in cut.records if int(item.get("r", r)) == r),
        cut.records[0],
    )
    del proposed_use
    return _ObservationRuntime(frame=frame, cut=cut, record=record, prefix=prefix), ()


def _ledger_ref_resolved(
    runtime: ResolvedAuthorityRuntime,
    ref_value: Any,
    *,
    kind: ReferenceKind | None = None,
) -> bool:
    if isinstance(ref_value, Mapping):
        ref_value = ref_value.get("artifact_ref")
    if not isinstance(ref_value, str) or not ref_value:
        return False
    artifact_id, _, pointer = ref_value.partition("#")
    for entry in runtime.ledger_entries:
        if kind is not None and entry.kind is not kind:
            continue
        if not entry.resolved:
            continue
        if entry.ref_value == ref_value:
            return True
        if entry.target_artifact_id == artifact_id and (
            not pointer or entry.target_path == pointer
        ):
            return True
    return False


def _strict_missing_ref_block(label: str, ref_value: Any) -> BlockingRecord:
    suffix = f": {ref_value}" if ref_value else ""
    return blocking_record(
        FailureCode.CHECKER_UNKNOWN,
        Layer.OPERATIONAL,
        f"strict authority replay lacks resolved {label} evidence{suffix}",
        source_artifact="authority-runtime",
        source_path="/ledger_entries",
    )


def _strict_observation_blocks(
    runtime: ResolvedAuthorityRuntime,
    records: tuple[Mapping[str, Any], ...],
) -> tuple[BlockingRecord, ...]:
    if not runtime.strict_replay:
        return ()
    blocks: list[BlockingRecord] = []
    required_fields = (
        ("measurement relation", "measurement_relation_ref", ReferenceKind.ARTIFACT),
        ("representation relation", "representation_relation_ref", ReferenceKind.ARTIFACT),
        ("calibration", "calibration_ref", None),
        ("latency", "latency_ref", None),
        ("dependency", "dependency_ref", None),
        ("event-order", "event_order_ref", None),
        ("representation", "representation_proof_ref", ReferenceKind.PROOF),
    )
    for record in records:
        for label, field_name, kind in required_fields:
            ref_value = record.get(field_name)
            if not _ledger_ref_resolved(runtime, ref_value, kind=kind):
                blocks.append(_strict_missing_ref_block(label, ref_value))
    return tuple(blocks)


def _strict_kernel_proof_blocks(runtime: ResolvedAuthorityRuntime) -> tuple[BlockingRecord, ...]:
    if not runtime.strict_replay:
        return ()
    if any(
        ref.artifact_ref is not None
        and str(ref.artifact_ref).startswith("artifact:")
        and ref.status in {"pass", "accepted"}
        for ref in runtime.proof_refs
    ):
        return ()
    return (
        blocking_record(
            FailureCode.CHECKER_UNKNOWN,
            Layer.REPRESENTED,
            "strict authority replay requires a resolved KernelProofArtifact",
            source_artifact="authority-runtime",
            source_path="/proof_refs",
        ),
    )


def _strict_kernel_proof_consistency_blocks(
    runtime: ResolvedAuthorityRuntime, kernel: KernelView
) -> tuple[BlockingRecord, ...]:
    if not runtime.strict_replay or not runtime.kernel_proof_artifacts:
        return ()
    blocks: list[BlockingRecord] = []
    for artifact in runtime.kernel_proof_artifacts:
        proof = artifact.proof
        required = (
            ("expected_verdict", proof.expected_verdict, kernel.verdict.value),
            ("feasibility", proof.feasibility, kernel.feasibility),
            ("inclusion", proof.inclusion, kernel.inclusion),
            ("disjointness", proof.disjointness, kernel.disjointness),
        )
        for field_name, proof_value, actual_value in required:
            if proof_value is None:
                blocks.append(
                    blocking_record(
                        FailureCode.CHECKER_UNKNOWN,
                        Layer.REPRESENTED,
                        f"kernel proof artifact lacks {field_name}",
                        source_artifact=artifact.artifact_id,
                        source_path=f"/proof/{field_name}",
                    )
                )
            elif str(proof_value) != str(actual_value):
                blocks.append(
                    blocking_record(
                        FailureCode.ARTIFACT_CONFLICT,
                        Layer.REPRESENTED,
                        f"kernel proof {field_name} conflicts with computed kernel view",
                        source_artifact=artifact.artifact_id,
                        source_path=f"/proof/{field_name}",
                    )
                )
        backend_identity = kernel.proof.backend_identity if kernel.proof is not None else None
        if backend_identity and proof.backend_identity != backend_identity:
            blocks.append(
                blocking_record(
                    FailureCode.ARTIFACT_CONFLICT,
                    Layer.REPRESENTED,
                    "kernel proof backend identity conflicts with computed backend proof",
                    source_artifact=artifact.artifact_id,
                    source_path="/proof/backend_identity",
                )
            )
        feasible = str(proof.feasibility or kernel.feasibility) == "feasible"
        if feasible and not tuple(
            dict.fromkeys((*artifact.witness_provenance_refs, *proof.witness_refs))
        ):
            blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.REPRESENTED,
                    "kernel proof artifact lacks witness provenance refs",
                    source_artifact=artifact.artifact_id,
                    source_path="/witness_provenance_refs",
                )
            )
        needs_inclusion = (
            proof.expected_verdict == VerdictCode.ASSERT.value
            or proof.inclusion == "yes"
            or kernel.inclusion == "yes"
        )
        if needs_inclusion and proof.inclusion_ref is None:
            blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.REPRESENTED,
                    "kernel proof artifact lacks inclusion proof ref",
                    source_artifact=artifact.artifact_id,
                    source_path="/proof/inclusion_ref",
                )
            )
        needs_disjointness = (
            proof.expected_verdict == VerdictCode.DENY.value
            or proof.disjointness == "yes"
            or kernel.disjointness == "yes"
        )
        if needs_disjointness and proof.disjointness_ref is None:
            blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.REPRESENTED,
                    "kernel proof artifact lacks disjointness proof ref",
                    source_artifact=artifact.artifact_id,
                    source_path="/proof/disjointness_ref",
                )
            )
        needs_infeasibility = (
            proof.expected_verdict == VerdictCode.INFEASIBLE.value
            or proof.feasibility == "infeasible"
            or kernel.feasibility == "infeasible"
        )
        if needs_infeasibility and proof.infeasibility_ref is None:
            blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.REPRESENTED,
                    "kernel proof artifact lacks infeasibility proof ref",
                    source_artifact=artifact.artifact_id,
                    source_path="/proof/infeasibility_ref",
                )
            )
    return tuple(blocks)


def _strict_operational_blocks(
    runtime: ResolvedAuthorityRuntime,
    observation_record: Mapping[str, Any],
    completion: CompletionAdmission,
    frame_source: Mapping[str, Any],
) -> tuple[BlockingRecord, ...]:
    if not runtime.strict_replay:
        return ()
    checks: list[tuple[str, Any, ReferenceKind | None]] = [
        ("completion transcript", completion.checker_transcript_ref, ReferenceKind.TRANSCRIPT),
        ("completion outer set", completion.c_out_ref, ReferenceKind.SET),
        (
            "prefix adjudication",
            observation_record.get("prefix_adjudication_proof_ref"),
            ReferenceKind.PROOF,
        ),
        (
            "target adjudication",
            observation_record.get("target_adjudication_proof_ref"),
            ReferenceKind.PROOF,
        ),
        (
            "adequacy",
            dict(frame_source.get("policy", {})).get("adequacy_proof_ref")
            or observation_record.get("adequacy_proof_ref"),
            ReferenceKind.PROOF,
        ),
    ]
    return tuple(
        _strict_missing_ref_block(label, ref_value)
        for label, ref_value, kind in checks
        if not _ledger_ref_resolved(runtime, ref_value, kind=kind)
    )


def _derive_operational_objects(
    observation: _ObservationRuntime | None,
    context: StatusContext,
    certificate: IssueCertificate,
    proposed_use: ProposedUse,
    runtime: ResolvedAuthorityRuntime,
    residual: Any,
    effective_policy: Mapping[str, Any],
    *,
    r: int,
    registry: PredicateRegistry,
) -> _OperationalObjects | None:
    if observation is None:
        return None
    completion_policy = {
        "completion_status": "unknown",
        "status_time": context.status_time,
        **context.completion_policy,
    }
    if context.completion_admission is not None:
        completion_policy.update(context.completion_admission)
    completion = frame_completion_admission(
        observation.prefix,
        completion_interface(observation.frame, r, runtime.claim.horizon),
        completion_policy,
    )
    frame_source = {
        "frame_id": certificate.assessment_frame_ref,
        **certificate.frame,
        **context.frame,
    }
    strict_blocks = _strict_operational_blocks(
        runtime,
        observation.record,
        completion,
        frame_source,
    )
    local_blocks = list(strict_blocks)
    completion_fiber = operational_completion_fiber(
        observation.record,
        observation.frame,
        residual,
    )
    if (
        runtime.strict_replay
        and completion.c_out_ref is not None
        and observation.record.get("_operational_completions_source") != completion.c_out_ref
    ):
        local_blocks.append(
            blocking_record(
                FailureCode.CHECKER_UNKNOWN,
                Layer.OPERATIONAL,
                "strict authority replay requires completion set artifact members",
                source_artifact="authority-runtime",
                source_path="/completion_policy/c_out_ref",
            )
        )
    if completion_fiber.status != "pass" or completion_fiber.completions.is_empty():
        fiber_reasons = completion_fiber.reason_refs
        if fiber_reasons:
            local_blocks.extend(
                BlockingRecord(
                    block_id=ref.reason_id,
                    failure_code=ref.failure_code,
                    layer=ref.layer,
                    severity="error",
                    reason_refs=(ref,),
                )
                for ref in fiber_reasons
            )
        else:
            local_blocks.append(
                blocking_record(
                    FailureCode.COMPLETION_MISSING,
                    Layer.OPERATIONAL,
                    "operational completion fiber is empty",
                    source_artifact="authority-runtime",
                    source_path="/completion_policy/c_out_ref",
                )
            )
    fiber = frame_fiber_assoc_view(
        observation.record,
        runtime.claim,
        runtime.compiled,
        residual,
        observation.frame,
        registry=registry,
    )
    proposed_source = {
        "mode": proposed_use.mode,
        "scope": list(proposed_use.scope),
        "consumer": proposed_use.consumer,
        "policy": proposed_use.policy,
        "frame": proposed_use.frame,
        "context": proposed_use.context,
    }
    target_condition = context.target_condition or certificate.frame.get("target_condition", {})
    adjudication = frame_adjudication_views(
        observation.record,
        proposed_source,
        target_condition,
        observation.frame,
        effective_policy,
    )
    proof_adequacy = observation.record.get("adequacy_direction")
    adequacy = (
        AdequacyDirection(str(proof_adequacy))
        if proof_adequacy is not None
        else frame_adequacy(runtime.claim, target_condition, observation.frame)
    )
    return _OperationalObjects(completion, fiber, adjudication, adequacy, tuple(local_blocks))


def _completion(source: Mapping[str, Any] | None) -> CompletionAdmission:
    if source is None:
        return CompletionAdmission(completion_status="unknown")
    return CompletionAdmission(
        tag=str(source.get("tag", "CompletionAdmission")),
        completion_status=str(source.get("completion_status", "unknown")),
        c_out_ref=source.get("c_out_ref"),
        c_in_ref=source.get("c_in_ref"),
        admission_source=source.get("admission_source"),
        expiry=source.get("expiry"),
        uncertainty_model=source.get("uncertainty_model"),
        reference_digest=source.get("reference_digest"),
        checker_result=source.get("checker_result"),
        checker_transcript_ref=source.get("checker_transcript_ref"),
        completion_obligations=tuple(
            str(item) for item in source.get("completion_obligations", ())
        ),
    )


def _fiber(source: Mapping[str, Any] | None) -> FiberAssocView:
    if source is None:
        return FiberAssocView(AssociationStatus.UNKNOWN)
    return FiberAssocView(
        fiber_status=AssociationStatus(str(source.get("fiber_status", "unknown"))),
        f_out_ref=source.get("f_out_ref"),
        f_in_ref=source.get("f_in_ref"),
        fiber_obligations=tuple(str(item) for item in source.get("fiber_obligations", ())),
    )


def _adjudication(source: Mapping[str, str]) -> AdjudicationViews:
    return AdjudicationViews(
        prefix=AdjudicationCode(str(source.get("prefix", "indeterminate"))),
        usage=AdjudicationCode(str(source.get("usage", "indeterminate"))),
        target=AdjudicationCode(str(source.get("target", "indeterminate"))),
    )


def _represented_outcome(
    kernel: KernelView,
    gate: GateDecision,
    blocks: tuple[BlockingRecord, ...],
    certificate: IssueCertificate,
    status_time: str,
) -> AuthorityOutcome:
    local_blocks = list(blocks)
    if gate is GateDecision.BLOCK:
        outcome = AuthorityOutcome(
            layer=Layer.POLICY,
            code=GateDecision.BLOCK.value,
            direction=Direction.NONE,
            blocking_set=tuple(local_blocks),
            gate_decision=gate,
            profile_ref=certificate.schema_profile_ref,
            outcome_schema_ref="status-authority-view",
            issued_at_status_time=status_time,
            reason_refs=tuple(ref for block in local_blocks for ref in block.reason_refs),
        )
    else:
        decisive_codes = {"assert", "deny", "infeasible"}
        if kernel.verdict.value not in decisive_codes and not local_blocks:
            local_blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.REPRESENTED,
                    "represented kernel verdict is not decisive",
                    source_artifact=certificate.certificate_id,
                    source_path="/kernel_verdict",
                )
            )
        reason_refs = tuple(
            dict.fromkeys(
                (*kernel.reason_refs, *(ref for block in local_blocks for ref in block.reason_refs))
            )
        )
        if kernel.verdict.value in {"deny", "infeasible"} and not reason_refs:
            reason_refs = (
                reason(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.REPRESENTED,
                    f"represented {kernel.verdict.value} authority is negative decisive",
                    source_artifact=certificate.certificate_id,
                    source_path="/kernel_verdict",
                ),
            )
        outcome = AuthorityOutcome(
            layer=Layer.REPRESENTED,
            code=kernel.verdict.value,
            direction=kernel.direction,
            blocking_set=tuple(local_blocks),
            gate_decision=GateDecision.BLOCK if local_blocks else gate,
            profile_ref=certificate.schema_profile_ref,
            outcome_schema_ref="status-authority-view",
            issued_at_status_time=status_time,
            reason_refs=reason_refs,
        )
    validate_authority_outcome(outcome)
    return outcome


def _operational_outcome(
    kernel: KernelView,
    context: StatusContext,
    certificate: IssueCertificate,
    status_time: str,
    gate: GateDecision,
    blocks: tuple[BlockingRecord, ...],
    derived: _OperationalObjects | None = None,
) -> AuthorityOutcome:
    local_blocks = list(blocks)
    if derived is not None:
        local_blocks.extend(derived.blocking_set)
    completion = (
        derived.completion if derived is not None else _completion(context.completion_admission)
    )
    if not completion.passed:
        local_blocks.append(
            blocking_record(
                FailureCode.COMPLETION_MISSING,
                Layer.OPERATIONAL,
                "completion admission is missing or not pass",
            )
        )
    if derived is None:
        local_blocks.append(
            blocking_record(
                FailureCode.CHECKER_UNKNOWN,
                Layer.OPERATIONAL,
                "operational authority requires accepted observation replay evidence",
            )
        )
    fiber = derived.fiber if derived is not None else _fiber(context.fiber_assoc_view)
    adjudication = (
        derived.adjudication if derived is not None else _adjudication(context.adjudication_views)
    )
    adequacy = (
        derived.adequacy if derived is not None else AdequacyDirection(context.adequacy_direction)
    )
    if fiber.fiber_status in {AssociationStatus.UNKNOWN, AssociationStatus.UNDETERMINED}:
        local_blocks.append(
            blocking_record(
                FailureCode.CHECKER_UNKNOWN,
                Layer.OPERATIONAL,
                "fiber association has not been checked",
            )
        )
    if AdjudicationCode.INDETERMINATE in {
        adjudication.prefix,
        adjudication.usage,
        adjudication.target,
    }:
        local_blocks.append(
            blocking_record(
                FailureCode.CHECKER_UNKNOWN,
                Layer.OPERATIONAL,
                "operational adjudication is indeterminate",
            )
        )
    if adequacy is AdequacyDirection.UNKNOWN:
        local_blocks.append(
            blocking_record(
                FailureCode.CHECKER_UNKNOWN,
                Layer.OPERATIONAL,
                "frame adequacy is unknown",
            )
        )

    code = OperationalCode.UNKNOWN.value
    direction = Direction.NONE
    if gate is GateDecision.BLOCK:
        code = OperationalCode.UNKNOWN.value
    elif (
        kernel.verdict is VerdictCode.ASSERT
        and completion.passed
        and fiber.fiber_status is AssociationStatus.POSITIVE
        and adjudication.prefix is AdjudicationCode.ACCEPT
        and adjudication.usage is AdjudicationCode.ACCEPT
        and adjudication.target is AdjudicationCode.ACCEPT
        and adequacy is AdequacyDirection.POSITIVE
        and not local_blocks
    ):
        code = OperationalCode.ACCEPT.value
        direction = Direction.POSITIVE
    elif (
        kernel.verdict is VerdictCode.DENY
        and completion.passed
        and fiber.fiber_status is AssociationStatus.NEGATIVE
        and adjudication.prefix is AdjudicationCode.ACCEPT
        and adjudication.usage is AdjudicationCode.ACCEPT
        and adjudication.target is AdjudicationCode.REJECT
        and adequacy is AdequacyDirection.NEGATIVE
        and not local_blocks
    ):
        code = OperationalCode.REJECT.value
        direction = Direction.NEGATIVE
    elif fiber.fiber_status is AssociationStatus.MIXED:
        local_blocks.append(
            blocking_record(
                FailureCode.ASSOC_MIXED, Layer.OPERATIONAL, "fiber association is mixed"
            )
        )
        code = OperationalCode.INDETERMINATE.value
        direction = Direction.NEUTRAL
    elif fiber.fiber_status is AssociationStatus.EMPTY:
        local_blocks.append(
            blocking_record(
                FailureCode.ASSOC_EMPTY, Layer.OPERATIONAL, "fiber association is empty"
            )
        )
    elif code == OperationalCode.UNKNOWN.value and not local_blocks:
        local_blocks.append(
            blocking_record(
                FailureCode.ARTIFACT_CONFLICT,
                Layer.OPERATIONAL,
                "kernel, fiber, adjudication, adequacy, and policy directions are inconsistent",
                source_artifact=certificate.certificate_id,
                source_path="/agreement",
            )
        )

    all_reason_refs = tuple(ref for block in local_blocks for ref in block.reason_refs)
    if code == OperationalCode.REJECT.value and not all_reason_refs:
        all_reason_refs = (
            reason(
                FailureCode.CHECKER_UNKNOWN,
                Layer.OPERATIONAL,
                "operational reject authority is licensed by negative agreement",
                source_artifact=certificate.certificate_id,
                source_path="/agreement",
            ),
        )
    outcome = AuthorityOutcome(
        layer=Layer.OPERATIONAL,
        code=code,
        direction=direction,
        blocking_set=tuple(local_blocks),
        gate_decision=GateDecision.BLOCK if local_blocks else gate,
        profile_ref=certificate.schema_profile_ref,
        outcome_schema_ref="status-authority-view",
        issued_at_status_time=status_time,
        reason_refs=all_reason_refs,
    )
    validate_authority_outcome(outcome)
    return outcome


def _check_authority_core(
    certificate: IssueCertificate | Mapping[str, Any],
    proposed_use: ProposedUse | Mapping[str, Any],
    status_context: StatusContext | Mapping[str, Any],
    *,
    policy: Mapping[str, Any] | None = None,
    backend: DFCCBackend | None = None,
    checker: DFCCChecker | None = None,
    registry: PredicateRegistry | None = None,
    resolved_runtime: ResolvedAuthorityRuntime | None = None,
) -> StatusAuthorityView | ValidationResult:
    """Recompute status-time authority from an immutable issue certificate."""

    certificate = (
        certificate
        if isinstance(certificate, IssueCertificate)
        else IssueCertificate.from_json(certificate)
    )
    proposed_use = (
        proposed_use
        if isinstance(proposed_use, ProposedUse)
        else ProposedUse.from_json(proposed_use)
    )
    status_context = (
        status_context
        if isinstance(status_context, StatusContext)
        else StatusContext.from_json(status_context)
    )
    registry = registry or default_predicate_registry()
    backend = backend or EnumeratingBackend(registry)
    checker = checker or ReferenceChecker()
    effective_policy = {**certificate.policy, **dict(policy or {})}

    validation = validate_pipeline(
        certificate.minimum_profile(), schema_name="issue-certificate.schema.json"
    )
    if not validation.passed:
        return validation
    runtime = resolved_runtime or _runtime(
        certificate,
        registry,
        synthetic_trust=True,
    )
    guard_records: list[GuardRecord] = list(
        _identity_guards(certificate, proposed_use, runtime.claim, effective_policy)
    )
    identity_blocks = _guard_blocks(tuple(guard_records))
    if identity_blocks:
        reason_refs = tuple(ref for block in identity_blocks for ref in block.reason_refs)
        return _status_outcome(
            certificate,
            proposed_use,
            validation,
            StatusCode.OUT_OF_FRAME,
            identity_blocks,
            reason_refs=reason_refs,
            guard_records=tuple(guard_records),
            runtime=runtime,
        )

    events = tuple(LifecycleEvent.from_json(item) for item in status_context.event_log)
    fold = fold_status(
        certificate.certificate_id,
        events,
        EventOrder(confluence_proof=status_context.confluence_proof),
        FoldContext(
            policy_version=str(effective_policy.get("version", "default")),
            dependency_snapshot=status_context.dependency_snapshot,
            confluence_proof=status_context.confluence_proof,
        ),
    )
    if fold.dominant_status is not StatusCode.ACTIVE:
        guard_records.append(
            guard_record(
                "status_active",
                False,
                failure_code=FailureCode.TRACE_CONFLICT
                if fold.dominant_status is StatusCode.CONFLICT
                else FailureCode.VALIDITY_UNKNOWN,
                layer=Layer.STATUS,
                message=f"folded lifecycle status is {fold.dominant_status.value}",
            )
        )
        return _status_outcome(
            certificate,
            proposed_use,
            validation,
            fold.dominant_status,
            fold.blocking_set,
            reason_refs=tuple(ref for block in fold.blocking_set for ref in block.reason_refs),
            status_coordinates=fold.coordinates,
            guard_records=tuple(guard_records),
            runtime=runtime,
        )
    guard_records.append(guard_record("status_active", True, layer=Layer.STATUS))

    clock = status_clock(
        parse_rfc3339(status_context.status_time), runtime.time_basis, runtime.anchor
    )
    if clock.status is StatusCode.EXPIRED:
        block = blocking_record(
            FailureCode.EXPIRED,
            Layer.STATUS,
            "status time is after horizon end",
            source_artifact=certificate.certificate_id,
            source_path="/status_context/status_time",
        )
        guard_records.append(
            guard_record(
                "clock_inside",
                False,
                failure_code=FailureCode.EXPIRED,
                layer=Layer.STATUS,
                message="status time is after horizon end",
                reason_refs=block.reason_refs,
            )
        )
        return _status_outcome(
            certificate,
            proposed_use,
            validation,
            StatusCode.EXPIRED,
            (block,),
            reason_refs=block.reason_refs,
            status_coordinates=fold.coordinates,
            guard_records=tuple(guard_records),
            runtime=runtime,
        )
    if clock.status in {StatusCode.NOT_EFFECTIVE, StatusCode.BOUNDARY_UNKNOWN}:
        block = blocking_record(
            FailureCode.CLOCK_BOUNDARY_UNKNOWN,
            Layer.STATUS,
            f"status clock is {clock.status.value}",
            source_artifact=certificate.certificate_id,
            source_path="/status_context/status_time",
        )
        guard_records.append(
            guard_record(
                "clock_inside",
                False,
                failure_code=FailureCode.CLOCK_BOUNDARY_UNKNOWN,
                layer=Layer.STATUS,
                message=f"status clock is {clock.status.value}",
                reason_refs=block.reason_refs,
            )
        )
        return _status_outcome(
            certificate,
            proposed_use,
            validation,
            StatusCode.UNKNOWN,
            (block,),
            reason_refs=block.reason_refs,
            status_coordinates=fold.coordinates,
            guard_records=tuple(guard_records),
            runtime=runtime,
        )
    assert clock.index is not None
    guard_records.append(guard_record("clock_inside", True, layer=Layer.STATUS))

    observation_runtime, observation_blocks = _observation_runtime(
        status_context,
        certificate,
        proposed_use,
        effective_policy,
        runtime,
        r=clock.index,
        checker=checker,
    )
    if observation_blocks:
        prefix = None
        prefix_blocks = observation_blocks
    elif observation_runtime is not None:
        prefix = observation_runtime.prefix
        prefix_blocks = ()
    else:
        prefix, prefix_blocks = _prefix_from_context(
            status_context, r=clock.index, compiled=runtime.compiled
        )
    if prefix is None:
        guard_records.append(
            guard_record(
                "ExactPrefixEnclosure",
                False,
                failure_code=FailureCode.PREFIX_UNSOUND,
                layer=Layer.OPERATIONAL,
                message="prefix admission did not provide an exact enclosure",
                reason_refs=tuple(ref for block in prefix_blocks for ref in block.reason_refs),
            )
        )
        reason_refs = tuple(ref for block in prefix_blocks for ref in block.reason_refs)
        return _status_outcome(
            certificate,
            proposed_use,
            validation,
            StatusCode.UNKNOWN,
            prefix_blocks,
            reason_refs=reason_refs,
            status_coordinates=fold.coordinates,
            guard_records=tuple(guard_records),
            runtime=runtime,
        )
    guard_records.append(guard_record("ExactPrefixEnclosure", True, layer=Layer.OPERATIONAL))

    if status_context.validity_status == "conflict":
        block = blocking_record(
            FailureCode.VALIDITY_CONFLICT, Layer.STATUS, "validity view is conflict"
        )
        guard_records.append(
            guard_record(
                "validity_pass",
                False,
                failure_code=FailureCode.VALIDITY_CONFLICT,
                layer=Layer.STATUS,
                message="validity view is conflict",
                reason_refs=block.reason_refs,
            )
        )
        return _status_outcome(
            certificate,
            proposed_use,
            validation,
            StatusCode.CONFLICT,
            (block,),
            reason_refs=block.reason_refs,
            status_coordinates=fold.coordinates,
            guard_records=tuple(guard_records),
            runtime=runtime,
        )
    if status_context.validity_status != "pass":
        block = blocking_record(
            FailureCode.VALIDITY_UNKNOWN, Layer.STATUS, "validity view is not pass"
        )
        guard_records.append(
            guard_record(
                "validity_pass",
                False,
                failure_code=FailureCode.VALIDITY_UNKNOWN,
                layer=Layer.STATUS,
                message="validity view is not pass",
                reason_refs=block.reason_refs,
            )
        )
        return _status_outcome(
            certificate,
            proposed_use,
            validation,
            StatusCode.UNKNOWN,
            (block,),
            reason_refs=block.reason_refs,
            status_coordinates=fold.coordinates,
            guard_records=tuple(guard_records),
            runtime=runtime,
        )
    guard_records.append(guard_record("validity_pass", True, layer=Layer.STATUS))
    guard_records.append(
        guard_record(
            "ArtifactConsistent",
            bool(certificate.artifact_refs),
            failure_code=FailureCode.ARTIFACT_CONFLICT,
            layer=Layer.INTEROP,
            message="certificate contains no artifact references",
        )
    )
    set_ref_guard = _set_ref_sound_guard(certificate, runtime, checker)
    guard_records.append(set_ref_guard)
    if set_ref_guard.status is not GuardStatus.PASS:
        block = _block_from_guard(set_ref_guard)
        return _status_outcome(
            certificate,
            proposed_use,
            validation,
            StatusCode.UNKNOWN,
            (block,),
            reason_refs=block.reason_refs,
            status_coordinates=fold.coordinates,
            guard_records=tuple(guard_records),
            runtime=runtime,
        )

    residual = build_residual_context(
        runtime.compiled,
        r=clock.index,
        p_star=prefix.p_star,
        p_out=prefix.p_out,
        p_in=prefix.p_in,
    )
    kernel = kernel_verdict(
        runtime.claim, runtime.compiled, residual, backend, checker, registry=registry
    )
    runtime_proof_refs = tuple(dict.fromkeys((*runtime.proof_refs, *kernel.proof_refs)))
    kernel_proof_blocks = (
        *_strict_kernel_proof_blocks(runtime),
        *_strict_kernel_proof_consistency_blocks(runtime, kernel),
    )
    if kernel_proof_blocks:
        kernel = replace(
            kernel,
            verdict=VerdictCode.UNKNOWN,
            direction=Direction.NONE,
            reason_refs=tuple(
                dict.fromkeys(
                    (
                        *kernel.reason_refs,
                        *(ref for block in kernel_proof_blocks for ref in block.reason_refs),
                    )
                )
            ),
        )
    guard_records.append(
        guard_record(
            "checker_obligations",
            kernel.verdict not in {VerdictCode.UNKNOWN, VerdictCode.CONFLICT}
            and not kernel_proof_blocks,
            failure_code=FailureCode.CHECKER_UNKNOWN,
            layer=Layer.REPRESENTED,
            message=f"kernel checker returned {kernel.verdict.value}",
            evidence_refs=kernel.evidence_refs,
            reason_refs=kernel.reason_refs,
        )
    )
    gate, policy_blocks = gate_decision(
        effective_policy,
        soundness_grade=certificate.soundness_grade,
        blocking_set=fold.blocking_set,
        proposed_mode=proposed_use.mode,
    )

    operational_mode = proposed_use.mode in {
        "operational",
        "frame-relative assessment",
        "control_gating",
    }
    if operational_mode:
        derived_operational = _derive_operational_objects(
            observation_runtime,
            status_context,
            certificate,
            proposed_use,
            runtime,
            residual,
            effective_policy,
            r=clock.index,
            registry=registry,
        )
        outcome = _operational_outcome(
            kernel,
            status_context,
            certificate,
            status_context.status_time,
            gate,
            (*policy_blocks, *kernel_proof_blocks),
            derived_operational,
        )
        completion = (
            derived_operational.completion
            if derived_operational is not None
            else _completion(status_context.completion_admission)
        )
        fiber = (
            derived_operational.fiber
            if derived_operational is not None
            else _fiber(status_context.fiber_assoc_view)
        )
        adjudication = (
            derived_operational.adjudication
            if derived_operational is not None
            else _adjudication(status_context.adjudication_views)
        )
        adequacy = (
            derived_operational.adequacy
            if derived_operational is not None
            else AdequacyDirection(status_context.adequacy_direction)
        )
        guard_records.extend(
            (
                guard_record(
                    "completion_admission",
                    completion.passed,
                    failure_code=FailureCode.COMPLETION_MISSING,
                    layer=Layer.OPERATIONAL,
                    message="completion admission is missing or not pass",
                    reason_refs=completion.reason_refs,
                ),
                guard_record(
                    "fiber_association",
                    fiber.fiber_status in {AssociationStatus.POSITIVE, AssociationStatus.NEGATIVE},
                    failure_code=FailureCode.CHECKER_UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    message=f"fiber association is {fiber.fiber_status.value}",
                    reason_refs=fiber.reason_refs,
                ),
                guard_record(
                    "prefix_adjudication",
                    adjudication.prefix is AdjudicationCode.ACCEPT,
                    failure_code=FailureCode.OUT_OF_FRAME,
                    layer=Layer.OPERATIONAL,
                    message=f"prefix adjudication is {adjudication.prefix.value}",
                ),
                guard_record(
                    "usage_adjudication",
                    adjudication.usage is AdjudicationCode.ACCEPT,
                    failure_code=FailureCode.OUT_OF_FRAME,
                    layer=Layer.OPERATIONAL,
                    message=f"usage adjudication is {adjudication.usage.value}",
                ),
                guard_record(
                    "target_adjudication",
                    adjudication.target in {AdjudicationCode.ACCEPT, AdjudicationCode.REJECT},
                    failure_code=FailureCode.OUT_OF_FRAME,
                    layer=Layer.OPERATIONAL,
                    message=f"target adjudication is {adjudication.target.value}",
                ),
                guard_record(
                    "adequacy",
                    adequacy in {AdequacyDirection.POSITIVE, AdequacyDirection.NEGATIVE},
                    failure_code=FailureCode.CHECKER_UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    message=f"adequacy is {adequacy.value}",
                ),
                guard_record(
                    "agreement",
                    outcome.code in {OperationalCode.ACCEPT.value, OperationalCode.REJECT.value}
                    and not outcome.blocking_set,
                    failure_code=FailureCode.CHECKER_UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    message="kernel, fiber, adjudication, adequacy, and policy did not agree",
                ),
            )
        )
    else:
        outcome = _represented_outcome(
            kernel,
            gate,
            (*policy_blocks, *kernel_proof_blocks),
            certificate,
            status_context.status_time,
        )

    outcome = replace(
        outcome,
        blocking_set=_authority_blocking_set(runtime, outcome.blocking_set),
        reason_refs=_authority_reason_refs(runtime, outcome.reason_refs),
    )
    reason_refs = _authority_reason_refs(runtime, (*kernel.reason_refs, *outcome.reason_refs))
    view_reason_refs = _status_view_reason_refs(runtime, reason_refs)
    required = required_guard_set(certificate.schema_profile_ref, proposed_use.mode)
    missing_guards = required_missing_records(required, tuple(guard_records))
    if missing_guards:
        guard_records.extend(missing_guards)
    guard_records.append(
        GuardRecord(
            "GuardPass",
            GuardStatus.PASS
            if guard_pass(tuple(guard_records)) and not outcome.blocking_set
            else GuardStatus.FAIL,
            evidence_refs=kernel.evidence_refs,
            reason_refs=reason_refs,
        )
    )
    view = StatusAuthorityView(
        certificate_id=certificate.certificate_id,
        schema_profile_ref=certificate.schema_profile_ref,
        canonicalization_profile_ref=certificate.canonicalization_profile_ref,
        manifest_digest=certificate.manifest_digest,
        validation_result=validation,
        proposed_use=proposed_use,
        status_coordinates=fold.coordinates,
        blocking_set=outcome.blocking_set,
        dominant_status=StatusCode.ACTIVE,
        kernel_verdict=kernel.verdict,
        authority_outcome=outcome,
        guard_records=tuple(guard_records),
        status_observation_context_ref="status-observation-context",
        prefix_view_ref=f"prefix-view:r{clock.index}",
        completion_admission_ref="completion-admission" if operational_mode else None,
        residual_context_ref=f"residual-context:r{clock.index}",
        validity_view_ref="validity-view",
        kernel_view_ref=f"kernel-view:{kernel.verdict.value}" if kernel.verdict else "not-run",
        exact_fiber_assoc_ref="exact-fiber-assoc" if operational_mode else None,
        fiber_assoc_view_ref="fiber-assoc-view" if operational_mode else None,
        adjudication_views_ref="adjudication-views" if operational_mode else None,
        agreement_ref="agreement" if operational_mode else None,
        gate_decision_ref=outcome.gate_decision.value,
        set_refs=certificate.set_refs,
        set_ref_records=runtime.set_ref_records or certificate.set_ref_records,
        artifact_refs=runtime.artifact_refs,
        obligation_refs=tuple(
            dict.fromkeys(
                (
                    *certificate.obligation_refs,
                    *(ref.source_artifact for ref in runtime.resolved_obligations),
                    *_synthetic_trust_obligations(runtime),
                )
            )
        ),
        reason_refs=view_reason_refs,
        proof_refs=tuple(ref.proof_id for ref in runtime_proof_refs),
        proof_ref_records=tuple(_runtime_proof_ref_record(ref) for ref in runtime_proof_refs),
        ledger_entries=runtime.ledger_entries,
        stage_blockers=tuple(outcome.blocking_set),
    )
    field_policy = status_authority_field_policy(proposed_use.mode, outcome.code)
    view_profile = view.minimum_profile()
    field_validation = validate_pipeline(
        view_profile,
        schema_name="status-authority-view.schema.json",
        required_fields=field_policy.required_fields,
    )
    if not field_validation.passed:
        return field_validation
    for field in field_policy.not_applicable_fields:
        if view_profile.get(field) != "not-applicable":
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.SCHEMA_VALIDATE,
                f"field must be not-applicable for this use profile: {field}",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=certificate.certificate_id,
                source_path=f"/{field}",
            )
    return view


def check_authority(
    certificate: IssueCertificate | Mapping[str, Any],
    proposed_use: ProposedUse | Mapping[str, Any],
    status_context: StatusContext | Mapping[str, Any],
    *,
    policy: Mapping[str, Any] | None = None,
    backend: DFCCBackend | None = None,
    checker: DFCCChecker | None = None,
    registry: PredicateRegistry | None = None,
) -> StatusAuthorityView | ValidationResult:
    """Public authority entrypoint.

    All public inputs are normalized to an artifact-bundle replay context. The
    internal core only consumes typed records produced by replay, which prevents
    direct declarations from bypassing reference/profile/admission checks.
    """

    from dfcc.artifacts import ArtifactBundle, artifact_bundle_from_json
    from dfcc.replay import replay_authority_from_bundle, synthetic_authority_bundle

    if isinstance(certificate, ArtifactBundle):
        replay = replay_authority_from_bundle(
            certificate,
            strict_ledger=True,
            policy=policy,
            backend=backend,
            checker=checker,
            registry=registry,
        )
        return (
            replay.authority_view if replay.authority_view is not None else replay.validation_result
        )
    if (
        isinstance(certificate, Mapping)
        and "artifacts" in certificate
        and "manifest" in certificate
    ):
        replay = replay_authority_from_bundle(
            artifact_bundle_from_json(certificate),
            strict_ledger=True,
            policy=policy,
            backend=backend,
            checker=checker,
            registry=registry,
        )
        return (
            replay.authority_view if replay.authority_view is not None else replay.validation_result
        )
    if isinstance(status_context, Mapping) and isinstance(
        status_context.get("artifact_bundle"), Mapping
    ):
        replay = replay_authority_from_bundle(
            artifact_bundle_from_json(status_context["artifact_bundle"]),
            strict_ledger=True,
            policy=policy,
            backend=backend,
            checker=checker,
            registry=registry,
        )
        return (
            replay.authority_view if replay.authority_view is not None else replay.validation_result
        )

    replay = replay_authority_from_bundle(
        synthetic_authority_bundle(certificate, proposed_use, status_context),
        strict_ledger=False,
        policy=policy,
        backend=backend,
        checker=checker,
        registry=registry,
    )
    return replay.authority_view if replay.authority_view is not None else replay.validation_result
