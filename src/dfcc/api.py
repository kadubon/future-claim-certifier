"""Normative DFCC protocol API.

This module exposes the semantic endpoint names listed in the paper. The
finite reference implementation is conservative: when an obligation cannot be
checked, the surrounding authority flow must report unknown or blocked rather
than pass.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dfcc import artifacts as artifact_mod
from dfcc import frame as frame_mod
from dfcc import records as record_mod
from dfcc.admission import admit_evidence, validity_view
from dfcc.artifacts import (
    ArtifactBundle,
    ArtifactStore,
    ReferenceResolutionContext,
    artifact_bundle_from_json,
)
from dfcc.authority import check_authority
from dfcc.backend import ReferenceChecker, ResidualContext
from dfcc.bundle import AssumptionBundle
from dfcc.bundle import compile_bundle as _compile_bundle
from dfcc.certificate import certify_claim_from_artifact_bundle, update_certificate
from dfcc.claims import compile_claim
from dfcc.kernel import (
    KernelProof,
    KernelProofArtifact,
    ProofRef,
    build_residual_context,
    kernel_verdict,
)
from dfcc.lifecycle import EventOrder, LifecycleDecision, fold_status
from dfcc.models import (
    AdjudicationViews,
    Agreement,
    IssueCertificate,
)
from dfcc.policy import gate_decision
from dfcc.profiles import ProfileResolution, resolve_profile
from dfcc.replay import (
    ProtocolRecordArtifact,
    ReplayStageTrace,
    ReplayTrace,
    replay_authority_from_bundle,
)
from dfcc.runtime import ResolvedAuthorityRuntime
from dfcc.sets import FiniteSet
from dfcc.time import TimeBasis, parse_time_basis
from dfcc.types import (
    AdequacyDirection,
    AuthorityOutcome,
    BlockingRecord,
    Direction,
    FailureCode,
    GateDecision,
    Layer,
    OperationalCode,
    ValidationResult,
    blocking_record,
    reason,
    validate_authority_outcome,
)
from dfcc.validation import PipelineReport, validate_artifact_bundle, validate_pipeline

MeasurementRelationArtifact = frame_mod.MeasurementRelationArtifact
RepresentationRelationArtifact = frame_mod.RepresentationRelationArtifact


def validate_artifact_ref(
    artifact_ref: artifact_mod.ArtifactRef,
    schema_profile: Any | None = None,
    policy: Mapping[str, Any] | None = None,
) -> ValidationResult:
    del schema_profile
    return artifact_mod.validate_artifact_ref(artifact_ref, policy=dict(policy or {}))


def manifest_digest(
    artifact: Any,
    schema_profile: Any,
    dependencies: tuple[artifact_mod.ArtifactRef, ...] = (),
) -> str:
    schema_digest = getattr(schema_profile, "schema_digest", None) or "sha256:profile"
    return artifact_mod.manifest_digest(
        artifact,
        artifact_type=type(artifact).__name__,
        schema_profile_digest=str(schema_digest),
        dependencies=dependencies,
    )


def resolve_reference(
    ref: str,
    reference_resolution_context: ReferenceResolutionContext,
    *,
    store: ArtifactStore,
) -> tuple[ValidationResult, Any | None]:
    artifact_id, _, pointer = ref.partition("#")
    return artifact_mod.resolve_reference(
        artifact_id,
        pointer or "",
        store=store,
        context=reference_resolution_context,
    )


def profile_resolution(
    requested_profile: str,
    implemented_profiles: Mapping[str, Any] | None = None,
) -> ProfileResolution:
    return resolve_profile(requested_profile, implemented_profiles)


def resolve_reason_path(
    artifact_ref: artifact_mod.ArtifactRef,
    json_pointer: str,
    *,
    store: ArtifactStore,
) -> ValidationResult:
    context = ReferenceResolutionContext(snapshot_id="reason-path")
    result, _ = artifact_mod.resolve_reference(
        artifact_ref.artifact_id,
        json_pointer,
        store=store,
        context=context,
    )
    return result


def scalar_record(
    value: str | int, unit: str, dimension: str, uncertainty: str | None = None
) -> record_mod.ScalarRecord:
    return record_mod.scalar_record(value, unit, dimension, uncertainty)


def interval_record(
    lower: record_mod.ScalarRecord,
    upper: record_mod.ScalarRecord,
    closure: tuple[bool, bool] = (True, True),
    uncertainty: str | None = None,
    basis: str | None = None,
) -> record_mod.IntervalRecord:
    return record_mod.interval_record(lower, upper, closure, uncertainty, basis)


def timestamp_record(
    lexical_time: str, time_basis: str, policy: str | None = None
) -> record_mod.TimestampRecord:
    return record_mod.timestamp_record(lexical_time, time_basis, policy)


def set_ref(
    carrier: str,
    encoding: str,
    constraint: str,
    approximation: str,
    soundness: str,
) -> record_mod.SetRef:
    return record_mod.set_ref(carrier, encoding, constraint, approximation, soundness)


def define_assessment_frame(
    frame_record: Mapping[str, Any],
    policy: Mapping[str, Any] | None = None,
) -> frame_mod.AssessmentFrame:
    return frame_mod.define_assessment_frame(frame_record, policy)


def define_time_basis(
    clock_record: Mapping[str, Any], timestamp_policy: str | None = None
) -> TimeBasis:
    basis = parse_time_basis(clock_record)
    if timestamp_policy is None:
        return basis
    return TimeBasis(
        clock_id=basis.clock_id,
        time_scale=basis.time_scale,
        uncertainty_seconds=basis.uncertainty_seconds,
        source=basis.source,
        traceability=basis.traceability,
        timestamp_policy=timestamp_policy,
    )


def define_event_order(
    events: tuple[Mapping[str, Any], ...],
    order_policy: Mapping[str, Any] | None = None,
    log_commitments: tuple[str, ...] = (),
) -> EventOrder:
    order_policy = order_policy or {}
    accepted_event_ids = tuple(
        str(item)
        for item in order_policy.get(
            "accepted_event_ids",
            tuple(event["event_id"] for event in events),
        )
    )
    return EventOrder(
        accepted_event_ids=accepted_event_ids,
        confluence_proof=order_policy.get("confluence_proof"),
        conflict_policy=str(order_policy.get("conflict_policy", "conflict-on-disagreement")),
        log_root=log_commitments[0] if log_commitments else order_policy.get("log_root"),
        trace_class=tuple(str(item) for item in order_policy.get("trace_class", ())),
        causal_cut=tuple(str(item) for item in order_policy.get("causal_cut", ())),
    )


def compile_bundle(
    bundle: AssumptionBundle,
    anchor: Mapping[str, Any] | int,
    assessment_frame: Any | None = None,
    policy: Mapping[str, Any] | None = None,
) -> Any:
    del assessment_frame, policy
    horizon = anchor if isinstance(anchor, int) else int(anchor["horizon"])
    return _compile_bundle(bundle, horizon)


def initial_context(
    bundle: AssumptionBundle,
    anchor: Mapping[str, Any] | int,
    frame: Any,
    policy: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    del frame, policy
    horizon = anchor if isinstance(anchor, int) else int(anchor["horizon"])
    compiled = _compile_bundle(bundle, horizon)
    p0 = FiniteSet.from_iterable((state,) for state in compiled.initial_set)
    return {
        "r": 0,
        "p_out": p0,
        "p_in": p0,
        "initial_obligations": compiled.obligations,
        "reason": "finite initial context",
    }


def representation_interface(
    bundle: Mapping[str, Any],
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
    policy: Mapping[str, Any] | None = None,
) -> frame_mod.RepresentationInterface:
    return frame_mod.representation_interface(bundle, frame, policy)


def completion_admission(
    prefix_context: Any,
    completion_interface: Any,
    policy: Mapping[str, Any],
) -> Any:
    return frame_mod.completion_admission(prefix_context, completion_interface, policy)


def make_observation_cut(
    records: tuple[Mapping[str, Any], ...],
    status_time: str,
    time_basis: str,
    event_order: str,
    dependencies: Mapping[str, str],
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
    policy: Mapping[str, Any],
) -> frame_mod.ObservationCut:
    return frame_mod.make_observation_cut(
        records,
        status_time,
        time_basis,
        event_order,
        dependencies,
        frame,
        policy,
    )


def status_observation_context(
    certificate: Any,
    observation_cut: frame_mod.ObservationCut,
    policy: Mapping[str, Any],
) -> frame_mod.StatusObservationContext:
    return frame_mod.status_observation_context(certificate, observation_cut, policy)


def operational_prefix_fiber(
    observation_cut: frame_mod.ObservationCut,
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
    index: int,
) -> frame_mod.OperationalPrefixFiber:
    return frame_mod.operational_prefix_fiber(observation_cut, frame, index)


def operational_completion_fiber(
    prefix_record: Mapping[str, Any],
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
    residual_context: ResidualContext,
) -> frame_mod.OperationalCompletionFiber:
    return frame_mod.operational_completion_fiber(prefix_record, frame, residual_context)


def exact_prefix_set(
    observation_cut: frame_mod.ObservationCut,
    bundle: Mapping[str, Any],
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
    index: int,
) -> FiniteSet:
    return frame_mod.exact_prefix_set(observation_cut, bundle, frame, index)


def admit_prefix(
    observation_cut: frame_mod.ObservationCut,
    bundle: Mapping[str, Any],
    anchor: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> Any:
    return frame_mod.admit_prefix(observation_cut, bundle, anchor, policy)


def residual_context(
    certificate: IssueCertificate,
    status_time: str,
    prefix_view: Any,
    exact_prefix_set_value: FiniteSet,
    policy: Mapping[str, Any] | None = None,
) -> ResidualContext:
    del status_time, policy
    from dfcc.bundle import parse_bundle

    claim = compile_claim(certificate.claim_source)
    bundle = parse_bundle(certificate.bundle_source)
    compiled = _compile_bundle(bundle, claim.horizon)
    return build_residual_context(
        compiled,
        r=prefix_view.r,
        p_star=exact_prefix_set_value,
        p_out=prefix_view.p_out,
        p_in=prefix_view.p_in,
    )


def checked_assoc_view(
    observation_record: Mapping[str, Any],
    claim: Any,
    compiled_bundle: Any,
    residual_context_value: ResidualContext,
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
) -> frame_mod.CheckedAssocView:
    return frame_mod.checked_assoc_view(
        observation_record,
        claim,
        compiled_bundle,
        residual_context_value,
        frame,
    )


def exact_fiber_assoc(
    observation_record: Mapping[str, Any],
    claim: Any,
    compiled_bundle: Any,
    residual_context_value: ResidualContext,
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
) -> frame_mod.ExactFiberAssoc:
    return frame_mod.exact_fiber_assoc(
        observation_record,
        claim,
        compiled_bundle,
        residual_context_value,
        frame,
    )


def fiber_assoc_view(
    observation_record: Mapping[str, Any],
    claim: Any,
    compiled_bundle: Any,
    residual_context_value: ResidualContext,
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
) -> Any:
    return frame_mod.fiber_assoc_view(
        observation_record,
        claim,
        compiled_bundle,
        residual_context_value,
        frame,
    )


def prefix_adjudication(
    observation_record: Mapping[str, Any],
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
) -> Any:
    return frame_mod.prefix_adjudication(observation_record, frame)


def usage_adjudication(
    proposed_use: Mapping[str, Any],
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
    policy: Mapping[str, Any],
) -> Any:
    return frame_mod.usage_adjudication(proposed_use, frame, policy)


def target_adjudication(
    observation_record: Mapping[str, Any],
    target_condition: Mapping[str, Any],
    frame: frame_mod.AssessmentFrame | Mapping[str, Any],
) -> Any:
    return frame_mod.target_adjudication(observation_record, target_condition, frame)


def agreement(
    kernel_view: Any,
    fiber_assoc_view_value: Any,
    adjudication_views: AdjudicationViews,
    adequacy: AdequacyDirection,
    blocking_set: tuple[BlockingRecord, ...],
    policy_gate: GateDecision,
) -> Agreement:
    kernel_direction = getattr(kernel_view, "direction", Direction.NONE).value
    assoc = getattr(fiber_assoc_view_value, "fiber_status", None)
    assoc_direction = assoc.value if assoc is not None else "unknown"
    frame_direction = (
        "positive"
        if adjudication_views.prefix.value == "accept"
        and adjudication_views.usage.value == "accept"
        and adjudication_views.target.value == "accept"
        else "negative"
        if adjudication_views.target.value == "reject"
        else "unknown"
    )
    agreement_status = (
        "positive"
        if kernel_direction == "positive"
        and assoc_direction == "positive"
        and adequacy.value == "positive"
        and not blocking_set
        and policy_gate is GateDecision.ALLOW
        else "negative"
        if kernel_direction == "negative"
        and assoc_direction == "negative"
        and adequacy.value == "negative"
        and not blocking_set
        and policy_gate is GateDecision.ALLOW
        else "indeterminate"
    )
    return Agreement(
        kernel_direction=kernel_direction,
        assoc_direction=assoc_direction,
        frame_direction=frame_direction,
        adequacy_direction=adequacy,
        blocking_set=blocking_set,
        gate_decision=policy_gate,
        agreement_status=agreement_status,
    )


def typed_authority_outcome(
    status_view: Any,
    kernel_view: Any,
    agreement_value: Agreement,
    blocking_set: tuple[BlockingRecord, ...],
    gate_decision_value: GateDecision,
    profile_ref: str | None = None,
    outcome_schema_ref: str | None = None,
) -> AuthorityOutcome:
    del status_view
    local_blocking = list(blocking_set)
    reason_refs = tuple(ref for block in local_blocking for ref in block.reason_refs)
    if agreement_value.agreement_status == "positive":
        code = OperationalCode.ACCEPT.value
        direction = Direction.POSITIVE
        layer = Layer.OPERATIONAL
    elif agreement_value.agreement_status == "negative":
        code = OperationalCode.REJECT.value
        direction = Direction.NEGATIVE
        layer = Layer.OPERATIONAL
        if not reason_refs:
            reason_refs = (
                reason(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.OPERATIONAL,
                    "operational reject authority is licensed by negative agreement",
                    source_artifact="artifact:api-authority-outcome",
                    source_path="/agreement",
                ),
            )
    else:
        code = getattr(getattr(kernel_view, "verdict", None), "value", "unknown")
        direction = getattr(kernel_view, "direction", Direction.NONE)
        layer = (
            Layer.REPRESENTED
            if code in {"assert", "deny", "infeasible", "abstain"}
            else Layer.STATUS
        )
        kernel_reason_refs = tuple(getattr(kernel_view, "reason_refs", ()))
        if kernel_reason_refs:
            reason_refs = tuple(dict.fromkeys((*reason_refs, *kernel_reason_refs)))
        if code in {"deny", "infeasible"} and not reason_refs:
            reason_refs = (
                reason(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.REPRESENTED,
                    f"represented {code} authority is negative decisive",
                    source_artifact="artifact:api-authority-outcome",
                    source_path="/kernel_verdict",
                ),
            )
        if code not in {"allow", "accept", "reject", "assert", "deny", "infeasible", "active"}:
            if not local_blocking:
                local_blocking.append(
                    blocking_record(
                        FailureCode.CHECKER_UNKNOWN,
                        layer,
                        "authority outcome lacks decisive checker evidence",
                        source_artifact="artifact:api-authority-outcome",
                        source_path="/authority_outcome",
                    )
                )
            reason_refs = tuple(
                dict.fromkeys(
                    (*reason_refs, *(ref for block in local_blocking for ref in block.reason_refs))
                )
            )
    outcome = AuthorityOutcome(
        layer=layer,
        code=code,
        direction=direction,
        blocking_set=tuple(local_blocking),
        gate_decision=gate_decision_value,
        profile_ref=profile_ref,
        outcome_schema_ref=outcome_schema_ref,
        reason_refs=reason_refs,
    )
    validate_authority_outcome(outcome)
    return outcome


def transfer_authority(
    certificate: IssueCertificate,
    target_claim: Mapping[str, Any],
    proof: Mapping[str, Any],
    target_frame: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    proof_kinds = ("transfer_authority", "authority_transfer", "claim_transfer")
    accepted = ReferenceChecker._accepted_digest_bound_evidence(
        proof,
        expected_kinds=proof_kinds,
    )
    payload_bindings = {
        "certificate_id": certificate.certificate_id,
        "target_claim_id": str(target_claim.get("claim_id", "")),
    }
    if target_frame.get("frame_id") is not None:
        payload_bindings["target_frame_id"] = str(target_frame["frame_id"])
    if policy.get("policy_id") is not None:
        payload_bindings["policy_id"] = str(policy["policy_id"])
    missing_or_mismatched = []
    for field_name, expected_value in payload_bindings.items():
        proof_value = ReferenceChecker._accepted_payload_value(
            proof,
            field_name,
            expected_kinds=proof_kinds,
        )
        if proof_value is None or str(proof_value) != expected_value:
            missing_or_mismatched.append(field_name)
    accepted = accepted and not missing_or_mismatched
    return {
        "certificate_id": certificate.certificate_id,
        "target_claim": dict(target_claim),
        "target_frame": dict(target_frame),
        "decision": "translate" if accepted else "block",
        "reason": "accepted transfer proof"
        if accepted
        else "missing or mismatched accepted transfer proof",
        "failure_code": None if accepted else "checker_unknown",
        "proof_ref": proof.get("artifact_ref") or proof.get("source_artifact"),
        "missing_or_mismatched": missing_or_mismatched,
        "policy": dict(policy),
    }


__all__ = [
    "ArtifactBundle",
    "KernelProof",
    "KernelProofArtifact",
    "LifecycleDecision",
    "MeasurementRelationArtifact",
    "PipelineReport",
    "ProofRef",
    "ProtocolRecordArtifact",
    "ReplayStageTrace",
    "ReplayTrace",
    "RepresentationRelationArtifact",
    "ResolvedAuthorityRuntime",
    "admit_evidence",
    "admit_prefix",
    "agreement",
    "artifact_bundle_from_json",
    "certify_claim_from_artifact_bundle",
    "check_authority",
    "checked_assoc_view",
    "compile_bundle",
    "compile_claim",
    "completion_admission",
    "define_assessment_frame",
    "define_event_order",
    "define_time_basis",
    "exact_fiber_assoc",
    "exact_prefix_set",
    "fiber_assoc_view",
    "fold_status",
    "gate_decision",
    "initial_context",
    "interval_record",
    "kernel_verdict",
    "make_observation_cut",
    "manifest_digest",
    "operational_completion_fiber",
    "operational_prefix_fiber",
    "prefix_adjudication",
    "profile_resolution",
    "replay_authority_from_bundle",
    "representation_interface",
    "residual_context",
    "resolve_reason_path",
    "resolve_reference",
    "scalar_record",
    "set_ref",
    "status_observation_context",
    "target_adjudication",
    "timestamp_record",
    "transfer_authority",
    "typed_authority_outcome",
    "update_certificate",
    "usage_adjudication",
    "validate_artifact_bundle",
    "validate_artifact_ref",
    "validate_pipeline",
    "validity_view",
]
