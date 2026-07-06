"""Assessment frame, observation, prefix, completion, and association records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from dfcc.backend import ResidualContext
from dfcc.claims import ClaimRecord, PredicateRegistry, default_predicate_registry
from dfcc.models import (
    AdjudicationViews,
    CompletionAdmission,
    FiberAssocView,
    PrefixView,
)
from dfcc.sets import FiniteSet, canonical_key
from dfcc.time import parse_rfc3339
from dfcc.types import (
    AdequacyDirection,
    AdjudicationCode,
    AssociationStatus,
    FailureCode,
    Layer,
    ReasonRef,
    reason,
)


def _bound_ref(value: Any) -> str | None:
    if isinstance(value, str):
        base = value.split("#", 1)[0]
        if base.startswith("artifact:") or value.startswith(("sha256:", "sha384:", "sha512:")):
            return value
        return None
    if isinstance(value, Mapping):
        artifact_ref = value.get("artifact_ref")
        if isinstance(artifact_ref, str):
            return _bound_ref(artifact_ref)
        for digest_key in ("artifact_digest", "digest", "reference_digest"):
            digest = value.get(digest_key)
            if isinstance(digest, str) and digest.startswith(("sha256:", "sha384:", "sha512:")):
                return digest
    return None


def _require_bound_ref(value: Any, field_name: str) -> str:
    ref = _bound_ref(value)
    if ref is None:
        raise ValueError(f"{field_name} must be artifact/digest-bound")
    return ref


def _bound_ref_tuple(values: Any, field_name: str) -> tuple[str, ...]:
    refs = tuple(str(item) for item in values or ())
    unbound = [ref for ref in refs if _bound_ref(ref) is None]
    if unbound:
        raise ValueError(f"{field_name} must be artifact/digest-bound")
    return refs


def _stable_ref_label(value: Any) -> str | None:
    if isinstance(value, Mapping):
        for digest_key in ("artifact_digest", "digest", "reference_digest"):
            digest = value.get(digest_key)
            if isinstance(digest, str) and digest.startswith(("sha256:", "sha384:", "sha512:")):
                return digest
    ref = _bound_ref(value)
    if ref is not None:
        return ref
    if isinstance(value, Mapping):
        source_artifact = value.get("source_artifact")
        source_path = value.get("source_path")
        if isinstance(source_artifact, str) and isinstance(source_path, str):
            return f"{source_artifact}#{source_path.lstrip('/')}"
    return None


def _first_bound_ref(values: Any) -> str | None:
    if isinstance(values, str | Mapping):
        return _bound_ref(values)
    if isinstance(values, list | tuple):
        for item in values:
            ref = _bound_ref(item)
            if ref is not None:
                return ref
    return None


def _accepted_completion_transcript_ref(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return _bound_ref(value)
    kind = next(
        (
            value.get(key)
            for key in ("proof_kind", "checker_kind", "kind", "evidence_kind")
            if value.get(key) is not None
        ),
        None,
    )
    if str(kind) not in {"completion_admission", "completion", "checker_transcript"}:
        return None
    status = next(
        (
            value.get(key)
            for key in ("checker_status", "proof_status", "status", "result", "checker_result")
            if value.get(key) is not None
        ),
        None,
    )
    if str(status) not in {"pass", "accepted"}:
        return None
    return _bound_ref(value)


@dataclass(frozen=True, slots=True)
class AssessmentFrame:
    frame_id: str
    scope: tuple[str, ...] = ()
    policy: dict[str, Any] = field(default_factory=dict)
    target_condition: dict[str, Any] = field(default_factory=dict)
    completion_interface_ref: str = "completion-interface:unspecified"

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> AssessmentFrame:
        return cls(
            frame_id=str(source.get("frame_id", "frame:default")),
            scope=tuple(str(item) for item in source.get("scope", ())),
            policy=dict(source.get("policy", {})),
            target_condition=dict(source.get("target_condition", {})),
            completion_interface_ref=str(
                source.get("completion_interface_ref", "completion-interface:unspecified")
            ),
        )


@dataclass(frozen=True, slots=True)
class RepresentationInterface:
    interface_id: str
    projection_coherence: bool
    error_model: dict[str, Any] = field(default_factory=dict)
    scope: tuple[str, ...] = ()
    obligations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CompletionInterface:
    interface_id: str
    admission_procedure: str = "declared"
    completion_scope: tuple[str, ...] = ()
    uncertainty_model: dict[str, Any] = field(default_factory=dict)
    validity_interval: dict[str, Any] = field(default_factory=dict)
    obligations: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class MeasurementRelation:
    relation_id: str
    accepted: bool
    calibration_ref: str
    latency_ref: str
    dependency_ref: str
    event_order_ref: str

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> MeasurementRelation | None:
        if record.get("measurement_relation") is not None:
            source = record["measurement_relation"]
            if isinstance(source, Mapping):
                proof_ref = _first_bound_ref(
                    source.get(
                        "proof_ref",
                        source.get("proof_refs", record.get("measurement_proof_ref")),
                    )
                )
                if proof_ref is None:
                    return None
                required_refs = (
                    source.get("calibration_ref"),
                    source.get("latency_ref"),
                    source.get("dependency_ref"),
                    source.get("event_order_ref"),
                )
                if not all(_bound_ref(item) is not None for item in required_refs):
                    return None
                return cls(
                    relation_id=str(source.get("relation_id", "measurement:record")),
                    accepted=str(source.get("accepted", "unknown"))
                    in {"pass", "accepted", "true", "True"},
                    calibration_ref=str(source.get("calibration_ref", "")),
                    latency_ref=str(source.get("latency_ref", "")),
                    dependency_ref=str(source.get("dependency_ref", "")),
                    event_order_ref=str(source.get("event_order_ref", "")),
                )
        required = ("calibration_ref", "latency_ref", "dependency_ref", "event_order_ref")
        if (
            all(
                record.get(key) is not None and _bound_ref(record.get(key)) is not None
                for key in required
            )
            and _first_bound_ref(
                record.get("measurement_proof_ref", record.get("measurement_relation_proof_ref"))
            )
            is not None
        ):
            return cls(
                relation_id=str(record.get("measurement_relation_ref", "measurement:record")),
                accepted=True,
                calibration_ref=str(record["calibration_ref"]),
                latency_ref=str(record["latency_ref"]),
                dependency_ref=str(record["dependency_ref"]),
                event_order_ref=str(record["event_order_ref"]),
            )
        return None


@dataclass(frozen=True, slots=True)
class MeasurementRelationArtifact:
    artifact_id: str
    relation: MeasurementRelation
    proof_refs: tuple[str, ...] = ()
    checker_status: str = "unknown"

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> MeasurementRelationArtifact:
        relation_source = source.get("relation", source)
        if not isinstance(relation_source, Mapping):
            raise TypeError("measurement relation artifact relation must be an object")
        if source.get("checker_status") is None:
            raise ValueError("checker_status is required")
        proof_refs = _bound_ref_tuple(source.get("proof_refs", ()), "proof_refs")
        if not proof_refs:
            raise ValueError("proof_refs must contain at least one artifact/digest-bound proof")
        relation = MeasurementRelation(
            relation_id=str(relation_source.get("relation_id", source.get("artifact_id", ""))),
            accepted=str(source.get("checker_status", relation_source.get("accepted", "")))
            in {"pass", "accepted", "true", "True"},
            calibration_ref=_require_bound_ref(
                relation_source.get("calibration_ref"), "calibration_ref"
            ),
            latency_ref=_require_bound_ref(relation_source.get("latency_ref"), "latency_ref"),
            dependency_ref=_require_bound_ref(
                relation_source.get("dependency_ref"), "dependency_ref"
            ),
            event_order_ref=_require_bound_ref(
                relation_source.get("event_order_ref"), "event_order_ref"
            ),
        )
        return cls(
            artifact_id=str(source["artifact_id"]),
            relation=relation,
            proof_refs=proof_refs,
            checker_status=str(source.get("checker_status", "unknown")),
        )


@dataclass(frozen=True, slots=True)
class RepresentationRelation:
    relation_id: str
    operational_prefix: tuple[Any, ...]
    represented_prefix: tuple[Any, ...]
    proof_ref: str

    @classmethod
    def from_record(cls, record: Mapping[str, Any]) -> tuple[RepresentationRelation, ...]:
        source = record.get("representation_relation")
        if isinstance(source, Mapping):
            source = (source,)
        if isinstance(source, list | tuple):
            return tuple(
                cls(
                    relation_id=str(item.get("relation_id", "representation:record")),
                    operational_prefix=tuple(item.get("operational_prefix", ())),
                    represented_prefix=tuple(item.get("represented_prefix", ())),
                    proof_ref=str(item.get("proof_ref", "")),
                )
                for item in source
                if isinstance(item, Mapping)
                and item.get("proof_ref") is not None
                and _bound_ref(item.get("proof_ref")) is not None
                and item.get("represented_prefix") is not None
            )
        return ()


@dataclass(frozen=True, slots=True)
class RepresentationRelationArtifact:
    artifact_id: str
    relations: tuple[RepresentationRelation, ...]
    checker_status: str = "unknown"

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> RepresentationRelationArtifact:
        if source.get("checker_status") is None:
            raise ValueError("checker_status is required")
        relation_source = source.get("relations", source.get("relation", ()))
        if isinstance(relation_source, Mapping):
            relation_source = (relation_source,)
        if not isinstance(relation_source, list | tuple):
            raise TypeError("representation relation artifact relations must be a sequence")
        relations_list: list[RepresentationRelation] = []
        for index, item in enumerate(relation_source):
            if not isinstance(item, Mapping):
                raise TypeError(f"representation relation {index} must be an object")
            if item.get("relation_id") is None:
                raise ValueError("relation_id is required")
            if item.get("represented_prefix") is None:
                raise ValueError("represented_prefix is required")
            relations_list.append(
                RepresentationRelation(
                    relation_id=str(item["relation_id"]),
                    operational_prefix=tuple(item.get("operational_prefix", ())),
                    represented_prefix=tuple(item["represented_prefix"]),
                    proof_ref=_require_bound_ref(item.get("proof_ref"), "proof_ref"),
                )
            )
        relations = tuple(relations_list)
        if not relations:
            raise ValueError("relations must contain at least one representation relation")
        return cls(
            artifact_id=str(source["artifact_id"]),
            relations=relations,
            checker_status=str(source.get("checker_status", "unknown")),
        )


@dataclass(frozen=True, slots=True)
class ObservationCut:
    records: tuple[dict[str, Any], ...]
    status_time: str
    time_basis_ref: str
    event_order_ref: str
    dependency_snapshot: dict[str, str]
    frame_id: str
    policy_ref: str


@dataclass(frozen=True, slots=True)
class StatusObservationContext:
    status_time: str
    r: int
    observation_cut: ObservationCut
    prefix_view: PrefixView
    time_basis_ref: str
    event_order_ref: str
    dependency_snapshot: dict[str, str]
    frame_id: str
    policy_ref: str
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class OperationalPrefixFiber:
    status: str
    prefixes: FiniteSet
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class OperationalCompletionFiber:
    status: str
    completions: FiniteSet
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class CheckedAssocView:
    assoc_status: AssociationStatus
    a_out: FiniteSet
    a_in: FiniteSet
    assoc_obligations: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class ExactFiberAssoc:
    associated: FiniteSet


def define_assessment_frame(
    frame_record: Mapping[str, Any], policy: Mapping[str, Any] | None = None
) -> AssessmentFrame:
    frame = AssessmentFrame.from_json(frame_record)
    if policy:
        merged = {**frame.policy, **dict(policy)}
        return AssessmentFrame(
            frame_id=frame.frame_id,
            scope=frame.scope,
            policy=merged,
            target_condition=frame.target_condition,
            completion_interface_ref=frame.completion_interface_ref,
        )
    return frame


def representation_interface(
    bundle: Mapping[str, Any],
    frame: AssessmentFrame | Mapping[str, Any],
    policy: Mapping[str, Any] | None = None,
) -> RepresentationInterface:
    frame_obj = frame if isinstance(frame, AssessmentFrame) else AssessmentFrame.from_json(frame)
    explicit = bundle.get("representation_interface", {})
    obligations = tuple(str(item) for item in explicit.get("obligations", ()))
    if policy and policy.get("require_projection_coherence", False):
        obligations = (*obligations, "projection-coherence")
    for proof_field in (
        "projection_coherence_proof",
        "projection_coherence_proof_ref",
        "representation_projection_coherence_proof",
        "representation_projection_coherence_proof_ref",
        "checker_transcript",
        "checker_transcript_ref",
    ):
        proof_label = _stable_ref_label(explicit.get(proof_field))
        if proof_label is not None:
            obligations = (*obligations, proof_label)
    return RepresentationInterface(
        interface_id=str(explicit.get("interface_id", f"representation:{frame_obj.frame_id}")),
        projection_coherence=bool(explicit.get("projection_coherence", True)),
        error_model=dict(explicit.get("error_model", {})),
        scope=tuple(str(item) for item in explicit.get("scope", frame_obj.scope)),
        obligations=obligations,
    )


def completion_interface(
    frame: AssessmentFrame | Mapping[str, Any],
    r: int,
    h: int,
) -> CompletionInterface:
    frame_obj = frame if isinstance(frame, AssessmentFrame) else AssessmentFrame.from_json(frame)
    return CompletionInterface(
        interface_id=f"{frame_obj.completion_interface_ref}:r{r}:h{h}",
        completion_scope=frame_obj.scope,
        obligations=tuple(str(item) for item in frame_obj.policy.get("completion_obligations", ())),
    )


def make_observation_cut(
    records: tuple[Mapping[str, Any], ...],
    status_time: str,
    time_basis: str,
    event_order: str,
    dependencies: Mapping[str, str],
    frame: AssessmentFrame | Mapping[str, Any],
    policy: Mapping[str, Any],
) -> ObservationCut:
    frame_obj = frame if isinstance(frame, AssessmentFrame) else AssessmentFrame.from_json(frame)
    return ObservationCut(
        records=tuple(dict(item) for item in records),
        status_time=status_time,
        time_basis_ref=time_basis,
        event_order_ref=event_order,
        dependency_snapshot=dict(dependencies),
        frame_id=frame_obj.frame_id,
        policy_ref=str(policy.get("policy_id", policy.get("version", "policy:default"))),
    )


def operational_prefix_fiber(
    observation_cut: ObservationCut,
    frame: AssessmentFrame | Mapping[str, Any],
    index: int,
) -> OperationalPrefixFiber:
    del frame
    prefixes: list[tuple[Any, ...]] = []
    for record in observation_cut.records:
        measurement = MeasurementRelation.from_record(record)
        if measurement is None or not measurement.accepted:
            continue
        if int(record.get("r", index)) <= index and "operational_prefix" in record:
            prefixes.append(tuple(record["operational_prefix"]))
    if not prefixes and index == 0:
        prefixes = [()] if not observation_cut.records else []
    if not prefixes:
        ref = reason(FailureCode.PREFIX_UNSOUND, Layer.OPERATIONAL, "no operational prefix fiber")
        return OperationalPrefixFiber("unknown", FiniteSet.from_iterable(()), (ref,))
    return OperationalPrefixFiber("pass", FiniteSet.from_iterable(prefixes))


def exact_prefix_set(
    observation_cut: ObservationCut,
    bundle: Mapping[str, Any],
    frame: AssessmentFrame | Mapping[str, Any],
    index: int,
) -> FiniteSet:
    del bundle, frame
    prefixes: list[tuple[Any, ...]] = []
    for record in observation_cut.records:
        if int(record.get("r", index)) != index:
            continue
        relations = RepresentationRelation.from_record(record)
        if relations:
            prefixes.extend(relation.represented_prefix for relation in relations)
    return FiniteSet.from_iterable(prefixes)


def admit_prefix(
    observation_cut: ObservationCut,
    bundle: Mapping[str, Any],
    anchor: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> PrefixView:
    del anchor
    r = int(policy.get("r", 0))
    p_star = exact_prefix_set(observation_cut, bundle, {}, r)
    p_out_source = policy.get("p_out")
    p_out = (
        FiniteSet.from_iterable(tuple(item) for item in p_out_source)
        if p_out_source is not None
        else p_star
    )
    if p_star.is_empty() and not p_out.is_empty():
        ref = reason(
            FailureCode.EXACT_PREFIX_EMPTY,
            Layer.OPERATIONAL,
            "exact prefix is empty while outer prefix is nonempty",
        )
        return PrefixView("unknown", r, p_star, p_out, reason_refs=(ref,))
    if not p_star.subset_of(p_out):
        ref = reason(FailureCode.PREFIX_UNSOUND, Layer.OPERATIONAL, "exact prefix not enclosed")
        return PrefixView("conflict", r, p_star, p_out, reason_refs=(ref,))
    return PrefixView("pass", r, p_star, p_out)


def status_observation_context(
    certificate: Any,
    observation_cut: ObservationCut,
    policy: Mapping[str, Any],
) -> StatusObservationContext:
    del certificate
    prefix = admit_prefix(observation_cut, {}, {}, policy)
    return StatusObservationContext(
        status_time=observation_cut.status_time,
        r=prefix.r,
        observation_cut=observation_cut,
        prefix_view=prefix,
        time_basis_ref=observation_cut.time_basis_ref,
        event_order_ref=observation_cut.event_order_ref,
        dependency_snapshot=observation_cut.dependency_snapshot,
        frame_id=observation_cut.frame_id,
        policy_ref=observation_cut.policy_ref,
        reason_refs=prefix.reason_refs,
    )


def completion_admission(
    prefix_context: PrefixView | Mapping[str, Any],
    completion_interface_value: CompletionInterface | Mapping[str, Any],
    policy: Mapping[str, Any],
) -> CompletionAdmission:
    del prefix_context
    interface_id = (
        completion_interface_value.interface_id
        if isinstance(completion_interface_value, CompletionInterface)
        else str(completion_interface_value.get("interface_id", "completion-interface"))
    )
    status = str(policy.get("completion_status", "unknown"))
    checker_transcript_ref = _accepted_completion_transcript_ref(
        policy.get("checker_transcript_ref")
    )
    required = (
        policy.get("admission_source"),
        policy.get("expiry"),
        policy.get("uncertainty_model"),
        policy.get("reference_digest"),
        policy.get("checker_result"),
        checker_transcript_ref,
    )
    if status == "pass" and not all(item is not None and str(item) for item in required):
        ref = reason(
            FailureCode.COMPLETION_MISSING,
            Layer.OPERATIONAL,
            "completion admission semantic identity or checker transcript binding is incomplete",
        )
        return CompletionAdmission(completion_status="unknown", reason_refs=(ref,))
    checker_result = str(policy.get("checker_result", "unknown"))
    if status == "pass" and checker_result not in {"pass", "accepted"}:
        ref = reason(
            FailureCode.CHECKER_UNKNOWN,
            Layer.OPERATIONAL,
            f"completion checker result is {checker_result}",
        )
        return CompletionAdmission(completion_status="unknown", reason_refs=(ref,))
    reference_digest = str(policy.get("reference_digest", ""))
    if status == "pass" and not reference_digest.startswith(("sha256:", "sha384:", "sha512:")):
        ref = reason(
            FailureCode.DIGEST_MISMATCH,
            Layer.OPERATIONAL,
            "completion admission reference digest is not a supported digest",
        )
        return CompletionAdmission(completion_status="unknown", reason_refs=(ref,))
    expiry = str(policy.get("expiry", ""))
    status_time = policy.get("status_time")
    if (
        status == "pass"
        and expiry != "unbounded"
        and status_time is not None
        and parse_rfc3339(str(status_time)) > parse_rfc3339(expiry)
    ):
        ref = reason(
            FailureCode.EXPIRED,
            Layer.OPERATIONAL,
            "completion admission is expired at status time",
        )
        return CompletionAdmission(completion_status="expired", reason_refs=(ref,))
    c_out_ref = policy.get("c_out_ref")
    c_in_ref = policy.get("c_in_ref")
    return CompletionAdmission(
        completion_status=status,
        c_out_ref=str(c_out_ref) if status == "pass" and c_out_ref else None,
        c_in_ref=str(c_in_ref) if status == "pass" and c_in_ref else None,
        admission_source=str(policy.get("admission_source")) if status == "pass" else None,
        expiry=expiry if status == "pass" else None,
        uncertainty_model=str(policy.get("uncertainty_model")) if status == "pass" else None,
        reference_digest=reference_digest if status == "pass" else None,
        checker_result=checker_result if status == "pass" else None,
        checker_transcript_ref=checker_transcript_ref if status == "pass" else None,
        completion_obligations=tuple(
            dict.fromkeys(
                (
                    interface_id,
                    *tuple(str(item) for item in policy.get("completion_obligations", ())),
                )
            )
        ),
    )


def operational_completion_fiber(
    prefix_record: Mapping[str, Any],
    frame: AssessmentFrame | Mapping[str, Any],
    residual_context: ResidualContext,
) -> OperationalCompletionFiber:
    del frame
    completions = prefix_record.get("operational_completions")
    if completions is None:
        ref = reason(FailureCode.COMPLETION_MISSING, Layer.OPERATIONAL, "no completions admitted")
        return OperationalCompletionFiber("unknown", FiniteSet.from_iterable(()), (ref,))
    completion_set = FiniteSet.from_iterable(tuple(item) for item in completions)
    adm_keys = {canonical_key(tuple(item)) for item in residual_context.adm_out}
    compatible = completion_set.filter(lambda item: canonical_key(tuple(item)) in adm_keys)
    return OperationalCompletionFiber("pass", compatible)


def checked_assoc_view(
    observation_record: Mapping[str, Any],
    claim: ClaimRecord,
    compiled_bundle: Any,
    residual_context: ResidualContext,
    frame: AssessmentFrame | Mapping[str, Any],
    *,
    registry: PredicateRegistry | None = None,
) -> CheckedAssocView:
    del observation_record, compiled_bundle, frame
    registry = registry or default_predicate_registry()
    associated = residual_context.adm_star
    satisfaction = claim.satisfaction_set(associated, registry)
    if associated.is_empty():
        return CheckedAssocView(AssociationStatus.EMPTY, associated, FiniteSet.from_iterable(()))
    if associated.subset_of(satisfaction):
        return CheckedAssocView(AssociationStatus.POSITIVE, associated, satisfaction)
    if associated.disjoint_from(satisfaction):
        return CheckedAssocView(AssociationStatus.NEGATIVE, associated, FiniteSet.from_iterable(()))
    return CheckedAssocView(AssociationStatus.MIXED, associated, satisfaction)


def exact_fiber_assoc(
    observation_record: Mapping[str, Any],
    claim: ClaimRecord,
    compiled_bundle: Any,
    residual_context: ResidualContext,
    frame: AssessmentFrame | Mapping[str, Any],
) -> ExactFiberAssoc:
    del observation_record, claim, compiled_bundle, frame
    return ExactFiberAssoc(residual_context.adm_star)


def fiber_assoc_view(
    observation_record: Mapping[str, Any],
    claim: ClaimRecord,
    compiled_bundle: Any,
    residual_context: ResidualContext,
    frame: AssessmentFrame | Mapping[str, Any],
    *,
    registry: PredicateRegistry | None = None,
) -> FiberAssocView:
    view = checked_assoc_view(
        observation_record,
        claim,
        compiled_bundle,
        residual_context,
        frame,
        registry=registry,
    )
    return FiberAssocView(view.assoc_status, fiber_obligations=view.assoc_obligations)


def prefix_adjudication(
    observation_record: Mapping[str, Any],
    frame: AssessmentFrame | Mapping[str, Any],
) -> AdjudicationCode:
    del frame
    return AdjudicationCode(str(observation_record.get("prefix_adjudication", "indeterminate")))


def usage_adjudication(
    proposed_use: Mapping[str, Any],
    frame: AssessmentFrame | Mapping[str, Any],
    policy: Mapping[str, Any],
) -> AdjudicationCode:
    frame_obj = frame if isinstance(frame, AssessmentFrame) else AssessmentFrame.from_json(frame)
    mode = str(proposed_use.get("mode", ""))
    if mode in {str(item) for item in policy.get("blocked_modes", ())}:
        return AdjudicationCode.REJECT
    if frame_obj.scope and not set(proposed_use.get("scope", ())).issubset(set(frame_obj.scope)):
        return AdjudicationCode.OUT_OF_FRAME
    return AdjudicationCode.ACCEPT


def target_adjudication(
    observation_record: Mapping[str, Any],
    target_condition: Mapping[str, Any],
    frame: AssessmentFrame | Mapping[str, Any],
) -> AdjudicationCode:
    del target_condition, frame
    return AdjudicationCode(str(observation_record.get("target_adjudication", "indeterminate")))


def frame_adequacy(
    represented_claim: ClaimRecord,
    target_condition: Mapping[str, Any],
    frame: AssessmentFrame | Mapping[str, Any],
) -> AdequacyDirection:
    del represented_claim, target_condition
    frame_obj = frame if isinstance(frame, AssessmentFrame) else AssessmentFrame.from_json(frame)
    return AdequacyDirection(str(frame_obj.policy.get("adequacy_direction", "unknown")))


def adjudication_views(
    observation_record: Mapping[str, Any],
    proposed_use: Mapping[str, Any],
    target_condition: Mapping[str, Any],
    frame: AssessmentFrame | Mapping[str, Any],
    policy: Mapping[str, Any],
) -> AdjudicationViews:
    return AdjudicationViews(
        prefix=prefix_adjudication(observation_record, frame),
        usage=usage_adjudication(proposed_use, frame, policy),
        target=target_adjudication(observation_record, target_condition, frame),
    )
