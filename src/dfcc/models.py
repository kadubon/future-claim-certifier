"""High-level DFCC artifact models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from dfcc.artifacts import ArtifactRef
from dfcc.canonical import digest_json
from dfcc.profiles import BASE_SCHEMA_PROFILE, JCS_CANONICALIZATION
from dfcc.sets import FiniteSet
from dfcc.types import (
    AdequacyDirection,
    AdjudicationCode,
    AssociationStatus,
    AuthorityOutcome,
    BlockingRecord,
    GateDecision,
    GuardRecord,
    ReasonRef,
    StatusCode,
    StatusCoordinate,
    ValidationResult,
    VerdictCode,
)


def _artifact_bound_id(value: str | None, fallback: str) -> str:
    if value and value.startswith("artifact:"):
        return value
    if value:
        safe = "".join(char if char.isalnum() or char in "._-" else "-" for char in value)
        return f"artifact:{safe}"
    return fallback


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


def _normalized_reason_ref(
    ref: ReasonRef,
    *,
    fallback_artifact: str = "artifact:status-authority-view",
) -> ReasonRef:
    source_artifact = _artifact_bound_id(ref.source_artifact, fallback_artifact)
    source_path = ref.source_path if ref.source_path.startswith("/") else f"/{ref.source_path}"
    normalized = ReasonRef(
        reason_id=ref.reason_id,
        failure_code=ref.failure_code,
        layer=ref.layer,
        source_artifact=source_artifact,
        source_path=source_path,
        message=ref.message,
        digest=ref.digest,
    )
    if normalized.digest is not None:
        return normalized
    return ReasonRef(
        reason_id=normalized.reason_id,
        failure_code=normalized.failure_code,
        layer=normalized.layer,
        source_artifact=normalized.source_artifact,
        source_path=normalized.source_path,
        message=normalized.message,
        digest=_reason_digest(normalized),
    )


def _normalized_reason_refs(refs: tuple[ReasonRef, ...]) -> tuple[ReasonRef, ...]:
    return tuple(dict.fromkeys(_normalized_reason_ref(ref) for ref in refs))


def _reason_ref_record(ref: ReasonRef) -> dict[str, Any]:
    ref = _normalized_reason_ref(ref)
    return {
        "reason_id": ref.reason_id,
        "failure_code": ref.failure_code.value,
        "layer": ref.layer.value,
        "source_artifact": ref.source_artifact,
        "source_path": ref.source_path,
        "message": ref.message,
        "digest": ref.digest,
    }


def _blocking_record_record(block: BlockingRecord) -> dict[str, Any]:
    reason_refs = _normalized_reason_refs(block.reason_refs)
    return {
        "block_id": block.block_id,
        "failure_code": block.failure_code.value,
        "layer": block.layer.value,
        "severity": block.severity,
        "reason_refs": [ref.reason_id for ref in reason_refs],
        "reason_ref_records": [_reason_ref_record(ref) for ref in reason_refs],
    }


def _bound_reference_string(value: str | None) -> bool:
    if value is None:
        return False
    ref = str(value)
    base = ref.split("#", 1)[0]
    return base.startswith("artifact:") or ref.startswith(("sha256:", "sha384:", "sha512:"))


def _obligation_ref_record(ref: str, ledger_entries: tuple[Any, ...]) -> dict[str, Any]:
    entry = next(
        (
            item
            for item in ledger_entries
            if str(getattr(item, "ref_value", "")) == ref
            or str(getattr(item, "target_artifact_id", "")) == ref.split("#", 1)[0]
        ),
        None,
    )
    target_digest = entry.target_digest if entry is not None else None
    active_status = str(getattr(entry, "active_scope_status", "unknown"))
    compatibility_waiver = not _bound_reference_string(ref) and active_status not in {
        "pass",
        "waived",
    }
    waiver_reason_suffix = digest_json(ref).split(":", 1)[1][:16]
    waiver_reason_id = f"reason:compatibility-obligation:{waiver_reason_suffix}"
    return {
        "obligation_id": ref,
        "kind": str(getattr(getattr(entry, "kind", None), "value", "obligation")),
        "status": "waived" if compatibility_waiver else active_status,
        "scope": [str(getattr(entry, "target_artifact_id", ""))] if entry is not None else [],
        "checker": str(getattr(getattr(entry, "expected_kind", None), "value", ""))
        if entry is not None
        else None,
        "expiry": None,
        "reason_refs": [waiver_reason_id] if compatibility_waiver else [],
        "source_artifact": str(getattr(entry, "target_artifact_id", ""))
        if entry is not None
        else None,
        "source_path": str(getattr(entry, "target_path", "")) if entry is not None else None,
        "digest": str(target_digest) if target_digest is not None else None,
    }


def _proof_ref_record(
    ref: str,
    ledger_entries: tuple[Any, ...],
    artifact_refs: tuple[ArtifactRef, ...] = (),
) -> dict[str, Any]:
    entry = next(
        (
            item
            for item in ledger_entries
            if str(getattr(item, "ref_value", "")) == ref
            or str(getattr(item, "target_artifact_id", "")) == ref.split("#", 1)[0]
        ),
        None,
    )
    if entry is None:
        ref_value = str(ref)
        ref_base, separator, pointer = ref_value.partition("#")
        artifact_ref = next(
            (item for item in artifact_refs if str(item.artifact_id) == ref_base),
            None,
        )
        if artifact_ref is not None:
            return {
                "proof_id": ref_value,
                "proof_kind": str(artifact_ref.semantic_role or artifact_ref.artifact_type),
                "artifact_ref": artifact_ref.artifact_id,
                "source_artifact": artifact_ref.artifact_id,
                "source_path": pointer if separator and pointer.startswith("/") else "/",
                "digest": artifact_ref.digest_value,
                "status": "accepted" if artifact_ref.digest_value is not None else "unknown",
            }
    target_digest = getattr(entry, "target_digest", None) if entry is not None else None
    return {
        "proof_id": ref,
        "proof_kind": str(getattr(getattr(entry, "kind", None), "value", "proof")),
        "artifact_ref": str(getattr(entry, "target_artifact_id", "")) if entry is not None else ref,
        "source_artifact": _artifact_bound_id(str(getattr(entry, "owner_artifact", "")), "")
        if entry is not None
        else None,
        "source_path": str(getattr(entry, "owner_path", "")) if entry is not None else "",
        "digest": str(target_digest) if target_digest is not None else None,
        "status": "accepted" if bool(getattr(entry, "resolved", False)) else "unknown",
    }


def _artifact_ref_record(ref: ArtifactRef | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(ref, Mapping):
        return {
            "artifact_id": str(ref["artifact_id"]),
            "artifact_type": str(ref.get("artifact_type", "unknown")),
            "schema_profile": str(ref.get("schema_profile", BASE_SCHEMA_PROFILE)),
            "canonicalization": str(ref.get("canonicalization", JCS_CANONICALIZATION)),
            "media_type": str(ref.get("media_type", "application/json")),
            "schema_digest": ref.get("schema_digest"),
            "canonicalization_digest": ref.get("canonicalization_digest"),
            "digest_algorithm": str(ref.get("digest_algorithm", "sha256")),
            "digest_value": ref.get("digest_value"),
            "content_uri": ref.get("content_uri"),
            "retrieval_policy": str(ref.get("retrieval_policy", "local")),
            "immutability_policy": str(ref.get("immutability_policy", "digest-addressed")),
            "provenance_refs": [str(item) for item in ref.get("provenance_refs", ())],
            "semantic_role": ref.get("semantic_role"),
            "dependency_labels": [str(item) for item in ref.get("dependency_labels", ())],
        }
    return {
        "artifact_id": ref.artifact_id,
        "artifact_type": ref.artifact_type,
        "schema_profile": ref.schema_profile,
        "canonicalization": ref.canonicalization,
        "media_type": ref.media_type,
        "schema_digest": ref.schema_digest,
        "canonicalization_digest": ref.canonicalization_digest,
        "digest_algorithm": ref.digest_algorithm,
        "digest_value": ref.digest_value,
        "content_uri": ref.content_uri,
        "retrieval_policy": ref.retrieval_policy,
        "immutability_policy": ref.immutability_policy,
        "provenance_refs": list(ref.provenance_refs),
        "semantic_role": ref.semantic_role,
        "dependency_labels": list(ref.dependency_labels),
    }


def _legacy_artifact_ref_record(ref: str) -> dict[str, Any]:
    return {
        "artifact_id": ref,
        "artifact_type": "legacy-reference",
        "schema_profile": BASE_SCHEMA_PROFILE,
        "canonicalization": JCS_CANONICALIZATION,
        "media_type": "application/json",
        "schema_digest": None,
        "canonicalization_digest": None,
        "digest_algorithm": "sha256",
        "digest_value": None,
        "content_uri": None,
        "retrieval_policy": "local",
        "immutability_policy": "digest-addressed",
        "provenance_refs": [],
        "semantic_role": None,
        "dependency_labels": [],
    }


def _set_ref_digest(record: Mapping[str, Any]) -> str:
    return digest_json(
        {
            "carrier_ref": str(record["carrier_ref"]),
            "encoding_kind": str(record["encoding_kind"]),
            "constraint_ref": str(record["constraint_ref"]),
            "approximation_kind": str(record["approximation_kind"]),
            "soundness_ref": str(record["soundness_ref"]),
        }
    )


def _set_ref_record(record: Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        payload = {
            "carrier_ref": str(record["carrier_ref"]),
            "encoding_kind": str(record["encoding_kind"]),
            "constraint_ref": str(record["constraint_ref"]),
            "approximation_kind": str(record["approximation_kind"]),
            "soundness_ref": str(record["soundness_ref"]),
            "digest": str(record.get("digest") or ""),
        }
    else:
        payload = {
            "carrier_ref": str(record.carrier_ref),
            "encoding_kind": str(record.encoding_kind),
            "constraint_ref": str(record.constraint_ref),
            "approximation_kind": str(record.approximation_kind),
            "soundness_ref": str(record.soundness_ref),
            "digest": str(getattr(record, "digest", "")),
        }
    if not payload["digest"]:
        payload["digest"] = _set_ref_digest(payload)
    return payload


def _legacy_set_ref_record(ref: str) -> dict[str, Any]:
    payload = {
        "carrier_ref": ref,
        "encoding_kind": "legacy-reference",
        "constraint_ref": ref,
        "approximation_kind": "unknown",
        "soundness_ref": f"legacy:set-ref:{digest_json(ref).split(':', 1)[1][:16]}",
    }
    return {**payload, "digest": _set_ref_digest(payload)}


@dataclass(frozen=True, slots=True)
class PrefixView:
    prefix_status: str
    r: int
    p_star: FiniteSet
    p_out: FiniteSet
    p_in: FiniteSet | None = None
    prefix_obligations: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class CompletionAdmission:
    tag: str = "CompletionAdmission"
    completion_status: str = "unknown"
    c_out_ref: str | None = None
    c_in_ref: str | None = None
    admission_source: str | None = None
    expiry: str | None = None
    uncertainty_model: str | None = None
    reference_digest: str | None = None
    checker_result: str | None = None
    checker_transcript_ref: str | None = None
    completion_obligations: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()

    @property
    def passed(self) -> bool:
        semantic_identity = (
            self.admission_source,
            self.expiry,
            self.uncertainty_model,
            self.reference_digest,
            self.checker_result,
            self.checker_transcript_ref,
        )
        return (
            self.tag == "CompletionAdmission"
            and self.completion_status == "pass"
            and all(item is not None and str(item) for item in semantic_identity)
            and _bound_reference_string(self.checker_transcript_ref)
        )


@dataclass(frozen=True, slots=True)
class FiberAssocView:
    fiber_status: AssociationStatus
    f_out_ref: str | None = None
    f_in_ref: str | None = None
    fiber_obligations: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class AdjudicationViews:
    prefix: AdjudicationCode = AdjudicationCode.INDETERMINATE
    usage: AdjudicationCode = AdjudicationCode.INDETERMINATE
    target: AdjudicationCode = AdjudicationCode.INDETERMINATE


@dataclass(frozen=True, slots=True)
class Agreement:
    kernel_direction: str
    assoc_direction: str
    frame_direction: str
    adequacy_direction: AdequacyDirection
    blocking_set: tuple[BlockingRecord, ...]
    gate_decision: GateDecision
    agreement_status: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class ProposedUse:
    mode: str
    claim: str
    horizon: int
    anchor: str
    scope: tuple[str, ...] = ()
    consumer: str | None = None
    policy: str | None = None
    frame: str | None = None
    context: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> ProposedUse:
        return cls(
            mode=str(source["mode"]),
            claim=str(source["claim"]),
            horizon=int(source["horizon"]),
            anchor=str(source["anchor"]),
            scope=tuple(str(item) for item in source.get("scope", ())),
            consumer=source.get("consumer"),
            policy=source.get("policy"),
            frame=source.get("frame"),
            context=dict(source.get("context", {})),
        )


@dataclass(frozen=True, slots=True)
class IssueCertificate:
    certificate_id: str
    schema_profile_ref: str
    canonicalization_profile_ref: str
    manifest_digest: str
    claim_ref: str
    anchor_ref: str
    time_basis_ref: str
    event_order_commitment_ref: str
    assessment_frame_ref: str
    assumption_bundle_ref: str
    initial_context_ref: str
    representation_interface_ref: str
    completion_interface_ref: str
    compiled_semantics_ref: str
    set_refs: tuple[str, ...]
    proof_refs: tuple[str, ...]
    kernel_verdict_at_issue: VerdictCode
    soundness_grade: int
    dependency_graph_ref: str
    artifact_refs: tuple[str, ...]
    obligation_refs: tuple[str, ...]
    provenance_refs: tuple[str, ...]
    claim_source: dict[str, Any]
    bundle_source: dict[str, Any]
    anchor_source: dict[str, Any]
    time_basis_source: dict[str, Any]
    frame: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)
    artifact_ref_records: tuple[dict[str, Any], ...] = ()
    set_ref_records: tuple[dict[str, Any], ...] = ()
    obligation_ref_records: tuple[dict[str, Any], ...] = ()
    proof_ref_records: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not self.artifact_ref_records:
            object.__setattr__(
                self,
                "artifact_ref_records",
                tuple(_legacy_artifact_ref_record(ref) for ref in self.artifact_refs),
            )
        if not self.set_ref_records:
            object.__setattr__(
                self,
                "set_ref_records",
                tuple(_legacy_set_ref_record(ref) for ref in self.set_refs),
            )
        if not self.obligation_ref_records:
            object.__setattr__(
                self,
                "obligation_ref_records",
                tuple(_obligation_ref_record(ref, ()) for ref in self.obligation_refs),
            )
        if not self.proof_ref_records:
            object.__setattr__(
                self,
                "proof_ref_records",
                tuple(_proof_ref_record(ref, ()) for ref in self.proof_refs),
            )

    def minimum_profile(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "schema_profile_ref": self.schema_profile_ref,
            "canonicalization_profile_ref": self.canonicalization_profile_ref,
            "manifest_digest": self.manifest_digest,
            "claim_ref": self.claim_ref,
            "anchor_ref": self.anchor_ref,
            "time_basis_ref": self.time_basis_ref,
            "event_order_commitment_ref": self.event_order_commitment_ref,
            "assessment_frame_ref": self.assessment_frame_ref,
            "assumption_bundle_ref": self.assumption_bundle_ref,
            "initial_context_ref": self.initial_context_ref,
            "representation_interface_ref": self.representation_interface_ref,
            "completion_interface_ref": self.completion_interface_ref,
            "compiled_semantics_ref": self.compiled_semantics_ref,
            "set_refs": list(self.set_refs),
            "set_ref_records": list(self.set_ref_records),
            "proof_refs": list(self.proof_refs),
            "kernel_verdict_at_issue": self.kernel_verdict_at_issue.value,
            "soundness_grade": self.soundness_grade,
            "dependency_graph_ref": self.dependency_graph_ref,
            "artifact_refs": list(self.artifact_refs),
            "artifact_ref_records": list(self.artifact_ref_records),
            "obligation_refs": list(self.obligation_refs),
            "obligation_ref_records": list(self.obligation_ref_records),
            "provenance_refs": list(self.provenance_refs),
            "proof_ref_records": list(self.proof_ref_records),
        }

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> IssueCertificate:
        return cls(
            certificate_id=str(source["certificate_id"]),
            schema_profile_ref=str(source.get("schema_profile_ref", BASE_SCHEMA_PROFILE)),
            canonicalization_profile_ref=str(
                source.get("canonicalization_profile_ref", JCS_CANONICALIZATION)
            ),
            manifest_digest=str(source["manifest_digest"]),
            claim_ref=str(source["claim_ref"]),
            anchor_ref=str(source["anchor_ref"]),
            time_basis_ref=str(source["time_basis_ref"]),
            event_order_commitment_ref=str(source["event_order_commitment_ref"]),
            assessment_frame_ref=str(source["assessment_frame_ref"]),
            assumption_bundle_ref=str(source["assumption_bundle_ref"]),
            initial_context_ref=str(source["initial_context_ref"]),
            representation_interface_ref=str(source["representation_interface_ref"]),
            completion_interface_ref=str(source["completion_interface_ref"]),
            compiled_semantics_ref=str(source["compiled_semantics_ref"]),
            set_refs=tuple(str(item) for item in source.get("set_refs", ())),
            proof_refs=tuple(str(item) for item in source.get("proof_refs", ())),
            kernel_verdict_at_issue=VerdictCode(str(source["kernel_verdict_at_issue"])),
            soundness_grade=int(source["soundness_grade"]),
            dependency_graph_ref=str(source["dependency_graph_ref"]),
            artifact_refs=tuple(str(item) for item in source.get("artifact_refs", ())),
            obligation_refs=tuple(str(item) for item in source.get("obligation_refs", ())),
            provenance_refs=tuple(str(item) for item in source.get("provenance_refs", ())),
            claim_source=dict(source["claim_source"]),
            bundle_source=dict(source["bundle_source"]),
            anchor_source=dict(source["anchor_source"]),
            time_basis_source=dict(source["time_basis_source"]),
            frame=dict(source.get("frame", {})),
            policy=dict(source.get("policy", {})),
            artifact_ref_records=tuple(
                dict(item) for item in source.get("artifact_ref_records", ())
            ),
            obligation_ref_records=tuple(
                dict(item) for item in source.get("obligation_ref_records", ())
            ),
            set_ref_records=tuple(dict(item) for item in source.get("set_ref_records", ())),
            proof_ref_records=tuple(dict(item) for item in source.get("proof_ref_records", ())),
        )


@dataclass(frozen=True, slots=True)
class StatusContext:
    status_time: str
    event_log: tuple[dict[str, Any], ...] = ()
    dependency_snapshot: dict[str, str] = field(default_factory=dict)
    observation_records: tuple[dict[str, Any], ...] = ()
    observation_policy: dict[str, Any] = field(default_factory=dict)
    frame: dict[str, Any] = field(default_factory=dict)
    completion_policy: dict[str, Any] = field(default_factory=dict)
    target_condition: dict[str, Any] = field(default_factory=dict)
    prefix_view: dict[str, Any] | None = None
    validity_status: str = "pass"
    completion_admission: dict[str, Any] | None = None
    fiber_assoc_view: dict[str, Any] | None = None
    adjudication_views: dict[str, str] = field(default_factory=dict)
    adequacy_direction: str = "unknown"
    confluence_proof: Any | None = None

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> StatusContext:
        return cls(
            status_time=str(source["status_time"]),
            event_log=tuple(dict(item) for item in source.get("event_log", ())),
            dependency_snapshot=dict(source.get("dependency_snapshot", {})),
            observation_records=tuple(dict(item) for item in source.get("observation_records", ())),
            observation_policy=dict(source.get("observation_policy", {})),
            frame=dict(source.get("frame", {})),
            completion_policy=dict(source.get("completion_policy", {})),
            target_condition=dict(source.get("target_condition", {})),
            prefix_view=dict(source["prefix_view"])
            if source.get("prefix_view") is not None
            else None,
            validity_status=str(source.get("validity_status", "pass")),
            completion_admission=dict(source["completion_admission"])
            if source.get("completion_admission") is not None
            else None,
            fiber_assoc_view=dict(source["fiber_assoc_view"])
            if source.get("fiber_assoc_view") is not None
            else None,
            adjudication_views=dict(source.get("adjudication_views", {})),
            adequacy_direction=str(source.get("adequacy_direction", "unknown")),
            confluence_proof=source.get("confluence_proof"),
        )


@dataclass(frozen=True, slots=True)
class StatusAuthorityView:
    certificate_id: str
    schema_profile_ref: str
    canonicalization_profile_ref: str
    manifest_digest: str
    validation_result: ValidationResult
    proposed_use: ProposedUse
    status_coordinates: tuple[StatusCoordinate, ...]
    blocking_set: tuple[BlockingRecord, ...]
    dominant_status: StatusCode
    kernel_verdict: VerdictCode | None
    authority_outcome: AuthorityOutcome
    status_observation_context_ref: str | None = None
    prefix_view_ref: str | None = None
    completion_admission_ref: str | None = None
    residual_context_ref: str | None = None
    validity_view_ref: str | None = None
    exact_fiber_assoc_ref: str | None = None
    fiber_assoc_view_ref: str | None = None
    adjudication_views_ref: str | None = None
    agreement_ref: str | None = None
    kernel_view_ref: str | None = None
    gate_decision_ref: str | None = None
    set_refs: tuple[str, ...] = ()
    set_ref_records: tuple[Any, ...] = ()
    guard_records: tuple[GuardRecord, ...] = ()
    artifact_refs: tuple[ArtifactRef, ...] = ()
    obligation_refs: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()
    proof_refs: tuple[str, ...] = ()
    proof_ref_records: tuple[Any, ...] = ()
    protocol_record_refs: tuple[str, ...] = ()
    ledger_entries: tuple[Any, ...] = ()
    stage_blockers: tuple[Any, ...] = ()

    def minimum_profile(self) -> dict[str, Any]:
        blocking_reason_refs = tuple(
            ref for block in self.blocking_set for ref in block.reason_refs
        )
        outcome_blocking_reason_refs = tuple(
            ref for block in self.authority_outcome.blocking_set for ref in block.reason_refs
        )
        reason_refs = _normalized_reason_refs(
            (
                *self.reason_refs,
                *blocking_reason_refs,
                *self.authority_outcome.reason_refs,
                *outcome_blocking_reason_refs,
            )
        )
        outcome_reason_refs = _normalized_reason_refs(
            (*self.authority_outcome.reason_refs, *outcome_blocking_reason_refs)
        )
        reason_ids = [ref.reason_id for ref in reason_refs]
        reason_records = [_reason_ref_record(ref) for ref in reason_refs]
        outcome_reason_records = [_reason_ref_record(ref) for ref in outcome_reason_refs]
        blocking_records = [_blocking_record_record(block) for block in self.blocking_set]
        outcome_blocking_records = [
            _blocking_record_record(block) for block in self.authority_outcome.blocking_set
        ]
        obligation_records = [
            _obligation_ref_record(ref, self.ledger_entries) for ref in self.obligation_refs
        ]
        proof_records = (
            [dict(record) for record in self.proof_ref_records]
            if self.proof_ref_records
            else [
                _proof_ref_record(ref, self.ledger_entries, self.artifact_refs)
                for ref in self.proof_refs
            ]
        )
        set_records = [_set_ref_record(record) for record in self.set_ref_records]
        if not set_records:
            set_records = [_legacy_set_ref_record(ref) for ref in self.set_refs]
        artifact_records = [_artifact_ref_record(ref) for ref in self.artifact_refs]
        return {
            "certificate_id": self.certificate_id,
            "schema_profile_ref": self.schema_profile_ref,
            "canonicalization_profile_ref": self.canonicalization_profile_ref,
            "manifest_digest": self.manifest_digest,
            "validation_result_ref": self.validation_result.status.value,
            "proposed_use_ref": self.proposed_use.mode,
            "fold_context_ref": "fold-context",
            "status_coordinates_ref": "status-coordinates",
            "blocking_set_ref": "blocking-set",
            "dominant_status": self.dominant_status.value,
            "status_observation_context_ref": self.status_observation_context_ref
            or "not-applicable",
            "prefix_view_ref": self.prefix_view_ref or "not-applicable",
            "completion_admission_ref": self.completion_admission_ref or "not-applicable",
            "residual_context_ref": self.residual_context_ref or "not-applicable",
            "validity_view_ref": self.validity_view_ref or "validity-view",
            "kernel_view_ref": self.kernel_view_ref
            or (f"kernel-view:{self.kernel_verdict.value}" if self.kernel_verdict else "not-run"),
            "exact_fiber_assoc_ref": self.exact_fiber_assoc_ref or "not-applicable",
            "fiber_assoc_view_ref": self.fiber_assoc_view_ref or "not-applicable",
            "adjudication_views_ref": self.adjudication_views_ref or "not-applicable",
            "agreement_ref": self.agreement_ref or "not-applicable",
            "gate_decision_ref": self.gate_decision_ref
            or self.authority_outcome.gate_decision.value,
            "authority_outcome": {
                "layer": self.authority_outcome.layer.value,
                "code": self.authority_outcome.code,
                "direction": self.authority_outcome.direction.value,
                "blocking_set_ref": "blocking-set",
                "gate_decision": self.authority_outcome.gate_decision.value,
                "gate_decision_ref": self.gate_decision_ref
                or self.authority_outcome.gate_decision.value,
                "profile_ref": self.authority_outcome.profile_ref,
                "outcome_schema_ref": self.authority_outcome.outcome_schema_ref,
                "issued_at_status_time": self.authority_outcome.issued_at_status_time,
                "reason_refs": [ref.reason_id for ref in outcome_reason_refs],
                "reason_ref_records": outcome_reason_records,
                "blocking_records": outcome_blocking_records,
            },
            "set_refs": list(self.set_refs),
            "set_ref_records": set_records,
            "artifact_refs": [ref.artifact_id for ref in self.artifact_refs],
            "artifact_ref_records": artifact_records,
            "obligation_refs": list(self.obligation_refs),
            "obligation_ref_records": obligation_records,
            "reason_refs": reason_ids,
            "reason_ref_records": reason_records,
            "blocking_records": blocking_records,
            "proof_refs": list(self.proof_refs),
            "proof_ref_records": proof_records,
            "protocol_record_refs": list(self.protocol_record_refs),
            "ledger_entries": [
                {
                    "kind": getattr(getattr(entry, "kind", None), "value", "unknown"),
                    "owner_artifact": str(getattr(entry, "owner_artifact", "")),
                    "owner_path": str(getattr(entry, "owner_path", "")),
                    "ref_value": str(getattr(entry, "ref_value", "")),
                    "target_artifact_id": str(getattr(entry, "target_artifact_id", "")),
                    "target_path": str(getattr(entry, "target_path", "")),
                    "resolved": bool(getattr(entry, "resolved", False)),
                    "expected_kind": str(
                        getattr(getattr(entry, "expected_kind", None), "value", "")
                    ),
                    "expected_semantic_role": str(
                        getattr(entry, "expected_semantic_role", "") or ""
                    ),
                    "expected_digest": str(getattr(entry, "expected_digest", "") or ""),
                    "required_stage": str(
                        getattr(getattr(entry, "required_stage", None), "value", "")
                    ),
                    "active_scope_status": str(
                        getattr(entry, "active_scope_status", "not_checked")
                    ),
                }
                for entry in self.ledger_entries
            ],
            "stage_blockers": [
                str(getattr(blocker, "block_id", getattr(blocker, "failure_id", "")))
                for blocker in self.stage_blockers
            ],
        }
