"""Evidence admission and dependency records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from dfcc.artifacts import (
    ArtifactRole,
    ObligationRefRecord,
    ReferenceKind,
    ReferenceLedgerEntry,
    manifest_digest,
)
from dfcc.time import parse_rfc3339
from dfcc.types import (
    FailureCode,
    Layer,
    ReasonRef,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    reason,
    validation_failure,
)


def _enum_value(enum_type: type[FailureCode] | type[Layer], value: Any, fallback: Any) -> Any:
    try:
        return enum_type(str(value))
    except ValueError:
        return fallback


def _reason_ref_from_json(item: Any, *, default_artifact: str, default_path: str) -> ReasonRef:
    if isinstance(item, Mapping):
        failure_code = _enum_value(
            FailureCode,
            item.get("failure_code", FailureCode.CHECKER_UNKNOWN.value),
            FailureCode.CHECKER_UNKNOWN,
        )
        layer = _enum_value(
            Layer,
            item.get("layer", Layer.INTEROP.value),
            Layer.INTEROP,
        )
        message = str(item.get("message", "accepted clause provenance"))
        return reason(
            failure_code,
            layer,
            message,
            source_artifact=str(item.get("source_artifact", default_artifact)),
            source_path=str(item.get("source_path", default_path)),
            reason_id=str(item["reason_id"]) if item.get("reason_id") is not None else None,
            digest=str(item["digest"]) if item.get("digest") is not None else None,
        )
    return reason(
        FailureCode.CHECKER_UNKNOWN,
        Layer.INTEROP,
        str(item),
        source_artifact=default_artifact,
        source_path=default_path,
    )


def _bound_reference_string(value: str | None) -> bool:
    if value is None:
        return False
    ref = str(value)
    base = ref.split("#", 1)[0]
    return base.startswith("artifact:") or ref.startswith(("sha256:", "sha384:", "sha512:"))


def _ledger_ref_required(ref_value: Any) -> bool:
    return isinstance(ref_value, str) and (
        "#" in ref_value or ref_value.startswith(("artifact:", "synthetic:"))
    )


def _ledger_ref_entry(
    entries: tuple[ReferenceLedgerEntry, ...], ref_value: Any
) -> ReferenceLedgerEntry | None:
    if not isinstance(ref_value, str) or not ref_value:
        return None
    artifact_id, _, pointer = ref_value.partition("#")
    for entry in entries:
        if not entry.resolved:
            continue
        if entry.ref_value == ref_value:
            return entry
        if entry.target_artifact_id == artifact_id and (
            not pointer or entry.target_path == pointer
        ):
            return entry
    return None


def _ledger_ref_problem(
    entries: tuple[ReferenceLedgerEntry, ...],
    ref_value: Any,
    *,
    expected_kind: ReferenceKind | None = None,
    expected_role: str | None = None,
    expected_digest: str | None = None,
) -> FailureCode | None:
    entry = _ledger_ref_entry(entries, ref_value)
    if entry is None:
        return FailureCode.MISSING_REF
    if expected_kind is not None and entry.kind is not expected_kind:
        typed_entry = next(
            (
                candidate
                for candidate in entries
                if candidate.resolved
                and candidate.kind is expected_kind
                and candidate.ref_value == ref_value
            ),
            None,
        )
        if typed_entry is None and isinstance(ref_value, str):
            artifact_id, _, pointer = ref_value.partition("#")
            typed_entry = next(
                (
                    candidate
                    for candidate in entries
                    if candidate.resolved
                    and candidate.kind is expected_kind
                    and candidate.target_artifact_id == artifact_id
                    and (not pointer or candidate.target_path == pointer)
                ),
                None,
            )
        if typed_entry is None:
            return FailureCode.ARTIFACT_CONFLICT
        entry = typed_entry
    if expected_role is not None and entry.semantic_role != expected_role:
        return FailureCode.ARTIFACT_CONFLICT
    if expected_digest is not None and entry.target_digest != expected_digest:
        return FailureCode.DIGEST_MISMATCH
    return None


def _ledger_ref_status(problem: FailureCode) -> ValidationStatus:
    return (
        ValidationStatus.CONFLICT
        if problem in {FailureCode.ARTIFACT_CONFLICT, FailureCode.DIGEST_MISMATCH}
        else ValidationStatus.UNKNOWN
    )


def _obligation_record_ref(record: ObligationRefRecord) -> str | None:
    if record.source_artifact is not None:
        return f"{record.source_artifact}#{record.source_path or ''}"
    if _bound_reference_string(record.obligation_id) or "#" in record.obligation_id:
        return record.obligation_id
    return None


def trust_assumption_result(
    source: Mapping[str, Any],
    entries: tuple[ReferenceLedgerEntry, ...],
    *,
    assumption_id: str,
    source_layer: Layer,
) -> ValidationResult | None:
    transcript_ref = source.get("checker_transcript_ref")
    if not _ledger_ref_required(transcript_ref):
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            f"trust assumption checker transcript is not ledger-addressed: {transcript_ref}",
            status=ValidationStatus.UNKNOWN,
            layer=source_layer,
            source_artifact=assumption_id,
            source_path="/checker_transcript_ref",
        )
    transcript_problem = _ledger_ref_problem(
        entries,
        transcript_ref,
        expected_kind=ReferenceKind.TRANSCRIPT,
    )
    if transcript_problem is not None:
        return validation_failure(
            transcript_problem,
            ValidationStage.GUARD_EVALUATE,
            f"trust assumption cannot resolve checker transcript: {transcript_ref}",
            status=_ledger_ref_status(transcript_problem),
            layer=source_layer,
            source_artifact=assumption_id,
            source_path="/checker_transcript_ref",
        )
    reason_record_failure = trust_assumption_reason_record_result(
        source,
        entries,
        assumption_id=assumption_id,
        source_layer=source_layer,
    )
    if reason_record_failure is not None:
        return reason_record_failure
    ref_fields = {
        "reason_refs": (ReferenceKind.REASON, ArtifactRole.REASON.value),
        "obligation_refs": (ReferenceKind.OBLIGATION, ArtifactRole.OBLIGATION.value),
    }
    for field_name, (expected_kind, expected_role) in ref_fields.items():
        values = tuple(source.get(field_name, ()))
        if not values:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.GUARD_EVALUATE,
                f"trust assumption lacks {field_name}",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=assumption_id,
                source_path=f"/{field_name}",
            )
        for index, ref_value in enumerate(values):
            if not _ledger_ref_required(ref_value):
                return validation_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    ValidationStage.GUARD_EVALUATE,
                    f"trust assumption {field_name} item is not ledger-addressed: {ref_value}",
                    status=ValidationStatus.UNKNOWN,
                    layer=source_layer,
                    source_artifact=assumption_id,
                    source_path=f"/{field_name}/{index}",
                )
            problem = _ledger_ref_problem(
                entries,
                ref_value,
                expected_kind=expected_kind,
                expected_role=expected_role,
            )
            if problem is not None:
                return validation_failure(
                    problem,
                    ValidationStage.GUARD_EVALUATE,
                    f"trust assumption cannot resolve matching {field_name}: {ref_value}",
                    status=_ledger_ref_status(problem),
                    layer=source_layer,
                    source_artifact=assumption_id,
                    source_path=f"/{field_name}/{index}",
                )
            if expected_kind is ReferenceKind.OBLIGATION:
                entry = _ledger_ref_entry(entries, ref_value)
                active_status = entry.active_scope_status if entry is not None else "not_checked"
                if active_status not in {"pass", "waived"}:
                    return validation_failure(
                        FailureCode.VALIDITY_UNKNOWN
                        if active_status in {"expired", "invalid"}
                        else FailureCode.CHECKER_UNKNOWN,
                        ValidationStage.GUARD_EVALUATE,
                        f"trust assumption obligation {ref_value} is {active_status}",
                        status=ValidationStatus.UNKNOWN,
                        layer=source_layer,
                        source_artifact=assumption_id,
                        source_path=f"/{field_name}/{index}",
                    )
    return None


def trust_assumption_reason_record_result(
    source: Mapping[str, Any],
    entries: tuple[ReferenceLedgerEntry, ...],
    *,
    assumption_id: str,
    source_layer: Layer,
) -> ValidationResult | None:
    records = source.get("reason_ref_records", ())
    if not isinstance(records, list | tuple):
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.GUARD_EVALUATE,
            "trust assumption reason_ref_records is not an array",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=source_layer,
            source_artifact=assumption_id,
            source_path="/reason_ref_records",
        )
    if source.get("reason_refs") and not records:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            "trust assumption reason refs lack typed reason records",
            status=ValidationStatus.UNKNOWN,
            layer=source_layer,
            source_artifact=assumption_id,
            source_path="/reason_ref_records",
        )
    for index, item in enumerate(records):
        if not isinstance(item, Mapping):
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.GUARD_EVALUATE,
                "trust assumption reason_ref_records item is not typed",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=source_layer,
                source_artifact=assumption_id,
                source_path=f"/reason_ref_records/{index}",
            )
        source_artifact = item.get("source_artifact")
        source_path = item.get("source_path")
        digest = item.get("digest")
        if (
            not isinstance(source_artifact, str)
            or not source_artifact
            or not isinstance(source_path, str)
            or not source_path.startswith("/")
            or not isinstance(digest, str)
            or not _bound_digest_string(digest)
        ):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.GUARD_EVALUATE,
                "trust assumption reason record lacks artifact, JSON Pointer, or digest evidence",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=assumption_id,
                source_path=f"/reason_ref_records/{index}",
            )
        reason_ref = f"{source_artifact}#{source_path}"
        problem = _ledger_ref_problem(
            entries,
            reason_ref,
            expected_kind=ReferenceKind.REASON,
            expected_role=ArtifactRole.REASON.value,
            expected_digest=digest,
        )
        if problem is not None:
            return validation_failure(
                problem,
                ValidationStage.GUARD_EVALUATE,
                f"trust assumption reason record is not ledger-resolved: {reason_ref}",
                status=_ledger_ref_status(problem),
                layer=source_layer,
                source_artifact=assumption_id,
                source_path=f"/reason_ref_records/{index}",
            )
    return None


def admission_contract_result(
    source: Mapping[str, Any],
    entries: tuple[ReferenceLedgerEntry, ...],
    *,
    contract_id: str,
    source_layer: Layer,
) -> ValidationResult | None:
    required_fields = ("kind", "source", "target", "clause", "checker_transcript_ref")
    for field_name in required_fields:
        if field_name not in source or source.get(field_name) is None:
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.SCHEMA_VALIDATE,
                f"admission contract lacks required field: {field_name}",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=source_layer,
                source_artifact=contract_id,
                source_path=f"/{field_name}",
            )
    if not isinstance(source.get("clause"), Mapping):
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.SCHEMA_VALIDATE,
            "admission contract clause is not an object",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=source_layer,
            source_artifact=contract_id,
            source_path="/clause",
        )
    transcript_ref = source.get("checker_transcript_ref")
    if not _ledger_ref_required(transcript_ref):
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            f"admission contract checker transcript is not ledger-addressed: {transcript_ref}",
            status=ValidationStatus.UNKNOWN,
            layer=source_layer,
            source_artifact=contract_id,
            source_path="/checker_transcript_ref",
        )
    transcript_problem = _ledger_ref_problem(
        entries,
        transcript_ref,
        expected_kind=ReferenceKind.TRANSCRIPT,
    )
    if transcript_problem is not None:
        return validation_failure(
            transcript_problem,
            ValidationStage.GUARD_EVALUATE,
            f"admission contract cannot resolve checker transcript: {transcript_ref}",
            status=_ledger_ref_status(transcript_problem),
            layer=source_layer,
            source_artifact=contract_id,
            source_path="/checker_transcript_ref",
        )
    obligation_refs = tuple(source.get("obligation_refs", ()))
    if not obligation_refs:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            "admission contract lacks ledger-backed obligation refs",
            status=ValidationStatus.UNKNOWN,
            layer=source_layer,
            source_artifact=contract_id,
            source_path="/obligation_refs",
        )
    for index, ref_value in enumerate(obligation_refs):
        if not _ledger_ref_required(ref_value):
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"admission contract obligation is not ledger-addressed: {ref_value}",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=contract_id,
                source_path=f"/obligation_refs/{index}",
            )
        problem = _ledger_ref_problem(
            entries,
            ref_value,
            expected_kind=ReferenceKind.OBLIGATION,
            expected_role=ArtifactRole.OBLIGATION.value,
        )
        if problem is not None:
            return validation_failure(
                problem,
                ValidationStage.GUARD_EVALUATE,
                f"admission contract cannot resolve matching obligation: {ref_value}",
                status=_ledger_ref_status(problem),
                layer=source_layer,
                source_artifact=contract_id,
                source_path=f"/obligation_refs/{index}",
            )
        entry = _ledger_ref_entry(entries, ref_value)
        active_status = entry.active_scope_status if entry is not None else "not_checked"
        if active_status not in {"pass", "waived"}:
            return validation_failure(
                FailureCode.VALIDITY_UNKNOWN
                if active_status in {"expired", "invalid"}
                else FailureCode.CHECKER_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"admission contract obligation {ref_value} is {active_status}",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=contract_id,
                source_path=f"/obligation_refs/{index}",
            )
    monitor_ref_fields = {
        "monitor_evidence_ref": (ReferenceKind.ARTIFACT, ArtifactRole.EVIDENCE.value),
        "monitor_completeness_ref": (ReferenceKind.ARTIFACT, "proof"),
    }
    monitor_obligations = tuple(source.get("monitor_obligations", ()))
    monitor_refs = tuple(
        (field_name, source.get(field_name))
        for field_name in monitor_ref_fields
        if isinstance(source.get(field_name), str) and source.get(field_name)
    )
    if monitor_obligations and not monitor_refs:
        return validation_failure(
            FailureCode.VALIDITY_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            "admission contract monitor obligations lack monitor evidence",
            status=ValidationStatus.UNKNOWN,
            layer=source_layer,
            source_artifact=contract_id,
            source_path="/monitor_obligations",
        )
    for field_name, ref_value in monitor_refs:
        expected_kind, expected_role = monitor_ref_fields[field_name]
        if not _ledger_ref_required(ref_value):
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"admission contract {field_name} is not ledger-addressed: {ref_value}",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=contract_id,
                source_path=f"/{field_name}",
            )
        problem = _ledger_ref_problem(
            entries,
            ref_value,
            expected_kind=expected_kind,
            expected_role=expected_role,
        )
        if problem is not None:
            return validation_failure(
                problem,
                ValidationStage.GUARD_EVALUATE,
                f"admission contract cannot resolve matching {field_name}: {ref_value}",
                status=_ledger_ref_status(problem),
                layer=source_layer,
                source_artifact=contract_id,
                source_path=f"/{field_name}",
            )
    return None


def _bound_digest_string(value: str | None) -> bool:
    if value is None:
        return False
    return str(value).startswith(("sha256:", "sha384:", "sha512:"))


def accepted_clause_obligation_record_result(
    source: Mapping[str, Any],
    entries: tuple[ReferenceLedgerEntry, ...],
    *,
    clause_id: str,
    source_layer: Layer,
    status_time: str | None = None,
) -> ValidationResult | None:
    records = source.get("obligation_ref_records", ())
    if not isinstance(records, list | tuple):
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause obligation_ref_records is not an array",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=source_layer,
            source_artifact=clause_id,
            source_path="/obligation_ref_records",
        )
    if source.get("obligation_refs") and not records:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause obligation refs lack typed obligation records",
            status=ValidationStatus.UNKNOWN,
            layer=source_layer,
            source_artifact=clause_id,
            source_path="/obligation_ref_records",
        )
    for index, item in enumerate(records):
        if not isinstance(item, Mapping):
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.GUARD_EVALUATE,
                "accepted clause obligation_ref_records item is not typed",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=source_layer,
                source_artifact=clause_id,
                source_path=f"/obligation_ref_records/{index}",
            )
        obligation = ObligationRefRecord.from_json(item)
        active_status = obligation.active_scope_status_at(status_time)
        if active_status not in {"pass", "waived"}:
            return validation_failure(
                FailureCode.VALIDITY_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause obligation {obligation.obligation_id} is {active_status}",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=clause_id,
                source_path=f"/obligation_ref_records/{index}/status",
            )
        record_ref = _obligation_record_ref(obligation)
        if record_ref is None:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.GUARD_EVALUATE,
                "accepted clause obligation record lacks artifact-bound source",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=clause_id,
                source_path=f"/obligation_ref_records/{index}",
            )
        if active_status == "pass" and (
            obligation.source_artifact is None
            or not obligation.source_artifact.startswith("artifact:")
            or not str(obligation.source_path or "").startswith("/")
            or not _bound_digest_string(obligation.digest)
        ):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.GUARD_EVALUATE,
                "accepted clause pass obligation lacks artifact, pointer, or digest evidence",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=clause_id,
                source_path=f"/obligation_ref_records/{index}",
            )
        problem = _ledger_ref_problem(
            entries,
            record_ref,
            expected_kind=ReferenceKind.OBLIGATION,
            expected_role=ArtifactRole.OBLIGATION.value,
            expected_digest=obligation.digest,
        )
        if problem is not None:
            return validation_failure(
                problem,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause obligation record is not ledger-resolved: {record_ref}",
                status=(
                    ValidationStatus.CONFLICT
                    if problem in {FailureCode.ARTIFACT_CONFLICT, FailureCode.DIGEST_MISMATCH}
                    else ValidationStatus.UNKNOWN
                ),
                layer=source_layer,
                source_artifact=clause_id,
                source_path=f"/obligation_ref_records/{index}",
            )
        if obligation.status == "waived":
            for reason_index, reason_ref in enumerate(obligation.reason_refs):
                problem = _ledger_ref_problem(
                    entries,
                    reason_ref,
                    expected_kind=ReferenceKind.REASON,
                    expected_role=ArtifactRole.REASON.value,
                )
                if problem is not None:
                    return validation_failure(
                        problem,
                        ValidationStage.GUARD_EVALUATE,
                        "accepted clause waived obligation reason is not ledger-resolved",
                        status=(
                            ValidationStatus.CONFLICT
                            if problem is FailureCode.ARTIFACT_CONFLICT
                            else ValidationStatus.UNKNOWN
                        ),
                        layer=source_layer,
                        source_artifact=clause_id,
                        source_path=(f"/obligation_ref_records/{index}/reason_refs/{reason_index}"),
                    )
    return None


def accepted_clause_reason_record_result(
    source: Mapping[str, Any],
    entries: tuple[ReferenceLedgerEntry, ...],
    *,
    clause_id: str,
    source_layer: Layer,
) -> ValidationResult | None:
    records = source.get("reason_refs", ())
    if not isinstance(records, list | tuple):
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause reason_refs is not an array",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=source_layer,
            source_artifact=clause_id,
            source_path="/reason_refs",
        )
    if not records:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause lacks typed reason refs",
            status=ValidationStatus.UNKNOWN,
            layer=source_layer,
            source_artifact=clause_id,
            source_path="/reason_refs",
        )
    for index, item in enumerate(records):
        if not isinstance(item, Mapping):
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.GUARD_EVALUATE,
                "accepted clause reason_refs item is not typed",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=source_layer,
                source_artifact=clause_id,
                source_path=f"/reason_refs/{index}",
            )
        source_artifact = item.get("source_artifact")
        source_path = item.get("source_path")
        digest = item.get("digest")
        if (
            not isinstance(source_artifact, str)
            or not source_artifact
            or not isinstance(source_path, str)
            or not source_path.startswith("/")
            or not isinstance(digest, str)
            or not _bound_digest_string(digest)
        ):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.GUARD_EVALUATE,
                "accepted clause reason ref lacks artifact, JSON Pointer, or digest evidence",
                status=ValidationStatus.UNKNOWN,
                layer=source_layer,
                source_artifact=clause_id,
                source_path=f"/reason_refs/{index}",
            )
        reason_ref = f"{source_artifact}#{source_path}"
        problem = _ledger_ref_problem(
            entries,
            reason_ref,
            expected_kind=ReferenceKind.REASON,
            expected_role=ArtifactRole.REASON.value,
            expected_digest=digest,
        )
        if problem is not None:
            return validation_failure(
                problem,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause reason record is not ledger-resolved: {reason_ref}",
                status=_ledger_ref_status(problem),
                layer=source_layer,
                source_artifact=clause_id,
                source_path=f"/reason_refs/{index}",
            )
    return None


@dataclass(frozen=True, slots=True)
class EvidenceArtifact:
    artifact_id: str
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    artifact_refs: tuple[str, ...] = ()
    checker_status: str = "unchecked"
    reason_refs: tuple[ReasonRef, ...] = ()

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> EvidenceArtifact:
        return cls(
            artifact_id=str(source["artifact_id"]),
            kind=str(source.get("kind", "unknown")),
            payload=dict(source.get("payload", {})),
            artifact_refs=tuple(str(item) for item in source.get("artifact_refs", ())),
            checker_status=str(source.get("checker_status", "unchecked")),
        )


@dataclass(frozen=True, slots=True)
class AdmissionContract:
    kind: str
    source: str
    target: str
    clause: dict[str, Any]
    scope: tuple[str, ...] = ()
    horizon: int | None = None
    frame: str | None = None
    validity: dict[str, Any] = field(default_factory=dict)
    checker: str = "policy"
    limits: dict[str, Any] = field(default_factory=dict)
    failure: str = "unknown"
    contract_id: str | None = None
    uncertainty_model: str | None = None
    expiry_rule: str | None = None
    monitor_obligations: tuple[str, ...] = ()
    obligation_refs: tuple[str, ...] = ()
    reason_ref_ids: tuple[str, ...] = ()
    checker_transcript_ref: str | None = None
    reference_digest: str | None = None
    monitor_evidence_ref: str | None = None
    monitor_completeness_ref: str | None = None

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> AdmissionContract:
        return cls(
            kind=str(source["kind"]),
            source=str(source["source"]),
            target=str(source["target"]),
            clause=dict(source.get("clause", {})),
            scope=tuple(str(item) for item in source.get("scope", ())),
            horizon=int(source["horizon"]) if source.get("horizon") is not None else None,
            frame=str(source["frame"]) if source.get("frame") is not None else None,
            validity=dict(source.get("validity", {})),
            checker=str(source.get("checker", "policy")),
            limits=dict(source.get("limits", {})),
            failure=str(source.get("failure", "unknown")),
            contract_id=str(source["contract_id"])
            if source.get("contract_id") is not None
            else None,
            uncertainty_model=str(source["uncertainty_model"])
            if source.get("uncertainty_model") is not None
            else None,
            expiry_rule=str(source["expiry_rule"])
            if source.get("expiry_rule") is not None
            else None,
            monitor_obligations=tuple(str(item) for item in source.get("monitor_obligations", ())),
            obligation_refs=tuple(str(item) for item in source.get("obligation_refs", ())),
            reason_ref_ids=tuple(str(item) for item in source.get("reason_refs", ())),
            checker_transcript_ref=str(source["checker_transcript_ref"])
            if source.get("checker_transcript_ref") is not None
            else None,
            reference_digest=str(source["reference_digest"])
            if source.get("reference_digest") is not None
            else None,
            monitor_evidence_ref=str(source["monitor_evidence_ref"])
            if source.get("monitor_evidence_ref") is not None
            else None,
            monitor_completeness_ref=str(source["monitor_completeness_ref"])
            if source.get("monitor_completeness_ref") is not None
            else None,
        )


@dataclass(frozen=True, slots=True)
class AcceptedClause:
    clause_id: str
    target: str
    clause: dict[str, Any]
    evidence_ref: str
    contract_ref: str
    checker_transcript_ref: str
    obligation_refs: tuple[str, ...]
    obligation_ref_records: tuple[ObligationRefRecord, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()
    validity_status: str = "pass"
    monitor_status: str = "pass"
    monitor_evidence_ref: str | None = None
    monitor_completeness_ref: str | None = None

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> AcceptedClause:
        reason_refs = tuple(
            _reason_ref_from_json(
                item,
                default_artifact=str(source.get("clause_id", "accepted-clause")),
                default_path=f"/reason_refs/{index}",
            )
            for index, item in enumerate(source.get("reason_refs", ()))
        )
        return cls(
            clause_id=str(source["clause_id"]),
            target=str(source["target"]),
            clause=dict(source.get("clause", {})),
            evidence_ref=str(source["evidence_ref"]),
            contract_ref=str(source["contract_ref"]),
            checker_transcript_ref=str(source["checker_transcript_ref"]),
            obligation_refs=tuple(
                (
                    f"{item.get('source_artifact')}#{item.get('source_path', '')}"
                    if isinstance(item, Mapping) and item.get("source_artifact") is not None
                    else str(item)
                )
                for item in source.get("obligation_refs", ())
            ),
            obligation_ref_records=tuple(
                ObligationRefRecord.from_json(item)
                for item in source.get("obligation_ref_records", ())
                if isinstance(item, Mapping)
            ),
            reason_refs=reason_refs
            or (
                reason(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.INTEROP,
                    "accepted clause artifact lacks explicit reason refs",
                    source_artifact=str(source["clause_id"]),
                    source_path="/reason_refs",
                ),
            ),
            validity_status=str(source.get("validity_status", "pass")),
            monitor_status=str(source.get("monitor_status", "pass")),
            monitor_evidence_ref=str(source["monitor_evidence_ref"])
            if source.get("monitor_evidence_ref") is not None
            else None,
            monitor_completeness_ref=str(source["monitor_completeness_ref"])
            if source.get("monitor_completeness_ref") is not None
            else None,
        )


@dataclass(frozen=True, slots=True)
class TrustAssumption:
    assumption_id: str
    target: str
    scope: tuple[str, ...]
    reason_refs: tuple[ReasonRef, ...]
    reason_ref_records: tuple[ReasonRef, ...] = ()
    obligation_refs: tuple[str, ...] = ()
    checker_transcript_ref: str = "artifact:trust-assumption-transcript"

    @classmethod
    def raw_bundle(
        cls, *, target: str = "semantics", source_artifact: str = "bundle"
    ) -> TrustAssumption:
        message = "legacy raw assumption bundle is admitted by explicit trust assumption"
        ref = reason(
            FailureCode.CHECKER_UNKNOWN,
            Layer.ISSUE,
            message,
            source_artifact=source_artifact,
            source_path="/bundle_source",
            digest=manifest_digest(
                message,
                artifact_type="reference-target",
                schema_profile_digest="DFCC-Interop",
            ),
        )
        return cls(
            assumption_id=f"trust:{target}:raw-bundle",
            target=target,
            scope=("legacy-raw-bundle",),
            reason_refs=(ref,),
            reason_ref_records=(ref,),
            obligation_refs=("trust-assumption:raw-bundle",),
        )

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> TrustAssumption:
        reason_ref_records = tuple(
            _reason_ref_from_json(
                item,
                default_artifact=str(source.get("assumption_id", "trust")),
                default_path=f"/reason_ref_records/{index}",
            )
            for index, item in enumerate(source.get("reason_ref_records", ()))
        )
        reason_refs = tuple(
            _reason_ref_from_json(
                item,
                default_artifact=str(source.get("assumption_id", "trust")),
                default_path=f"/reason_refs/{index}",
            )
            for index, item in enumerate(source.get("reason_refs", ()))
        )
        return cls(
            assumption_id=str(source["assumption_id"]),
            target=str(source.get("target", "semantics")),
            scope=tuple(str(item) for item in source.get("scope", ())),
            reason_refs=reason_ref_records
            or reason_refs
            or cls.raw_bundle(
                target=str(source.get("target", "semantics")),
                source_artifact=str(source["assumption_id"]),
            ).reason_refs,
            reason_ref_records=reason_ref_records,
            obligation_refs=tuple(str(item) for item in source.get("obligation_refs", ())),
            checker_transcript_ref=str(
                source.get("checker_transcript_ref", "artifact:trust-assumption-transcript")
            ),
        )


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    status: str
    accepted_clauses: tuple[dict[str, Any], ...] = ()
    accepted_clause_records: tuple[AcceptedClause, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status == "pass"


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    source: str
    target: str
    relation: str
    freshness_seconds: int | None = None
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class DependencyGraph:
    graph_id: str
    vertices: tuple[str, ...] = ()
    edges: tuple[DependencyEdge, ...] = ()

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> DependencyGraph:
        return cls(
            graph_id=str(source.get("graph_id", "dependency-graph")),
            vertices=tuple(str(item) for item in source.get("vertices", ())),
            edges=tuple(
                DependencyEdge(
                    source=str(edge["source"]),
                    target=str(edge["target"]),
                    relation=str(edge["relation"]),
                    freshness_seconds=int(edge["freshness_seconds"])
                    if edge.get("freshness_seconds") is not None
                    else None,
                )
                for edge in source.get("edges", ())
            ),
        )


@dataclass(frozen=True, slots=True)
class ValidityView:
    validity_status: str
    requirement_set: tuple[str, ...] = ()
    validity_clauses: tuple[dict[str, Any], ...] = ()
    validity_reason: str | None = None
    reason_refs: tuple[ReasonRef, ...] = ()


def _validity_active(validity: Mapping[str, Any], status_time: str | None) -> bool:
    if status_time is None:
        return True
    not_before = validity.get("not_before")
    expiry = validity.get("expiry")
    current = parse_rfc3339(status_time)
    if not_before is not None and current < parse_rfc3339(str(not_before)):
        return False
    return not (expiry is not None and current > parse_rfc3339(str(expiry)))


def admit_evidence(
    evidence: EvidenceArtifact | Mapping[str, Any],
    admission_contract: AdmissionContract | Mapping[str, Any],
    policy: Mapping[str, Any] | None = None,
) -> AdmissionResult:
    """Apply an admission contract; raw evidence never changes semantics directly."""

    evidence_obj = (
        evidence if isinstance(evidence, EvidenceArtifact) else EvidenceArtifact.from_json(evidence)
    )
    contract = (
        admission_contract
        if isinstance(admission_contract, AdmissionContract)
        else AdmissionContract.from_json(admission_contract)
    )
    policy = policy or {}
    status_time = str(policy["status_time"]) if policy.get("status_time") is not None else None

    if evidence_obj.artifact_id != contract.source or evidence_obj.kind != contract.kind:
        ref = reason(
            FailureCode.MISSING_REF,
            Layer.VALIDATION,
            "evidence artifact does not match admission contract source or kind",
            source_artifact=evidence_obj.artifact_id,
            source_path="/source",
        )
        return AdmissionResult(
            "unknown", evidence_refs=(evidence_obj.artifact_id,), reason_refs=(ref,)
        )
    if evidence_obj.checker_status not in {"pass", "accepted"}:
        ref = reason(
            FailureCode.CHECKER_UNKNOWN,
            Layer.VALIDATION,
            f"evidence checker status is {evidence_obj.checker_status}",
            source_artifact=evidence_obj.artifact_id,
            source_path="/checker_status",
        )
        return AdmissionResult(
            "unknown", evidence_refs=(evidence_obj.artifact_id,), reason_refs=(ref,)
        )
    checker_transcript_ref = contract.checker_transcript_ref
    if not _bound_reference_string(checker_transcript_ref):
        ref = reason(
            FailureCode.CHECKER_UNKNOWN,
            Layer.VALIDATION,
            "admission contract lacks artifact-bound checker transcript reference",
            source_artifact=evidence_obj.artifact_id,
            source_path="/checker_transcript_ref",
        )
        return AdmissionResult(
            "unknown", evidence_refs=(evidence_obj.artifact_id,), reason_refs=(ref,)
        )
    assert checker_transcript_ref is not None
    if contract.reference_digest is not None:
        accepted_digests = {
            str(evidence_obj.payload.get("digest", "")),
            *evidence_obj.artifact_refs,
        }
        if contract.reference_digest not in accepted_digests:
            ref = reason(
                FailureCode.DIGEST_MISMATCH,
                Layer.VALIDATION,
                "admission contract reference digest is not present in evidence",
                source_artifact=evidence_obj.artifact_id,
                source_path="/reference_digest",
            )
            return AdmissionResult(
                "unknown", evidence_refs=(evidence_obj.artifact_id,), reason_refs=(ref,)
            )
    if not _validity_active(contract.validity, status_time):
        ref = reason(
            FailureCode.VALIDITY_UNKNOWN,
            Layer.STATUS,
            "admission contract is outside its validity interval",
            source_artifact=evidence_obj.artifact_id,
            source_path="/validity",
        )
        return AdmissionResult(
            "unknown", evidence_refs=(evidence_obj.artifact_id,), reason_refs=(ref,)
        )
    if contract.expiry_rule == "requires-status-time" and status_time is None:
        ref = reason(
            FailureCode.VALIDITY_UNKNOWN,
            Layer.STATUS,
            "admission contract requires an explicit status time",
            source_artifact=evidence_obj.artifact_id,
            source_path="/expiry_rule",
        )
        return AdmissionResult(
            "unknown", evidence_refs=(evidence_obj.artifact_id,), reason_refs=(ref,)
        )
    monitor_status = str(policy.get("monitor_status", "pass"))
    if monitor_status != "pass":
        ref = reason(
            FailureCode.VALIDITY_UNKNOWN,
            Layer.STATUS,
            f"monitor status is {monitor_status}",
            source_artifact=evidence_obj.artifact_id,
            source_path="/monitor_status",
        )
        return AdmissionResult(
            "unknown", evidence_refs=(evidence_obj.artifact_id,), reason_refs=(ref,)
        )
    monitor_evidence_ref = (
        str(policy["monitor_evidence_ref"])
        if policy.get("monitor_evidence_ref") is not None
        else contract.monitor_evidence_ref
    )
    monitor_completeness_ref = (
        str(policy["monitor_completeness_ref"])
        if policy.get("monitor_completeness_ref") is not None
        else contract.monitor_completeness_ref
    )
    if contract.monitor_obligations and not (monitor_evidence_ref or monitor_completeness_ref):
        ref = reason(
            FailureCode.VALIDITY_UNKNOWN,
            Layer.STATUS,
            "monitor obligations require monitor evidence or completeness reference",
            source_artifact=evidence_obj.artifact_id,
            source_path="/monitor_obligations",
        )
        return AdmissionResult(
            "unknown", evidence_refs=(evidence_obj.artifact_id,), reason_refs=(ref,)
        )

    obligation_refs = (
        *contract.obligation_refs,
        *contract.monitor_obligations,
        *tuple(str(item) for item in contract.limits.get("obligations", ())),
    )
    if not obligation_refs:
        obligation_refs = ("obligation:admission-contract",)
    clause_reason = reason(
        FailureCode.CHECKER_UNKNOWN,
        Layer.INTEROP,
        "accepted clause provenance",
        source_artifact=evidence_obj.artifact_id,
        source_path="/payload",
        digest=manifest_digest(
            evidence_obj.payload,
            artifact_type="reference-target",
            schema_profile_digest="DFCC-Interop",
        ),
    )
    accepted = AcceptedClause(
        clause_id=f"accepted:{contract.target}",
        target=contract.target,
        clause=dict(contract.clause),
        evidence_ref=evidence_obj.artifact_id,
        contract_ref=contract.contract_id or f"contract:{contract.source}:{contract.target}",
        checker_transcript_ref=checker_transcript_ref,
        obligation_refs=obligation_refs,
        obligation_ref_records=(),
        reason_refs=(clause_reason,),
        validity_status="pass",
        monitor_status=monitor_status,
        monitor_evidence_ref=monitor_evidence_ref,
        monitor_completeness_ref=monitor_completeness_ref,
    )

    return AdmissionResult(
        "pass",
        accepted_clauses=(contract.clause,),
        accepted_clause_records=(accepted,),
        evidence_refs=(evidence_obj.artifact_id,),
        reason_refs=accepted.reason_refs,
    )


def admit_evidence_set(
    evidence_artifacts: tuple[EvidenceArtifact, ...],
    contracts: tuple[AdmissionContract, ...],
    policy: Mapping[str, Any] | None = None,
) -> tuple[AdmissionResult, ...]:
    by_id = {artifact.artifact_id: artifact for artifact in evidence_artifacts}
    results: list[AdmissionResult] = []
    for contract in contracts:
        evidence = by_id.get(contract.source)
        if evidence is None:
            ref = reason(
                FailureCode.MISSING_REF,
                Layer.VALIDATION,
                "admission source evidence is missing",
                source_path="/source",
            )
            results.append(AdmissionResult("unknown", reason_refs=(ref,)))
            continue
        results.append(admit_evidence(evidence, contract, policy))
    return tuple(results)


def validity_view(
    bundle: Mapping[str, Any],
    observation_cut: Mapping[str, Any] | None,
    dependency_snapshot: Mapping[str, str],
    frame: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> ValidityView:
    del observation_cut, frame
    requirements = tuple(str(item) for item in bundle.get("validity", {}).get("requirements", ()))
    missing = tuple(req for req in requirements if req not in dependency_snapshot)
    if policy.get("validity_status") == "conflict":
        ref = reason(FailureCode.VALIDITY_CONFLICT, Layer.STATUS, "validity policy is conflict")
        return ValidityView("conflict", requirements, validity_reason="policy", reason_refs=(ref,))
    if missing:
        ref = reason(
            FailureCode.VALIDITY_UNKNOWN,
            Layer.STATUS,
            f"missing dependency requirements: {', '.join(missing)}",
            source_path="/dependency_snapshot",
        )
        return ValidityView(
            "unknown", requirements, validity_reason="missing dependency", reason_refs=(ref,)
        )
    return ValidityView("pass", requirements)
