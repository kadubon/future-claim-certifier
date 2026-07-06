"""DFCC validation pipeline."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, overload

from dfcc.artifacts import (
    ArtifactBundle,
    ArtifactEntry,
    ArtifactRef,
    ArtifactRole,
    ArtifactStore,
    ReferenceResolutionContext,
    ResolvedReference,
    manifest_digest,
    resolve_reference,
    validate_artifact_ref,
    validate_manifest_dependencies,
)
from dfcc.backend import DFCCChecker, ReferenceChecker
from dfcc.canonical import CanonicalizationError, canonical_bytes
from dfcc.profiles import resolve_profile
from dfcc.records import (
    IntervalRecord,
    ScalarRecord,
    SetRef,
    TimestampRecord,
    validate_interval_record,
    validate_scalar_record,
    validate_set_ref,
    validate_timestamp_record,
)
from dfcc.schema import validate_named_schema
from dfcc.serialization import to_jsonable
from dfcc.types import (
    FailureCode,
    Layer,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    pass_validation,
    validation_failure,
)


def _reason_ref_record(ref: Any) -> dict[str, Any]:
    return {
        "reason_id": getattr(ref, "reason_id", str(ref)),
        "failure_code": getattr(getattr(ref, "failure_code", None), "value", "checker_unknown"),
        "layer": getattr(getattr(ref, "layer", None), "value", "validation"),
        "source_artifact": getattr(ref, "source_artifact", "inline"),
        "source_path": getattr(ref, "source_path", ""),
        "message": getattr(ref, "message", str(ref)),
        "digest": getattr(ref, "digest", None),
    }


def _proof_ref_id(ref: Any) -> str:
    return str(getattr(ref, "proof_id", ref))


def _proof_ref_record(ref: Any) -> dict[str, Any]:
    return {
        "proof_id": _proof_ref_id(ref),
        "proof_kind": str(getattr(ref, "proof_kind", "unknown")),
        "artifact_ref": getattr(ref, "artifact_ref", None),
        "source_artifact": getattr(ref, "source_artifact", None),
        "source_path": str(getattr(ref, "source_path", "")),
        "digest": getattr(ref, "digest", None),
        "status": str(getattr(ref, "status", "unknown")),
    }


def _failure_record_record(record: Any) -> dict[str, Any]:
    reason_refs = tuple(getattr(record, "reason_refs", ()))
    return {
        "failure_id": getattr(record, "failure_id", str(record)),
        "code": getattr(getattr(record, "code", None), "value", "checker_unknown"),
        "layer": getattr(getattr(record, "layer", None), "value", "validation"),
        "stage": getattr(getattr(record, "stage", None), "value", "AuthorityEmit"),
        "severity": getattr(record, "severity", "error"),
        "blocking": bool(getattr(record, "blocking", True)),
        "remediation": getattr(record, "remediation", None),
        "reason_refs": [getattr(ref, "reason_id", str(ref)) for ref in reason_refs],
        "reason_ref_records": [_reason_ref_record(ref) for ref in reason_refs],
    }


def _validation_result_record(result: ValidationResult) -> dict[str, Any]:
    reason_refs = tuple(
        dict.fromkeys(
            (
                *result.reason_refs,
                *(ref for failure in result.failure_records for ref in failure.reason_refs),
            )
        )
    )
    return {
        "stage": result.stage.value,
        "status": result.status.value,
        "failure_records": [_failure_record_record(record) for record in result.failure_records],
        "artifact_refs": list(result.artifact_refs),
        "reason_refs": [getattr(ref, "reason_id", str(ref)) for ref in reason_refs],
        "reason_ref_records": [_reason_ref_record(ref) for ref in reason_refs],
    }


def _bundle_reason_digest_index(bundle: ArtifactBundle) -> dict[str, str]:
    index: dict[str, str] = {}
    bundle_digest = bundle.manifest.manifest_digest
    if bundle_digest is None:
        bundle_digest = manifest_digest(
            _manifest_identity(bundle),
            artifact_type="manifest",
            schema_profile_digest="DFCC-Interop",
            dependencies=bundle.manifest.artifact_refs,
        )
    index[bundle.bundle_id] = bundle_digest
    index[bundle.manifest.manifest_id] = bundle_digest
    for ref in bundle.manifest.artifact_refs:
        if ref.digest_value:
            index[ref.artifact_id] = ref.digest_value
    for entry in bundle.entries:
        digest = entry.artifact_ref.digest_value or index.get(entry.artifact_ref.artifact_id)
        if not digest:
            continue
        index[entry.artifact_ref.artifact_id] = digest
        if entry.role is ArtifactRole.STATUS_CONTEXT:
            index.setdefault("policy", digest)
            index.setdefault("status_context", digest)
        if entry.role is ArtifactRole.ISSUE_CERTIFICATE:
            index.setdefault("issue-certificate", digest)
        _index_nested_protocol_ids(index, entry.artifact, digest)
    return index


def _index_nested_protocol_ids(index: dict[str, str], value: Any, digest: str) -> None:
    if isinstance(value, Mapping):
        for field_name in (
            "artifact_id",
            "certificate_id",
            "claim_id",
            "clause_id",
            "bundle_id",
            "event_id",
            "reason_id",
            "block_id",
        ):
            field_value = value.get(field_name)
            if isinstance(field_value, str) and field_value:
                index[field_value] = digest
        for item in value.values():
            _index_nested_protocol_ids(index, item, digest)
    elif isinstance(value, list | tuple):
        for item in value:
            _index_nested_protocol_ids(index, item, digest)


def _bind_reason_digest(ref: Any, index: Mapping[str, str]) -> Any:
    if getattr(ref, "digest", None):
        return ref
    digest = index.get(str(getattr(ref, "source_artifact", "")))
    if digest is None:
        return ref
    return replace(ref, digest=digest)


def _bind_failure_digest(record: Any, index: Mapping[str, str]) -> Any:
    reason_refs = tuple(getattr(record, "reason_refs", ()))
    if not reason_refs:
        return record
    return replace(
        record,
        reason_refs=tuple(_bind_reason_digest(ref, index) for ref in reason_refs),
    )


def _bind_blocking_digest(record: Any, index: Mapping[str, str]) -> Any:
    reason_refs = tuple(getattr(record, "reason_refs", ()))
    if not reason_refs:
        return record
    return replace(
        record,
        reason_refs=tuple(_bind_reason_digest(ref, index) for ref in reason_refs),
    )


def _bind_validation_result_digest(
    result: ValidationResult, index: Mapping[str, str]
) -> ValidationResult:
    return replace(
        result,
        failure_records=tuple(
            _bind_failure_digest(record, index) for record in result.failure_records
        ),
        reason_refs=tuple(_bind_reason_digest(ref, index) for ref in result.reason_refs),
    )


def _bind_authority_view_digest(view: Any, index: Mapping[str, str]) -> Any:
    if view is None:
        return None
    outcome = view.authority_outcome
    outcome = replace(
        outcome,
        blocking_set=tuple(_bind_blocking_digest(block, index) for block in outcome.blocking_set),
        reason_refs=tuple(_bind_reason_digest(ref, index) for ref in outcome.reason_refs),
    )
    return replace(
        view,
        validation_result=_bind_validation_result_digest(view.validation_result, index),
        blocking_set=tuple(_bind_blocking_digest(block, index) for block in view.blocking_set),
        authority_outcome=outcome,
        status_coordinates=tuple(
            replace(
                coordinate,
                reason_refs=tuple(
                    _bind_reason_digest(ref, index) for ref in coordinate.reason_refs
                ),
            )
            for coordinate in view.status_coordinates
        ),
        guard_records=tuple(
            replace(
                guard,
                reason_refs=tuple(_bind_reason_digest(ref, index) for ref in guard.reason_refs),
            )
            for guard in view.guard_records
        ),
        reason_refs=tuple(_bind_reason_digest(ref, index) for ref in view.reason_refs),
        stage_blockers=tuple(_bind_failure_digest(record, index) for record in view.stage_blockers),
    )


@dataclass(frozen=True, slots=True)
class PipelineReport:
    bundle_id: str
    profile: str
    stage_results: tuple[ValidationResult, ...]
    resolved_refs: tuple[ResolvedReference, ...] = ()
    resolved_obligations: tuple[ResolvedReference, ...] = ()
    resolved_reason_refs: tuple[ResolvedReference, ...] = ()
    unresolved_refs: tuple[tuple[str, str], ...] = ()
    ledger_entries: tuple[Any, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    artifact_ref_records: tuple[ArtifactRef, ...] = ()
    accepted_clause_records: tuple[Any, ...] = ()
    trust_assumptions: tuple[Any, ...] = ()
    compiled_bundle_ref: str | None = None
    guard_records: tuple[Any, ...] = ()
    proof_refs: tuple[Any, ...] = ()
    authority_runtime_summary: dict[str, Any] | None = None
    stage_artifacts: dict[str, tuple[str, ...]] = field(default_factory=dict)
    protocol_records: tuple[Any, ...] = ()
    replay_trace: dict[str, Any] | None = None
    kernel_view_ref: str | None = None
    observation_context_ref: str | None = None
    agreement_ref: str | None = None
    runtime_summary_digest: str | None = None
    failure_records: tuple[Any, ...] = ()
    reason_refs: tuple[Any, ...] = ()
    stage_blockers: tuple[Any, ...] = ()
    authority_view: Any | None = None
    authority_outcome_digest: str | None = None

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.stage_results)

    @property
    def final_result(self) -> ValidationResult:
        for result in self.stage_results:
            if not result.passed:
                return result
        return pass_validation(ValidationStage.AUTHORITY_EMIT)

    def to_json(self) -> dict[str, Any]:
        reason_refs = tuple(
            dict.fromkeys(
                (
                    *self.reason_refs,
                    *(ref for failure in self.failure_records for ref in failure.reason_refs),
                )
            )
        )
        return {
            "bundle_id": self.bundle_id,
            "profile": self.profile,
            "stage_results": [_validation_result_record(result) for result in self.stage_results],
            "resolved_refs": to_jsonable(self.resolved_refs),
            "resolved_obligations": to_jsonable(self.resolved_obligations),
            "resolved_reason_refs": to_jsonable(self.resolved_reason_refs),
            "unresolved_refs": [list(item) for item in self.unresolved_refs],
            "ledger_entries": to_jsonable(self.ledger_entries),
            "artifact_refs": list(self.artifact_refs),
            "artifact_ref_records": to_jsonable(self.artifact_ref_records),
            "accepted_clause_records": to_jsonable(self.accepted_clause_records),
            "trust_assumptions": to_jsonable(self.trust_assumptions),
            "compiled_bundle_ref": self.compiled_bundle_ref,
            "guard_records": to_jsonable(self.guard_records),
            "proof_refs": [_proof_ref_id(ref) for ref in self.proof_refs],
            "proof_ref_records": [_proof_ref_record(ref) for ref in self.proof_refs],
            "authority_runtime_summary": to_jsonable(self.authority_runtime_summary),
            "stage_artifacts": {key: list(value) for key, value in self.stage_artifacts.items()},
            "protocol_records": to_jsonable(self.protocol_records),
            "replay_trace": self.replay_trace,
            "kernel_view_ref": self.kernel_view_ref,
            "observation_context_ref": self.observation_context_ref,
            "agreement_ref": self.agreement_ref,
            "runtime_summary_digest": self.runtime_summary_digest,
            "failure_records": [_failure_record_record(record) for record in self.failure_records],
            "reason_refs": [getattr(ref, "reason_id", str(ref)) for ref in reason_refs],
            "reason_ref_records": [_reason_ref_record(ref) for ref in reason_refs],
            "stage_blockers": [_failure_record_record(record) for record in self.stage_blockers],
            "authority_view": to_jsonable(self.authority_view),
            "authority_outcome_digest": self.authority_outcome_digest,
        }


def _field_presence(
    artifact: Any,
    *,
    artifact_id: str,
    required_fields: tuple[str, ...],
    forbidden_fields: tuple[str, ...],
    closed_world_fields: tuple[str, ...] | None,
) -> ValidationResult:
    if not isinstance(artifact, Mapping):
        if required_fields or forbidden_fields or closed_world_fields is not None:
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.SCHEMA_VALIDATE,
                "field-presence checks require a JSON object",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=artifact_id,
            )
        return pass_validation(ValidationStage.SCHEMA_VALIDATE)

    for field_name in required_fields:
        if field_name not in artifact:
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.SCHEMA_VALIDATE,
                f"required field is missing: {field_name}",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=artifact_id,
                source_path=f"/{field_name}",
            )
    for field_name in forbidden_fields:
        if field_name in artifact:
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.SCHEMA_VALIDATE,
                f"field is forbidden in this outcome: {field_name}",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=artifact_id,
                source_path=f"/{field_name}",
            )
    if closed_world_fields is not None:
        allowed = set(closed_world_fields)
        extras = sorted(str(field) for field in artifact if field not in allowed)
        if extras:
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.SCHEMA_VALIDATE,
                f"unknown closed-world field: {extras[0]}",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=artifact_id,
                source_path=f"/{extras[0]}",
            )
    return pass_validation(ValidationStage.SCHEMA_VALIDATE)


def _canonicalization_error_path(exc: CanonicalizationError) -> str:
    message = str(exc)
    marker = " at "
    if marker not in message:
        return ""
    path = message.split(marker, 1)[1].split(" ", 1)[0]
    return path if path.startswith("/") else ""


def _validate_wire_records(
    *,
    scalar_records: tuple[ScalarRecord, ...],
    interval_records: tuple[IntervalRecord, ...],
    timestamp_records: tuple[TimestampRecord, ...],
    set_refs: tuple[SetRef, ...],
) -> ValidationResult:
    for scalar in scalar_records:
        result = validate_scalar_record(scalar)
        if not result.passed:
            return result
    for interval in interval_records:
        result = validate_interval_record(interval)
        if not result.passed:
            return result
    for timestamp in timestamp_records:
        result = validate_timestamp_record(timestamp)
        if not result.passed:
            return result
    for set_record in set_refs:
        result = validate_set_ref(set_record)
        if not result.passed:
            return result
    return pass_validation(ValidationStage.DIGEST_CHECK)


def _validate_artifacts(
    *,
    artifact: Any,
    artifact_refs: tuple[ArtifactRef, ...],
    artifact_store: ArtifactStore | None,
    dependencies: tuple[ArtifactRef, ...],
    artifact_id: str,
) -> ValidationResult:
    for artifact_ref in artifact_refs:
        stored_artifact = None
        if artifact_store is not None:
            item = artifact_store.get(artifact_ref.artifact_id)
            stored_artifact = item[1] if item is not None else None
        elif artifact_ref.artifact_id == artifact_id:
            stored_artifact = artifact
        result = validate_artifact_ref(artifact_ref, artifact=stored_artifact)
        if not result.passed:
            return result
    if dependencies:
        return validate_manifest_dependencies(dependencies, root_artifact_id=artifact_id)
    return pass_validation(ValidationStage.DIGEST_CHECK)


def _resolve_references(
    *,
    artifact_store: ArtifactStore | None,
    reference_context: ReferenceResolutionContext | None,
    reason_paths: tuple[tuple[str, str], ...],
) -> ValidationResult:
    if not reason_paths:
        return pass_validation(ValidationStage.REFERENCE_RESOLVE)
    if artifact_store is None or reference_context is None:
        artifact_id = reason_paths[0][0]
        pointer = reason_paths[0][1]
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.REFERENCE_RESOLVE,
            "reference-resolution context is missing",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
            source_path=pointer,
        )
    for artifact_id, pointer in reason_paths:
        result, _ = resolve_reference(
            artifact_id,
            pointer,
            store=artifact_store,
            context=reference_context,
        )
        if not result.passed:
            return result
    return pass_validation(ValidationStage.REFERENCE_RESOLVE)


def _first_failure_or_pass(
    stage: ValidationStage, results: tuple[ValidationResult, ...]
) -> ValidationResult:
    for result in results:
        if not result.passed:
            return result
    return pass_validation(stage)


def _blocked_stage(
    stage: ValidationStage, prior: ValidationResult, bundle_id: str
) -> ValidationResult:
    return validation_failure(
        FailureCode.CHECKER_UNKNOWN,
        stage,
        f"stage blocked by prior failure at {prior.stage.value}",
        status=ValidationStatus.UNKNOWN,
        layer=Layer.VALIDATION,
        source_artifact=bundle_id,
        source_path=stage.value,
    )


def _append_blocked_stages(
    stage_results: list[ValidationResult],
    failed: ValidationResult,
    bundle_id: str,
) -> None:
    stages = tuple(ValidationStage)
    start = stages.index(failed.stage) + 1
    for stage in stages[start:]:
        stage_results.append(_blocked_stage(stage, failed, bundle_id))


def _entry_reference_paths(entry: ArtifactEntry) -> tuple[tuple[str, str], ...]:
    paths: list[tuple[str, str]] = [
        (entry.artifact_ref.artifact_id, path) for path in entry.reason_paths
    ]
    artifact = entry.artifact
    if isinstance(artifact, Mapping):
        for key in ("reason_refs", "obligation_refs"):
            refs = artifact.get(key, ())
            if isinstance(refs, list | tuple):
                for ref in refs:
                    if not isinstance(ref, Mapping):
                        continue
                    source_artifact = ref.get("source_artifact")
                    source_path = ref.get("source_path")
                    if source_artifact is not None and source_path is not None:
                        paths.append((str(source_artifact), str(source_path)))
    return tuple(paths)


def _manifest_identity(bundle: ArtifactBundle) -> dict[str, Any]:
    return {
        "manifest_id": bundle.manifest.manifest_id,
        "root_artifact_id": bundle.manifest.root_artifact_id,
        "artifact_refs": [
            {
                "artifact_id": ref.artifact_id,
                "artifact_type": ref.artifact_type,
                "digest_value": ref.digest_value,
                "semantic_role": ref.semantic_role,
                "provenance_refs": list(ref.provenance_refs),
                "dependency_labels": list(ref.dependency_labels),
            }
            for ref in bundle.manifest.artifact_refs
        ],
        "dependency_order": list(bundle.manifest.dependency_order),
        "semantic_roles": bundle.manifest.semantic_roles,
        "fixed_point_admissions": list(bundle.manifest.fixed_point_admissions),
    }


def _validate_manifest_digest(bundle: ArtifactBundle) -> ValidationResult:
    if bundle.manifest.manifest_digest is None:
        return pass_validation(ValidationStage.DIGEST_CHECK)
    actual = manifest_digest(
        _manifest_identity(bundle),
        artifact_type="manifest",
        schema_profile_digest="DFCC-Interop",
        dependencies=bundle.manifest.artifact_refs,
    )
    if actual != bundle.manifest.manifest_digest:
        return validation_failure(
            FailureCode.DIGEST_MISMATCH,
            ValidationStage.DIGEST_CHECK,
            "manifest digest does not match artifact dependency identity",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=bundle.manifest.manifest_id,
            source_path="/manifest_digest",
        )
    return pass_validation(ValidationStage.DIGEST_CHECK)


def _parse_stage(bundle: ArtifactBundle) -> ValidationResult:
    if not bundle.entries:
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.PARSE,
            "artifact bundle contains no artifacts",
            status=ValidationStatus.REJECT_INPUT,
            layer=Layer.INTEROP,
            source_artifact=bundle.bundle_id,
            source_path="/artifacts",
        )
    ids = [entry.artifact_ref.artifact_id for entry in bundle.entries]
    if len(set(ids)) != len(ids):
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.PARSE,
            "artifact bundle contains duplicate artifact ids",
            status=ValidationStatus.CONFLICT,
            layer=Layer.INTEROP,
            source_artifact=bundle.bundle_id,
            source_path="/artifacts",
        )
    if bundle.manifest.root_artifact_id not in set(ids):
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.PARSE,
            "manifest root artifact is not present in the bundle",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=bundle.manifest.root_artifact_id,
        )
    return pass_validation(ValidationStage.PARSE)


def _canonicalize_stage(bundle: ArtifactBundle) -> ValidationResult:
    for entry in bundle.entries:
        try:
            canonical_bytes(entry.artifact)
        except CanonicalizationError as exc:
            return validation_failure(
                FailureCode.CANONICALIZATION_MISMATCH,
                ValidationStage.CANONICALIZE,
                str(exc),
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=entry.artifact_ref.artifact_id,
                source_path=_canonicalization_error_path(exc),
            )
    return pass_validation(ValidationStage.CANONICALIZE)


def _schema_stage(bundle: ArtifactBundle) -> ValidationResult:
    role_schemas = {
        ArtifactRole.ACCEPTED_CLAUSE: "accepted-clause.schema.json",
        ArtifactRole.ADMISSION: "admission-contract.schema.json",
        ArtifactRole.AGREEMENT: "agreement.schema.json",
        ArtifactRole.COMPLETION_ADMISSION: "completion-admission.schema.json",
        ArtifactRole.DEPENDENCY_GRAPH: "dependency-graph.schema.json",
        ArtifactRole.EVIDENCE: "evidence-artifact.schema.json",
        ArtifactRole.FIBER_ASSOC_VIEW: "fiber-assoc-view.schema.json",
        ArtifactRole.GUARD_RECORD: "guard-record.schema.json",
        ArtifactRole.ISSUE_CERTIFICATE: "issue-certificate.schema.json",
        ArtifactRole.KERNEL_PROOF: "kernel-proof-artifact.schema.json",
        ArtifactRole.LIFECYCLE_DECISION: "lifecycle-decision.schema.json",
        ArtifactRole.LIFECYCLE_EVENT: "lifecycle-event.schema.json",
        ArtifactRole.MEASUREMENT_RELATION: "measurement-relation-artifact.schema.json",
        ArtifactRole.OBSERVATION: "observation-cut.schema.json",
        ArtifactRole.PIPELINE_REPORT: "pipeline-report.schema.json",
        ArtifactRole.PREFIX_VIEW: "prefix-view.schema.json",
        ArtifactRole.PROFILE: "profile-resolution.schema.json",
        ArtifactRole.PROTOCOL_RECORD: "protocol-record-artifact.schema.json",
        ArtifactRole.PROPOSED_USE: "proposed-use.schema.json",
        ArtifactRole.REPLAY_STAGE_TRACE: "replay-stage-trace.schema.json",
        ArtifactRole.REPLAY_TRACE: "replay-trace.schema.json",
        ArtifactRole.REPRESENTATION_RELATION: "representation-relation-artifact.schema.json",
        ArtifactRole.RESOLVED_AUTHORITY_RUNTIME: "resolved-authority-runtime.schema.json",
        ArtifactRole.SCALAR_RECORD: "scalar-record.schema.json",
        ArtifactRole.SET: "set-ref.schema.json",
        ArtifactRole.STATUS_AUTHORITY_VIEW: "status-authority-view.schema.json",
        ArtifactRole.STATUS_CONTEXT: "status-context.schema.json",
        ArtifactRole.INTERVAL_RECORD: "interval-record.schema.json",
        ArtifactRole.TIMESTAMP_RECORD: "timestamp-record.schema.json",
        ArtifactRole.TRUST_ASSUMPTION: "trust-assumption.schema.json",
        ArtifactRole.VALIDATION_RESULT: "validation-result.schema.json",
    }
    for entry in bundle.entries:
        schema_name = entry.schema_name or role_schemas.get(entry.role)
        if schema_name is None:
            continue
        result = validate_named_schema(
            entry.artifact,
            schema_name,
            artifact_id=entry.artifact_ref.artifact_id,
        )
        if not result.passed:
            return result
        wire_result = _validate_wire_artifact(entry)
        if not wire_result.passed:
            return wire_result
    return pass_validation(ValidationStage.SCHEMA_VALIDATE)


def _scalar_record_from_mapping(source: Mapping[str, Any]) -> ScalarRecord:
    return ScalarRecord(
        decimal_string=str(source["decimal_string"]),
        unit_ref=str(source["unit_ref"]),
        dimension_ref=str(source["dimension_ref"]),
        exactness=str(source.get("exactness", "exact")),
        uncertainty_ref=str(source["uncertainty_ref"])
        if source.get("uncertainty_ref") is not None
        else None,
    )


def _validate_wire_artifact(entry: ArtifactEntry) -> ValidationResult:
    artifact = entry.artifact
    if not isinstance(artifact, Mapping):
        return pass_validation(ValidationStage.SCHEMA_VALIDATE)
    try:
        if entry.role is ArtifactRole.SCALAR_RECORD:
            return validate_scalar_record(_scalar_record_from_mapping(artifact))
        if entry.role is ArtifactRole.INTERVAL_RECORD:
            lower = artifact["lower"]
            upper = artifact["upper"]
            if not isinstance(lower, Mapping) or not isinstance(upper, Mapping):
                return validation_failure(
                    FailureCode.SCHEMA_INVALID,
                    ValidationStage.SCHEMA_VALIDATE,
                    "IntervalRecord bounds must be ScalarRecord objects",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.INTEROP,
                    source_artifact=entry.artifact_ref.artifact_id,
                )
            return validate_interval_record(
                IntervalRecord(
                    lower=_scalar_record_from_mapping(lower),
                    upper=_scalar_record_from_mapping(upper),
                    lower_closed=bool(artifact["lower_closed"]),
                    upper_closed=bool(artifact["upper_closed"]),
                    uncertainty_ref=str(artifact["uncertainty_ref"])
                    if artifact.get("uncertainty_ref") is not None
                    else None,
                    basis_ref=str(artifact["basis_ref"])
                    if artifact.get("basis_ref") is not None
                    else None,
                )
            )
        if entry.role is ArtifactRole.TIMESTAMP_RECORD:
            return validate_timestamp_record(
                TimestampRecord(
                    lexical_time=str(artifact["lexical_time"]),
                    time_basis_ref=str(artifact["time_basis_ref"]),
                    time_scale=str(artifact.get("time_scale", "UTC")),
                    source=str(artifact.get("source", "unspecified")),
                    traceability=str(artifact["traceability"])
                    if artifact.get("traceability") is not None
                    else None,
                    uncertainty_ref=str(artifact["uncertainty_ref"])
                    if artifact.get("uncertainty_ref") is not None
                    else None,
                    timestamp_policy_ref=str(artifact["timestamp_policy_ref"])
                    if artifact.get("timestamp_policy_ref") is not None
                    else None,
                )
            )
    except (KeyError, TypeError) as exc:
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.SCHEMA_VALIDATE,
            f"wire record cannot be parsed: {exc}",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=entry.artifact_ref.artifact_id,
        )
    return pass_validation(ValidationStage.SCHEMA_VALIDATE)


def _digest_stage(bundle: ArtifactBundle) -> ValidationResult:
    policy = {
        "allowed_retrieval_policies": bundle.reference_context.allowed_retrieval_policies,
        "allowed_immutability_policies": bundle.reference_context.allowed_immutability_policies,
        "schema_digests": bundle.reference_context.schema_digests,
        "canonicalization_digests": bundle.reference_context.canonicalization_digests,
        "semantic_roles": {
            **bundle.reference_context.semantic_roles,
            **bundle.manifest.semantic_roles,
        },
    }
    for entry in bundle.entries:
        result = validate_artifact_ref(entry.artifact_ref, artifact=entry.artifact, policy=policy)
        if not result.passed:
            return result
        if entry.role is ArtifactRole.SET:
            artifact = entry.artifact
            if not isinstance(artifact, Mapping):
                return validation_failure(
                    FailureCode.SCHEMA_INVALID,
                    ValidationStage.DIGEST_CHECK,
                    "SetRef artifact must be an object",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.INTEROP,
                    source_artifact=entry.artifact_ref.artifact_id,
                )
            set_result = validate_set_ref(
                SetRef(
                    carrier_ref=str(artifact["carrier_ref"]),
                    encoding_kind=str(artifact["encoding_kind"]),
                    constraint_ref=str(artifact["constraint_ref"]),
                    approximation_kind=str(artifact["approximation_kind"]),
                    soundness_ref=str(artifact["soundness_ref"]),
                    digest=str(artifact["digest"]),
                )
            )
            if not set_result.passed:
                return set_result
    result = validate_manifest_dependencies(
        bundle.manifest.artifact_refs,
        root_artifact_id=bundle.manifest.root_artifact_id,
        dependency_order=bundle.manifest.dependency_order,
        fixed_point_admissions=bundle.manifest.fixed_point_admissions,
    )
    if not result.passed:
        return result
    return _validate_manifest_digest(bundle)


def _reference_stage(
    bundle: ArtifactBundle,
) -> tuple[ValidationResult, tuple[ResolvedReference, ...]]:
    store = ArtifactStore()
    for entry in bundle.entries:
        try:
            store.add(entry.artifact_ref, entry.artifact)
        except ValueError as exc:
            result = validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.REFERENCE_RESOLVE,
                str(exc),
                status=ValidationStatus.CONFLICT,
                layer=Layer.INTEROP,
                source_artifact=entry.artifact_ref.artifact_id,
            )
            return result, ()
    resolved: list[ResolvedReference] = []
    for entry in bundle.entries:
        for artifact_id, pointer in _entry_reference_paths(entry):
            result, value = resolve_reference(
                artifact_id,
                pointer,
                store=store,
                context=bundle.reference_context,
            )
            if not result.passed:
                return result, tuple(resolved)
            resolved.append(
                ResolvedReference(
                    source_artifact=artifact_id,
                    source_path=pointer,
                    target_digest=manifest_digest(
                        value,
                        artifact_type="reference-target",
                        schema_profile_digest="DFCC-Interop",
                    ),
                )
            )
    return pass_validation(ValidationStage.REFERENCE_RESOLVE), tuple(resolved)


def _profile_stage(profile: str) -> ValidationResult:
    resolved = resolve_profile(profile)
    if resolved.status != "pass":
        return validation_failure(
            FailureCode.UNSUPPORTED_PROFILE,
            ValidationStage.PROFILE_RESOLVE,
            f"unsupported conformance profile: {profile}",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=profile,
        )
    return pass_validation(ValidationStage.PROFILE_RESOLVE)


def _replay_stage(bundle: ArtifactBundle, checker: DFCCChecker) -> ValidationResult:
    events = tuple(
        entry.artifact
        for entry in bundle.entries
        if entry.role is ArtifactRole.LIFECYCLE_EVENT
        or entry.artifact_ref.semantic_role == ArtifactRole.LIFECYCLE_EVENT.value
    )
    if not events:
        return pass_validation(ValidationStage.REPLAY)
    return checker.event_order(
        events,
        {
            "accepted_event_ids": tuple(
                str(event.get("event_id", "")) for event in events if isinstance(event, Mapping)
            )
        },
        {"log_root": bundle.reference_context.snapshot_id},
    )


def _guard_stage(bundle: ArtifactBundle, checker: DFCCChecker) -> ValidationResult:
    observation_entries = tuple(
        entry for entry in bundle.entries if entry.role is ArtifactRole.OBSERVATION
    )
    for entry in observation_entries:
        artifact = entry.artifact
        if not isinstance(artifact, Mapping):
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.GUARD_EVALUATE,
                "observation artifact must be an object",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.OPERATIONAL,
                source_artifact=entry.artifact_ref.artifact_id,
            )
        result = checker.observation_cut(
            artifact.get("records", ()),
            artifact.get("status_time"),
            artifact.get("time_basis_ref"),
            artifact.get("event_order_ref"),
            artifact.get("dependency_snapshot", {}),
            artifact.get("frame", {}),
        )
        if not result.passed:
            return result
    return pass_validation(ValidationStage.GUARD_EVALUATE)


def _kernel_stage(bundle: ArtifactBundle) -> ValidationResult:
    has_claim = any(entry.role is ArtifactRole.CLAIM for entry in bundle.entries)
    has_bundle = any(entry.role is ArtifactRole.ASSUMPTION_BUNDLE for entry in bundle.entries)
    issue_entries = tuple(
        entry for entry in bundle.entries if entry.role is ArtifactRole.ISSUE_CERTIFICATE
    )
    for entry in issue_entries:
        if not isinstance(entry.artifact, Mapping):
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.KERNEL_CHECK,
                "issue certificate artifact must be an object for kernel replay",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.REPRESENTED,
                source_artifact=entry.artifact_ref.artifact_id,
            )
        if not entry.artifact.get("compiled_semantics_ref"):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.KERNEL_CHECK,
                "kernel replay requires compiled_semantics_ref",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.REPRESENTED,
                source_artifact=entry.artifact_ref.artifact_id,
                source_path="/compiled_semantics_ref",
            )
        if not entry.artifact.get("proof_refs"):
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.KERNEL_CHECK,
                "kernel replay requires issue-time proof refs",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.REPRESENTED,
                source_artifact=entry.artifact_ref.artifact_id,
                source_path="/proof_refs",
            )
    if has_claim != has_bundle:
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.KERNEL_CHECK,
            "kernel replay requires both claim and assumption_bundle artifacts",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.REPRESENTED,
            source_artifact=bundle.bundle_id,
        )
    return pass_validation(ValidationStage.KERNEL_CHECK)


def _authority_stage(bundle: ArtifactBundle, checker: DFCCChecker) -> ValidationResult:
    status_entries = tuple(
        entry
        for entry in bundle.entries
        if entry.role in {ArtifactRole.STATUS, ArtifactRole.STATUS_AUTHORITY_VIEW}
    )
    for entry in status_entries:
        artifact = entry.artifact
        if not isinstance(artifact, Mapping):
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.AUTHORITY_EMIT,
                "status authority artifact must be an object",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
                source_artifact=entry.artifact_ref.artifact_id,
            )
        outcome = artifact.get("authority_outcome")
        blocking = artifact.get("blocking_set", ())
        reason_refs = artifact.get("reason_refs", ())
        code = outcome.get("code") if isinstance(outcome, Mapping) else None
        decisive_codes = {"allow", "accept", "reject", "assert", "deny", "infeasible", "active"}
        if code not in decisive_codes and not blocking and not reason_refs:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "non-allow authority outcome lacks blocking or reason refs",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
                source_artifact=entry.artifact_ref.artifact_id,
                source_path="/reason_refs",
            )
        result = checker.typed_authority_outcome(artifact, None, None, blocking, None)
        if not result.passed:
            return result
    return pass_validation(ValidationStage.AUTHORITY_EMIT)


def validate_artifact_bundle(
    bundle: ArtifactBundle,
    *,
    requested_profile: str = "DFCC-Interop",
    checker: DFCCChecker | None = None,
    full_replay: bool = False,
) -> PipelineReport:
    checker = checker or ReferenceChecker()
    stage_results: list[ValidationResult] = []
    resolved_refs: tuple[ResolvedReference, ...] = ()

    parse = _parse_stage(bundle)
    stage_results.append(parse)
    if not parse.passed:
        _append_blocked_stages(stage_results, parse, bundle.bundle_id)
    else:
        canonical = _canonicalize_stage(bundle)
        stage_results.append(canonical)
        if not canonical.passed:
            _append_blocked_stages(stage_results, canonical, bundle.bundle_id)
        else:
            schema = _schema_stage(bundle)
            stage_results.append(schema)
            if not schema.passed:
                _append_blocked_stages(stage_results, schema, bundle.bundle_id)
            else:
                digest = _digest_stage(bundle)
                stage_results.append(digest)
                if not digest.passed:
                    _append_blocked_stages(stage_results, digest, bundle.bundle_id)
                else:
                    refs, resolved_refs = _reference_stage(bundle)
                    stage_results.append(refs)
                    if not refs.passed:
                        _append_blocked_stages(stage_results, refs, bundle.bundle_id)
                    else:
                        profile = _profile_stage(requested_profile)
                        stage_results.append(profile)
                        if not profile.passed:
                            _append_blocked_stages(stage_results, profile, bundle.bundle_id)
                        elif full_replay:
                            pass
                        else:
                            replay = _replay_stage(bundle, checker)
                            stage_results.append(replay)
                            if not replay.passed:
                                _append_blocked_stages(stage_results, replay, bundle.bundle_id)
                            else:
                                guard = _guard_stage(bundle, checker)
                                stage_results.append(guard)
                                if not guard.passed:
                                    _append_blocked_stages(stage_results, guard, bundle.bundle_id)
                                else:
                                    kernel = _kernel_stage(bundle)
                                    stage_results.append(kernel)
                                    if not kernel.passed:
                                        _append_blocked_stages(
                                            stage_results, kernel, bundle.bundle_id
                                        )
                                    else:
                                        stage_results.append(_authority_stage(bundle, checker))

    authority_view = None
    authority_outcome_digest = None
    resolved_obligations: tuple[ResolvedReference, ...] = ()
    resolved_reason_refs: tuple[ResolvedReference, ...] = ()
    unresolved_refs: tuple[tuple[str, str], ...] = ()
    ledger_entries: tuple[Any, ...] = ()
    accepted_clause_records: tuple[Any, ...] = ()
    trust_assumptions: tuple[Any, ...] = ()
    compiled_bundle_ref: str | None = None
    guard_records: tuple[Any, ...] = ()
    proof_refs: tuple[Any, ...] = ()
    authority_runtime_summary: dict[str, Any] | None = None
    stage_artifacts: dict[str, tuple[str, ...]] = {}
    protocol_records: tuple[Any, ...] = ()
    replay_trace: dict[str, Any] | None = None
    kernel_view_ref: str | None = None
    observation_context_ref: str | None = None
    agreement_ref: str | None = None
    runtime_summary_digest: str | None = None
    if all(result.passed for result in stage_results):
        from dfcc.replay import replay_authority_from_bundle

        roles = {entry.role for entry in bundle.entries}
        should_replay = full_replay or {
            ArtifactRole.ISSUE_CERTIFICATE,
            ArtifactRole.PROPOSED_USE,
            ArtifactRole.STATUS_CONTEXT,
        }.issubset(roles)
        if should_replay:
            authority_replay = replay_authority_from_bundle(
                bundle,
                resolved_refs=resolved_refs,
                strict_ledger=full_replay,
            )
            unresolved_refs = authority_replay.unresolved_refs
            trace = authority_replay.replay_trace
            if authority_replay.context is not None:
                resolved_obligations = authority_replay.context.resolved_obligations
                resolved_reason_refs = authority_replay.context.resolved_reason_refs
                accepted_clause_records = authority_replay.context.accepted_clause_records
                trust_assumptions = authority_replay.context.trust_assumptions
                compiled_bundle_ref = authority_replay.context.compiled_bundle_ref
                guard_records = authority_replay.context.guard_records
                ledger_entries = authority_replay.context.ledger_entries
                proof_refs = authority_replay.context.proof_refs
                authority_runtime_summary = authority_replay.context.authority_runtime_summary
                trace = authority_replay.context.replay_trace or trace
            if trace is not None:
                stage_artifacts = trace.stage_artifacts
                kernel_view_ref = trace.kernel_view_ref
                observation_context_ref = trace.observation_context_ref
                agreement_ref = trace.agreement_ref
                runtime_summary_digest = trace.runtime_summary_digest
                protocol_records = trace.protocol_records
                replay_trace = trace.to_json()
                if full_replay:
                    stage_results.extend(trace.stage_results)
            if authority_replay.authority_view is not None:
                authority_view = authority_replay.authority_view
                authority_outcome_digest = authority_replay.authority_outcome_digest
            elif full_replay and trace is None:
                if not unresolved_refs:
                    unresolved_refs = tuple(
                        (ref.source_artifact, ref.source_path)
                        for ref in authority_replay.validation_result.reason_refs
                    )
                stage_results.append(authority_replay.validation_result)

    reason_digest_index = _bundle_reason_digest_index(bundle)
    if runtime_summary_digest is not None:
        reason_digest_index["authority-runtime"] = runtime_summary_digest
    stage_results = [
        _bind_validation_result_digest(result, reason_digest_index) for result in stage_results
    ]
    authority_view = _bind_authority_view_digest(authority_view, reason_digest_index)
    failures = tuple(record for result in stage_results for record in result.failure_records)
    reasons = tuple(ref for result in stage_results for ref in result.reason_refs)
    stage_blockers = tuple(record for record in failures if record.blocking)
    return PipelineReport(
        bundle_id=bundle.bundle_id,
        profile=requested_profile,
        stage_results=tuple(stage_results),
        resolved_refs=resolved_refs,
        resolved_obligations=resolved_obligations,
        resolved_reason_refs=resolved_reason_refs,
        unresolved_refs=unresolved_refs,
        ledger_entries=ledger_entries,
        artifact_refs=tuple(entry.artifact_ref.artifact_id for entry in bundle.entries),
        artifact_ref_records=tuple(entry.artifact_ref for entry in bundle.entries),
        accepted_clause_records=accepted_clause_records,
        trust_assumptions=trust_assumptions,
        compiled_bundle_ref=compiled_bundle_ref,
        guard_records=guard_records,
        proof_refs=proof_refs,
        authority_runtime_summary=authority_runtime_summary,
        stage_artifacts=stage_artifacts,
        protocol_records=protocol_records,
        replay_trace=replay_trace,
        kernel_view_ref=kernel_view_ref,
        observation_context_ref=observation_context_ref,
        agreement_ref=agreement_ref,
        runtime_summary_digest=runtime_summary_digest,
        failure_records=failures,
        reason_refs=reasons,
        stage_blockers=stage_blockers,
        authority_view=authority_view,
        authority_outcome_digest=authority_outcome_digest,
    )


@overload
def validate_pipeline(
    artifact: ArtifactBundle,
    *,
    schema_name: str | None = None,
    requested_profile: str = "DFCC-Interop",
    artifact_id: str = "input",
    artifact_refs: tuple[ArtifactRef, ...] = (),
    artifact_store: ArtifactStore | None = None,
    dependencies: tuple[ArtifactRef, ...] = (),
    reference_context: ReferenceResolutionContext | None = None,
    reason_paths: tuple[tuple[str, str], ...] = (),
    scalar_records: tuple[ScalarRecord, ...] = (),
    interval_records: tuple[IntervalRecord, ...] = (),
    timestamp_records: tuple[TimestampRecord, ...] = (),
    set_refs: tuple[SetRef, ...] = (),
    required_fields: tuple[str, ...] = (),
    forbidden_fields: tuple[str, ...] = (),
    closed_world_fields: tuple[str, ...] | None = None,
    full_replay: bool = False,
) -> PipelineReport: ...


@overload
def validate_pipeline(
    artifact: Any,
    *,
    schema_name: str | None = None,
    requested_profile: str = "DFCC-Interop",
    artifact_id: str = "input",
    artifact_refs: tuple[ArtifactRef, ...] = (),
    artifact_store: ArtifactStore | None = None,
    dependencies: tuple[ArtifactRef, ...] = (),
    reference_context: ReferenceResolutionContext | None = None,
    reason_paths: tuple[tuple[str, str], ...] = (),
    scalar_records: tuple[ScalarRecord, ...] = (),
    interval_records: tuple[IntervalRecord, ...] = (),
    timestamp_records: tuple[TimestampRecord, ...] = (),
    set_refs: tuple[SetRef, ...] = (),
    required_fields: tuple[str, ...] = (),
    forbidden_fields: tuple[str, ...] = (),
    closed_world_fields: tuple[str, ...] | None = None,
    full_replay: bool = False,
) -> ValidationResult: ...


def validate_pipeline(
    artifact: Any,
    *,
    schema_name: str | None = None,
    requested_profile: str = "DFCC-Interop",
    artifact_id: str = "input",
    artifact_refs: tuple[ArtifactRef, ...] = (),
    artifact_store: ArtifactStore | None = None,
    dependencies: tuple[ArtifactRef, ...] = (),
    reference_context: ReferenceResolutionContext | None = None,
    reason_paths: tuple[tuple[str, str], ...] = (),
    scalar_records: tuple[ScalarRecord, ...] = (),
    interval_records: tuple[IntervalRecord, ...] = (),
    timestamp_records: tuple[TimestampRecord, ...] = (),
    set_refs: tuple[SetRef, ...] = (),
    required_fields: tuple[str, ...] = (),
    forbidden_fields: tuple[str, ...] = (),
    closed_world_fields: tuple[str, ...] | None = None,
    full_replay: bool = False,
) -> ValidationResult | PipelineReport:
    if isinstance(artifact, ArtifactBundle):
        return validate_artifact_bundle(
            artifact,
            requested_profile=requested_profile,
            full_replay=full_replay,
        )

    if full_replay:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.REPLAY,
            "full replay requires an ArtifactBundle input",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
            source_path="/",
        )

    if artifact is None:
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.PARSE,
            "artifact is null",
            status=ValidationStatus.REJECT_INPUT,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
        )

    try:
        canonical_bytes(artifact)
    except CanonicalizationError as exc:
        return validation_failure(
            FailureCode.CANONICALIZATION_MISMATCH,
            ValidationStage.CANONICALIZE,
            str(exc),
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
            source_path=_canonicalization_error_path(exc),
        )

    if schema_name is not None:
        schema_result = validate_named_schema(artifact, schema_name, artifact_id=artifact_id)
        if not schema_result.passed:
            return schema_result

    fields = _field_presence(
        artifact,
        artifact_id=artifact_id,
        required_fields=required_fields,
        forbidden_fields=forbidden_fields,
        closed_world_fields=closed_world_fields,
    )
    if not fields.passed:
        return fields

    artifacts = _validate_artifacts(
        artifact=artifact,
        artifact_refs=artifact_refs,
        artifact_store=artifact_store,
        dependencies=dependencies,
        artifact_id=artifact_id,
    )
    if not artifacts.passed:
        return artifacts

    wire = _validate_wire_records(
        scalar_records=scalar_records,
        interval_records=interval_records,
        timestamp_records=timestamp_records,
        set_refs=set_refs,
    )
    if not wire.passed:
        return wire

    refs = _resolve_references(
        artifact_store=artifact_store,
        reference_context=reference_context,
        reason_paths=reason_paths,
    )
    if not refs.passed:
        return refs

    profile = resolve_profile(requested_profile)
    if profile.status != "pass":
        return validation_failure(
            FailureCode.UNSUPPORTED_PROFILE,
            ValidationStage.PROFILE_RESOLVE,
            f"unsupported conformance profile: {requested_profile}",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
        )
    return pass_validation(ValidationStage.AUTHORITY_EMIT)
