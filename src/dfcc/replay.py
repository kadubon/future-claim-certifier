"""Artifact-bundle authority replay."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from dfcc.admission import (
    AcceptedClause,
    AdmissionContract,
    EvidenceArtifact,
    TrustAssumption,
    accepted_clause_obligation_record_result,
    accepted_clause_reason_record_result,
    admission_contract_result,
    admit_evidence_set,
    trust_assumption_result,
)
from dfcc.artifacts import (
    ArtifactBundle,
    ArtifactEntry,
    ArtifactRef,
    ArtifactRole,
    ReferenceKind,
    ReferenceLedgerEntry,
    ResolvedReference,
    artifact_bundle_from_json,
    build_artifact_ref,
    build_reference_ledger,
    resolve_reference,
)
from dfcc.bundle import (
    assumption_bundle_from_accepted_clauses,
    assumption_bundle_to_json,
    compile_bundle,
)
from dfcc.canonical import digest_json
from dfcc.certificate import certify_claim
from dfcc.jsonpointer import JsonPointerError, resolve_pointer
from dfcc.kernel import KernelProofArtifact, ProofRef
from dfcc.models import IssueCertificate, ProposedUse, StatusAuthorityView, StatusContext
from dfcc.records import SetRef
from dfcc.runtime import ResolvedAuthorityRuntime
from dfcc.schema import validate_named_schema
from dfcc.serialization import to_jsonable
from dfcc.types import (
    BlockingRecord,
    FailureCode,
    FailureRecord,
    Layer,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
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


def _reason_ref_id(ref: Any) -> str:
    return str(getattr(ref, "reason_id", ref))


def _artifact_ref_id(ref: Any) -> str:
    if isinstance(ref, Mapping):
        return str(ref.get("artifact_id", ref))
    return str(getattr(ref, "artifact_id", ref))


def _artifact_ref_record(ref: Any) -> dict[str, Any]:
    payload = to_jsonable(ref)
    if isinstance(payload, Mapping):
        artifact_id = str(payload.get("artifact_id", _artifact_ref_id(ref)))
        return {
            "artifact_id": artifact_id,
            "artifact_type": str(payload.get("artifact_type", "protocol-record-source")),
            "schema_profile": str(payload.get("schema_profile", "dfcc-json/0.1")),
            "canonicalization": str(payload.get("canonicalization", "rfc8785-jcs")),
            "media_type": str(payload.get("media_type", "application/json")),
            "schema_digest": payload.get("schema_digest"),
            "canonicalization_digest": payload.get("canonicalization_digest"),
            "digest_algorithm": str(payload.get("digest_algorithm", "sha256")),
            "digest_value": payload.get("digest_value"),
            "content_uri": payload.get("content_uri"),
            "retrieval_policy": str(payload.get("retrieval_policy", "local")),
            "immutability_policy": str(payload.get("immutability_policy", "digest-addressed")),
            "provenance_refs": [str(item) for item in payload.get("provenance_refs", ())],
            "semantic_role": payload.get("semantic_role"),
            "dependency_labels": [str(item) for item in payload.get("dependency_labels", ())],
        }
    artifact_id = str(ref)
    synthetic_payload = to_jsonable(
        build_artifact_ref(
            {"artifact_ref": artifact_id},
            artifact_id=artifact_id,
            artifact_type="protocol-record-source",
            semantic_role=ArtifactRole.PROTOCOL_RECORD,
        )
    )
    if isinstance(synthetic_payload, Mapping):
        return {str(key): value for key, value in synthetic_payload.items()}
    return {
        "artifact_id": artifact_id,
        "artifact_type": "protocol-record-source",
        "schema_profile": "dfcc-json/0.1",
        "canonicalization": "rfc8785-jcs",
        "media_type": "application/json",
        "schema_digest": None,
        "canonicalization_digest": None,
        "digest_algorithm": "sha256",
        "digest_value": None,
        "content_uri": None,
        "retrieval_policy": "local",
        "immutability_policy": "digest-addressed",
        "provenance_refs": [],
        "semantic_role": ArtifactRole.PROTOCOL_RECORD.value,
        "dependency_labels": [],
    }


def _typed_artifact_ref_records(refs: tuple[Any, ...]) -> tuple[dict[str, Any], ...]:
    return tuple(_artifact_ref_record(ref) for ref in refs)


def _typed_reason_ref_records(refs: tuple[Any, ...]) -> tuple[dict[str, Any], ...]:
    return tuple(_reason_ref_record(ref) for ref in refs if hasattr(ref, "reason_id"))


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


def _typed_proof_ref_records(refs: tuple[Any, ...]) -> tuple[dict[str, Any], ...]:
    return tuple(_proof_ref_record(ref) for ref in refs)


def _blocking_record_record(block: BlockingRecord) -> dict[str, Any]:
    return {
        "block_id": block.block_id,
        "failure_code": block.failure_code.value,
        "layer": block.layer.value,
        "severity": block.severity,
        "reason_ref_records": [_reason_ref_record(ref) for ref in block.reason_refs],
    }


@dataclass(frozen=True, slots=True)
class ProtocolRecordArtifact:
    record_id: str
    record_kind: str
    stage: ValidationStage
    payload: dict[str, Any] = field(default_factory=dict)
    artifact_refs: tuple[str, ...] = ()
    artifact_ref_records: tuple[Any, ...] = ()
    proof_refs: tuple[Any, ...] = ()
    reason_refs: tuple[Any, ...] = ()
    digest: str | None = None

    @classmethod
    def build(
        cls,
        *,
        record_id: str,
        record_kind: str,
        stage: ValidationStage,
        payload: Mapping[str, Any],
        artifact_refs: tuple[str, ...] = (),
        artifact_ref_records: tuple[Any, ...] = (),
        proof_refs: tuple[Any, ...] = (),
        reason_refs: tuple[Any, ...] = (),
    ) -> ProtocolRecordArtifact:
        payload_record = {str(key): to_jsonable(value) for key, value in payload.items()}
        artifact_records_source: tuple[Any, ...] = (
            artifact_ref_records if artifact_ref_records else artifact_refs
        )
        artifact_records = _typed_artifact_ref_records(artifact_records_source)
        proof_ids = tuple(_proof_ref_id(ref) for ref in proof_refs)
        proof_records = _typed_proof_ref_records(proof_refs)
        reason_ids = tuple(_reason_ref_id(ref) for ref in reason_refs)
        reason_records = _typed_reason_ref_records(reason_refs)
        digest = digest_json(
            {
                "record_id": record_id,
                "record_kind": record_kind,
                "stage": stage.value,
                "payload": payload_record,
                "artifact_refs": artifact_refs,
                "artifact_ref_records": artifact_records,
                "proof_refs": proof_ids,
                "proof_ref_records": proof_records,
                "reason_refs": reason_ids,
                "reason_ref_records": reason_records,
            }
        )
        return cls(
            record_id=record_id,
            record_kind=record_kind,
            stage=stage,
            payload=payload_record,
            artifact_refs=artifact_refs,
            artifact_ref_records=artifact_records_source,
            proof_refs=proof_refs,
            reason_refs=reason_refs,
            digest=digest,
        )

    def to_json(self) -> dict[str, Any]:
        proof_ids = tuple(_proof_ref_id(ref) for ref in self.proof_refs)
        reason_ids = tuple(_reason_ref_id(ref) for ref in self.reason_refs)
        return {
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "stage": self.stage.value,
            "payload": self.payload,
            "artifact_refs": list(self.artifact_refs),
            "artifact_ref_records": list(_typed_artifact_ref_records(self.artifact_ref_records)),
            "proof_refs": list(proof_ids),
            "proof_ref_records": list(_typed_proof_ref_records(self.proof_refs)),
            "reason_refs": list(reason_ids),
            "reason_ref_records": list(_typed_reason_ref_records(self.reason_refs)),
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class ReplayStageTrace:
    stage: ValidationStage
    result: ValidationResult
    record_refs: tuple[str, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    artifact_ref_records: tuple[Any, ...] = ()
    proof_refs: tuple[str, ...] = ()
    proof_ref_records: tuple[Any, ...] = ()
    blocking_records: tuple[BlockingRecord, ...] = ()
    reason_refs: tuple[Any, ...] = ()

    def to_json(self) -> dict[str, Any]:
        reason_refs = tuple(
            dict.fromkeys(
                (
                    *self.reason_refs,
                    *(ref for block in self.blocking_records for ref in block.reason_refs),
                )
            )
        )
        return {
            "stage": self.stage.value,
            "status": self.result.status.value,
            "record_refs": list(self.record_refs),
            "artifact_refs": list(self.artifact_refs),
            "artifact_ref_records": list(_typed_artifact_ref_records(self.artifact_ref_records)),
            "proof_refs": list(self.proof_refs),
            "proof_ref_records": list(_typed_proof_ref_records(self.proof_ref_records)),
            "blocking_set": [block.block_id for block in self.blocking_records],
            "blocking_records": [_blocking_record_record(block) for block in self.blocking_records],
            "reason_refs": [getattr(ref, "reason_id", str(ref)) for ref in reason_refs],
            "reason_ref_records": [_reason_ref_record(ref) for ref in reason_refs],
        }


@dataclass(frozen=True, slots=True)
class ReplayTrace:
    stage_traces: tuple[ReplayStageTrace, ...]
    stage_artifacts: dict[str, tuple[str, ...]]
    protocol_records: tuple[ProtocolRecordArtifact, ...] = ()
    kernel_view_ref: str | None = None
    observation_context_ref: str | None = None
    agreement_ref: str | None = None
    runtime_summary_digest: str | None = None

    @property
    def stage_results(self) -> tuple[ValidationResult, ...]:
        return tuple(item.result for item in self.stage_traces)

    def to_json(self) -> dict[str, Any]:
        return {
            "stage_traces": [trace.to_json() for trace in self.stage_traces],
            "stage_artifacts": {
                stage: list(records) for stage, records in self.stage_artifacts.items()
            },
            "protocol_records": [record.to_json() for record in self.protocol_records],
            "kernel_view_ref": self.kernel_view_ref,
            "observation_context_ref": self.observation_context_ref,
            "agreement_ref": self.agreement_ref,
            "runtime_summary_digest": self.runtime_summary_digest,
        }


@dataclass(frozen=True, slots=True)
class AuthorityReplayContext:
    bundle_id: str
    certificate: IssueCertificate
    proposed_use: ProposedUse
    status_context: StatusContext
    accepted_clause_records: tuple[AcceptedClause, ...] = ()
    trust_assumptions: tuple[TrustAssumption, ...] = ()
    compiled_bundle_ref: str | None = None
    resolved_obligations: tuple[ResolvedReference, ...] = ()
    resolved_reason_refs: tuple[ResolvedReference, ...] = ()
    artifact_refs: tuple[ArtifactRef, ...] = ()
    ledger_entries: tuple[ReferenceLedgerEntry, ...] = ()
    guard_records: tuple[Any, ...] = ()
    runtime: ResolvedAuthorityRuntime | None = None
    proof_refs: tuple[Any, ...] = ()
    authority_runtime_summary: dict[str, Any] | None = None
    replay_trace: ReplayTrace | None = None
    protocol_records: tuple[ProtocolRecordArtifact, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorityReplayResult:
    context: AuthorityReplayContext | None
    authority_view: StatusAuthorityView | None
    validation_result: ValidationResult
    authority_outcome_digest: str | None = None
    unresolved_refs: tuple[tuple[str, str], ...] = ()
    replay_trace: ReplayTrace | None = None

    @property
    def passed(self) -> bool:
        return self.validation_result.passed and self.authority_view is not None


def _entry_matches(entry: ArtifactEntry, *roles: ArtifactRole, artifact_type: str = "") -> bool:
    role_values = {role.value for role in roles}
    return (
        entry.role in roles
        or str(entry.artifact_ref.semantic_role or "") in role_values
        or (bool(artifact_type) and entry.artifact_ref.artifact_type == artifact_type)
    )


def _first_mapping(
    bundle: ArtifactBundle, *roles: ArtifactRole, artifact_type: str = ""
) -> dict[str, Any] | None:
    for entry in bundle.entries:
        if _entry_matches(entry, *roles, artifact_type=artifact_type) and isinstance(
            entry.artifact, Mapping
        ):
            return dict(entry.artifact)
    return None


def _all_mappings(
    bundle: ArtifactBundle, *roles: ArtifactRole, artifact_type: str = ""
) -> tuple[dict[str, Any], ...]:
    return tuple(
        dict(entry.artifact)
        for entry in bundle.entries
        if _entry_matches(entry, *roles, artifact_type=artifact_type)
        and isinstance(entry.artifact, Mapping)
    )


def _missing(message: str, *, source_artifact: str, source_path: str = "/") -> ValidationResult:
    return validation_failure(
        FailureCode.MISSING_REF,
        ValidationStage.AUTHORITY_EMIT,
        message,
        status=ValidationStatus.UNKNOWN,
        layer=Layer.INTEROP,
        source_artifact=source_artifact,
        source_path=source_path,
    )


def _artifact_by_id(bundle: ArtifactBundle, artifact_id: str) -> dict[str, Any] | None:
    for entry in bundle.entries:
        if entry.artifact_ref.artifact_id == artifact_id and isinstance(entry.artifact, Mapping):
            return dict(entry.artifact)
    return None


def _artifact_target_by_ref(bundle: ArtifactBundle, ref_value: Any) -> Any | None:
    if not isinstance(ref_value, str) or not ref_value:
        return None
    artifact_id, separator, pointer = ref_value.partition("#")
    artifact = _artifact_by_id(bundle, artifact_id)
    if artifact is None:
        return None
    if not separator:
        return artifact
    try:
        return resolve_pointer(artifact, pointer)
    except JsonPointerError:
        return None


def _artifact_by_ref(bundle: ArtifactBundle, ref_value: Any) -> dict[str, Any] | None:
    target = _artifact_target_by_ref(bundle, ref_value)
    if isinstance(target, Mapping):
        return dict(target)
    return None


def _artifact_ref_digest(bundle: ArtifactBundle, ref_value: Any) -> str | None:
    if not isinstance(ref_value, str) or not ref_value:
        return None
    artifact_id, _, _ = ref_value.partition("#")
    for entry in bundle.entries:
        if entry.artifact_ref.artifact_id == artifact_id:
            return entry.artifact_ref.digest_value
    return None


def _bound_artifact_or_digest_ref(ref_value: Any) -> bool:
    if not isinstance(ref_value, str) or not ref_value:
        return False
    artifact_id = ref_value.split("#", 1)[0]
    return artifact_id.startswith("artifact:") or ref_value.startswith(
        ("sha256:", "sha384:", "sha512:")
    )


def _proof_payload_value(
    bundle: ArtifactBundle,
    ref_value: Any,
    *field_names: str,
) -> str | None:
    if not _bound_artifact_or_digest_ref(ref_value):
        return None
    artifact = _artifact_by_ref(bundle, ref_value)
    if artifact is None:
        return None
    status = str(
        artifact.get(
            "status",
            artifact.get("proof_status", artifact.get("checker_status", "unknown")),
        )
    )
    if status not in {"pass", "accepted"}:
        return None
    payloads: list[Mapping[str, Any]] = [artifact]
    proof_payload = artifact.get("proof")
    if isinstance(proof_payload, Mapping):
        payloads.append(proof_payload)
    for payload in payloads:
        for field_name in field_names:
            value = payload.get(field_name)
            if value is not None:
                return str(value)
    return None


def _proof_payload_field(
    bundle: ArtifactBundle,
    ref_value: Any,
    *field_names: str,
) -> Any:
    if not _bound_artifact_or_digest_ref(ref_value):
        return None
    artifact = _artifact_by_ref(bundle, ref_value)
    if artifact is None:
        return None
    status = str(
        artifact.get(
            "status",
            artifact.get("proof_status", artifact.get("checker_status", "unknown")),
        )
    )
    if status not in {"pass", "accepted"}:
        return None
    payloads: list[Mapping[str, Any]] = [artifact]
    proof_payload = artifact.get("proof")
    if isinstance(proof_payload, Mapping):
        payloads.append(proof_payload)
    for payload in payloads:
        for field_name in field_names:
            value = payload.get(field_name)
            if value is not None:
                return value
    return None


def _json_value_equal(left: Any, right: Any) -> bool:
    return digest_json(to_jsonable(left)) == digest_json(to_jsonable(right))


def _relation_proof_payload_failure(
    *,
    bundle: ArtifactBundle,
    artifact_id: str,
    proof_ref: Any,
    expected_fields: Mapping[str, Any],
    source_path_prefix: str,
) -> ValidationResult | None:
    for field_name, expected in expected_fields.items():
        proof_value = _proof_payload_field(bundle, proof_ref, field_name)
        if proof_value is None:
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"relation proof artifact lacks accepted {field_name}: {proof_ref}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.OPERATIONAL,
                source_artifact=artifact_id,
                source_path=f"{source_path_prefix}/{field_name}",
            )
        if not _json_value_equal(proof_value, expected):
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                f"relation proof artifact {field_name} conflicts with relation payload",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
                source_artifact=artifact_id,
                source_path=f"{source_path_prefix}/{field_name}",
            )
    return None


def _completion_proof_payload_failure(
    *,
    bundle: ArtifactBundle,
    ref_value: Any,
    expected_fields: Mapping[str, Any],
    source_artifact: str,
    source_path_prefix: str,
) -> ValidationResult | None:
    if ref_value is None:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            "completion admission lacks checker transcript proof",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
            source_artifact=source_artifact,
            source_path=source_path_prefix,
        )
    if not _bound_artifact_or_digest_ref(ref_value):
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            f"completion admission proof is symbolic, not ledger validated: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
            source_artifact=source_artifact,
            source_path=source_path_prefix,
        )
    artifact = _artifact_by_ref(bundle, ref_value)
    if artifact is None:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            f"completion admission proof artifact is unresolved: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
            source_artifact=source_artifact,
            source_path=source_path_prefix,
        )
    status = str(
        artifact.get(
            "status",
            artifact.get("proof_status", artifact.get("checker_status", "unknown")),
        )
    )
    if status not in {"pass", "accepted"}:
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            f"completion admission proof artifact is not accepted: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
            source_artifact=source_artifact,
            source_path=source_path_prefix,
        )
    proof_kind = str(
        artifact.get(
            "proof_kind",
            artifact.get("checker_kind", artifact.get("kind", artifact.get("evidence_kind", ""))),
        )
    )
    if proof_kind not in {"completion_admission", "completion", "checker_transcript"}:
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            "completion admission proof artifact is not purpose-bound",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
            source_artifact=source_artifact,
            source_path=source_path_prefix,
        )
    for field_name, expected in expected_fields.items():
        proof_value = _proof_payload_field(bundle, ref_value, field_name)
        if proof_value is None:
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"completion admission proof artifact lacks accepted {field_name}: {ref_value}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.OPERATIONAL,
                source_artifact=source_artifact,
                source_path=f"{source_path_prefix}/{field_name}",
            )
        if not _json_value_equal(proof_value, expected):
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                f"completion admission proof artifact {field_name} conflicts with policy",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
                source_artifact=source_artifact,
                source_path=f"{source_path_prefix}/{field_name}",
            )
    return None


def _completion_admission_content_failure(
    bundle: ArtifactBundle,
    status_context: StatusContext,
) -> ValidationResult | None:
    completion_policy = dict(status_context.completion_policy)
    if status_context.completion_admission is not None:
        completion_policy.update(status_context.completion_admission)
    if str(completion_policy.get("completion_status", "unknown")) != "pass":
        return None
    expected_fields: dict[str, Any] = {
        "completion_status": "pass",
        "admission_source": completion_policy.get("admission_source"),
        "expiry": completion_policy.get("expiry"),
        "uncertainty_model": completion_policy.get("uncertainty_model"),
        "reference_digest": completion_policy.get("reference_digest"),
        "checker_result": completion_policy.get("checker_result"),
    }
    for optional_field in ("c_out_ref", "c_in_ref"):
        if completion_policy.get(optional_field) is not None:
            expected_fields[optional_field] = completion_policy[optional_field]
    if status_context.status_time:
        expected_fields["status_time"] = status_context.status_time
    for field_name, expected in tuple(expected_fields.items()):
        if expected is None or expected == "":
            return validation_failure(
                FailureCode.COMPLETION_MISSING,
                ValidationStage.GUARD_EVALUATE,
                f"completion admission semantic identity lacks {field_name}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.OPERATIONAL,
                source_artifact=bundle.bundle_id,
                source_path=f"/completion_policy/{field_name}",
            )
    for proof_field in ("checker_transcript_ref", "completion_admission_proof_ref"):
        proof_ref = completion_policy.get(proof_field)
        if proof_ref is None and proof_field == "completion_admission_proof_ref":
            continue
        failure = _completion_proof_payload_failure(
            bundle=bundle,
            ref_value=proof_ref,
            expected_fields=expected_fields,
            source_artifact=bundle.bundle_id,
            source_path_prefix=f"/completion_policy/{proof_field}",
        )
        if failure is not None:
            return failure
    return None


def _operational_proof_content_failure(
    bundle: ArtifactBundle,
    status_context: StatusContext,
) -> ValidationResult | None:
    completion_failure = _completion_admission_content_failure(bundle, status_context)
    if completion_failure is not None:
        return completion_failure
    checks = (
        (
            "prefix_adjudication_proof_ref",
            "prefix_adjudication",
            ("prefix_adjudication", "adjudication", "result"),
            {"accept", "reject", "indeterminate", "out_of_frame"},
        ),
        (
            "target_adjudication_proof_ref",
            "target_adjudication",
            ("target_adjudication", "adjudication", "result"),
            {"accept", "reject", "indeterminate", "out_of_frame"},
        ),
        (
            "adequacy_proof_ref",
            "adequacy_direction",
            ("adequacy_direction", "adequacy", "result"),
            {"positive", "negative", "unknown", "conflict", "out_of_frame"},
        ),
    )
    for index, record in enumerate(status_context.observation_records):
        for proof_field, result_field, field_names, allowed_values in checks:
            proof_ref = record.get(proof_field)
            if proof_ref is None:
                continue
            proof_value = _proof_payload_value(bundle, proof_ref, *field_names)
            if proof_value is None:
                return validation_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    ValidationStage.GUARD_EVALUATE,
                    f"operational proof artifact lacks accepted {result_field}: {proof_ref}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    source_artifact=bundle.bundle_id,
                    source_path=f"/observation_records/{index}/{proof_field}",
                )
            if proof_value not in allowed_values:
                return validation_failure(
                    FailureCode.SCHEMA_INVALID,
                    ValidationStage.GUARD_EVALUATE,
                    f"operational proof artifact has invalid {result_field}: {proof_value}",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.OPERATIONAL,
                    source_artifact=bundle.bundle_id,
                    source_path=f"/observation_records/{index}/{proof_field}",
                )
            declared = record.get(result_field)
            if declared is not None and str(declared) != proof_value:
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    f"operational proof content conflicts with declared {result_field}",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.OPERATIONAL,
                    source_artifact=bundle.bundle_id,
                    source_path=f"/observation_records/{index}/{result_field}",
                )
    frame_policy = status_context.frame.get("policy")
    if isinstance(frame_policy, Mapping):
        proof_ref = frame_policy.get("adequacy_proof_ref")
        if proof_ref is not None:
            proof_value = _proof_payload_value(
                bundle,
                proof_ref,
                "adequacy_direction",
                "adequacy",
                "result",
            )
            if proof_value is None:
                return validation_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    ValidationStage.GUARD_EVALUATE,
                    f"frame adequacy proof artifact lacks accepted adequacy_direction: {proof_ref}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    source_artifact=bundle.bundle_id,
                    source_path="/frame/policy/adequacy_proof_ref",
                )
            if proof_value not in {"positive", "negative", "unknown", "conflict", "out_of_frame"}:
                return validation_failure(
                    FailureCode.SCHEMA_INVALID,
                    ValidationStage.GUARD_EVALUATE,
                    f"frame adequacy proof artifact has invalid adequacy_direction: {proof_value}",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.OPERATIONAL,
                    source_artifact=bundle.bundle_id,
                    source_path="/frame/policy/adequacy_proof_ref",
                )
            declared = frame_policy.get("adequacy_direction")
            if declared is not None and str(declared) != proof_value:
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    "frame adequacy proof content conflicts with declared adequacy_direction",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.OPERATIONAL,
                    source_artifact=bundle.bundle_id,
                    source_path="/frame/policy/adequacy_direction",
                )
    return None


def _enrich_status_context_from_proof_artifacts(
    bundle: ArtifactBundle, status_context: StatusContext
) -> StatusContext:
    records: list[dict[str, Any]] = []
    for source_record in status_context.observation_records:
        record = dict(source_record)
        prefix = _proof_payload_value(
            bundle,
            record.get("prefix_adjudication_proof_ref"),
            "prefix_adjudication",
            "adjudication",
            "result",
        )
        if prefix is not None:
            record["prefix_adjudication"] = prefix
        target = _proof_payload_value(
            bundle,
            record.get("target_adjudication_proof_ref"),
            "target_adjudication",
            "adjudication",
            "result",
        )
        if target is not None:
            record["target_adjudication"] = target
        adequacy = _proof_payload_value(
            bundle,
            record.get("adequacy_proof_ref"),
            "adequacy_direction",
            "adequacy",
            "result",
        )
        if adequacy is not None:
            record["adequacy_direction"] = adequacy
        records.append(record)
    frame = dict(status_context.frame)
    frame_policy = frame.get("policy")
    if isinstance(frame_policy, Mapping):
        enriched_policy = dict(frame_policy)
        adequacy = _proof_payload_value(
            bundle,
            enriched_policy.get("adequacy_proof_ref"),
            "adequacy_direction",
            "adequacy",
            "result",
        )
        if adequacy is not None:
            enriched_policy["adequacy_direction"] = adequacy
            frame["policy"] = enriched_policy
    return replace(status_context, observation_records=tuple(records), frame=frame)


def _enrich_status_context_from_relation_artifacts(
    bundle: ArtifactBundle, status_context: StatusContext
) -> StatusContext:
    if not status_context.observation_records:
        return status_context
    records: list[dict[str, Any]] = []
    for source_record in status_context.observation_records:
        record = dict(source_record)
        measurement_artifact = _artifact_by_ref(bundle, record.get("measurement_relation_ref"))
        if measurement_artifact is not None:
            relation = measurement_artifact.get("relation")
            if isinstance(relation, Mapping):
                accepted = str(measurement_artifact.get("checker_status", "")).lower() in {
                    "pass",
                    "accepted",
                }
                enriched_relation = {**dict(relation), "accepted": accepted}
                proof_refs = tuple(str(item) for item in measurement_artifact.get("proof_refs", ()))
                if proof_refs:
                    enriched_relation["proof_ref"] = proof_refs[0]
                    record["measurement_proof_ref"] = proof_refs[0]
                record["measurement_relation"] = enriched_relation
                proof_kinds = {
                    "calibration_ref": "calibration",
                    "latency_ref": "latency",
                    "dependency_ref": "dependency",
                    "event_order_ref": "event_order",
                }
                for key in ("calibration_ref", "latency_ref", "dependency_ref", "event_order_ref"):
                    if relation.get(key) is not None:
                        artifact_digest = _artifact_ref_digest(bundle, relation[key])
                        proof_artifact = _artifact_by_ref(bundle, relation[key])
                        payload: dict[str, Any] = {}
                        if proof_artifact is not None:
                            proof_payload = proof_artifact.get("proof")
                            nested_payload = proof_artifact.get("payload")
                            if isinstance(proof_payload, Mapping):
                                payload.update(proof_payload)
                            if isinstance(nested_payload, Mapping):
                                payload.update(nested_payload)
                            for field_name in (
                                "status_time",
                                "observation_time",
                                "time",
                                "time_basis",
                                "time_basis_ref",
                                "clock",
                                "clock_basis",
                                "event_order",
                                "event_order_ref",
                                "order",
                                "frame_id",
                                "target_frame_id",
                                "assessment_frame_id",
                            ):
                                if field_name in proof_artifact:
                                    payload[field_name] = proof_artifact[field_name]
                        record[key] = {
                            "checker_status": "pass" if accepted else "unknown",
                            "artifact_ref": relation[key],
                            "proof_kind": proof_kinds[key],
                            "artifact_digest": artifact_digest,
                            **({"payload": payload} if payload else {}),
                        }
        representation_artifact = _artifact_by_ref(
            bundle, record.get("representation_relation_ref")
        )
        if representation_artifact is not None:
            relations = representation_artifact.get(
                "relations", representation_artifact.get("relation")
            )
            if isinstance(relations, Mapping):
                relation_items: tuple[Any, ...] = (dict(relations),)
            elif isinstance(relations, list | tuple):
                relation_items = tuple(item for item in relations if isinstance(item, Mapping))
            else:
                relation_items = ()
            if relation_items:
                record["representation_relation"] = tuple(dict(item) for item in relation_items)
                first = relation_items[0]
                if first.get("proof_ref") is not None:
                    record["representation_proof_ref"] = first["proof_ref"]
                if first.get("operational_prefix") is not None:
                    record["operational_prefix"] = first["operational_prefix"]
                if first.get("represented_prefix") is not None:
                    record["represented_prefix"] = first["represented_prefix"]
        records.append(record)
    return replace(status_context, observation_records=tuple(records))


def _completion_set_members(source: Mapping[str, Any]) -> tuple[Any, ...] | None:
    candidates: list[Any] = [
        source.get("members"),
        source.get("elements"),
        source.get("values"),
        source.get("operational_completions"),
    ]
    nested = source.get("set")
    if isinstance(nested, Mapping):
        candidates.extend(
            (
                nested.get("members"),
                nested.get("elements"),
                nested.get("values"),
                nested.get("operational_completions"),
            )
        )
    for candidate in candidates:
        if isinstance(candidate, list | tuple):
            return tuple(candidate)
    return None


def _enrich_status_context_from_completion_set_artifacts(
    bundle: ArtifactBundle, status_context: StatusContext
) -> StatusContext:
    if not status_context.observation_records:
        return status_context
    completion_policy = dict(status_context.completion_policy)
    if status_context.completion_admission is not None:
        completion_policy.update(status_context.completion_admission)
    c_out_ref = completion_policy.get("c_out_ref")
    completion_set = _artifact_by_ref(bundle, c_out_ref)
    if completion_set is None:
        return status_context
    members = _completion_set_members(completion_set)
    if members is None:
        return status_context
    records: list[dict[str, Any]] = []
    for source_record in status_context.observation_records:
        record = dict(source_record)
        record["operational_completions"] = to_jsonable(members)
        record["_operational_completions_source"] = str(c_out_ref)
        records.append(record)
    return replace(status_context, observation_records=tuple(records))


def _accepted_clauses(
    bundle: ArtifactBundle, status_context: StatusContext
) -> tuple[AcceptedClause, ...]:
    direct = tuple(
        AcceptedClause.from_json(item)
        for item in _all_mappings(
            bundle,
            ArtifactRole.ACCEPTED_CLAUSE,
            artifact_type="accepted-clause",
        )
    )
    evidence: list[EvidenceArtifact] = []
    for item in _all_mappings(bundle, ArtifactRole.EVIDENCE, artifact_type="evidence"):
        try:
            evidence.append(EvidenceArtifact.from_json(item))
        except (KeyError, TypeError, ValueError):
            continue
    contracts: list[AdmissionContract] = []
    for item in _all_mappings(bundle, ArtifactRole.ADMISSION, artifact_type="admission"):
        try:
            contracts.append(AdmissionContract.from_json(item))
        except (KeyError, TypeError, ValueError):
            continue
    if not evidence or not contracts:
        return direct
    results = admit_evidence_set(
        tuple(evidence),
        tuple(contracts),
        {"status_time": status_context.status_time},
    )
    admitted = tuple(clause for result in results for clause in result.accepted_clause_records)
    return (*direct, *admitted)


def _trust_assumptions(bundle: ArtifactBundle) -> tuple[TrustAssumption, ...]:
    return tuple(
        TrustAssumption.from_json(item)
        for item in _all_mappings(
            bundle,
            ArtifactRole.TRUST_ASSUMPTION,
            artifact_type="trust-assumption",
        )
    )


def _kernel_proof_artifacts(bundle: ArtifactBundle) -> tuple[KernelProofArtifact, ...]:
    return tuple(
        KernelProofArtifact.from_json(item)
        for item in _all_mappings(
            bundle,
            ArtifactRole.KERNEL_PROOF,
            artifact_type="kernel-proof",
        )
    )


def _bundle_artifact_digest(bundle: ArtifactBundle, ref_value: str | None) -> str | None:
    if ref_value is None:
        return None
    artifact_id = str(ref_value).split("#", 1)[0]
    entry = next(
        (item for item in bundle.entries if str(item.artifact_ref.artifact_id) == artifact_id),
        None,
    )
    if entry is None:
        return None
    return entry.artifact_ref.digest_value


def _kernel_proof_refs(
    proofs: tuple[KernelProofArtifact, ...], bundle: ArtifactBundle
) -> tuple[ProofRef, ...]:
    refs: list[ProofRef] = []
    for proof in proofs:
        refs.append(
            ProofRef(
                proof_id=proof.artifact_id,
                proof_kind=proof.proof.proof_kind,
                artifact_ref=proof.artifact_id,
                source_artifact=proof.artifact_id,
                source_path="/",
                digest=_bundle_artifact_digest(bundle, proof.artifact_id),
                status=proof.proof.proof_status,
            )
        )
        refs.extend(
            ProofRef(
                proof_id=ref.proof_id,
                proof_kind=ref.proof_kind,
                artifact_ref=ref.artifact_ref,
                source_artifact=ref.source_artifact or ref.artifact_ref,
                source_path=ref.source_path or "/",
                digest=ref.digest or _bundle_artifact_digest(bundle, ref.artifact_ref),
                status=ref.status if ref.artifact_ref is not None else "unknown",
            )
            for ref in proof.proof_refs()
        )
    return tuple(refs)


def _set_ref_records(bundle: ArtifactBundle) -> tuple[SetRef, ...]:
    records: list[SetRef] = []
    for entry in bundle.entries:
        if not _entry_matches(entry, ArtifactRole.SET, artifact_type="set") or not isinstance(
            entry.artifact, Mapping
        ):
            continue
        artifact = entry.artifact
        records.append(
            SetRef(
                carrier_ref=str(artifact.get("carrier_ref", "")),
                encoding_kind=str(artifact.get("encoding_kind", "")),
                constraint_ref=str(artifact.get("constraint_ref", "")),
                approximation_kind=str(artifact.get("approximation_kind", "")),
                soundness_ref=str(artifact.get("soundness_ref", "")),
                digest=str(artifact.get("digest", "")),
            )
        )
    return tuple(records)


def _kernel_proof_target_failure(
    bundle: ArtifactBundle,
    proof: KernelProofArtifact,
    ref_value: str | None,
    *,
    source_path: str,
    expected_kinds: tuple[str, ...],
    expected_fields: Mapping[str, Any] | None = None,
) -> ValidationResult | None:
    if ref_value is None:
        return None
    if not ref_value.startswith("artifact:"):
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.KERNEL_CHECK,
            f"kernel proof reference is not content-resolvable: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.REPRESENTED,
            source_artifact=proof.artifact_id,
            source_path=source_path,
        )
    artifact_id, separator, pointer = ref_value.partition("#")
    result, target = resolve_reference(
        artifact_id,
        pointer if separator else "",
        store=bundle.store(),
        context=bundle.reference_context,
    )
    if not result.passed:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.KERNEL_CHECK,
            f"kernel proof target is unresolved: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.REPRESENTED,
            source_artifact=proof.artifact_id,
            source_path=source_path,
        )
    if not isinstance(target, Mapping):
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.KERNEL_CHECK,
            f"kernel proof target is not an object: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.REPRESENTED,
            source_artifact=proof.artifact_id,
            source_path=source_path,
        )
    status = str(
        target.get(
            "proof_status",
            target.get("checker_status", target.get("status", target.get("result", "unknown"))),
        )
    )
    if status not in {"pass", "accepted"}:
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.KERNEL_CHECK,
            f"kernel proof target is not accepted: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.REPRESENTED,
            source_artifact=proof.artifact_id,
            source_path=source_path,
        )
    proof_kind = target.get("proof_kind", target.get("checker_kind", target.get("kind")))
    if str(proof_kind) not in set(expected_kinds):
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.KERNEL_CHECK,
            f"kernel proof target kind mismatch for {ref_value}: expected {expected_kinds}",
            status=ValidationStatus.CONFLICT,
            layer=Layer.REPRESENTED,
            source_artifact=proof.artifact_id,
            source_path=source_path,
        )
    for field_name, expected in (expected_fields or {}).items():
        proof_value = _proof_payload_field(bundle, ref_value, field_name)
        if proof_value is None:
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.KERNEL_CHECK,
                f"kernel proof target lacks accepted {field_name}: {ref_value}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.REPRESENTED,
                source_artifact=proof.artifact_id,
                source_path=f"{source_path}/{field_name}",
            )
        if not _json_value_equal(proof_value, expected):
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.KERNEL_CHECK,
                f"kernel proof target {field_name} conflicts with KernelProofArtifact",
                status=ValidationStatus.CONFLICT,
                layer=Layer.REPRESENTED,
                source_artifact=proof.artifact_id,
                source_path=f"{source_path}/{field_name}",
            )
    return None


def _kernel_proof_failure(
    bundle: ArtifactBundle,
    proofs: tuple[KernelProofArtifact, ...],
    entries: tuple[ReferenceLedgerEntry, ...],
    *,
    bundle_id: str,
) -> ValidationResult | None:
    if not proofs:
        return None
    for proof in proofs:
        if proof.proof.proof_status not in {"pass", "accepted"}:
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.KERNEL_CHECK,
                f"kernel proof artifact is not accepted: {proof.artifact_id}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.REPRESENTED,
                source_artifact=proof.artifact_id,
                source_path="/proof/proof_status",
            )
        if proof.checker_transcript_ref is None:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.KERNEL_CHECK,
                f"kernel proof artifact lacks checker transcript: {proof.artifact_id}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.REPRESENTED,
                source_artifact=proof.artifact_id,
                source_path="/checker_transcript_ref",
            )
        if not _ledger_ref_resolved(entries, proof.checker_transcript_ref):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.KERNEL_CHECK,
                f"kernel checker transcript is unresolved: {proof.checker_transcript_ref}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.REPRESENTED,
                source_artifact=proof.artifact_id,
                source_path="/checker_transcript_ref",
            )
        for ref in proof.proof_refs():
            artifact_ref = ref.artifact_ref
            if artifact_ref is None or not artifact_ref.startswith("artifact:"):
                continue
            if not _ledger_ref_resolved(entries, artifact_ref):
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.KERNEL_CHECK,
                    f"kernel proof reference is unresolved: {artifact_ref}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.REPRESENTED,
                    source_artifact=proof.artifact_id,
                    source_path="/proof_refs",
                )
        common_expected_fields: dict[str, Any] = {"kernel_proof_ref": proof.artifact_id}
        if proof.proof.backend_identity:
            common_expected_fields["backend_identity"] = proof.proof.backend_identity
        if proof.proof.expected_verdict is not None:
            common_expected_fields["expected_verdict"] = proof.proof.expected_verdict
        target_checks: list[tuple[str | None, str, tuple[str, ...], dict[str, Any]]] = [
            (
                proof.proof.inclusion_ref,
                "/proof/inclusion_ref",
                ("inclusion", "inclusion_proof", "kernel_inclusion"),
                {
                    **common_expected_fields,
                    **(
                        {"inclusion": proof.proof.inclusion}
                        if proof.proof.inclusion is not None
                        else {}
                    ),
                },
            ),
            (
                proof.proof.disjointness_ref,
                "/proof/disjointness_ref",
                ("disjointness", "disjointness_proof", "kernel_disjointness"),
                {
                    **common_expected_fields,
                    **(
                        {"disjointness": proof.proof.disjointness}
                        if proof.proof.disjointness is not None
                        else {}
                    ),
                },
            ),
            (
                proof.proof.infeasibility_ref,
                "/proof/infeasibility_ref",
                ("infeasibility", "infeasibility_proof", "kernel_infeasibility"),
                {
                    **common_expected_fields,
                    **(
                        {"feasibility": proof.proof.feasibility}
                        if proof.proof.feasibility is not None
                        else {}
                    ),
                },
            ),
        ]
        for index, ref_value in enumerate(proof.witness_provenance_refs):
            target_checks.append(
                (
                    ref_value,
                    f"/witness_provenance_refs/{index}",
                    ("witness", "witness_provenance", "kernel_witness"),
                    common_expected_fields,
                )
            )
        for index, ref_value in enumerate(proof.proof.witness_refs):
            target_checks.append(
                (
                    ref_value,
                    f"/proof/witness_refs/{index}",
                    ("witness", "witness_provenance", "kernel_witness"),
                    common_expected_fields,
                )
            )
        for check_ref_value, source_path, expected_kinds, expected_fields in target_checks:
            target_failure = _kernel_proof_target_failure(
                bundle,
                proof,
                check_ref_value,
                source_path=source_path,
                expected_kinds=expected_kinds,
                expected_fields=expected_fields,
            )
            if target_failure is not None:
                return target_failure
    return None


def _relation_artifact_failure(
    bundle: ArtifactBundle,
    entries: tuple[ReferenceLedgerEntry, ...],
) -> ValidationResult | None:
    measurement_artifacts = _all_mappings(
        bundle,
        ArtifactRole.MEASUREMENT_RELATION,
        artifact_type="measurement-relation",
    )
    for source in measurement_artifacts:
        artifact_id = str(source.get("artifact_id", "artifact:measurement-relation"))
        if str(source.get("checker_status", "unknown")) not in {"pass", "accepted"}:
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"measurement relation artifact is not accepted: {artifact_id}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.OPERATIONAL,
                source_artifact=artifact_id,
                source_path="/checker_status",
            )
        proof_refs = tuple(str(item) for item in source.get("proof_refs", ()))
        if not proof_refs:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.GUARD_EVALUATE,
                f"measurement relation artifact lacks proof refs: {artifact_id}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.OPERATIONAL,
                source_artifact=artifact_id,
                source_path="/proof_refs",
            )
        for index, ref_value in enumerate(proof_refs):
            if not _bound_artifact_or_digest_ref(ref_value):
                return validation_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    ValidationStage.GUARD_EVALUATE,
                    "measurement relation proof ref is symbolic, "
                    f"not ledger validated: {ref_value}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    source_artifact=artifact_id,
                    source_path=f"/proof_refs/{index}",
                )
            if not _ledger_ref_resolved(entries, ref_value):
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.GUARD_EVALUATE,
                    f"measurement relation proof ref is unresolved: {ref_value}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    source_artifact=artifact_id,
                    source_path=f"/proof_refs/{index}",
                )
        relation = source.get("relation")
        if isinstance(relation, Mapping):
            expected_relation_fields = {
                "relation_id": relation.get("relation_id", artifact_id),
                "calibration_ref": relation.get("calibration_ref"),
                "latency_ref": relation.get("latency_ref"),
                "dependency_ref": relation.get("dependency_ref"),
                "event_order_ref": relation.get("event_order_ref"),
            }
            for proof_index, ref_value in enumerate(proof_refs):
                content_failure = _relation_proof_payload_failure(
                    bundle=bundle,
                    artifact_id=artifact_id,
                    proof_ref=ref_value,
                    expected_fields=expected_relation_fields,
                    source_path_prefix=f"/proof_refs/{proof_index}",
                )
                if content_failure is not None:
                    return content_failure
            for field_name in (
                "calibration_ref",
                "latency_ref",
                "dependency_ref",
                "event_order_ref",
            ):
                relation_ref = relation.get(field_name)
                if not _bound_artifact_or_digest_ref(relation_ref):
                    return validation_failure(
                        FailureCode.CHECKER_UNKNOWN,
                        ValidationStage.GUARD_EVALUATE,
                        f"measurement relation {field_name} is symbolic, not ledger validated",
                        status=ValidationStatus.UNKNOWN,
                        layer=Layer.OPERATIONAL,
                        source_artifact=artifact_id,
                        source_path=f"/relation/{field_name}",
                    )

    representation_artifacts = _all_mappings(
        bundle,
        ArtifactRole.REPRESENTATION_RELATION,
        artifact_type="representation-relation",
    )
    for source in representation_artifacts:
        artifact_id = str(source.get("artifact_id", "artifact:representation-relation"))
        if str(source.get("checker_status", "unknown")) not in {"pass", "accepted"}:
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"representation relation artifact is not accepted: {artifact_id}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.OPERATIONAL,
                source_artifact=artifact_id,
                source_path="/checker_status",
            )
        relations = source.get("relations", source.get("relation", ()))
        if isinstance(relations, Mapping):
            relation_items: tuple[Any, ...] = (relations,)
        elif isinstance(relations, list | tuple):
            relation_items = tuple(item for item in relations if isinstance(item, Mapping))
        else:
            relation_items = ()
        if not relation_items:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.GUARD_EVALUATE,
                f"representation relation artifact lacks relation records: {artifact_id}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.OPERATIONAL,
                source_artifact=artifact_id,
                source_path="/relations",
            )
        for index, relation in enumerate(relation_items):
            proof_ref = relation.get("proof_ref")
            if not _bound_artifact_or_digest_ref(proof_ref):
                return validation_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    ValidationStage.GUARD_EVALUATE,
                    "representation relation proof ref is symbolic, "
                    f"not ledger validated: {proof_ref}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    source_artifact=artifact_id,
                    source_path=f"/relations/{index}/proof_ref",
                )
            if not _ledger_ref_resolved(entries, proof_ref):
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.GUARD_EVALUATE,
                    f"representation relation proof ref is unresolved: {proof_ref}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.OPERATIONAL,
                    source_artifact=artifact_id,
                    source_path=f"/relations/{index}/proof_ref",
                )
            expected_relation_fields = {
                "relation_id": relation.get("relation_id", artifact_id),
                "operational_prefix": relation.get("operational_prefix", ()),
                "represented_prefix": relation.get("represented_prefix", ()),
            }
            content_failure = _relation_proof_payload_failure(
                bundle=bundle,
                artifact_id=artifact_id,
                proof_ref=proof_ref,
                expected_fields=expected_relation_fields,
                source_path_prefix=f"/relations/{index}/proof_ref",
            )
            if content_failure is not None:
                return content_failure
    return None


def _certificate_from_bundle(
    bundle: ArtifactBundle,
    status_context: StatusContext,
    accepted_clauses: tuple[AcceptedClause, ...],
    trust_assumptions: tuple[TrustAssumption, ...],
    *,
    strict_sources: bool = False,
) -> IssueCertificate | ValidationResult:
    certificate_source = _first_mapping(
        bundle,
        ArtifactRole.ISSUE_CERTIFICATE,
        artifact_type="issue-certificate",
    )
    if certificate_source is not None:
        certificate = IssueCertificate.from_json(certificate_source)
        replacements: dict[str, dict[str, Any]] = {}
        source_refs = (
            ("claim_source", certificate.claim_ref),
            ("bundle_source", certificate.assumption_bundle_ref),
            ("anchor_source", certificate.anchor_ref),
            ("time_basis_source", certificate.time_basis_ref),
        )
        for field_name, artifact_id in source_refs:
            artifact = _artifact_by_id(bundle, artifact_id)
            if artifact is not None:
                replacements[field_name] = artifact
            elif strict_sources:
                return _missing(
                    f"authority replay requires explicit artifact for certificate ref "
                    f"{artifact_id}",
                    source_artifact=bundle.bundle_id,
                    source_path=f"/certificate/{field_name}",
                )
        if replacements:
            certificate = replace(
                certificate,
                claim_source=replacements.get("claim_source", certificate.claim_source),
                bundle_source=replacements.get("bundle_source", certificate.bundle_source),
                anchor_source=replacements.get("anchor_source", certificate.anchor_source),
                time_basis_source=replacements.get(
                    "time_basis_source", certificate.time_basis_source
                ),
            )
    else:
        claim = _first_mapping(bundle, ArtifactRole.CLAIM, artifact_type="claim")
        source_bundle = _first_mapping(
            bundle,
            ArtifactRole.ASSUMPTION_BUNDLE,
            artifact_type="bundle",
        )
        anchor = _first_mapping(bundle, ArtifactRole.ANCHOR, artifact_type="anchor")
        time_basis = _first_mapping(bundle, ArtifactRole.TIME_BASIS, artifact_type="time-basis")
        if claim is None or source_bundle is None or anchor is None or time_basis is None:
            return _missing(
                "authority replay requires issue certificate or claim/bundle/anchor/time_basis",
                source_artifact=bundle.bundle_id,
                source_path="/manifest/root_artifact_id",
            )
        issued = certify_claim(claim, source_bundle, anchor, time_basis)
        if isinstance(issued, ValidationResult):
            return issued
        certificate = issued

    if accepted_clauses:
        target_failure = _accepted_clause_target_failure(
            accepted_clauses,
            certificate.bundle_source,
        )
        if target_failure is not None:
            return target_failure
        accepted_bundle = assumption_bundle_from_accepted_clauses(
            certificate.bundle_source,
            accepted_clauses,
        )
        compiled = compile_bundle(accepted_bundle, certificate.claim_source["horizon"])
        certificate = replace(
            certificate,
            bundle_source=assumption_bundle_to_json(accepted_bundle),
            assumption_bundle_ref=f"accepted-bundle:{accepted_bundle.bundle_id}",
            compiled_semantics_ref=f"compiled:{compiled.bundle_id}",
            obligation_refs=tuple(
                dict.fromkeys((*certificate.obligation_refs, *compiled.obligations))
            ),
        )
    elif trust_assumptions:
        obligations = tuple(
            dict.fromkeys(
                (
                    *certificate.obligation_refs,
                    *(item for trust in trust_assumptions for item in trust.obligation_refs),
                    *(trust.assumption_id for trust in trust_assumptions),
                )
            )
        )
        certificate = replace(certificate, obligation_refs=obligations)
    return certificate


def _proposed_use_from_bundle(bundle: ArtifactBundle) -> ProposedUse | ValidationResult:
    source = _first_mapping(bundle, ArtifactRole.PROPOSED_USE, artifact_type="proposed-use")
    if source is None:
        return _missing(
            "authority replay requires proposed_use artifact",
            source_artifact=bundle.bundle_id,
            source_path="/artifacts/proposed_use",
        )
    return ProposedUse.from_json(source)


def _status_context_from_bundle(bundle: ArtifactBundle) -> StatusContext | ValidationResult:
    source = _first_mapping(bundle, ArtifactRole.STATUS_CONTEXT, artifact_type="status-context")
    if source is None:
        source = _first_mapping(bundle, ArtifactRole.STATUS, artifact_type="status")
    if source is None:
        return _missing(
            "authority replay requires status_context artifact",
            source_artifact=bundle.bundle_id,
            source_path="/artifacts/status_context",
        )
    lifecycle_events = _all_mappings(
        bundle,
        ArtifactRole.LIFECYCLE_EVENT,
        artifact_type="lifecycle-event",
    )
    observations = _all_mappings(bundle, ArtifactRole.OBSERVATION, artifact_type="observation")
    if lifecycle_events or observations:
        source = dict(source)
        if lifecycle_events:
            source["event_log"] = [
                *list(source.get("event_log", ())),
                *list(lifecycle_events),
            ]
        if observations:
            records: list[dict[str, Any]] = list(source.get("observation_records", ()))
            for observation in observations:
                nested = observation.get("records")
                if isinstance(nested, list | tuple):
                    records.extend(dict(item) for item in nested if isinstance(item, Mapping))
                else:
                    records.append(observation)
            source["observation_records"] = records
    return StatusContext.from_json(source)


def _enrich_status_context_from_lifecycle_artifacts(
    bundle: ArtifactBundle,
    status_context: StatusContext,
) -> StatusContext:
    confluence_proof = status_context.confluence_proof
    if isinstance(confluence_proof, str):
        artifact = _artifact_by_ref(bundle, confluence_proof)
        if artifact is not None:
            confluence_proof = {
                **artifact,
                "artifact_ref": confluence_proof,
            }
    if confluence_proof is None:
        for event in status_context.event_log:
            ref_value = event.get("confluence_proof_ref") if isinstance(event, Mapping) else None
            artifact = _artifact_by_ref(bundle, ref_value)
            if artifact is not None:
                confluence_proof = {
                    **artifact,
                    "artifact_ref": ref_value,
                }
                break
    if confluence_proof is status_context.confluence_proof:
        return status_context
    return replace(status_context, confluence_proof=confluence_proof)


def _split_resolved_refs(
    resolved_refs: tuple[ResolvedReference, ...],
) -> tuple[tuple[ResolvedReference, ...], tuple[ResolvedReference, ...]]:
    reasons = []
    obligations = []
    for item in resolved_refs:
        material = f"{item.source_artifact} {item.source_path}".lower()
        if "obligation" in material:
            obligations.append(item)
        elif "reason" in material:
            reasons.append(item)
    return tuple(obligations), tuple(reasons)


def _split_ledger_refs(
    entries: tuple[ReferenceLedgerEntry, ...],
) -> tuple[tuple[ResolvedReference, ...], tuple[ResolvedReference, ...]]:
    obligations = tuple(
        ResolvedReference(entry.target_artifact_id, entry.target_path, entry.target_digest or "")
        for entry in entries
        if entry.kind is ReferenceKind.OBLIGATION and entry.resolved and entry.target_digest
    )
    reasons = tuple(
        ResolvedReference(entry.target_artifact_id, entry.target_path, entry.target_digest or "")
        for entry in entries
        if entry.kind is ReferenceKind.REASON and entry.resolved and entry.target_digest
    )
    return obligations, reasons


def _unresolved_required(
    entries: tuple[ReferenceLedgerEntry, ...],
) -> tuple[ReferenceLedgerEntry, ...]:
    return tuple(entry for entry in entries if entry.required and not entry.resolved)


def _ledger_ref_resolved(entries: tuple[ReferenceLedgerEntry, ...], ref_value: Any) -> bool:
    return _ledger_ref_entry(entries, ref_value) is not None


def _ledger_ref_entry(
    entries: tuple[ReferenceLedgerEntry, ...],
    ref_value: Any,
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
) -> FailureCode | None:
    entry = _ledger_ref_entry(entries, ref_value)
    if entry is None:
        return FailureCode.MISSING_REF
    if expected_kind is not None and entry.kind is not expected_kind:
        return FailureCode.ARTIFACT_CONFLICT
    if expected_role is not None and entry.semantic_role != expected_role:
        return FailureCode.ARTIFACT_CONFLICT
    return None


def _ledger_ref_required(ref_value: Any) -> bool:
    return isinstance(ref_value, str) and (
        "#" in ref_value or ref_value.startswith(("artifact:", "synthetic:"))
    )


def _lifecycle_proof_ref_like(ref_value: Any) -> bool:
    return _bound_artifact_or_digest_ref(ref_value)


def _lifecycle_proof_payloads(
    bundle: ArtifactBundle,
    ref_value: Any,
) -> tuple[Mapping[str, Any], ...]:
    artifact = _artifact_by_ref(bundle, ref_value)
    if artifact is None:
        return ()
    payloads: list[Mapping[str, Any]] = [artifact]
    proof_payload = artifact.get("proof")
    if isinstance(proof_payload, Mapping):
        payloads.append(proof_payload)
    return tuple(payloads)


def _payload_first(payloads: tuple[Mapping[str, Any], ...], *keys: str) -> Any:
    for payload in payloads:
        for key in keys:
            value = payload.get(key)
            if value is not None:
                return value
    return None


def _payload_string_set(payloads: tuple[Mapping[str, Any], ...], *keys: str) -> set[str]:
    values: set[str] = set()
    for payload in payloads:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str):
                values.add(value)
            elif isinstance(value, list | tuple | set):
                values.update(str(item) for item in value)
    return values


def _lifecycle_proof_content_failure(
    bundle: ArtifactBundle,
    ref_value: Any,
    *,
    expected_kinds: tuple[str, ...],
    source_artifact: str,
    source_path: str,
    required_event_ids: tuple[str, ...] = (),
    required_signature_result: str | None = None,
    required_manifest_digest: str | None = None,
    required_trace_kind: str | None = None,
    required_causal_cut: tuple[str, ...] = (),
    required_log_hashes: tuple[str, ...] = (),
) -> ValidationResult | None:
    payloads = _lifecycle_proof_payloads(bundle, ref_value)
    if not payloads:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.AUTHORITY_EMIT,
            f"lifecycle proof artifact payload is missing: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.STATUS,
            source_artifact=source_artifact,
            source_path=source_path,
        )
    status = str(
        _payload_first(
            payloads,
            "proof_status",
            "checker_status",
            "status",
            "result",
            "checker_result",
        )
    )
    if status not in {"pass", "accepted"}:
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.AUTHORITY_EMIT,
            f"lifecycle proof artifact is not accepted: {ref_value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.STATUS,
            source_artifact=source_artifact,
            source_path=source_path,
        )
    proof_kind = str(
        _payload_first(payloads, "proof_kind", "checker_kind", "kind", "evidence_kind")
    )
    if proof_kind not in set(expected_kinds):
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.AUTHORITY_EMIT,
            f"lifecycle proof artifact has wrong kind: {proof_kind}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.STATUS,
            source_artifact=source_artifact,
            source_path=source_path,
        )
    if required_event_ids:
        event_ids = _payload_string_set(
            payloads,
            "event_ids",
            "accepted_event_ids",
            "covered_event_ids",
        )
        if not set(required_event_ids).issubset(event_ids):
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.AUTHORITY_EMIT,
                "lifecycle proof artifact does not cover the required event ids",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.STATUS,
                source_artifact=source_artifact,
                source_path=source_path,
            )
    if required_signature_result is not None:
        signature_result = str(
            _payload_first(
                payloads,
                "signature_verifier_result",
                "signature_result",
                "verification_result",
                "checker_result",
            )
        )
        if signature_result != required_signature_result:
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.AUTHORITY_EMIT,
                "signature verifier proof result does not match the lifecycle event",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.STATUS,
                source_artifact=source_artifact,
                source_path=source_path,
            )
    if required_manifest_digest is not None:
        manifest_digest_value = str(
            _payload_first(payloads, "event_manifest_digest", "manifest_digest")
        )
        if manifest_digest_value != required_manifest_digest:
            return validation_failure(
                FailureCode.DIGEST_MISMATCH,
                ValidationStage.AUTHORITY_EMIT,
                "event manifest proof digest does not match the lifecycle event",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
                source_artifact=source_artifact,
                source_path=source_path,
            )
    if required_trace_kind is not None:
        trace_class = _payload_string_set(payloads, "trace_class", "accepted_trace_class")
        if required_trace_kind not in trace_class:
            return validation_failure(
                FailureCode.TRACE_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "trace-class proof does not admit the lifecycle event kind",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
                source_artifact=source_artifact,
                source_path=source_path,
            )
    if required_causal_cut:
        causal_cut = _payload_string_set(payloads, "causal_cut", "accepted_causal_cut")
        if not set(required_causal_cut).issubset(causal_cut):
            return validation_failure(
                FailureCode.TRACE_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "causal-cut proof does not cover the lifecycle event ancestry",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
                source_artifact=source_artifact,
                source_path=source_path,
            )
    log_root = _payload_first(payloads, "log_root", "root")
    if log_root is not None and str(log_root) not in set(required_log_hashes):
        return validation_failure(
            FailureCode.TRACE_CONFLICT,
            ValidationStage.AUTHORITY_EMIT,
            "log-root proof is not committed by the lifecycle event hashes",
            status=ValidationStatus.CONFLICT,
            layer=Layer.STATUS,
            source_artifact=source_artifact,
            source_path=source_path,
        )
    return None


def _accepted_clause_target_failure(
    accepted_clauses: tuple[AcceptedClause, ...],
    base_bundle: Mapping[str, Any],
) -> ValidationResult | None:
    bundle_id = str(base_bundle.get("bundle_id", "")).strip()
    allowed_targets = {"semantics"}
    if bundle_id:
        allowed_targets.update(
            {
                bundle_id,
                f"bundle:{bundle_id}",
                f"compiled:{bundle_id}",
                f"accepted-bundle:{bundle_id}",
            }
        )
    for clause in accepted_clauses:
        if clause.target not in allowed_targets:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause target {clause.target!r} does not license this bundle",
                status=ValidationStatus.CONFLICT,
                layer=Layer.VALIDATION,
                source_artifact=clause.clause_id,
                source_path="/target",
            )
    return None


def _accepted_clause_monitor_required(source: Mapping[str, Any]) -> bool:
    if bool(source.get("monitor_required", False)):
        return True
    return any("monitor" in str(item).lower() for item in source.get("obligation_refs", ()))


def _accepted_clause_monitor_ref(source: Mapping[str, Any]) -> tuple[str, str] | None:
    for field_name in ("monitor_evidence_ref", "monitor_completeness_ref"):
        value = source.get(field_name)
        if isinstance(value, str) and value:
            return field_name, value
    return None


def _accepted_clause_monitor_expected_role(field_name: str) -> str:
    if field_name == "monitor_evidence_ref":
        return ArtifactRole.EVIDENCE.value
    return "proof"


def _accepted_clause_provenance_failure(
    bundle: ArtifactBundle,
    source: Mapping[str, Any],
    *,
    clause_id: str,
    layer: Layer,
) -> ValidationResult | None:
    contract_source = _artifact_by_ref(bundle, source.get("contract_ref"))
    if contract_source is None:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            f"accepted clause contract payload is unresolved: {source.get('contract_ref')}",
            status=ValidationStatus.UNKNOWN,
            layer=layer,
            source_artifact=clause_id,
            source_path="/contract_ref",
        )
    evidence_source = _artifact_by_ref(bundle, source.get("evidence_ref"))
    if evidence_source is None:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            f"accepted clause evidence payload is unresolved: {source.get('evidence_ref')}",
            status=ValidationStatus.UNKNOWN,
            layer=layer,
            source_artifact=clause_id,
            source_path="/evidence_ref",
        )
    try:
        contract = AdmissionContract.from_json(contract_source)
        evidence = EvidenceArtifact.from_json(evidence_source)
    except (KeyError, TypeError, ValueError) as exc:
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.GUARD_EVALUATE,
            f"accepted clause provenance payload is not typed: {exc}",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=layer,
            source_artifact=clause_id,
            source_path="/contract_ref",
        )
    if contract.target != str(source.get("target", "")):
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause target conflicts with admission contract",
            status=ValidationStatus.CONFLICT,
            layer=layer,
            source_artifact=clause_id,
            source_path="/target",
        )
    if digest_json(contract.clause) != digest_json(dict(source.get("clause", {}))):
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause payload conflicts with admission contract clause",
            status=ValidationStatus.CONFLICT,
            layer=layer,
            source_artifact=clause_id,
            source_path="/clause",
        )
    if contract.checker_transcript_ref != str(source.get("checker_transcript_ref", "")):
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause checker transcript conflicts with admission contract",
            status=ValidationStatus.CONFLICT,
            layer=layer,
            source_artifact=clause_id,
            source_path="/checker_transcript_ref",
        )
    if evidence.artifact_id != contract.source or evidence.kind != contract.kind:
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause evidence conflicts with admission contract source or kind",
            status=ValidationStatus.CONFLICT,
            layer=layer,
            source_artifact=clause_id,
            source_path="/evidence_ref",
        )
    if contract.reference_digest is not None:
        accepted_digests = {
            str(evidence.payload.get("digest", "")),
            *evidence.artifact_refs,
        }
        if contract.reference_digest not in accepted_digests:
            return validation_failure(
                FailureCode.DIGEST_MISMATCH,
                ValidationStage.GUARD_EVALUATE,
                "accepted clause evidence does not carry admission reference digest",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=layer,
                source_artifact=clause_id,
                source_path="/evidence_ref",
            )
    return None


def _direct_accepted_clause_failure(
    bundle: ArtifactBundle,
    entries: tuple[ReferenceLedgerEntry, ...],
    *,
    status_time: str | None,
) -> ValidationResult | None:
    direct = _all_mappings(
        bundle,
        ArtifactRole.ACCEPTED_CLAUSE,
        artifact_type="accepted-clause",
    )
    for index, source in enumerate(direct):
        clause_id = str(source.get("clause_id", f"accepted:{index}"))
        if str(source.get("validity_status", "pass")) != "pass":
            return validation_failure(
                FailureCode.VALIDITY_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause validity is {source.get('validity_status')}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.VALIDATION,
                source_artifact=clause_id,
                source_path="/validity_status",
            )
        if str(source.get("monitor_status", "pass")) != "pass":
            return validation_failure(
                FailureCode.VALIDITY_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause monitor status is {source.get('monitor_status')}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.VALIDATION,
                source_artifact=clause_id,
                source_path="/monitor_status",
            )
        monitor_ref_info = _accepted_clause_monitor_ref(source)
        if _accepted_clause_monitor_required(source) and monitor_ref_info is None:
            return validation_failure(
                FailureCode.VALIDITY_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                "accepted clause monitor obligation lacks monitor evidence or completeness ref",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.VALIDATION,
                source_artifact=clause_id,
                source_path="/monitor_evidence_ref",
            )
        if monitor_ref_info is not None:
            monitor_field, monitor_ref = monitor_ref_info
            problem = _ledger_ref_problem(
                entries,
                monitor_ref,
                expected_kind=ReferenceKind.ARTIFACT,
                expected_role=_accepted_clause_monitor_expected_role(monitor_field),
            )
            if problem is not None:
                return validation_failure(
                    problem,
                    ValidationStage.GUARD_EVALUATE,
                    f"accepted clause cannot resolve matching {monitor_field}: {monitor_ref}",
                    status=(
                        ValidationStatus.CONFLICT
                        if problem is FailureCode.ARTIFACT_CONFLICT
                        else ValidationStatus.UNKNOWN
                    ),
                    layer=Layer.VALIDATION,
                    source_artifact=clause_id,
                    source_path=f"/{monitor_field}",
                )
        field_expectations = {
            "evidence_ref": (ReferenceKind.ARTIFACT, ArtifactRole.EVIDENCE.value),
            "contract_ref": (ReferenceKind.ARTIFACT, ArtifactRole.ADMISSION.value),
            "checker_transcript_ref": (ReferenceKind.TRANSCRIPT, None),
        }
        obligation_record_failure = accepted_clause_obligation_record_result(
            source,
            entries,
            clause_id=clause_id,
            source_layer=Layer.VALIDATION,
            status_time=status_time,
        )
        if obligation_record_failure is not None:
            return obligation_record_failure
        reason_record_failure = accepted_clause_reason_record_result(
            source,
            entries,
            clause_id=clause_id,
            source_layer=Layer.VALIDATION,
        )
        if reason_record_failure is not None:
            return reason_record_failure
        for field_name, (expected_kind, expected_role) in field_expectations.items():
            ref_value = source.get(field_name)
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
                    f"accepted clause lacks matching {field_name}: {ref_value}",
                    status=(
                        ValidationStatus.CONFLICT
                        if problem is FailureCode.ARTIFACT_CONFLICT
                        else ValidationStatus.UNKNOWN
                    ),
                    layer=Layer.VALIDATION,
                    source_artifact=clause_id,
                    source_path=f"/{field_name}",
                )
        provenance_failure = _accepted_clause_provenance_failure(
            bundle,
            source,
            clause_id=clause_id,
            layer=Layer.VALIDATION,
        )
        if provenance_failure is not None:
            return provenance_failure
        for field_name in ("obligation_refs", "reason_refs"):
            values = tuple(source.get(field_name, ()))
            if not values:
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.GUARD_EVALUATE,
                    f"accepted clause lacks {field_name}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.VALIDATION,
                    source_artifact=clause_id,
                    source_path=f"/{field_name}",
                )
            for item_index, ref_value in enumerate(values):
                candidate = ref_value
                if isinstance(ref_value, Mapping):
                    source_artifact = ref_value.get("source_artifact")
                    source_path = ref_value.get("source_path", "")
                    candidate = f"{source_artifact}#{source_path}" if source_artifact else None
                if not _ledger_ref_required(candidate):
                    return validation_failure(
                        FailureCode.CHECKER_UNKNOWN,
                        ValidationStage.GUARD_EVALUATE,
                        f"accepted clause {field_name} item is not ledger-addressed: {candidate}",
                        status=ValidationStatus.UNKNOWN,
                        layer=Layer.VALIDATION,
                        source_artifact=clause_id,
                        source_path=f"/{field_name}/{item_index}",
                    )
                expected_kind = (
                    ReferenceKind.OBLIGATION
                    if field_name == "obligation_refs"
                    else ReferenceKind.REASON
                )
                expected_role = (
                    ArtifactRole.OBLIGATION.value
                    if field_name == "obligation_refs"
                    else ArtifactRole.REASON.value
                )
                problem = _ledger_ref_problem(
                    entries,
                    candidate,
                    expected_kind=expected_kind,
                    expected_role=expected_role,
                )
                if problem is not None:
                    return validation_failure(
                        problem,
                        ValidationStage.GUARD_EVALUATE,
                        f"accepted clause cannot resolve matching {field_name}: {candidate}",
                        status=(
                            ValidationStatus.CONFLICT
                            if problem is FailureCode.ARTIFACT_CONFLICT
                            else ValidationStatus.UNKNOWN
                        ),
                        layer=Layer.VALIDATION,
                        source_artifact=clause_id,
                        source_path=f"/{field_name}/{item_index}",
                    )
    return None


def _direct_accepted_clause_schema_failure(bundle: ArtifactBundle) -> ValidationResult | None:
    direct = _all_mappings(
        bundle,
        ArtifactRole.ACCEPTED_CLAUSE,
        artifact_type="accepted-clause",
    )
    for index, source in enumerate(direct):
        clause_id = str(source.get("clause_id", f"accepted:{index}"))
        result = validate_named_schema(
            source,
            "accepted-clause.schema.json",
            artifact_id=clause_id,
        )
        if not result.passed:
            return result
    return None


def _lifecycle_ref_failure(
    bundle: ArtifactBundle,
    status_context: StatusContext,
    entries: tuple[ReferenceLedgerEntry, ...],
    *,
    bundle_id: str,
) -> ValidationResult | None:
    if status_context.confluence_proof is not None:
        from dfcc.lifecycle import CONFLUENCE_PROOF_KINDS

        if not _lifecycle_proof_ref_like(status_context.confluence_proof):
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.AUTHORITY_EMIT,
                "lifecycle confluence proof is symbolic, not ledger validated",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.STATUS,
                source_artifact=bundle_id,
                source_path="/confluence_proof",
            )
        if not _ledger_ref_resolved(entries, status_context.confluence_proof):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "lifecycle replay cannot resolve status confluence proof: "
                f"{status_context.confluence_proof}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.STATUS,
                source_artifact=bundle_id,
                source_path="/confluence_proof",
            )
        content_failure = _lifecycle_proof_content_failure(
            bundle,
            status_context.confluence_proof,
            expected_kinds=CONFLUENCE_PROOF_KINDS,
            source_artifact=bundle_id,
            source_path="/confluence_proof",
            required_event_ids=tuple(
                str(event["event_id"])
                for event in status_context.event_log
                if isinstance(event, Mapping) and event.get("event_id") is not None
            ),
        )
        if content_failure is not None:
            return content_failure
    for event_index, event in enumerate(status_context.event_log):
        payload = event.get("payload", {}) if isinstance(event, Mapping) else {}
        event_id = str(event.get("event_id", "")) if isinstance(event, Mapping) else ""
        signature_required = (
            isinstance(payload, Mapping) and str(payload.get("signature_policy")) == "required"
        )
        if signature_required and not event.get("signature_verifier_result_ref"):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "required lifecycle signature verification must be backed by a resolved "
                "signature_verifier_result_ref",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.STATUS,
                source_artifact=bundle_id,
                source_path=f"/event_log/{event_index}/signature_verifier_result_ref",
            )
        if event.get("manifest_digest") is not None and not event.get("manifest_digest_ref"):
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.AUTHORITY_EMIT,
                "lifecycle event manifest digest is declared without a ledger-resolved "
                "manifest_digest_ref",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.STATUS,
                source_artifact=bundle_id,
                source_path=f"/event_log/{event_index}/manifest_digest_ref",
            )
        for key in (
            "confluence_proof_ref",
            "signature_verifier_result_ref",
            "log_root_ref",
            "causal_cut_ref",
            "trace_class_ref",
            "event_manifest_ref",
            "manifest_digest_ref",
        ):
            ref_value = event.get(key) if isinstance(event, Mapping) else None
            if ref_value is None:
                continue
            if not _lifecycle_proof_ref_like(ref_value):
                return validation_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    ValidationStage.AUTHORITY_EMIT,
                    f"lifecycle {key} is symbolic, not ledger validated",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.STATUS,
                    source_artifact=bundle_id,
                    source_path=f"/event_log/{event_index}/{key}",
                )
            if not _ledger_ref_resolved(entries, ref_value):
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.AUTHORITY_EMIT,
                    f"lifecycle replay cannot resolve required {key}: {ref_value}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.STATUS,
                    source_artifact=bundle_id,
                    source_path=f"/event_log/{event_index}/{key}",
                )
            if key == "confluence_proof_ref":
                from dfcc.lifecycle import CONFLUENCE_PROOF_KINDS

                required_ids = [event_id]
                if isinstance(payload, Mapping) and payload.get("conflicts_with") is not None:
                    required_ids.append(str(payload["conflicts_with"]))
                content_failure = _lifecycle_proof_content_failure(
                    bundle,
                    ref_value,
                    expected_kinds=CONFLUENCE_PROOF_KINDS,
                    source_artifact=bundle_id,
                    source_path=f"/event_log/{event_index}/{key}",
                    required_event_ids=tuple(item for item in required_ids if item),
                )
            elif key == "signature_verifier_result_ref":
                content_failure = _lifecycle_proof_content_failure(
                    bundle,
                    ref_value,
                    expected_kinds=(
                        "signature_verifier",
                        "signature-verifier",
                        "signature_validation",
                        "signature-validation",
                    ),
                    source_artifact=bundle_id,
                    source_path=f"/event_log/{event_index}/{key}",
                    required_signature_result=str(event.get("signature_verifier_result")),
                )
            elif key in {"manifest_digest_ref", "event_manifest_ref"}:
                content_failure = _lifecycle_proof_content_failure(
                    bundle,
                    ref_value,
                    expected_kinds=(
                        "event_manifest_digest",
                        "event-manifest-digest",
                        "manifest_digest",
                        "event_manifest",
                        "event-manifest",
                    ),
                    source_artifact=bundle_id,
                    source_path=f"/event_log/{event_index}/{key}",
                    required_manifest_digest=str(event.get("manifest_digest"))
                    if event.get("manifest_digest") is not None
                    else None,
                    required_event_ids=(event_id,) if key == "event_manifest_ref" else (),
                )
            elif key == "trace_class_ref":
                content_failure = _lifecycle_proof_content_failure(
                    bundle,
                    ref_value,
                    expected_kinds=("trace_class", "trace-class"),
                    source_artifact=bundle_id,
                    source_path=f"/event_log/{event_index}/{key}",
                    required_trace_kind=str(event.get("kind")),
                )
            elif key == "causal_cut_ref":
                content_failure = _lifecycle_proof_content_failure(
                    bundle,
                    ref_value,
                    expected_kinds=("causal_cut", "causal-cut"),
                    source_artifact=bundle_id,
                    source_path=f"/event_log/{event_index}/{key}",
                    required_causal_cut=tuple(str(item) for item in event.get("ancestry", ())),
                )
            elif key == "log_root_ref":
                content_failure = _lifecycle_proof_content_failure(
                    bundle,
                    ref_value,
                    expected_kinds=("log_root", "log-root"),
                    source_artifact=bundle_id,
                    source_path=f"/event_log/{event_index}/{key}",
                    required_log_hashes=tuple(str(item) for item in event.get("hashes", ())),
                )
            else:
                content_failure = None
            if content_failure is not None:
                return content_failure
    return None


def _stage_pass(stage: ValidationStage, artifact_refs: tuple[str, ...]) -> ValidationResult:
    return ValidationResult(stage, ValidationStatus.PASS, artifact_refs=artifact_refs)


def _stage_status_from_block(block: BlockingRecord) -> ValidationStatus:
    if block.failure_code in {
        FailureCode.ARTIFACT_CONFLICT,
        FailureCode.ASSOC_MIXED,
        FailureCode.TRACE_CONFLICT,
        FailureCode.VALIDITY_CONFLICT,
    }:
        return ValidationStatus.CONFLICT
    if block.failure_code in {
        FailureCode.CANONICALIZATION_MISMATCH,
        FailureCode.DIGEST_MISMATCH,
        FailureCode.SCHEMA_INVALID,
        FailureCode.UNSUPPORTED_PROFILE,
    }:
        return ValidationStatus.INVALID_ARTIFACT
    return ValidationStatus.UNKNOWN


def _stage_result_from_blocks(
    stage: ValidationStage,
    artifact_refs: tuple[str, ...],
    blocking_records: tuple[BlockingRecord, ...],
    reason_refs: tuple[Any, ...],
) -> ValidationResult:
    stage_failure_codes = {
        FailureCode.ARTIFACT_CONFLICT,
        FailureCode.CANONICALIZATION_MISMATCH,
        FailureCode.CHECKER_UNKNOWN,
        FailureCode.DIGEST_MISMATCH,
        FailureCode.MISSING_REF,
        FailureCode.SCHEMA_INVALID,
        FailureCode.TRACE_CONFLICT,
        FailureCode.UNSUPPORTED_PROFILE,
        FailureCode.VALIDITY_CONFLICT,
    }
    stage_failures = tuple(
        block for block in blocking_records if block.failure_code in stage_failure_codes
    )
    if not stage_failures:
        return _stage_pass(stage, artifact_refs)
    first = stage_failures[0]
    failures = tuple(
        FailureRecord(
            failure_id=block.block_id,
            code=block.failure_code,
            layer=block.layer,
            stage=stage,
            severity=block.severity,
            blocking=True,
            reason_refs=block.reason_refs,
        )
        for block in stage_failures
    )
    typed_reasons = tuple(ref for ref in reason_refs if hasattr(ref, "reason_id"))
    if not typed_reasons:
        typed_reasons = tuple(
            ref
            for block in stage_failures
            for ref in block.reason_refs
            if hasattr(ref, "reason_id")
        )
    return ValidationResult(
        stage,
        _stage_status_from_block(first),
        failure_records=failures,
        artifact_refs=artifact_refs,
        reason_refs=typed_reasons,
    )


def _construction_sources(
    runtime: ResolvedAuthorityRuntime,
    *,
    stage: ValidationStage,
    owner_path_contains: tuple[str, ...] = (),
    target_artifact_contains: tuple[str, ...] = (),
    kinds: tuple[ReferenceKind, ...] = (),
    include_accepted_clauses: bool = False,
    include_compiled_bundle: bool = False,
) -> dict[str, Any]:
    def matches(entry: ReferenceLedgerEntry) -> bool:
        if kinds and entry.kind not in kinds:
            return False
        if owner_path_contains and any(token in entry.owner_path for token in owner_path_contains):
            return True
        if target_artifact_contains and any(
            token in entry.target_artifact_id for token in target_artifact_contains
        ):
            return True
        return not owner_path_contains and not target_artifact_contains

    ledger_entries = tuple(
        entry for entry in runtime.ledger_entries if entry.resolved and matches(entry)
    )
    proof_ref_records = tuple(
        ref
        for ref in runtime.proof_refs
        if any(ref.proof_id == entry.target_artifact_id for entry in ledger_entries)
    )
    return {
        "stage": stage.value,
        "strict_replay": runtime.strict_replay,
        "ledger_entries": [entry.to_json() for entry in ledger_entries],
        "proof_ref_records": [_proof_ref_record(ref) for ref in proof_ref_records],
        "accepted_clause_refs": list(runtime.accepted_clause_refs)
        if include_accepted_clauses
        else [],
        "compiled_bundle_ref": runtime.compiled_bundle_ref if include_compiled_bundle else None,
    }


def _build_replay_trace(
    *,
    bundle: ArtifactBundle,
    context_bundle_id: str,
    view: StatusAuthorityView,
    runtime: ResolvedAuthorityRuntime,
    accepted: tuple[AcceptedClause, ...],
    proposed_use: ProposedUse,
    status_context: StatusContext,
) -> ReplayTrace:
    artifact_ids = tuple(entry.artifact_ref.artifact_id for entry in bundle.entries)
    artifact_records_by_id = {
        entry.artifact_ref.artifact_id: entry.artifact_ref for entry in bundle.entries
    }

    def artifact_records_for(refs: tuple[str, ...]) -> tuple[ArtifactRef, ...]:
        return tuple(
            artifact_records_by_id[artifact_id]
            for artifact_id in refs
            if artifact_id in artifact_records_by_id
        )

    lifecycle_refs = tuple(
        entry.artifact_ref.artifact_id
        for entry in bundle.entries
        if entry.role is ArtifactRole.LIFECYCLE_EVENT
    )
    observation_refs = tuple(
        entry.artifact_ref.artifact_id
        for entry in bundle.entries
        if entry.role is ArtifactRole.OBSERVATION
    )
    accepted_refs = tuple(clause.clause_id for clause in accepted)
    proof_ids = tuple(str(ref.proof_id) for ref in runtime.proof_refs)
    record_proof_refs = (
        *runtime.proof_refs,
        *(ref for ref in view.proof_refs if str(ref) not in proof_ids),
    )
    runtime_summary = runtime.summary()
    runtime_summary_digest = digest_json(runtime_summary)
    outcome_digest = digest_json(view.minimum_profile()["authority_outcome"])
    status_blocks = tuple(block for block in view.blocking_set if block.layer is Layer.STATUS)
    operational_blocks = tuple(
        block for block in view.blocking_set if block.layer is Layer.OPERATIONAL
    )
    represented_blocks = tuple(
        block for block in view.blocking_set if block.layer is Layer.REPRESENTED
    )
    validation_blocks = tuple(
        block for block in view.blocking_set if block.layer is Layer.VALIDATION
    )
    status_stage_reasons = tuple(ref for block in status_blocks for ref in block.reason_refs)
    represented_stage_reasons = tuple(
        ref for block in represented_blocks for ref in block.reason_refs
    )
    guard_stage_reasons = tuple(ref for record in view.guard_records for ref in record.reason_refs)
    guard_failed = any(
        getattr(record.status, "value", str(record.status)) != "pass"
        for record in view.guard_records
    )
    guard_blocks = (*operational_blocks, *validation_blocks) if guard_failed else operational_blocks
    status_observation_context = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:status-observation-context",
        record_kind="StatusObservationContext",
        stage=ValidationStage.REPLAY,
        payload={
            "certificate_id": view.certificate_id,
            "status_time": status_context.status_time,
            "dominant_status": view.dominant_status.value,
            "status_observation_context_ref": view.status_observation_context_ref,
            "status_coordinates": [
                {
                    "coordinate": coordinate.coordinate,
                    "value": coordinate.value,
                    "evidence_refs": list(coordinate.evidence_refs),
                    "schema_profile": coordinate.schema_profile,
                    "digest": coordinate.digest,
                    "reason_refs": [ref.reason_id for ref in coordinate.reason_refs],
                }
                for coordinate in view.status_coordinates
            ],
            "dependency_snapshot": dict(status_context.dependency_snapshot),
            "event_count": len(status_context.event_log),
            "lifecycle_refs": lifecycle_refs,
            "confluence_proof_ref": status_context.confluence_proof,
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.REPLAY,
                owner_path_contains=("/event_log", "/confluence_proof"),
                target_artifact_contains=("lifecycle", "confluence", "trace", "causal"),
                kinds=(ReferenceKind.PROOF, ReferenceKind.ARTIFACT),
            ),
        },
        artifact_refs=(*artifact_ids, *lifecycle_refs),
        artifact_ref_records=artifact_records_for((*artifact_ids, *lifecycle_refs)),
        proof_refs=record_proof_refs,
        reason_refs=status_stage_reasons,
    )
    observation_cut = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:observation-cut",
        record_kind="ObservationCut",
        stage=ValidationStage.REPLAY,
        payload={
            "status_time": status_context.status_time,
            "observation_context_ref": view.status_observation_context_ref,
            "observation_records": to_jsonable(status_context.observation_records),
            "observation_policy": to_jsonable(status_context.observation_policy),
            "frame": to_jsonable(status_context.frame),
            "dependency_snapshot": dict(status_context.dependency_snapshot),
            "event_order_ref": status_context.confluence_proof,
            "record_count": len(status_context.observation_records),
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.GUARD_EVALUATE,
                owner_path_contains=(
                    "/observation_records",
                    "/relation",
                    "/relations",
                    "/measurement",
                    "/representation",
                ),
                target_artifact_contains=(
                    "observation",
                    "measurement",
                    "representation",
                    "calibration",
                    "latency",
                    "dependency",
                    "event-order",
                ),
                kinds=(ReferenceKind.ARTIFACT, ReferenceKind.PROOF, ReferenceKind.TRANSCRIPT),
            ),
        },
        artifact_refs=observation_refs,
        artifact_ref_records=artifact_records_for(observation_refs),
        proof_refs=record_proof_refs,
        reason_refs=status_stage_reasons,
    )
    prefix_view = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:prefix-view",
        record_kind="PrefixView",
        stage=ValidationStage.GUARD_EVALUATE,
        payload={
            "status_time": status_context.status_time,
            "prefix_view_ref": view.prefix_view_ref,
            "status_context_prefix_view": to_jsonable(status_context.prefix_view),
            "observation_policy": to_jsonable(status_context.observation_policy),
            "frame_digest": digest_json(status_context.frame) if status_context.frame else None,
            "guard_records": [
                {
                    "guard_name": record.guard_name,
                    "status": record.status.value,
                    "evidence_refs": list(record.evidence_refs),
                    "reason_refs": [ref.reason_id for ref in record.reason_refs],
                }
                for record in view.guard_records
            ],
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.GUARD_EVALUATE,
                owner_path_contains=(
                    "/prefix",
                    "/representation",
                    "/observation_records",
                    "/relations",
                ),
                target_artifact_contains=("prefix", "representation", "observation"),
                kinds=(ReferenceKind.PROOF, ReferenceKind.TRANSCRIPT, ReferenceKind.ARTIFACT),
            ),
        },
        artifact_refs=observation_refs,
        artifact_ref_records=artifact_records_for(observation_refs),
        proof_refs=record_proof_refs,
        reason_refs=guard_stage_reasons,
    )
    residual_context = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:residual-context",
        record_kind="ResidualContext",
        stage=ValidationStage.GUARD_EVALUATE,
        payload={
            "residual_context_ref": view.residual_context_ref,
            "prefix_view_ref": view.prefix_view_ref,
            "compiled_bundle_ref": runtime.compiled_bundle_ref,
            "accepted_clause_refs": accepted_refs,
            "set_refs": list(view.set_refs),
            "validity_view_ref": view.validity_view_ref,
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.GUARD_EVALUATE,
                owner_path_contains=(
                    "/accepted",
                    "/obligation",
                    "/reason",
                    "/completion_policy",
                ),
                target_artifact_contains=("accepted", "obligation", "reason", "completion"),
                kinds=(
                    ReferenceKind.ARTIFACT,
                    ReferenceKind.OBLIGATION,
                    ReferenceKind.REASON,
                    ReferenceKind.SET,
                    ReferenceKind.TRANSCRIPT,
                ),
                include_accepted_clauses=True,
                include_compiled_bundle=True,
            ),
        },
        artifact_refs=artifact_ids,
        artifact_ref_records=artifact_records_for(artifact_ids),
        proof_refs=record_proof_refs,
        reason_refs=guard_stage_reasons,
    )
    completion_admission = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:completion-admission",
        record_kind="CompletionAdmission",
        stage=ValidationStage.GUARD_EVALUATE,
        payload={
            "completion_admission_ref": view.completion_admission_ref,
            "completion_admission": to_jsonable(status_context.completion_admission),
            "completion_policy": to_jsonable(status_context.completion_policy),
            "status_time": status_context.status_time,
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.GUARD_EVALUATE,
                owner_path_contains=("/completion", "/completion_policy"),
                target_artifact_contains=("completion",),
                kinds=(ReferenceKind.PROOF, ReferenceKind.TRANSCRIPT, ReferenceKind.SET),
            ),
        },
        artifact_refs=artifact_ids,
        artifact_ref_records=artifact_records_for(artifact_ids),
        proof_refs=record_proof_refs,
        reason_refs=guard_stage_reasons,
    )
    fiber_assoc_view = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:fiber-assoc-view",
        record_kind="FiberAssocView",
        stage=ValidationStage.GUARD_EVALUATE,
        payload={
            "exact_fiber_assoc_ref": view.exact_fiber_assoc_ref,
            "fiber_assoc_view_ref": view.fiber_assoc_view_ref,
            "fiber_assoc_view": to_jsonable(status_context.fiber_assoc_view),
            "target_condition": to_jsonable(status_context.target_condition),
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.GUARD_EVALUATE,
                owner_path_contains=(
                    "/fiber",
                    "/association",
                    "/relations",
                    "/representation",
                ),
                target_artifact_contains=("fiber", "association", "representation"),
                kinds=(ReferenceKind.PROOF, ReferenceKind.TRANSCRIPT, ReferenceKind.ARTIFACT),
            ),
        },
        artifact_refs=artifact_ids,
        artifact_ref_records=artifact_records_for(artifact_ids),
        proof_refs=record_proof_refs,
        reason_refs=guard_stage_reasons,
    )
    adjudication_views = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:adjudication-views",
        record_kind="AdjudicationViews",
        stage=ValidationStage.AUTHORITY_EMIT,
        payload={
            "adjudication_views_ref": view.adjudication_views_ref,
            "adjudication_views": dict(status_context.adjudication_views),
            "adequacy_direction": status_context.adequacy_direction,
            "proposed_use": {
                "mode": proposed_use.mode,
                "claim": proposed_use.claim,
                "horizon": proposed_use.horizon,
                "anchor": proposed_use.anchor,
                "scope": list(proposed_use.scope),
            },
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.GUARD_EVALUATE,
                owner_path_contains=(
                    "/adjudication",
                    "/adequacy",
                    "/frame",
                    "/observation_records",
                ),
                target_artifact_contains=("adjudication", "adequacy", "frame"),
                kinds=(ReferenceKind.PROOF, ReferenceKind.TRANSCRIPT, ReferenceKind.ARTIFACT),
            ),
        },
        artifact_refs=artifact_ids,
        artifact_ref_records=artifact_records_for(artifact_ids),
        proof_refs=record_proof_refs,
        reason_refs=view.authority_outcome.reason_refs,
    )
    kernel_view = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:kernel-view",
        record_kind="KernelView",
        stage=ValidationStage.KERNEL_CHECK,
        payload={
            "kernel_verdict": view.kernel_verdict.value if view.kernel_verdict else "not-run",
            "accepted_clause_refs": accepted_refs,
            "compiled_bundle_ref": runtime.compiled_bundle_ref,
            "proof_refs": tuple(view.proof_refs or proof_ids),
            "runtime_summary_digest": runtime_summary_digest,
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.KERNEL_CHECK,
                owner_path_contains=("/proof_refs", "/kernel"),
                target_artifact_contains=("kernel", "proof"),
                kinds=(ReferenceKind.PROOF,),
                include_accepted_clauses=True,
                include_compiled_bundle=True,
            ),
        },
        artifact_refs=artifact_ids,
        artifact_ref_records=artifact_records_for(artifact_ids),
        proof_refs=record_proof_refs,
        reason_refs=represented_stage_reasons,
    )
    agreement = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:agreement",
        record_kind="Agreement",
        stage=ValidationStage.AUTHORITY_EMIT,
        payload={
            "agreement_ref": view.agreement_ref,
            "gate_decision_ref": view.gate_decision_ref,
            "authority_outcome_digest": outcome_digest,
            "runtime_summary_digest": runtime_summary_digest,
            "proposed_use": {
                "mode": proposed_use.mode,
                "claim": proposed_use.claim,
                "horizon": proposed_use.horizon,
                "anchor": proposed_use.anchor,
                "scope": list(proposed_use.scope),
                "consumer": proposed_use.consumer,
                "policy": proposed_use.policy,
                "frame": proposed_use.frame,
            },
            "authority_outcome": {
                "layer": view.authority_outcome.layer.value,
                "code": view.authority_outcome.code,
                "direction": view.authority_outcome.direction.value,
                "gate_decision": view.authority_outcome.gate_decision.value,
                "blocking_set": [block.block_id for block in view.authority_outcome.blocking_set],
                "reason_refs": [ref.reason_id for ref in view.authority_outcome.reason_refs],
            },
            "construction_sources": _construction_sources(
                runtime,
                stage=ValidationStage.AUTHORITY_EMIT,
                owner_path_contains=("/agreement", "/authority", "/gate"),
                target_artifact_contains=("agreement", "authority", "gate"),
                kinds=(ReferenceKind.PROOF, ReferenceKind.TRANSCRIPT, ReferenceKind.SCHEMA),
            ),
        },
        artifact_refs=artifact_ids,
        artifact_ref_records=artifact_records_for(artifact_ids),
        proof_refs=record_proof_refs,
        reason_refs=view.authority_outcome.reason_refs,
    )
    protocol_records = (
        status_observation_context,
        observation_cut,
        prefix_view,
        residual_context,
        completion_admission,
        fiber_assoc_view,
        adjudication_views,
        kernel_view,
        agreement,
    )
    stage_artifacts = {
        ValidationStage.REPLAY.value: (
            status_observation_context.record_id,
            observation_cut.record_id,
            *lifecycle_refs,
            view.status_observation_context_ref or "",
        ),
        ValidationStage.GUARD_EVALUATE.value: (
            prefix_view.record_id,
            residual_context.record_id,
            completion_admission.record_id,
            fiber_assoc_view.record_id,
            *(record.guard_name for record in view.guard_records),
            *observation_refs,
            view.prefix_view_ref or "",
            view.residual_context_ref or "",
        ),
        ValidationStage.KERNEL_CHECK.value: (
            kernel_view.record_id,
            view.kernel_verdict.value if view.kernel_verdict else "not-run",
            *(view.proof_refs or proof_ids),
            *accepted_refs,
        ),
        ValidationStage.AUTHORITY_EMIT.value: (
            adjudication_views.record_id,
            agreement.record_id,
            f"authority-outcome:{outcome_digest}",
            view.agreement_ref or "",
            view.gate_decision_ref or "",
            f"runtime:{runtime_summary_digest}",
        ),
    }
    traces = (
        ReplayStageTrace(
            ValidationStage.REPLAY,
            _stage_result_from_blocks(
                ValidationStage.REPLAY,
                artifact_ids,
                status_blocks,
                status_stage_reasons,
            ),
            record_refs=(status_observation_context.record_id, observation_cut.record_id),
            artifact_refs=(*artifact_ids, *lifecycle_refs),
            artifact_ref_records=artifact_records_for((*artifact_ids, *lifecycle_refs)),
            proof_refs=proof_ids,
            proof_ref_records=record_proof_refs,
            blocking_records=status_blocks,
            reason_refs=status_stage_reasons,
        ),
        ReplayStageTrace(
            ValidationStage.GUARD_EVALUATE,
            _stage_result_from_blocks(
                ValidationStage.GUARD_EVALUATE,
                artifact_ids,
                guard_blocks,
                guard_stage_reasons,
            ),
            record_refs=(
                prefix_view.record_id,
                residual_context.record_id,
                completion_admission.record_id,
                fiber_assoc_view.record_id,
            ),
            artifact_refs=(*artifact_ids, *observation_refs),
            artifact_ref_records=artifact_records_for((*artifact_ids, *observation_refs)),
            proof_refs=proof_ids,
            proof_ref_records=record_proof_refs,
            blocking_records=guard_blocks,
            reason_refs=guard_stage_reasons,
        ),
        ReplayStageTrace(
            ValidationStage.KERNEL_CHECK,
            _stage_result_from_blocks(
                ValidationStage.KERNEL_CHECK,
                artifact_ids,
                represented_blocks,
                view.reason_refs,
            ),
            record_refs=(kernel_view.record_id,),
            artifact_refs=artifact_ids,
            artifact_ref_records=artifact_records_for(artifact_ids),
            proof_refs=tuple(view.proof_refs or proof_ids),
            proof_ref_records=record_proof_refs,
            blocking_records=represented_blocks,
            reason_refs=view.reason_refs,
        ),
        ReplayStageTrace(
            ValidationStage.AUTHORITY_EMIT,
            _stage_result_from_blocks(
                ValidationStage.AUTHORITY_EMIT,
                artifact_ids,
                view.blocking_set,
                view.authority_outcome.reason_refs,
            ),
            record_refs=(adjudication_views.record_id, agreement.record_id),
            artifact_refs=artifact_ids,
            artifact_ref_records=artifact_records_for(artifact_ids),
            proof_refs=tuple(view.proof_refs or proof_ids),
            proof_ref_records=record_proof_refs,
            blocking_records=view.blocking_set,
            reason_refs=view.authority_outcome.reason_refs,
        ),
    )
    del context_bundle_id
    return ReplayTrace(
        traces,
        stage_artifacts={
            key: tuple(item for item in values if item) for key, values in stage_artifacts.items()
        },
        protocol_records=protocol_records,
        kernel_view_ref=kernel_view.record_id,
        observation_context_ref=view.status_observation_context_ref,
        agreement_ref=view.agreement_ref,
        runtime_summary_digest=runtime_summary_digest,
    )


def _blocking_records_from_result(result: ValidationResult) -> tuple[BlockingRecord, ...]:
    return tuple(
        BlockingRecord(
            block_id=record.failure_id,
            failure_code=record.code,
            layer=record.layer,
            severity=record.severity,
            reason_refs=record.reason_refs,
        )
        for record in result.failure_records
        if record.blocking
    )


def _failure_replay_trace(
    bundle: ArtifactBundle,
    result: ValidationResult,
    *,
    ledger_entries: tuple[ReferenceLedgerEntry, ...] = (),
    unresolved_refs: tuple[tuple[str, str], ...] = (),
) -> ReplayTrace:
    artifact_ids = tuple(entry.artifact_ref.artifact_id for entry in bundle.entries)
    proof_ids = tuple(
        dict.fromkeys(
            str(entry.target_artifact_id)
            for entry in ledger_entries
            if entry.kind is ReferenceKind.PROOF
        )
    )
    reason_refs = tuple(
        dict.fromkeys(
            (
                *result.reason_refs,
                *(ref for failure in result.failure_records for ref in failure.reason_refs),
            )
        )
    )
    reason_ids = tuple(getattr(ref, "reason_id", str(ref)) for ref in reason_refs)
    payload = {
        "status": result.status.value,
        "failure_codes": [record.code.value for record in result.failure_records],
        "unresolved_refs": [
            {"artifact_id": artifact_id, "path": path} for artifact_id, path in unresolved_refs
        ],
    }
    record = ProtocolRecordArtifact.build(
        record_id=f"{bundle.bundle_id}:failure:{result.stage.value}",
        record_kind="ReplayFailure",
        stage=result.stage,
        payload=payload,
        artifact_refs=artifact_ids,
        artifact_ref_records=tuple(entry.artifact_ref for entry in bundle.entries),
        proof_refs=proof_ids,
        reason_refs=reason_ids,
    )
    stage_artifacts = {
        result.stage.value: tuple(
            item
            for item in (
                record.record_id,
                *result.artifact_refs,
                *(artifact_id for artifact_id, _ in unresolved_refs),
            )
            if item
        )
    }
    return ReplayTrace(
        (
            ReplayStageTrace(
                result.stage,
                result,
                record_refs=(record.record_id,),
                artifact_refs=artifact_ids,
                artifact_ref_records=tuple(entry.artifact_ref for entry in bundle.entries),
                proof_refs=proof_ids,
                proof_ref_records=proof_ids,
                blocking_records=_blocking_records_from_result(result),
                reason_refs=reason_refs,
            ),
        ),
        stage_artifacts=stage_artifacts,
        protocol_records=(record,),
        runtime_summary_digest=digest_json(
            {
                "bundle_id": bundle.bundle_id,
                "stage": result.stage.value,
                "status": result.status.value,
                "record_digest": record.digest,
            }
        ),
    )


def _authority_replay_failure(
    bundle: ArtifactBundle,
    result: ValidationResult,
    *,
    ledger_entries: tuple[ReferenceLedgerEntry, ...] = (),
    unresolved_refs: tuple[tuple[str, str], ...] = (),
) -> AuthorityReplayResult:
    trace = _failure_replay_trace(
        bundle,
        result,
        ledger_entries=ledger_entries,
        unresolved_refs=unresolved_refs,
    )
    return AuthorityReplayResult(
        None,
        None,
        result,
        unresolved_refs=unresolved_refs,
        replay_trace=trace,
    )


def _entry(artifact: Any, role: ArtifactRole, artifact_id: str) -> dict[str, Any]:
    ref = build_artifact_ref(
        artifact,
        artifact_id=artifact_id,
        artifact_type="json",
        semantic_role=role,
    )
    return {"artifact_ref": to_jsonable(ref), "artifact": artifact, "role": role.value}


def synthetic_authority_bundle(
    certificate: IssueCertificate | Mapping[str, Any],
    proposed_use: ProposedUse | Mapping[str, Any],
    status_context: StatusContext | Mapping[str, Any],
) -> ArtifactBundle:
    """Create a local ArtifactBundle for legacy direct authority inputs."""

    cert_source = to_jsonable(certificate)
    use_source = to_jsonable(proposed_use)
    status_source = to_jsonable(status_context)
    entries = [
        _entry(cert_source, ArtifactRole.ISSUE_CERTIFICATE, "synthetic:certificate"),
        _entry(use_source, ArtifactRole.PROPOSED_USE, "synthetic:proposed-use"),
        _entry(status_source, ArtifactRole.STATUS_CONTEXT, "synthetic:status-context"),
    ]
    if isinstance(cert_source, Mapping):
        embedded = (
            ("claim_source", "claim_ref", ArtifactRole.CLAIM, "synthetic:claim"),
            (
                "bundle_source",
                "assumption_bundle_ref",
                ArtifactRole.ASSUMPTION_BUNDLE,
                "synthetic:bundle",
            ),
            ("anchor_source", "anchor_ref", ArtifactRole.ANCHOR, "synthetic:anchor"),
            (
                "time_basis_source",
                "time_basis_ref",
                ArtifactRole.TIME_BASIS,
                "synthetic:time-basis",
            ),
        )
        for source_key, ref_key, role, fallback_id in embedded:
            artifact = cert_source.get(source_key)
            if artifact is not None:
                entries.append(
                    _entry(
                        artifact,
                        role,
                        str(cert_source.get(ref_key, fallback_id)),
                    )
                )
    refs = [entry["artifact_ref"] for entry in entries]
    source = {
        "bundle_id": "synthetic:authority-input",
        "manifest": {
            "manifest_id": "synthetic:authority-input:manifest",
            "root_artifact_id": "synthetic:certificate",
            "artifact_refs": refs,
            "dependency_order": [str(ref["artifact_id"]) for ref in refs],
            "semantic_roles": {
                str(ref["artifact_id"]): str(entry["role"])
                for ref, entry in zip(refs, entries, strict=True)
            },
        },
        "artifacts": entries,
    }
    return artifact_bundle_from_json(source)


def replay_authority_from_bundle(
    bundle: ArtifactBundle,
    *,
    resolved_refs: tuple[ResolvedReference, ...] = (),
    strict_ledger: bool = False,
    policy: Mapping[str, Any] | None = None,
    backend: Any | None = None,
    checker: Any | None = None,
    registry: Any | None = None,
) -> AuthorityReplayResult:
    ledger = build_reference_ledger(bundle, strict=strict_ledger)
    if not ledger.passed:
        return _authority_replay_failure(
            bundle,
            ledger.validation_result,
            ledger_entries=ledger.entries,
            unresolved_refs=ledger.unresolved_refs,
        )
    missing_required = _unresolved_required(ledger.entries) if strict_ledger else ()
    if missing_required:
        first = missing_required[0]
        return _authority_replay_failure(
            bundle,
            validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                f"authority replay cannot resolve required {first.kind.value} reference: "
                f"{first.ref_value}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.INTEROP,
                source_artifact=first.owner_artifact,
                source_path=first.owner_path,
            ),
            ledger_entries=ledger.entries,
            unresolved_refs=tuple(
                (entry.target_artifact_id, entry.target_path) for entry in missing_required
            ),
        )
    resolved_refs = (*resolved_refs, *ledger.resolved_refs)
    status_context = _status_context_from_bundle(bundle)
    if isinstance(status_context, ValidationResult):
        return _authority_replay_failure(
            bundle,
            status_context,
            ledger_entries=ledger.entries,
            unresolved_refs=ledger.unresolved_refs,
        )
    if strict_ledger:
        lifecycle_failure = _lifecycle_ref_failure(
            bundle, status_context, ledger.entries, bundle_id=bundle.bundle_id
        )
        if lifecycle_failure is not None:
            return _authority_replay_failure(
                bundle,
                lifecycle_failure,
                ledger_entries=ledger.entries,
                unresolved_refs=ledger.unresolved_refs,
            )
        status_context = _enrich_status_context_from_lifecycle_artifacts(bundle, status_context)
        relation_failure = _relation_artifact_failure(bundle, ledger.entries)
        if relation_failure is not None:
            return _authority_replay_failure(
                bundle,
                relation_failure,
                ledger_entries=ledger.entries,
                unresolved_refs=ledger.unresolved_refs,
            )
    status_context = _enrich_status_context_from_relation_artifacts(bundle, status_context)
    status_context = _enrich_status_context_from_completion_set_artifacts(bundle, status_context)
    if strict_ledger:
        proof_content_failure = _operational_proof_content_failure(bundle, status_context)
        if proof_content_failure is not None:
            return _authority_replay_failure(
                bundle,
                proof_content_failure,
                ledger_entries=ledger.entries,
                unresolved_refs=ledger.unresolved_refs,
            )
    status_context = _enrich_status_context_from_proof_artifacts(bundle, status_context)
    accepted_schema_failure = _direct_accepted_clause_schema_failure(bundle)
    if accepted_schema_failure is not None:
        return _authority_replay_failure(
            bundle,
            accepted_schema_failure,
            ledger_entries=ledger.entries,
            unresolved_refs=ledger.unresolved_refs,
        )
    if strict_ledger:
        for source in _all_mappings(bundle, ArtifactRole.ADMISSION, artifact_type="admission"):
            contract_id = str(source.get("contract_id", bundle.bundle_id))
            contract_failure = admission_contract_result(
                source,
                ledger.entries,
                contract_id=contract_id,
                source_layer=Layer.ISSUE,
            )
            if contract_failure is not None:
                return _authority_replay_failure(
                    bundle,
                    contract_failure,
                    ledger_entries=ledger.entries,
                    unresolved_refs=ledger.unresolved_refs,
                )
    accepted = _accepted_clauses(bundle, status_context)
    if strict_ledger:
        accepted_failure = _direct_accepted_clause_failure(
            bundle,
            ledger.entries,
            status_time=status_context.status_time,
        )
        if accepted_failure is not None:
            return _authority_replay_failure(
                bundle,
                accepted_failure,
                ledger_entries=ledger.entries,
                unresolved_refs=ledger.unresolved_refs,
            )
    trusts = _trust_assumptions(bundle)
    if strict_ledger:
        for source in _all_mappings(
            bundle,
            ArtifactRole.TRUST_ASSUMPTION,
            artifact_type="trust-assumption",
        ):
            assumption_id = str(source.get("assumption_id", "trust-assumption"))
            trust_failure = trust_assumption_result(
                source,
                ledger.entries,
                assumption_id=assumption_id,
                source_layer=Layer.ISSUE,
            )
            if trust_failure is not None:
                return _authority_replay_failure(
                    bundle,
                    trust_failure,
                    ledger_entries=ledger.entries,
                    unresolved_refs=ledger.unresolved_refs,
                )
    kernel_proofs = _kernel_proof_artifacts(bundle)
    if strict_ledger and kernel_proofs:
        kernel_proof_failure = _kernel_proof_failure(
            bundle,
            kernel_proofs,
            ledger.entries,
            bundle_id=bundle.bundle_id,
        )
        if kernel_proof_failure is not None:
            return _authority_replay_failure(
                bundle,
                kernel_proof_failure,
                ledger_entries=ledger.entries,
                unresolved_refs=ledger.unresolved_refs,
            )
    kernel_proof_refs = _kernel_proof_refs(kernel_proofs, bundle)
    certificate = _certificate_from_bundle(
        bundle,
        status_context,
        accepted,
        trusts,
        strict_sources=strict_ledger,
    )
    if isinstance(certificate, ValidationResult):
        return _authority_replay_failure(
            bundle,
            certificate,
            ledger_entries=ledger.entries,
            unresolved_refs=ledger.unresolved_refs,
        )
    proposed_use = _proposed_use_from_bundle(bundle)
    if isinstance(proposed_use, ValidationResult):
        return _authority_replay_failure(
            bundle,
            proposed_use,
            ledger_entries=ledger.entries,
            unresolved_refs=ledger.unresolved_refs,
        )

    resolved_obligations, resolved_reasons = _split_resolved_refs(resolved_refs)
    ledger_obligations, ledger_reasons = _split_ledger_refs(ledger.entries)
    obligations = (*resolved_obligations, *ledger_obligations)
    reasons = (*resolved_reasons, *ledger_reasons)
    from dfcc.authority import _check_authority_core, _runtime

    accepted_clause_refs = tuple(clause.clause_id for clause in accepted)
    runtime = _runtime(
        certificate,
        registry,
        artifact_refs=tuple(entry.artifact_ref for entry in bundle.entries),
        ledger_entries=ledger.entries,
        resolved_obligations=obligations,
        resolved_reason_refs=reasons,
        accepted_clause_refs=accepted_clause_refs,
        compiled_bundle_ref=certificate.compiled_semantics_ref,
        set_ref_records=_set_ref_records(bundle),
        proof_refs=kernel_proof_refs,
        kernel_proof_artifacts=kernel_proofs,
        strict_replay=strict_ledger,
        synthetic_trust=bundle.bundle_id.startswith("synthetic:"),
    )

    view = _check_authority_core(
        certificate,
        proposed_use,
        status_context,
        policy=policy,
        backend=backend,
        checker=checker,
        registry=registry,
        resolved_runtime=runtime,
    )
    if isinstance(view, ValidationResult):
        return _authority_replay_failure(
            bundle,
            view,
            ledger_entries=ledger.entries,
            unresolved_refs=ledger.unresolved_refs,
        )
    view = replace(
        view,
        artifact_refs=tuple(entry.artifact_ref for entry in bundle.entries),
        obligation_refs=tuple(
            dict.fromkeys(
                (
                    *view.obligation_refs,
                    *(
                        item.target_artifact_id
                        for item in ledger.entries
                        if item.kind is ReferenceKind.OBLIGATION
                    ),
                )
            )
        ),
        proof_refs=tuple(
            dict.fromkeys((*view.proof_refs, *(ref.proof_id for ref in runtime.proof_refs)))
        ),
        ledger_entries=ledger.entries,
    )
    replay_trace = _build_replay_trace(
        bundle=bundle,
        context_bundle_id=bundle.bundle_id,
        view=view,
        runtime=runtime,
        accepted=accepted,
        proposed_use=proposed_use,
        status_context=status_context,
    )
    view = replace(
        view,
        protocol_record_refs=tuple(record.record_id for record in replay_trace.protocol_records),
        kernel_view_ref=replay_trace.kernel_view_ref,
    )
    context = AuthorityReplayContext(
        bundle_id=bundle.bundle_id,
        certificate=certificate,
        proposed_use=proposed_use,
        status_context=status_context,
        accepted_clause_records=accepted,
        trust_assumptions=trusts,
        compiled_bundle_ref=certificate.compiled_semantics_ref,
        resolved_obligations=obligations,
        resolved_reason_refs=reasons,
        artifact_refs=tuple(entry.artifact_ref for entry in bundle.entries),
        ledger_entries=ledger.entries,
        guard_records=view.guard_records,
        runtime=runtime,
        proof_refs=runtime.proof_refs,
        authority_runtime_summary=runtime.summary(),
        replay_trace=replay_trace,
        protocol_records=replay_trace.protocol_records,
    )
    return AuthorityReplayResult(
        context,
        view,
        ValidationResult(ValidationStage.AUTHORITY_EMIT, ValidationStatus.PASS),
        authority_outcome_digest=digest_json(view.minimum_profile()["authority_outcome"]),
        unresolved_refs=ledger.unresolved_refs,
        replay_trace=replay_trace,
    )
