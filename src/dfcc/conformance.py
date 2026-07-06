"""Golden conformance cases for the reference implementation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from dfcc.artifacts import (
    ArtifactRef,
    ArtifactRole,
    ArtifactStore,
    ReferenceResolutionContext,
    artifact_bundle_from_json,
    build_artifact_ref,
    manifest_digest,
    resolve_reference,
    validate_artifact_ref,
    validate_manifest_dependencies,
)
from dfcc.authority import check_authority
from dfcc.bundle import compile_bundle_from_accepted_clauses
from dfcc.canonical import CanonicalizationError, canonical_bytes, digest_json
from dfcc.certificate import certify_claim, certify_claim_from_artifact_bundle
from dfcc.models import IssueCertificate, StatusAuthorityView
from dfcc.records import set_ref
from dfcc.schema import validate_named_schema
from dfcc.serialization import to_jsonable
from dfcc.types import (
    FailureCode,
    Layer,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    validation_failure,
)
from dfcc.validation import PipelineReport, validate_artifact_bundle


@dataclass(frozen=True, slots=True)
class GoldenResult:
    case_id: str
    passed: bool
    expected: str
    actual: str
    outcome_digest: str | None = None
    equality_key: str | None = None


def load_golden_cases(case_dir: Path | None = None) -> tuple[dict[str, Any], ...]:
    if case_dir is not None:
        if case_dir.is_file():
            with case_dir.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                return tuple(dict(item) for item in data)
            return (dict(data),)
        loaded: list[dict[str, Any]] = []
        for path in sorted(case_dir.glob("*.json")):
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, list):
                loaded.extend(dict(item) for item in data)
            else:
                loaded.append(dict(data))
        return tuple(loaded)
    resource = files("dfcc.golden").joinpath("cases.json")
    with resource.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise TypeError("golden cases must be a JSON array")
    return tuple(dict(item) for item in data)


def _base_claim() -> dict[str, Any]:
    return {
        "claim_id": "safe-temp",
        "horizon": 2,
        "formula": {
            "op": "G",
            "a": 0,
            "b": 2,
            "child": {
                "op": "atom",
                "name": "field_cmp",
                "args": {"field": "temp", "op": "lte", "value": "80"},
            },
        },
        "scope": ["demo"],
    }


def _base_bundle() -> dict[str, Any]:
    return {
        "bundle_id": "finite-demo",
        "state_space": [{"temp": "70"}, {"temp": "75"}],
        "initial_states": [{"temp": "70"}],
        "transitions": [
            {"from": {"temp": "70"}, "to": {"temp": "75"}},
            {"from": {"temp": "75"}, "to": {"temp": "75"}},
        ],
        "admissions": ["exact-finite-model"],
    }


def _anchor() -> dict[str, Any]:
    return {
        "issue_time": "2026-01-01T00:00:00Z",
        "horizon": 2,
        "step_seconds": 60,
    }


def _time_basis() -> dict[str, Any]:
    return {"clock_id": "utc-demo", "uncertainty_seconds": "0", "source": "test"}


def _issue() -> IssueCertificate:
    issued = certify_claim(_base_claim(), _base_bundle(), _anchor(), _time_basis())
    if isinstance(issued, ValidationResult):
        raise AssertionError(f"unexpected validation failure: {issued}")
    return issued


def _reason_ref_key(ref: Any) -> dict[str, Any]:
    return {
        "source_artifact": ref.source_artifact,
        "source_path": ref.source_path,
        "failure_code": ref.failure_code.value,
        "digest": ref.digest,
    }


def _validation_equality_key(value: ValidationResult) -> str:
    failure = value.failure_records[0].code.value if value.failure_records else ""
    reason_refs = tuple(
        sorted(
            dict.fromkeys(
                (
                    *value.reason_refs,
                    *(ref for record in value.failure_records for ref in record.reason_refs),
                )
            ),
            key=lambda ref: (
                ref.source_artifact,
                ref.source_path,
                ref.failure_code.value,
                ref.digest or "",
                ref.reason_id,
            ),
        )
    )
    return digest_json(
        {
            "stage": value.stage.value,
            "status": value.status.value,
            "failure": failure,
            "reason_refs": [_reason_ref_key(ref) for ref in reason_refs],
        }
    )


def _artifact_ref_record_key(record: Any) -> dict[str, Any]:
    payload = to_jsonable(record)
    if not isinstance(payload, dict):
        return {"artifact_id": str(payload)}
    return {
        "artifact_id": str(payload.get("artifact_id", "")),
        "artifact_type": str(payload.get("artifact_type", "")),
        "schema_profile": str(payload.get("schema_profile", "")),
        "canonicalization": str(payload.get("canonicalization", "")),
        "schema_digest": payload.get("schema_digest"),
        "canonicalization_digest": payload.get("canonicalization_digest"),
        "digest_algorithm": str(payload.get("digest_algorithm", "")),
        "digest_value": payload.get("digest_value"),
        "semantic_role": payload.get("semantic_role"),
        "dependency_labels": list(payload.get("dependency_labels", ())),
    }


def _artifact_ref_records_key(records: tuple[Any, ...]) -> list[dict[str, Any]]:
    return sorted(
        (_artifact_ref_record_key(record) for record in records),
        key=lambda item: (
            str(item.get("artifact_id", "")),
            str(item.get("digest_value", "")),
            str(item.get("semantic_role", "")),
        ),
    )


def _proof_ref_record_key(record: Any) -> dict[str, Any]:
    payload = to_jsonable(record)
    if not isinstance(payload, dict):
        return {"proof_id": str(payload)}
    return {
        "proof_id": str(payload.get("proof_id", "")),
        "proof_kind": str(payload.get("proof_kind", "")),
        "artifact_ref": payload.get("artifact_ref"),
        "source_artifact": payload.get("source_artifact"),
        "source_path": str(payload.get("source_path", "")),
        "digest": payload.get("digest"),
        "status": str(payload.get("status", "")),
    }


def _proof_ref_records_key(records: tuple[Any, ...]) -> list[dict[str, Any]]:
    return sorted(
        (_proof_ref_record_key(record) for record in records),
        key=lambda item: (
            str(item.get("proof_id", "")),
            str(item.get("digest", "")),
            str(item.get("status", "")),
        ),
    )


def _replay_trace_stage_evidence_key(replay_trace: Any) -> list[dict[str, Any]]:
    if not isinstance(replay_trace, dict):
        return []
    stage_traces = replay_trace.get("stage_traces", ())
    if not isinstance(stage_traces, list):
        return []
    return sorted(
        (
            {
                "stage": str(trace.get("stage", "")),
                "status": str(trace.get("status", "")),
                "record_refs": list(trace.get("record_refs", ())),
                "artifact_refs": list(trace.get("artifact_refs", ())),
                "artifact_ref_records": _artifact_ref_records_key(
                    tuple(trace.get("artifact_ref_records", ()))
                ),
                "proof_refs": list(trace.get("proof_refs", ())),
                "proof_ref_records": _proof_ref_records_key(
                    tuple(trace.get("proof_ref_records", ()))
                ),
            }
            for trace in stage_traces
            if isinstance(trace, dict)
        ),
        key=lambda item: (item["stage"], item["status"], tuple(item["record_refs"])),
    )


def _pipeline_equality_key(value: PipelineReport) -> tuple[str | None, str]:
    if value.authority_view is not None:
        return _authority_equality_key(value.authority_view)
    if not value.passed:
        protocol_record_digests = tuple(
            sorted(
                str(digest)
                for digest in (
                    getattr(record, "digest", None)
                    if not isinstance(record, dict)
                    else record.get("digest")
                    for record in value.protocol_records
                )
                if digest
            )
        )
        replay_trace = value.replay_trace or {}
        replay_trace_digest = (
            replay_trace.get("runtime_summary_digest") if isinstance(replay_trace, dict) else None
        )
        key = digest_json(
            {
                "final_result": _validation_equality_key(value.final_result),
                "stage_results": [
                    {"stage": result.stage.value, "status": result.status.value}
                    for result in value.stage_results
                ],
                "artifact_refs": list(value.artifact_refs),
                "artifact_ref_records": _artifact_ref_records_key(value.artifact_ref_records),
                "unresolved_refs": [list(item) for item in value.unresolved_refs],
                "stage_artifacts": {
                    stage: list(refs) for stage, refs in sorted(value.stage_artifacts.items())
                },
                "protocol_record_digests": list(protocol_record_digests),
                "runtime_summary_digest": value.runtime_summary_digest,
                "replay_trace_runtime_summary_digest": replay_trace_digest,
                "replay_trace_stage_evidence": _replay_trace_stage_evidence_key(replay_trace),
            }
        )
        return None, key
    key = digest_json(
        {
            "bundle_id": value.bundle_id,
            "profile": value.profile,
            "stage_results": [
                {"stage": result.stage.value, "status": result.status.value}
                for result in value.stage_results
            ],
            "artifact_refs": list(value.artifact_refs),
            "artifact_ref_records": _artifact_ref_records_key(value.artifact_ref_records),
            "authority_outcome_digest": value.authority_outcome_digest,
            "runtime_summary_digest": value.runtime_summary_digest,
        }
    )
    return value.authority_outcome_digest, key


def _authority_equality_key(value: StatusAuthorityView) -> tuple[str, str]:
    profile = value.minimum_profile()
    outcome_digest = digest_json(profile["authority_outcome"])
    artifact_digests = [value.manifest_digest]
    artifact_digests.extend(
        ref.digest_value for ref in value.artifact_refs if ref.digest_value is not None
    )
    artifact_ref_records = _artifact_ref_records_key(tuple(profile.get("artifact_ref_records", ())))
    sorted_blocks = tuple(
        sorted(
            value.blocking_set,
            key=lambda block: (block.block_id, block.failure_code.value, block.layer.value),
        )
    )
    sorted_outcome_blocks = tuple(
        sorted(
            value.authority_outcome.blocking_set,
            key=lambda block: (block.block_id, block.failure_code.value, block.layer.value),
        )
    )
    sorted_outcome_refs = tuple(
        sorted(
            value.authority_outcome.reason_refs,
            key=lambda ref: (
                ref.source_artifact,
                ref.source_path,
                ref.failure_code.value,
                ref.digest or "",
                ref.reason_id,
            ),
        )
    )
    material = {
        "authority_outcome_digest": outcome_digest,
        "blocking": [
            {
                "block_id": block.block_id,
                "failure_code": block.failure_code.value,
                "reason_refs": [
                    _reason_ref_key(ref)
                    for ref in sorted(
                        block.reason_refs,
                        key=lambda ref: (
                            ref.source_artifact,
                            ref.source_path,
                            ref.failure_code.value,
                            ref.digest or "",
                            ref.reason_id,
                        ),
                    )
                ],
            }
            for block in sorted_blocks
        ],
        "outcome_blocking": [
            {
                "block_id": block.block_id,
                "failure_code": block.failure_code.value,
                "reason_refs": [
                    _reason_ref_key(ref)
                    for ref in sorted(
                        block.reason_refs,
                        key=lambda ref: (
                            ref.source_artifact,
                            ref.source_path,
                            ref.failure_code.value,
                            ref.digest or "",
                            ref.reason_id,
                        ),
                    )
                ],
            }
            for block in sorted_outcome_blocks
        ],
        "artifact_digests": sorted(str(item) for item in artifact_digests if item is not None),
        "artifact_ref_records": artifact_ref_records,
        "reason_refs": [_reason_ref_key(ref) for ref in sorted_outcome_refs],
    }
    return outcome_digest, digest_json(material)


def _view_key(
    value: StatusAuthorityView | ValidationResult,
) -> tuple[str, str, str | None, str | None]:
    if isinstance(value, ValidationResult):
        failure = value.failure_records[0].code.value if value.failure_records else ""
        return (
            value.status.value,
            failure,
            _validation_equality_key(value),
            _validation_equality_key(value),
        )
    block = ""
    if value.blocking_set:
        trace = next(
            (
                item.failure_code.value
                for item in value.blocking_set
                if item.failure_code is FailureCode.TRACE_CONFLICT
            ),
            None,
        )
        block = trace or value.blocking_set[0].failure_code.value
    outcome_digest, equality_key = _authority_equality_key(value)
    return value.authority_outcome.code, block, outcome_digest, equality_key


def _failure_key(result: ValidationResult) -> str:
    return result.failure_records[0].code.value if result.failure_records else result.status.value


def _validation_result_case(case: dict[str, Any], result: ValidationResult) -> GoldenResult:
    actual = _failure_key(result)
    expected = str(case["expected"])
    return GoldenResult(
        str(case["case_id"]),
        actual == expected,
        expected,
        actual,
        equality_key=_validation_equality_key(result),
    )


def _semantic_equality_key(case: dict[str, Any], actual: str) -> str:
    return digest_json(
        {
            "case_id": str(case["case_id"]),
            "kind": str(case["kind"]),
            "semantic_outcome": actual,
        }
    )


def _authority_case(case: dict[str, Any]) -> GoldenResult:
    time_basis = _time_basis()
    if case.get("boundary_uncertainty"):
        time_basis = {**time_basis, "uncertainty_seconds": str(case["boundary_uncertainty"])}
    claim_source = _base_claim()
    bundle_source = _base_bundle()
    if case.get("unsafe_claim"):
        bundle_source = {
            "bundle_id": "unsafe-demo",
            "state_space": [{"temp": "90"}],
            "initial_states": [{"temp": "90"}],
            "transitions": [{"from": {"temp": "90"}, "to": {"temp": "90"}}],
            "admissions": ["exact-finite-model"],
        }
    issued = certify_claim(claim_source, bundle_source, _anchor(), time_basis)
    if isinstance(issued, ValidationResult):
        return _validation_result_case(case, issued)
    status_context = dict(case["status_context"])
    if "event_log" in status_context:
        status_context["event_log"] = [
            {**dict(item), "certificate_id": issued.certificate_id}
            for item in status_context["event_log"]
        ]
    value = check_authority(
        issued,
        case["proposed_use"],
        status_context,
        policy=case.get("policy"),
    )
    code, block, digest, equality_key = _view_key(value)
    actual = f"{code}|{block}"
    expected = str(case["expected"])
    return GoldenResult(
        str(case["case_id"]), actual == expected, expected, actual, digest, equality_key
    )


def _artifact_bundle_entry(
    artifact: Any,
    role: ArtifactRole,
    artifact_id: str,
) -> dict[str, Any]:
    ref = build_artifact_ref(
        artifact,
        artifact_id=artifact_id,
        artifact_type="json",
        semantic_role=role,
    )
    return {"artifact_ref": to_jsonable(ref), "artifact": to_jsonable(artifact), "role": role.value}


def _artifact_bundle_entry_with_semantic_role(
    artifact: Any,
    *,
    role: ArtifactRole,
    semantic_role: str,
    artifact_id: str,
) -> dict[str, Any]:
    ref = build_artifact_ref(
        artifact,
        artifact_id=artifact_id,
        artifact_type="json",
        semantic_role=semantic_role,
    )
    return {"artifact_ref": to_jsonable(ref), "artifact": to_jsonable(artifact), "role": role.value}


def _kernel_coordinates(expected_verdict: str) -> dict[str, str]:
    if expected_verdict == "assert":
        return {"feasibility": "feasible", "inclusion": "yes", "disjointness": "no"}
    if expected_verdict == "deny":
        return {"feasibility": "feasible", "inclusion": "no", "disjointness": "yes"}
    if expected_verdict == "infeasible":
        return {
            "feasibility": "infeasible",
            "inclusion": "not_applicable",
            "disjointness": "not_applicable",
        }
    return {"feasibility": "feasible", "inclusion": "no", "disjointness": "no"}


def _kernel_proof_fixture_entries(expected_verdict: str = "assert") -> tuple[dict[str, Any], ...]:
    coordinates = _kernel_coordinates(expected_verdict)
    feasible = coordinates["feasibility"] == "feasible"
    proof_refs: dict[str, Any] = {}
    extra_entries: list[dict[str, Any]] = []
    if feasible:
        proof_refs["witness_provenance_refs"] = ["artifact:kernel-witness"]
        extra_entries.append(
            _artifact_bundle_entry_with_semantic_role(
                {
                    "status": "pass",
                    "proof_kind": "witness_provenance",
                    "kernel_proof_ref": "artifact:kernel-proof",
                    "backend_identity": "EnumeratingBackend",
                    "expected_verdict": expected_verdict,
                },
                role=ArtifactRole.OTHER,
                semantic_role="proof",
                artifact_id="artifact:kernel-witness",
            )
        )
    if expected_verdict == "assert" or coordinates["inclusion"] == "yes":
        proof_refs["inclusion_ref"] = "artifact:kernel-inclusion-proof"
        extra_entries.append(
            _artifact_bundle_entry_with_semantic_role(
                {
                    "status": "pass",
                    "proof_kind": "inclusion",
                    "kernel_proof_ref": "artifact:kernel-proof",
                    "backend_identity": "EnumeratingBackend",
                    "expected_verdict": expected_verdict,
                    "inclusion": coordinates["inclusion"],
                },
                role=ArtifactRole.OTHER,
                semantic_role="proof",
                artifact_id="artifact:kernel-inclusion-proof",
            )
        )
    if expected_verdict == "deny" or coordinates["disjointness"] == "yes":
        proof_refs["disjointness_ref"] = "artifact:kernel-disjointness-proof"
        extra_entries.append(
            _artifact_bundle_entry_with_semantic_role(
                {
                    "status": "pass",
                    "proof_kind": "disjointness",
                    "kernel_proof_ref": "artifact:kernel-proof",
                    "backend_identity": "EnumeratingBackend",
                    "expected_verdict": expected_verdict,
                    "disjointness": coordinates["disjointness"],
                },
                role=ArtifactRole.OTHER,
                semantic_role="proof",
                artifact_id="artifact:kernel-disjointness-proof",
            )
        )
    if expected_verdict == "infeasible" or coordinates["feasibility"] == "infeasible":
        proof_refs["infeasibility_ref"] = "artifact:kernel-infeasibility-proof"
        extra_entries.append(
            _artifact_bundle_entry_with_semantic_role(
                {
                    "status": "pass",
                    "proof_kind": "infeasibility",
                    "kernel_proof_ref": "artifact:kernel-proof",
                    "backend_identity": "EnumeratingBackend",
                    "expected_verdict": expected_verdict,
                    "feasibility": coordinates["feasibility"],
                },
                role=ArtifactRole.OTHER,
                semantic_role="proof",
                artifact_id="artifact:kernel-infeasibility-proof",
            )
        )
    return (
        _artifact_bundle_entry(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:kernel-transcript",
                **(
                    {"witness_provenance_refs": proof_refs["witness_provenance_refs"]}
                    if feasible
                    else {}
                ),
                "proof": {
                    "backend_identity": "EnumeratingBackend",
                    "proof_kind": "exact-finite-enumeration",
                    "proof_status": "accepted",
                    "expected_verdict": expected_verdict,
                    **coordinates,
                    **{
                        key: value
                        for key, value in proof_refs.items()
                        if key != "witness_provenance_refs"
                    },
                },
            },
            ArtifactRole.KERNEL_PROOF,
            "artifact:kernel-proof",
        ),
        _artifact_bundle_entry(
            {"status": "pass", "transcript": "accepted kernel proof fixture"},
            ArtifactRole.OTHER,
            "artifact:kernel-transcript",
        ),
        *extra_entries,
    )


def _proof_fixture_entry(artifact_id: str, **payload: object) -> dict[str, Any]:
    proof = {"status": "pass", "proof_kind": "operational-proof", **payload}
    return _artifact_bundle_entry_with_semantic_role(
        proof,
        role=ArtifactRole.OTHER,
        semantic_role="proof",
        artifact_id=artifact_id,
    )


def _plain_fixture_entry(artifact_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    return _artifact_bundle_entry_with_semantic_role(
        payload or {"status": "pass"},
        role=ArtifactRole.OTHER,
        semantic_role=ArtifactRole.OTHER.value,
        artifact_id=artifact_id,
    )


def _accepted_clause_fixture_entries(
    clause: dict[str, Any],
    *,
    target: str = "semantics",
) -> tuple[dict[str, Any], ...]:
    obligation = {
        "obligation_id": "obligation:model",
        "kind": "admission",
        "status": "pass",
    }
    obligation_digest = manifest_digest(
        obligation,
        artifact_type="reference-target",
        schema_profile_digest="DFCC-Interop",
    )
    reason_digest = manifest_digest(
        "accepted clause fixture",
        artifact_type="reference-target",
        schema_profile_digest="DFCC-Interop",
    )
    accepted_clause = {
        "clause_id": "accepted:semantics",
        "target": target,
        "clause": clause,
        "evidence_ref": "artifact:evidence",
        "contract_ref": "artifact:contract",
        "checker_transcript_ref": "artifact:transcript",
        "obligation_refs": ["artifact:obligation#/obligation"],
        "obligation_ref_records": [
            {
                "obligation_id": "artifact:obligation#/obligation",
                "kind": "admission",
                "status": "pass",
                "source_artifact": "artifact:obligation",
                "source_path": "/obligation",
                "digest": obligation_digest,
            }
        ],
        "reason_refs": [
            {
                "reason_id": "reason:accepted-clause",
                "failure_code": "checker_unknown",
                "layer": "issue",
                "source_artifact": "artifact:reason",
                "source_path": "/reason",
                "message": "accepted clause fixture",
                "digest": reason_digest,
            }
        ],
        "validity_status": "pass",
        "monitor_status": "pass",
    }
    return (
        _artifact_bundle_entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
        _artifact_bundle_entry(
            {
                "artifact_id": "artifact:evidence",
                "kind": "finite-model",
                "payload": {},
                "checker_status": "pass",
            },
            ArtifactRole.EVIDENCE,
            "artifact:evidence",
        ),
        _artifact_bundle_entry(
            {
                "kind": "finite-model",
                "source": "artifact:evidence",
                "target": "semantics",
                "clause": clause,
                "checker_transcript_ref": "artifact:transcript",
                "obligation_refs": ["artifact:obligation#/obligation"],
            },
            ArtifactRole.ADMISSION,
            "artifact:contract",
        ),
        _plain_fixture_entry("artifact:transcript", {"status": "pass", "transcript": "accepted"}),
        _artifact_bundle_entry(
            {"obligation": obligation},
            ArtifactRole.OBLIGATION,
            "artifact:obligation",
        ),
        _artifact_bundle_entry(
            {"reason": "accepted clause fixture"},
            ArtifactRole.REASON,
            "artifact:reason",
        ),
    )


def _operational_relation_fixture_entries(
    *,
    temp: str,
    target_adjudication: str,
    adequacy_direction: str,
    completion_members: tuple[tuple[dict[str, str], ...], ...],
) -> tuple[dict[str, Any], ...]:
    measurement_artifact = {
        "artifact_id": "artifact:measurement",
        "checker_status": "pass",
        "proof_refs": ["artifact:measurement-proof"],
        "relation": {
            "relation_id": "measurement:demo",
            "calibration_ref": "artifact:calibration",
            "latency_ref": "artifact:latency",
            "dependency_ref": "artifact:dependency",
            "event_order_ref": "artifact:event-order",
        },
    }
    representation_artifact = {
        "artifact_id": "artifact:representation",
        "checker_status": "pass",
        "relations": [
            {
                "relation_id": "representation:demo",
                "operational_prefix": [{"temp": temp}],
                "represented_prefix": [{"temp": temp}],
                "proof_ref": "artifact:representation-proof",
            }
        ],
    }
    return (
        _artifact_bundle_entry(
            measurement_artifact,
            ArtifactRole.MEASUREMENT_RELATION,
            "artifact:measurement",
        ),
        _artifact_bundle_entry(
            representation_artifact,
            ArtifactRole.REPRESENTATION_RELATION,
            "artifact:representation",
        ),
        _proof_fixture_entry(
            "artifact:calibration",
            proof_kind="calibration",
            status_time="2026-01-01T00:00:00Z",
            time_basis="utc-demo",
            event_order="event-order:canonical",
            frame_id="frame:demo",
        ),
        _proof_fixture_entry(
            "artifact:latency",
            proof_kind="latency",
            status_time="2026-01-01T00:00:00Z",
            time_basis="utc-demo",
            event_order="event-order:canonical",
            frame_id="frame:demo",
        ),
        _proof_fixture_entry(
            "artifact:dependency",
            proof_kind="dependency",
            status_time="2026-01-01T00:00:00Z",
            time_basis="utc-demo",
            event_order="event-order:canonical",
            frame_id="frame:demo",
        ),
        _proof_fixture_entry(
            "artifact:event-order",
            proof_kind="event_order",
            status_time="2026-01-01T00:00:00Z",
            time_basis="utc-demo",
            event_order="event-order:canonical",
            frame_id="frame:demo",
        ),
        _proof_fixture_entry(
            "artifact:completion-transcript",
            proof_kind="completion_admission",
            completion_status="pass",
            admission_source="completion-contract:demo",
            expiry="unbounded",
            uncertainty_model="exact",
            reference_digest="sha256:completion",
            checker_result="pass",
            c_out_ref="artifact:completion-set",
            status_time="2026-01-01T00:00:00Z",
        ),
        _artifact_bundle_entry(
            {
                **to_jsonable(
                    set_ref(
                        "carrier",
                        "finite-json",
                        "constraint",
                        "exact",
                        "artifact:set-soundness-proof#/proof",
                    )
                ),
                "members": [
                    [dict(state) for state in completion] for completion in completion_members
                ],
            },
            ArtifactRole.SET,
            "artifact:completion-set",
        ),
        _proof_fixture_entry(
            "artifact:measurement-proof",
            relation_id="measurement:demo",
            calibration_ref="artifact:calibration",
            latency_ref="artifact:latency",
            dependency_ref="artifact:dependency",
            event_order_ref="artifact:event-order",
        ),
        _proof_fixture_entry(
            "artifact:representation-proof",
            relation_id="representation:demo",
            operational_prefix=[{"temp": temp}],
            represented_prefix=[{"temp": temp}],
        ),
        _proof_fixture_entry("artifact:prefix-proof", prefix_adjudication="accept"),
        _proof_fixture_entry("artifact:target-proof", target_adjudication=target_adjudication),
        _proof_fixture_entry("artifact:adequacy-proof", adequacy_direction=adequacy_direction),
    )


def _artifact_bundle_from_entries(
    *,
    case_id: str,
    entries: list[dict[str, Any]],
    root_artifact_id: str = "artifact:cert",
) -> dict[str, Any]:
    refs = [entry["artifact_ref"] for entry in entries]
    return {
        "bundle_id": f"bundle:{case_id}",
        "manifest": {
            "manifest_id": f"manifest:{case_id}",
            "root_artifact_id": root_artifact_id,
            "artifact_refs": refs,
            "dependency_order": [str(ref["artifact_id"]) for ref in refs],
            "semantic_roles": {
                str(ref["artifact_id"]): str(ref.get("semantic_role") or entry["role"])
                for ref, entry in zip(refs, entries, strict=True)
            },
        },
        "reference_context": {"snapshot_id": f"snapshot:{case_id}"},
        "artifacts": entries,
    }


def _interop_artifact_bundle_fixture(case: dict[str, Any]) -> dict[str, Any]:
    fixture = str(case.get("fixture", ""))
    case_id = str(case.get("case_id", fixture.replace(":", "-")))
    if fixture == "interop:canonicalization-mismatch":
        ref = ArtifactRef(
            "artifact:canonicalization-mismatch",
            "json",
            digest_value="sha256:canonicalization-mismatch-input",
            semantic_role=ArtifactRole.ROOT.value,
        )
        return {
            "bundle_id": f"bundle:{case_id}",
            "manifest": {
                "manifest_id": f"manifest:{case_id}",
                "root_artifact_id": ref.artifact_id,
                "artifact_refs": [to_jsonable(ref)],
                "dependency_order": [ref.artifact_id],
            },
            "reference_context": {"snapshot_id": f"snapshot:{case_id}"},
            "artifacts": [
                {
                    "artifact_ref": to_jsonable(ref),
                    "artifact": {"x": 1.2},
                    "role": ArtifactRole.ROOT.value,
                }
            ],
        }
    if fixture == "interop:schema-invalid":
        schema_artifact: dict[str, Any] = {"certificate_id": "missing-required-fields"}
        return _artifact_bundle_from_entries(
            case_id=case_id,
            root_artifact_id="artifact:schema-invalid",
            entries=[
                _artifact_bundle_entry(
                    schema_artifact,
                    ArtifactRole.ISSUE_CERTIFICATE,
                    "artifact:schema-invalid",
                )
            ],
        )
    if fixture == "interop:digest-mismatch":
        digest_artifact: dict[str, Any] = {"x": 1}
        ref = build_artifact_ref(
            digest_artifact,
            artifact_id="artifact:digest-mismatch",
            artifact_type="json",
            semantic_role=ArtifactRole.ROOT,
        )
        bad_ref = ArtifactRef(
            ref.artifact_id,
            ref.artifact_type,
            ref.schema_profile,
            ref.canonicalization,
            ref.media_type,
            ref.schema_digest,
            ref.canonicalization_digest,
            ref.digest_algorithm,
            "sha256:not-the-digest",
            ref.content_uri,
            ref.retrieval_policy,
            ref.immutability_policy,
            ref.provenance_refs,
            ref.semantic_role,
            ref.dependency_labels,
        )
        return {
            "bundle_id": f"bundle:{case_id}",
            "manifest": {
                "manifest_id": f"manifest:{case_id}",
                "root_artifact_id": bad_ref.artifact_id,
                "artifact_refs": [to_jsonable(bad_ref)],
                "dependency_order": [bad_ref.artifact_id],
            },
            "reference_context": {"snapshot_id": f"snapshot:{case_id}"},
            "artifacts": [
                {
                    "artifact_ref": to_jsonable(bad_ref),
                    "artifact": digest_artifact,
                    "role": ArtifactRole.ROOT.value,
                }
            ],
        }
    if fixture == "interop:missing-ref":
        missing_ref_artifact: dict[str, Any] = {"x": {"y": "z"}}
        ref = build_artifact_ref(
            missing_ref_artifact,
            artifact_id="artifact:missing-ref",
            artifact_type="json",
            semantic_role=ArtifactRole.ROOT,
        )
        return {
            "bundle_id": f"bundle:{case_id}",
            "manifest": {
                "manifest_id": f"manifest:{case_id}",
                "root_artifact_id": ref.artifact_id,
                "artifact_refs": [to_jsonable(ref)],
                "dependency_order": [ref.artifact_id],
            },
            "reference_context": {"snapshot_id": f"snapshot:{case_id}"},
            "artifacts": [
                {
                    "artifact_ref": to_jsonable(ref),
                    "artifact": missing_ref_artifact,
                    "role": ArtifactRole.ROOT.value,
                    "reason_paths": ["/missing"],
                }
            ],
        }
    if fixture == "interop:manifest-order-conflict":
        dep_b = build_artifact_ref({"b": 1}, artifact_id="artifact:b", artifact_type="json")
        dep_a_base = build_artifact_ref({"a": 1}, artifact_id="artifact:a", artifact_type="json")
        dep_a = ArtifactRef(
            dep_a_base.artifact_id,
            dep_a_base.artifact_type,
            dep_a_base.schema_profile,
            dep_a_base.canonicalization,
            dep_a_base.media_type,
            dep_a_base.schema_digest,
            dep_a_base.canonicalization_digest,
            dep_a_base.digest_algorithm,
            dep_a_base.digest_value,
            dep_a_base.content_uri,
            dep_a_base.retrieval_policy,
            dep_a_base.immutability_policy,
            ("artifact:b",),
            dep_a_base.semantic_role,
            ("depends-on",),
        )
        entries = [
            {"artifact_ref": to_jsonable(dep_a), "artifact": {"a": 1}, "role": "root"},
            {"artifact_ref": to_jsonable(dep_b), "artifact": {"b": 1}, "role": "other"},
        ]
        return {
            "bundle_id": f"bundle:{case_id}",
            "manifest": {
                "manifest_id": f"manifest:{case_id}",
                "root_artifact_id": "artifact:a",
                "artifact_refs": [to_jsonable(dep_a), to_jsonable(dep_b)],
                "dependency_order": ["artifact:a", "artifact:b"],
            },
            "reference_context": {"snapshot_id": f"snapshot:{case_id}"},
            "artifacts": entries,
        }
    raise ValueError(f"unknown interop artifact-bundle fixture: {fixture}")


def _authority_artifact_bundle_fixture(case: dict[str, Any]) -> dict[str, Any]:
    fixture = str(case.get("fixture", ""))
    if not fixture.startswith("authority:"):
        raise ValueError(f"unknown artifact-bundle fixture: {fixture}")

    claim_source = _base_claim()
    bundle_source = _base_bundle()
    anchor_source = _anchor()
    time_basis_source = _time_basis()
    certificate_frame: dict[str, Any] = {}
    certificate_policy: dict[str, Any] = {}
    proposed_use = {
        "mode": "assertion",
        "claim": "safe-temp",
        "horizon": 2,
        "anchor": "anchor:issue",
        "scope": ["demo"],
    }
    status_context: dict[str, Any] = {"status_time": "2026-01-01T00:00:00Z"}
    include_kernel_proof = True
    extra_entries: list[dict[str, Any]] = []
    formal_accepted_issuance = False
    stale_embedded_source = False

    if fixture == "authority:missing-kernel-proof":
        include_kernel_proof = False
    elif fixture == "authority:stale-embedded-source":
        stale_embedded_source = True
    elif fixture == "authority:raw-evidence-only":
        extra_entries.append(
            _artifact_bundle_entry(
                {
                    "artifact_id": "artifact:raw-evidence",
                    "kind": "finite-model",
                    "payload": {
                        "state_space": [{"temp": "90"}],
                        "initial_states": [{"temp": "90"}],
                        "transitions": [{"from": {"temp": "90"}, "to": {"temp": "90"}}],
                    },
                    "checker_status": "pass",
                },
                ArtifactRole.EVIDENCE,
                "artifact:raw-evidence",
            )
        )
    elif fixture == "authority:operational-accept":
        certificate_frame = {
            "frame_id": "frame:demo",
            "scope": ["demo"],
            "policy": {"adequacy_direction": "positive"},
            "completion_interface_ref": "completion:demo",
        }
        proposed_use = {
            "mode": "operational",
            "claim": "safe-temp",
            "horizon": 2,
            "anchor": "anchor:issue",
            "scope": ["demo"],
            "frame": "frame:demo",
        }
        status_context = {
            "status_time": "2026-01-01T00:00:00Z",
            "observation_records": [
                {
                    "r": 0,
                    "measurement_relation_ref": "artifact:measurement",
                    "representation_relation_ref": "artifact:representation",
                    "operational_completions": [[{"temp": "70"}, {"temp": "75"}, {"temp": "75"}]],
                    "prefix_adjudication_proof_ref": "artifact:prefix-proof",
                    "target_adjudication_proof_ref": "artifact:target-proof",
                    "adequacy_proof_ref": "artifact:adequacy-proof",
                }
            ],
            "observation_policy": {"r": 0},
            "completion_policy": {
                "completion_status": "pass",
                "admission_source": "completion-contract:demo",
                "expiry": "unbounded",
                "uncertainty_model": "exact",
                "reference_digest": "sha256:completion",
                "checker_result": "pass",
                "checker_transcript_ref": "artifact:completion-transcript",
                "c_out_ref": "artifact:completion-set",
            },
        }
        extra_entries.extend(
            _operational_relation_fixture_entries(
                temp="70",
                target_adjudication="accept",
                adequacy_direction="positive",
                completion_members=(({"temp": "70"}, {"temp": "75"}, {"temp": "75"}),),
            )
        )
    elif fixture == "authority:operational-reject":
        bundle_source = {
            "bundle_id": "unsafe-demo",
            "state_space": [{"temp": "90"}],
            "initial_states": [{"temp": "90"}],
            "transitions": [{"from": {"temp": "90"}, "to": {"temp": "90"}}],
            "admissions": ["exact-finite-model"],
        }
        certificate_frame = {
            "frame_id": "frame:demo",
            "scope": ["demo"],
            "policy": {"adequacy_direction": "negative"},
            "completion_interface_ref": "completion:demo",
        }
        proposed_use = {
            "mode": "operational",
            "claim": "safe-temp",
            "horizon": 2,
            "anchor": "anchor:issue",
            "scope": ["demo"],
            "frame": "frame:demo",
        }
        status_context = {
            "status_time": "2026-01-01T00:00:00Z",
            "observation_records": [
                {
                    "r": 0,
                    "measurement_relation_ref": "artifact:measurement",
                    "representation_relation_ref": "artifact:representation",
                    "operational_completions": [[{"temp": "90"}, {"temp": "90"}, {"temp": "90"}]],
                    "prefix_adjudication_proof_ref": "artifact:prefix-proof",
                    "target_adjudication_proof_ref": "artifact:target-proof",
                    "adequacy_proof_ref": "artifact:adequacy-proof",
                }
            ],
            "observation_policy": {"r": 0},
            "completion_policy": {
                "completion_status": "pass",
                "admission_source": "completion-contract:demo",
                "expiry": "unbounded",
                "uncertainty_model": "exact",
                "reference_digest": "sha256:completion",
                "checker_result": "pass",
                "checker_transcript_ref": "artifact:completion-transcript",
                "c_out_ref": "artifact:completion-set",
            },
        }
        extra_entries.extend(
            _operational_relation_fixture_entries(
                temp="90",
                target_adjudication="reject",
                adequacy_direction="negative",
                completion_members=(({"temp": "90"}, {"temp": "90"}, {"temp": "90"}),),
            )
        )
    elif fixture == "authority:operational-agreement-mismatch":
        certificate_frame = {
            "frame_id": "frame:demo",
            "scope": ["demo"],
            "policy": {"adequacy_direction": "positive"},
            "completion_interface_ref": "completion:demo",
        }
        proposed_use = {
            "mode": "operational",
            "claim": "safe-temp",
            "horizon": 2,
            "anchor": "anchor:issue",
            "scope": ["demo"],
            "frame": "frame:demo",
        }
        status_context = {
            "status_time": "2026-01-01T00:00:00Z",
            "observation_records": [
                {
                    "r": 0,
                    "measurement_relation_ref": "artifact:measurement",
                    "representation_relation_ref": "artifact:representation",
                    "operational_completions": [[{"temp": "70"}, {"temp": "75"}, {"temp": "75"}]],
                    "prefix_adjudication_proof_ref": "artifact:prefix-proof",
                    "target_adjudication_proof_ref": "artifact:target-proof",
                    "adequacy_proof_ref": "artifact:adequacy-proof",
                }
            ],
            "observation_policy": {"r": 0},
            "completion_policy": {
                "completion_status": "pass",
                "admission_source": "completion-contract:demo",
                "expiry": "unbounded",
                "uncertainty_model": "exact",
                "reference_digest": "sha256:completion",
                "checker_result": "pass",
                "checker_transcript_ref": "artifact:completion-transcript",
                "c_out_ref": "artifact:completion-set",
            },
        }
        extra_entries.extend(
            _operational_relation_fixture_entries(
                temp="70",
                target_adjudication="reject",
                adequacy_direction="positive",
                completion_members=(({"temp": "70"}, {"temp": "75"}, {"temp": "75"}),),
            )
        )
    elif fixture == "authority:missing-completion-proof":
        certificate_frame = {
            "frame_id": "frame:demo",
            "scope": ["demo"],
            "policy": {"adequacy_direction": "positive"},
            "completion_interface_ref": "completion:demo",
        }
        proposed_use = {
            "mode": "operational",
            "claim": "safe-temp",
            "horizon": 2,
            "anchor": "anchor:issue",
            "scope": ["demo"],
            "frame": "frame:demo",
        }
        status_context = {
            "status_time": "2026-01-01T00:00:00Z",
            "observation_records": [
                {
                    "r": 0,
                    "measurement_relation_ref": "artifact:measurement",
                    "representation_relation_ref": "artifact:representation",
                    "operational_completions": [[{"temp": "70"}, {"temp": "75"}]],
                    "prefix_adjudication_proof_ref": "artifact:prefix-proof",
                    "target_adjudication_proof_ref": "artifact:target-proof",
                    "adequacy_proof_ref": "artifact:adequacy-proof",
                }
            ],
            "observation_policy": {"r": 0},
            "completion_policy": {
                "completion_status": "pass",
                "admission_source": "completion-contract:demo",
                "expiry": "unbounded",
                "uncertainty_model": "exact",
                "reference_digest": "sha256:completion",
                "checker_result": "pass",
                "checker_transcript_ref": "artifact:completion-transcript",
            },
        }
        extra_entries.extend(
            _operational_relation_fixture_entries(
                temp="70",
                target_adjudication="accept",
                adequacy_direction="positive",
                completion_members=(({"temp": "70"}, {"temp": "75"}),),
            )
        )
    elif fixture == "authority:accepted-clause-provenance":
        formal_accepted_issuance = True
    elif fixture == "authority:accepted-clause-target-mismatch":
        accepted_clause = {
            "state_space": [{"temp": "70"}],
            "initial_states": [{"temp": "70"}],
            "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        }
        extra_entries.extend(
            _accepted_clause_fixture_entries(
                accepted_clause,
                target="compiled:foreign-bundle",
            )
        )
    elif fixture == "authority:expired-clock":
        status_context["status_time"] = "2026-01-01T00:03:01Z"
        include_kernel_proof = False
    elif fixture == "authority:boundary-unknown-clock":
        time_basis_source = {**time_basis_source, "uncertainty_seconds": "2"}
        status_context["status_time"] = "2026-01-01T00:01:00Z"
        include_kernel_proof = False
    elif fixture == "authority:policy-block":
        certificate_policy = {"blocked_modes": ["assertion"]}
    elif fixture == "authority:conflicting-traces":
        include_kernel_proof = False
        status_context["event_log"] = [
            {
                "event_id": "evt-1",
                "certificate_id": "",
                "time": "2026-01-01T00:00:00Z",
                "logical_clock": 1,
                "kind": "expire",
            },
            {
                "event_id": "evt-2",
                "certificate_id": "",
                "time": "2026-01-01T00:00:01Z",
                "logical_clock": 1,
                "kind": "revoke",
            },
        ]
    elif fixture == "authority:missing-confluence-proof":
        include_kernel_proof = False
        status_context["event_log"] = [
            {
                "event_id": "evt-conflict",
                "certificate_id": "",
                "time": "2026-01-01T00:00:00Z",
                "logical_clock": 1,
                "kind": "conflict",
                "confluence_proof_ref": "artifact:missing-confluence-proof",
            }
        ]
    else:
        raise ValueError(f"unknown authority artifact-bundle fixture: {fixture}")

    issued = certify_claim(
        claim_source,
        bundle_source,
        anchor_source,
        time_basis_source,
        frame=certificate_frame,
        policy=certificate_policy,
    )
    if isinstance(issued, ValidationResult):
        raise AssertionError(f"fixture certificate issuance failed: {issued}")
    if formal_accepted_issuance:
        accepted_clause = {
            "state_space": [{"temp": "70"}],
            "initial_states": [{"temp": "70"}],
            "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        }
        issue_entries = [
            _artifact_bundle_entry(claim_source, ArtifactRole.CLAIM, "artifact:claim"),
            _artifact_bundle_entry(
                bundle_source,
                ArtifactRole.ASSUMPTION_BUNDLE,
                "artifact:bundle",
            ),
            _artifact_bundle_entry(anchor_source, ArtifactRole.ANCHOR, "artifact:anchor"),
            _artifact_bundle_entry(
                time_basis_source,
                ArtifactRole.TIME_BASIS,
                "artifact:time-basis",
            ),
            *_accepted_clause_fixture_entries(accepted_clause),
        ]
        formal_issue = certify_claim_from_artifact_bundle(
            artifact_bundle_from_json(
                {
                    "bundle_id": "bundle:formal-golden-issue",
                    "manifest": {
                        "manifest_id": "manifest:formal-golden-issue",
                        "root_artifact_id": "artifact:claim",
                        "artifact_refs": [entry["artifact_ref"] for entry in issue_entries],
                        "dependency_order": [
                            str(entry["artifact_ref"]["artifact_id"]) for entry in issue_entries
                        ],
                    },
                    "artifacts": issue_entries,
                }
            )
        )
        if isinstance(formal_issue, ValidationResult):
            raise AssertionError(f"formal fixture issuance failed: {formal_issue}")
        issued = formal_issue
        extra_entries.extend(_accepted_clause_fixture_entries(accepted_clause))
    if status_context.get("event_log"):
        status_context["event_log"] = [
            {**dict(item), "certificate_id": issued.certificate_id}
            for item in status_context["event_log"]
        ]
    cert_source = to_jsonable(issued)
    if stale_embedded_source and isinstance(cert_source, dict):
        stale_claim = dict(issued.claim_source)
        stale_formula = dict(stale_claim["formula"])
        stale_child = dict(stale_formula["child"])
        stale_args = dict(stale_child["args"])
        stale_args["value"] = "60"
        stale_child["args"] = stale_args
        stale_formula["child"] = stale_child
        stale_claim["formula"] = stale_formula
        cert_source["claim_source"] = stale_claim

    entries = [
        _artifact_bundle_entry(cert_source, ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _artifact_bundle_entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _artifact_bundle_entry(
            issued.bundle_source,
            ArtifactRole.ASSUMPTION_BUNDLE,
            issued.assumption_bundle_ref,
        ),
        _artifact_bundle_entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _artifact_bundle_entry(
            issued.time_basis_source,
            ArtifactRole.TIME_BASIS,
            issued.time_basis_ref,
        ),
        _artifact_bundle_entry(proposed_use, ArtifactRole.PROPOSED_USE, "artifact:use"),
        _artifact_bundle_entry(
            status_context,
            ArtifactRole.STATUS_CONTEXT,
            "artifact:status-context",
        ),
    ]
    if include_kernel_proof:
        entries.extend(_kernel_proof_fixture_entries(issued.kernel_verdict_at_issue.value))
    entries.extend(extra_entries)
    case_id = str(case.get("case_id", fixture.replace(":", "-")))
    return _artifact_bundle_from_entries(case_id=case_id, entries=entries)


def _artifact_bundle_case_source(case: dict[str, Any]) -> dict[str, Any]:
    source = case.get("bundle")
    if isinstance(source, dict):
        return source
    if case.get("fixture") is not None:
        if str(case["fixture"]).startswith("interop:"):
            return _interop_artifact_bundle_fixture(case)
        return _authority_artifact_bundle_fixture(case)
    raise KeyError("artifact-bundle case requires bundle or fixture")


def _validation_case(case: dict[str, Any]) -> GoldenResult:
    kind = str(case["kind"])
    if kind == "canonicalization-mismatch":
        try:
            canonical_bytes({"x": 1.2})
        except CanonicalizationError:
            result = validation_failure(
                FailureCode.CANONICALIZATION_MISMATCH,
                ValidationStage.CANONICALIZE,
                "canonical JSON rejects non-integer floats",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=str(case["case_id"]),
                source_path="/x",
            )
        else:
            result = ValidationResult(
                status=ValidationStatus.PASS,
                stage=ValidationStage.CANONICALIZE,
            )
        actual = result.status.value
        expected = str(case["expected"])
        return GoldenResult(
            str(case["case_id"]),
            actual == expected,
            expected,
            actual,
            equality_key=_validation_equality_key(result),
        )
    elif kind == "schema-invalid":
        result = validate_named_schema({"certificate_id": "x"}, "issue-certificate.schema.json")
        return _validation_result_case(case, result)
    elif kind == "digest-mismatch":
        ref = ArtifactRef("artifact:mismatch", "json", digest_value="sha256:not-the-digest")
        result = validate_artifact_ref(ref, artifact={"x": 1})
        return _validation_result_case(case, result)
    elif kind == "missing-ref":
        result, _ = resolve_reference(
            "artifact:missing",
            "/reason",
            store=ArtifactStore(),
            context=ReferenceResolutionContext("golden"),
        )
        return _validation_result_case(case, result)
    elif kind == "artifact-bundle":
        bundle = artifact_bundle_from_json(_artifact_bundle_case_source(case))
        full_replay = bool(case.get("full_replay", _canonical_equality_required(case)))
        report = validate_artifact_bundle(bundle, full_replay=full_replay)
        trace_contract = _artifact_bundle_trace_contract_failure(case, report)
        if trace_contract is not None:
            return trace_contract
        outcome_digest, equality_key = _pipeline_equality_key(report)
        if report.authority_view is not None:
            code, block, view_digest, view_equality_key = _view_key(report.authority_view)
            outcome_digest = view_digest or outcome_digest
            equality_key = view_equality_key or equality_key
            actual = f"{code}|{block}"
        else:
            actual = "pass" if report.passed else report.final_result.failure_records[0].code.value
        expected = str(case["expected"])
        return GoldenResult(
            str(case["case_id"]),
            actual == expected,
            expected,
            actual,
            outcome_digest,
            equality_key,
        )
    elif kind == "manifest-order-conflict":
        dep_b = build_artifact_ref({"b": 1}, artifact_id="artifact:b", artifact_type="json")
        dep_a = build_artifact_ref(
            {"a": 1},
            artifact_id="artifact:a",
            artifact_type="json",
            dependency_labels=("depends-on",),
        )
        dep_a = ArtifactRef(
            dep_a.artifact_id,
            dep_a.artifact_type,
            dep_a.schema_profile,
            dep_a.canonicalization,
            dep_a.media_type,
            dep_a.schema_digest,
            dep_a.canonicalization_digest,
            dep_a.digest_algorithm,
            dep_a.digest_value,
            dep_a.content_uri,
            dep_a.retrieval_policy,
            dep_a.immutability_policy,
            ("artifact:b",),
            dep_a.semantic_role,
            dep_a.dependency_labels,
        )
        result = validate_manifest_dependencies(
            (dep_a, dep_b),
            root_artifact_id="artifact:a",
            dependency_order=("artifact:a", "artifact:b"),
        )
        return _validation_result_case(case, result)
    elif kind == "raw-evidence-only-semantics":
        compiled = compile_bundle_from_accepted_clauses(
            {
                "bundle_id": "raw-only",
                "state_space": [{"temp": "70"}],
                "initial_states": [{"temp": "70"}],
                "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
            },
            (),
            1,
        )
        actual = "empty_semantics" if compiled.initial_set.is_empty() else "raw_influenced"
        expected = str(case["expected"])
        return GoldenResult(
            str(case["case_id"]),
            actual == expected,
            expected,
            actual,
            equality_key=_semantic_equality_key(case, actual),
        )
    else:
        raise ValueError(f"unknown validation golden case: {kind}")


def _canonical_equality_required(case: dict[str, Any]) -> bool:
    return bool(case.get("canonical_equality_required", True))


def _case_suite(case: dict[str, Any]) -> str:
    return str(case.get("suite", "primary"))


def _case_matches_suite(case: dict[str, Any], suite: str | None) -> bool:
    if suite is None:
        return True
    case_suite = _case_suite(case)
    if suite == "legacy":
        return case_suite.startswith("legacy")
    return case_suite == suite


def _is_legacy_case(case: dict[str, Any]) -> bool:
    return _case_suite(case).startswith("legacy")


def _contract_equality_key(case: dict[str, Any], failure: str) -> str:
    return digest_json(
        {
            "case_id": str(case.get("case_id", "")),
            "kind": str(case.get("kind", "")),
            "suite": _case_suite(case),
            "conformance_failure": failure,
        }
    )


def _case_contract_failure(case: dict[str, Any]) -> GoldenResult | None:
    case_id = str(case.get("case_id", ""))
    if case.get("expected_digest") is None and _canonical_equality_required(case):
        return GoldenResult(
            case_id,
            False,
            "expected_digest",
            "missing_expected_digest",
            equality_key=_contract_equality_key(case, "missing_expected_digest"),
        )
    if _is_legacy_case(case):
        return None
    kind = str(case.get("kind", ""))
    if kind != "artifact-bundle":
        return GoldenResult(
            case_id,
            False,
            "artifact-bundle",
            f"synthetic:{kind}",
            equality_key=_contract_equality_key(case, "synthetic_primary_case"),
        )
    if case.get("full_replay") is False:
        return GoldenResult(
            case_id,
            False,
            "full_replay",
            "disabled_full_replay",
            equality_key=_contract_equality_key(case, "full_replay_disabled"),
        )
    expected_digest = case.get("expected_digest")
    if _canonical_equality_required(case) and not _canonical_digest_value(expected_digest):
        return GoldenResult(
            case_id,
            False,
            "canonical_expected_digest",
            "invalid_expected_digest",
            equality_key=_contract_equality_key(case, "invalid_expected_digest"),
        )
    return None


def _canonical_digest_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    algorithm, separator, hexdigest = value.partition(":")
    expected_lengths = {"sha256": 64, "sha384": 96, "sha512": 128}
    if separator != ":" or algorithm not in expected_lengths:
        return False
    return len(hexdigest) == expected_lengths[algorithm] and all(
        char in "0123456789abcdef" for char in hexdigest
    )


def _reason_ref_has_pointer(ref: Any) -> bool:
    source_artifact = getattr(ref, "source_artifact", "")
    source_path = getattr(ref, "source_path", "")
    return (
        isinstance(source_artifact, str)
        and source_artifact.startswith("artifact:")
        and str(source_path).startswith("/")
    )


def _reason_ref_has_canonical_source_key(ref: Any) -> bool:
    return _reason_ref_has_pointer(ref) and _canonical_digest_value(getattr(ref, "digest", None))


def _replay_stage_trace_contract_failure(
    case: dict[str, Any],
    report: PipelineReport,
) -> GoldenResult | None:
    replay_trace = report.replay_trace or {}
    stage_traces_source = replay_trace.get("stage_traces", ())
    stage_traces = stage_traces_source if isinstance(stage_traces_source, list) else ()
    case_id = str(case.get("case_id", ""))
    for trace in stage_traces:
        if not isinstance(trace, dict):
            continue
        stage = str(trace.get("stage", "unknown"))
        if "artifact_ref_records" not in trace:
            return GoldenResult(
                case_id,
                False,
                "stage_artifact_ref_records",
                f"missing_stage_artifact_ref_records:{stage}",
                equality_key=_contract_equality_key(
                    case, f"missing_stage_artifact_ref_records:{stage}"
                ),
            )
        artifact_records = tuple(trace.get("artifact_ref_records", ()))
        artifact_refs = tuple(trace.get("artifact_refs", ()))
        if artifact_refs and not any(
            isinstance(record, dict) and record.get("digest_value") is not None
            for record in artifact_records
        ):
            return GoldenResult(
                case_id,
                False,
                "stage_artifact_ref_record_digest",
                f"missing_stage_artifact_ref_record_digest:{stage}",
                equality_key=_contract_equality_key(
                    case, f"missing_stage_artifact_ref_record_digest:{stage}"
                ),
            )
        if "proof_ref_records" not in trace:
            return GoldenResult(
                case_id,
                False,
                "stage_proof_ref_records",
                f"missing_stage_proof_ref_records:{stage}",
                equality_key=_contract_equality_key(
                    case, f"missing_stage_proof_ref_records:{stage}"
                ),
            )
    return None


def _artifact_bundle_trace_contract_failure(
    case: dict[str, Any],
    report: PipelineReport,
) -> GoldenResult | None:
    if _is_legacy_case(case) or not _canonical_equality_required(case):
        return None
    stage_trace_failure = _replay_stage_trace_contract_failure(case, report)
    if stage_trace_failure is not None:
        return stage_trace_failure
    case_id = str(case.get("case_id", ""))
    if report.authority_view is not None:
        view = report.authority_view
        if view.authority_outcome.code not in {
            "allow",
            "accept",
            "assert",
            "deny",
            "reject",
            "active",
        }:
            outcome_block_reasons = tuple(
                ref for block in view.authority_outcome.blocking_set for ref in block.reason_refs
            )
            reasons = (
                tuple(ref for block in view.blocking_set for ref in block.reason_refs)
                + tuple(view.authority_outcome.reason_refs)
                + outcome_block_reasons
            )
            if not view.blocking_set or not reasons:
                return GoldenResult(
                    case_id,
                    False,
                    "typed_blocking_reason_refs",
                    "missing_typed_blocking_reason_refs",
                    equality_key=_contract_equality_key(case, "missing_typed_blocking_reason_refs"),
                )
            if not view.authority_outcome.blocking_set:
                return GoldenResult(
                    case_id,
                    False,
                    "authority_outcome_blocking_records",
                    "missing_outcome_blocking_records",
                    equality_key=_contract_equality_key(case, "missing_outcome_blocking_records"),
                )
            if not all(_reason_ref_has_pointer(ref) for ref in reasons):
                return GoldenResult(
                    case_id,
                    False,
                    "json_pointer_reason_refs",
                    "missing_json_pointer_reason_refs",
                    equality_key=_contract_equality_key(case, "missing_json_pointer_reason_refs"),
                )
            if not all(_reason_ref_has_canonical_source_key(ref) for ref in reasons):
                return GoldenResult(
                    case_id,
                    False,
                    "artifact_digest_reason_refs",
                    "missing_reason_ref_digests",
                    equality_key=_contract_equality_key(case, "missing_reason_ref_digests"),
                )
        artifact_digests = [
            ref.digest_value for ref in view.artifact_refs if ref.digest_value is not None
        ]
        artifact_records = tuple(view.minimum_profile().get("artifact_ref_records", ()))
        artifact_record_digests = [
            record.get("digest_value")
            for record in artifact_records
            if isinstance(record, dict) and record.get("digest_value") is not None
        ]
        if not artifact_records:
            return GoldenResult(
                case_id,
                False,
                "artifact_ref_records",
                "missing_artifact_ref_records",
                equality_key=_contract_equality_key(case, "missing_artifact_ref_records"),
            )
        if view.manifest_digest is None and not artifact_digests and not artifact_record_digests:
            return GoldenResult(
                case_id,
                False,
                "artifact_digest",
                "missing_artifact_digest",
                equality_key=_contract_equality_key(case, "missing_artifact_digest"),
            )
        if not artifact_record_digests:
            return GoldenResult(
                case_id,
                False,
                "artifact_ref_record_digest",
                "missing_artifact_ref_record_digest",
                equality_key=_contract_equality_key(case, "missing_artifact_ref_record_digest"),
            )
        proof_records = {
            str(record.get("proof_id", "")): record
            for record in view.minimum_profile().get("proof_ref_records", ())
            if isinstance(record, dict)
        }
        for proof_ref in view.proof_refs:
            if not str(proof_ref).startswith("artifact:"):
                continue
            record = proof_records.get(str(proof_ref))
            if (
                record is None
                or record.get("status") != "accepted"
                or not str(record.get("source_artifact", "")).startswith("artifact:")
                or not str(record.get("source_path", "")).startswith("/")
                or not record.get("digest")
            ):
                return GoldenResult(
                    case_id,
                    False,
                    "artifact_digest_proof_refs",
                    "missing_proof_ref_digest",
                    equality_key=_contract_equality_key(case, "missing_proof_ref_digest"),
                )
        return None
    if not report.passed:
        reasons = tuple(
            dict.fromkeys(
                (
                    *report.final_result.reason_refs,
                    *(
                        ref
                        for failure in report.final_result.failure_records
                        for ref in failure.reason_refs
                    ),
                )
            )
        )
        if not reasons:
            return GoldenResult(
                case_id,
                False,
                "json_pointer_reason_refs",
                "missing_reason_refs",
                equality_key=_contract_equality_key(case, "missing_reason_refs"),
            )
        if not all(_reason_ref_has_pointer(ref) for ref in reasons):
            return GoldenResult(
                case_id,
                False,
                "json_pointer_reason_refs",
                "missing_json_pointer_reason_refs",
                equality_key=_contract_equality_key(case, "missing_json_pointer_reason_refs"),
            )
        if not all(_reason_ref_has_canonical_source_key(ref) for ref in reasons):
            return GoldenResult(
                case_id,
                False,
                "artifact_digest_reason_refs",
                "missing_reason_ref_digests",
                equality_key=_contract_equality_key(case, "missing_reason_ref_digests"),
            )
        if not report.artifact_ref_records:
            return GoldenResult(
                case_id,
                False,
                "artifact_ref_records",
                "missing_artifact_ref_records",
                equality_key=_contract_equality_key(case, "missing_artifact_ref_records"),
            )
        if not any(ref.digest_value is not None for ref in report.artifact_ref_records):
            return GoldenResult(
                case_id,
                False,
                "artifact_ref_record_digest",
                "missing_artifact_ref_record_digest",
                equality_key=_contract_equality_key(case, "missing_artifact_ref_record_digest"),
            )
    return None


def _apply_canonical_expectation(case: dict[str, Any], result: GoldenResult) -> GoldenResult:
    expected_digest = case.get("expected_digest")
    if expected_digest is None:
        return result
    actual_digest = result.equality_key or digest_json(
        {
            "case_id": result.case_id,
            "actual": result.actual,
            "outcome_digest": result.outcome_digest,
        }
    )
    return GoldenResult(
        result.case_id,
        actual_digest == expected_digest,
        str(expected_digest),
        actual_digest,
        result.outcome_digest,
        equality_key=actual_digest,
    )


def run_golden_cases(
    case_dir: Path | None = None,
    *,
    suite: str | None = None,
) -> tuple[GoldenResult, ...]:
    results: list[GoldenResult] = []
    for case in load_golden_cases(case_dir):
        if not _case_matches_suite(case, suite):
            continue
        contract_failure = _case_contract_failure(case)
        if contract_failure is not None:
            results.append(contract_failure)
            continue
        if str(case["kind"]).startswith("authority:"):
            result = _authority_case(case)
        else:
            result = _validation_case(case)
        results.append(_apply_canonical_expectation(case, result))
    return tuple(results)
