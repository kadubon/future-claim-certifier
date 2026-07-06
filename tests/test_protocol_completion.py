from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from dfcc.admission import (
    AcceptedClause,
    AdmissionContract,
    EvidenceArtifact,
    TrustAssumption,
    accepted_clause_obligation_record_result,
    accepted_clause_reason_record_result,
    admission_contract_result,
    admit_evidence,
    admit_evidence_set,
    trust_assumption_result,
)
from dfcc.artifacts import (
    ArtifactRef,
    ArtifactRole,
    ArtifactStore,
    ProofRefRecord,
    ReferenceKind,
    ReferenceLedgerEntry,
    ReferenceResolutionContext,
    ResolvedReference,
    build_artifact_ref,
    build_reference_ledger,
    manifest_digest,
    resolve_reference,
    validate_artifact_ref,
    validate_manifest_dependencies,
)
from dfcc.artifacts import (
    artifact_bundle_from_json as _artifact_bundle_from_json,
)
from dfcc.authority import check_authority
from dfcc.backend import ReferenceChecker
from dfcc.bundle import (
    BundleCompileError,
    compile_bundle,
    compile_bundle_from_accepted_clauses,
    parse_bundle,
)
from dfcc.certificate import (
    _artifact_bound_id,
    _lifecycle_reason_ref,
    certify_claim,
    certify_claim_from_artifact_bundle,
    update_certificate,
)
from dfcc.cli import main
from dfcc.conformance import run_golden_cases
from dfcc.frame import (
    MeasurementRelationArtifact,
    RepresentationRelationArtifact,
    completion_admission,
    make_observation_cut,
)
from dfcc.kernel import KernelProof, KernelProofArtifact, ProofRef
from dfcc.lifecycle import (
    EventOrder,
    FoldContext,
    LifecycleEvent,
    event_commitment,
    fold_status,
)
from dfcc.models import IssueCertificate, ProposedUse, StatusAuthorityView, StatusContext
from dfcc.profiles import resolve_profile, status_authority_field_policy
from dfcc.records import set_ref
from dfcc.replay import (
    ProtocolRecordArtifact,
    ReplayStageTrace,
    ReplayTrace,
    _bound_artifact_or_digest_ref,
    _completion_proof_payload_failure,
    _operational_proof_content_failure,
    _proof_payload_value,
    replay_authority_from_bundle,
    synthetic_authority_bundle,
)
from dfcc.schema import list_schemas, load_schema, validate_named_schema
from dfcc.serialization import to_jsonable
from dfcc.types import (
    AuthorityOutcome,
    Direction,
    FailureCode,
    GateDecision,
    Layer,
    OperationalCode,
    ReasonRef,
    StatusCode,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    blocking_record,
    reason,
    validate_authority_outcome,
)
from dfcc.validation import PipelineReport, validate_artifact_bundle, validate_pipeline


def _claim() -> dict[str, object]:
    return {
        "claim_id": "safe-temp",
        "horizon": 1,
        "formula": {
            "op": "atom",
            "name": "field_cmp",
            "args": {"field": "temp", "op": "lte", "value": "80"},
        },
        "scope": ["demo"],
    }


def _finite_bundle() -> dict[str, object]:
    return {
        "bundle_id": "finite-demo",
        "state_space": [{"temp": "70"}],
        "initial_states": [{"temp": "70"}],
        "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        "admissions": ["exact-finite-model"],
    }


def _with_manifest_digest(source: dict[str, Any]) -> dict[str, Any]:
    manifest = dict(source["manifest"])
    artifacts = source.get("artifacts", ())
    if "artifact_refs" not in manifest and isinstance(artifacts, list):
        refs = [
            dict(entry["artifact_ref"])
            for entry in artifacts
            if isinstance(entry, dict) and isinstance(entry.get("artifact_ref"), dict)
        ]
        manifest["artifact_refs"] = refs
        manifest.setdefault(
            "dependency_order",
            [str(ref["artifact_id"]) for ref in refs],
        )
    bundle = _artifact_bundle_from_json({**source, "manifest": manifest})
    identity = {
        "manifest_id": bundle.manifest.manifest_id,
        "root_artifact_id": bundle.manifest.root_artifact_id,
        "artifact_refs": [
            {
                "artifact_id": ref.artifact_id,
                "artifact_type": ref.artifact_type,
                "digest_value": ref.digest_value,
                "semantic_role": ref.semantic_role,
                "schema_profile": ref.schema_profile,
                "schema_digest": ref.schema_digest,
                "canonicalization": ref.canonicalization,
                "canonicalization_digest": ref.canonicalization_digest,
                "retrieval_policy": ref.retrieval_policy,
                "immutability_policy": ref.immutability_policy,
                "provenance_refs": list(ref.provenance_refs),
                "dependency_labels": list(ref.dependency_labels),
            }
            for ref in bundle.manifest.artifact_refs
        ],
        "dependency_order": list(bundle.manifest.dependency_order),
        "semantic_roles": dict(bundle.manifest.semantic_roles),
        "fixed_point_admissions": list(bundle.manifest.fixed_point_admissions),
    }
    manifest["manifest_digest"] = manifest_digest(
        identity,
        artifact_type="manifest",
        schema_profile_digest="DFCC-Interop",
        dependencies=bundle.manifest.artifact_refs,
    )
    return {**source, "manifest": manifest}


def artifact_bundle_from_json(source: dict[str, Any]):
    manifest = source.get("manifest")
    if (
        isinstance(manifest, dict)
        and "manifest_digest" not in manifest
        and (manifest.get("artifact_refs") or source.get("artifacts"))
    ):
        source = _with_manifest_digest(source)
    return _artifact_bundle_from_json(source)


def _artifact_bundle_source(
    artifact: object,
    *,
    role: str = ArtifactRole.REASON.value,
    ref_override: dict[str, object] | None = None,
    schema_name: str | None = None,
    reason_paths: tuple[str, ...] = (),
) -> dict[str, object]:
    ref = build_artifact_ref(
        artifact,
        artifact_id=f"artifact:{role}",
        artifact_type="json",
        semantic_role=role,
    )
    ref_source = dict(to_jsonable(ref))
    if ref_override:
        ref_source.update(ref_override)
    return _with_manifest_digest(
        {
            "bundle_id": "bundle:test",
            "manifest": {
                "manifest_id": "manifest:test",
                "root_artifact_id": ref_source["artifact_id"],
                "artifact_refs": [ref_source],
                "dependency_order": [ref_source["artifact_id"]],
                "semantic_roles": {ref_source["artifact_id"]: role},
            },
            "reference_context": {"snapshot_id": "snapshot:test"},
            "artifacts": [
                {
                    "artifact_ref": ref_source,
                    "artifact": artifact,
                    "role": role,
                    "schema_name": schema_name,
                    "reason_paths": list(reason_paths),
                }
            ],
        }
    )


def _reason_ref_record(
    *,
    source_artifact: str = "artifact:reason",
    source_path: str = "/reason",
    message: str = "accepted clause fixture",
) -> dict[str, str]:
    return {
        "reason_id": f"reason:{source_artifact}:{source_path}",
        "failure_code": "checker_unknown",
        "layer": "issue",
        "source_artifact": source_artifact,
        "source_path": source_path,
        "message": message,
        "digest": manifest_digest(
            message,
            artifact_type="reference-target",
            schema_profile_digest="DFCC-Interop",
        ),
    }


def _obligation_payload() -> dict[str, str]:
    return {
        "obligation_id": "obligation:model",
        "kind": "admission",
        "status": "pass",
    }


def _obligation_digest() -> str:
    return manifest_digest(
        _obligation_payload(),
        artifact_type="reference-target",
        schema_profile_digest="DFCC-Interop",
    )


def _evidence_artifact() -> dict[str, object]:
    return {
        "artifact_id": "artifact:evidence",
        "kind": "finite-model",
        "payload": {},
        "checker_status": "unchecked",
    }


def _admission_contract() -> dict[str, object]:
    return {
        "kind": "finite-model",
        "source": "artifact:evidence",
        "target": "semantics",
        "clause": {
            "state_space": [{"temp": "70"}],
            "initial_states": [{"temp": "70"}],
            "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        },
        "checker_transcript_ref": "artifact:transcript",
        "obligation_refs": ["artifact:obligation#/obligation"],
    }


def _entry(artifact: object, role: ArtifactRole, artifact_id: str) -> dict[str, Any]:
    ref = build_artifact_ref(
        artifact,
        artifact_id=artifact_id,
        artifact_type="json",
        semantic_role=role,
    )
    return {"artifact_ref": to_jsonable(ref), "artifact": artifact, "role": role.value}


def _proof_entry(artifact_id: str, **payload: object) -> dict[str, Any]:
    proof = {"status": "pass", "proof_kind": "kernel-proof-evidence", **payload}
    ref = build_artifact_ref(
        proof,
        artifact_id=artifact_id,
        artifact_type="json",
        semantic_role="proof",
    )
    return {
        "artifact_ref": to_jsonable(ref),
        "artifact": proof,
        "role": ArtifactRole.OTHER.value,
    }


def _kernel_proof_entries() -> tuple[dict[str, Any], ...]:
    return (
        _entry(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:kernel-transcript",
                "witness_provenance_refs": ["artifact:kernel-witness"],
                "proof": {
                    "backend_identity": "EnumeratingBackend",
                    "proof_kind": "exact-finite-enumeration",
                    "proof_status": "accepted",
                    "expected_verdict": "assert",
                    "feasibility": "feasible",
                    "inclusion": "yes",
                    "disjointness": "no",
                    "inclusion_ref": "artifact:kernel-inclusion-proof",
                },
            },
            ArtifactRole.KERNEL_PROOF,
            "artifact:kernel-proof",
        ),
        _entry({"status": "pass"}, ArtifactRole.OTHER, "artifact:kernel-transcript"),
        _proof_entry(
            "artifact:kernel-witness",
            proof_kind="witness_provenance",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="assert",
        ),
        _proof_entry(
            "artifact:kernel-inclusion-proof",
            proof_kind="inclusion",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="assert",
            inclusion="yes",
        ),
    )


def test_artifact_bundle_pipeline_success_and_cli(tmp_path: Path, capsys) -> None:
    source = _artifact_bundle_source({"reason": {"message": "ok"}}, reason_paths=("/reason",))
    bundle = artifact_bundle_from_json(_with_manifest_digest(source))
    report = validate_pipeline(bundle)
    assert isinstance(report, PipelineReport)
    assert report.passed
    assert report.resolved_refs[0].source_path == "/reason"

    bundle_file = tmp_path / "artifact-bundle.json"
    bundle_file.write_text(json.dumps(_with_manifest_digest(source)), encoding="utf-8")
    assert main(["validate-bundle", str(bundle_file), "--horizon", "1"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["stage_results"][-1]["status"] == "pass"


def test_schema_export_includes_replay_trace_and_pipeline_report() -> None:
    names = set(list_schemas())
    for name in (
        "agreement.schema.json",
        "completion-admission.schema.json",
        "failure-record.schema.json",
        "fiber-assoc-view.schema.json",
        "guard-record.schema.json",
        "kernel-proof-artifact.schema.json",
        "dependency-graph.schema.json",
        "lifecycle-decision.schema.json",
        "lifecycle-event.schema.json",
        "measurement-relation-artifact.schema.json",
        "observation-cut.schema.json",
        "pipeline-report.schema.json",
        "profile-resolution.schema.json",
        "protocol-record-artifact.schema.json",
        "proposed-use.schema.json",
        "representation-relation-artifact.schema.json",
        "replay-stage-trace.schema.json",
        "replay-trace.schema.json",
        "scalar-record.schema.json",
        "status-context.schema.json",
        "set-ref.schema.json",
        "interval-record.schema.json",
        "timestamp-record.schema.json",
    ):
        assert name in names
        Draft202012Validator.check_schema(load_schema(name))
    resolved_profile = to_jsonable(resolve_profile("DFCC-Interop"))
    assert validate_named_schema(
        resolved_profile,
        "profile-resolution.schema.json",
    ).passed
    unsupported_profile_record = to_jsonable(resolve_profile("DFCC-Unknown"))
    assert unsupported_profile_record["reason_refs"]
    assert validate_named_schema(
        unsupported_profile_record,
        "profile-resolution.schema.json",
    ).passed
    unsupported_without_reason = {**unsupported_profile_record, "reason_refs": []}
    unsupported_without_reason_schema = validate_named_schema(
        unsupported_without_reason,
        "profile-resolution.schema.json",
    )
    assert not unsupported_without_reason_schema.passed
    assert unsupported_without_reason_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    legacy_profile_shape = {
        "profile_id": "DFCC-Interop",
        "status": "pass",
        "required_extensions": [],
    }
    legacy_profile_schema = validate_named_schema(
        legacy_profile_shape,
        "profile-resolution.schema.json",
    )
    assert not legacy_profile_schema.passed
    assert legacy_profile_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    profile_bundle = _artifact_bundle_source(
        resolved_profile,
        role=ArtifactRole.PROFILE.value,
    )
    assert validate_artifact_bundle(artifact_bundle_from_json(profile_bundle)).passed
    openapi_text = (Path(__file__).parents[1] / "docs" / "openapi.yaml").read_text(encoding="utf-8")
    openapi = yaml.safe_load(openapi_text)
    assert isinstance(openapi, dict)
    openapi_components = openapi["components"]["schemas"]
    assert "LifecycleEvent:" in openapi_text
    assert '$ref: "#/components/schemas/LifecycleEvent"' in openapi_text
    lifecycle_fields = {
        "manifest_digest_ref",
        "event_manifest_ref",
        "manifest_digest_status",
        "event_manifest_digest_status",
        "signature_verifier_result_ref",
        "signature_verifier_result_status",
        "log_root_ref",
        "causal_cut_ref",
        "trace_class_ref",
    }
    lifecycle_schema = load_schema("lifecycle-event.schema.json")
    assert lifecycle_fields.issubset(lifecycle_schema["properties"])
    for field_name in lifecycle_fields:
        assert f"{field_name}:" in openapi_text
    lifecycle_decision_schema = load_schema("lifecycle-decision.schema.json")
    lifecycle_decision_required = {
        "blocking_records",
        "reason_ref_records",
        "event_manifest_digest",
        "event_manifest_digest_ref",
        "signature_verifier_result_ref",
        "accepted_event_ids",
        "accepted_event_ids_ref",
        "trace_class",
        "trace_class_ref",
        "causal_cut",
        "causal_cut_ref",
        "log_root",
        "log_root_ref",
        "dependency_updates",
        "frame_transfer_ref",
        "proof_preservation_refs",
    }
    assert lifecycle_decision_required.issubset(lifecycle_decision_schema["required"])
    for field_name in lifecycle_decision_required:
        assert f"{field_name}:" in openapi_text
    observation_cut_schema = load_schema("observation-cut.schema.json")
    observation_record_properties = observation_cut_schema["$defs"]["observation_record"][
        "properties"
    ]
    observation_relation_fields = {
        "measurement_proof_ref",
        "measurement_relation_proof_ref",
        "measurement_relation",
        "representation_relation",
    }
    assert observation_relation_fields.issubset(observation_record_properties)
    status_context_schema = load_schema("status-context.schema.json")
    status_observation_record_properties = status_context_schema["$defs"]["observation_record"][
        "properties"
    ]
    assert observation_relation_fields.issubset(status_observation_record_properties)
    for field_name in observation_relation_fields:
        assert f"{field_name}:" in openapi_text
    observation_cut_profile = {
        "records": [
            {
                "measurement_relation": {
                    "relation_id": "measurement:demo",
                    "accepted": "pass",
                    "calibration_ref": "artifact:calibration",
                    "latency_ref": "artifact:latency",
                    "dependency_ref": "artifact:dependency",
                    "event_order_ref": "artifact:event-order",
                    "proof_ref": "artifact:measurement-proof",
                },
                "representation_relation": {
                    "relation_id": "representation:demo",
                    "operational_prefix": [{"temp": "70"}],
                    "represented_prefix": [{"temp": "70"}],
                    "proof_ref": "artifact:representation-proof",
                },
            }
        ],
        "status_time": "2026-01-01T00:00:00Z",
        "time_basis_ref": "artifact:time-basis",
        "event_order_ref": "artifact:event-order",
        "dependency_snapshot": {"dep": "sha256:dep"},
        "frame_id": "frame:demo",
        "policy_ref": "policy:demo",
    }
    assert validate_named_schema(observation_cut_profile, "observation-cut.schema.json").passed
    invalid_observation_cut_profile = {
        **observation_cut_profile,
        "records": [
            {
                **observation_cut_profile["records"][0],
                "representation_relation": {
                    **observation_cut_profile["records"][0]["representation_relation"],
                    "proof_ref": "representation-proof:local",
                },
            }
        ],
    }
    assert not validate_named_schema(
        invalid_observation_cut_profile,
        "observation-cut.schema.json",
    ).passed
    accepted_clause_schema = load_schema("accepted-clause.schema.json")
    assert "obligation_ref_records" in accepted_clause_schema["properties"]
    assert "obligation_ref_records:" in openapi_text
    protocol_record_schema = load_schema("protocol-record-artifact.schema.json")
    assert "artifact_ref_records" in protocol_record_schema["required"]
    assert "proof_ref_records" in protocol_record_schema["required"]
    assert "reason_ref_records" in protocol_record_schema["required"]
    protocol_record_component = openapi_components["ProtocolRecordArtifact"]
    assert set(protocol_record_schema["required"]).issubset(
        set(protocol_record_component["required"])
    )
    assert (
        protocol_record_component["properties"]["stage"]["enum"]
        == (protocol_record_schema["properties"]["stage"]["enum"])
    )
    assert (
        protocol_record_component["properties"]["digest"]["type"]
        == (protocol_record_schema["properties"]["digest"]["type"])
    )
    assert (
        protocol_record_component["properties"]["digest"]["pattern"]
        == (protocol_record_schema["properties"]["digest"]["pattern"])
    )
    replay_stage_schema = load_schema("replay-stage-trace.schema.json")
    assert "artifact_ref_records" in replay_stage_schema["required"]
    assert "proof_ref_records" in replay_stage_schema["required"]
    replay_stage_component = openapi_components["ReplayStageTrace"]
    assert set(replay_stage_schema["required"]).issubset(set(replay_stage_component["required"]))
    assert (
        replay_stage_component["properties"]["stage"]["enum"]
        == (replay_stage_schema["properties"]["stage"]["enum"])
    )
    replay_trace_schema = load_schema("replay-trace.schema.json")
    replay_trace_component = openapi_components["ReplayTrace"]
    assert set(replay_trace_schema["required"]).issubset(set(replay_trace_component["required"]))
    assert (
        replay_trace_component["properties"]["stage_artifacts"]["propertyNames"]["enum"]
        == replay_trace_schema["properties"]["stage_artifacts"]["propertyNames"]["enum"]
    )
    pipeline_schema = load_schema("pipeline-report.schema.json")
    pipeline_component = openapi_components["PipelineReport"]
    assert (
        pipeline_component["properties"]["stage_artifacts"]["propertyNames"]["enum"]
        == pipeline_schema["properties"]["stage_artifacts"]["propertyNames"]["enum"]
    )
    assert "proof_ref_records:" in openapi_text
    assert "reason_ref_records:" in openapi_text
    proof_ref_schema = load_schema("proof-ref.schema.json")
    assert validate_named_schema(
        {
            "proof_id": "artifact:proof",
            "proof_kind": "kernel",
            "artifact_ref": "artifact:proof",
            "source_artifact": "artifact:proof",
            "source_path": "/",
            "digest": "sha256:proof",
            "status": "accepted",
        },
        "proof-ref.schema.json",
    ).passed
    assert validate_named_schema(
        {
            "proof_id": "artifact:proof",
            "proof_kind": "kernel",
            "artifact_ref": "artifact:proof",
            "source_artifact": "artifact:proof",
            "source_path": "/",
            "digest": None,
            "status": "unknown",
        },
        "proof-ref.schema.json",
    ).passed
    accepted_without_digest = validate_named_schema(
        {
            "proof_id": "artifact:proof",
            "proof_kind": "kernel",
            "artifact_ref": "artifact:proof",
            "source_artifact": "artifact:proof",
            "source_path": "/",
            "digest": None,
            "status": "accepted",
        },
        "proof-ref.schema.json",
    )
    assert not accepted_without_digest.passed
    assert accepted_without_digest.failure_records[0].code is FailureCode.SCHEMA_INVALID
    assert proof_ref_schema["allOf"]
    parsed_proof_ref = ProofRefRecord.from_json(
        {
            "proof_id": "artifact:proof",
            "proof_kind": "kernel",
            "artifact_ref": "artifact:proof",
            "source_artifact": "artifact:proof",
            "source_path": "/",
            "digest": "sha256:proof",
            "status": "accepted",
        }
    )
    assert parsed_proof_ref.status == "accepted"
    with pytest.raises(ValueError, match="digest"):
        ProofRefRecord.from_json(
            {
                "proof_id": "artifact:proof",
                "proof_kind": "kernel",
                "artifact_ref": "artifact:proof",
                "source_artifact": "artifact:proof",
                "source_path": "/",
                "status": "accepted",
            }
        )
    with pytest.raises(ValueError, match="source_path"):
        ProofRefRecord.from_json(
            {
                "proof_id": "artifact:proof",
                "proof_kind": "kernel",
                "source_path": "relative",
                "status": "unknown",
            }
        )
    runtime_schema = load_schema("resolved-authority-runtime.schema.json")
    assert "resolved_obligation_records" in runtime_schema["required"]
    assert "resolved_reason_ref_records" in runtime_schema["required"]
    assert "artifact_ref_records" in runtime_schema["required"]
    assert "set_ref_records" in runtime_schema["required"]
    assert "proof_ref_records" in runtime_schema["required"]
    assert "authority_runtime_summary:" in openapi_text
    assert "SetRef:" in openapi_text
    issue_schema = load_schema("issue-certificate.schema.json")
    status_schema = load_schema("status-authority-view.schema.json")
    assert "obligation_ref_records" in issue_schema["required"]
    assert "artifact_ref_records" in issue_schema["required"]
    assert "set_ref_records" in issue_schema["required"]
    assert "proof_ref_records" in issue_schema["required"]
    assert "artifact_ref_records" in status_schema["required"]
    assert "set_ref_records" in status_schema["required"]
    pipeline_schema = load_schema("pipeline-report.schema.json")
    assert "artifact_ref_records" in pipeline_schema["required"]
    assert issue_schema["properties"]["proof_refs"]["minItems"] == 1
    assert issue_schema["properties"]["proof_ref_records"]["minItems"] == 1
    assert "IssueCertificate:" in openapi_text
    obligation_ref_schema = load_schema("obligation-ref.schema.json")
    obligation_fields = {"source_artifact", "source_path", "digest"}
    assert obligation_fields.issubset(obligation_ref_schema["properties"])
    for field_name in obligation_fields:
        assert f"{field_name}:" in openapi_text
    assert validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "confluence_proof": {
                "proof_kind": "confluence",
                "proof_status": "accepted",
                "artifact_ref": "artifact:confluence-proof",
                "artifact_digest": "sha256:confluence-proof",
                "event_ids": ["evt-1", "evt-2"],
            },
        },
        "status-context.schema.json",
    ).passed
    assert validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "observation_records": [
                {
                    "measurement_relation_ref": "artifact:measurement",
                    "representation_relation_ref": "artifact:representation",
                    "calibration_ref": {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:calibration-proof",
                        "proof_kind": "calibration",
                        "artifact_digest": "sha256:calibration-proof",
                    },
                    "latency_ref": "artifact:latency-proof",
                    "dependency_ref": "sha256:dependency-proof",
                    "event_order_ref": "artifact:event-order-proof",
                    "representation_proof_ref": "artifact:representation-proof",
                    "prefix_adjudication_proof_ref": "artifact:prefix-proof",
                    "target_adjudication_proof_ref": "artifact:target-proof",
                    "adequacy_proof_ref": "artifact:adequacy-proof",
                }
            ],
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "observation_records": [{"representation_proof_ref": "representation-proof:local"}],
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "observation_records": [{"calibration_ref": "calibration:local"}],
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "confluence_proof": "proof:local-confluence",
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [
                {
                    "event_id": "evt",
                    "signature_verifier_result_ref": "proof:signature",
                }
            ],
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "confluence_proof": {"proof_status": "accepted"},
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "confluence_proof": {
                "proof_kind": "confluence",
                "proof_status": "accepted",
                "artifact_ref": "artifact:confluence-proof",
            },
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "confluence_proof": {
                "proof_kind": "confluence",
                "artifact_ref": "artifact:confluence-proof",
                "artifact_digest": "sha256:confluence-proof",
            },
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "event_id": "evt",
            "certificate_id": "cert",
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "conflict",
            "confluence_proof_ref": "proof:local-confluence",
        },
        "lifecycle-event.schema.json",
    ).passed
    lifecycle_event_with_refs = {
        "event_id": "evt",
        "certificate_id": "cert",
        "time": "2026-01-01T00:00:00Z",
        "logical_clock": 1,
        "kind": "audit",
        "manifest_digest": "sha256:event-manifest",
        "manifest_digest_ref": "artifact:manifest-proof",
        "manifest_digest_status": {
            "status": "accepted",
            "artifact_ref": "artifact:manifest-proof",
            "artifact_digest": "sha256:manifest-proof",
            "proof_kind": "event_manifest_digest",
            "payload": {
                "event_id": "evt",
                "event_manifest_digest": "sha256:event-manifest",
            },
        },
        "event_manifest_ref": "artifact:event-manifest-proof",
        "event_manifest_digest_status": {
            "status": "accepted",
            "artifact_ref": "artifact:event-manifest-proof",
            "artifact_digest": "sha256:event-manifest-proof",
            "proof_kind": "event_manifest_digest",
            "payload": {
                "event_id": "evt",
                "event_manifest_digest": "sha256:event-manifest",
            },
        },
        "log_root_ref": "artifact:log-root-proof",
        "causal_cut_ref": "artifact:causal-cut-proof",
        "trace_class_ref": "artifact:trace-class-proof",
        "confluence_proof_ref": "artifact:confluence-proof",
        "signature_verifier_result_ref": "artifact:signature-proof",
    }
    assert validate_named_schema(
        lifecycle_event_with_refs,
        "lifecycle-event.schema.json",
    ).passed
    parsed_lifecycle_event = LifecycleEvent.from_json(lifecycle_event_with_refs)
    assert parsed_lifecycle_event.manifest_digest_ref == "artifact:manifest-proof"
    assert parsed_lifecycle_event.event_manifest_ref == "artifact:event-manifest-proof"
    assert parsed_lifecycle_event.manifest_digest_status is not None
    assert parsed_lifecycle_event.event_manifest_digest_status is not None
    assert parsed_lifecycle_event.log_root_ref == "artifact:log-root-proof"
    assert parsed_lifecycle_event.causal_cut_ref == "artifact:causal-cut-proof"
    assert parsed_lifecycle_event.trace_class_ref == "artifact:trace-class-proof"
    assert parsed_lifecycle_event.signature_verifier_result_ref == "artifact:signature-proof"
    assert validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [lifecycle_event_with_refs],
        },
        "status-context.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [
                {
                    **lifecycle_event_with_refs,
                    "manifest_digest_status": {"status": "accepted"},
                }
            ],
        },
        "status-context.schema.json",
    ).passed
    assert validate_named_schema(
        {
            "event_id": "evt",
            "certificate_id": "cert",
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "signature": "signature-bytes",
            "signature_verifier_result": "pass",
            "signature_verifier_result_ref": "artifact:signature-proof",
            "signature_verifier_result_status": {
                "status": "accepted",
                "artifact_ref": "artifact:signature-proof",
                "artifact_digest": "sha256:signature-proof",
                "proof_kind": "signature_verifier",
                "payload": {
                    "event_id": "evt",
                    "signature_verifier_result": "pass",
                },
            },
            "payload": {"signature_policy": "required"},
        },
        "lifecycle-event.schema.json",
    ).passed


def test_protocol_record_and_relation_artifact_models() -> None:
    source_artifact_ref = build_artifact_ref(
        {"record": "kernel"},
        artifact_id="artifact:cert",
        artifact_type="protocol-evidence",
        semantic_role=ArtifactRole.PROTOCOL_RECORD,
    )
    record_block = blocking_record(
        FailureCode.CHECKER_UNKNOWN,
        Layer.REPRESENTED,
        "kernel proof evidence missing",
        source_artifact="artifact:reason",
        source_path="/reason",
    )
    record = ProtocolRecordArtifact.build(
        record_id="record:kernel",
        record_kind="KernelView",
        stage=ValidationStage.KERNEL_CHECK,
        payload={"verdict": "assert"},
        artifact_refs=(source_artifact_ref.artifact_id,),
        artifact_ref_records=(source_artifact_ref,),
        proof_refs=(
            ProofRef(
                proof_id="artifact:kernel-proof",
                proof_kind="kernel",
                artifact_ref="artifact:kernel-proof",
                source_artifact="artifact:kernel-proof",
                source_path="/proof",
                digest="sha256:kernel-proof",
                status="accepted",
            ),
        ),
        reason_refs=record_block.reason_refs,
    )
    assert record.digest is not None
    record_json = record.to_json()
    assert record_json["record_id"] == "record:kernel"
    assert record_json["payload"] == {"verdict": "assert"}
    assert record_json["artifact_refs"] == ["artifact:cert"]
    assert record_json["artifact_ref_records"][0]["digest_value"].startswith("sha256:")
    assert record_json["proof_refs"] == ["artifact:kernel-proof"]
    assert record_json["proof_ref_records"][0]["status"] == "accepted"
    assert record_json["reason_ref_records"][0]["source_path"] == "/reason"
    assert validate_named_schema(record_json, "protocol-record-artifact.schema.json").passed
    missing_record_digest = dict(record_json)
    missing_record_digest.pop("digest")
    assert not validate_named_schema(
        missing_record_digest, "protocol-record-artifact.schema.json"
    ).passed
    missing_artifact_records = dict(record_json)
    missing_artifact_records.pop("artifact_ref_records")
    assert not validate_named_schema(
        missing_artifact_records, "protocol-record-artifact.schema.json"
    ).passed
    legacy_record = ProtocolRecordArtifact.build(
        record_id="record:legacy-kernel",
        record_kind="KernelView",
        stage=ValidationStage.KERNEL_CHECK,
        payload={"verdict": "assert"},
        artifact_refs=("artifact:legacy-cert",),
        proof_refs=(),
        reason_refs=(),
    )
    legacy_json = legacy_record.to_json()
    assert legacy_json["artifact_ref_records"][0]["artifact_id"] == "artifact:legacy-cert"
    assert legacy_json["artifact_ref_records"][0]["semantic_role"] == "protocol_record"
    assert str(legacy_json["artifact_ref_records"][0]["digest_value"]).startswith("sha256:")
    assert validate_named_schema(legacy_json, "protocol-record-artifact.schema.json").passed
    assert not validate_named_schema(
        {**record_json, "stage": "Kernel"},
        "protocol-record-artifact.schema.json",
    ).passed
    stage_trace = ReplayStageTrace(
        ValidationStage.KERNEL_CHECK,
        ValidationResult(ValidationStage.KERNEL_CHECK, ValidationStatus.PASS),
        record_refs=(record.record_id,),
        artifact_refs=(source_artifact_ref.artifact_id,),
        artifact_ref_records=(source_artifact_ref,),
        proof_refs=("proof:kernel",),
        proof_ref_records=record.proof_refs,
    )
    stage_trace_json = stage_trace.to_json()
    assert stage_trace_json["artifact_ref_records"][0]["artifact_id"] == "artifact:cert"
    assert stage_trace_json["artifact_ref_records"][0]["digest_value"].startswith("sha256:")
    assert stage_trace_json["proof_ref_records"][0]["proof_id"] == "artifact:kernel-proof"
    assert validate_named_schema(stage_trace_json, "replay-stage-trace.schema.json").passed
    missing_stage_artifact_records = dict(stage_trace_json)
    missing_stage_artifact_records.pop("artifact_ref_records")
    assert not validate_named_schema(
        missing_stage_artifact_records, "replay-stage-trace.schema.json"
    ).passed
    missing_stage_proof_records = dict(stage_trace_json)
    missing_stage_proof_records.pop("proof_ref_records")
    assert not validate_named_schema(
        missing_stage_proof_records, "replay-stage-trace.schema.json"
    ).passed
    blocking_trace = ReplayStageTrace(
        ValidationStage.GUARD_EVALUATE,
        ValidationResult(ValidationStage.GUARD_EVALUATE, ValidationStatus.UNKNOWN),
        blocking_records=(
            blocking_record(
                FailureCode.CHECKER_UNKNOWN,
                Layer.OPERATIONAL,
                "guard evidence missing",
            ),
        ),
    )
    replay_trace = ReplayTrace(
        stage_traces=(stage_trace, blocking_trace),
        stage_artifacts={"KernelCheck": (record.record_id,)},
        protocol_records=(record,),
    )
    assert validate_named_schema(replay_trace.to_json(), "replay-trace.schema.json").passed
    invalid_stage_artifacts = {
        **replay_trace.to_json(),
        "stage_artifacts": {"Kernel": [record.record_id]},
    }
    assert not validate_named_schema(invalid_stage_artifacts, "replay-trace.schema.json").passed
    assert replay_trace.stage_results[0].passed
    stage_trace_json = stage_trace.to_json()
    assert stage_trace_json["record_refs"] == ["record:kernel"]
    assert validate_named_schema(stage_trace_json, "replay-stage-trace.schema.json").passed
    assert not validate_named_schema(
        {**stage_trace_json, "stage": "Kernel"},
        "replay-stage-trace.schema.json",
    ).passed
    blocking_trace_json = blocking_trace.to_json()
    assert blocking_trace_json["blocking_set"]
    assert blocking_trace_json["blocking_records"][0]["reason_ref_records"]
    assert validate_named_schema(blocking_trace_json, "replay-stage-trace.schema.json").passed
    legacy_trace_json = {
        **blocking_trace_json,
        "blocking_records": blocking_trace_json["blocking_set"],
    }
    assert not validate_named_schema(legacy_trace_json, "replay-stage-trace.schema.json").passed
    empty_unknown_trace_json = {
        **blocking_trace_json,
        "blocking_set": [],
        "blocking_records": [],
        "reason_refs": [],
        "reason_ref_records": [],
    }
    assert not validate_named_schema(
        empty_unknown_trace_json, "replay-stage-trace.schema.json"
    ).passed

    measurement = MeasurementRelationArtifact.from_json(
        {
            "artifact_id": "artifact:measurement",
            "checker_status": "pass",
            "proof_refs": ["artifact:proof"],
            "relation": {
                "relation_id": "measurement:1",
                "calibration_ref": "artifact:calibration",
                "latency_ref": "artifact:latency",
                "dependency_ref": "artifact:dependency",
                "event_order_ref": "artifact:event-order",
            },
        }
    )
    assert measurement.relation.accepted
    assert measurement.proof_refs == ("artifact:proof",)
    digest_bound = "sha256:" + "a" * 64
    measurement_with_digest_objects = MeasurementRelationArtifact.from_json(
        {
            "artifact_id": "artifact:measurement-digest",
            "checker_status": "accepted",
            "proof_refs": ["artifact:proof"],
            "relation": {
                "relation_id": "measurement:digest",
                "calibration_ref": {"digest": digest_bound},
                "latency_ref": {"artifact_ref": "artifact:latency"},
                "dependency_ref": {"reference_digest": digest_bound},
                "event_order_ref": digest_bound,
            },
        }
    )
    assert measurement_with_digest_objects.relation.calibration_ref == digest_bound
    assert measurement_with_digest_objects.relation.dependency_ref == digest_bound
    with pytest.raises(TypeError, match="relation must be an object"):
        MeasurementRelationArtifact.from_json(
            {
                "artifact_id": "artifact:measurement",
                "relation": "measurement:declared-only",
            }
        )
    with pytest.raises(ValueError, match="checker_status"):
        MeasurementRelationArtifact.from_json(
            {
                "artifact_id": "artifact:measurement",
                "proof_refs": ["artifact:proof"],
                "relation": {
                    "relation_id": "measurement:1",
                    "calibration_ref": "artifact:calibration",
                    "latency_ref": "artifact:latency",
                    "dependency_ref": "artifact:dependency",
                    "event_order_ref": "artifact:event-order",
                },
            }
        )
    with pytest.raises(ValueError, match="proof_refs"):
        MeasurementRelationArtifact.from_json(
            {
                "artifact_id": "artifact:measurement",
                "checker_status": "pass",
                "proof_refs": [],
                "relation": {
                    "relation_id": "measurement:1",
                    "calibration_ref": "artifact:calibration",
                    "latency_ref": "artifact:latency",
                    "dependency_ref": "artifact:dependency",
                    "event_order_ref": "artifact:event-order",
                },
            }
        )
    with pytest.raises(ValueError, match="proof_refs"):
        MeasurementRelationArtifact.from_json(
            {
                "artifact_id": "artifact:measurement",
                "checker_status": "pass",
                "proof_refs": ["proof:measurement"],
                "relation": {
                    "relation_id": "measurement:1",
                    "calibration_ref": "artifact:calibration",
                    "latency_ref": "artifact:latency",
                    "dependency_ref": "artifact:dependency",
                    "event_order_ref": "artifact:event-order",
                },
            }
        )
    with pytest.raises(ValueError, match="calibration_ref"):
        MeasurementRelationArtifact.from_json(
            {
                "artifact_id": "artifact:measurement",
                "checker_status": "pass",
                "proof_refs": ["artifact:proof"],
                "relation": {
                    "relation_id": "measurement:1",
                    "calibration_ref": "calibration:local",
                    "latency_ref": "artifact:latency",
                    "dependency_ref": "artifact:dependency",
                    "event_order_ref": "artifact:event-order",
                },
            }
        )

    rejected_transcript = completion_admission(
        {},
        {"interface_id": "completion:demo"},
        {
            "completion_status": "pass",
            "admission_source": "completion-contract:demo",
            "expiry": "unbounded",
            "uncertainty_model": "exact",
            "reference_digest": digest_bound,
            "checker_result": "pass",
            "checker_transcript_ref": {
                "proof_kind": "completion_admission",
                "checker_status": "fail",
                "artifact_ref": "artifact:completion-transcript",
            },
        },
    )
    assert not rejected_transcript.passed
    assert rejected_transcript.reason_refs[0].failure_code is FailureCode.COMPLETION_MISSING

    representation = RepresentationRelationArtifact.from_json(
        {
            "artifact_id": "artifact:representation",
            "checker_status": "pass",
            "relations": [
                {
                    "relation_id": "representation:1",
                    "operational_prefix": [{"temp": "70"}],
                    "represented_prefix": [{"temp": "70"}],
                    "proof_ref": "artifact:proof",
                }
            ],
        }
    )
    assert representation.relations[0].proof_ref == "artifact:proof"
    with pytest.raises(ValueError, match="checker_status"):
        RepresentationRelationArtifact.from_json(
            {
                "artifact_id": "artifact:representation",
                "relations": [
                    {
                        "relation_id": "representation:1",
                        "represented_prefix": [{"temp": "70"}],
                        "proof_ref": "artifact:proof",
                    }
                ],
            }
        )
    with pytest.raises(ValueError, match="relations"):
        RepresentationRelationArtifact.from_json(
            {
                "artifact_id": "artifact:representation",
                "checker_status": "pass",
                "relations": [],
            }
        )
    with pytest.raises(ValueError, match="represented_prefix"):
        RepresentationRelationArtifact.from_json(
            {
                "artifact_id": "artifact:representation",
                "checker_status": "pass",
                "relations": [
                    {
                        "relation_id": "representation:1",
                        "proof_ref": "artifact:proof",
                    }
                ],
            }
        )
    with pytest.raises(ValueError, match="proof_ref"):
        RepresentationRelationArtifact.from_json(
            {
                "artifact_id": "artifact:representation",
                "checker_status": "pass",
                "relations": [
                    {
                        "relation_id": "representation:1",
                        "represented_prefix": [{"temp": "70"}],
                        "proof_ref": "representation-proof:local",
                    }
                ],
            }
        )
    assert not validate_named_schema(
        {
            "artifact_id": "artifact:measurement",
            "checker_status": "pass",
            "proof_refs": ["proof:measurement"],
            "relation": {
                "relation_id": "measurement:1",
                "calibration_ref": "artifact:calibration",
                "latency_ref": "artifact:latency",
                "dependency_ref": "artifact:dependency",
                "event_order_ref": "artifact:event-order",
            },
        },
        "measurement-relation-artifact.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "artifact_id": "artifact:representation",
            "checker_status": "pass",
            "relations": [],
        },
        "representation-relation-artifact.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "artifact_id": "artifact:representation",
            "checker_status": "pass",
            "relations": [
                {
                    "relation_id": "representation:1",
                    "represented_prefix": [{"temp": "70"}],
                    "proof_ref": "representation-proof:local",
                }
            ],
        },
        "representation-relation-artifact.schema.json",
    ).passed

    kernel_proof = KernelProofArtifact.from_json(
        {
            "artifact_id": "artifact:kernel-proof",
            "checker_transcript_ref": "artifact:transcript",
            "witness_provenance_refs": ["artifact:witness"],
            "reason_ref_records": [
                {
                    "reason_id": "reason:kernel-proof",
                    "failure_code": "checker_unknown",
                    "layer": "represented",
                    "source_artifact": "artifact:kernel-proof",
                    "source_path": "/proof",
                    "message": "kernel proof provenance",
                    "digest": "sha256:kernel-reason",
                }
            ],
            "proof": {
                "backend_identity": "finite",
                "proof_kind": "finite-enumeration",
                "proof_status": "pass",
                "reason_refs": [
                    {
                        "reason_id": "reason:inline-kernel-proof",
                        "failure_code": "checker_unknown",
                        "layer": "represented",
                        "source_artifact": "artifact:kernel-proof",
                        "source_path": "/proof/reason_refs/0",
                        "message": "inline kernel proof provenance",
                        "digest": "sha256:inline-kernel-reason",
                    }
                ],
            },
        }
    )
    assert kernel_proof.proof_refs()[-1].proof_kind == "checker_transcript"
    assert kernel_proof.reason_ref_records[0].reason_id == "reason:kernel-proof"
    assert kernel_proof.proof.reason_refs == ("reason:inline-kernel-proof",)
    assert kernel_proof.proof.reason_ref_records[0].source_path == "/proof/reason_refs/0"
    kernel_proof_json = kernel_proof.proof.to_json()
    assert kernel_proof_json["reason_ref_records"][0]["reason_id"] == ("reason:inline-kernel-proof")
    assert validate_named_schema(
        {
            "backend_identity": "finite",
            "proof_kind": "finite-enumeration",
            "proof_status": "pass",
            "reason_ref_records": kernel_proof_json["reason_ref_records"],
        },
        "kernel-proof.schema.json",
    ).passed
    assert validate_named_schema(
        {
            "artifact_id": "artifact:kernel-proof",
            "checker_transcript_ref": "artifact:transcript",
            "proof": {
                "backend_identity": "finite",
                "proof_kind": "finite-enumeration",
                "proof_status": "pass",
            },
            "reason_ref_records": [ref.to_json() for ref in kernel_proof.reason_ref_records],
        },
        "kernel-proof-artifact.schema.json",
    ).passed
    no_transcript = KernelProofArtifact.from_json(
        {
            "artifact_id": "artifact:kernel-proof",
            "proof": {
                "backend_identity": "finite",
                "proof_kind": "finite-enumeration",
                "proof_status": "pass",
            },
        }
    )
    assert all(ref.proof_kind != "checker_transcript" for ref in no_transcript.proof_refs())
    with pytest.raises(ValueError, match="checker_transcript_ref"):
        KernelProofArtifact.from_json(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "checker:kernel",
                "proof": {
                    "backend_identity": "finite",
                    "proof_kind": "finite-enumeration",
                    "proof_status": "pass",
                },
            }
        )
    with pytest.raises(ValueError, match="inclusion_ref"):
        KernelProofArtifact.from_json(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:transcript",
                "proof": {
                    "backend_identity": "finite",
                    "proof_kind": "finite-enumeration",
                    "proof_status": "pass",
                    "inclusion_ref": "checker:inclusion",
                },
            }
        )
    assert not validate_named_schema(
        {
            "artifact_id": "artifact:kernel-proof",
            "checker_transcript_ref": "checker:kernel",
            "proof": {
                "backend_identity": "finite",
                "proof_kind": "finite-enumeration",
                "proof_status": "pass",
            },
        },
        "kernel-proof-artifact.schema.json",
    ).passed
    assert not validate_named_schema(
        {
            "backend_identity": "finite",
            "proof_kind": "finite-enumeration",
            "proof_status": "pass",
            "witness_refs": ["witness:local"],
        },
        "kernel-proof.schema.json",
    ).passed
    assert replay_trace.to_json()["protocol_records"][0]["record_id"] == "record:kernel"


def test_operational_proof_payload_rejects_symbolic_and_invalid_refs() -> None:
    proof_entry = _entry(
        {
            "status": "pass",
            "proof_kind": "operational-proof",
            "prefix_adjudication": "maybe",
            "nested": {"status": "pass", "proof_kind": "operational-proof"},
            "proof": {
                "status": "pass",
                "proof_kind": "operational-proof",
                "prefix_adjudication": "accept",
            },
        },
        ArtifactRole.OTHER,
        "artifact:bad-prefix-proof",
    )
    bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:proof-payload",
            "manifest": {
                "manifest_id": "manifest:proof-payload",
                "root_artifact_id": "artifact:bad-prefix-proof",
                "artifact_refs": [proof_entry["artifact_ref"]],
                "dependency_order": ["artifact:bad-prefix-proof"],
            },
            "artifacts": [proof_entry],
        }
    )
    assert _bound_artifact_or_digest_ref("artifact:proof")
    assert _bound_artifact_or_digest_ref("sha256:proof")
    assert not _bound_artifact_or_digest_ref("proof:local")
    assert _proof_payload_value(bundle, "proof:local", "prefix_adjudication") is None
    assert (
        _proof_payload_value(
            bundle,
            "artifact:bad-prefix-proof#/nested",
            "prefix_adjudication",
        )
        is None
    )
    assert (
        _proof_payload_value(
            bundle,
            "artifact:bad-prefix-proof#/proof",
            "prefix_adjudication",
        )
        == "accept"
    )

    symbolic = _operational_proof_content_failure(
        bundle,
        StatusContext.from_json(
            {
                "status_time": "2026-01-01T00:00:00Z",
                "observation_records": [{"prefix_adjudication_proof_ref": "proof:local"}],
            }
        ),
    )
    assert symbolic is not None
    assert symbolic.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    invalid = _operational_proof_content_failure(
        bundle,
        StatusContext.from_json(
            {
                "status_time": "2026-01-01T00:00:00Z",
                "observation_records": [
                    {"prefix_adjudication_proof_ref": "artifact:bad-prefix-proof"}
                ],
            }
        ),
    )
    assert invalid is not None
    assert invalid.failure_records[0].code is FailureCode.SCHEMA_INVALID


def test_artifact_bundle_stage_failures_and_conformance_case_dir(tmp_path: Path) -> None:
    empty = artifact_bundle_from_json(
        {"bundle_id": "empty", "manifest": {"manifest_id": "m", "root_artifact_id": "missing"}}
    )
    assert validate_artifact_bundle(empty).final_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )

    canonical_source = _artifact_bundle_source({"x": "1.2"})
    artifacts = canonical_source["artifacts"]
    assert isinstance(artifacts, list)
    artifacts[0]["artifact"] = {"x": 1.2}
    canonical = artifact_bundle_from_json(canonical_source)
    assert validate_artifact_bundle(canonical).final_result.failure_records[0].code is (
        FailureCode.CANONICALIZATION_MISMATCH
    )

    schema_source = _artifact_bundle_source({"bad": 1}, schema_name="artifact-ref.schema.json")
    schema_report = validate_artifact_bundle(artifact_bundle_from_json(schema_source))
    assert schema_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_kernel_proof = _artifact_bundle_source(
        {"artifact_id": "artifact:kernel-proof"},
        role=ArtifactRole.KERNEL_PROOF.value,
    )
    kernel_proof_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_kernel_proof))
    assert kernel_proof_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert kernel_proof_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_measurement = _artifact_bundle_source(
        {
            "artifact_id": "artifact:measurement",
            "checker_status": "pass",
        },
        role=ArtifactRole.MEASUREMENT_RELATION.value,
    )
    measurement_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_measurement))
    assert measurement_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert measurement_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_representation = _artifact_bundle_source(
        {
            "artifact_id": "artifact:representation",
            "checker_status": "pass",
            "relations": [{"relation_id": "r", "represented_prefix": []}],
        },
        role=ArtifactRole.REPRESENTATION_RELATION.value,
    )
    representation_report = validate_artifact_bundle(
        artifact_bundle_from_json(invalid_representation)
    )
    assert representation_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert representation_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_dependency_graph = _artifact_bundle_source(
        {"graph_id": "graph:deps", "vertices": ["a", "b"], "edges": [{"source": "a"}]},
        role=ArtifactRole.DEPENDENCY_GRAPH.value,
    )
    dependency_report = validate_artifact_bundle(
        artifact_bundle_from_json(invalid_dependency_graph)
    )
    assert dependency_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert dependency_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_guard = _artifact_bundle_source(
        {"guard_name": "clock_inside", "status": "maybe"},
        role=ArtifactRole.GUARD_RECORD.value,
    )
    guard_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_guard))
    assert guard_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert guard_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_prefix = _artifact_bundle_source(
        {"prefix_status": "out_of_frame", "r": 0, "p_star": [], "p_out": []},
        role=ArtifactRole.PREFIX_VIEW.value,
    )
    prefix_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_prefix))
    assert prefix_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert prefix_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_completion = _artifact_bundle_source(
        {"tag": "CompletionAdmission", "completion_status": "pass"},
        role=ArtifactRole.COMPLETION_ADMISSION.value,
    )
    completion_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_completion))
    assert completion_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert completion_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID
    unbound_completion = _artifact_bundle_source(
        {
            "tag": "CompletionAdmission",
            "completion_status": "pass",
            "admission_source": "completion-contract:test",
            "expiry": "unbounded",
            "uncertainty_model": "exact",
            "reference_digest": "sha256:completion",
            "checker_result": "pass",
            "checker_transcript_ref": "checker:completion",
        },
        role=ArtifactRole.COMPLETION_ADMISSION.value,
    )
    unbound_completion_report = validate_artifact_bundle(
        artifact_bundle_from_json(unbound_completion)
    )
    assert unbound_completion_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert unbound_completion_report.final_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )

    invalid_fiber = _artifact_bundle_source(
        {"fiber_status": "allowed"},
        role=ArtifactRole.FIBER_ASSOC_VIEW.value,
    )
    fiber_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_fiber))
    assert fiber_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert fiber_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_agreement = _artifact_bundle_source(
        {
            "kernel_direction": "positive",
            "assoc_direction": "positive",
            "frame_direction": "positive",
            "adequacy_direction": "positive",
            "blocking_set": [],
            "gate_decision": "allow",
        },
        role=ArtifactRole.AGREEMENT.value,
    )
    agreement_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_agreement))
    assert agreement_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert agreement_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_protocol_record = _artifact_bundle_source(
        {
            "record_id": "record:bad",
            "record_kind": "KernelView",
            "stage": "KernelCheck",
            "artifact_refs": [],
            "proof_refs": [],
        },
        role=ArtifactRole.PROTOCOL_RECORD.value,
    )
    protocol_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_protocol_record))
    assert protocol_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert protocol_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_replay_trace = _artifact_bundle_source(
        {"stage_traces": [], "protocol_records": []},
        role=ArtifactRole.REPLAY_TRACE.value,
    )
    replay_trace_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_replay_trace))
    assert replay_trace_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert replay_trace_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_stage_trace = _artifact_bundle_source(
        {
            "stage": "Replay",
            "status": "pass",
            "record_refs": [],
            "proof_refs": [],
            "blocking_records": [],
        },
        role=ArtifactRole.REPLAY_STAGE_TRACE.value,
    )
    stage_trace_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_stage_trace))
    assert stage_trace_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert stage_trace_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_pipeline_report = _artifact_bundle_source(
        {
            "bundle_id": "bundle:bad-report",
            "profile": "DFCC-Interop",
            "resolved_refs": [],
            "unresolved_refs": [],
            "ledger_entries": [],
            "artifact_refs": [],
            "proof_refs": [],
            "stage_artifacts": {},
            "protocol_records": [],
            "failure_records": [],
            "reason_refs": [],
            "stage_blockers": [],
        },
        role=ArtifactRole.PIPELINE_REPORT.value,
    )
    pipeline_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_pipeline_report))
    assert pipeline_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert pipeline_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_runtime = _artifact_bundle_source(
        {
            "compiled_bundle_ref": "compiled:bundle",
            "accepted_clause_refs": [],
            "artifact_refs": [],
            "ledger_entries": 0,
            "resolved_obligations": [],
            "resolved_reason_refs": [],
            "proof_refs": [],
            "strict_replay": "yes",
            "synthetic_trust": False,
        },
        role=ArtifactRole.RESOLVED_AUTHORITY_RUNTIME.value,
    )
    runtime_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_runtime))
    assert runtime_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert runtime_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    invalid_lifecycle_decision = _artifact_bundle_source(
        {
            "decision": "reject",
            "event_id": "evt",
            "dominant_status": "unknown",
            "blocking_set": [],
            "reason_refs": [],
        },
        role=ArtifactRole.LIFECYCLE_DECISION.value,
    )
    lifecycle_decision_report = validate_artifact_bundle(
        artifact_bundle_from_json(invalid_lifecycle_decision)
    )
    assert lifecycle_decision_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert lifecycle_decision_report.final_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )

    invalid_validation_result = _artifact_bundle_source(
        {
            "stage": "Parse",
            "status": "maybe",
            "failure_records": [],
            "artifact_refs": [],
            "reason_refs": [],
        },
        role=ArtifactRole.VALIDATION_RESULT.value,
    )
    validation_result_report = validate_artifact_bundle(
        artifact_bundle_from_json(invalid_validation_result)
    )
    assert validation_result_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert validation_result_report.final_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )
    canonicalization_result = validate_pipeline({"x": 1.2})
    assert isinstance(canonicalization_result, ValidationResult)
    assert validate_named_schema(
        to_jsonable(canonicalization_result), "validation-result.schema.json"
    ).passed

    valid_set = to_jsonable(set_ref("carrier", "finite", "constraint", "exact", "soundness"))
    bad_set_source = _artifact_bundle_source(
        {**valid_set, "digest": "sha256:bad"},
        role=ArtifactRole.SET.value,
    )
    bad_set_report = validate_artifact_bundle(artifact_bundle_from_json(bad_set_source))
    assert bad_set_report.final_result.stage is ValidationStage.DIGEST_CHECK
    assert bad_set_report.final_result.failure_records[0].code is FailureCode.DIGEST_MISMATCH

    valid_set_source = _artifact_bundle_source(valid_set, role=ArtifactRole.SET.value)
    assert validate_artifact_bundle(artifact_bundle_from_json(valid_set_source)).passed

    valid_scalar = {"decimal_string": "1.5", "unit_ref": "unit", "dimension_ref": "dimension"}
    valid_scalar_source = _artifact_bundle_source(
        valid_scalar,
        role=ArtifactRole.SCALAR_RECORD.value,
    )
    assert validate_artifact_bundle(artifact_bundle_from_json(valid_scalar_source)).passed

    invalid_scalar = _artifact_bundle_source(
        {"decimal_string": "not-decimal", "unit_ref": "unit", "dimension_ref": "dimension"},
        role=ArtifactRole.SCALAR_RECORD.value,
    )
    scalar_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_scalar))
    assert scalar_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert scalar_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    scalar_low = {"decimal_string": "2", "unit_ref": "unit", "dimension_ref": "dimension"}
    scalar_high = {"decimal_string": "1", "unit_ref": "unit", "dimension_ref": "dimension"}
    invalid_interval = _artifact_bundle_source(
        {
            "lower": scalar_low,
            "upper": scalar_high,
            "lower_closed": True,
            "upper_closed": True,
        },
        role=ArtifactRole.INTERVAL_RECORD.value,
    )
    interval_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_interval))
    assert interval_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert interval_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    valid_interval = _artifact_bundle_source(
        {
            "lower": valid_scalar,
            "upper": valid_scalar,
            "lower_closed": True,
            "upper_closed": True,
        },
        role=ArtifactRole.INTERVAL_RECORD.value,
    )
    assert validate_artifact_bundle(artifact_bundle_from_json(valid_interval)).passed

    invalid_timestamp = _artifact_bundle_source(
        {
            "lexical_time": "2026-01-01T00:00:00",
            "time_basis_ref": "utc",
            "time_scale": "UTC",
            "source": "test",
        },
        role=ArtifactRole.TIMESTAMP_RECORD.value,
    )
    timestamp_report = validate_artifact_bundle(artifact_bundle_from_json(invalid_timestamp))
    assert timestamp_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert timestamp_report.final_result.failure_records[0].code is (
        FailureCode.CLOCK_BOUNDARY_UNKNOWN
    )

    valid_timestamp = _artifact_bundle_source(
        {
            "lexical_time": "2026-01-01T00:00:00Z",
            "time_basis_ref": "utc",
            "time_scale": "UTC",
            "source": "test",
        },
        role=ArtifactRole.TIMESTAMP_RECORD.value,
    )
    assert validate_artifact_bundle(artifact_bundle_from_json(valid_timestamp)).passed

    digest_source = _artifact_bundle_source({"x": 1}, ref_override={"digest_value": "sha256:bad"})
    digest_report = validate_artifact_bundle(artifact_bundle_from_json(digest_source))
    assert digest_report.final_result.failure_records[0].code is FailureCode.DIGEST_MISMATCH

    missing_ref_source = _artifact_bundle_source({"x": 1}, reason_paths=("/missing",))
    missing_report = validate_artifact_bundle(artifact_bundle_from_json(missing_ref_source))
    assert missing_report.final_result.failure_records[0].code is FailureCode.MISSING_REF

    cases = tmp_path / "cases"
    cases.mkdir()
    (cases / "case.json").write_text(
        json.dumps(
            {
                "case_id": "external-bundle",
                "kind": "artifact-bundle",
                "suite": "legacy-interop",
                "canonical_equality_required": False,
                "full_replay": False,
                "bundle": _artifact_bundle_source({"x": {"y": "z"}}, reason_paths=("/x/y",)),
                "expected": "pass",
            }
        ),
        encoding="utf-8",
    )
    assert run_golden_cases(cases)[0].passed
    assert main(["conformance", "run", "--case-dir", str(cases)]) == 0

    strict_cases = tmp_path / "strict-cases"
    strict_cases.mkdir()
    (strict_cases / "case.json").write_text(
        json.dumps(
            {
                "case_id": "strict-external-bundle",
                "kind": "artifact-bundle",
                "bundle": _artifact_bundle_source({"x": {"y": "z"}}, reason_paths=("/x/y",)),
                "expected": "pass",
            }
        ),
        encoding="utf-8",
    )
    strict_result = run_golden_cases(strict_cases)[0]
    assert not strict_result.passed
    assert strict_result.expected == "expected_digest"
    assert strict_result.actual == "missing_expected_digest"
    assert strict_result.equality_key is not None
    assert main(["conformance", "run", "--case-dir", str(strict_cases)]) == 1

    replay_cases = tmp_path / "replay-cases"
    replay_cases.mkdir()
    (replay_cases / "case.json").write_text(
        json.dumps(
            {
                "case_id": "strict-replay-bundle",
                "kind": "artifact-bundle",
                "canonical_equality_required": False,
                "full_replay": True,
                "bundle": _artifact_bundle_source({"x": {"y": "z"}}, reason_paths=("/x/y",)),
                "expected": "pass",
            }
        ),
        encoding="utf-8",
    )
    replay_result = run_golden_cases(replay_cases)[0]
    assert not replay_result.passed
    assert replay_result.actual == FailureCode.MISSING_REF.value


def test_artifact_reference_policy_and_manifest_checks() -> None:
    ref = build_artifact_ref({"x": 1}, artifact_id="artifact:x", artifact_type="json")
    assert (
        validate_artifact_ref(
            ArtifactRef("bad-alg", "json", digest_algorithm="md5", digest_value="sha256:x")
        )
        .failure_records[0]
        .code
        is FailureCode.UNSUPPORTED_PROFILE
    )
    assert (
        validate_artifact_ref(
            ArtifactRef("bad-canon", "json", canonicalization="other", digest_value="sha256:x")
        )
        .failure_records[0]
        .code
        is FailureCode.CANONICALIZATION_MISMATCH
    )
    assert (
        validate_artifact_ref(
            ref,
            policy={"allowed_retrieval_policies": ("remote",)},
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        validate_artifact_ref(
            ArtifactRef("mutable", "json", digest_value="sha256:x", immutability_policy="mutable")
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        validate_artifact_ref(ArtifactRef("missing", "json")).failure_records[0].code
        is FailureCode.MISSING_REF
    )
    assert (
        validate_artifact_ref(
            ref,
            policy={"schema_digests": {"json": "sha256:expected"}},
        )
        .failure_records[0]
        .code
        is FailureCode.DIGEST_MISMATCH
    )
    assert (
        validate_artifact_ref(
            ref,
            policy={"canonicalization_digests": {ref.canonicalization: "sha256:expected"}},
        )
        .failure_records[0]
        .code
        is FailureCode.DIGEST_MISMATCH
    )
    assert (
        validate_artifact_ref(
            ArtifactRef("role", "json", digest_value="sha256:x", semantic_role="claim"),
            policy={"semantic_roles": {"role": "status"}},
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        validate_artifact_ref(
            ArtifactRef(
                "labels",
                "json",
                digest_value="sha256:x",
                provenance_refs=("a", "b"),
                dependency_labels=("depends-on",),
            )
        )
        .failure_records[0]
        .code
        is FailureCode.SCHEMA_INVALID
    )

    dep_a = ArtifactRef("a", "json", digest_value="sha256:a", provenance_refs=("b",))
    dep_b = ArtifactRef("b", "json", digest_value="sha256:b")
    assert (
        validate_manifest_dependencies(
            (dep_a, dep_b), root_artifact_id="a", dependency_order=("a", "b")
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert validate_manifest_dependencies(
        (dep_a, dep_b), root_artifact_id="a", dependency_order=("b", "a")
    ).passed

    store = ArtifactStore()
    store.add(ref, {"x": 1})
    conflict, value = resolve_reference(
        "artifact:x",
        "/x",
        store=store,
        context=ReferenceResolutionContext("snap", retrieval_policy="remote"),
    )
    assert conflict.status is ValidationStatus.CONFLICT
    assert value is None


def test_artifact_bundle_parser_manifest_and_stage_negative_paths() -> None:
    good = _artifact_bundle_source({"x": {"y": "z"}}, reason_paths=("/x/y",))
    bundle = artifact_bundle_from_json(good)
    store = bundle.store()
    assert store.get("artifact:reason") is not None
    bad_ref = ArtifactRef("bad", "json", digest_value="sha256:bad")
    with pytest.raises(ValueError, match="digest"):
        ArtifactStore().add(bad_ref, {"x": 1})

    with pytest.raises(TypeError):
        artifact_bundle_from_json({"bundle_id": "b", "manifest": {}, "artifacts": [1]})
    with pytest.raises(TypeError):
        artifact_bundle_from_json({"bundle_id": "b", "manifest": {}, "artifacts": [{}]})
    with pytest.raises(TypeError):
        artifact_bundle_from_json({"bundle_id": "b", "manifest": [], "artifacts": []})
    broken_ref_source = {
        **good,
        "manifest": {**dict(good["manifest"]), "artifact_refs": [1]},
    }
    with pytest.raises(TypeError):
        artifact_bundle_from_json(broken_ref_source)
    with pytest.raises(TypeError):
        artifact_bundle_from_json({**good, "reference_context": []})

    duplicate = dict(good)
    artifacts = list(good["artifacts"])  # type: ignore[arg-type]
    duplicate["artifacts"] = [artifacts[0], artifacts[0]]
    duplicate_report = validate_artifact_bundle(artifact_bundle_from_json(duplicate))
    assert duplicate_report.final_result.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT

    root_missing = {
        **good,
        "manifest": {**dict(good["manifest"]), "root_artifact_id": "missing"},
    }
    assert validate_artifact_bundle(
        artifact_bundle_from_json(root_missing)
    ).final_result.status is (ValidationStatus.INVALID_ARTIFACT)

    manifest_bad = {
        **good,
        "manifest": {**dict(good["manifest"]), "manifest_digest": "sha256:bad"},
    }
    assert (
        validate_artifact_bundle(artifact_bundle_from_json(manifest_bad))
        .final_result.failure_records[0]
        .code
        is FailureCode.DIGEST_MISMATCH
    )

    embedded_ref = _artifact_bundle_source(
        {
            "reason_refs": [
                "not-a-ref",
                {"source_artifact": "artifact:reason"},
                {"source_artifact": "artifact:reason", "source_path": "/target"},
            ],
            "target": {"ok": True},
        }
    )
    report = validate_artifact_bundle(artifact_bundle_from_json(embedded_ref))
    assert report.resolved_refs[0].source_path == "/target"

    unsupported_profile = validate_artifact_bundle(
        artifact_bundle_from_json(good), requested_profile="missing-profile"
    )
    assert unsupported_profile.final_result.failure_records[0].code is (
        FailureCode.UNSUPPORTED_PROFILE
    )


def test_artifact_bundle_replay_guard_kernel_and_authority_stage_paths() -> None:
    event = {
        "event_id": "evt",
        "certificate_id": "cert",
        "time": "2026-01-01T00:00:00Z",
        "logical_clock": 1,
        "kind": "mark-unknown",
    }
    replay_source = _artifact_bundle_source(event, role=ArtifactRole.LIFECYCLE_EVENT.value)
    replay_report = validate_artifact_bundle(artifact_bundle_from_json(replay_source))
    assert replay_report.final_result.failure_records[0].code is FailureCode.TRACE_CONFLICT

    invalid_event = {
        "event_id": "evt",
        "certificate_id": "cert",
        "time": "2026-01-01T00:00:00Z",
        "logical_clock": 1,
    }
    invalid_replay_source = _artifact_bundle_source(
        invalid_event,
        role=ArtifactRole.LIFECYCLE_EVENT.value,
    )
    invalid_replay = validate_artifact_bundle(artifact_bundle_from_json(invalid_replay_source))
    assert invalid_replay.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert invalid_replay.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    observation_bad = _artifact_bundle_source([], role=ArtifactRole.OBSERVATION.value)
    guard_report = validate_artifact_bundle(artifact_bundle_from_json(observation_bad))
    assert guard_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    observation_unknown = _artifact_bundle_source(
        {
            "records": [],
            "status_time": "2026-01-01T00:00:00Z",
            "time_basis_ref": "utc",
            "event_order_ref": "order",
            "dependency_snapshot": {},
            "frame": {},
        },
        role=ArtifactRole.OBSERVATION.value,
    )
    unknown_report = validate_artifact_bundle(artifact_bundle_from_json(observation_unknown))
    assert unknown_report.final_result.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    observation_missing_ref = _artifact_bundle_source(
        {
            "records": [],
            "status_time": "2026-01-01T00:00:00Z",
            "time_basis_ref": "utc",
            "dependency_snapshot": {},
            "frame": {},
        },
        role=ArtifactRole.OBSERVATION.value,
    )
    missing_ref_report = validate_artifact_bundle(
        artifact_bundle_from_json(observation_missing_ref)
    )
    assert missing_ref_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert missing_ref_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    claim_only = _artifact_bundle_source(_claim(), role=ArtifactRole.CLAIM.value)
    assert validate_artifact_bundle(artifact_bundle_from_json(claim_only)).final_result.status is (
        ValidationStatus.UNKNOWN
    )

    status_bad = _artifact_bundle_source([], role=ArtifactRole.STATUS.value)
    assert validate_artifact_bundle(artifact_bundle_from_json(status_bad)).final_result.status is (
        ValidationStatus.INVALID_ARTIFACT
    )
    proposed_bad = _artifact_bundle_source(
        {"mode": "assertion", "claim": "safe-temp", "horizon": "1", "anchor": "anchor:issue"},
        role=ArtifactRole.PROPOSED_USE.value,
    )
    proposed_report = validate_artifact_bundle(artifact_bundle_from_json(proposed_bad))
    assert proposed_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert proposed_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    status_context_bad = _artifact_bundle_source(
        {"event_log": []},
        role=ArtifactRole.STATUS_CONTEXT.value,
    )
    status_context_report = validate_artifact_bundle(artifact_bundle_from_json(status_context_bad))
    assert status_context_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert status_context_report.final_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )

    status_unknown = _artifact_bundle_source(
        {"authority_outcome": {"code": "unknown"}},
        role=ArtifactRole.STATUS.value,
    )
    assert (
        validate_artifact_bundle(artifact_bundle_from_json(status_unknown))
        .final_result.failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )


def test_checker_contract_evidence_paths() -> None:
    checker = ReferenceChecker()
    ref = build_artifact_ref({"x": 1}, artifact_id="artifact:x", artifact_type="json")
    body = {"artifact_type": "manifest", "payload": {"x": 1}}
    expected = manifest_digest(
        body,
        artifact_type="manifest",
        schema_profile_digest="profile",
        dependencies=(ref,),
    )
    assert checker.manifest_digest({**body, "manifest_digest": expected}, "profile", (ref,)).passed
    assert (
        checker.manifest_digest({**body, "manifest_digest": "sha256:bad"}, "profile", (ref,))
        .failure_records[0]
        .code
        is FailureCode.DIGEST_MISMATCH
    )
    same_digest_different_id = ArtifactRef(
        "artifact:y",
        "json",
        digest_value=ref.digest_value,
        semantic_role=ref.semantic_role,
        schema_digest=ref.schema_digest,
        canonicalization_digest=ref.canonicalization_digest,
    )
    same_digest_different_role = ArtifactRef(
        ref.artifact_id,
        ref.artifact_type,
        digest_value=ref.digest_value,
        semantic_role="reason",
        schema_digest=ref.schema_digest,
        canonicalization_digest=ref.canonicalization_digest,
    )
    assert (
        manifest_digest(
            body,
            artifact_type="manifest",
            schema_profile_digest="profile",
            dependencies=(same_digest_different_id,),
        )
        != expected
    )
    assert (
        manifest_digest(
            body,
            artifact_type="manifest",
            schema_profile_digest="profile",
            dependencies=(same_digest_different_role,),
        )
        != expected
    )

    store = ArtifactStore()
    store.add(ref, {"x": 1})
    assert checker.reference_resolution(
        {"artifact_id": "artifact:x", "pointer": "/x", "store": store},
        ReferenceResolutionContext("snap"),
    ).passed

    event = {
        "event_id": "evt",
        "certificate_id": "cert",
        "time": "2026-01-01T00:00:00Z",
        "logical_clock": 1,
        "kind": "mark-unknown",
    }
    assert checker.event_order((event,), {"accepted_event_ids": ("evt",)}, {}).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.event_order(
        (event,),
        {
            "accepted_event_ids": ("evt",),
            "event_order_proof_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:event-order-proof",
                "proof_kind": "event_order",
                "artifact_digest": "sha256:event-order-proof",
            },
        },
        {},
    ).passed
    cut_payload = {
        "status_time": "now",
        "time_basis": "utc",
        "event_order": "order",
        "frame_id": "f",
    }
    accepted_record = (
        {
            "calibration_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:calibration-test",
                "proof_kind": "calibration",
                "artifact_digest": "sha256:calibration",
                "payload": cut_payload,
            },
            "latency_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:latency-test",
                "proof_kind": "latency",
                "artifact_digest": "sha256:latency",
                "payload": cut_payload,
            },
            "dependency_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:dependency-test",
                "proof_kind": "dependency",
                "artifact_digest": "sha256:dependency",
                "payload": cut_payload,
            },
            "event_order_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:event-order-test",
                "proof_kind": "event_order",
                "artifact_digest": "sha256:event-order",
                "payload": cut_payload,
            },
        },
    )
    assert checker.observation_cut(
        accepted_record, "now", "utc", "order", {}, {"frame_id": "f"}
    ).passed
    shallow_measurement_record = (
        {
            key: {
                item_key: item_value
                for item_key, item_value in value.items()
                if item_key != "payload"
            }
            for key, value in accepted_record[0].items()
        },
    )
    assert (
        checker.observation_cut(
            shallow_measurement_record,
            "now",
            "utc",
            "order",
            {},
            {"frame_id": "f"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    conflicting_measurement_record = (
        {
            **accepted_record[0],
            "latency_ref": {
                **accepted_record[0]["latency_ref"],
                "payload": {**cut_payload, "event_order": "other-order"},
            },
        },
    )
    assert (
        checker.observation_cut(
            conflicting_measurement_record,
            "now",
            "utc",
            "order",
            {},
            {"frame_id": "f"},
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.observation_cut(None, None, None, None, {}, {}).status is (
        ValidationStatus.UNKNOWN
    )
    assert (
        checker.status_observation_context(
            None,
            type("CutWithPrefix", (), {"prefix_view": object()})(),
            {
                "r": 0,
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:status-observation-context-transcript",
                    "proof_kind": "status_observation_context",
                },
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.status_observation_context(
        None,
        type("CutWithPrefix", (), {"prefix_view": object()})(),
        {
            "r": 0,
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:status-observation-context-transcript",
                "proof_kind": "status_observation_context",
                "artifact_digest": "sha256:status-observation-context",
                "payload": {"r": 0},
            },
        },
    ).passed
    cut_with_coordinates = type(
        "CutWithCoordinates",
        (),
        {
            "prefix_view": object(),
            "status_time": "2026-01-01T00:00:00Z",
            "time_basis_ref": "clock:utc",
            "event_order_ref": "event-order:accepted",
            "frame_id": "frame:temperature",
        },
    )()
    assert checker.status_observation_context(
        None,
        cut_with_coordinates,
        {
            "r": 0,
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:status-observation-context-transcript",
                "proof_kind": "status_observation_context",
                "artifact_digest": "sha256:status-observation-context",
                "payload": {
                    "r": 0,
                    "status_time": "2026-01-01T00:00:00Z",
                    "time_basis_ref": "clock:utc",
                    "event_order_ref": "event-order:accepted",
                    "frame_id": "frame:temperature",
                },
            },
        },
    ).passed
    assert (
        checker.status_observation_context(
            None,
            cut_with_coordinates,
            {
                "r": 0,
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:status-observation-context-transcript",
                    "proof_kind": "status_observation_context",
                    "artifact_digest": "sha256:status-observation-context",
                    "payload": {"r": 0},
                },
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.status_observation_context(
            None,
            cut_with_coordinates,
            {
                "r": 0,
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:status-observation-context-transcript",
                    "proof_kind": "status_observation_context",
                    "artifact_digest": "sha256:status-observation-context",
                    "payload": {
                        "r": 0,
                        "status_time": "2026-01-01T00:00:00Z",
                        "time_basis_ref": "clock:utc",
                        "event_order_ref": "event-order:accepted",
                        "frame_id": "frame:other",
                    },
                },
            },
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.status_confluence((), (("a",), ("b",)), EventOrder()).status is (
        ValidationStatus.CONFLICT
    )
    assert (
        checker.status_confluence((), (("a",), ("b",)), EventOrder(confluence_proof="proof")).status
        is ValidationStatus.CONFLICT
    )
    assert checker.status_confluence(
        (),
        (("a",), ("b",)),
        EventOrder(
            confluence_proof={
                "proof_status": "accepted",
                "artifact_ref": "artifact:confluence-proof",
                "proof_kind": "confluence",
                "artifact_digest": "sha256:confluence-proof",
                "payload": {"blocking_sets": [["a"], ["b"]]},
            }
        ),
    ).passed
    assert (
        checker.status_confluence(
            (),
            (("a",), ("b",)),
            EventOrder(
                confluence_proof={
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:confluence-proof",
                    "proof_kind": "confluence",
                    "artifact_digest": "sha256:confluence-proof",
                    "payload": {"blocking_sets": [["a"], ["other"]]},
                }
            ),
        )
        .failure_records[0]
        .code
        is FailureCode.TRACE_CONFLICT
    )
    assert (
        checker.status_confluence(
            (),
            (("a",), ("b",)),
            EventOrder(
                confluence_proof={
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-confluence-proof",
                    "proof_kind": "schema_validation",
                }
            ),
        )
        .failure_records[0]
        .code
        is FailureCode.TRACE_CONFLICT
    )
    malformed = checker.event_order(({"event_id": "evt"},), {}, {})
    assert malformed.failure_records[0].code is FailureCode.SCHEMA_INVALID
    conflict = checker.event_order(
        (
            {
                "event_id": "evt",
                "certificate_id": "cert",
                "time": "2026-01-01T00:00:00Z",
                "logical_clock": 1,
                "kind": "mark-unknown",
            },
        ),
        {},
        {"log_root": "missing"},
    )
    assert conflict.failure_records[0].code is FailureCode.TRACE_CONFLICT


def test_reference_checker_requires_accepted_checker_evidence() -> None:
    checker = ReferenceChecker()
    assert not checker._accepted_field([], "missing")
    assert not checker._typed_reason_ref({"source_artifact": "reason", "source_path": "relative"})
    assert not checker._typed_reason_ref(
        {
            "source_artifact": "artifact:reason",
            "source_path": "/reason",
            "digest": "sha256:reason",
        }
    )
    assert not checker._typed_reason_ref(
        {
            "reason_id": "reason:missing-code",
            "layer": "interop",
            "source_artifact": "artifact:reason",
            "source_path": "/reason",
            "message": "missing failure code",
            "digest": "sha256:reason",
        }
    )
    typed_reason = {
        "reason_id": "reason:block",
        "failure_code": "checker_unknown",
        "layer": "interop",
        "source_artifact": "artifact:reason",
        "source_path": "/reason",
        "message": "blocking reason",
        "digest": "sha256:reason",
    }
    assert not checker._typed_blocking_record(
        {
            "block_id": "block:missing-ids",
            "failure_code": "checker_unknown",
            "layer": "interop",
            "severity": "error",
            "reason_ref_records": [typed_reason],
        }
    )
    assert not checker._typed_blocking_record(
        {
            "block_id": "block:mismatch",
            "failure_code": "checker_unknown",
            "layer": "interop",
            "severity": "error",
            "reason_refs": ["reason:other"],
            "reason_ref_records": [typed_reason],
        }
    )
    assert checker.schema({"schema_validation_ref": "checker:schema"}).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.schema({"schema_validation_ref": {}}).status is ValidationStatus.UNKNOWN
    assert checker.schema({"schema_validation_ref": {"checker_status": "fail"}}).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.schema({"schema_validation_ref": {"checker_status": "pass"}}).status is (
        ValidationStatus.UNKNOWN
    )
    assert (
        checker.schema(
            {
                "schema_validation_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "checker:schema",
                    "proof_kind": "schema_validation",
                }
            }
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.schema(
            {
                "schema_validation_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:schema-validation-transcript",
                    "proof_kind": "reason_path",
                }
            }
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.schema(
            {
                "schema_validation_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:schema-validation-transcript",
                    "proof_kind": "schema_validation",
                }
            }
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.schema(
            {
                "schema_validation_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:schema-validation-transcript",
                    "proof_kind": "schema_validation",
                    "artifact_digest": "sha256:schema-validation",
                }
            }
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.schema(
        {
            "schema_profile_ref": "DFCC-Core",
            "canonicalization_profile_ref": "rfc8785-jcs",
            "schema_validation_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:schema-validation-transcript",
                "proof_kind": "schema_validation",
                "artifact_digest": "sha256:schema-validation",
                "payload": {
                    "target_schema_profile": "DFCC-Core",
                    "target_canonicalization_profile": "rfc8785-jcs",
                },
            },
        }
    ).passed
    assert (
        checker.schema(
            {
                "artifact_id": "artifact:issue",
                "schema_name": "issue-certificate.schema.json",
                "schema_validation_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:schema-validation-transcript",
                    "proof_kind": "schema_validation",
                    "artifact_digest": "sha256:schema-validation",
                },
            }
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.schema(
            {
                "artifact_id": "artifact:issue",
                "schema_name": "issue-certificate.schema.json",
                "schema_validation_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:schema-validation-transcript",
                    "proof_kind": "schema_validation",
                    "artifact_digest": "sha256:schema-validation",
                    "payload": {
                        "target_artifact_id": "artifact:other",
                        "target_schema": "issue-certificate.schema.json",
                    },
                },
            }
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.schema(
        {
            "artifact_id": "artifact:issue",
            "schema_name": "issue-certificate.schema.json",
            "schema_validation_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:schema-validation-transcript",
                "proof_kind": "schema_validation",
                "artifact_digest": "sha256:schema-validation",
                "payload": {
                    "target_artifact_id": "artifact:issue",
                    "target_schema": "issue-certificate.schema.json",
                },
            },
        }
    ).passed
    assert (
        checker.reason_path(
            {
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:reason-path-transcript",
                    "proof_kind": "schema_validation",
                }
            },
            "/reason",
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.reason_path(
            {
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:reason-path-transcript",
                    "proof_kind": "reason_path",
                }
            },
            "/reason",
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.reason_path(
            {
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:reason-path-transcript",
                    "proof_kind": "reason_path",
                    "artifact_digest": "sha256:reason-path",
                }
            },
            "/reason",
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.reason_path(
            {
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:reason-path-transcript",
                    "proof_kind": "reason_path",
                    "artifact_digest": "sha256:reason-path",
                    "payload": {"json_pointer": "/other"},
                }
            },
            "/reason",
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.reason_path(
        {
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:reason-path-transcript",
                "proof_kind": "reason_path",
                "artifact_digest": "sha256:reason-path",
                "payload": {"json_pointer": "/reason"},
            }
        },
        "/reason",
    ).passed
    assert (
        checker.assessment_frame(
            {"frame_id": "frame", "checker_transcript_ref": {"checker_status": "pass"}}
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.assessment_frame(
            {
                "frame_id": "frame",
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "checker:frame",
                    "proof_kind": "assessment_frame",
                },
            }
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.assessment_frame(
            {
                "frame_id": "frame",
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:assessment-frame-transcript",
                    "proof_kind": "reason_path",
                },
            }
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.assessment_frame(
            {
                "frame_id": "frame",
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:assessment-frame-transcript",
                    "proof_kind": "assessment_frame",
                },
            }
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.assessment_frame(
            {
                "frame_id": "frame",
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:assessment-frame-transcript",
                    "proof_kind": "assessment_frame",
                    "artifact_digest": "sha256:assessment-frame",
                    "payload": {"target_frame_id": "other-frame"},
                },
            }
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.assessment_frame(
        {
            "frame_id": "frame",
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:assessment-frame-transcript",
                "proof_kind": "assessment_frame",
                "artifact_digest": "sha256:assessment-frame",
                "payload": {"target_frame_id": "frame"},
            },
        }
    ).passed
    assert (
        checker.initial_context(
            {
                "bundle_id": "bundle",
                "admissions": [
                    {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:not-initial-context",
                        "proof_kind": "schema_validation",
                    }
                ],
            },
            {"horizon": 1},
            {"frame_id": "frame"},
            {},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.initial_context(
            {
                "bundle_id": "bundle",
                "admissions": [
                    {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:accepted-admission",
                        "proof_kind": "admission",
                    }
                ],
            },
            {"horizon": 1},
            {"frame_id": "frame"},
            {},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.initial_context(
            {
                "bundle_id": "bundle",
                "admissions": [
                    {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:accepted-admission",
                        "proof_kind": "admission",
                        "artifact_digest": "sha256:accepted-admission",
                    }
                ],
            },
            {"horizon": 1},
            {"frame_id": "frame"},
            {},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.initial_context(
        {
            "bundle_id": "bundle",
            "admissions": [
                {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:accepted-admission",
                    "proof_kind": "admission",
                    "artifact_digest": "sha256:accepted-admission",
                    "payload": {
                        "bundle_id": "bundle",
                        "horizon": 1,
                        "frame_id": "frame",
                    },
                }
            ],
        },
        {"horizon": 1},
        {"frame_id": "frame"},
        {},
    ).passed

    accepted_proof_record = (
        {
            "observation_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:observation-proof",
                "proof_kind": "observation_cut",
                "artifact_digest": "sha256:observation-cut",
                "payload": {
                    "status_time": "2026-01-01T00:00:00Z",
                    "time_basis": "utc",
                    "event_order": "event-order",
                    "frame_id": "frame",
                },
            }
        },
    )
    shallow_proof_record = (
        {
            "observation_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:observation-proof",
                "proof_kind": "observation_cut",
            }
        },
    )
    assert (
        checker.observation_cut(
            shallow_proof_record,
            "2026-01-01T00:00:00Z",
            "utc",
            "event-order",
            {},
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    conflicting_proof_record = (
        {
            "observation_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:observation-proof",
                "proof_kind": "observation_cut",
                "artifact_digest": "sha256:observation-cut",
                "payload": {
                    "status_time": "2026-01-01T00:00:00Z",
                    "time_basis": "utc",
                    "event_order": "other-event-order",
                    "frame_id": "frame",
                },
            }
        },
    )
    assert (
        checker.observation_cut(
            conflicting_proof_record,
            "2026-01-01T00:00:00Z",
            "utc",
            "event-order",
            {},
            {"frame_id": "frame"},
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.observation_cut(
        accepted_proof_record,
        "2026-01-01T00:00:00Z",
        "utc",
        "event-order",
        {},
        {"frame_id": "frame"},
    ).passed
    assert (
        checker.representation_interface(
            {"representation_interface": {"projection_coherence": True}},
            {"frame_id": "frame"},
            {},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.representation_interface(
        {
            "representation_interface": {
                "projection_coherence": True,
                "projection_coherence_proof_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:projection-coherence-proof",
                    "proof_kind": "projection_coherence",
                    "artifact_digest": "sha256:projection-coherence-proof",
                },
            }
        },
        {"frame_id": "frame"},
        {},
    ).passed
    assert (
        checker.representation_interface(
            {
                "representation_interface": {
                    "projection_coherence": True,
                    "projection_coherence_proof_ref": {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:projection-coherence-proof",
                        "proof_kind": "latency",
                        "artifact_digest": "sha256:projection-coherence-proof",
                    },
                }
            },
            {"frame_id": "frame"},
            {},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.observation_cut(
            (1,),
            "2026-01-01T00:00:00Z",
            "utc",
            "event-order",
            {},
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    unbound_measurement_record = (
        {
            "calibration_ref": {"checker_status": "pass"},
            "latency_ref": {"checker_status": "pass", "artifact_ref": "artifact:latency"},
            "dependency_ref": {"checker_status": "pass", "artifact_ref": "artifact:dependency"},
            "event_order_ref": {"checker_status": "pass", "artifact_ref": "artifact:event-order"},
        },
    )
    assert (
        checker.observation_cut(
            unbound_measurement_record,
            "2026-01-01T00:00:00Z",
            "utc",
            "event-order",
            {},
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    wrong_kind_measurement_record = (
        {
            "calibration_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:calibration",
                "proof_kind": "latency",
            },
            "latency_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:latency",
                "proof_kind": "latency",
            },
            "dependency_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:dependency",
                "proof_kind": "dependency",
            },
            "event_order_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:event-order",
                "proof_kind": "event_order",
            },
        },
    )
    assert (
        checker.observation_cut(
            wrong_kind_measurement_record,
            "2026-01-01T00:00:00Z",
            "utc",
            "event-order",
            {},
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.status_observation_context(
            None,
            type("CutWithPrefix", (), {"prefix_view": object()})(),
            {"r": 0, "checker_transcript_ref": "checker:status-observation-context"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.status_observation_context(
            None,
            type("CutWithPrefix", (), {"prefix_view": object()})(),
            {
                "r": 0,
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:status-observation-context-transcript",
                    "proof_kind": "reason_path",
                },
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.status_observation_context(
            None,
            type("CutWithPrefix", (), {"prefix_view": object()})(),
            {
                "r": 0,
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:status-observation-context-transcript",
                    "proof_kind": "status_observation_context",
                    "artifact_digest": "sha256:status-observation-context",
                },
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.status_observation_context(
            None,
            type("CutWithPrefix", (), {"prefix_view": object()})(),
            {
                "r": 0,
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:status-observation-context-transcript",
                    "proof_kind": "status_observation_context",
                    "artifact_digest": "sha256:status-observation-context",
                    "payload": {"r": 1},
                },
            },
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    prefix_admission_cut = make_observation_cut(
        (
            {
                "r": 0,
                "represented_prefix": [{"temp": "70"}],
                "representation_proof_ref": "artifact:representation-proof",
                "prefix_admission_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:prefix-admission-proof",
                    "proof_kind": "prefix_admission",
                    "artifact_digest": "sha256:prefix-admission-proof",
                },
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "event-order",
        {},
        {"frame_id": "frame"},
        {},
    )
    assert checker.prefix_admission(prefix_admission_cut, {}, {}).passed
    wrong_prefix_admission_cut = make_observation_cut(
        (
            {
                "r": 0,
                "represented_prefix": [{"temp": "70"}],
                "representation_proof_ref": "artifact:representation-proof",
                "prefix_admission_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-prefix-admission-proof",
                    "proof_kind": "prefix_adjudication",
                },
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "event-order",
        {},
        {"frame_id": "frame"},
        {},
    )
    assert checker.prefix_admission(wrong_prefix_admission_cut, {}, {}).status is (
        ValidationStatus.UNKNOWN
    )
    assert (
        checker.prefix_adjudication({"prefix_adjudication": "accept"}, {"frame_id": "frame"}).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.prefix_adjudication(
        {
            "prefix_adjudication": "accept",
            "prefix_adjudication_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:prefix-proof",
                "proof_kind": "prefix_adjudication",
                "artifact_digest": "sha256:prefix-proof",
                "payload": {"prefix_adjudication": "accept", "frame_id": "frame"},
            },
        },
        {"frame_id": "frame"},
    ).passed
    assert (
        checker.prefix_adjudication(
            {
                "prefix_adjudication": "accept",
                "prefix_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:prefix-proof",
                    "proof_kind": "prefix_adjudication",
                    "artifact_digest": "sha256:prefix-proof",
                    "payload": {"prefix_adjudication": "accept", "frame_id": "other-frame"},
                },
            },
            {"frame_id": "frame"},
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.prefix_adjudication(
            {
                "prefix_adjudication": "accept",
                "prefix_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:prefix-proof",
                    "proof_kind": "prefix_adjudication",
                    "artifact_digest": "sha256:prefix-proof",
                },
            },
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.prefix_adjudication(
            {
                "prefix_adjudication": "accept",
                "prefix_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:prefix-proof",
                    "proof_kind": "prefix_adjudication",
                    "artifact_digest": "sha256:prefix-proof",
                    "payload": {"prefix_adjudication": "reject"},
                },
            },
            {"frame_id": "frame"},
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.prefix_adjudication(
            {
                "prefix_adjudication": "accept",
                "prefix_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-prefix-proof",
                    "proof_kind": "target_adjudication",
                },
            },
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.usage_adjudication(
            {"mode": "assertion"},
            {"frame_id": "frame"},
            {
                "usage_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-usage-proof",
                    "proof_kind": "prefix_adjudication",
                }
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.usage_adjudication(
        {"mode": "assertion"},
        {"frame_id": "frame"},
        {
            "usage_adjudication_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:usage-proof",
                "proof_kind": "usage_adjudication",
                "artifact_digest": "sha256:usage-proof",
                "payload": {
                    "usage_adjudication": "accept",
                    "mode": "assertion",
                    "frame_id": "frame",
                },
            }
        },
    ).passed
    assert checker.usage_adjudication(
        {
            "mode": "assertion",
            "usage_adjudication_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:usage-proof",
                "proof_kind": "usage_adjudication",
                "artifact_digest": "sha256:usage-proof",
                "payload": {
                    "usage_adjudication": "accept",
                    "mode": "assertion",
                    "frame_id": "frame",
                },
            },
        },
        {"frame_id": "frame"},
        {},
    ).passed
    assert (
        checker.usage_adjudication(
            {"mode": "assertion"},
            {"frame_id": "frame"},
            {
                "usage_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:usage-proof",
                    "proof_kind": "usage_adjudication",
                    "artifact_digest": "sha256:usage-proof",
                    "payload": {
                        "usage_adjudication": "accept",
                        "mode": "different",
                        "frame_id": "frame",
                    },
                }
            },
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.target_adjudication(
            {"target_adjudication": "accept"},
            {},
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.target_adjudication(
        {
            "target_adjudication": "reject",
            "target_adjudication_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:target-proof",
                "proof_kind": "target_adjudication",
                "artifact_digest": "sha256:target-proof",
                "payload": {"target_adjudication": "reject", "frame_id": "frame"},
            },
        },
        {},
        {"frame_id": "frame"},
    ).passed
    assert checker.target_adjudication(
        {
            "target_adjudication": "reject",
            "target_adjudication_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:target-proof",
                "proof_kind": "target_adjudication",
                "artifact_digest": "sha256:target-proof",
                "payload": {
                    "target_adjudication": "reject",
                    "frame_id": "frame",
                    "target_id": "target:safe",
                },
            },
        },
        {"target_id": "target:safe"},
        {"frame_id": "frame"},
    ).passed
    assert (
        checker.target_adjudication(
            {
                "target_adjudication": "reject",
                "target_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:target-proof",
                    "proof_kind": "target_adjudication",
                    "artifact_digest": "sha256:target-proof",
                    "payload": {
                        "target_adjudication": "reject",
                        "frame_id": "frame",
                        "target_id": "target:other",
                    },
                },
            },
            {"target_id": "target:safe"},
            {"frame_id": "frame"},
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.target_adjudication(
            {
                "target_adjudication": "reject",
                "target_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:target-proof",
                    "proof_kind": "target_adjudication",
                    "artifact_digest": "sha256:target-proof",
                },
            },
            {},
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.target_adjudication(
            {
                "target_adjudication": "reject",
                "target_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:target-proof",
                    "proof_kind": "target_adjudication",
                    "artifact_digest": "sha256:target-proof",
                    "payload": {"target_adjudication": "accept"},
                },
            },
            {},
            {"frame_id": "frame"},
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.target_adjudication(
            {
                "target_adjudication": "reject",
                "target_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-target-proof",
                    "proof_kind": "prefix_adjudication",
                },
            },
            {},
            {"frame_id": "frame"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.frame_adequacy(
            object(),
            {},
            {"frame_id": "frame", "policy": {"adequacy_direction": "positive"}},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.frame_adequacy(
        object(),
        {},
        {
            "frame_id": "frame",
            "adequacy_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:adequacy-proof",
                "proof_kind": "frame_adequacy",
                "artifact_digest": "sha256:adequacy-proof",
                "payload": {"adequacy_direction": "positive", "frame_id": "frame"},
            },
            "policy": {"adequacy_direction": "positive"},
        },
    ).passed
    assert checker.frame_adequacy(
        object(),
        {},
        {
            "frame_id": "frame",
            "policy": {
                "adequacy_direction": "positive",
                "adequacy_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:adequacy-proof",
                    "proof_kind": "frame_adequacy",
                    "artifact_digest": "sha256:adequacy-proof",
                    "payload": {"adequacy_direction": "positive", "frame_id": "frame"},
                },
            },
        },
    ).passed
    assert (
        checker.frame_adequacy(
            object(),
            {},
            {
                "frame_id": "frame",
                "policy": {
                    "adequacy_direction": "positive",
                    "adequacy_proof_ref": {
                        "proof_status": "accepted",
                        "artifact_ref": "artifact:adequacy-proof",
                        "proof_kind": "frame_adequacy",
                        "artifact_digest": "sha256:adequacy-proof",
                        "payload": {"adequacy_direction": "positive", "frame_id": "other-frame"},
                    },
                },
            },
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.frame_adequacy(
            object(),
            {},
            {
                "frame_id": "frame",
                "policy": {
                    "adequacy_direction": "positive",
                    "adequacy_proof_ref": {
                        "proof_status": "accepted",
                        "artifact_ref": "artifact:adequacy-proof",
                        "proof_kind": "frame_adequacy",
                        "artifact_digest": "sha256:adequacy-proof",
                    },
                },
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.frame_adequacy(
            object(),
            {},
            {
                "frame_id": "frame",
                "policy": {
                    "adequacy_direction": "positive",
                    "adequacy_proof_ref": {
                        "proof_status": "accepted",
                        "artifact_ref": "artifact:adequacy-proof",
                        "proof_kind": "frame_adequacy",
                        "artifact_digest": "sha256:adequacy-proof",
                        "payload": {"adequacy_direction": "negative"},
                    },
                },
            },
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.frame_adequacy(
            object(),
            {},
            {
                "frame_id": "frame",
                "policy": {
                    "adequacy_direction": "positive",
                    "adequacy_proof_ref": {
                        "proof_status": "accepted",
                        "artifact_ref": "artifact:not-adequacy-proof",
                        "proof_kind": "target_adjudication",
                    },
                },
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.event_order((), {}, {}).status is ValidationStatus.UNKNOWN
    assert checker.time_basis({}, None).failure_records[0].code is (
        FailureCode.CLOCK_BOUNDARY_UNKNOWN
    )
    valid_clock = {"clock_id": "utc", "uncertainty_seconds": "0", "source": "clock:lab"}
    missing_clock_proof = checker.time_basis(valid_clock, None)
    assert missing_clock_proof.status is ValidationStatus.UNKNOWN
    assert missing_clock_proof.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    clock_proof = {
        "proof_status": "accepted",
        "proof_kind": "time_basis",
        "artifact_digest": "sha256:time-basis",
        "payload": {
            "clock_id": "utc",
            "time_scale": "UTC",
            "uncertainty_seconds": "0",
            "source": "clock:lab",
        },
    }
    assert checker.time_basis({**valid_clock, "checker_transcript_ref": clock_proof}, None).passed
    policy_proof = {"time_basis_proof_ref": clock_proof}
    assert checker.time_basis(valid_clock, policy_proof).passed
    conflicting_clock_proof = {
        **clock_proof,
        "payload": {**clock_proof["payload"], "clock_id": "tai"},
    }
    assert (
        checker.time_basis(
            {**valid_clock, "checker_transcript_ref": conflicting_clock_proof},
            None,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.manifest_digest("not-a-manifest", "profile", ()).status is (
        ValidationStatus.UNKNOWN
    )
    assert (
        checker.reference_resolution(
            {"store": object(), "artifact_id": "artifact:x", "pointer": "/x"},
            ReferenceResolutionContext("snap"),
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.admission(
            {"artifact_id": "evidence:accepted", "kind": "finite-model", "checker_status": "pass"},
            {
                "kind": "finite-model",
                "source": "evidence:accepted",
                "target": "semantics",
                "clause": {},
                "checker_transcript_ref": "artifact:accepted-transcript",
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.admission(
        {"artifact_id": "evidence:accepted", "kind": "finite-model", "checker_status": "pass"},
        {
            "kind": "finite-model",
            "source": "evidence:accepted",
            "target": "semantics",
            "clause": {},
            "checker_transcript_ref": "artifact:accepted-transcript#/transcript",
        },
    ).passed

    assert checker.agreement(
        type("KernelLike", (), {"direction": "positive"})(),
        type("FiberLike", (), {"fiber_status": "positive"})(),
        {
            "prefix": "accept",
            "usage": "accept",
            "target": "accept",
            "agreement_proof_ref": {
                "proof_status": "pass",
                "artifact_ref": "artifact:agreement",
                "proof_kind": "agreement",
                "artifact_digest": "sha256:agreement",
                "kernel_direction": "positive",
                "assoc_direction": "positive",
                "adequacy_direction": "positive",
                "prefix": "accept",
                "usage": "accept",
                "target": "accept",
                "gate_decision": "allow",
            },
        },
        "positive",
        (),
        GateDecision.ALLOW,
    ).passed
    assert (
        checker.agreement(
            type("KernelLike", (), {"direction": "positive"})(),
            type("FiberLike", (), {"fiber_status": "positive"})(),
            {
                "prefix": "accept",
                "usage": "accept",
                "target": "accept",
                "agreement_proof_ref": {
                    "proof_status": "pass",
                    "artifact_ref": "artifact:agreement",
                    "proof_kind": "agreement",
                    "kernel_direction": "positive",
                    "assoc_direction": "positive",
                    "adequacy_direction": "positive",
                    "prefix": "accept",
                    "usage": "accept",
                    "target": "accept",
                    "gate_decision": "allow",
                },
            },
            "positive",
            (),
            GateDecision.ALLOW,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.agreement(
        type("KernelLike", (), {"direction": "positive"})(),
        type("FiberLike", (), {"fiber_status": "positive"})(),
        {
            "prefix": "accept",
            "usage": "accept",
            "target": "accept",
            "agreement_proof_ref": {
                "proof_status": "pass",
                "artifact_ref": "artifact:agreement",
                "proof_kind": "agreement",
                "artifact_digest": "sha256:agreement-nested-payload",
                "proof": {
                    "kernel_direction": "positive",
                    "assoc_direction": "positive",
                    "adequacy_direction": "positive",
                    "prefix": "accept",
                    "usage": "accept",
                    "target": "accept",
                    "gate_decision": "allow",
                },
            },
        },
        "positive",
        (),
        GateDecision.ALLOW,
    ).passed
    assert (
        checker.agreement(
            type("KernelLike", (), {"direction": "positive"})(),
            type("FiberLike", (), {"fiber_status": "positive"})(),
            {
                "prefix": "accept",
                "usage": "accept",
                "target": "accept",
                "agreement_proof_ref": {
                    "proof_status": "pass",
                    "artifact_ref": "artifact:agreement",
                    "proof_kind": "agreement",
                },
            },
            "positive",
            (),
            GateDecision.ALLOW,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.agreement(
            type("KernelLike", (), {"direction": "positive"})(),
            type("FiberLike", (), {"fiber_status": "negative"})(),
            {
                "prefix": "accept",
                "usage": "accept",
                "target": "accept",
                "agreement_proof_ref": {
                    "proof_status": "pass",
                    "artifact_ref": "artifact:agreement",
                    "proof_kind": "agreement",
                    "artifact_digest": "sha256:agreement-conflict",
                    "kernel_direction": "positive",
                    "assoc_direction": "negative",
                    "adequacy_direction": "positive",
                    "prefix": "accept",
                    "usage": "accept",
                    "target": "accept",
                    "gate_decision": "allow",
                },
            },
            "positive",
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.agreement(
            type("KernelLike", (), {"direction": "positive"})(),
            type("FiberLike", (), {"fiber_status": "positive"})(),
            {"agreement_proof_ref": {"proof_status": "pass"}},
            "positive",
            (),
            GateDecision.ALLOW,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.agreement(
            type("KernelLike", (), {"direction": "positive"})(),
            type("FiberLike", (), {"fiber_status": "positive"})(),
            {
                "prefix": "accept",
                "usage": "accept",
                "target": "accept",
                "agreement_proof_ref": {
                    "proof_status": "pass",
                    "artifact_ref": "artifact:not-agreement",
                    "proof_kind": "schema_validation",
                },
            },
            "positive",
            (),
            GateDecision.ALLOW,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.typed_authority_outcome(
            {"authority_outcome": []},
            None,
            None,
            (),
            GateDecision.ALLOW,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.typed_authority_outcome(
            {"authority_outcome": {"code": "allow"}},
            None,
            None,
            (),
            GateDecision.ALLOW,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.typed_authority_outcome(
            {"authority_outcome": {"code": "allow", "outcome_schema_ref": "local-schema"}},
            None,
            None,
            (),
            GateDecision.ALLOW,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.typed_authority_outcome(
        {
            "authority_outcome": {
                "layer": "policy",
                "code": "allow",
                "direction": "none",
                "outcome_schema_ref": {
                    "checker_status": "pass",
                    "checker_kind": "authority_outcome_schema",
                    "source_artifact": "artifact:authority-outcome-schema",
                    "source_path": "/schema",
                    "digest": "sha256:authority-outcome-schema",
                },
            }
        },
        None,
        None,
        (),
        GateDecision.ALLOW,
    ).passed
    assert checker.typed_authority_outcome(
        {
            "authority_outcome": {
                "layer": "status",
                "code": "unknown",
                "direction": "none",
                "outcome_schema_ref": "status-authority-view",
            },
            "reason_refs": ["artifact:reason#/reason"],
            "reason_ref_records": [
                {
                    "reason_id": "reason:unknown",
                    "failure_code": "checker_unknown",
                    "layer": "status",
                    "source_artifact": "artifact:reason",
                    "source_path": "/reason",
                    "message": "typed authority reason",
                    "digest": "sha256:reason",
                }
            ],
            "blocking_records": [
                {
                    "block_id": "block:unknown",
                    "failure_code": "checker_unknown",
                    "layer": "status",
                    "severity": "error",
                    "reason_refs": ["reason:unknown"],
                    "reason_ref_records": [
                        {
                            "reason_id": "reason:unknown",
                            "failure_code": "checker_unknown",
                            "layer": "status",
                            "source_artifact": "artifact:reason",
                            "source_path": "/reason",
                            "message": "typed authority reason",
                            "digest": "sha256:reason",
                        }
                    ],
                }
            ],
        },
        None,
        None,
        (),
        GateDecision.ALLOW,
    ).passed
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "status",
                    "code": "unknown",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "reason_ref_records": [
                    {
                        "reason_id": "reason:unknown",
                        "failure_code": "checker_unknown",
                        "layer": "status",
                        "source_artifact": "artifact:reason",
                        "source_path": "/reason",
                        "message": "typed authority reason",
                        "digest": "sha256:reason",
                    }
                ],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "status",
                    "code": "unknown",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "reason_refs": ["artifact:reason#/reason"],
                "blocking_records": [
                    {
                        "block_id": "block:unknown",
                        "failure_code": "checker_unknown",
                        "layer": "status",
                        "severity": "error",
                        "reason_refs": ["reason:unknown"],
                        "reason_ref_records": [
                            {
                                "reason_id": "reason:unknown",
                                "failure_code": "checker_unknown",
                                "layer": "status",
                                "source_artifact": "artifact:reason",
                                "source_path": "/reason",
                                "message": "typed authority reason",
                                "digest": "sha256:reason",
                            }
                        ],
                    }
                ],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "status",
                    "code": "unknown",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "reason_refs": ["artifact:reason#/reason"],
                "blocking_records": [{"block_id": "block:unknown"}],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "status",
                    "code": "unknown",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "reason_refs": [1],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "status",
                    "code": "unknown",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "reason_refs": [],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert checker.typed_authority_outcome(
        {
            "authority_outcome": {
                "layer": "policy",
                "code": "allow",
                "direction": "none",
                "outcome_schema_ref": "status-authority-view",
            }
        },
        None,
        None,
        (),
        GateDecision.ALLOW,
    ).passed
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "obligation_refs": ["artifact:obligation#/obligation"],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "obligation_refs": ["artifact:obligation#/obligation"],
                "obligation_ref_records": [
                    {
                        "obligation_id": "artifact:obligation#/obligation",
                        "kind": "obligation",
                        "status": "not_checked",
                    }
                ],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.CHECKER_UNKNOWN
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                    "issued_at_status_time": "2026-01-01T00:00:00Z",
                },
                "obligation_refs": ["artifact:obligation#/obligation"],
                "obligation_ref_records": [
                    {
                        "obligation_id": "artifact:obligation#/obligation",
                        "kind": "obligation",
                        "status": "pass",
                    }
                ],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                    "issued_at_status_time": "2026-01-01T00:00:00Z",
                },
                "obligation_refs": ["artifact:obligation#/obligation"],
                "obligation_ref_records": [
                    {
                        "obligation_id": "artifact:obligation#/obligation",
                        "kind": "obligation",
                        "status": "pass",
                        "expiry": "2025-01-01T00:00:00Z",
                        "source_artifact": "artifact:obligation",
                        "source_path": "/obligation",
                        "digest": "sha256:obligation",
                    }
                ],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.VALIDITY_UNKNOWN
    )
    assert checker.typed_authority_outcome(
        {
            "authority_outcome": {
                "layer": "policy",
                "code": "allow",
                "direction": "none",
                "outcome_schema_ref": "status-authority-view",
                "issued_at_status_time": "2026-01-01T00:00:00Z",
            },
            "obligation_refs": ["artifact:obligation#/obligation"],
            "obligation_ref_records": [
                {
                    "obligation_id": "artifact:obligation#/obligation",
                    "kind": "obligation",
                    "status": "pass",
                    "source_artifact": "artifact:obligation",
                    "source_path": "/obligation",
                    "digest": "sha256:obligation",
                }
            ],
        },
        None,
        None,
        (),
        GateDecision.ALLOW,
    ).passed
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "obligation_refs": ["artifact:obligation#/obligation"],
                "obligation_ref_records": [
                    {
                        "obligation_id": "artifact:obligation#/obligation",
                        "kind": "obligation",
                        "status": "waived",
                        "reason_refs": [],
                    }
                ],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.CHECKER_UNKNOWN
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "obligation_refs": ["artifact:obligation#/obligation"],
                "obligation_ref_records": [
                    {
                        "obligation_id": "artifact:obligation#/obligation",
                        "kind": "obligation",
                        "status": "waived",
                        "reason_refs": [""],
                    }
                ],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.SCHEMA_INVALID
    )
    assert (
        checker.typed_authority_outcome(
            {
                "dominant_status": "expired",
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "operational",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "operational",
                    "code": "accept",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            type("AgreementLike", (), {"agreement_status": "positive"})(),
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "not-a-layer",
                    "code": "unknown",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.SCHEMA_INVALID
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "operational",
                    "code": "accept",
                    "direction": "positive",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "operational",
                    "code": "accept",
                    "direction": "positive",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            type("AgreementLike", (), {"agreement_status": "negative"})(),
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.typed_authority_outcome(
        {
            "authority_outcome": {
                "layer": "operational",
                "code": "accept",
                "direction": "positive",
                "outcome_schema_ref": "status-authority-view",
            }
        },
        None,
        type("AgreementLike", (), {"agreement_status": "positive"})(),
        (),
        GateDecision.ALLOW,
    ).passed
    negative_authority_reason = {
        "reason_id": "reason:negative-authority",
        "failure_code": "checker_unknown",
        "layer": "operational",
        "source_artifact": "artifact:reason",
        "source_path": "/reason",
        "message": "negative authority evidence",
        "digest": "sha256:reason",
    }
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "operational",
                    "code": "reject",
                    "direction": "negative",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            type("AgreementLike", (), {"agreement_status": "negative"})(),
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert checker.typed_authority_outcome(
        {
            "authority_outcome": {
                "layer": "operational",
                "code": "reject",
                "direction": "negative",
                "outcome_schema_ref": "status-authority-view",
                "reason_refs": ["reason:negative-authority"],
                "reason_ref_records": [negative_authority_reason],
            },
            "reason_refs": ["reason:negative-authority"],
            "reason_ref_records": [negative_authority_reason],
        },
        None,
        type("AgreementLike", (), {"agreement_status": "negative"})(),
        (),
        GateDecision.ALLOW,
    ).passed
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "operational",
                    "code": "reject",
                    "direction": "negative",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            type("AgreementLike", (), {"agreement_status": "positive"})(),
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    represented_deny_reason = {
        **negative_authority_reason,
        "reason_id": "reason:represented-deny",
        "layer": "represented",
        "message": "represented denial evidence",
    }
    represented_deny_with_proof = {
        "authority_outcome": {
            "layer": "represented",
            "code": "deny",
            "direction": "negative",
            "outcome_schema_ref": "status-authority-view",
            "reason_refs": ["reason:represented-deny"],
            "reason_ref_records": [represented_deny_reason],
        },
        "reason_refs": ["reason:represented-deny"],
        "reason_ref_records": [represented_deny_reason],
        "proof_refs": ["artifact:kernel-proof"],
        "proof_ref_records": [
            {
                "proof_id": "artifact:kernel-proof",
                "proof_kind": "kernel",
                "artifact_ref": "artifact:kernel-proof",
                "source_artifact": "artifact:kernel-proof",
                "source_path": "/proof",
                "digest": "sha256:kernel-proof",
                "status": "accepted",
            }
        ],
    }
    assert checker.typed_authority_outcome(
        represented_deny_with_proof,
        None,
        None,
        (),
        GateDecision.ALLOW,
    ).passed
    missing_proof_records = {
        **represented_deny_with_proof,
        "proof_ref_records": [],
    }
    assert (
        checker.typed_authority_outcome(
            missing_proof_records,
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    mismatched_proof_records = {
        **represented_deny_with_proof,
        "proof_ref_records": [
            {
                **represented_deny_with_proof["proof_ref_records"][0],
                "proof_id": "artifact:other-proof",
            }
        ],
    }
    assert (
        checker.typed_authority_outcome(
            mismatched_proof_records,
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    digestless_proof_records = {
        **represented_deny_with_proof,
        "proof_ref_records": [
            {
                **represented_deny_with_proof["proof_ref_records"][0],
                "digest": None,
            }
        ],
    }
    assert (
        checker.typed_authority_outcome(
            digestless_proof_records,
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "represented",
                    "code": "deny",
                    "direction": "negative",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )
    assert checker.typed_authority_outcome(
        {
            "authority_outcome": {
                "layer": "represented",
                "code": "deny",
                "direction": "negative",
                "outcome_schema_ref": "status-authority-view",
                "reason_refs": ["reason:represented-deny"],
                "reason_ref_records": [represented_deny_reason],
            },
            "reason_refs": ["reason:represented-deny"],
            "reason_ref_records": [represented_deny_reason],
        },
        None,
        None,
        (),
        GateDecision.ALLOW,
    ).passed
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "represented",
                    "code": "deny",
                    "direction": "negative",
                    "gate_decision": "block",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            None,
            (),
            None,
        )
        .failure_records[0]
        .code
        is FailureCode.POLICY_BLOCK
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                },
                "blocking_records": [
                    {
                        "block_id": "block:conflict",
                        "failure_code": "checker_unknown",
                        "reason_ref_records": ["artifact:reason#/reason"],
                    }
                ],
            },
            None,
            None,
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "policy",
                    "code": "allow",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            None,
            (),
            GateDecision.BLOCK,
        )
        .failure_records[0]
        .code
        is FailureCode.POLICY_BLOCK
    )
    assert (
        checker.typed_authority_outcome(
            {
                "authority_outcome": {
                    "layer": "status",
                    "code": "unknown",
                    "direction": "none",
                    "outcome_schema_ref": "status-authority-view",
                }
            },
            None,
            type("AgreementLike", (), {"agreement_status": "positive"})(),
            (),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert checker.status_confluence((), (), EventOrder()).status is ValidationStatus.UNKNOWN
    shallow_ref_proof_obj = type(
        "BareRefProofObject",
        (),
        {"proof_status": "accepted", "infeasibility_ref": "artifact:proof"},
    )()
    assert not checker.infeasibility(shallow_ref_proof_obj)
    proof_obj = type(
        "ProofObject",
        (),
        {"proof_status": "accepted", "infeasibility_ref": "artifact:proof#/infeasibility"},
    )()
    assert checker.infeasibility(proof_obj)
    digest_proof_obj = type(
        "DigestProofObject",
        (),
        {"proof_status": "accepted", "infeasibility_ref": "sha256:abc"},
    )()
    assert checker.infeasibility(digest_proof_obj)
    mapped_proof_obj = type(
        "MappedProofObject",
        (),
        {
            "proof_status": "accepted",
            "infeasibility_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:proof",
                "proof_kind": "infeasibility",
            },
        },
    )()
    assert not checker.infeasibility(mapped_proof_obj)
    mapped_proof_obj.infeasibility_ref["artifact_digest"] = "sha256:infeasibility-proof"
    assert checker.infeasibility(mapped_proof_obj)
    shallow_proof_obj = type(
        "ShallowProofObject",
        (),
        {"proof_status": "accepted", "proof_kind": "external"},
    )()
    assert not checker.infeasibility(shallow_proof_obj)
    finite_backend_proof = type(
        "FiniteBackendProof",
        (),
        {
            "proof_status": "accepted",
            "proof_kind": "exact-finite-enumeration",
            "backend_identity": "EnumeratingBackend",
            "proof_ref": "sha256:finite-enumeration",
        },
    )()
    assert checker.infeasibility(finite_backend_proof)
    finite_backend_proof_without_ref = type(
        "FiniteBackendProofWithoutRef",
        (),
        {
            "proof_status": "accepted",
            "proof_kind": "exact-finite-enumeration",
            "backend_identity": "EnumeratingBackend",
        },
    )()
    assert not checker.infeasibility(finite_backend_proof_without_ref)
    assert not checker.infeasibility({"proof_status": "fail", "proof_ref": "artifact:proof"})
    assert checker.artifact_conflict(
        (
            {
                "artifact_id": "artifact:same",
                "artifact_type": "json",
                "digest_value": "sha256:first",
            },
            {
                "artifact_ref": {
                    "artifact_id": "artifact:same",
                    "artifact_type": "json",
                    "digest_value": "sha256:second",
                }
            },
        )
    )
    assert not checker.artifact_conflict(
        (
            {
                "artifact_id": "artifact:same",
                "artifact_type": "json",
                "digest_value": "sha256:first",
            },
            {
                "artifact_ref": {
                    "artifact_id": "artifact:same",
                    "artifact_type": "json",
                    "digest_value": "sha256:first",
                }
            },
        )
    )


def test_admission_accepted_clause_compiler_uses_only_admitted_clauses() -> None:
    evidence = EvidenceArtifact("evidence:1", "finite-model", checker_status="pass")
    contract = AdmissionContract(
        kind="finite-model",
        source="evidence:1",
        target="semantics",
        clause={
            "state_space": [{"temp": "70"}],
            "initial_states": [{"temp": "70"}],
            "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        },
        contract_id="contract:1",
        obligation_refs=("obligation:model",),
        checker_transcript_ref="artifact:model-transcript",
    )
    accepted = admit_evidence(evidence, contract, {"status_time": "2026-01-01T00:00:00Z"})
    assert accepted.passed
    assert accepted.accepted_clause_records[0].obligation_refs == ("obligation:model",)
    compiled = compile_bundle_from_accepted_clauses(
        {"bundle_id": "accepted-only"},
        accepted.accepted_clause_records,
        1,
    )
    assert compiled.accepted_clause_refs == ("accepted:semantics",)
    assert len(compiled.enumerate_trajectories()) == 1

    raw_only = compile_bundle_from_accepted_clauses({"bundle_id": "empty"}, (), 1)
    assert raw_only.initial_set.is_empty()
    assert admit_evidence(evidence, {**to_jsonable(contract), "kind": "wrong"}).status == "unknown"
    assert admit_evidence(
        evidence,
        AdmissionContract(
            kind="finite-model",
            source="evidence:1",
            target="semantics",
            clause={},
            expiry_rule="requires-status-time",
            checker_transcript_ref="artifact:model-transcript",
        ),
    ).reason_refs
    assert admit_evidence_set((), (contract,))[0].reason_refs[0].failure_code is (
        FailureCode.MISSING_REF
    )
    assert EvidenceArtifact.from_json({"artifact_id": "e", "kind": "k"}).checker_status == (
        "unchecked"
    )
    loaded_contract = AdmissionContract.from_json(
        {
            "kind": "finite-model",
            "source": "evidence:1",
            "target": "semantics",
            "clause": {},
            "horizon": 1,
            "frame": "frame",
            "contract_id": "contract:loaded",
            "uncertainty_model": "bounded",
            "expiry_rule": "none",
            "monitor_obligations": ["monitor"],
            "obligation_refs": ["obligation"],
            "reason_refs": ["reason"],
            "checker_transcript_ref": "artifact:loaded-transcript",
        }
    )
    assert loaded_contract.contract_id == "contract:loaded"
    assert validate_named_schema(
        {
            "kind": "finite-model",
            "source": "evidence:1",
            "target": "semantics",
            "clause": {},
            "checker_transcript_ref": "artifact:model-transcript",
        },
        "admission-contract.schema.json",
    ).passed
    invalid_contract_schema = validate_named_schema(
        {
            "kind": "finite-model",
            "source": "evidence:1",
            "target": "semantics",
            "clause": {},
            "checker_transcript_ref": "checker:model",
        },
        "admission-contract.schema.json",
    )
    assert not invalid_contract_schema.passed
    assert invalid_contract_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    assert (
        admit_evidence(
            EvidenceArtifact("evidence:1", "finite-model", checker_status="unchecked"),
            contract,
        )
        .reason_refs[0]
        .failure_code
        is FailureCode.CHECKER_UNKNOWN
    )
    assert (
        admit_evidence(
            evidence,
            AdmissionContract(
                kind="finite-model",
                source="evidence:1",
                target="semantics",
                clause={},
                validity={"not_before": "2026-01-02T00:00:00Z"},
                checker_transcript_ref="artifact:model-transcript",
            ),
            {"status_time": "2026-01-01T00:00:00Z"},
        )
        .reason_refs[0]
        .failure_code
        is FailureCode.VALIDITY_UNKNOWN
    )


def test_admission_strict_transcript_monitor_digest_and_trust_assumption() -> None:
    evidence = EvidenceArtifact(
        "evidence:1",
        "finite-model",
        payload={"digest": "sha256:evidence"},
        artifact_refs=("sha256:evidence",),
        checker_status="pass",
    )
    no_transcript = AdmissionContract(
        kind="finite-model",
        source="evidence:1",
        target="semantics",
        clause={},
    )
    assert admit_evidence(evidence, no_transcript).reason_refs[0].failure_code is (
        FailureCode.CHECKER_UNKNOWN
    )
    unbound_transcript = AdmissionContract(
        kind="finite-model",
        source="evidence:1",
        target="semantics",
        clause={},
        checker_transcript_ref="checker:model",
        reference_digest="sha256:evidence",
    )
    unbound_result = admit_evidence(evidence, unbound_transcript)
    assert not unbound_result.passed
    assert unbound_result.reason_refs[0].failure_code is FailureCode.CHECKER_UNKNOWN
    assert unbound_result.reason_refs[0].source_path == "/checker_transcript_ref"

    mismatch = AdmissionContract(
        kind="finite-model",
        source="evidence:1",
        target="semantics",
        clause={},
        checker_transcript_ref="artifact:model-transcript",
        reference_digest="sha256:other",
    )
    assert admit_evidence(evidence, mismatch).reason_refs[0].failure_code is (
        FailureCode.DIGEST_MISMATCH
    )

    monitored = AdmissionContract(
        kind="finite-model",
        source="evidence:1",
        target="semantics",
        clause={},
        checker_transcript_ref="artifact:model-transcript",
        reference_digest="sha256:evidence",
    )
    assert (
        admit_evidence(evidence, monitored, {"monitor_status": "silent"})
        .reason_refs[0]
        .failure_code
        is FailureCode.VALIDITY_UNKNOWN
    )
    monitored_obligation = AdmissionContract(
        kind="finite-model",
        source="evidence:1",
        target="semantics",
        clause={},
        checker_transcript_ref="artifact:model-transcript",
        reference_digest="sha256:evidence",
        monitor_obligations=("monitor:heartbeat",),
    )
    missing_monitor_evidence = admit_evidence(evidence, monitored_obligation)
    assert missing_monitor_evidence.reason_refs[0].failure_code is FailureCode.VALIDITY_UNKNOWN
    complete_monitor = admit_evidence(
        evidence,
        monitored_obligation,
        {"monitor_completeness_ref": "artifact:monitor#/completeness"},
    )
    assert complete_monitor.passed
    assert complete_monitor.accepted_clause_records[0].monitor_completeness_ref == (
        "artifact:monitor#/completeness"
    )

    trust = TrustAssumption.raw_bundle(target="semantics", source_artifact="bundle:raw")
    assert trust.obligation_refs == ("trust-assumption:raw-bundle",)
    assert trust.reason_ref_records == trust.reason_refs
    assert trust.reason_ref_records[0].digest is not None
    loaded = TrustAssumption.from_json(
        {
            "assumption_id": "trust:loaded",
            "target": "semantics",
            "scope": ["legacy-raw-bundle"],
            "reason_refs": ["accepted migration assumption"],
            "obligation_refs": ["obligation:trust"],
            "checker_transcript_ref": "artifact:trust-transcript",
        }
    )
    assert loaded.reason_refs[0].source_path == "/reason_refs/0"
    assert (
        TrustAssumption.raw_bundle(
            target="semantics",
            source_artifact="bundle:raw",
        ).checker_transcript_ref
        == "artifact:trust-assumption-transcript"
    )
    assert validate_named_schema(
        {
            "assumption_id": "trust:schema",
            "target": "semantics",
            "scope": ["legacy-raw-bundle"],
            "reason_refs": ["artifact:reason#/reason"],
            "reason_ref_records": [_reason_ref_record(message="accepted migration assumption")],
            "obligation_refs": ["artifact:obligation#/obligation"],
            "checker_transcript_ref": "artifact:trust-transcript",
        },
        "trust-assumption.schema.json",
    ).passed
    invalid_trust_schema = validate_named_schema(
        {
            "assumption_id": "trust:schema",
            "target": "semantics",
            "scope": ["legacy-raw-bundle"],
            "reason_refs": ["artifact:reason#/reason"],
            "reason_ref_records": [_reason_ref_record(message="accepted migration assumption")],
            "obligation_refs": ["artifact:obligation#/obligation"],
            "checker_transcript_ref": "checker:trust",
        },
        "trust-assumption.schema.json",
    )
    assert not invalid_trust_schema.passed
    assert invalid_trust_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID

    trust_reason_record = _reason_ref_record(message="accepted migration assumption")
    trust_source = {
        "assumption_id": "trust:loaded",
        "target": "semantics",
        "scope": ["legacy-raw-bundle"],
        "reason_refs": ["artifact:reason#/reason"],
        "reason_ref_records": [trust_reason_record],
        "obligation_refs": ["artifact:obligation#/obligation"],
        "checker_transcript_ref": "artifact:trust-transcript",
    }
    trust_entries = (
        ReferenceLedgerEntry(
            ref_value="artifact:trust-transcript",
            kind=ReferenceKind.TRANSCRIPT,
            owner_artifact="artifact:trust",
            owner_path="/checker_transcript_ref",
            target_artifact_id="artifact:trust-transcript",
            target_path="",
            target_digest="sha256:transcript",
            resolved=True,
        ),
        ReferenceLedgerEntry(
            ref_value="artifact:reason#/reason",
            kind=ReferenceKind.REASON,
            owner_artifact="artifact:trust",
            owner_path="/reason_refs/0",
            target_artifact_id="artifact:reason",
            target_path="/reason",
            target_digest=trust_reason_record["digest"],
            semantic_role=ArtifactRole.REASON.value,
            resolved=True,
        ),
        ReferenceLedgerEntry(
            ref_value="artifact:obligation#/obligation",
            kind=ReferenceKind.OBLIGATION,
            owner_artifact="artifact:trust",
            owner_path="/obligation_refs/0",
            target_artifact_id="artifact:obligation",
            target_path="/obligation",
            target_digest=_obligation_digest(),
            semantic_role=ArtifactRole.OBLIGATION.value,
            resolved=True,
            active_scope_status="pass",
        ),
    )
    assert (
        trust_assumption_result(
            trust_source,
            trust_entries,
            assumption_id="trust:loaded",
            source_layer=Layer.ISSUE,
        )
        is None
    )
    symbolic_trust = {
        **trust_source,
        "reason_refs": ["accepted migration assumption"],
        "reason_ref_records": [trust_reason_record],
    }
    symbolic_trust_result = trust_assumption_result(
        symbolic_trust,
        trust_entries,
        assumption_id="trust:loaded",
        source_layer=Layer.ISSUE,
    )
    assert symbolic_trust_result is not None
    assert symbolic_trust_result.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    missing_reason_records_result = trust_assumption_result(
        {key: value for key, value in trust_source.items() if key != "reason_ref_records"},
        trust_entries,
        assumption_id="trust:loaded",
        source_layer=Layer.ISSUE,
    )
    assert missing_reason_records_result is not None
    assert missing_reason_records_result.failure_records[0].code is FailureCode.MISSING_REF
    malformed_reason_records_result = trust_assumption_result(
        {**trust_source, "reason_ref_records": "artifact:reason#/reason"},
        trust_entries,
        assumption_id="trust:loaded",
        source_layer=Layer.ISSUE,
    )
    assert malformed_reason_records_result is not None
    assert malformed_reason_records_result.failure_records[0].code is FailureCode.SCHEMA_INVALID
    untyped_reason_record_result = trust_assumption_result(
        {**trust_source, "reason_ref_records": ["artifact:reason#/reason"]},
        trust_entries,
        assumption_id="trust:loaded",
        source_layer=Layer.ISSUE,
    )
    assert untyped_reason_record_result is not None
    assert untyped_reason_record_result.failure_records[0].code is FailureCode.SCHEMA_INVALID
    incomplete_reason_record_result = trust_assumption_result(
        {
            **trust_source,
            "reason_ref_records": [
                {key: value for key, value in trust_reason_record.items() if key != "digest"}
            ],
        },
        trust_entries,
        assumption_id="trust:loaded",
        source_layer=Layer.ISSUE,
    )
    assert incomplete_reason_record_result is not None
    assert incomplete_reason_record_result.failure_records[0].code is FailureCode.MISSING_REF
    mismatched_reason_record_result = trust_assumption_result(
        {
            **trust_source,
            "reason_ref_records": [{**trust_reason_record, "digest": "sha256:mismatch"}],
        },
        trust_entries,
        assumption_id="trust:loaded",
        source_layer=Layer.ISSUE,
    )
    assert mismatched_reason_record_result is not None
    assert mismatched_reason_record_result.failure_records[0].code is FailureCode.DIGEST_MISMATCH

    expired_trust_result = trust_assumption_result(
        trust_source,
        (
            *trust_entries[:2],
            replace(trust_entries[2], active_scope_status="expired"),
        ),
        assumption_id="trust:loaded",
        source_layer=Layer.ISSUE,
    )
    assert expired_trust_result is not None
    assert expired_trust_result.failure_records[0].code is FailureCode.VALIDITY_UNKNOWN

    contract_source = {
        "kind": "finite-model",
        "source": "artifact:evidence",
        "target": "semantics",
        "clause": {},
        "checker_transcript_ref": "artifact:trust-transcript",
        "obligation_refs": ["artifact:obligation#/obligation"],
    }
    assert (
        admission_contract_result(
            contract_source,
            trust_entries,
            contract_id="contract:loaded",
            source_layer=Layer.ISSUE,
        )
        is None
    )
    symbolic_contract = {**contract_source, "obligation_refs": ["obligation:symbolic"]}
    symbolic_contract_result = admission_contract_result(
        symbolic_contract,
        trust_entries,
        contract_id="contract:loaded",
        source_layer=Layer.ISSUE,
    )
    assert symbolic_contract_result is not None
    assert symbolic_contract_result.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    missing_contract_obligation_result = admission_contract_result(
        {key: value for key, value in contract_source.items() if key != "obligation_refs"},
        trust_entries,
        contract_id="contract:loaded",
        source_layer=Layer.ISSUE,
    )
    assert missing_contract_obligation_result is not None
    assert missing_contract_obligation_result.failure_records[0].code is FailureCode.MISSING_REF


def test_bundle_compile_error_paths() -> None:
    with pytest.raises(BundleCompileError):
        parse_bundle({})
    with pytest.raises(BundleCompileError):
        parse_bundle({"bundle_id": "bad", "transitions": [1]})
    with pytest.raises(BundleCompileError):
        compile_bundle(
            parse_bundle({"bundle_id": "bad", "state_space": [], "initial_states": [{"x": 1}]}),
            1,
        )
    with pytest.raises(BundleCompileError):
        compile_bundle(
            parse_bundle(
                {
                    "bundle_id": "bad",
                    "state_space": [{"x": 1}],
                    "initial_states": [{"x": 1}],
                    "transitions": [{"from": {"x": 2}, "to": {"x": 1}}],
                }
            ),
            1,
        )
    with pytest.raises(BundleCompileError):
        compile_bundle(
            parse_bundle(
                {
                    "bundle_id": "bad",
                    "state_space": [{"x": 1}],
                    "initial_states": [{"x": 1}],
                    "transitions": [{"from": {"x": 1}, "to": {"x": 1}, "step": 2}],
                }
            ),
            1,
        )


def test_conformance_file_and_digest_expectation_paths(tmp_path: Path) -> None:
    case = {
        "case_id": "single-file",
        "kind": "canonicalization-mismatch",
        "suite": "legacy-interop",
        "canonical_equality_required": False,
        "expected": ValidationStatus.INVALID_ARTIFACT.value,
    }
    case_file = tmp_path / "case.json"
    case_file.write_text(json.dumps(case), encoding="utf-8")
    assert run_golden_cases(case_file)[0].passed

    case_list = tmp_path / "cases.json"
    case_list.write_text(json.dumps([case]), encoding="utf-8")
    assert run_golden_cases(case_list)[0].passed

    strict_missing_digest = {
        "case_id": "strict-missing-digest",
        "kind": "canonicalization-mismatch",
        "expected": ValidationStatus.INVALID_ARTIFACT.value,
    }
    strict_file = tmp_path / "strict-case.json"
    strict_file.write_text(json.dumps(strict_missing_digest), encoding="utf-8")
    strict = run_golden_cases(strict_file)[0]
    assert not strict.passed
    assert strict.expected == "expected_digest"
    assert strict.actual == "missing_expected_digest"
    assert strict.equality_key is not None

    digest_case = {
        **case,
        "case_id": "digest-case",
        "expected_digest": "sha256:not-actual",
    }
    digest_dir = tmp_path / "digest"
    digest_dir.mkdir()
    (digest_dir / "case.json").write_text(json.dumps(digest_case), encoding="utf-8")
    assert not run_golden_cases(digest_dir)[0].passed
    unknown_dir = tmp_path / "unknown"
    unknown_dir.mkdir()
    (unknown_dir / "case.json").write_text(
        json.dumps(
            {
                "case_id": "unknown",
                "kind": "unknown-kind",
                "suite": "legacy-interop",
                "canonical_equality_required": False,
                "expected": "x",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown validation"):
        run_golden_cases(unknown_dir)


def test_lifecycle_hash_chain_signature_and_causal_failures() -> None:
    event = LifecycleEvent.from_json(
        {
            "event_id": "evt-1",
            "certificate_id": "cert",
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "mark-unknown",
        }
    )
    committed = event_commitment(event)
    with_hash = LifecycleEvent.from_json(
        {
            **to_jsonable(event),
            "payload": {"event_hash": committed},
            "hashes": [committed],
        }
    )
    folded = fold_status("cert", (with_hash,), EventOrder(), FoldContext("default"))
    assert folded.dominant_status is StatusCode.UNKNOWN
    missing_hash_commitment = LifecycleEvent.from_json(
        {
            **to_jsonable(event),
            "payload": {"event_hash": committed},
            "hashes": [],
        }
    )
    assert (
        fold_status(
            "cert", (missing_hash_commitment,), EventOrder(), FoldContext("default")
        ).dominant_status
        is StatusCode.CONFLICT
    )
    missing_manifest_commitment = LifecycleEvent.from_json(
        {
            **to_jsonable(event),
            "manifest_digest": "sha256:manifest",
            "hashes": [event_commitment(event)],
        }
    )
    assert (
        fold_status(
            "cert", (missing_manifest_commitment,), EventOrder(), FoldContext("default")
        ).dominant_status
        is StatusCode.CONFLICT
    )
    assert (
        fold_status(
            "cert",
            (
                LifecycleEvent.from_json(
                    {**to_jsonable(event), "payload": {"signature_policy": "required"}}
                ),
            ),
            EventOrder(),
            FoldContext("default"),
        ).dominant_status
        is StatusCode.CONFLICT
    )
    assert (
        fold_status(
            "cert",
            (LifecycleEvent.from_json({**to_jsonable(event), "payload": {"event_hash": "bad"}}),),
            EventOrder(),
            FoldContext("default"),
        ).dominant_status
        is StatusCode.CONFLICT
    )
    assert (
        fold_status(
            "cert",
            (
                LifecycleEvent.from_json(
                    {**to_jsonable(event), "payload": {"previous_hash": "bad"}}
                ),
            ),
            EventOrder(),
            FoldContext("default"),
        ).dominant_status
        is StatusCode.CONFLICT
    )
    assert (
        fold_status(
            "cert",
            (event,),
            EventOrder(trace_class=("expire",)),
            FoldContext("default"),
        ).dominant_status
        is StatusCode.CONFLICT
    )
    assert (
        fold_status(
            "cert",
            (LifecycleEvent.from_json({**to_jsonable(event), "ancestry": ["parent"]}),),
            EventOrder(causal_cut=("other",)),
            FoldContext("default"),
        ).dominant_status
        is StatusCode.CONFLICT
    )
    missing_accepted_event = fold_status(
        "cert",
        (event,),
        EventOrder(accepted_event_ids=("evt-1", "evt-missing")),
        FoldContext("default"),
    )
    assert missing_accepted_event.dominant_status is StatusCode.CONFLICT
    assert any(
        block.failure_code is FailureCode.TRACE_CONFLICT
        and block.reason_refs[0].source_path == "/accepted_event_ids"
        for block in missing_accepted_event.blocking_set
    )


def test_update_certificate_returns_typed_lifecycle_decision_with_transfer_blockers() -> None:
    issued = _issued_lifecycle_certificate()
    decision = update_certificate(
        issued,
        {
            "event_id": "evt-dependency",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "mark-unknown",
            "payload": {
                "dependency_updates": ["sensor-calibration"],
                "requires_proof_preservation": True,
            },
        },
    )
    assert decision == "recompute"
    assert str(decision) == "recompute"
    assert decision != object()
    assert decision.decision == "recompute"
    assert decision.dependency_updates == ("sensor-calibration",)
    assert decision.blocking_set
    assert any(block.failure_code is FailureCode.CHECKER_UNKNOWN for block in decision.blocking_set)
    decision_json = decision.to_json()
    assert decision_json["accepted"] is False
    assert decision_json["blocking_records"]
    assert {"/payload/dependency_transfer_ref", "/payload/proof_preservation_refs"}.issubset(
        {
            record["reason_ref_records"][0]["source_path"]
            for record in decision_json["blocking_records"]
        }
    )
    assert validate_named_schema(decision_json, "lifecycle-decision.schema.json").passed

    missing_accepted_certificate = _issued_lifecycle_certificate()
    missing_accepted = update_certificate(
        missing_accepted_certificate,
        {
            "event_id": "evt-missing-accepted",
            "certificate_id": missing_accepted_certificate.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
        },
        {
            "accepted_event_ids": ["evt-missing-accepted", "evt-not-in-log"],
            "accepted_event_ids_ref": "artifact:accepted-event-set",
            "accepted_event_ids_status": {
                "status": "accepted",
                "artifact_ref": "artifact:accepted-event-set",
                "artifact_digest": "sha256:accepted-event-set",
                "proof_kind": "accepted_event_set",
                "payload": {
                    "event_id": "evt-missing-accepted",
                    "accepted_event_ids": ["evt-missing-accepted", "evt-not-in-log"],
                },
            },
        },
    )
    assert missing_accepted.decision == "recompute"
    assert missing_accepted.dominant_status is StatusCode.CONFLICT
    assert any(
        block.failure_code is FailureCode.TRACE_CONFLICT
        and block.reason_refs[0].source_path == "/accepted_event_ids"
        for block in missing_accepted.blocking_set
    )


def _issued_lifecycle_certificate() -> IssueCertificate:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    return issued


def test_lifecycle_reason_normalization_preserves_bound_digest_and_fallback() -> None:
    assert _artifact_bound_id("artifact:event", "artifact:fallback") == "artifact:event"
    assert _artifact_bound_id(None, "artifact:fallback") == "artifact:fallback"

    ref = ReasonRef(
        "reason:existing",
        FailureCode.CHECKER_UNKNOWN,
        Layer.STATUS,
        "artifact:lifecycle-proof",
        "/proof",
        "proof already has digest",
        digest="sha256:existing",
    )
    normalized = _lifecycle_reason_ref("evt", ref)
    assert normalized.source_artifact == "artifact:lifecycle-proof"
    assert normalized.source_path == "/proof"
    assert normalized.digest == "sha256:existing"


def test_update_certificate_rejects_invalid_schema_and_canonicalization() -> None:
    issued = _issued_lifecycle_certificate()
    decision = update_certificate(
        issued,
        {
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
        },
    )
    assert decision.decision == "reject"
    assert decision.dominant_status is StatusCode.INVALID
    assert any(block.failure_code is FailureCode.SCHEMA_INVALID for block in decision.blocking_set)
    decision_json = decision.to_json()
    assert validate_named_schema(decision_json, "lifecycle-decision.schema.json").passed
    reason_record = decision_json["reason_ref_records"][0]
    assert reason_record["source_artifact"].startswith("artifact:")
    assert reason_record["source_path"].startswith("/")
    assert reason_record["digest"].startswith("sha256:")
    legacy_decision = decision.to_json()
    legacy_decision.pop("blocking_records")
    legacy_decision.pop("reason_ref_records")
    assert not validate_named_schema(legacy_decision, "lifecycle-decision.schema.json").passed
    legacy_trace_decision = decision.to_json()
    legacy_trace_decision.pop("accepted_event_ids")
    legacy_trace_decision.pop("causal_cut")
    assert not validate_named_schema(
        legacy_trace_decision,
        "lifecycle-decision.schema.json",
    ).passed

    canonicalization = update_certificate(
        issued,
        {
            "event_id": "evt-float",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {"ambiguous": 0.1},
        },
    )
    assert canonicalization.decision == "reject"
    assert canonicalization.dominant_status is StatusCode.INVALID
    assert any(
        block.failure_code is FailureCode.CANONICALIZATION_MISMATCH
        for block in canonicalization.blocking_set
    )

    invalid_time = update_certificate(
        issued,
        {
            "event_id": "evt-invalid-time",
            "certificate_id": issued.certificate_id,
            "time": "not-a-time",
            "logical_clock": 1,
            "kind": "audit",
        },
    )
    assert invalid_time.decision == "reject"
    assert invalid_time.dominant_status is StatusCode.INVALID
    assert any(
        block.failure_code is FailureCode.SCHEMA_INVALID for block in invalid_time.blocking_set
    )


def test_update_certificate_blocks_manifest_policy_and_unaccepted_transfer_refs() -> None:
    issued = _issued_lifecycle_certificate()
    manifest_without_proof = update_certificate(
        issued,
        {
            "event_id": "evt-manifest-no-proof",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "manifest_digest": "sha256:manifest-direct",
            "hashes": ["sha256:manifest-direct"],
        },
    )
    assert manifest_without_proof.decision == "recompute"
    assert any(
        ref.source_path == "/manifest_digest_ref"
        for block in manifest_without_proof.blocking_set
        for ref in block.reason_refs
    )

    manifest_with_shallow_proof = update_certificate(
        issued,
        {
            "event_id": "evt-manifest-shallow-proof",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "manifest_digest": "sha256:manifest-shallow",
            "manifest_digest_ref": "artifact:manifest-proof",
            "manifest_digest_status": {
                "status": "accepted",
                "artifact_ref": "artifact:manifest-proof",
                "proof_kind": "event_manifest_digest",
                "payload": {
                    "event_id": "evt-manifest-shallow-proof",
                    "event_manifest_digest": "sha256:manifest-shallow",
                },
            },
            "hashes": ["sha256:manifest-shallow"],
        },
    )
    assert manifest_with_shallow_proof.decision == "reject"
    assert any(
        block.failure_code is FailureCode.SCHEMA_INVALID
        for block in manifest_with_shallow_proof.blocking_set
    )

    manifest_with_proof = update_certificate(
        issued,
        {
            "event_id": "evt-manifest-proof",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "manifest_digest": "sha256:manifest-proof",
            "manifest_digest_ref": "artifact:manifest-proof",
            "manifest_digest_status": {
                "status": "accepted",
                "artifact_ref": "artifact:manifest-proof",
                "artifact_digest": "sha256:manifest-proof-evidence",
                "proof_kind": "event_manifest_digest",
                "payload": {
                    "event_id": "evt-manifest-proof",
                    "event_manifest_digest": "sha256:manifest-proof",
                },
            },
            "hashes": ["sha256:manifest-proof"],
        },
    )
    assert manifest_with_proof.decision == "maintain"
    assert manifest_with_proof.accepted is True
    assert validate_named_schema(
        manifest_with_proof.to_json(),
        "lifecycle-decision.schema.json",
    ).passed

    decision = update_certificate(
        issued,
        {
            "event_id": "evt-transfer",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "manifest_digest": "md5:actual",
            "hashes": ["md5:actual"],
            "payload": {
                "dependency_updates": ["sensor-calibration"],
                "dependency_transfer_ref": "proof:dependency",
                "dependency_transfer_status": "unknown",
                "frame_digest": "frame:new",
                "frame_transfer_ref": "proof:frame",
                "frame_transfer_status": "unknown",
                "proof_preservation_refs": ["proof:preservation"],
                "proof_preservation_status": "unknown",
            },
        },
        {"event_manifest_digest": "sha256:expected", "require_policy_version": True},
    )
    codes = {block.failure_code for block in decision.blocking_set}
    assert decision.decision == "recompute"
    assert FailureCode.DIGEST_MISMATCH in codes
    assert FailureCode.POLICY_BLOCK in codes
    assert FailureCode.CHECKER_UNKNOWN in codes
    assert decision.frame_transfer_ref == "proof:frame"
    assert decision.proof_preservation_refs == ("proof:preservation",)
    source_paths = {ref.source_path for block in decision.blocking_set for ref in block.reason_refs}
    assert {
        "/manifest_digest",
        "/payload/policy_version",
        "/payload/dependency_transfer_status",
        "/payload/frame_transfer_status",
        "/payload/proof_preservation_status",
    }.issubset(source_paths)

    issued_with_frame = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
        frame={"frame_digest": "frame:old"},
    )
    assert isinstance(issued_with_frame, IssueCertificate)
    frame_change = update_certificate(
        issued_with_frame,
        {
            "event_id": "evt-frame-change",
            "certificate_id": issued_with_frame.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {"frame_digest": "frame:new"},
        },
    )
    assert any(
        block.failure_code is FailureCode.OUT_OF_FRAME for block in frame_change.blocking_set
    )
    assert any(
        ref.source_path == "/payload/frame_transfer_ref"
        for block in frame_change.blocking_set
        for ref in block.reason_refs
    )


def test_update_certificate_maintains_when_transfer_refs_are_accepted() -> None:
    issued = _issued_lifecycle_certificate()
    symbolic = update_certificate(
        issued,
        {
            "event_id": "evt-symbolic-transfer",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {
                "dependency_updates": ["sensor-calibration"],
                "dependency_transfer_ref": "proof:dependency",
                "dependency_transfer_status": "accepted",
                "proof_preservation_refs": ["proof:preservation"],
                "proof_preservation_status": "accepted",
            },
        },
    )
    assert symbolic.decision == "recompute"
    assert any(block.failure_code is FailureCode.CHECKER_UNKNOWN for block in symbolic.blocking_set)
    assert {ref.source_path for block in symbolic.blocking_set for ref in block.reason_refs} == {
        "/payload/dependency_transfer_status",
        "/payload/proof_preservation_status",
    }

    shallow_artifact_status = update_certificate(
        issued,
        {
            "event_id": "evt-shallow-transfer",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {
                "dependency_updates": ["sensor-calibration"],
                "dependency_transfer_ref": "artifact:dependency-transfer",
                "dependency_transfer_status": "accepted",
                "proof_preservation_refs": ["artifact:proof-preservation"],
                "proof_preservation_status": "accepted",
            },
        },
    )
    assert shallow_artifact_status.decision == "recompute"
    assert {
        ref.source_path
        for block in shallow_artifact_status.blocking_set
        for ref in block.reason_refs
    } == {
        "/payload/dependency_transfer_status",
        "/payload/proof_preservation_status",
    }

    unproved_trace_policy = update_certificate(
        issued,
        {
            "event_id": "evt-trace-policy",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {"policy_version": "update"},
        },
        {
            "policy_version": "update",
            "trace_class": ("audit",),
            "causal_cut": ("evt-parent",),
        },
    )
    assert unproved_trace_policy.decision == "recompute"
    assert {
        "/policy/trace_class_ref",
        "/policy/causal_cut_ref",
    }.issubset(
        {
            ref.source_path
            for block in unproved_trace_policy.blocking_set
            for ref in block.reason_refs
        }
    )

    unproved_event_set_policy = update_certificate(
        issued,
        {
            "event_id": "evt-event-set-policy",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {"policy_version": "update"},
        },
        {
            "policy_version": "update",
            "accepted_event_ids": ("evt-event-set-policy",),
        },
    )
    assert unproved_event_set_policy.decision == "recompute"
    assert any(
        ref.source_path == "/policy/accepted_event_ids_ref"
        for block in unproved_event_set_policy.blocking_set
        for ref in block.reason_refs
    )

    event_set_without_event = update_certificate(
        issued,
        {
            "event_id": "evt-ignored-by-policy",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {"policy_version": "update"},
        },
        {
            "policy_version": "update",
            "accepted_event_ids": ("evt-other",),
            "accepted_event_ids_ref": "artifact:accepted-events",
            "accepted_event_ids_status": {
                "status": "accepted",
                "artifact_ref": "artifact:accepted-events",
                "artifact_digest": "sha256:accepted-events",
                "payload": {
                    "event_id": "evt-ignored-by-policy",
                    "accepted_event_ids": ["evt-other"],
                },
            },
        },
    )
    assert event_set_without_event.decision == "recompute"
    assert any(
        ref.source_path == "/policy/accepted_event_ids"
        for block in event_set_without_event.blocking_set
        for ref in block.reason_refs
    )

    event_set_outside_cut = update_certificate(
        issued,
        {
            "event_id": "evt-current-cut",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {"policy_version": "update"},
        },
        {
            "policy_version": "update",
            "accepted_event_ids": ("evt-current-cut", "evt-missing-from-cut"),
            "accepted_event_ids_ref": "artifact:accepted-events",
            "accepted_event_ids_status": {
                "status": "accepted",
                "artifact_ref": "artifact:accepted-events",
                "artifact_digest": "sha256:accepted-events-cut-conflict",
                "proof_kind": "accepted_event_set",
                "payload": {
                    "event_id": "evt-current-cut",
                    "accepted_event_ids": ["evt-current-cut", "evt-missing-from-cut"],
                },
            },
            "causal_cut": ("evt-parent",),
            "causal_cut_ref": "artifact:causal-cut",
            "causal_cut_status": {
                "status": "accepted",
                "artifact_ref": "artifact:causal-cut",
                "artifact_digest": "sha256:causal-cut-conflict",
                "proof_kind": "causal_cut",
                "payload": {
                    "event_id": "evt-current-cut",
                    "causal_cut": ["evt-parent"],
                },
            },
        },
    )
    assert event_set_outside_cut.decision == "recompute"
    assert any(
        block.failure_code is FailureCode.TRACE_CONFLICT
        and any(ref.source_path == "/policy/accepted_event_ids" for ref in block.reason_refs)
        for block in event_set_outside_cut.blocking_set
    )
    assert validate_named_schema(
        event_set_outside_cut.to_json(),
        "lifecycle-decision.schema.json",
    ).passed

    unproved_log_root = update_certificate(
        issued,
        {
            "event_id": "evt-log-root-unproved",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "hashes": ["sha256:log-root"],
            "payload": {"policy_version": "update"},
        },
        {"policy_version": "update", "log_root": "sha256:log-root"},
    )
    assert unproved_log_root.decision == "recompute"
    assert unproved_log_root.log_root == "sha256:log-root"
    assert any(
        ref.source_path == "/policy/log_root_ref"
        for block in unproved_log_root.blocking_set
        for ref in block.reason_refs
    )

    mismatched_log_root = update_certificate(
        issued,
        {
            "event_id": "evt-log-root-mismatch",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "hashes": ["sha256:log-root"],
            "payload": {"policy_version": "update"},
        },
        {
            "policy_version": "update",
            "log_root": "sha256:log-root",
            "log_root_ref": "artifact:log-root",
            "log_root_status": {
                "status": "accepted",
                "artifact_ref": "artifact:log-root",
                "artifact_digest": "sha256:log-root-proof",
                "proof_kind": "log_root",
                "payload": {"event_id": "evt-log-root-mismatch", "log_root": "sha256:other"},
            },
        },
    )
    assert mismatched_log_root.decision == "recompute"
    assert any(
        ref.source_path == "/policy/log_root_status"
        for block in mismatched_log_root.blocking_set
        for ref in block.reason_refs
    )

    accepted_log_root = update_certificate(
        issued,
        {
            "event_id": "evt-log-root-accepted",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "hashes": ["sha256:log-root"],
            "payload": {"policy_version": "update"},
        },
        {
            "policy_version": "update",
            "log_root": "sha256:log-root",
            "log_root_ref": "artifact:log-root",
            "log_root_status": {
                "status": "accepted",
                "artifact_ref": "artifact:log-root",
                "artifact_digest": "sha256:log-root-proof",
                "proof_kind": "log_root",
                "payload": {"event_id": "evt-log-root-accepted", "log_root": "sha256:log-root"},
            },
        },
    )
    assert accepted_log_root.decision == "maintain"
    assert accepted_log_root.accepted is True
    assert accepted_log_root.log_root == "sha256:log-root"
    assert accepted_log_root.log_root_ref == "artifact:log-root"
    assert validate_named_schema(
        accepted_log_root.to_json(),
        "lifecycle-decision.schema.json",
    ).passed

    wrong_lifecycle_proof_kind = update_certificate(
        issued,
        {
            "event_id": "evt-wrong-lifecycle-proof-kind",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "manifest_digest": "sha256:wrong-kind",
            "hashes": ["sha256:wrong-kind"],
            "payload": {"policy_version": "update"},
        },
        {
            "policy_version": "update",
            "event_manifest_digest": "sha256:wrong-kind",
            "event_manifest_digest_ref": "artifact:event-manifest-digest",
            "event_manifest_digest_status": {
                "status": "accepted",
                "artifact_ref": "artifact:event-manifest-digest",
                "artifact_digest": "sha256:event-manifest-digest-wrong-kind",
                "proof_kind": "schema_validation",
                "payload": {
                    "event_id": "evt-wrong-lifecycle-proof-kind",
                    "event_manifest_digest": "sha256:wrong-kind",
                },
            },
            "accepted_event_ids": ("evt-wrong-lifecycle-proof-kind",),
            "accepted_event_ids_ref": "artifact:accepted-events",
            "accepted_event_ids_status": {
                "status": "accepted",
                "artifact_ref": "artifact:accepted-events",
                "artifact_digest": "sha256:accepted-events-wrong-kind",
                "proof_kind": "schema_validation",
                "payload": {
                    "event_id": "evt-wrong-lifecycle-proof-kind",
                    "accepted_event_ids": ["evt-wrong-lifecycle-proof-kind"],
                },
            },
        },
    )
    assert wrong_lifecycle_proof_kind.decision == "recompute"
    assert {
        "/policy/event_manifest_digest_status",
        "/policy/accepted_event_ids_status",
    }.issubset(
        {
            ref.source_path
            for block in wrong_lifecycle_proof_kind.blocking_set
            for ref in block.reason_refs
        }
    )
    assert all(
        block.failure_code is FailureCode.ARTIFACT_CONFLICT
        for block in wrong_lifecycle_proof_kind.blocking_set
        if block.reason_refs[0].source_path
        in {
            "/policy/event_manifest_digest_status",
            "/policy/accepted_event_ids_status",
        }
    )

    mismatched_lifecycle_proof_payload = update_certificate(
        issued,
        {
            "event_id": "evt-lifecycle-proof-payload-mismatch",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {"policy_version": "update"},
        },
        {
            "policy_version": "update",
            "accepted_event_ids": ("evt-lifecycle-proof-payload-mismatch",),
            "accepted_event_ids_ref": "artifact:accepted-events",
            "accepted_event_ids_status": {
                "status": "accepted",
                "artifact_ref": "artifact:accepted-events",
                "artifact_digest": "sha256:accepted-events-payload-mismatch",
                "proof_kind": "accepted_event_set",
                "payload": {
                    "event_id": "evt-other",
                    "accepted_event_ids": ["evt-lifecycle-proof-payload-mismatch"],
                },
            },
            "trace_class": ("audit",),
            "trace_class_ref": "artifact:trace-class",
            "trace_class_status": {
                "status": "accepted",
                "artifact_ref": "artifact:other-trace-class",
                "artifact_digest": "sha256:trace-class-ref-mismatch",
                "proof_kind": "trace_class",
                "payload": {
                    "event_id": "evt-lifecycle-proof-payload-mismatch",
                    "trace_class": ["audit"],
                },
            },
        },
    )
    assert mismatched_lifecycle_proof_payload.decision == "recompute"
    mismatch_by_path = {
        ref.source_path: block.failure_code
        for block in mismatched_lifecycle_proof_payload.blocking_set
        for ref in block.reason_refs
    }
    assert mismatch_by_path["/policy/accepted_event_ids_status"] is (FailureCode.ARTIFACT_CONFLICT)
    assert mismatch_by_path["/policy/trace_class_status"] is FailureCode.ARTIFACT_CONFLICT

    decision = update_certificate(
        issued,
        {
            "event_id": "evt-accepted-transfer",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "manifest_digest": "sha256:accepted",
            "hashes": ["sha256:accepted"],
            "payload": {
                "policy_version": "update",
                "dependency_updates": ["sensor-calibration"],
                "dependency_transfer_ref": "artifact:dependency-transfer",
                "dependency_transfer_status": {
                    "status": "accepted",
                    "artifact_ref": "artifact:dependency-transfer",
                    "artifact_digest": "sha256:dependency-transfer",
                    "proof_kind": "dependency_transfer",
                    "payload": {
                        "event_id": "evt-accepted-transfer",
                        "dependency_updates": ["sensor-calibration"],
                    },
                },
                "frame_digest": "frame:new",
                "frame_transfer_ref": "artifact:frame-transfer",
                "frame_transfer_status": {
                    "status": "pass",
                    "artifact_ref": "artifact:frame-transfer",
                    "artifact_digest": "sha256:frame-transfer",
                    "proof_kind": "frame_transfer",
                    "payload": {
                        "event_id": "evt-accepted-transfer",
                        "frame_digest": "frame:new",
                    },
                },
                "proof_preservation_refs": ["artifact:proof-preservation"],
                "proof_preservation_status": {
                    "status": "accepted",
                    "artifact_ref": ["artifact:proof-preservation"],
                    "artifact_digest": "sha256:proof-preservation",
                    "proof_kind": "proof_preservation",
                    "payload": {
                        "event_id": "evt-accepted-transfer",
                        "proof_preservation_refs": ["artifact:proof-preservation"],
                    },
                },
            },
        },
        {
            "event_manifest_digest": "sha256:accepted",
            "event_manifest_digest_ref": "artifact:event-manifest-digest",
            "event_manifest_digest_status": {
                "status": "accepted",
                "artifact_ref": "artifact:event-manifest-digest",
                "artifact_digest": "sha256:event-manifest-digest",
                "proof_kind": "event_manifest_digest",
                "payload": {
                    "event_id": "evt-accepted-transfer",
                    "event_manifest_digest": "sha256:accepted",
                },
            },
            "require_policy_version": True,
            "accepted_event_ids": ("evt-accepted-transfer",),
            "accepted_event_ids_ref": "artifact:accepted-events",
            "accepted_event_ids_status": {
                "status": "accepted",
                "artifact_ref": "artifact:accepted-events",
                "artifact_digest": "sha256:accepted-events",
                "proof_kind": "accepted_event_set",
                "payload": {
                    "event_id": "evt-accepted-transfer",
                    "accepted_event_ids": ["evt-accepted-transfer"],
                },
            },
            "trace_class": ("audit",),
            "trace_class_ref": "artifact:trace-class",
            "trace_class_status": {
                "status": "accepted",
                "artifact_ref": "artifact:trace-class",
                "artifact_digest": "sha256:trace-class",
                "proof_kind": "trace_class",
                "payload": {
                    "event_id": "evt-accepted-transfer",
                    "trace_class": ["audit"],
                },
            },
            "causal_cut": ("evt-parent",),
            "causal_cut_ref": "artifact:causal-cut",
            "causal_cut_status": {
                "status": "accepted",
                "artifact_ref": "artifact:causal-cut",
                "artifact_digest": "sha256:causal-cut",
                "proof_kind": "causal_cut",
                "payload": {
                    "event_id": "evt-accepted-transfer",
                    "causal_cut": ["evt-parent"],
                },
            },
        },
    )
    assert decision == "maintain"
    assert decision.accepted is True
    assert decision.accepted_event_ids == ("evt-accepted-transfer",)
    assert decision.event_manifest_digest_ref == "artifact:event-manifest-digest"
    assert decision.accepted_event_ids_ref == "artifact:accepted-events"
    assert decision.trace_class_ref == "artifact:trace-class"
    assert decision.causal_cut_ref == "artifact:causal-cut"
    assert decision.blocking_set == ()
    assert validate_named_schema(decision.to_json(), "lifecycle-decision.schema.json").passed

    bare_artifact_status = update_certificate(
        issued,
        {
            "event_id": "evt-bare-transfer",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {
                "policy_version": "update",
                "dependency_updates": ["sensor-calibration"],
                "dependency_transfer_ref": "artifact:dependency-transfer",
                "dependency_transfer_status": {
                    "status": "accepted",
                    "artifact_ref": "artifact:dependency-transfer",
                    "proof_kind": "dependency_transfer",
                    "payload": {
                        "event_id": "evt-bare-transfer",
                        "dependency_updates": ["sensor-calibration"],
                    },
                },
            },
        },
        {"policy_version": "update"},
    )
    assert bare_artifact_status.decision == "recompute"
    assert any(
        ref.source_path == "/payload/dependency_transfer_status"
        for block in bare_artifact_status.blocking_set
        for ref in block.reason_refs
    )
    bare_status_json = bare_artifact_status.to_json()
    assert validate_named_schema(
        bare_status_json,
        "lifecycle-decision.schema.json",
    ).passed
    assert bare_status_json["reason_ref_records"][0]["source_artifact"].startswith("artifact:")
    assert bare_status_json["reason_ref_records"][0]["digest"].startswith("sha256:")

    pointer_bound_status = update_certificate(
        issued,
        {
            "event_id": "evt-pointer-bound-transfer",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "payload": {
                "policy_version": "update",
                "dependency_updates": ["sensor-calibration"],
                "dependency_transfer_ref": "artifact:dependency-transfer",
                "dependency_transfer_status": {
                    "status": "accepted",
                    "artifact_ref": "artifact:dependency-transfer",
                    "source_artifact": "artifact:dependency-transfer",
                    "source_path": "/proof",
                    "proof_kind": "dependency_transfer",
                    "payload": {
                        "event_id": "evt-pointer-bound-transfer",
                        "dependency_updates": ["sensor-calibration"],
                    },
                },
            },
        },
        {"policy_version": "update"},
    )
    assert pointer_bound_status.decision == "maintain"
    assert pointer_bound_status.accepted is True
    assert pointer_bound_status.blocking_set == ()


def test_operational_authority_reconstructs_from_observation_records() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
        frame={
            "frame_id": "frame:demo",
            "scope": ["demo"],
            "policy": {"adequacy_direction": "positive"},
            "completion_interface_ref": "completion:demo",
        },
    )
    assert isinstance(issued, IssueCertificate)
    legacy_issued = replace(
        issued,
        artifact_ref_records=(),
        set_ref_records=(),
        obligation_ref_records=(),
        proof_ref_records=(),
    )
    legacy_profile = legacy_issued.minimum_profile()
    assert legacy_profile["artifact_ref_records"]
    assert legacy_profile["set_ref_records"]
    assert legacy_profile["obligation_ref_records"]
    assert legacy_profile["proof_ref_records"]
    result = check_authority(
        issued,
        {
            "mode": "operational",
            "claim": "safe-temp",
            "horizon": 1,
            "anchor": "anchor:issue",
            "scope": ["demo"],
            "frame": "frame:demo",
        },
        {
            "status_time": "2026-01-01T00:00:00Z",
            "observation_records": [
                {
                    "r": 0,
                    "represented_prefix": [{"temp": "70"}],
                    "operational_prefix": [{"temp": "70"}],
                    "operational_completions": [[{"temp": "70"}, {"temp": "70"}]],
                    "prefix_adjudication": "accept",
                    "target_adjudication": "accept",
                    "observation_proof_ref": {
                        "proof_status": "accepted",
                        "artifact_ref": "artifact:observation-proof",
                        "proof_kind": "observation_cut",
                        "artifact_digest": "sha256:observation-proof",
                        "payload": {
                            "status_time": "2026-01-01T00:00:00Z",
                            "time_basis": issued.time_basis_ref,
                            "event_order": issued.event_order_commitment_ref,
                            "frame_id": "frame:demo",
                        },
                    },
                    "calibration_ref": {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:calibration-demo",
                        "proof_kind": "calibration",
                        "artifact_digest": "sha256:calibration",
                    },
                    "latency_ref": {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:latency-demo",
                        "proof_kind": "latency",
                        "artifact_digest": "sha256:latency",
                    },
                    "dependency_ref": {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:dependency-demo",
                        "proof_kind": "dependency",
                        "artifact_digest": "sha256:dependency",
                    },
                    "event_order_ref": {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:event-order-demo",
                        "proof_kind": "event_order",
                        "artifact_digest": "sha256:event-order",
                    },
                    "measurement_proof_ref": {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:measurement-proof-demo",
                        "proof_kind": "measurement",
                        "artifact_digest": "sha256:measurement",
                    },
                    "representation_relation": {
                        "relation_id": "representation:demo",
                        "operational_prefix": [{"temp": "70"}],
                        "represented_prefix": [{"temp": "70"}],
                        "proof_ref": "artifact:representation-proof-demo",
                    },
                    "representation_proof_ref": "artifact:representation-proof-demo",
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
        },
        allow_synthetic_trust=True,
    )
    assert not isinstance(result, type(validate_artifact_ref(ArtifactRef("x", "json"))))
    assert result.authority_outcome.code == OperationalCode.ACCEPT.value


def test_artifact_bundle_full_replay_recomputes_authority_from_accepted_clauses(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    issued_profile = issued.minimum_profile()
    assert issued_profile["artifact_ref_records"]
    issue_artifact_record = issued_profile["artifact_ref_records"][0]
    assert issue_artifact_record["artifact_id"] in issued_profile["artifact_refs"]
    assert str(issue_artifact_record["digest_value"]).startswith("sha256:")
    assert issued_profile["obligation_ref_records"]
    assert issued_profile["set_ref_records"]
    assert issued_profile["proof_ref_records"]
    issue_set_record = issued_profile["set_ref_records"][0]
    assert issue_set_record["carrier_ref"] in issued_profile["set_refs"]
    assert str(issue_set_record["soundness_ref"]).startswith("artifact:")
    assert (
        issue_set_record["digest"]
        == set_ref(
            issue_set_record["carrier_ref"],
            issue_set_record["encoding_kind"],
            issue_set_record["constraint_ref"],
            issue_set_record["approximation_kind"],
            issue_set_record["soundness_ref"],
        ).digest
    )
    issue_proof_record = issued_profile["proof_ref_records"][0]
    assert issue_proof_record["status"] == "accepted"
    assert str(issue_proof_record["source_artifact"]).startswith("artifact:")
    assert str(issue_proof_record["source_path"]).startswith("/")
    assert str(issue_proof_record["digest"]).startswith("sha256:")
    assert issue_proof_record["proof_id"] in issued_profile["proof_refs"]
    assert validate_named_schema(issued_profile, "issue-certificate.schema.json").passed
    missing_issue_proof = json.loads(json.dumps(issued_profile))
    missing_issue_proof["proof_refs"] = []
    missing_issue_proof["proof_ref_records"] = []
    missing_issue_proof_schema = validate_named_schema(
        missing_issue_proof,
        "issue-certificate.schema.json",
    )
    assert not missing_issue_proof_schema.passed
    assert missing_issue_proof_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    missing_issue_set_ref_records = json.loads(json.dumps(issued_profile))
    missing_issue_set_ref_records.pop("set_ref_records")
    missing_issue_set_ref_records_schema = validate_named_schema(
        missing_issue_set_ref_records,
        "issue-certificate.schema.json",
    )
    assert not missing_issue_set_ref_records_schema.passed
    assert (
        missing_issue_set_ref_records_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    )
    missing_issue_artifact_records = json.loads(json.dumps(issued_profile))
    missing_issue_artifact_records.pop("artifact_ref_records")
    missing_issue_artifact_records_schema = validate_named_schema(
        missing_issue_artifact_records,
        "issue-certificate.schema.json",
    )
    assert not missing_issue_artifact_records_schema.passed
    assert (
        missing_issue_artifact_records_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    )
    unknown_issue_proof = json.loads(json.dumps(issued_profile))
    unknown_issue_proof["proof_ref_records"][0]["status"] = "unknown"
    unknown_issue_proof["proof_ref_records"][0].pop("digest", None)
    unknown_issue_proof_schema = validate_named_schema(
        unknown_issue_proof,
        "issue-certificate.schema.json",
    )
    assert not unknown_issue_proof_schema.passed
    assert unknown_issue_proof_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    proposed = {
        "mode": "assertion",
        "claim": "safe-temp",
        "horizon": 1,
        "anchor": "anchor:issue",
        "scope": ["demo"],
    }
    status = {"status_time": "2026-01-01T00:00:00Z"}
    evidence = {
        "artifact_id": "evidence:model",
        "kind": "finite-model",
        "checker_status": "pass",
    }
    admission = {
        "kind": "finite-model",
        "source": "evidence:model",
        "target": "semantics",
        "clause": {
            "state_space": [{"temp": "70"}],
            "initial_states": [{"temp": "70"}],
            "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        },
        "contract_id": "contract:model",
        "checker_transcript_ref": "artifact:transcript",
        "obligation_refs": ["artifact:obligation#/obligation"],
    }
    entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(proposed, ArtifactRole.PROPOSED_USE, "artifact:use"),
        _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
        _entry(evidence, ArtifactRole.EVIDENCE, "evidence:model"),
        _entry(admission, ArtifactRole.ADMISSION, "artifact:admission"),
        _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
        _entry(
            {"obligation": _obligation_payload()}, ArtifactRole.OBLIGATION, "artifact:obligation"
        ),
        *_kernel_proof_entries(),
    ]
    refs = [entry["artifact_ref"] for entry in entries]
    source = {
        "bundle_id": "bundle:authority-replay",
        "manifest": {
            "manifest_id": "manifest:authority-replay",
            "root_artifact_id": "artifact:cert",
            "artifact_refs": refs,
            "dependency_order": [str(ref["artifact_id"]) for ref in refs],
        },
        "artifacts": entries,
    }
    bundle = artifact_bundle_from_json(_with_manifest_digest(source))

    report = validate_artifact_bundle(bundle, full_replay=True)
    assert report.passed
    assert report.authority_view is not None
    assert report.authority_outcome_digest is not None
    assert report.authority_view.authority_outcome.code == "assert"
    assert "trust-assumption:synthetic-authority-input" not in report.authority_view.obligation_refs
    assert not any(
        ref.reason_id == "reason:synthetic-authority-input"
        for ref in report.authority_view.reason_refs
    )
    stage_names = [result.stage.value for result in report.stage_results]
    assert stage_names.count("Replay") == 1
    assert stage_names[-4:] == ["Replay", "GuardEvaluate", "KernelCheck", "AuthorityEmit"]
    assert report.stage_artifacts["KernelCheck"]
    assert report.kernel_view_ref is not None
    assert any(ref.proof_id == "artifact:kernel-proof" for ref in report.proof_refs)
    assert report.runtime_summary_digest is not None
    assert report.authority_runtime_summary is not None
    assert validate_named_schema(
        report.authority_runtime_summary,
        "resolved-authority-runtime.schema.json",
    ).passed
    assert report.authority_runtime_summary["artifact_ref_records"]
    assert report.authority_runtime_summary["artifact_ref_records"][0]["digest_value"].startswith(
        "sha256:"
    )
    assert report.authority_runtime_summary["proof_ref_records"]
    assert (
        report.authority_runtime_summary["proof_ref_records"][0]["proof_id"]
        == "artifact:kernel-proof"
    )
    trust_source = {
        "assumption_id": "trust:replay",
        "target": "semantics",
        "scope": ["legacy-raw-bundle"],
        "reason_refs": ["artifact:reason#/reason"],
        "reason_ref_records": [_reason_ref_record(message="accepted migration assumption")],
        "obligation_refs": ["artifact:obligation#/obligation"],
        "checker_transcript_ref": "artifact:trust-transcript",
    }
    trust_entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(proposed, ArtifactRole.PROPOSED_USE, "artifact:use"),
        _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
        _entry(trust_source, ArtifactRole.TRUST_ASSUMPTION, "artifact:trust"),
        _entry(
            {"status": "pass", "transcript": "accepted trust"},
            ArtifactRole.OTHER,
            "artifact:trust-transcript",
        ),
        _entry(
            {"obligation": _obligation_payload()},
            ArtifactRole.OBLIGATION,
            "artifact:obligation",
        ),
        _entry({"reason": "accepted migration assumption"}, ArtifactRole.REASON, "artifact:reason"),
        *_kernel_proof_entries(),
    ]
    trust_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:authority-trust-replay",
                "manifest": {
                    "manifest_id": "manifest:authority-trust-replay",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in trust_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in trust_entries
                    ],
                },
                "artifacts": trust_entries,
            }
        ),
        full_replay=True,
    )
    assert trust_report.passed
    assert trust_report.authority_view is not None
    assert "trust:replay" in trust_report.authority_view.obligation_refs

    symbolic_trust_entries = [
        (
            _entry(
                {**trust_source, "reason_refs": ["accepted migration assumption"]},
                ArtifactRole.TRUST_ASSUMPTION,
                "artifact:trust",
            )
            if entry["role"] == ArtifactRole.TRUST_ASSUMPTION.value
            else entry
        )
        for entry in trust_entries
    ]
    symbolic_trust_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:authority-symbolic-trust-replay",
                "manifest": {
                    "manifest_id": "manifest:authority-symbolic-trust-replay",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in symbolic_trust_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in symbolic_trust_entries
                    ],
                },
                "artifacts": symbolic_trust_entries,
            }
        ),
        full_replay=True,
    )
    assert symbolic_trust_report.authority_view is None
    assert symbolic_trust_report.final_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )
    assert symbolic_trust_report.final_result.reason_refs[0].source_path.endswith("/reason_refs/0")

    assert report.replay_trace is not None
    assert report.replay_trace["stage_traces"]
    records_by_kind = {record.record_kind: record for record in report.protocol_records}
    protocol_record_ids = {record.record_id for record in report.protocol_records}
    for stage_trace in report.replay_trace["stage_traces"]:
        assert set(stage_trace["record_refs"]).issubset(protocol_record_ids)
    assert any(
        item not in protocol_record_ids
        for item in report.stage_artifacts[ValidationStage.KERNEL_CHECK.value]
    )
    kernel_record_json = records_by_kind["KernelView"].to_json()
    assert kernel_record_json["proof_ref_records"]
    assert kernel_record_json["proof_ref_records"][0]["proof_id"] == "artifact:kernel-proof"
    assert records_by_kind["StatusObservationContext"].payload["status_time"] == (
        "2026-01-01T00:00:00Z"
    )
    assert records_by_kind["ObservationCut"].payload["record_count"] == len(
        status.get("observation_records", ())
    )
    assert records_by_kind["ObservationCut"].payload["construction_sources"]["strict_replay"]
    assert records_by_kind["PrefixView"].payload["guard_records"]
    assert (
        records_by_kind["ResidualContext"].payload["compiled_bundle_ref"]
        == issued.compiled_semantics_ref
    )
    assert (
        records_by_kind["ResidualContext"].payload["construction_sources"]["compiled_bundle_ref"]
        == issued.compiled_semantics_ref
    )
    assert "completion_admission_ref" in records_by_kind["CompletionAdmission"].payload
    assert "fiber_assoc_view_ref" in records_by_kind["FiberAssocView"].payload
    assert "adjudication_views_ref" in records_by_kind["AdjudicationViews"].payload
    assert (
        records_by_kind["KernelView"].payload["compiled_bundle_ref"]
        == issued.compiled_semantics_ref
    )
    assert records_by_kind["Agreement"].payload["authority_outcome"]["code"] == "assert"
    assert (
        "bundle:authority-replay:residual-context"
        in report.stage_artifacts[ValidationStage.GUARD_EVALUATE.value]
    )
    assert (
        "bundle:authority-replay:adjudication-views"
        in report.stage_artifacts[ValidationStage.AUTHORITY_EMIT.value]
    )
    assert all(
        validate_named_schema(record.to_json(), "protocol-record-artifact.schema.json").passed
        for record in report.protocol_records
    )
    kernel_record_json = records_by_kind["KernelView"].to_json()
    assert kernel_record_json["artifact_ref_records"]
    assert str(kernel_record_json["artifact_ref_records"][0]["digest_value"]).startswith("sha256:")
    assert validate_named_schema(report.replay_trace, "replay-trace.schema.json").passed
    report_json = to_jsonable(report)
    assert report_json["artifact_ref_records"]
    assert str(report_json["artifact_ref_records"][0]["digest_value"]).startswith("sha256:")
    assert report_json["protocol_records"][0]["payload"]["status_time"] == ("2026-01-01T00:00:00Z")
    assert report_json["replay_trace"]["stage_traces"]
    assert all(
        validate_named_schema(trace, "replay-stage-trace.schema.json").passed
        for trace in report_json["replay_trace"]["stage_traces"]
    )
    kernel_stage_trace = next(
        trace
        for trace in report_json["replay_trace"]["stage_traces"]
        if trace["stage"] == ValidationStage.KERNEL_CHECK.value
    )
    assert kernel_stage_trace["artifact_ref_records"]
    assert str(kernel_stage_trace["artifact_ref_records"][0]["digest_value"]).startswith("sha256:")
    assert kernel_stage_trace["proof_ref_records"]
    assert kernel_stage_trace["proof_ref_records"][0]["proof_id"] in report_json["proof_refs"]
    assert report_json["proof_refs"] == [
        record["proof_id"] for record in report_json["proof_ref_records"]
    ]
    assert report_json["proof_ref_records"][0]["source_path"].startswith("/")
    assert validate_named_schema(report_json, "pipeline-report.schema.json").passed
    missing_report_proof_records = json.loads(json.dumps(report_json))
    missing_report_proof_records.pop("proof_ref_records")
    missing_report_proof_records_schema = validate_named_schema(
        missing_report_proof_records,
        "pipeline-report.schema.json",
    )
    assert not missing_report_proof_records_schema.passed
    assert missing_report_proof_records_schema.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )
    missing_report_artifact_records = json.loads(json.dumps(report_json))
    missing_report_artifact_records.pop("artifact_ref_records")
    missing_report_artifact_records_schema = validate_named_schema(
        missing_report_artifact_records,
        "pipeline-report.schema.json",
    )
    assert not missing_report_artifact_records_schema.passed
    assert missing_report_artifact_records_schema.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )
    view_profile = report.authority_view.minimum_profile()
    assert view_profile["kernel_view_ref"] == report.kernel_view_ref
    assert view_profile["kernel_view_ref"] != report.authority_view.authority_outcome.code
    assert (
        view_profile["kernel_view_ref"]
        in report.stage_artifacts[ValidationStage.KERNEL_CHECK.value]
    )
    kernel_proof_record = next(
        record
        for record in view_profile["proof_ref_records"]
        if record["proof_id"] == "artifact:kernel-proof"
    )
    assert kernel_proof_record["source_artifact"] == "artifact:kernel-proof"
    assert kernel_proof_record["source_path"] == "/"
    assert str(kernel_proof_record["digest"]).startswith("sha256:")
    assert kernel_proof_record["status"] == "accepted"
    bad_proof_path_profile = json.loads(json.dumps(view_profile))
    bad_proof_path_profile["proof_ref_records"][0]["source_path"] = "relative"
    bad_proof_path_schema = validate_named_schema(
        bad_proof_path_profile,
        "status-authority-view.schema.json",
    )
    assert not bad_proof_path_schema.passed
    assert bad_proof_path_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID

    replay = replay_authority_from_bundle(bundle, strict_ledger=True)
    assert replay.context is not None
    assert replay.context.accepted_clause_records[0].checker_transcript_ref == "artifact:transcript"
    assert any(ref.proof_id == "artifact:kernel-proof" for ref in replay.context.proof_refs)
    assert replay.replay_trace is not None
    assert replay.replay_trace.runtime_summary_digest == report.runtime_summary_digest

    bad_admission_entries = [
        entry
        if entry["role"] != ArtifactRole.ADMISSION.value
        else _entry(
            {
                "kind": "finite-model",
                "source": "evidence:model",
                "target": "semantics",
                "clause": {},
            },
            ArtifactRole.ADMISSION,
            "artifact:admission",
        )
        for entry in entries
    ]
    bad_admission_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:authority-replay-bad-admission",
                "manifest": {
                    "manifest_id": "manifest:authority-replay-bad-admission",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in bad_admission_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in bad_admission_entries
                    ],
                },
                "artifacts": bad_admission_entries,
            }
        ),
        full_replay=True,
    )
    assert bad_admission_report.authority_view is None
    assert bad_admission_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert bad_admission_report.final_result.failure_records[0].code is (FailureCode.SCHEMA_INVALID)
    bad_report_json = to_jsonable(bad_admission_report)
    assert bad_report_json["failure_records"][0]["reason_ref_records"]
    assert bad_report_json["stage_blockers"][0]["reason_ref_records"]
    assert validate_named_schema(bad_report_json, "pipeline-report.schema.json").passed

    bundle_file = tmp_path / "authority-bundle.json"
    bundle_file.write_text(json.dumps(_with_manifest_digest(source)), encoding="utf-8")
    assert main(["validate-bundle", str(bundle_file), "--horizon", "1", "--full-replay"]) == 0
    cli_output = json.loads(capsys.readouterr().out)
    assert cli_output["replay_trace"]["stage_traces"]
    assert cli_output["replay_trace"]["runtime_summary_digest"] == report.runtime_summary_digest


def test_artifact_bundle_full_replay_failure_and_claim_certificate_paths() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    proposed = {
        "mode": "assertion",
        "claim": "safe-temp",
        "horizon": 1,
        "anchor": "anchor:issue",
        "scope": ["demo"],
    }
    status = {"status_time": "2026-01-01T00:00:00Z"}

    invalid_issue = _entry(
        {**to_jsonable(issued), "authority_outcome": {"code": "assert"}},
        ArtifactRole.ISSUE_CERTIFICATE,
        "artifact:cert",
    )
    invalid_issue_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:invalid-issue-certificate",
                "manifest": {
                    "manifest_id": "manifest:invalid-issue-certificate",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [invalid_issue["artifact_ref"]],
                },
                "artifacts": [invalid_issue],
            }
        ),
        full_replay=True,
    )
    assert invalid_issue_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert invalid_issue_report.final_result.failure_records[0].code is (FailureCode.SCHEMA_INVALID)

    missing_status_entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(proposed, ArtifactRole.PROPOSED_USE, "artifact:use"),
    ]
    missing_status_refs = [entry["artifact_ref"] for entry in missing_status_entries]
    missing_status_source = {
        "bundle_id": "bundle:missing-status",
        "manifest": {
            "manifest_id": "manifest:missing-status",
            "root_artifact_id": "artifact:cert",
            "artifact_refs": missing_status_refs,
        },
        "artifacts": missing_status_entries,
    }
    missing_status_report = validate_artifact_bundle(
        artifact_bundle_from_json(missing_status_source), full_replay=True
    )
    assert missing_status_report.final_result.failure_records[0].code is FailureCode.MISSING_REF

    missing_use_entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
    ]
    missing_use_refs = [entry["artifact_ref"] for entry in missing_use_entries]
    missing_use = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:missing-use",
                "manifest": {
                    "manifest_id": "manifest:missing-use",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": missing_use_refs,
                },
                "artifacts": missing_use_entries,
            }
        )
    )
    assert not missing_use.passed
    assert missing_use.validation_result.failure_records[0].code is FailureCode.MISSING_REF

    claim_entries = [
        _entry(_claim(), ArtifactRole.CLAIM, "artifact:claim"),
        _entry(_finite_bundle(), ArtifactRole.ASSUMPTION_BUNDLE, "artifact:bundle"),
        _entry(
            {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
            ArtifactRole.ANCHOR,
            "artifact:anchor",
        ),
        _entry(
            {"clock_id": "utc", "uncertainty_seconds": "0"},
            ArtifactRole.TIME_BASIS,
            "artifact:time-basis",
        ),
        _entry(proposed, ArtifactRole.PROPOSED_USE, "artifact:use"),
        _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
    ]
    claim_refs = [entry["artifact_ref"] for entry in claim_entries]
    claim_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:claim-replay",
            "manifest": {
                "manifest_id": "manifest:claim-replay",
                "root_artifact_id": "artifact:claim",
                "artifact_refs": claim_refs,
                "dependency_order": [str(ref["artifact_id"]) for ref in claim_refs],
            },
            "artifacts": claim_entries,
        }
    )
    replay = replay_authority_from_bundle(
        claim_bundle,
        resolved_refs=(
            ResolvedReference("artifact:obligation", "/obligation/ref", "sha256:o"),
            ResolvedReference("artifact:reason", "/reason/ref", "sha256:r"),
        ),
    )
    assert replay.passed
    assert replay.context is not None
    assert replay.context.resolved_obligations[0].source_path == "/obligation/ref"
    assert replay.context.resolved_reason_refs[0].source_path == "/reason/ref"


def test_reference_ledger_accepted_clause_and_cli_bundle_replay(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    proposed = {
        "mode": "assertion",
        "claim": "safe-temp",
        "horizon": 1,
        "anchor": "anchor:issue",
        "scope": ["demo"],
    }
    status = {"status_time": "2026-01-01T00:00:00Z"}
    accepted_clause = {
        "clause_id": "accepted:semantics",
        "target": "semantics",
        "clause": {
            "state_space": [{"temp": "70"}],
            "initial_states": [{"temp": "70"}],
            "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        },
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
                "digest": _obligation_digest(),
            }
        ],
        "reason_refs": [_reason_ref_record()],
        "validity_status": "pass",
        "monitor_status": "pass",
    }
    entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(proposed, ArtifactRole.PROPOSED_USE, "artifact:use"),
        _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
        _entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
        _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
        _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
        _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
        _entry(
            {
                "obligation": {
                    "obligation_id": "obligation:model",
                    "kind": "admission",
                    "status": "pass",
                }
            },
            ArtifactRole.OBLIGATION,
            "artifact:obligation",
        ),
        _entry({"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"),
        *_kernel_proof_entries(),
    ]
    refs = [entry["artifact_ref"] for entry in entries]
    source = {
        "bundle_id": "bundle:accepted-artifact",
        "manifest": {
            "manifest_id": "manifest:accepted-artifact",
            "root_artifact_id": "artifact:cert",
            "artifact_refs": refs,
            "dependency_order": [str(ref["artifact_id"]) for ref in refs],
        },
        "artifacts": entries,
    }
    bundle = artifact_bundle_from_json(_with_manifest_digest(source))
    ledger = build_reference_ledger(bundle, strict=True)
    assert ledger.passed
    assert any(ref.source_artifact == "artifact:transcript" for ref in ledger.resolved_refs)

    report = validate_pipeline(bundle, full_replay=True)
    assert isinstance(report, PipelineReport)
    assert report.passed
    assert report.accepted_clause_records[0].checker_transcript_ref == "artifact:transcript"
    assert any(ref.proof_id == "artifact:kernel-proof" for ref in report.proof_refs)
    assert report.protocol_records

    bundle_file = tmp_path / "authority-bundle.json"
    bundle_file.write_text(json.dumps(_with_manifest_digest(source)), encoding="utf-8")
    assert main(["replay-status", "--bundle", str(bundle_file)]) == 0
    assert "authority_outcome_digest" in capsys.readouterr().out

    invalid_accepted = dict(accepted_clause)
    invalid_accepted.pop("validity_status")
    invalid_entries = [
        entry
        if entry["role"] != ArtifactRole.ACCEPTED_CLAUSE.value
        else _entry(
            invalid_accepted,
            ArtifactRole.ACCEPTED_CLAUSE,
            "artifact:accepted",
        )
        for entry in entries
    ]
    invalid_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:accepted-artifact-schema-invalid",
            "manifest": {
                "manifest_id": "manifest:accepted-artifact-schema-invalid",
                "root_artifact_id": "artifact:cert",
                "artifact_refs": [entry["artifact_ref"] for entry in invalid_entries],
                "dependency_order": [
                    str(entry["artifact_ref"]["artifact_id"]) for entry in invalid_entries
                ],
            },
            "artifacts": invalid_entries,
        }
    )
    replay_invalid = replay_authority_from_bundle(invalid_bundle, strict_ledger=True)
    assert not replay_invalid.passed
    assert replay_invalid.validation_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert replay_invalid.validation_result.failure_records[0].code is (FailureCode.SCHEMA_INVALID)
    invalid_report = validate_pipeline(invalid_bundle, full_replay=True)
    assert isinstance(invalid_report, PipelineReport)
    assert invalid_report.authority_view is None
    assert invalid_report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    rejected_transcript_entries = [
        entry
        if str(entry["artifact_ref"]["artifact_id"]) != "artifact:transcript"
        else _entry({"status": "fail"}, ArtifactRole.OTHER, "artifact:transcript")
        for entry in entries
    ]
    rejected_transcript_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:accepted-artifact-rejected-transcript",
            "manifest": {
                "manifest_id": "manifest:accepted-artifact-rejected-transcript",
                "root_artifact_id": "artifact:cert",
                "artifact_refs": [entry["artifact_ref"] for entry in rejected_transcript_entries],
                "dependency_order": [
                    str(entry["artifact_ref"]["artifact_id"])
                    for entry in rejected_transcript_entries
                ],
            },
            "artifacts": rejected_transcript_entries,
        }
    )
    rejected_transcript_replay = replay_authority_from_bundle(
        rejected_transcript_bundle,
        strict_ledger=True,
    )
    assert not rejected_transcript_replay.passed
    assert rejected_transcript_replay.validation_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert (
        rejected_transcript_replay.validation_result.failure_records[0].reason_refs[0].source_path
        == "/checker_transcript_ref"
    )

    mismatched_contract_entries = [
        entry
        if str(entry["artifact_ref"]["artifact_id"]) != "artifact:contract"
        else _entry(
            {
                **_admission_contract(),
                "clause": {
                    "state_space": [{"temp": "71"}],
                    "initial_states": [{"temp": "71"}],
                    "transitions": [{"from": {"temp": "71"}, "to": {"temp": "71"}}],
                },
            },
            ArtifactRole.ADMISSION,
            "artifact:contract",
        )
        for entry in entries
    ]
    mismatched_contract_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-contract-mismatch",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-contract-mismatch",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in mismatched_contract_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in mismatched_contract_entries
                    ],
                },
                "artifacts": mismatched_contract_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not mismatched_contract_replay.passed
    assert mismatched_contract_replay.validation_result.failure_records[0].code is (
        FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        mismatched_contract_replay.validation_result.failure_records[0].reason_refs[0].source_path
        == "/clause"
    )

    transcript_mismatch_replay_entries = [
        entry
        if str(entry["artifact_ref"]["artifact_id"]) != "artifact:contract"
        else _entry(
            {
                **_admission_contract(),
                "checker_transcript_ref": "artifact:other-transcript",
            },
            ArtifactRole.ADMISSION,
            "artifact:contract",
        )
        for entry in entries
    ]
    transcript_mismatch_replay_entries.append(
        _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:other-transcript")
    )
    transcript_mismatch_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-transcript-mismatch",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-transcript-mismatch",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in transcript_mismatch_replay_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in transcript_mismatch_replay_entries
                    ],
                },
                "artifacts": transcript_mismatch_replay_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not transcript_mismatch_replay.passed
    assert transcript_mismatch_replay.validation_result.failure_records[0].code is (
        FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        transcript_mismatch_replay.validation_result.failure_records[0].reason_refs[0].source_path
        == "/checker_transcript_ref"
    )

    evidence_kind_mismatch_replay_entries = [
        entry
        if str(entry["artifact_ref"]["artifact_id"]) != "artifact:evidence"
        else _entry(
            {**_evidence_artifact(), "kind": "other-model"},
            ArtifactRole.EVIDENCE,
            "artifact:evidence",
        )
        for entry in entries
    ]
    evidence_kind_mismatch_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-evidence-kind-mismatch",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-evidence-kind-mismatch",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in evidence_kind_mismatch_replay_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in evidence_kind_mismatch_replay_entries
                    ],
                },
                "artifacts": evidence_kind_mismatch_replay_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not evidence_kind_mismatch_replay.passed
    assert evidence_kind_mismatch_replay.validation_result.failure_records[0].code is (
        FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        evidence_kind_mismatch_replay.validation_result.failure_records[0]
        .reason_refs[0]
        .source_path
        == "/evidence_ref"
    )

    reference_digest_mismatch_replay_entries = [
        entry
        if str(entry["artifact_ref"]["artifact_id"]) != "artifact:contract"
        else _entry(
            {**_admission_contract(), "reference_digest": "sha256:missing"},
            ArtifactRole.ADMISSION,
            "artifact:contract",
        )
        for entry in entries
    ]
    reference_digest_mismatch_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-reference-digest-mismatch",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-reference-digest-mismatch",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in reference_digest_mismatch_replay_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in reference_digest_mismatch_replay_entries
                    ],
                },
                "artifacts": reference_digest_mismatch_replay_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not reference_digest_mismatch_replay.passed
    assert reference_digest_mismatch_replay.validation_result.failure_records[0].code is (
        FailureCode.DIGEST_MISMATCH
    )
    assert (
        reference_digest_mismatch_replay.validation_result.failure_records[0]
        .reason_refs[0]
        .source_path
        == "/evidence_ref"
    )

    reference_digest_match_replay_entries = [
        (
            _entry(
                {**_evidence_artifact(), "payload": {"digest": "sha256:accepted"}},
                ArtifactRole.EVIDENCE,
                "artifact:evidence",
            )
            if str(entry["artifact_ref"]["artifact_id"]) == "artifact:evidence"
            else _entry(
                {**_admission_contract(), "reference_digest": "sha256:accepted"},
                ArtifactRole.ADMISSION,
                "artifact:contract",
            )
            if str(entry["artifact_ref"]["artifact_id"]) == "artifact:contract"
            else entry
        )
        for entry in entries
    ]
    reference_digest_match_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-reference-digest-match",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-reference-digest-match",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in reference_digest_match_replay_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in reference_digest_match_replay_entries
                    ],
                },
                "artifacts": reference_digest_match_replay_entries,
            }
        ),
        strict_ledger=True,
    )
    assert reference_digest_match_replay.passed

    malformed_contract_replay_entries = [
        entry
        if str(entry["artifact_ref"]["artifact_id"]) != "artifact:contract"
        else _entry({"kind": "finite-model"}, ArtifactRole.ADMISSION, "artifact:contract")
        for entry in entries
    ]
    malformed_contract_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-malformed-contract",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-malformed-contract",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in malformed_contract_replay_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in malformed_contract_replay_entries
                    ],
                },
                "artifacts": malformed_contract_replay_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not malformed_contract_replay.passed
    assert malformed_contract_replay.validation_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )

    malformed_evidence_replay_entries = [
        entry
        if str(entry["artifact_ref"]["artifact_id"]) != "artifact:evidence"
        else _entry({"kind": "finite-model"}, ArtifactRole.EVIDENCE, "artifact:evidence")
        for entry in entries
    ]
    malformed_evidence_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-malformed-evidence",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-malformed-evidence",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in malformed_evidence_replay_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in malformed_evidence_replay_entries
                    ],
                },
                "artifacts": malformed_evidence_replay_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not malformed_evidence_replay.passed
    assert malformed_evidence_replay.validation_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )

    scalar_contract_ref_clause = {
        **accepted_clause,
        "contract_ref": "artifact:contract#/nested",
    }
    scalar_contract_ref_entries = [
        (
            _entry(scalar_contract_ref_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted")
            if entry["role"] == ArtifactRole.ACCEPTED_CLAUSE.value
            else _entry(
                {**_admission_contract(), "nested": "not-a-contract"},
                ArtifactRole.ADMISSION,
                "artifact:contract",
            )
            if str(entry["artifact_ref"]["artifact_id"]) == "artifact:contract"
            else entry
        )
        for entry in entries
    ]
    scalar_contract_ref_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-scalar-contract-ref",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-scalar-contract-ref",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in scalar_contract_ref_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in scalar_contract_ref_entries
                    ],
                },
                "artifacts": scalar_contract_ref_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not scalar_contract_ref_replay.passed
    assert scalar_contract_ref_replay.validation_result.failure_records[0].code is (
        FailureCode.MISSING_REF
    )
    assert (
        scalar_contract_ref_replay.validation_result.failure_records[0].reason_refs[0].source_path
        == "/contract_ref"
    )

    scalar_evidence_ref_clause = {
        **accepted_clause,
        "evidence_ref": "artifact:evidence#/nested",
    }
    scalar_evidence_ref_entries = [
        (
            _entry(scalar_evidence_ref_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted")
            if entry["role"] == ArtifactRole.ACCEPTED_CLAUSE.value
            else _entry(
                {**_evidence_artifact(), "nested": "not-evidence"},
                ArtifactRole.EVIDENCE,
                "artifact:evidence",
            )
            if str(entry["artifact_ref"]["artifact_id"]) == "artifact:evidence"
            else entry
        )
        for entry in entries
    ]
    scalar_evidence_ref_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-scalar-evidence-ref",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-scalar-evidence-ref",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in scalar_evidence_ref_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in scalar_evidence_ref_entries
                    ],
                },
                "artifacts": scalar_evidence_ref_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not scalar_evidence_ref_replay.passed
    assert scalar_evidence_ref_replay.validation_result.failure_records[0].code is (
        FailureCode.MISSING_REF
    )
    assert (
        scalar_evidence_ref_replay.validation_result.failure_records[0].reason_refs[0].source_path
        == "/evidence_ref"
    )

    monitor_required = {**accepted_clause, "monitor_required": True}
    monitor_entries = [
        entry
        if entry["role"] != ArtifactRole.ACCEPTED_CLAUSE.value
        else _entry(
            monitor_required,
            ArtifactRole.ACCEPTED_CLAUSE,
            "artifact:accepted",
        )
        for entry in entries
    ]
    monitor_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:accepted-artifact-monitor-missing",
            "manifest": {
                "manifest_id": "manifest:accepted-artifact-monitor-missing",
                "root_artifact_id": "artifact:cert",
                "artifact_refs": [entry["artifact_ref"] for entry in monitor_entries],
                "dependency_order": [
                    str(entry["artifact_ref"]["artifact_id"]) for entry in monitor_entries
                ],
            },
            "artifacts": monitor_entries,
        }
    )
    monitor_replay = replay_authority_from_bundle(monitor_bundle, strict_ledger=True)
    assert not monitor_replay.passed
    assert monitor_replay.validation_result.failure_records[0].code is (
        FailureCode.VALIDITY_UNKNOWN
    )

    monitor_evidence_entries = [
        entry
        if entry["role"] != ArtifactRole.ACCEPTED_CLAUSE.value
        else _entry(
            {
                **accepted_clause,
                "monitor_required": True,
                "monitor_evidence_ref": "artifact:evidence",
            },
            ArtifactRole.ACCEPTED_CLAUSE,
            "artifact:accepted",
        )
        for entry in entries
    ]
    monitor_evidence_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-monitor-evidence",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-monitor-evidence",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in monitor_evidence_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in monitor_evidence_entries
                    ],
                },
                "artifacts": monitor_evidence_entries,
            }
        ),
        strict_ledger=True,
    )
    assert monitor_evidence_replay.passed

    monitor_completeness_mismatch_entries = [
        entry
        if entry["role"] != ArtifactRole.ACCEPTED_CLAUSE.value
        else _entry(
            {
                **accepted_clause,
                "monitor_required": True,
                "monitor_completeness_ref": "artifact:reason",
            },
            ArtifactRole.ACCEPTED_CLAUSE,
            "artifact:accepted",
        )
        for entry in entries
    ]
    monitor_completeness_mismatch_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:accepted-artifact-monitor-completeness-mismatch",
                "manifest": {
                    "manifest_id": "manifest:accepted-artifact-monitor-completeness-mismatch",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in monitor_completeness_mismatch_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in monitor_completeness_mismatch_entries
                    ],
                },
                "artifacts": monitor_completeness_mismatch_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not monitor_completeness_mismatch_replay.passed
    assert monitor_completeness_mismatch_replay.validation_result.failure_records[0].code is (
        FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        monitor_completeness_mismatch_replay.validation_result.failure_records[0]
        .reason_refs[0]
        .source_path
        == "/monitor_completeness_ref"
    )

    target_mismatch_entries = [
        entry
        if entry["role"] != ArtifactRole.ACCEPTED_CLAUSE.value
        else _entry(
            {**accepted_clause, "target": "compiled:foreign-bundle"},
            ArtifactRole.ACCEPTED_CLAUSE,
            "artifact:accepted",
        )
        for entry in entries
    ]
    target_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:accepted-artifact-target-mismatch",
            "manifest": {
                "manifest_id": "manifest:accepted-artifact-target-mismatch",
                "root_artifact_id": "artifact:cert",
                "artifact_refs": [entry["artifact_ref"] for entry in target_mismatch_entries],
                "dependency_order": [
                    str(entry["artifact_ref"]["artifact_id"]) for entry in target_mismatch_entries
                ],
            },
            "artifacts": target_mismatch_entries,
        }
    )
    target_mismatch_replay = replay_authority_from_bundle(
        target_mismatch_bundle,
        strict_ledger=True,
    )
    assert not target_mismatch_replay.passed
    assert target_mismatch_replay.validation_result.failure_records[0].code is (
        FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        target_mismatch_replay.validation_result.failure_records[0].reason_refs[0].source_path
        == "/target"
    )

    evidence_role_mismatch_entries = [
        entry
        if entry["role"] != ArtifactRole.ACCEPTED_CLAUSE.value
        else _entry(
            {**accepted_clause, "evidence_ref": "artifact:reason"},
            ArtifactRole.ACCEPTED_CLAUSE,
            "artifact:accepted",
        )
        for entry in entries
    ]
    evidence_role_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:accepted-artifact-evidence-role-mismatch",
            "manifest": {
                "manifest_id": "manifest:accepted-artifact-evidence-role-mismatch",
                "root_artifact_id": "artifact:cert",
                "artifact_refs": [
                    entry["artifact_ref"] for entry in evidence_role_mismatch_entries
                ],
                "dependency_order": [
                    str(entry["artifact_ref"]["artifact_id"])
                    for entry in evidence_role_mismatch_entries
                ],
            },
            "artifacts": evidence_role_mismatch_entries,
        }
    )
    evidence_role_mismatch_replay = replay_authority_from_bundle(
        evidence_role_mismatch_bundle,
        strict_ledger=True,
    )
    assert not evidence_role_mismatch_replay.passed
    assert evidence_role_mismatch_replay.validation_result.failure_records[0].code is (
        FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        evidence_role_mismatch_replay.validation_result.failure_records[0]
        .reason_refs[0]
        .source_path
        == "/evidence_ref"
    )

    unresolved_source = _artifact_bundle_source(
        {"reason": "missing"},
        reason_paths=("/absent",),
    )
    unresolved = build_reference_ledger(artifact_bundle_from_json(unresolved_source), strict=True)
    assert not unresolved.passed
    assert unresolved.unresolved_refs


def test_typed_reference_ledger_classifies_required_symbolic_and_embedded_refs() -> None:
    reason_target = {"reason": {"message": "ok"}}
    obligation_target = {
        "obligation": {
            "obligation_id": "obligation:active",
            "kind": "admission",
            "status": "pass",
            "scope": ["semantics"],
        }
    }
    owner = {
        "schema_profile_ref": "profile:symbolic",
        "canonicalization_profile_ref": "canonicalization:symbolic",
        "set_refs": ["set:symbolic"],
        "proof_refs": ["proof:symbolic"],
        "obligation_refs": ["artifact:obligation#/obligation"],
        "reason_refs": [{"source_artifact": "artifact:reason", "source_path": "/reason/message"}],
        "checker_transcript_ref": "artifact:transcript",
    }
    source = {
        "bundle_id": "bundle:typed-ledger",
        "manifest": {
            "manifest_id": "manifest:typed-ledger",
            "root_artifact_id": "artifact:owner",
        },
        "artifacts": [
            _entry(owner, ArtifactRole.OTHER, "artifact:owner"),
            _entry(reason_target, ArtifactRole.REASON, "artifact:reason"),
            _entry(obligation_target, ArtifactRole.OBLIGATION, "artifact:obligation"),
            _entry(
                {"status": "pass", "transcript": "accepted"},
                ArtifactRole.OTHER,
                "artifact:transcript",
            ),
        ],
    }
    ledger = build_reference_ledger(artifact_bundle_from_json(source), strict=True)
    assert ledger.passed
    assert ledger.by_kind(ReferenceKind.REASON)[0].resolved
    assert ledger.by_kind(ReferenceKind.OBLIGATION)[0].target_digest is not None
    assert ledger.by_kind(ReferenceKind.OBLIGATION)[0].expected_semantic_role == (
        ArtifactRole.OBLIGATION.value
    )
    assert ledger.by_kind(ReferenceKind.OBLIGATION)[0].active_scope_status == "pass"
    assert ledger.by_kind(ReferenceKind.OBLIGATION)[0].required_stage.value == "ReferenceResolve"
    assert ledger.by_kind(ReferenceKind.SET)[0].required is False
    assert ledger.by_kind(ReferenceKind.PROOF)[0].resolved is False
    assert ledger.by_kind(ReferenceKind.SCHEMA)
    assert ledger.by_kind(ReferenceKind.TRANSCRIPT)[0].resolved

    rejected_transcript = {
        **source,
        "artifacts": [
            _entry(
                {"checker_transcript_ref": "artifact:transcript"},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry({"status": "fail"}, ArtifactRole.OTHER, "artifact:transcript"),
        ],
    }
    transcript_failed = build_reference_ledger(
        artifact_bundle_from_json(rejected_transcript),
        strict=True,
    )
    assert not transcript_failed.passed
    assert transcript_failed.validation_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )

    reason_digest = manifest_digest(
        "ok",
        artifact_type="reference-target",
        schema_profile_digest="DFCC-Interop",
    )
    digest_bound_reason = {
        **source,
        "artifacts": [
            _entry(
                {
                    "reason_refs": [
                        {
                            "source_artifact": "artifact:reason",
                            "source_path": "/reason/message",
                            "digest": reason_digest,
                        }
                    ]
                },
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(reason_target, ArtifactRole.REASON, "artifact:reason"),
        ],
    }
    digest_bound = build_reference_ledger(
        artifact_bundle_from_json(digest_bound_reason),
        strict=True,
    )
    assert digest_bound.passed
    assert digest_bound.by_kind(ReferenceKind.REASON)[0].expected_digest == reason_digest

    digest_mismatch_reason = {
        **digest_bound_reason,
        "artifacts": [
            _entry(
                {
                    "reason_refs": [
                        {
                            "source_artifact": "artifact:reason",
                            "source_path": "/reason/message",
                            "digest": "sha256:wrong",
                        }
                    ]
                },
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(reason_target, ArtifactRole.REASON, "artifact:reason"),
        ],
    }
    digest_mismatch = build_reference_ledger(
        artifact_bundle_from_json(digest_mismatch_reason),
        strict=True,
    )
    assert not digest_mismatch.passed
    assert digest_mismatch.validation_result.failure_records[0].code is (
        FailureCode.DIGEST_MISMATCH
    )
    assert digest_mismatch.entries[0].expected_digest == "sha256:wrong"

    bad_pointer = {
        **source,
        "artifacts": [
            _entry(
                {"reason_refs": [{"source_artifact": "artifact:target", "source_path": "/absent"}]},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(reason_target, ArtifactRole.REASON, "artifact:reason"),
        ],
    }
    failed = build_reference_ledger(artifact_bundle_from_json(bad_pointer), strict=True)
    assert not failed.passed
    assert failed.entries[0].required
    assert failed.entries[0].resolved is False

    role_mismatch = {
        **source,
        "artifacts": [
            _entry(
                {"obligation_refs": ["artifact:reason#/reason/message"]},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(reason_target, ArtifactRole.REASON, "artifact:reason"),
        ],
    }
    mismatch = build_reference_ledger(artifact_bundle_from_json(role_mismatch), strict=True)
    assert not mismatch.passed
    assert mismatch.validation_result.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT

    reason_ref_without_role = to_jsonable(
        build_artifact_ref(reason_target, artifact_id="artifact:reason", artifact_type="json")
    )
    reason_ref_without_role.pop("semantic_role", None)
    missing_role_source = {
        **source,
        "artifacts": [
            _entry(
                {
                    "reason_refs": [
                        {"source_artifact": "artifact:reason", "source_path": "/reason/message"}
                    ]
                },
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            {
                "artifact_ref": reason_ref_without_role,
                "artifact": reason_target,
                "role": ArtifactRole.OTHER.value,
            },
        ],
    }
    missing_role = build_reference_ledger(
        artifact_bundle_from_json(missing_role_source), strict=True
    )
    assert not missing_role.passed
    assert missing_role.validation_result.failure_records[0].code is (FailureCode.ARTIFACT_CONFLICT)

    entry_role_source = {
        **missing_role_source,
        "artifacts": [
            missing_role_source["artifacts"][0],
            {
                "artifact_ref": reason_ref_without_role,
                "artifact": reason_target,
                "role": ArtifactRole.REASON.value,
            },
        ],
    }
    entry_role = build_reference_ledger(artifact_bundle_from_json(entry_role_source), strict=True)
    assert entry_role.passed
    assert entry_role.by_kind(ReferenceKind.REASON)[0].semantic_role == ArtifactRole.REASON.value

    inactive_obligation = {
        **source,
        "artifacts": [
            _entry(
                {"obligation_refs": ["artifact:obligation#/obligation"]},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(
                {
                    "obligation": {
                        "obligation_id": "obligation:inactive",
                        "kind": "admission",
                        "status": "fail",
                    }
                },
                ArtifactRole.OBLIGATION,
                "artifact:obligation",
            ),
        ],
    }
    inactive = build_reference_ledger(artifact_bundle_from_json(inactive_obligation), strict=True)
    assert not inactive.passed
    assert inactive.validation_result.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    unexpired_obligation = {
        **source,
        "reference_context": {
            "snapshot_id": "snapshot:unexpired-obligation",
            "status_time": "2026-01-02T00:00:00Z",
        },
        "artifacts": [
            _entry(
                {"obligation_refs": ["artifact:obligation#/obligation"]},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(
                {
                    "obligation": {
                        "obligation_id": "obligation:unexpired",
                        "kind": "admission",
                        "status": "pass",
                        "expiry": "2026-01-02T00:00:01Z",
                    }
                },
                ArtifactRole.OBLIGATION,
                "artifact:obligation",
            ),
        ],
    }
    unexpired = build_reference_ledger(
        artifact_bundle_from_json(unexpired_obligation),
        strict=True,
    )
    assert unexpired.passed
    assert unexpired.by_kind(ReferenceKind.OBLIGATION)[0].active_scope_status == "pass"

    expired_obligation = {
        **unexpired_obligation,
        "reference_context": {
            "snapshot_id": "snapshot:expired-obligation",
            "status_time": "2026-01-02T00:00:01Z",
        },
        "artifacts": [
            _entry(
                {"obligation_refs": ["artifact:obligation#/obligation"]},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(
                {
                    "obligation": {
                        "obligation_id": "obligation:expired",
                        "kind": "admission",
                        "status": "pass",
                        "expiry": "2026-01-02T00:00:00Z",
                    }
                },
                ArtifactRole.OBLIGATION,
                "artifact:obligation",
            ),
        ],
    }
    expired = build_reference_ledger(artifact_bundle_from_json(expired_obligation), strict=True)
    assert not expired.passed
    assert expired.entries[0].active_scope_status == "expired"
    assert expired.validation_result.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    unchecked_expiry = {
        **unexpired_obligation,
        "reference_context": {"snapshot_id": "snapshot:unchecked-expiry"},
    }
    unchecked = build_reference_ledger(artifact_bundle_from_json(unchecked_expiry), strict=True)
    assert not unchecked.passed
    assert unchecked.entries[0].active_scope_status == "not_checked"
    assert unchecked.validation_result.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    waived_without_reason = {
        **source,
        "artifacts": [
            _entry(
                {"obligation_refs": ["artifact:obligation#/obligation"]},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(
                {
                    "obligation": {
                        "obligation_id": "obligation:waived",
                        "kind": "admission",
                        "status": "waived",
                    }
                },
                ArtifactRole.OBLIGATION,
                "artifact:obligation",
            ),
        ],
    }
    waived_missing = build_reference_ledger(
        artifact_bundle_from_json(waived_without_reason),
        strict=True,
    )
    assert not waived_missing.passed
    assert waived_missing.validation_result.failure_records[0].code is (FailureCode.CHECKER_UNKNOWN)
    assert not validate_named_schema(
        {
            "obligation_id": "obligation:waived",
            "kind": "admission",
            "status": "waived",
        },
        "obligation-ref.schema.json",
    ).passed

    waived_unresolved_reason = {
        **source,
        "artifacts": [
            _entry(
                {"obligation_refs": ["artifact:obligation#/obligation"]},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(
                {
                    "obligation": {
                        "obligation_id": "obligation:waived",
                        "kind": "admission",
                        "status": "waived",
                        "reason_refs": ["artifact:missing#/reason"],
                    }
                },
                ArtifactRole.OBLIGATION,
                "artifact:obligation",
            ),
        ],
    }
    waived_unresolved = build_reference_ledger(
        artifact_bundle_from_json(waived_unresolved_reason),
        strict=True,
    )
    assert not waived_unresolved.passed
    assert waived_unresolved.validation_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )

    waived_with_reason = {
        **source,
        "artifacts": [
            _entry(
                {"obligation_refs": ["artifact:obligation#/obligation"]},
                ArtifactRole.OTHER,
                "artifact:owner",
            ),
            _entry(
                {
                    "obligation": {
                        "obligation_id": "obligation:waived",
                        "kind": "admission",
                        "status": "waived",
                        "reason_refs": ["artifact:reason#/reason/message"],
                    }
                },
                ArtifactRole.OBLIGATION,
                "artifact:obligation",
            ),
            _entry(reason_target, ArtifactRole.REASON, "artifact:reason"),
        ],
    }
    waived = build_reference_ledger(artifact_bundle_from_json(waived_with_reason), strict=True)
    assert waived.passed
    assert waived.by_kind(ReferenceKind.OBLIGATION)[0].active_scope_status == "waived"
    assert validate_named_schema(
        {
            "obligation_id": "obligation:waived",
            "kind": "admission",
            "status": "waived",
            "reason_refs": ["artifact:reason#/reason/message"],
        },
        "obligation-ref.schema.json",
    ).passed

    proof_artifact = {"status": "unknown", "proof_kind": "representation"}
    proof_ref = build_artifact_ref(
        proof_artifact,
        artifact_id="artifact:proof",
        artifact_type="json",
        semantic_role="proof",
    )
    proof_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:proof-status",
            "manifest": {
                "manifest_id": "manifest:proof-status",
                "root_artifact_id": "artifact:owner",
            },
            "artifacts": [
                _entry({"proof_refs": ["artifact:proof"]}, ArtifactRole.OTHER, "artifact:owner"),
                {
                    "artifact_ref": to_jsonable(proof_ref),
                    "artifact": proof_artifact,
                    "role": ArtifactRole.OTHER.value,
                },
            ],
        }
    )
    proof_failed = build_reference_ledger(proof_bundle, strict=True)
    assert not proof_failed.passed
    assert proof_failed.validation_result.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    accepted_proof_artifact = {"status": "pass", "proof_kind": "representation"}
    accepted_proof_digest = manifest_digest(
        accepted_proof_artifact,
        artifact_type="reference-target",
        schema_profile_digest="DFCC-Interop",
    )
    accepted_proof_ref = build_artifact_ref(
        accepted_proof_artifact,
        artifact_id="artifact:accepted-proof",
        artifact_type="json",
        semantic_role="proof",
    )
    proof_digest_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:proof-digest",
            "manifest": {
                "manifest_id": "manifest:proof-digest",
                "root_artifact_id": "artifact:owner",
            },
            "artifacts": [
                _entry(
                    {
                        "proof_refs": [
                            {
                                "artifact_ref": "artifact:accepted-proof",
                                "source_path": "",
                                "digest": accepted_proof_digest,
                            }
                        ]
                    },
                    ArtifactRole.OTHER,
                    "artifact:owner",
                ),
                {
                    "artifact_ref": to_jsonable(accepted_proof_ref),
                    "artifact": accepted_proof_artifact,
                    "role": ArtifactRole.OTHER.value,
                },
            ],
        }
    )
    proof_digest = build_reference_ledger(proof_digest_bundle, strict=True)
    assert proof_digest.passed
    assert proof_digest.by_kind(ReferenceKind.PROOF)[0].expected_digest == accepted_proof_digest

    proof_digest_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:proof-digest-mismatch",
            "manifest": {
                "manifest_id": "manifest:proof-digest-mismatch",
                "root_artifact_id": "artifact:owner",
            },
            "artifacts": [
                _entry(
                    {
                        "proof_refs": [
                            {
                                "artifact_ref": "artifact:accepted-proof",
                                "source_path": "",
                                "digest": "sha256:wrong",
                            }
                        ]
                    },
                    ArtifactRole.OTHER,
                    "artifact:owner",
                ),
                {
                    "artifact_ref": to_jsonable(accepted_proof_ref),
                    "artifact": accepted_proof_artifact,
                    "role": ArtifactRole.OTHER.value,
                },
            ],
        }
    )
    proof_digest_mismatch = build_reference_ledger(proof_digest_mismatch_bundle, strict=True)
    assert not proof_digest_mismatch.passed
    assert proof_digest_mismatch.validation_result.failure_records[0].code is (
        FailureCode.DIGEST_MISMATCH
    )

    embedded = {
        "claim_ref": "claim:embedded",
        "claim_source": _claim(),
        "obligation_refs": ["obligation:symbolic"],
    }
    embedded_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:embedded",
            "manifest": {
                "manifest_id": "manifest:embedded",
                "root_artifact_id": "artifact:embedded",
            },
            "artifacts": [_entry(embedded, ArtifactRole.ISSUE_CERTIFICATE, "artifact:embedded")],
        }
    )
    embedded_ledger = build_reference_ledger(embedded_bundle, strict=True)
    assert not embedded_ledger.passed
    assert embedded_ledger.validation_result.failure_records[0].code is FailureCode.MISSING_REF
    compatibility_embedded_ledger = build_reference_ledger(embedded_bundle, strict=False)
    assert compatibility_embedded_ledger.passed
    assert (
        compatibility_embedded_ledger.by_kind(ReferenceKind.ARTIFACT)[0].target_artifact_id
        == "claim:embedded"
    )


def test_full_replay_requires_certificate_source_artifacts_and_merges_event_artifacts() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    proposed = {
        "mode": "assertion",
        "claim": "safe-temp",
        "horizon": 1,
        "anchor": "anchor:issue",
        "scope": ["demo"],
    }
    status = {"status_time": "2026-01-01T00:00:00Z"}
    incomplete_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:strict-source-missing",
            "manifest": {
                "manifest_id": "manifest:strict-source-missing",
                "root_artifact_id": "artifact:cert",
            },
            "artifacts": [
                _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
                _entry(proposed, ArtifactRole.PROPOSED_USE, "artifact:use"),
                _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
            ],
        }
    )
    missing = replay_authority_from_bundle(incomplete_bundle, strict_ledger=True)
    assert not missing.passed
    assert missing.validation_result.failure_records[0].code is FailureCode.MISSING_REF

    event = {
        "event_id": "evt-unknown",
        "certificate_id": issued.certificate_id,
        "time": "2026-01-01T00:00:00Z",
        "logical_clock": 1,
        "kind": "mark-unknown",
        "hashes": ["bundle:event-merge"],
    }
    entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(proposed, ArtifactRole.PROPOSED_USE, "artifact:use"),
        _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
        _entry(event, ArtifactRole.LIFECYCLE_EVENT, "artifact:event"),
    ]
    report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:event-merge",
                "manifest": {
                    "manifest_id": "manifest:event-merge",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in entries
                    ],
                },
                "artifacts": entries,
            }
        ),
        full_replay=True,
    )
    assert report.passed
    assert report.authority_view is not None
    assert report.authority_view.dominant_status is StatusCode.UNKNOWN
    assert report.ledger_entries


def test_certify_claim_from_artifact_bundle_requires_accepted_semantics() -> None:
    base_entries = [
        _entry(_claim(), ArtifactRole.CLAIM, "artifact:claim"),
        _entry(_finite_bundle(), ArtifactRole.ASSUMPTION_BUNDLE, "artifact:bundle"),
        _entry(
            {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
            ArtifactRole.ANCHOR,
            "artifact:anchor",
        ),
        _entry(
            {"clock_id": "utc", "uncertainty_seconds": "0"},
            ArtifactRole.TIME_BASIS,
            "artifact:time-basis",
        ),
    ]
    missing_admission = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-missing",
            "manifest": {
                "manifest_id": "manifest:formal-issue-missing",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": base_entries,
        }
    )
    missing = certify_claim_from_artifact_bundle(missing_admission)
    assert not isinstance(missing, IssueCertificate)
    assert missing.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    trust_source = {
        "assumption_id": "trust:formal",
        "target": "semantics",
        "scope": ["legacy-raw-bundle"],
        "reason_refs": ["artifact:reason#/reason"],
        "reason_ref_records": [_reason_ref_record(message="accepted migration assumption")],
        "obligation_refs": ["artifact:obligation#/obligation"],
        "checker_transcript_ref": "artifact:trust-transcript",
    }
    trusted_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-trust",
            "manifest": {
                "manifest_id": "manifest:formal-issue-trust",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(trust_source, ArtifactRole.TRUST_ASSUMPTION, "artifact:trust"),
                _entry(
                    {"status": "pass", "transcript": "accepted trust"},
                    ArtifactRole.OTHER,
                    "artifact:trust-transcript",
                ),
                _entry(
                    {"obligation": _obligation_payload()},
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted migration assumption"},
                    ArtifactRole.REASON,
                    "artifact:reason",
                ),
            ],
        }
    )
    trusted = certify_claim_from_artifact_bundle(trusted_bundle)
    assert isinstance(trusted, IssueCertificate)
    assert "trust:formal" in trusted.obligation_refs
    assert "artifact:obligation#/obligation" in trusted.obligation_refs

    symbolic_trust_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-symbolic-trust",
            "manifest": {
                "manifest_id": "manifest:formal-issue-symbolic-trust",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(
                    {**trust_source, "reason_refs": ["accepted migration assumption"]},
                    ArtifactRole.TRUST_ASSUMPTION,
                    "artifact:trust",
                ),
                _entry(
                    {"status": "pass", "transcript": "accepted trust"},
                    ArtifactRole.OTHER,
                    "artifact:trust-transcript",
                ),
                _entry(
                    {"obligation": _obligation_payload()},
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted migration assumption"},
                    ArtifactRole.REASON,
                    "artifact:reason",
                ),
            ],
        }
    )
    symbolic_trust = certify_claim_from_artifact_bundle(symbolic_trust_bundle)
    assert not isinstance(symbolic_trust, IssueCertificate)
    assert symbolic_trust.failure_records[0].code is FailureCode.MISSING_REF
    assert symbolic_trust.failure_records[0].reason_refs[0].source_path == ("/reason_ref_records/0")

    accepted_clause = {
        "clause_id": "accepted:semantics",
        "target": "semantics",
        "clause": {
            "state_space": [{"temp": "70"}],
            "initial_states": [{"temp": "70"}],
            "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        },
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
                "digest": _obligation_digest(),
            }
        ],
        "reason_refs": [_reason_ref_record()],
        "validity_status": "pass",
        "monitor_status": "pass",
    }
    accepted_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue",
            "manifest": {
                "manifest_id": "manifest:formal-issue",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    issued = certify_claim_from_artifact_bundle(accepted_bundle)
    assert isinstance(issued, IssueCertificate)
    assert issued.assumption_bundle_ref == "accepted-bundle:finite-demo"
    assert "trust-assumption:raw-bundle" not in issued.obligation_refs
    assert "accepted:semantics" in issued.obligation_refs

    role_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-role-mismatch",
            "manifest": {
                "manifest_id": "manifest:formal-issue-role-mismatch",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.OTHER, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    role_mismatch = certify_claim_from_artifact_bundle(role_mismatch_bundle)
    assert not isinstance(role_mismatch, IssueCertificate)
    assert role_mismatch.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT

    contract_clause_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-contract-clause-mismatch",
            "manifest": {
                "manifest_id": "manifest:formal-issue-contract-clause-mismatch",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(
                    {
                        **_admission_contract(),
                        "clause": {
                            "state_space": [{"temp": "71"}],
                            "initial_states": [{"temp": "71"}],
                            "transitions": [{"from": {"temp": "71"}, "to": {"temp": "71"}}],
                        },
                    },
                    ArtifactRole.ADMISSION,
                    "artifact:contract",
                ),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    contract_clause_mismatch = certify_claim_from_artifact_bundle(contract_clause_mismatch_bundle)
    assert not isinstance(contract_clause_mismatch, IssueCertificate)
    assert contract_clause_mismatch.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT
    assert contract_clause_mismatch.failure_records[0].reason_refs[0].source_path == "/clause"

    reference_digest_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-reference-digest-mismatch",
            "manifest": {
                "manifest_id": "manifest:formal-issue-reference-digest-mismatch",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(
                    {**_admission_contract(), "reference_digest": "sha256:missing"},
                    ArtifactRole.ADMISSION,
                    "artifact:contract",
                ),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    reference_digest_mismatch = certify_claim_from_artifact_bundle(reference_digest_mismatch_bundle)
    assert not isinstance(reference_digest_mismatch, IssueCertificate)
    assert reference_digest_mismatch.failure_records[0].code is FailureCode.DIGEST_MISMATCH
    assert reference_digest_mismatch.failure_records[0].reason_refs[0].source_path == (
        "/evidence_ref"
    )

    transcript_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-transcript-mismatch",
            "manifest": {
                "manifest_id": "manifest:formal-issue-transcript-mismatch",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(
                    {
                        **_admission_contract(),
                        "checker_transcript_ref": "artifact:other-transcript",
                    },
                    ArtifactRole.ADMISSION,
                    "artifact:contract",
                ),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:other-transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    transcript_mismatch = certify_claim_from_artifact_bundle(transcript_mismatch_bundle)
    assert not isinstance(transcript_mismatch, IssueCertificate)
    assert transcript_mismatch.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT
    assert transcript_mismatch.failure_records[0].reason_refs[0].source_path == (
        "/checker_transcript_ref"
    )

    evidence_kind_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-evidence-kind-mismatch",
            "manifest": {
                "manifest_id": "manifest:formal-issue-evidence-kind-mismatch",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(
                    {**_evidence_artifact(), "kind": "other-model"},
                    ArtifactRole.EVIDENCE,
                    "artifact:evidence",
                ),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    evidence_kind_mismatch = certify_claim_from_artifact_bundle(evidence_kind_mismatch_bundle)
    assert not isinstance(evidence_kind_mismatch, IssueCertificate)
    assert evidence_kind_mismatch.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT
    assert evidence_kind_mismatch.failure_records[0].reason_refs[0].source_path == ("/evidence_ref")

    malformed_contract_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-malformed-contract",
            "manifest": {
                "manifest_id": "manifest:formal-issue-malformed-contract",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(accepted_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry({"kind": "finite-model"}, ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    malformed_contract = certify_claim_from_artifact_bundle(malformed_contract_bundle)
    assert not isinstance(malformed_contract, IssueCertificate)
    assert malformed_contract.failure_records[0].code is FailureCode.SCHEMA_INVALID

    monitor_evidence_mismatch_clause = {
        **accepted_clause,
        "monitor_required": True,
        "monitor_evidence_ref": "artifact:reason",
    }
    monitor_evidence_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-monitor-evidence-mismatch",
            "manifest": {
                "manifest_id": "manifest:formal-issue-monitor-evidence-mismatch",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(
                    monitor_evidence_mismatch_clause,
                    ArtifactRole.ACCEPTED_CLAUSE,
                    "artifact:accepted",
                ),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    monitor_evidence_mismatch = certify_claim_from_artifact_bundle(monitor_evidence_mismatch_bundle)
    assert not isinstance(monitor_evidence_mismatch, IssueCertificate)
    assert monitor_evidence_mismatch.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT
    assert (
        monitor_evidence_mismatch.failure_records[0].reason_refs[0].source_path
        == "/monitor_evidence_ref"
    )

    failed_obligation_clause = {
        **accepted_clause,
        "obligation_ref_records": [
            {
                "obligation_id": "artifact:obligation#/obligation",
                "kind": "admission",
                "status": "fail",
                "source_artifact": "artifact:obligation",
                "source_path": "/obligation",
            }
        ],
    }
    failed_obligation_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-obligation-failed",
            "manifest": {
                "manifest_id": "manifest:formal-issue-obligation-failed",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(
                    failed_obligation_clause,
                    ArtifactRole.ACCEPTED_CLAUSE,
                    "artifact:accepted",
                ),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    failed_obligation = certify_claim_from_artifact_bundle(failed_obligation_bundle)
    assert not isinstance(failed_obligation, IssueCertificate)
    assert failed_obligation.failure_records[0].code is FailureCode.VALIDITY_UNKNOWN
    assert (
        failed_obligation.failure_records[0].reason_refs[0].source_path
        == "/obligation_ref_records/0/status"
    )

    target_mismatch_clause = {**accepted_clause, "target": "compiled:foreign-bundle"}
    target_mismatch_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-target-mismatch",
            "manifest": {
                "manifest_id": "manifest:formal-issue-target-mismatch",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(
                    target_mismatch_clause,
                    ArtifactRole.ACCEPTED_CLAUSE,
                    "artifact:accepted",
                ),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    target_mismatch = certify_claim_from_artifact_bundle(target_mismatch_bundle)
    assert not isinstance(target_mismatch, IssueCertificate)
    assert target_mismatch.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT
    assert target_mismatch.failure_records[0].reason_refs[0].source_path == "/target"

    symbolic_clause = {**accepted_clause, "obligation_refs": ["obligation:symbolic"]}
    symbolic_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-symbolic",
            "manifest": {
                "manifest_id": "manifest:formal-issue-symbolic",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(symbolic_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    symbolic = certify_claim_from_artifact_bundle(symbolic_bundle)
    assert not isinstance(symbolic, IssueCertificate)
    assert symbolic.failure_records[0].code is FailureCode.MISSING_REF

    invalid_clause = {**accepted_clause, "validity_status": "expired"}
    invalid_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-invalid-clause",
            "manifest": {
                "manifest_id": "manifest:formal-issue-invalid-clause",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(invalid_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    invalid = certify_claim_from_artifact_bundle(invalid_bundle)
    assert not isinstance(invalid, IssueCertificate)
    assert invalid.failure_records[0].code is FailureCode.VALIDITY_UNKNOWN

    monitor_clause = {**accepted_clause, "monitor_status": "silent"}
    monitor_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-monitor-silent",
            "manifest": {
                "manifest_id": "manifest:formal-issue-monitor-silent",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(monitor_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
                _entry(
                    {"reason": "accepted clause fixture"}, ArtifactRole.REASON, "artifact:reason"
                ),
            ],
        }
    )
    monitor = certify_claim_from_artifact_bundle(monitor_bundle)
    assert not isinstance(monitor, IssueCertificate)
    assert monitor.failure_records[0].code is FailureCode.VALIDITY_UNKNOWN

    missing_reason_clause = dict(accepted_clause)
    missing_reason_clause.pop("reason_refs")
    missing_reason_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:formal-issue-missing-reason",
            "manifest": {
                "manifest_id": "manifest:formal-issue-missing-reason",
                "root_artifact_id": "artifact:claim",
            },
            "artifacts": [
                *base_entries,
                _entry(missing_reason_clause, ArtifactRole.ACCEPTED_CLAUSE, "artifact:accepted"),
                _entry(_evidence_artifact(), ArtifactRole.EVIDENCE, "artifact:evidence"),
                _entry(_admission_contract(), ArtifactRole.ADMISSION, "artifact:contract"),
                _entry({"transcript": "pass"}, ArtifactRole.OTHER, "artifact:transcript"),
                _entry(
                    {
                        "obligation": {
                            "obligation_id": "obligation:model",
                            "kind": "admission",
                            "status": "pass",
                        }
                    },
                    ArtifactRole.OBLIGATION,
                    "artifact:obligation",
                ),
            ],
        }
    )
    missing_reason = certify_claim_from_artifact_bundle(missing_reason_bundle)
    assert not isinstance(missing_reason, IssueCertificate)
    assert missing_reason.failure_records[0].code is FailureCode.SCHEMA_INVALID


def test_accepted_clause_preserves_typed_reason_refs_and_schema_contract() -> None:
    source = {
        "clause_id": "accepted:typed-reason",
        "target": "semantics",
        "clause": {"state_space": [], "initial_states": [], "transitions": []},
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
                "digest": "sha256:obligation",
            }
        ],
        "reason_refs": [
            {
                "reason_id": "reason:typed",
                "failure_code": "missing_ref",
                "layer": "issue",
                "source_artifact": "artifact:reason",
                "source_path": "/reason",
                "message": "accepted typed provenance",
                "digest": "sha256:reason",
            }
        ],
        "validity_status": "pass",
        "monitor_status": "pass",
    }
    clause = AcceptedClause.from_json(source)
    assert clause.reason_refs[0].reason_id == "reason:typed"
    assert clause.reason_refs[0].failure_code is FailureCode.MISSING_REF
    assert clause.reason_refs[0].layer.value == "issue"
    assert clause.reason_refs[0].source_artifact == "artifact:reason"
    assert clause.reason_refs[0].source_path == "/reason"
    assert clause.reason_refs[0].digest == "sha256:reason"
    assert clause.obligation_ref_records[0].obligation_id == "artifact:obligation#/obligation"
    assert clause.obligation_ref_records[0].source_artifact == "artifact:obligation"
    assert clause.obligation_ref_records[0].source_path == "/obligation"
    assert clause.obligation_ref_records[0].digest == "sha256:obligation"
    assert validate_named_schema(source, "accepted-clause.schema.json").passed
    string_reason_schema = validate_named_schema(
        {**source, "reason_refs": ["artifact:reason#/reason"]},
        "accepted-clause.schema.json",
    )
    assert not string_reason_schema.passed
    assert string_reason_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    missing_reason_digest = json.loads(json.dumps(source))
    missing_reason_digest["reason_refs"][0].pop("digest")
    missing_digest_schema = validate_named_schema(
        missing_reason_digest,
        "accepted-clause.schema.json",
    )
    assert not missing_digest_schema.passed
    assert missing_digest_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    bad_reason_pointer = json.loads(json.dumps(source))
    bad_reason_pointer["reason_refs"][0]["source_path"] = "relative"
    bad_pointer_schema = validate_named_schema(
        bad_reason_pointer,
        "accepted-clause.schema.json",
    )
    assert not bad_pointer_schema.passed
    assert bad_pointer_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID

    empty_refs = {**source, "obligation_refs": [], "reason_refs": []}
    invalid = validate_named_schema(empty_refs, "accepted-clause.schema.json")
    assert not invalid.passed
    assert invalid.failure_records[0].code is FailureCode.SCHEMA_INVALID
    unbound_transcript_source = {
        **source,
        "checker_transcript_ref": "checker:accepted-clause",
    }
    unbound_transcript_schema = validate_named_schema(
        unbound_transcript_source,
        "accepted-clause.schema.json",
    )
    assert not unbound_transcript_schema.passed
    assert unbound_transcript_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID

    legacy_reason_source = {
        **source,
        "reason_refs": [
            "legacy string reason",
            {
                "reason_id": "reason:fallback",
                "failure_code": "not-a-failure-code",
                "layer": "not-a-layer",
                "message": "fallback provenance",
            },
        ],
    }
    legacy_clause = AcceptedClause.from_json(legacy_reason_source)
    assert legacy_clause.reason_refs[0].message == "legacy string reason"
    assert legacy_clause.reason_refs[0].source_path == "/reason_refs/0"
    assert legacy_clause.reason_refs[1].failure_code is FailureCode.CHECKER_UNKNOWN
    assert legacy_clause.reason_refs[1].layer is Layer.INTEROP


def test_accepted_clause_reason_records_check_digest_and_ledger_role() -> None:
    entry = ReferenceLedgerEntry(
        ref_value="artifact:reason#/reason",
        kind=ReferenceKind.REASON,
        owner_artifact="artifact:accepted",
        owner_path="/reason_refs/0",
        target_artifact_id="artifact:reason",
        target_path="/reason",
        target_digest="sha256:reason",
        semantic_role=ArtifactRole.REASON.value,
        required=True,
        resolved=True,
        expected_kind=ReferenceKind.REASON,
        expected_semantic_role=ArtifactRole.REASON.value,
        expected_digest="sha256:reason",
        required_stage=ValidationStage.GUARD_EVALUATE,
    )
    source = {
        "reason_refs": [
            {
                "reason_id": "reason:accepted",
                "failure_code": "checker_unknown",
                "layer": "issue",
                "source_artifact": "artifact:reason",
                "source_path": "/reason",
                "message": "accepted reason",
                "digest": "sha256:reason",
            }
        ]
    }
    assert (
        accepted_clause_reason_record_result(
            source,
            (entry,),
            clause_id="accepted:semantics",
            source_layer=Layer.ISSUE,
        )
        is None
    )

    not_array = accepted_clause_reason_record_result(
        {"reason_refs": {"not": "array"}},
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert not_array is not None
    assert not_array.failure_records[0].code is FailureCode.SCHEMA_INVALID

    not_typed = accepted_clause_reason_record_result(
        {"reason_refs": ["artifact:reason#/reason"]},
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert not_typed is not None
    assert not_typed.failure_records[0].code is FailureCode.SCHEMA_INVALID

    missing_digest = json.loads(json.dumps(source))
    missing_digest["reason_refs"][0].pop("digest")
    missing_digest_result = accepted_clause_reason_record_result(
        missing_digest,
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert missing_digest_result is not None
    assert missing_digest_result.failure_records[0].code is FailureCode.MISSING_REF

    digest_mismatch = json.loads(json.dumps(source))
    digest_mismatch["reason_refs"][0]["digest"] = "sha256:wrong"
    digest_mismatch_result = accepted_clause_reason_record_result(
        digest_mismatch,
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert digest_mismatch_result is not None
    assert digest_mismatch_result.failure_records[0].code is FailureCode.DIGEST_MISMATCH

    role_mismatch = accepted_clause_reason_record_result(
        source,
        (replace(entry, semantic_role=ArtifactRole.OTHER.value),),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert role_mismatch is not None
    assert role_mismatch.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT


def test_accepted_clause_obligation_records_check_scope_digest_and_waiver() -> None:
    entry = ReferenceLedgerEntry(
        ref_value="artifact:obligation#/obligation",
        kind=ReferenceKind.OBLIGATION,
        owner_artifact="artifact:accepted",
        owner_path="/obligation_ref_records/0",
        target_artifact_id="artifact:obligation",
        target_path="/obligation",
        target_digest="sha256:obligation",
        semantic_role=ArtifactRole.OBLIGATION.value,
        required=True,
        resolved=True,
        expected_kind=ReferenceKind.OBLIGATION,
        expected_semantic_role=ArtifactRole.OBLIGATION.value,
        expected_digest="sha256:obligation",
        required_stage=ValidationStage.GUARD_EVALUATE,
        active_scope_status="pass",
    )
    reason_entry = ReferenceLedgerEntry(
        ref_value="artifact:reason#/reason",
        kind=ReferenceKind.REASON,
        owner_artifact="artifact:accepted",
        owner_path="/obligation_ref_records/0/reason_refs/0",
        target_artifact_id="artifact:reason",
        target_path="/reason",
        target_digest="sha256:reason",
        semantic_role=ArtifactRole.REASON.value,
        required=True,
        resolved=True,
        expected_kind=ReferenceKind.REASON,
        expected_semantic_role=ArtifactRole.REASON.value,
        expected_digest="sha256:reason",
        required_stage=ValidationStage.GUARD_EVALUATE,
        active_scope_status="not_applicable",
    )
    source = {
        "obligation_ref_records": [
            {
                "obligation_id": "artifact:obligation#/obligation",
                "kind": "admission",
                "status": "pass",
                "source_artifact": "artifact:obligation",
                "source_path": "/obligation",
                "digest": "sha256:obligation",
            }
        ]
    }
    assert (
        accepted_clause_obligation_record_result(
            source,
            (entry,),
            clause_id="accepted:semantics",
            source_layer=Layer.ISSUE,
            status_time="2026-01-01T00:00:00Z",
        )
        is None
    )

    not_array = accepted_clause_obligation_record_result(
        {"obligation_ref_records": {"not": "array"}},
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert not_array is not None
    assert not_array.failure_records[0].code is FailureCode.SCHEMA_INVALID

    not_typed = accepted_clause_obligation_record_result(
        {"obligation_ref_records": ["artifact:obligation#/obligation"]},
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert not_typed is not None
    assert not_typed.failure_records[0].code is FailureCode.SCHEMA_INVALID

    missing_records = accepted_clause_obligation_record_result(
        {"obligation_refs": ["artifact:obligation#/obligation"], "obligation_ref_records": []},
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert missing_records is not None
    assert missing_records.failure_records[0].code is FailureCode.MISSING_REF
    assert missing_records.failure_records[0].reason_refs[0].source_path == (
        "/obligation_ref_records"
    )

    symbolic_record = accepted_clause_obligation_record_result(
        {
            "obligation_ref_records": [
                {
                    "obligation_id": "obligation:symbolic",
                    "kind": "admission",
                    "status": "pass",
                }
            ]
        },
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert symbolic_record is not None
    assert symbolic_record.failure_records[0].code is FailureCode.MISSING_REF

    pass_without_digest = accepted_clause_obligation_record_result(
        {
            "obligation_ref_records": [
                {
                    "obligation_id": "artifact:obligation#/obligation",
                    "kind": "admission",
                    "status": "pass",
                    "source_artifact": "artifact:obligation",
                    "source_path": "/obligation",
                }
            ]
        },
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert pass_without_digest is not None
    assert pass_without_digest.failure_records[0].code is FailureCode.MISSING_REF

    expired = accepted_clause_obligation_record_result(
        {
            "obligation_ref_records": [
                {
                    "obligation_id": "artifact:obligation#/obligation",
                    "kind": "admission",
                    "status": "pass",
                    "expiry": "2025-01-01T00:00:00Z",
                    "source_artifact": "artifact:obligation",
                    "source_path": "/obligation",
                }
            ]
        },
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
        status_time="2026-01-01T00:00:00Z",
    )
    assert expired is not None
    assert expired.failure_records[0].code is FailureCode.VALIDITY_UNKNOWN

    digest_mismatch = accepted_clause_obligation_record_result(
        {
            "obligation_ref_records": [
                {
                    "obligation_id": "artifact:obligation#/obligation",
                    "kind": "admission",
                    "status": "pass",
                    "source_artifact": "artifact:obligation",
                    "source_path": "/obligation",
                    "digest": "sha256:wrong",
                }
            ]
        },
        (entry,),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert digest_mismatch is not None
    assert digest_mismatch.failure_records[0].code is FailureCode.DIGEST_MISMATCH

    waived = accepted_clause_obligation_record_result(
        {
            "obligation_ref_records": [
                {
                    "obligation_id": "artifact:obligation#/obligation",
                    "kind": "admission",
                    "status": "waived",
                    "reason_refs": ["artifact:missing-reason#/reason"],
                    "source_artifact": "artifact:obligation",
                    "source_path": "/obligation",
                }
            ]
        },
        (entry, reason_entry),
        clause_id="accepted:semantics",
        source_layer=Layer.ISSUE,
    )
    assert waived is not None
    assert waived.failure_records[0].code is FailureCode.MISSING_REF


def test_direct_dict_authority_uses_synthetic_bundle_and_profile_field_policy() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    proposed = {
        "mode": "assertion",
        "claim": "safe-temp",
        "horizon": 1,
        "anchor": "anchor:issue",
        "scope": ["demo"],
    }
    status = {"status_time": "2026-01-01T00:00:00Z"}

    synthetic = synthetic_authority_bundle(to_jsonable(issued), proposed, status)
    assert synthetic.manifest.root_artifact_id == "synthetic:certificate"
    direct = check_authority(to_jsonable(issued), proposed, status)
    assert not isinstance(direct, type(validate_artifact_ref(ArtifactRef("x", "json"))))
    assert direct.authority_outcome.code == "unknown"
    assert direct.authority_outcome.blocking_set
    assert "trust-assumption:synthetic-authority-input" in direct.obligation_refs
    assert any(ref.reason_id == "reason:synthetic-authority-input" for ref in direct.reason_refs)
    allowed_direct = check_authority(
        to_jsonable(issued), proposed, status, allow_synthetic_trust=True
    )
    assert allowed_direct.authority_outcome.code == "assert"
    direct_profile = direct.minimum_profile()
    assert "trust-assumption:synthetic-authority-input" in direct_profile["obligation_refs"]
    assert any(
        record["reason_id"] == "reason:synthetic-authority-input"
        for record in direct_profile["reason_ref_records"]
    )
    assert validate_named_schema(direct_profile, "status-authority-view.schema.json").passed
    non_operational_with_operational_ref = json.loads(json.dumps(direct_profile))
    non_operational_with_operational_ref["completion_admission_ref"] = "artifact:completion"
    invalid_non_operational_schema = validate_named_schema(
        non_operational_with_operational_ref,
        "status-authority-view.schema.json",
    )
    assert not invalid_non_operational_schema.passed
    assert invalid_non_operational_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID

    operational_policy = status_authority_field_policy("operational", "accept")
    assert "completion_admission_ref" in operational_policy.required_fields
    represented_policy = status_authority_field_policy("assertion", "assert")
    assert "completion_admission_ref" in represented_policy.not_applicable_fields


def test_lifecycle_required_signature_uses_verifier_boundary() -> None:
    event = LifecycleEvent.from_json(
        {
            "event_id": "evt-signed",
            "certificate_id": "cert",
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "mark-unknown",
            "signature": "signature-bytes",
            "payload": {"signature_policy": "required"},
        }
    )

    default_fold = fold_status(
        "cert",
        (event,),
        EventOrder(),
        FoldContext(policy_version="default"),
    )
    assert default_fold.dominant_status is StatusCode.CONFLICT

    class PassingVerifier:
        def verify(self, checked_event: LifecycleEvent) -> str:
            assert checked_event.event_id == "evt-signed"
            return "pass"

    verified = fold_status(
        "cert",
        (event,),
        EventOrder(),
        FoldContext(policy_version="default"),
        signature_verifier=PassingVerifier(),
    )
    assert verified.dominant_status is StatusCode.UNKNOWN

    declared_only = LifecycleEvent.from_json(
        {
            "event_id": "evt-declared-signature",
            "certificate_id": "cert",
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "mark-unknown",
            "signature": "signature-bytes",
            "signature_verifier_result": "pass",
            "payload": {"signature_policy": "required"},
        }
    )
    declared_fold = fold_status(
        "cert",
        (declared_only,),
        EventOrder(),
        FoldContext(policy_version="default"),
    )
    assert declared_fold.dominant_status is StatusCode.CONFLICT
    assert declared_fold.blocking_set[0].reason_refs[0].source_path == (
        "/signature_verifier_result_status"
    )

    proof_bound = LifecycleEvent.from_json(
        {
            **to_jsonable(declared_only),
            "signature_verifier_result_ref": "artifact:signature-proof",
            "signature_verifier_result_status": {
                "status": "accepted",
                "artifact_ref": "artifact:signature-proof",
                "artifact_digest": "sha256:signature-proof",
                "proof_kind": "signature_verifier",
                "payload": {
                    "event_id": "evt-declared-signature",
                    "signature_verifier_result": "pass",
                },
            },
        }
    )
    proof_bound_fold = fold_status(
        "cert",
        (proof_bound,),
        EventOrder(),
        FoldContext(policy_version="default"),
    )
    assert proof_bound_fold.dominant_status is StatusCode.UNKNOWN


def test_update_certificate_requires_bound_signature_verifier_evidence() -> None:
    issued = _issued_lifecycle_certificate()
    declared_only = update_certificate(
        issued,
        {
            "event_id": "evt-signature-declared",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "signature": "signature-bytes",
            "signature_verifier_result": "pass",
            "payload": {"signature_policy": "required"},
        },
    )
    assert declared_only.decision == "recompute"
    assert any(
        ref.source_path == "/signature_verifier_result_ref"
        for block in declared_only.blocking_set
        for ref in block.reason_refs
    )

    shallow_status = update_certificate(
        issued,
        {
            "event_id": "evt-signature-shallow",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "signature": "signature-bytes",
            "signature_verifier_result": "pass",
            "signature_verifier_result_ref": "artifact:signature-proof",
            "signature_verifier_result_status": {
                "status": "accepted",
                "artifact_ref": "artifact:signature-proof",
                "proof_kind": "signature_verifier",
                "payload": {
                    "event_id": "evt-signature-shallow",
                    "signature_verifier_result": "pass",
                },
            },
            "payload": {"signature_policy": "required"},
        },
    )
    assert shallow_status.decision == "reject"
    assert any(
        block.failure_code is FailureCode.SCHEMA_INVALID for block in shallow_status.blocking_set
    )

    wrong_payload = update_certificate(
        issued,
        {
            "event_id": "evt-signature-wrong-payload",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "signature": "signature-bytes",
            "signature_verifier_result": "pass",
            "signature_verifier_result_ref": "artifact:signature-proof",
            "signature_verifier_result_status": {
                "status": "accepted",
                "artifact_ref": "artifact:signature-proof",
                "artifact_digest": "sha256:signature-proof",
                "proof_kind": "signature_verifier",
                "payload": {
                    "event_id": "evt-signature-wrong-payload",
                    "signature_verifier_result": "fail",
                },
            },
            "payload": {"signature_policy": "required"},
        },
    )
    assert wrong_payload.decision == "recompute"
    assert any(
        ref.source_path == "/signature_verifier_result_status"
        for block in wrong_payload.blocking_set
        for ref in block.reason_refs
    )

    accepted = update_certificate(
        issued,
        {
            "event_id": "evt-signature-accepted",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "signature": "signature-bytes",
            "signature_verifier_result": "pass",
            "signature_verifier_result_ref": "artifact:signature-proof",
            "signature_verifier_result_status": {
                "status": "accepted",
                "artifact_ref": "artifact:signature-proof",
                "artifact_digest": "sha256:signature-proof",
                "proof_kind": "signature_verifier",
                "payload": {
                    "event_id": "evt-signature-accepted",
                    "signature_verifier_result": "pass",
                },
            },
            "payload": {"signature_policy": "required"},
        },
    )
    assert accepted.decision == "maintain"
    assert accepted.accepted is True
    assert accepted.signature_verifier_result_ref == "artifact:signature-proof"
    assert validate_named_schema(accepted.to_json(), "lifecycle-decision.schema.json").passed

    proof_derived = update_certificate(
        issued,
        {
            "event_id": "evt-signature-proof-derived",
            "certificate_id": issued.certificate_id,
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "audit",
            "signature": "signature-bytes",
            "signature_verifier_result_ref": "artifact:signature-proof",
            "signature_verifier_result_status": {
                "status": "accepted",
                "artifact_ref": "artifact:signature-proof",
                "artifact_digest": "sha256:signature-proof",
                "proof_kind": "signature_verifier",
                "payload": {
                    "event_id": "evt-signature-proof-derived",
                    "signature_verifier_result": "pass",
                },
            },
            "payload": {"signature_policy": "required"},
        },
    )
    assert proof_derived.decision == "maintain"
    assert proof_derived.accepted is True
    assert proof_derived.signature_verifier_result_ref == "artifact:signature-proof"
    assert validate_named_schema(proof_derived.to_json(), "lifecycle-decision.schema.json").passed


def test_full_replay_uses_resolved_runtime_over_stale_embedded_sources() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    stale_certificate = to_jsonable(issued)
    stale_claim = _claim()
    formula = dict(stale_claim["formula"])  # type: ignore[index]
    assert isinstance(formula, dict)
    args = dict(formula["args"])  # type: ignore[index]
    args["value"] = "60"
    formula["args"] = args
    stale_claim["formula"] = formula
    stale_certificate["claim_source"] = stale_claim
    entries = [
        _entry(stale_certificate, ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(_claim(), ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(
            {
                "mode": "assertion",
                "claim": "safe-temp",
                "horizon": 1,
                "anchor": "anchor:issue",
                "scope": ["demo"],
            },
            ArtifactRole.PROPOSED_USE,
            "artifact:use",
        ),
        _entry(
            {"status_time": "2026-01-01T00:00:00Z"},
            ArtifactRole.STATUS_CONTEXT,
            "artifact:status-context",
        ),
        *_kernel_proof_entries(),
    ]
    bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:stale-source",
            "manifest": {
                "manifest_id": "manifest:stale-source",
                "root_artifact_id": "artifact:cert",
                "artifact_refs": [entry["artifact_ref"] for entry in entries],
                "dependency_order": [
                    str(entry["artifact_ref"]["artifact_id"]) for entry in entries
                ],
            },
            "artifacts": entries,
        }
    )
    report = validate_artifact_bundle(bundle, full_replay=True)
    assert report.authority_view is None
    assert report.final_result.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT


def test_strict_full_replay_requires_resolved_kernel_proof_artifact() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    base_entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(
            {
                "mode": "assertion",
                "claim": "safe-temp",
                "horizon": 1,
                "anchor": "anchor:issue",
                "scope": ["demo"],
            },
            ArtifactRole.PROPOSED_USE,
            "artifact:use",
        ),
        _entry(
            {"status_time": "2026-01-01T00:00:00Z"},
            ArtifactRole.STATUS_CONTEXT,
            "artifact:status-context",
        ),
    ]

    missing_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:missing-kernel-proof",
                "manifest": {
                    "manifest_id": "manifest:missing-kernel-proof",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in base_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in base_entries
                    ],
                },
                "artifacts": base_entries,
            }
        ),
        full_replay=True,
    )
    assert not missing_report.passed
    assert missing_report.authority_view is not None
    assert missing_report.authority_view.authority_outcome.code == "unknown"
    assert any(
        result.stage is ValidationStage.KERNEL_CHECK and result.status is ValidationStatus.UNKNOWN
        for result in missing_report.stage_results
    )
    assert any(
        block.failure_code is FailureCode.CHECKER_UNKNOWN
        and any("KernelProofArtifact" in ref.message for ref in block.reason_refs)
        for block in missing_report.authority_view.blocking_set
    )

    rejected_proof_entries = [
        *base_entries,
        _entry(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:kernel-transcript",
                "proof": {
                    "backend_identity": "EnumeratingBackend",
                    "proof_kind": "exact-finite-enumeration",
                    "proof_status": "fail",
                },
            },
            ArtifactRole.KERNEL_PROOF,
            "artifact:kernel-proof",
        ),
        _entry({"status": "pass"}, ArtifactRole.OTHER, "artifact:kernel-transcript"),
    ]
    rejected_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:rejected-kernel-proof",
                "manifest": {
                    "manifest_id": "manifest:rejected-kernel-proof",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in rejected_proof_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in rejected_proof_entries
                    ],
                },
                "artifacts": rejected_proof_entries,
            }
        ),
        full_replay=True,
    )
    assert rejected_report.authority_view is None
    assert rejected_report.final_result.stage is ValidationStage.KERNEL_CHECK
    assert rejected_report.final_result.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    assert rejected_report.replay_trace is not None
    assert rejected_report.stage_artifacts[ValidationStage.KERNEL_CHECK.value]
    assert rejected_report.protocol_records[0].record_kind == "ReplayFailure"
    assert rejected_report.runtime_summary_digest

    conflicting_proof_entries = [
        *base_entries,
        _entry(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:kernel-transcript",
                "witness_provenance_refs": ["artifact:kernel-witness"],
                "proof": {
                    "backend_identity": "EnumeratingBackend",
                    "proof_kind": "exact-finite-enumeration",
                    "proof_status": "accepted",
                    "expected_verdict": "deny",
                    "feasibility": "feasible",
                    "inclusion": "yes",
                    "disjointness": "no",
                    "inclusion_ref": "artifact:kernel-inclusion-proof",
                    "disjointness_ref": "artifact:kernel-disjointness-proof",
                },
            },
            ArtifactRole.KERNEL_PROOF,
            "artifact:kernel-proof",
        ),
        _entry({"status": "pass"}, ArtifactRole.OTHER, "artifact:kernel-transcript"),
        _proof_entry(
            "artifact:kernel-witness",
            proof_kind="witness_provenance",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="deny",
        ),
        _proof_entry(
            "artifact:kernel-inclusion-proof",
            proof_kind="inclusion",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="deny",
            inclusion="yes",
        ),
        _proof_entry(
            "artifact:kernel-disjointness-proof",
            proof_kind="disjointness",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="deny",
            disjointness="no",
        ),
    ]
    conflicting_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:conflicting-kernel-proof",
                "manifest": {
                    "manifest_id": "manifest:conflicting-kernel-proof",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in conflicting_proof_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in conflicting_proof_entries
                    ],
                },
                "artifacts": conflicting_proof_entries,
            }
        ),
        full_replay=True,
    )
    assert conflicting_report.authority_view is not None
    assert conflicting_report.authority_view.authority_outcome.code == "unknown"
    assert any(
        block.failure_code is FailureCode.ARTIFACT_CONFLICT
        and block.reason_refs[0].source_path == "/proof/expected_verdict"
        for block in conflicting_report.authority_view.blocking_set
    )

    missing_inclusion_ref_entries = [
        *base_entries,
        _entry(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:kernel-transcript",
                "witness_provenance_refs": ["artifact:kernel-witness"],
                "proof": {
                    "backend_identity": "EnumeratingBackend",
                    "proof_kind": "exact-finite-enumeration",
                    "proof_status": "accepted",
                    "expected_verdict": "assert",
                    "feasibility": "feasible",
                    "inclusion": "yes",
                    "disjointness": "no",
                },
            },
            ArtifactRole.KERNEL_PROOF,
            "artifact:kernel-proof",
        ),
        _entry({"status": "pass"}, ArtifactRole.OTHER, "artifact:kernel-transcript"),
        _proof_entry(
            "artifact:kernel-witness",
            proof_kind="witness_provenance",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="assert",
        ),
    ]
    missing_inclusion_ref_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:missing-kernel-inclusion-ref",
                "manifest": {
                    "manifest_id": "manifest:missing-kernel-inclusion-ref",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in missing_inclusion_ref_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in missing_inclusion_ref_entries
                    ],
                },
                "artifacts": missing_inclusion_ref_entries,
            }
        ),
        full_replay=True,
    )
    assert missing_inclusion_ref_report.authority_view is not None
    assert missing_inclusion_ref_report.authority_view.authority_outcome.code == "unknown"
    assert any(
        block.failure_code is FailureCode.CHECKER_UNKNOWN
        and block.reason_refs[0].source_path == "/proof/inclusion_ref"
        for block in missing_inclusion_ref_report.authority_view.blocking_set
    )

    inclusion_kind_mismatch_entries = [
        *base_entries,
        _entry(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:kernel-transcript",
                "witness_provenance_refs": ["artifact:kernel-witness"],
                "proof": {
                    "backend_identity": "EnumeratingBackend",
                    "proof_kind": "exact-finite-enumeration",
                    "proof_status": "accepted",
                    "expected_verdict": "assert",
                    "feasibility": "feasible",
                    "inclusion": "yes",
                    "disjointness": "no",
                    "inclusion_ref": "artifact:kernel-inclusion-proof",
                },
            },
            ArtifactRole.KERNEL_PROOF,
            "artifact:kernel-proof",
        ),
        _entry({"status": "pass"}, ArtifactRole.OTHER, "artifact:kernel-transcript"),
        _proof_entry(
            "artifact:kernel-witness",
            proof_kind="witness_provenance",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="assert",
        ),
        _proof_entry(
            "artifact:kernel-inclusion-proof",
            proof_kind="disjointness",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="assert",
            inclusion="yes",
        ),
    ]
    inclusion_kind_mismatch_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:kernel-inclusion-kind-mismatch",
                "manifest": {
                    "manifest_id": "manifest:kernel-inclusion-kind-mismatch",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in inclusion_kind_mismatch_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in inclusion_kind_mismatch_entries
                    ],
                },
                "artifacts": inclusion_kind_mismatch_entries,
            }
        ),
        full_replay=True,
    )
    assert inclusion_kind_mismatch_report.authority_view is None
    assert inclusion_kind_mismatch_report.final_result.stage is ValidationStage.KERNEL_CHECK
    assert (
        inclusion_kind_mismatch_report.final_result.failure_records[0].code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        inclusion_kind_mismatch_report.final_result.failure_records[0].reason_refs[0].source_path
        == "/proof/inclusion_ref"
    )

    inclusion_payload_missing_entries = [
        *base_entries,
        _entry(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:kernel-transcript",
                "witness_provenance_refs": ["artifact:kernel-witness"],
                "proof": {
                    "backend_identity": "EnumeratingBackend",
                    "proof_kind": "exact-finite-enumeration",
                    "proof_status": "accepted",
                    "expected_verdict": "assert",
                    "feasibility": "feasible",
                    "inclusion": "yes",
                    "disjointness": "no",
                    "inclusion_ref": "artifact:kernel-inclusion-proof",
                },
            },
            ArtifactRole.KERNEL_PROOF,
            "artifact:kernel-proof",
        ),
        _entry({"status": "pass"}, ArtifactRole.OTHER, "artifact:kernel-transcript"),
        _proof_entry(
            "artifact:kernel-witness",
            proof_kind="witness_provenance",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="assert",
        ),
        _proof_entry("artifact:kernel-inclusion-proof", proof_kind="inclusion"),
    ]
    inclusion_payload_missing_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:kernel-inclusion-payload-missing",
                "manifest": {
                    "manifest_id": "manifest:kernel-inclusion-payload-missing",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in inclusion_payload_missing_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in inclusion_payload_missing_entries
                    ],
                },
                "artifacts": inclusion_payload_missing_entries,
            }
        ),
        full_replay=True,
    )
    assert inclusion_payload_missing_report.authority_view is None
    assert inclusion_payload_missing_report.final_result.stage is ValidationStage.KERNEL_CHECK
    assert (
        inclusion_payload_missing_report.final_result.failure_records[0].code
        is FailureCode.CHECKER_UNKNOWN
    )
    assert (
        inclusion_payload_missing_report.final_result.failure_records[0].reason_refs[0].source_path
        == "/proof/inclusion_ref/kernel_proof_ref"
    )

    inclusion_payload_mismatch_entries = [
        *base_entries,
        _entry(
            {
                "artifact_id": "artifact:kernel-proof",
                "checker_transcript_ref": "artifact:kernel-transcript",
                "witness_provenance_refs": ["artifact:kernel-witness"],
                "proof": {
                    "backend_identity": "EnumeratingBackend",
                    "proof_kind": "exact-finite-enumeration",
                    "proof_status": "accepted",
                    "expected_verdict": "assert",
                    "feasibility": "feasible",
                    "inclusion": "yes",
                    "disjointness": "no",
                    "inclusion_ref": "artifact:kernel-inclusion-proof",
                },
            },
            ArtifactRole.KERNEL_PROOF,
            "artifact:kernel-proof",
        ),
        _entry({"status": "pass"}, ArtifactRole.OTHER, "artifact:kernel-transcript"),
        _proof_entry(
            "artifact:kernel-witness",
            proof_kind="witness_provenance",
            kernel_proof_ref="artifact:kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="assert",
        ),
        _proof_entry(
            "artifact:kernel-inclusion-proof",
            proof_kind="inclusion",
            kernel_proof_ref="artifact:other-kernel-proof",
            backend_identity="EnumeratingBackend",
            expected_verdict="assert",
            inclusion="yes",
        ),
    ]
    inclusion_payload_mismatch_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:kernel-inclusion-payload-mismatch",
                "manifest": {
                    "manifest_id": "manifest:kernel-inclusion-payload-mismatch",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in inclusion_payload_mismatch_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in inclusion_payload_mismatch_entries
                    ],
                },
                "artifacts": inclusion_payload_mismatch_entries,
            }
        ),
        full_replay=True,
    )
    assert inclusion_payload_mismatch_report.authority_view is None
    assert inclusion_payload_mismatch_report.final_result.stage is ValidationStage.KERNEL_CHECK
    assert (
        inclusion_payload_mismatch_report.final_result.failure_records[0].code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        inclusion_payload_mismatch_report.final_result.failure_records[0].reason_refs[0].source_path
        == "/proof/inclusion_ref/kernel_proof_ref"
    )


def test_status_failure_view_preserves_replay_evidence() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    status = {
        "status_time": "2026-01-01T00:00:00Z",
        "event_log": [
            {
                "event_id": "evt-unknown",
                "certificate_id": issued.certificate_id,
                "time": "2026-01-01T00:00:00Z",
                "logical_clock": 1,
                "kind": "mark-unknown",
            }
        ],
    }
    entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(
            {
                "mode": "assertion",
                "claim": "safe-temp",
                "horizon": 1,
                "anchor": "anchor:issue",
                "scope": ["demo"],
            },
            ArtifactRole.PROPOSED_USE,
            "artifact:use",
        ),
        _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
    ]
    report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:status-failure-evidence",
                "manifest": {
                    "manifest_id": "manifest:status-failure-evidence",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in entries
                    ],
                },
                "artifacts": entries,
            }
        ),
        full_replay=True,
    )
    assert report.authority_view is not None
    assert report.authority_view.dominant_status is StatusCode.UNKNOWN
    assert report.authority_view.artifact_refs
    assert report.authority_view.ledger_entries
    assert report.authority_view.stage_blockers
    profile = report.authority_view.minimum_profile()
    schema_result = validate_named_schema(profile, "status-authority-view.schema.json")
    assert schema_result.passed
    status_view_bundle = _artifact_bundle_source(
        profile,
        role=ArtifactRole.STATUS_AUTHORITY_VIEW.value,
    )
    assert validate_artifact_bundle(artifact_bundle_from_json(status_view_bundle)).passed
    allow_with_blocking_profile = json.loads(json.dumps(profile))
    allow_with_blocking_profile["dominant_status"] = "active"
    allow_with_blocking_profile["gate_decision_ref"] = "allow"
    allow_with_blocking_profile["authority_outcome"] = {
        **allow_with_blocking_profile["authority_outcome"],
        "layer": "policy",
        "code": "allow",
        "direction": "none",
        "gate_decision": "allow",
        "gate_decision_ref": "allow",
    }
    allow_with_blocking_schema = validate_named_schema(
        allow_with_blocking_profile,
        "status-authority-view.schema.json",
    )
    assert not allow_with_blocking_schema.passed
    assert allow_with_blocking_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    reasonless_deny_profile = json.loads(json.dumps(allow_with_blocking_profile))
    reasonless_deny_profile["reason_refs"] = []
    reasonless_deny_profile["reason_ref_records"] = []
    reasonless_deny_profile["blocking_records"] = []
    reasonless_deny_profile["authority_outcome"] = {
        **reasonless_deny_profile["authority_outcome"],
        "layer": "represented",
        "code": "deny",
        "direction": "negative",
        "gate_decision": "allow",
        "gate_decision_ref": "allow",
        "reason_refs": [],
        "reason_ref_records": [],
        "blocking_records": [],
    }
    reasonless_deny_schema = validate_named_schema(
        reasonless_deny_profile,
        "status-authority-view.schema.json",
    )
    assert not reasonless_deny_schema.passed
    assert reasonless_deny_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    reasoned_deny_profile = json.loads(json.dumps(reasonless_deny_profile))
    reasoned_deny_profile["reason_refs"] = profile["reason_refs"]
    reasoned_deny_profile["reason_ref_records"] = profile["reason_ref_records"]
    reasoned_deny_profile["authority_outcome"]["reason_refs"] = profile["reason_refs"]
    reasoned_deny_profile["authority_outcome"]["reason_ref_records"] = profile["reason_ref_records"]
    assert validate_named_schema(
        reasoned_deny_profile,
        "status-authority-view.schema.json",
    ).passed
    missing_nested_reason_profile = json.loads(json.dumps(reasoned_deny_profile))
    missing_nested_reason_profile["authority_outcome"].pop("reason_ref_records")
    missing_nested_reason_schema = validate_named_schema(
        missing_nested_reason_profile,
        "status-authority-view.schema.json",
    )
    assert not missing_nested_reason_schema.passed
    assert missing_nested_reason_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    expired_upgrade_profile = json.loads(json.dumps(allow_with_blocking_profile))
    expired_upgrade_profile["dominant_status"] = "expired"
    expired_upgrade_schema = validate_named_schema(
        expired_upgrade_profile,
        "status-authority-view.schema.json",
    )
    assert not expired_upgrade_schema.passed
    assert expired_upgrade_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    blocked_deny_profile = json.loads(json.dumps(allow_with_blocking_profile))
    blocked_deny_profile["authority_outcome"] = {
        **blocked_deny_profile["authority_outcome"],
        "layer": "represented",
        "code": "deny",
        "direction": "negative",
        "gate_decision": "block",
        "gate_decision_ref": "block",
    }
    blocked_deny_schema = validate_named_schema(
        blocked_deny_profile,
        "status-authority-view.schema.json",
    )
    assert not blocked_deny_schema.passed
    assert blocked_deny_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    missing_nested_block_profile = json.loads(json.dumps(profile))
    missing_nested_block_profile["authority_outcome"].pop("blocking_records")
    missing_nested_block_schema = validate_named_schema(
        missing_nested_block_profile,
        "status-authority-view.schema.json",
    )
    assert not missing_nested_block_schema.passed
    assert missing_nested_block_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    allow_with_blocking_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            _artifact_bundle_source(
                allow_with_blocking_profile,
                role=ArtifactRole.STATUS_AUTHORITY_VIEW.value,
            )
        )
    )
    assert not allow_with_blocking_report.passed
    assert allow_with_blocking_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert allow_with_blocking_report.final_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )
    assert profile["reason_ref_records"]
    assert profile["blocking_records"]
    assert "obligation_ref_records" in profile
    assert "proof_ref_records" in profile
    assert profile["authority_outcome"]["reason_ref_records"]
    assert profile["authority_outcome"]["blocking_records"]
    nested_reason = profile["blocking_records"][0]["reason_ref_records"][0]
    assert "source_path" in nested_reason
    assert nested_reason["source_artifact"]
    bad_pointer_profile = json.loads(json.dumps(profile))
    bad_pointer_profile["reason_ref_records"][0]["source_path"] = "relative"
    bad_pointer_schema = validate_named_schema(
        bad_pointer_profile,
        "status-authority-view.schema.json",
    )
    assert not bad_pointer_schema.passed
    assert bad_pointer_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    missing_digest_profile = json.loads(json.dumps(profile))
    missing_digest_profile["blocking_records"][0]["reason_ref_records"][0].pop("digest", None)
    missing_digest_schema = validate_named_schema(
        missing_digest_profile,
        "status-authority-view.schema.json",
    )
    assert not missing_digest_schema.passed
    assert missing_digest_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    missing_typed_evidence = {
        **profile,
        "reason_ref_records": [],
        "blocking_records": [],
        "authority_outcome": {
            **profile["authority_outcome"],
            "reason_ref_records": [],
            "blocking_records": [],
        },
    }
    invalid_schema = validate_named_schema(
        missing_typed_evidence,
        "status-authority-view.schema.json",
    )
    assert not invalid_schema.passed
    assert invalid_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    non_allow_gate_allow_missing_evidence = {
        **profile,
        "gate_decision_ref": "allow",
        "reason_ref_records": [],
        "blocking_records": [],
        "authority_outcome": {
            **profile["authority_outcome"],
            "code": "unknown",
            "gate_decision": "allow",
            "gate_decision_ref": "allow",
            "reason_ref_records": [],
            "blocking_records": [],
        },
    }
    non_allow_gate_allow_schema = validate_named_schema(
        non_allow_gate_allow_missing_evidence,
        "status-authority-view.schema.json",
    )
    assert not non_allow_gate_allow_schema.passed
    assert non_allow_gate_allow_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID

    missing_typed_proof = dict(profile)
    missing_typed_proof.pop("proof_ref_records")
    invalid_proof_schema = validate_named_schema(
        missing_typed_proof,
        "status-authority-view.schema.json",
    )
    assert not invalid_proof_schema.passed
    assert invalid_proof_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID

    missing_typed_set_refs = dict(profile)
    missing_typed_set_refs.pop("set_ref_records")
    invalid_set_ref_schema = validate_named_schema(
        missing_typed_set_refs,
        "status-authority-view.schema.json",
    )
    assert not invalid_set_ref_schema.passed
    assert invalid_set_ref_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID

    missing_typed_artifacts = dict(profile)
    missing_typed_artifacts.pop("artifact_ref_records")
    invalid_artifact_ref_schema = validate_named_schema(
        missing_typed_artifacts,
        "status-authority-view.schema.json",
    )
    assert not invalid_artifact_ref_schema.passed
    assert invalid_artifact_ref_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID


def test_status_view_normalizes_blocking_reasons_into_typed_profile() -> None:
    block = blocking_record(
        FailureCode.CHECKER_UNKNOWN,
        Layer.STATUS,
        "direct view construction lacks checker evidence",
    )
    outcome = AuthorityOutcome(
        layer=Layer.STATUS,
        code=StatusCode.UNKNOWN.value,
        direction=Direction.NONE,
        blocking_set=(block,),
        gate_decision=GateDecision.BLOCK,
        profile_ref="DFCC-Base",
        outcome_schema_ref="status-authority-view",
    )
    view = StatusAuthorityView(
        certificate_id="cert:direct",
        schema_profile_ref="DFCC-Base",
        canonicalization_profile_ref="RFC8785-JCS-SHA256",
        manifest_digest="sha256:direct",
        validation_result=ValidationResult(
            ValidationStage.AUTHORITY_EMIT,
            ValidationStatus.PASS,
        ),
        proposed_use=ProposedUse(
            mode="assertion",
            claim="safe-temp",
            horizon=1,
            anchor="anchor:issue",
        ),
        status_coordinates=(),
        blocking_set=(block,),
        dominant_status=StatusCode.UNKNOWN,
        kernel_verdict=None,
        authority_outcome=outcome,
    )

    profile = view.minimum_profile()

    assert profile["reason_refs"] == [block.reason_refs[0].reason_id]
    reason_record = profile["reason_ref_records"][0]
    assert reason_record["source_artifact"] == "artifact:inline"
    assert reason_record["source_path"] == "/"
    assert reason_record["digest"].startswith("sha256:")
    assert profile["authority_outcome"]["reason_ref_records"] == [profile["reason_ref_records"][0]]
    assert validate_named_schema(profile, "status-authority-view.schema.json").passed


def test_authority_outcome_runtime_invariant_requires_non_allow_evidence() -> None:
    typed_reason = reason(
        FailureCode.CHECKER_UNKNOWN,
        Layer.STATUS,
        "unknown authority needs blocking evidence",
        source_artifact="artifact:authority",
        source_path="/authority_outcome",
        digest="sha256:authority-reason",
    )
    with pytest.raises(ValueError, match="lacks reason refs"):
        validate_authority_outcome(
            AuthorityOutcome(
                layer=Layer.STATUS,
                code=StatusCode.UNKNOWN.value,
                direction=Direction.NONE,
                outcome_schema_ref="status-authority-view",
            )
        )
    with pytest.raises(ValueError, match="lacks blocking records"):
        validate_authority_outcome(
            AuthorityOutcome(
                layer=Layer.STATUS,
                code=StatusCode.UNKNOWN.value,
                direction=Direction.NONE,
                outcome_schema_ref="status-authority-view",
                reason_refs=(typed_reason,),
            )
        )
    block = blocking_record(
        FailureCode.CHECKER_UNKNOWN,
        Layer.STATUS,
        "unknown authority is blocked",
        source_artifact="artifact:authority",
        source_path="/authority_outcome",
    )
    validate_authority_outcome(
        AuthorityOutcome(
            layer=Layer.STATUS,
            code=StatusCode.UNKNOWN.value,
            direction=Direction.NONE,
            blocking_set=(block,),
            outcome_schema_ref="status-authority-view",
        )
    )
    with pytest.raises(ValueError, match="allow-like"):
        validate_authority_outcome(
            AuthorityOutcome(
                layer=Layer.OPERATIONAL,
                code=OperationalCode.ACCEPT.value,
                direction=Direction.POSITIVE,
                blocking_set=(block,),
                outcome_schema_ref="status-authority-view",
            )
        )


def test_strict_operational_replay_blocks_unresolved_declaration_proofs() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
        frame={
            "frame_id": "frame:demo",
            "scope": ["demo"],
            "policy": {"adequacy_direction": "positive"},
            "completion_interface_ref": "completion:demo",
        },
    )
    assert isinstance(issued, IssueCertificate)
    status = {
        "status_time": "2026-01-01T00:00:00Z",
        "observation_records": [
            {
                "r": 0,
                "represented_prefix": [{"temp": "70"}],
                "operational_prefix": [{"temp": "70"}],
                "operational_completions": [[{"temp": "70"}, {"temp": "70"}]],
                "prefix_adjudication": "accept",
                "target_adjudication": "accept",
                "calibration_ref": "calibration:demo",
                "latency_ref": "latency:demo",
                "dependency_ref": "dependency:demo",
                "event_order_ref": "event-order:demo",
                "representation_proof_ref": "representation-proof:demo",
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
    entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(
            {
                "mode": "operational",
                "claim": "safe-temp",
                "horizon": 1,
                "anchor": "anchor:issue",
                "scope": ["demo"],
                "frame": "frame:demo",
            },
            ArtifactRole.PROPOSED_USE,
            "artifact:use",
        ),
        _entry(status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
        _entry(
            {"status": "pass", "transcript": "completion admission accepted"},
            ArtifactRole.OTHER,
            "artifact:completion-transcript",
        ),
    ]
    report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:operational-missing-proofs",
                "manifest": {
                    "manifest_id": "manifest:operational-missing-proofs",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in entries
                    ],
                },
                "artifacts": entries,
            }
        ),
        full_replay=True,
    )
    assert report.authority_view is None
    assert report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert report.final_result.failure_records[0].code is FailureCode.SCHEMA_INVALID

    def proof_entry(artifact_id: str, **payload: object) -> dict[str, Any]:
        proof = {"status": "pass", "proof_kind": "operational-proof", **payload}
        ref = build_artifact_ref(
            proof,
            artifact_id=artifact_id,
            artifact_type="json",
            semantic_role="proof",
        )
        return {
            "artifact_ref": to_jsonable(ref),
            "artifact": proof,
            "role": ArtifactRole.OTHER.value,
        }

    def plain_entry(artifact_id: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        artifact = payload or {"status": "pass"}
        ref = build_artifact_ref(
            artifact,
            artifact_id=artifact_id,
            artifact_type="json",
            semantic_role=ArtifactRole.OTHER,
        )
        return {
            "artifact_ref": to_jsonable(ref),
            "artifact": artifact,
            "role": ArtifactRole.OTHER.value,
        }

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
                "operational_prefix": [{"temp": "70"}],
                "represented_prefix": [{"temp": "70"}],
                "proof_ref": "artifact:representation-proof",
            }
        ],
    }
    formal_status = {
        "status_time": "2026-01-01T00:00:00Z",
        "observation_records": [
            {
                "r": 0,
                "measurement_relation_ref": "artifact:measurement",
                "representation_relation_ref": "artifact:representation",
                "calibration_ref": "artifact:stale-calibration",
                "latency_ref": "artifact:stale-latency",
                "dependency_ref": "artifact:stale-dependency",
                "event_order_ref": "artifact:stale-event-order",
                "representation_proof_ref": "artifact:stale-representation-proof",
                "operational_prefix": [{"temp": "90"}],
                "represented_prefix": [{"temp": "90"}],
                "operational_completions": [[{"temp": "90"}, {"temp": "90"}]],
                "prefix_adjudication": "accept",
                "target_adjudication": "accept",
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
    completion_set_artifact = {
        **to_jsonable(
            set_ref(
                "carrier",
                "finite-json",
                "constraint",
                "exact",
                "artifact:set-soundness-proof#/proof",
            )
        ),
        "members": [[{"temp": "70"}, {"temp": "70"}]],
    }
    cut_payload = {
        "status_time": "2026-01-01T00:00:00Z",
        "time_basis": issued.time_basis_ref,
        "event_order": issued.event_order_commitment_ref,
        "frame_id": "frame:demo",
    }
    relation_entries = [
        *entries[:-2],
        _entry(formal_status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
        _entry(
            measurement_artifact,
            ArtifactRole.MEASUREMENT_RELATION,
            "artifact:measurement",
        ),
        _entry(
            representation_artifact,
            ArtifactRole.REPRESENTATION_RELATION,
            "artifact:representation",
        ),
        proof_entry("artifact:calibration", proof_kind="calibration", **cut_payload),
        proof_entry("artifact:latency", proof_kind="latency", **cut_payload),
        proof_entry("artifact:dependency", proof_kind="dependency", **cut_payload),
        proof_entry("artifact:event-order", proof_kind="event_order", **cut_payload),
        proof_entry(
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
        _entry(
            completion_set_artifact,
            ArtifactRole.SET,
            "artifact:completion-set",
        ),
        plain_entry("artifact:stale-calibration"),
        plain_entry("artifact:stale-latency"),
        plain_entry("artifact:stale-dependency"),
        plain_entry("artifact:stale-event-order"),
        proof_entry(
            "artifact:measurement-proof",
            relation_id="measurement:demo",
            calibration_ref="artifact:calibration",
            latency_ref="artifact:latency",
            dependency_ref="artifact:dependency",
            event_order_ref="artifact:event-order",
        ),
        proof_entry(
            "artifact:representation-proof",
            relation_id="representation:demo",
            operational_prefix=[{"temp": "70"}],
            represented_prefix=[{"temp": "70"}],
        ),
        proof_entry("artifact:stale-representation-proof"),
        proof_entry("artifact:prefix-proof", prefix_adjudication="accept"),
        proof_entry("artifact:target-proof", target_adjudication="accept"),
        proof_entry("artifact:adequacy-proof", adequacy_direction="positive"),
        *_kernel_proof_entries(),
    ]
    formal_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:operational-relation-artifacts",
            "manifest": {
                "manifest_id": "manifest:operational-relation-artifacts",
                "root_artifact_id": "artifact:cert",
                "artifact_refs": [entry["artifact_ref"] for entry in relation_entries],
                "dependency_order": [
                    str(entry["artifact_ref"]["artifact_id"]) for entry in relation_entries
                ],
            },
            "artifacts": relation_entries,
        }
    )
    formal_report = validate_artifact_bundle(
        formal_bundle,
        full_replay=True,
    )
    assert formal_report.authority_view is not None
    assert formal_report.authority_view.authority_outcome.code == OperationalCode.ACCEPT.value
    formal_profile = formal_report.authority_view.minimum_profile()
    assert validate_named_schema(formal_profile, "status-authority-view.schema.json").passed
    operational_missing_ref_profile = json.loads(json.dumps(formal_profile))
    operational_missing_ref_profile["agreement_ref"] = "not-applicable"
    invalid_operational_schema = validate_named_schema(
        operational_missing_ref_profile,
        "status-authority-view.schema.json",
    )
    assert not invalid_operational_schema.passed
    assert invalid_operational_schema.failure_records[0].code is FailureCode.SCHEMA_INVALID
    assert formal_report.authority_view.protocol_record_refs
    relation_records = {record.record_kind: record for record in formal_report.protocol_records}
    observation_sources = relation_records["ObservationCut"].payload["construction_sources"]
    assert observation_sources["strict_replay"]
    observation_owner_paths = {
        entry["owner_path"] for entry in observation_sources["ledger_entries"]
    }
    assert "/relations/0/proof_ref" in observation_owner_paths
    assert "/relation/calibration_ref" in observation_owner_paths
    completion_sources = relation_records["CompletionAdmission"].payload["construction_sources"]
    assert any(
        entry["owner_path"] == "/completion_policy/checker_transcript_ref"
        for entry in completion_sources["ledger_entries"]
    )
    assert any(
        entry.owner_path == "/relation/calibration_ref" and entry.resolved
        for entry in formal_report.authority_view.ledger_entries
    )
    assert any(
        entry.owner_path == "/relations/0/proof_ref" and entry.kind is ReferenceKind.PROOF
        for entry in formal_report.authority_view.ledger_entries
    )
    assert any(
        entry.owner_path == "/completion_policy/c_out_ref"
        and entry.kind is ReferenceKind.SET
        and entry.resolved
        for entry in formal_report.authority_view.ledger_entries
    )
    formal_replay = replay_authority_from_bundle(formal_bundle, strict_ledger=True)
    assert formal_replay.context is not None
    enriched_record = formal_replay.context.status_context.observation_records[0]
    assert enriched_record["representation_proof_ref"] == "artifact:representation-proof"
    assert enriched_record["operational_prefix"] == [{"temp": "70"}]
    assert enriched_record["represented_prefix"] == [{"temp": "70"}]
    assert enriched_record["operational_completions"] == [[{"temp": "70"}, {"temp": "70"}]]
    assert enriched_record["_operational_completions_source"] == "artifact:completion-set"
    assert enriched_record["calibration_ref"]["artifact_ref"] == "artifact:calibration"

    def relation_report(bundle_id: str, local_entries: list[dict[str, Any]]) -> PipelineReport:
        return validate_artifact_bundle(
            artifact_bundle_from_json(
                {
                    "bundle_id": bundle_id,
                    "manifest": {
                        "manifest_id": f"manifest:{bundle_id}",
                        "root_artifact_id": "artifact:cert",
                        "artifact_refs": [entry["artifact_ref"] for entry in local_entries],
                        "dependency_order": [
                            str(entry["artifact_ref"]["artifact_id"]) for entry in local_entries
                        ],
                    },
                    "artifacts": local_entries,
                }
            ),
            full_replay=True,
        )

    missing_completion_set_binding_entries = [
        (
            proof_entry(
                "artifact:completion-transcript",
                proof_kind="completion_admission",
                completion_status="pass",
                admission_source="completion-contract:demo",
                expiry="unbounded",
                uncertainty_model="exact",
                reference_digest="sha256:completion",
                checker_result="pass",
                status_time="2026-01-01T00:00:00Z",
            )
            if entry["artifact_ref"]["artifact_id"] == "artifact:completion-transcript"
            else entry
        )
        for entry in relation_entries
    ]
    missing_completion_set_binding_report = relation_report(
        "bundle:operational-completion-transcript-missing-set",
        missing_completion_set_binding_entries,
    )
    assert missing_completion_set_binding_report.authority_view is None
    assert missing_completion_set_binding_report.final_result.stage is (
        ValidationStage.GUARD_EVALUATE
    )
    assert missing_completion_set_binding_report.final_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert (
        missing_completion_set_binding_report.final_result.reason_refs[0].source_path
        == "/completion_policy/checker_transcript_ref/c_out_ref"
    )

    missing_completion_transcript_status = json.loads(json.dumps(formal_status))
    missing_completion_transcript_status["completion_policy"].pop("checker_transcript_ref")
    missing_completion_transcript_report = relation_report(
        "bundle:operational-completion-transcript-missing",
        [
            entry
            if entry["artifact_ref"]["artifact_id"] != "artifact:status-context"
            else _entry(
                missing_completion_transcript_status,
                ArtifactRole.STATUS_CONTEXT,
                "artifact:status-context",
            )
            for entry in relation_entries
        ],
    )
    assert missing_completion_transcript_report.authority_view is None
    assert missing_completion_transcript_report.final_result.failure_records[0].code is (
        FailureCode.MISSING_REF
    )
    assert (
        missing_completion_transcript_report.final_result.reason_refs[0].source_path
        == "/completion_policy/checker_transcript_ref"
    )

    digest_only_completion_transcript_status = json.loads(json.dumps(formal_status))
    digest_only_completion_transcript_status["completion_policy"]["checker_transcript_ref"] = (
        "sha256:completion-transcript"
    )
    digest_only_completion_transcript_report = relation_report(
        "bundle:operational-completion-transcript-digest-only",
        [
            entry
            if entry["artifact_ref"]["artifact_id"] != "artifact:status-context"
            else _entry(
                digest_only_completion_transcript_status,
                ArtifactRole.STATUS_CONTEXT,
                "artifact:status-context",
            )
            for entry in relation_entries
        ],
    )
    assert digest_only_completion_transcript_report.authority_view is None
    assert digest_only_completion_transcript_report.final_result.failure_records[0].code is (
        FailureCode.MISSING_REF
    )

    rejected_completion_transcript_entries = [
        (
            proof_entry(
                "artifact:completion-transcript",
                proof_kind="completion_admission",
                status="fail",
                completion_status="pass",
                admission_source="completion-contract:demo",
                expiry="unbounded",
                uncertainty_model="exact",
                reference_digest="sha256:completion",
                checker_result="pass",
                c_out_ref="artifact:completion-set",
                status_time="2026-01-01T00:00:00Z",
            )
            if entry["artifact_ref"]["artifact_id"] == "artifact:completion-transcript"
            else entry
        )
        for entry in relation_entries
    ]
    rejected_completion_transcript_report = relation_report(
        "bundle:operational-completion-transcript-rejected",
        rejected_completion_transcript_entries,
    )
    assert rejected_completion_transcript_report.authority_view is None
    assert rejected_completion_transcript_report.final_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )

    wrong_kind_completion_transcript_entries = [
        (
            proof_entry(
                "artifact:completion-transcript",
                proof_kind="schema_validation",
                completion_status="pass",
                admission_source="completion-contract:demo",
                expiry="unbounded",
                uncertainty_model="exact",
                reference_digest="sha256:completion",
                checker_result="pass",
                c_out_ref="artifact:completion-set",
                status_time="2026-01-01T00:00:00Z",
            )
            if entry["artifact_ref"]["artifact_id"] == "artifact:completion-transcript"
            else entry
        )
        for entry in relation_entries
    ]
    wrong_kind_completion_transcript_report = relation_report(
        "bundle:operational-completion-transcript-wrong-kind",
        wrong_kind_completion_transcript_entries,
    )
    assert wrong_kind_completion_transcript_report.authority_view is None
    assert wrong_kind_completion_transcript_report.final_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )

    frame_policy_status = json.loads(json.dumps(formal_status))
    frame_policy_status["frame"] = {
        "policy": {
            "adequacy_direction": "positive",
            "adequacy_proof_ref": "artifact:adequacy-proof",
        }
    }
    frame_policy_status["observation_records"][0].pop("adequacy_proof_ref")
    frame_policy_entries = [
        entry
        if entry["artifact_ref"]["artifact_id"] != "artifact:status-context"
        else _entry(frame_policy_status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context")
        for entry in relation_entries
    ]
    frame_policy_report = relation_report(
        "bundle:operational-frame-adequacy-proof",
        frame_policy_entries,
    )
    assert frame_policy_report.authority_view is not None
    assert frame_policy_report.authority_view.authority_outcome.code == (
        OperationalCode.ACCEPT.value
    )
    frame_policy_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:operational-frame-adequacy-proof-replay",
                "manifest": {
                    "manifest_id": "manifest:operational-frame-adequacy-proof-replay",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in frame_policy_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in frame_policy_entries
                    ],
                },
                "artifacts": frame_policy_entries,
            }
        ),
        strict_ledger=True,
    )
    assert frame_policy_replay.context is not None
    assert frame_policy_replay.context.status_context.frame["policy"]["adequacy_direction"] == (
        "positive"
    )

    conflicting_frame_adequacy_entries = [
        entry
        if entry["artifact_ref"]["artifact_id"] == "artifact:status-context"
        else (
            proof_entry("artifact:adequacy-proof", adequacy_direction="negative")
            if entry["artifact_ref"]["artifact_id"] == "artifact:adequacy-proof"
            else entry
        )
        for entry in frame_policy_entries
    ]
    conflicting_frame_adequacy_report = relation_report(
        "bundle:operational-frame-adequacy-conflict",
        conflicting_frame_adequacy_entries,
    )
    assert conflicting_frame_adequacy_report.authority_view is None
    assert conflicting_frame_adequacy_report.final_result.stage is ValidationStage.GUARD_EVALUATE
    assert conflicting_frame_adequacy_report.final_result.failure_records[0].code is (
        FailureCode.ARTIFACT_CONFLICT
    )
    assert conflicting_frame_adequacy_report.final_result.reason_refs[0].source_path == (
        "/frame/policy/adequacy_direction"
    )

    rejected_representation = {
        **representation_artifact,
        "checker_status": "fail",
    }
    rejected_relation_report = relation_report(
        "bundle:operational-rejected-representation-relation",
        [
            *entries[:-2],
            _entry(formal_status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
            _entry(measurement_artifact, ArtifactRole.MEASUREMENT_RELATION, "artifact:measurement"),
            _entry(
                rejected_representation,
                ArtifactRole.REPRESENTATION_RELATION,
                "artifact:representation",
            ),
            *relation_entries[9:],
        ],
    )
    assert rejected_relation_report.authority_view is None
    assert rejected_relation_report.final_result.stage is ValidationStage.GUARD_EVALUATE
    assert rejected_relation_report.final_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert rejected_relation_report.final_result.reason_refs[0].source_path == "/checker_status"

    missing_measurement_proof = {
        key: value for key, value in measurement_artifact.items() if key != "proof_refs"
    }
    missing_measurement_proof_report = relation_report(
        "bundle:operational-missing-measurement-proof",
        [
            *entries[:-2],
            _entry(formal_status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
            _entry(
                missing_measurement_proof,
                ArtifactRole.MEASUREMENT_RELATION,
                "artifact:measurement",
            ),
            _entry(
                representation_artifact,
                ArtifactRole.REPRESENTATION_RELATION,
                "artifact:representation",
            ),
            *relation_entries[9:],
        ],
    )
    assert missing_measurement_proof_report.authority_view is None
    assert missing_measurement_proof_report.final_result.stage is ValidationStage.SCHEMA_VALIDATE
    assert missing_measurement_proof_report.final_result.failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )

    symbolic_measurement_proof = {
        **measurement_artifact,
        "proof_refs": ["proof:measurement"],
    }
    symbolic_measurement_entries = [
        *entries[:-2],
        _entry(formal_status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
        _entry(
            symbolic_measurement_proof,
            ArtifactRole.MEASUREMENT_RELATION,
            "artifact:measurement",
        ),
        _entry(
            representation_artifact,
            ArtifactRole.REPRESENTATION_RELATION,
            "artifact:representation",
        ),
        *relation_entries[9:],
    ]
    symbolic_measurement_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:operational-symbolic-measurement-proof",
                "manifest": {
                    "manifest_id": "manifest:operational-symbolic-measurement-proof",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in symbolic_measurement_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in symbolic_measurement_entries
                    ],
                },
                "artifacts": symbolic_measurement_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not symbolic_measurement_replay.passed
    assert symbolic_measurement_replay.validation_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert symbolic_measurement_replay.validation_result.reason_refs[0].source_path == (
        "/proof_refs/0"
    )

    symbolic_representation = {
        **representation_artifact,
        "relations": [
            {
                **representation_artifact["relations"][0],
                "proof_ref": "representation-proof:local",
            }
        ],
    }
    symbolic_representation_entries = [
        *entries[:-2],
        _entry(formal_status, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
        _entry(measurement_artifact, ArtifactRole.MEASUREMENT_RELATION, "artifact:measurement"),
        _entry(
            symbolic_representation,
            ArtifactRole.REPRESENTATION_RELATION,
            "artifact:representation",
        ),
        *relation_entries[9:],
    ]
    symbolic_representation_replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:operational-symbolic-representation-proof",
                "manifest": {
                    "manifest_id": "manifest:operational-symbolic-representation-proof",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [
                        entry["artifact_ref"] for entry in symbolic_representation_entries
                    ],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in symbolic_representation_entries
                    ],
                },
                "artifacts": symbolic_representation_entries,
            }
        ),
        strict_ledger=True,
    )
    assert not symbolic_representation_replay.passed
    assert symbolic_representation_replay.validation_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert symbolic_representation_replay.validation_result.reason_refs[0].source_path == (
        "/relations/0/proof_ref"
    )

    missing_measurement_proof_content_entries = [
        entry
        if entry["artifact_ref"]["artifact_id"] != "artifact:measurement-proof"
        else proof_entry("artifact:measurement-proof")
        for entry in relation_entries
    ]
    missing_measurement_proof_content_report = relation_report(
        "bundle:operational-missing-measurement-proof-content",
        missing_measurement_proof_content_entries,
    )
    assert missing_measurement_proof_content_report.authority_view is None
    assert missing_measurement_proof_content_report.final_result.stage is (
        ValidationStage.GUARD_EVALUATE
    )
    assert (
        missing_measurement_proof_content_report.final_result.failure_records[0].code
        is FailureCode.CHECKER_UNKNOWN
    )
    assert missing_measurement_proof_content_report.final_result.reason_refs[0].source_path == (
        "/proof_refs/0/relation_id"
    )

    conflicting_representation_proof_entries = [
        entry
        if entry["artifact_ref"]["artifact_id"] != "artifact:representation-proof"
        else proof_entry(
            "artifact:representation-proof",
            relation_id="representation:demo",
            operational_prefix=[{"temp": "90"}],
            represented_prefix=[{"temp": "70"}],
        )
        for entry in relation_entries
    ]
    conflicting_representation_proof_report = relation_report(
        "bundle:operational-representation-proof-conflict",
        conflicting_representation_proof_entries,
    )
    assert conflicting_representation_proof_report.authority_view is None
    assert conflicting_representation_proof_report.final_result.stage is (
        ValidationStage.GUARD_EVALUATE
    )
    assert (
        conflicting_representation_proof_report.final_result.failure_records[0].code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert conflicting_representation_proof_report.final_result.reason_refs[0].source_path == (
        "/relations/0/proof_ref/operational_prefix"
    )

    missing_proof_content_entries = [
        entry
        if entry["artifact_ref"]["artifact_id"] != "artifact:prefix-proof"
        else proof_entry("artifact:prefix-proof")
        for entry in relation_entries
    ]
    missing_proof_content_report = relation_report(
        "bundle:operational-missing-prefix-proof-content",
        missing_proof_content_entries,
    )
    assert missing_proof_content_report.authority_view is None
    assert missing_proof_content_report.final_result.stage is ValidationStage.GUARD_EVALUATE
    assert missing_proof_content_report.final_result.failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert missing_proof_content_report.final_result.reason_refs[0].source_path == (
        "/observation_records/0/prefix_adjudication_proof_ref"
    )

    missing_completion_members_entries = [
        entry
        if entry["artifact_ref"]["artifact_id"] != "artifact:completion-set"
        else _entry(
            {key: value for key, value in completion_set_artifact.items() if key != "members"},
            ArtifactRole.SET,
            "artifact:completion-set",
        )
        for entry in relation_entries
    ]
    missing_completion_members_report = relation_report(
        "bundle:operational-missing-completion-members",
        missing_completion_members_entries,
    )
    assert missing_completion_members_report.authority_view is not None
    assert (
        missing_completion_members_report.authority_view.authority_outcome.code
        != OperationalCode.ACCEPT.value
    )
    assert any(
        block.failure_code is FailureCode.CHECKER_UNKNOWN
        and block.reason_refs
        and "completion set artifact members" in block.reason_refs[0].message
        for block in missing_completion_members_report.authority_view.blocking_set
    )

    symbolic_set_soundness = {
        **to_jsonable(set_ref("carrier", "finite-json", "constraint", "exact", "soundness")),
        "members": [[{"temp": "70"}, {"temp": "70"}]],
    }
    symbolic_set_soundness_report = relation_report(
        "bundle:operational-symbolic-set-soundness",
        [
            entry
            if entry["artifact_ref"]["artifact_id"] != "artifact:completion-set"
            else _entry(symbolic_set_soundness, ArtifactRole.SET, "artifact:completion-set")
            for entry in relation_entries
        ],
    )
    assert symbolic_set_soundness_report.authority_view is not None
    assert any(
        block.failure_code is FailureCode.CHECKER_UNKNOWN
        and block.reason_refs
        and "SetRef artifact" in block.reason_refs[0].message
        for block in symbolic_set_soundness_report.authority_view.blocking_set
    )

    conflicting_target_proof_entries = [
        entry
        if entry["artifact_ref"]["artifact_id"] != "artifact:target-proof"
        else proof_entry("artifact:target-proof", target_adjudication="reject")
        for entry in relation_entries
    ]
    conflicting_target_report = relation_report(
        "bundle:operational-target-proof-conflict",
        conflicting_target_proof_entries,
    )
    assert conflicting_target_report.authority_view is None
    assert conflicting_target_report.final_result.stage is ValidationStage.GUARD_EVALUATE
    assert conflicting_target_report.final_result.failure_records[0].code is (
        FailureCode.ARTIFACT_CONFLICT
    )
    assert conflicting_target_report.final_result.reason_refs[0].source_path == (
        "/observation_records/0/target_adjudication"
    )

    no_completion_set_status = {
        **formal_status,
        "completion_policy": {
            key: value
            for key, value in formal_status["completion_policy"].items()
            if key != "c_out_ref"
        },
    }
    no_completion_set_entries = [
        *entries[:-2],
        _entry(
            no_completion_set_status,
            ArtifactRole.STATUS_CONTEXT,
            "artifact:status-context",
        ),
        *relation_entries[7:],
    ]
    no_completion_set_report = validate_artifact_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:operational-missing-completion-set",
                "manifest": {
                    "manifest_id": "manifest:operational-missing-completion-set",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in no_completion_set_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in no_completion_set_entries
                    ],
                },
                "artifacts": no_completion_set_entries,
            }
        ),
        full_replay=True,
    )
    assert no_completion_set_report.authority_view is not None
    assert (
        no_completion_set_report.authority_view.authority_outcome.code
        != OperationalCode.ACCEPT.value
    )
    assert any(
        block.failure_code is FailureCode.CHECKER_UNKNOWN
        and block.reason_refs
        and "completion outer set" in block.reason_refs[0].message
        for block in no_completion_set_report.authority_view.blocking_set
    )


def test_completion_proof_payload_failure_classifies_unusable_refs() -> None:
    transcript_entry = _entry(
        {"status": "fail", "proof_kind": "completion_admission"},
        ArtifactRole.OTHER,
        "artifact:completion-transcript",
    )
    bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:completion-proof-helper",
            "manifest": {
                "manifest_id": "manifest:completion-proof-helper",
                "root_artifact_id": "artifact:completion-transcript",
                "artifact_refs": [transcript_entry["artifact_ref"]],
                "dependency_order": ["artifact:completion-transcript"],
            },
            "artifacts": [transcript_entry],
        }
    )
    expected = {"completion_status": "pass"}

    symbolic = _completion_proof_payload_failure(
        bundle=bundle,
        ref_value="checker:completion-transcript",
        expected_fields=expected,
        source_artifact=bundle.bundle_id,
        source_path_prefix="/completion_policy/checker_transcript_ref",
    )
    assert symbolic is not None
    assert symbolic.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    rejected = _completion_proof_payload_failure(
        bundle=bundle,
        ref_value="artifact:completion-transcript",
        expected_fields=expected,
        source_artifact=bundle.bundle_id,
        source_path_prefix="/completion_policy/checker_transcript_ref",
    )
    assert rejected is not None
    assert rejected.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    assert "not accepted" in rejected.reason_refs[0].message

    digest_only = _completion_proof_payload_failure(
        bundle=bundle,
        ref_value="sha256:completion-transcript",
        expected_fields=expected,
        source_artifact=bundle.bundle_id,
        source_path_prefix="/completion_policy/checker_transcript_ref",
    )
    assert digest_only is not None
    assert digest_only.failure_records[0].code is FailureCode.MISSING_REF

    conflicting_entry = _entry(
        {"status": "pass", "proof_kind": "completion_admission", "completion_status": "unknown"},
        ArtifactRole.OTHER,
        "artifact:conflicting-completion-transcript",
    )
    conflicting_bundle = artifact_bundle_from_json(
        {
            "bundle_id": "bundle:completion-proof-conflict",
            "manifest": {
                "manifest_id": "manifest:completion-proof-conflict",
                "root_artifact_id": "artifact:conflicting-completion-transcript",
                "artifact_refs": [conflicting_entry["artifact_ref"]],
                "dependency_order": ["artifact:conflicting-completion-transcript"],
            },
            "artifacts": [conflicting_entry],
        }
    )
    conflicting = _completion_proof_payload_failure(
        bundle=conflicting_bundle,
        ref_value="artifact:conflicting-completion-transcript",
        expected_fields=expected,
        source_artifact=conflicting_bundle.bundle_id,
        source_path_prefix="/completion_policy/checker_transcript_ref",
    )
    assert conflicting is not None
    assert conflicting.failure_records[0].code is FailureCode.ARTIFACT_CONFLICT


def test_lifecycle_unresolved_proof_ref_blocks_full_replay() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    entries = [
        _entry(to_jsonable(issued), ArtifactRole.ISSUE_CERTIFICATE, "artifact:cert"),
        _entry(issued.claim_source, ArtifactRole.CLAIM, issued.claim_ref),
        _entry(issued.bundle_source, ArtifactRole.ASSUMPTION_BUNDLE, issued.assumption_bundle_ref),
        _entry(issued.anchor_source, ArtifactRole.ANCHOR, issued.anchor_ref),
        _entry(issued.time_basis_source, ArtifactRole.TIME_BASIS, issued.time_basis_ref),
        _entry(
            {
                "mode": "assertion",
                "claim": "safe-temp",
                "horizon": 1,
                "anchor": "anchor:issue",
                "scope": ["demo"],
            },
            ArtifactRole.PROPOSED_USE,
            "artifact:use",
        ),
        _entry(
            {
                "status_time": "2026-01-01T00:00:00Z",
                "event_log": [
                    {
                        "event_id": "evt-conflict",
                        "certificate_id": issued.certificate_id,
                        "time": "2026-01-01T00:00:00Z",
                        "logical_clock": 1,
                        "kind": "conflict",
                        "confluence_proof_ref": "artifact:missing-confluence-proof",
                    }
                ],
            },
            ArtifactRole.STATUS_CONTEXT,
            "artifact:status-context",
        ),
    ]
    replay = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:missing-confluence-proof",
                "manifest": {
                    "manifest_id": "manifest:missing-confluence-proof",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in entries
                    ],
                },
                "artifacts": entries,
            }
        ),
        strict_ledger=True,
    )
    assert not replay.passed
    assert replay.validation_result.failure_records[0].code is FailureCode.MISSING_REF

    def replay_with_status(
        status_source: dict[str, object],
        extra_entries: tuple[dict[str, Any], ...] = (),
    ) -> ValidationResult:
        local_entries = [
            *entries[:-1],
            _entry(status_source, ArtifactRole.STATUS_CONTEXT, "artifact:status-context"),
            *extra_entries,
        ]
        result = replay_authority_from_bundle(
            artifact_bundle_from_json(
                {
                    "bundle_id": "bundle:lifecycle-strict-proof",
                    "manifest": {
                        "manifest_id": "manifest:lifecycle-strict-proof",
                        "root_artifact_id": "artifact:cert",
                        "artifact_refs": [entry["artifact_ref"] for entry in local_entries],
                        "dependency_order": [
                            str(entry["artifact_ref"]["artifact_id"]) for entry in local_entries
                        ],
                    },
                    "artifacts": local_entries,
                }
            ),
            strict_ledger=True,
        )
        assert not result.passed
        return result.validation_result

    top_level_missing = replay_with_status(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "confluence_proof": "artifact:missing-confluence-proof",
        }
    )
    assert top_level_missing.failure_records[0].code is FailureCode.MISSING_REF
    assert top_level_missing.reason_refs[0].source_path == "/confluence_proof"

    local_label = replay_with_status(
        {"status_time": "2026-01-01T00:00:00Z", "confluence_proof": "proof:local"}
    )
    assert local_label.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    assert local_label.reason_refs[0].source_path == "/confluence_proof"

    event_local_label = replay_with_status(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [
                {
                    "event_id": "evt-local-confluence",
                    "certificate_id": issued.certificate_id,
                    "time": "2026-01-01T00:00:00Z",
                    "logical_clock": 1,
                    "kind": "conflict",
                    "confluence_proof_ref": "proof:local",
                }
            ],
        }
    )
    assert event_local_label.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    assert event_local_label.reason_refs[0].source_path.endswith("/confluence_proof_ref")

    symbolic = replay_with_status(
        {"status_time": "2026-01-01T00:00:00Z", "confluence_proof": "symbolic-proof"}
    )
    assert symbolic.failure_records[0].code is FailureCode.CHECKER_UNKNOWN

    mismatched_confluence = replay_with_status(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "confluence_proof": "artifact:confluence-proof",
            "event_log": [
                {
                    "event_id": "evt-conflict",
                    "certificate_id": issued.certificate_id,
                    "time": "2026-01-01T00:00:00Z",
                    "logical_clock": 1,
                    "kind": "mark-unknown",
                }
            ],
        },
        (
            _proof_entry(
                "artifact:confluence-proof",
                proof_kind="confluence",
                event_ids=["evt-other"],
            ),
        ),
    )
    assert mismatched_confluence.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    assert mismatched_confluence.reason_refs[0].source_path == "/confluence_proof"

    missing_signature_ref = replay_with_status(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [
                {
                    "event_id": "evt-signed",
                    "certificate_id": issued.certificate_id,
                    "time": "2026-01-01T00:00:00Z",
                    "logical_clock": 1,
                    "kind": "mark-unknown",
                    "signature": "signature-bytes",
                    "signature_verifier_result": "pass",
                    "payload": {"signature_policy": "required"},
                }
            ],
        }
    )
    assert missing_signature_ref.failure_records[0].code is FailureCode.MISSING_REF
    assert missing_signature_ref.reason_refs[0].source_path.endswith(
        "/signature_verifier_result_ref"
    )

    missing_manifest_ref = replay_with_status(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [
                {
                    "event_id": "evt-manifest",
                    "certificate_id": issued.certificate_id,
                    "time": "2026-01-01T00:00:00Z",
                    "logical_clock": 1,
                    "kind": "mark-unknown",
                    "manifest_digest": "sha256:manifest",
                }
            ],
        }
    )
    assert missing_manifest_ref.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    assert missing_manifest_ref.reason_refs[0].source_path.endswith("/manifest_digest_ref")

    signature_proof = {
        "status": "pass",
        "proof_kind": "signature-verifier",
        "signature_verifier_result": "pass",
    }
    signature_ref = build_artifact_ref(
        signature_proof,
        artifact_id="artifact:signature-proof",
        artifact_type="json",
        semantic_role="proof",
    )
    verified_entries = [
        *entries[:-1],
        _entry(
            {
                "status_time": "2026-01-01T00:00:00Z",
                "event_log": [
                    {
                        "event_id": "evt-verified",
                        "certificate_id": issued.certificate_id,
                        "time": "2026-01-01T00:00:00Z",
                        "logical_clock": 1,
                        "kind": "mark-unknown",
                        "signature": "signature-bytes",
                        "signature_verifier_result": "pass",
                        "signature_verifier_result_ref": "artifact:signature-proof",
                        "payload": {"signature_policy": "required"},
                    }
                ],
            },
            ArtifactRole.STATUS_CONTEXT,
            "artifact:status-context",
        ),
        {
            "artifact_ref": to_jsonable(signature_ref),
            "artifact": signature_proof,
            "role": ArtifactRole.OTHER.value,
        },
    ]
    verified = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:lifecycle-verified-signature",
                "manifest": {
                    "manifest_id": "manifest:lifecycle-verified-signature",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in verified_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"]) for entry in verified_entries
                    ],
                },
                "artifacts": verified_entries,
            }
        ),
        strict_ledger=True,
    )
    assert verified.passed
    assert verified.context is not None
    assert any(
        entry.kind is ReferenceKind.PROOF
        and entry.owner_path == "/event_log/0/signature_verifier_result_ref"
        and entry.resolved
        for entry in verified.context.ledger_entries
    )

    signature_mismatch = replay_with_status(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [
                {
                    "event_id": "evt-signature-mismatch",
                    "certificate_id": issued.certificate_id,
                    "time": "2026-01-01T00:00:00Z",
                    "logical_clock": 1,
                    "kind": "mark-unknown",
                    "signature": "signature-bytes",
                    "signature_verifier_result": "pass",
                    "signature_verifier_result_ref": "artifact:bad-signature-proof",
                    "payload": {"signature_policy": "required"},
                }
            ],
        },
        (
            _proof_entry(
                "artifact:bad-signature-proof",
                proof_kind="signature-verifier",
                signature_verifier_result="fail",
            ),
        ),
    )
    assert signature_mismatch.failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    assert signature_mismatch.reason_refs[0].source_path.endswith("/signature_verifier_result_ref")

    manifest_mismatch = replay_with_status(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [
                {
                    "event_id": "evt-manifest-mismatch",
                    "certificate_id": issued.certificate_id,
                    "time": "2026-01-01T00:00:00Z",
                    "logical_clock": 1,
                    "kind": "mark-unknown",
                    "manifest_digest": "sha256:actual",
                    "manifest_digest_ref": "artifact:manifest-proof",
                    "hashes": ["sha256:actual"],
                }
            ],
        },
        (
            _proof_entry(
                "artifact:manifest-proof",
                proof_kind="event_manifest_digest",
                event_manifest_digest="sha256:other",
            ),
        ),
    )
    assert manifest_mismatch.failure_records[0].code is FailureCode.DIGEST_MISMATCH
    assert manifest_mismatch.reason_refs[0].source_path.endswith("/manifest_digest_ref")

    trace_class_mismatch = replay_with_status(
        {
            "status_time": "2026-01-01T00:00:00Z",
            "event_log": [
                {
                    "event_id": "evt-trace-mismatch",
                    "certificate_id": issued.certificate_id,
                    "time": "2026-01-01T00:00:00Z",
                    "logical_clock": 1,
                    "kind": "mark-unknown",
                    "trace_class_ref": "artifact:trace-class-proof",
                }
            ],
        },
        (
            _proof_entry(
                "artifact:trace-class-proof",
                proof_kind="trace_class",
                trace_class=["expire"],
            ),
        ),
    )
    assert trace_class_mismatch.failure_records[0].code is FailureCode.TRACE_CONFLICT
    assert trace_class_mismatch.reason_refs[0].source_path.endswith("/trace_class_ref")

    event_confluence_entries = [
        *entries[:-1],
        _entry(
            {
                "status_time": "2026-01-01T00:00:00Z",
                "event_log": [
                    {
                        "event_id": "evt-1",
                        "certificate_id": issued.certificate_id,
                        "time": "2026-01-01T00:00:00Z",
                        "logical_clock": 1,
                        "kind": "mark-unknown",
                    },
                    {
                        "event_id": "evt-2",
                        "certificate_id": issued.certificate_id,
                        "time": "2026-01-01T00:00:01Z",
                        "logical_clock": 2,
                        "kind": "mark-unknown",
                        "payload": {"conflicts_with": "evt-1"},
                        "confluence_proof_ref": "artifact:event-confluence-proof",
                    },
                ],
            },
            ArtifactRole.STATUS_CONTEXT,
            "artifact:status-context",
        ),
        _proof_entry(
            "artifact:event-confluence-proof",
            proof_kind="confluence",
            event_ids=["evt-1", "evt-2"],
        ),
    ]
    event_confluence = replay_authority_from_bundle(
        artifact_bundle_from_json(
            {
                "bundle_id": "bundle:lifecycle-event-confluence",
                "manifest": {
                    "manifest_id": "manifest:lifecycle-event-confluence",
                    "root_artifact_id": "artifact:cert",
                    "artifact_refs": [entry["artifact_ref"] for entry in event_confluence_entries],
                    "dependency_order": [
                        str(entry["artifact_ref"]["artifact_id"])
                        for entry in event_confluence_entries
                    ],
                },
                "artifacts": event_confluence_entries,
            }
        ),
        strict_ledger=True,
    )
    assert event_confluence.authority_view is not None
    assert all(
        block.failure_code is not FailureCode.TRACE_CONFLICT
        for block in event_confluence.authority_view.blocking_set
    )
    assert isinstance(event_confluence.context.status_context.confluence_proof, dict)


def test_kernel_view_exposes_typed_proof_metadata() -> None:
    issued = certify_claim(
        _claim(),
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(issued, IssueCertificate)
    result = check_authority(
        issued,
        {
            "mode": "assertion",
            "claim": "safe-temp",
            "horizon": 1,
            "anchor": "anchor:issue",
            "scope": ["demo"],
        },
        {"status_time": "2026-01-01T00:00:00Z"},
        allow_synthetic_trust=True,
    )
    assert not isinstance(result, type(validate_artifact_ref(ArtifactRef("x", "json"))))
    assert result.proof_refs
    profile = result.minimum_profile()
    assert profile["proof_ref_records"]
    assert profile["proof_ref_records"][0]["proof_id"] in profile["proof_refs"]
    proof_kinds = {record["proof_kind"] for record in profile["proof_ref_records"]}
    assert "witness" in proof_kinds
    assert "inclusion" in proof_kinds
    assert "exact-finite-witness" not in set(profile["proof_refs"])
    assert validate_named_schema(profile, "status-authority-view.schema.json").passed
    assert isinstance(
        KernelProof.from_mapping({"backend": "b", "proof_kind": "k", "proof_status": "accepted"}),
        KernelProof,
    )
    rich_proof = KernelProof.from_mapping(
        {
            "backend": "finite",
            "proof_kind": "relation",
            "proof_status": "accepted",
            "infeasibility_ref": "sha256:" + "1" * 64,
            "inclusion_ref": "sha256:" + "2" * 64,
            "disjointness_ref": "sha256:" + "3" * 64,
            "artifact_conflict_refs": ["sha256:" + "4" * 64],
        },
        witness_refs=("sha256:" + "5" * 64,),
        strict_refs=False,
    )
    rich_ref_kinds = {ref.proof_kind for ref in rich_proof.refs()}
    assert {
        "relation",
        "witness",
        "infeasibility",
        "inclusion",
        "disjointness",
        "artifact_conflict",
    } <= rich_ref_kinds
    assert rich_proof.to_json()["artifact_conflict_refs"] == ["sha256:" + "4" * 64]
    proof_artifact = KernelProofArtifact.from_json(
        {
            "artifact_id": "artifact:kernel-proof",
            "proof": rich_proof.to_json(),
            "checker_transcript_ref": "artifact:checker-transcript",
        }
    )
    assert any(ref.proof_kind == "checker_transcript" for ref in proof_artifact.proof_refs())
    deny_claim = {
        **_claim(),
        "claim_id": "unsafe-temp",
        "formula": {
            "op": "atom",
            "name": "field_cmp",
            "args": {"field": "temp", "op": "lte", "value": "60"},
        },
    }
    deny_issued = certify_claim(
        deny_claim,
        _finite_bundle(),
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60},
        {"clock_id": "utc", "uncertainty_seconds": "0"},
    )
    assert isinstance(deny_issued, IssueCertificate)
    deny_result = check_authority(
        deny_issued,
        {
            "mode": "assertion",
            "claim": "unsafe-temp",
            "horizon": 1,
            "anchor": "anchor:issue",
            "scope": ["demo"],
        },
        {"status_time": "2026-01-01T00:00:00Z"},
        allow_synthetic_trust=True,
    )
    assert deny_result.authority_outcome.code == "deny"
    deny_profile = deny_result.minimum_profile()
    assert any(
        record["proof_kind"] == "disjointness" for record in deny_profile["proof_ref_records"]
    )
    assert deny_result.authority_outcome.reason_refs
    assert deny_result.authority_outcome.reason_refs[0].source_path == "/kernel_verdict"
    assert validate_named_schema(
        deny_result.minimum_profile(),
        "status-authority-view.schema.json",
    ).passed
