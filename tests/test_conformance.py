from __future__ import annotations

import json
from dataclasses import asdict, replace
from pathlib import Path

from dfcc.artifacts import artifact_bundle_from_json, build_artifact_ref
from dfcc.conformance import (
    _artifact_bundle_case_source,
    _artifact_bundle_trace_contract_failure,
    _pipeline_equality_key,
    load_golden_cases,
    run_golden_cases,
)
from dfcc.types import (
    FailureCode,
    Layer,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    reason,
    validation_failure,
)
from dfcc.validation import PipelineReport, validate_artifact_bundle


def _minimal_artifact_bundle_source() -> dict[str, object]:
    artifact = {"x": {"y": "z"}}
    ref = build_artifact_ref(
        artifact,
        artifact_id="artifact:primary-contract-root",
        artifact_type="json",
    )
    ref_source = asdict(ref)
    return {
        "bundle_id": "primary-contract-bundle",
        "manifest": {
            "manifest_id": "manifest:primary-contract-bundle",
            "root_artifact_id": ref.artifact_id,
            "artifact_refs": [ref_source],
            "dependency_order": [ref.artifact_id],
        },
        "reference_context": {"snapshot_id": "snapshot:primary-contract"},
        "artifacts": [
            {
                "artifact_ref": ref_source,
                "artifact": artifact,
                "role": "root",
                "reason_paths": ["/x/y"],
            }
        ],
    }


def _case_dir(tmp_path: Path, case: dict[str, object]) -> Path:
    case_dir = tmp_path / "cases"
    case_dir.mkdir()
    (case_dir / "case.json").write_text(json.dumps(case), encoding="utf-8")
    return case_dir


def test_golden_cases_pass() -> None:
    results = run_golden_cases()
    assert results
    assert all(result.passed for result in results)


def test_bundled_cases_separate_primary_and_legacy_suites() -> None:
    cases = load_golden_cases()
    assert any(
        case.get("kind") == "artifact-bundle" and case.get("suite", "primary") == "primary"
        for case in cases
    )
    assert all(
        case.get("kind") == "artifact-bundle" or str(case.get("suite", "")).startswith("legacy")
        for case in cases
    )
    primary = run_golden_cases(suite="primary")
    legacy = run_golden_cases(suite="legacy")
    assert primary
    assert legacy
    assert all(result.case_id.startswith("primary-") for result in primary)
    assert not any(result.case_id.startswith("primary-") for result in legacy)
    assert all(result.passed for result in (*primary, *legacy))


def test_bundled_primary_authority_fixtures_materialize_to_full_replay() -> None:
    cases = load_golden_cases()
    primary_fixtures = [
        case
        for case in cases
        if case.get("kind") == "artifact-bundle"
        and case.get("suite", "primary") == "primary"
        and str(case.get("fixture", "")).startswith("authority:")
        and case.get("fixture") != "authority:missing-confluence-proof"
        and case.get("fixture") != "authority:accepted-clause-target-mismatch"
        and case.get("fixture") != "authority:stale-embedded-source"
    ]
    assert {
        "authority:missing-kernel-proof",
        "authority:raw-evidence-only",
        "authority:operational-accept",
        "authority:operational-reject",
        "authority:operational-agreement-mismatch",
        "authority:missing-completion-proof",
        "authority:accepted-clause-provenance",
        "authority:policy-block",
        "authority:expired-clock",
        "authority:boundary-unknown-clock",
        "authority:conflicting-traces",
    }.issubset({str(case["fixture"]) for case in primary_fixtures})
    for case in primary_fixtures:
        bundle = artifact_bundle_from_json(_artifact_bundle_case_source(case))
        report = validate_artifact_bundle(bundle, full_replay=True)
        assert report.authority_view is not None
        assert report.replay_trace is not None
        assert report.authority_outcome_digest is not None
        fixture = str(case["fixture"])
        if fixture == "authority:operational-accept":
            assert report.authority_view.authority_outcome.code == "accept"
            assert any(
                ref.endswith(":agreement") for ref in report.authority_view.protocol_record_refs
            )
        if fixture == "authority:operational-reject":
            assert report.authority_view.authority_outcome.code == "reject"
            assert any(
                entry.target_artifact_id == "artifact:target-proof"
                for entry in report.authority_view.ledger_entries
            )
        if fixture == "authority:operational-agreement-mismatch":
            assert report.authority_view.authority_outcome.code == "unknown"
            assert any(
                block.failure_code.value == "artifact_conflict"
                and any(ref.source_path == "/agreement" for ref in block.reason_refs)
                for block in report.authority_view.blocking_set
            )
        if fixture == "authority:accepted-clause-provenance":
            assert report.authority_view.authority_outcome.code == "assert"
            assert [clause.clause_id for clause in report.accepted_clause_records]
        if fixture == "authority:raw-evidence-only":
            assert report.authority_view.authority_outcome.code == "unknown"
            assert any(
                block.failure_code.value == "checker_unknown"
                for block in report.authority_view.blocking_set
            )
            assert not report.accepted_clause_records
        if fixture == "authority:stale-embedded-source":
            assert report.authority_view.authority_outcome.code == "assert"
        if fixture == "authority:missing-completion-proof":
            assert report.authority_view.authority_outcome.code == "unknown"
            assert any(
                block.failure_code.value == "checker_unknown"
                for block in report.authority_view.blocking_set
            )


def test_bundled_primary_interop_fixtures_materialize_to_full_replay_failures() -> None:
    cases = load_golden_cases()
    interop_expectations = {
        "interop:canonicalization-mismatch": ("canonicalization_mismatch", "/x"),
        "interop:schema-invalid": ("schema_invalid", "/schema_profile_ref"),
        "interop:digest-mismatch": ("digest_mismatch", ""),
        "interop:missing-ref": ("missing_ref", "/missing"),
    }
    for fixture, (failure_code, source_path) in interop_expectations.items():
        case = next(case for case in cases if case.get("fixture") == fixture)
        bundle = artifact_bundle_from_json(_artifact_bundle_case_source(case))
        report = validate_artifact_bundle(bundle, full_replay=True)
        assert report.authority_view is None
        assert report.final_result.failure_records[0].code.value == failure_code
        if source_path:
            assert report.final_result.reason_refs[0].source_path == source_path
        assert report.final_result.reason_refs[0].digest is not None

    confluence_case = next(
        case for case in cases if case.get("fixture") == "authority:missing-confluence-proof"
    )
    confluence_bundle = artifact_bundle_from_json(_artifact_bundle_case_source(confluence_case))
    confluence_report = validate_artifact_bundle(confluence_bundle, full_replay=True)
    assert confluence_report.authority_view is None
    assert confluence_report.final_result.failure_records[0].code.value == "missing_ref"
    assert confluence_report.final_result.reason_refs[0].source_path.endswith(
        "/confluence_proof_ref"
    )

    target_case = next(
        case for case in cases if case.get("fixture") == "authority:accepted-clause-target-mismatch"
    )
    target_bundle = artifact_bundle_from_json(_artifact_bundle_case_source(target_case))
    target_report = validate_artifact_bundle(target_bundle, full_replay=True)
    assert target_report.authority_view is None
    assert target_report.final_result.failure_records[0].code.value == "artifact_conflict"
    assert target_report.final_result.reason_refs[0].source_path == "/target"

    manifest_case = next(
        case for case in cases if case.get("fixture") == "interop:manifest-order-conflict"
    )
    bundle = artifact_bundle_from_json(_artifact_bundle_case_source(manifest_case))
    report = validate_artifact_bundle(bundle, full_replay=True)
    assert report.authority_view is None
    assert report.final_result.failure_records[0].code.value == "artifact_conflict"
    assert report.final_result.reason_refs[0].source_path == "/manifest/dependency_order"
    assert report.final_result.reason_refs[0].digest is not None


def test_primary_conformance_rejects_synthetic_cases(tmp_path: Path) -> None:
    result = run_golden_cases(
        _case_dir(
            tmp_path,
            {
                "case_id": "synthetic-primary",
                "kind": "canonicalization-mismatch",
                "expected": "invalid_artifact",
                "expected_digest": "sha256:not-used",
            },
        )
    )[0]
    assert not result.passed
    assert result.expected == "artifact-bundle"
    assert result.actual == "synthetic:canonicalization-mismatch"
    assert result.equality_key is not None


def test_primary_conformance_requires_full_replay(tmp_path: Path) -> None:
    result = run_golden_cases(
        _case_dir(
            tmp_path,
            {
                "case_id": "primary-replay-disabled",
                "kind": "artifact-bundle",
                "full_replay": False,
                "bundle": _minimal_artifact_bundle_source(),
                "expected": "pass",
                "expected_digest": "sha256:not-used",
            },
        )
    )[0]
    assert not result.passed
    assert result.expected == "full_replay"
    assert result.actual == "disabled_full_replay"
    assert result.equality_key is not None


def test_primary_conformance_requires_canonical_expected_digest(tmp_path: Path) -> None:
    result = run_golden_cases(
        _case_dir(
            tmp_path,
            {
                "case_id": "primary-invalid-expected-digest",
                "kind": "artifact-bundle",
                "bundle": _minimal_artifact_bundle_source(),
                "expected": "pass",
                "expected_digest": "sha256:not-used",
            },
        )
    )[0]
    assert not result.passed
    assert result.expected == "canonical_expected_digest"
    assert result.actual == "invalid_expected_digest"
    assert result.equality_key is not None


def test_primary_conformance_requires_json_pointer_reason_trace() -> None:
    case = {
        "case_id": "primary-missing-reason-trace",
        "kind": "artifact-bundle",
        "expected": "checker_unknown",
        "expected_digest": "sha256:not-used",
    }
    report = PipelineReport(
        bundle_id="bundle:missing-trace",
        profile="DFCC-Interop",
        stage_results=(
            ValidationResult(
                ValidationStage.AUTHORITY_EMIT,
                ValidationStatus.UNKNOWN,
            ),
        ),
    )
    result = _artifact_bundle_trace_contract_failure(case, report)
    assert result is not None
    assert result.expected == "json_pointer_reason_refs"
    assert result.actual == "missing_reason_refs"


def test_primary_conformance_requires_reason_ref_digest() -> None:
    case = {
        "case_id": "primary-missing-reason-digest",
        "kind": "artifact-bundle",
        "expected": "checker_unknown",
        "expected_digest": "sha256:not-used",
    }
    report = PipelineReport(
        bundle_id="bundle:missing-digest",
        profile="DFCC-Interop",
        stage_results=(
            validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.AUTHORITY_EMIT,
                "missing digest",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.VALIDATION,
                source_artifact="artifact:source",
                source_path="/reason",
            ),
        ),
    )
    result = _artifact_bundle_trace_contract_failure(case, report)
    assert result is not None
    assert result.expected == "artifact_digest_reason_refs"
    assert result.actual == "missing_reason_ref_digests"


def test_primary_conformance_requires_canonical_reason_source_key() -> None:
    case = {
        "case_id": "primary-bad-reason-source-key",
        "kind": "artifact-bundle",
        "expected": "checker_unknown",
        "expected_digest": "sha256:not-used",
    }
    bad_digest = reason(
        FailureCode.CHECKER_UNKNOWN,
        Layer.VALIDATION,
        "bad digest",
        source_artifact="artifact:source",
        source_path="/reason",
        digest="not-a-canonical-digest",
    )
    report = PipelineReport(
        bundle_id="bundle:bad-digest",
        profile="DFCC-Interop",
        stage_results=(
            ValidationResult(
                ValidationStage.AUTHORITY_EMIT,
                ValidationStatus.UNKNOWN,
                reason_refs=(bad_digest,),
            ),
        ),
    )
    result = _artifact_bundle_trace_contract_failure(case, report)
    assert result is not None
    assert result.expected == "artifact_digest_reason_refs"
    assert result.actual == "missing_reason_ref_digests"

    bad_source = reason(
        FailureCode.CHECKER_UNKNOWN,
        Layer.VALIDATION,
        "bad source",
        source_artifact="inline",
        source_path="/reason",
        digest="sha256:" + "0" * 64,
    )
    source_report = PipelineReport(
        bundle_id="bundle:bad-source",
        profile="DFCC-Interop",
        stage_results=(
            ValidationResult(
                ValidationStage.AUTHORITY_EMIT,
                ValidationStatus.UNKNOWN,
                reason_refs=(bad_source,),
            ),
        ),
    )
    source_result = _artifact_bundle_trace_contract_failure(case, source_report)
    assert source_result is not None
    assert source_result.expected == "json_pointer_reason_refs"
    assert source_result.actual == "missing_json_pointer_reason_refs"


def test_pipeline_failure_equality_key_includes_replay_trace_material() -> None:
    failure = validation_failure(
        FailureCode.CHECKER_UNKNOWN,
        ValidationStage.AUTHORITY_EMIT,
        "same failure",
        status=ValidationStatus.UNKNOWN,
        layer=Layer.VALIDATION,
        source_artifact="artifact:source",
        source_path="/reason",
    )
    report_a = PipelineReport(
        bundle_id="bundle:trace-a",
        profile="DFCC-Interop",
        stage_results=(failure,),
        artifact_refs=("artifact:source",),
        stage_artifacts={"AuthorityEmit": ("bundle:trace-a:failure",)},
        replay_trace={"runtime_summary_digest": "sha256:trace-a"},
        runtime_summary_digest="sha256:runtime-a",
    )
    report_b = replace(
        report_a,
        stage_artifacts={"AuthorityEmit": ("bundle:trace-b:failure",)},
        replay_trace={"runtime_summary_digest": "sha256:trace-b"},
        runtime_summary_digest="sha256:runtime-b",
    )
    assert _pipeline_equality_key(report_a)[1] != _pipeline_equality_key(report_b)[1]


def test_pipeline_failure_equality_key_includes_replay_stage_typed_evidence() -> None:
    failure = validation_failure(
        FailureCode.CHECKER_UNKNOWN,
        ValidationStage.AUTHORITY_EMIT,
        "same failure",
        status=ValidationStatus.UNKNOWN,
        layer=Layer.VALIDATION,
        source_artifact="artifact:source",
        source_path="/reason",
    )
    artifact_a = build_artifact_ref(
        {"value": "a"},
        artifact_id="artifact:source",
        artifact_type="json",
    )
    artifact_b = build_artifact_ref(
        {"value": "b"},
        artifact_id="artifact:source",
        artifact_type="json",
    )
    base_trace = {
        "runtime_summary_digest": "sha256:trace",
        "stage_traces": [
            {
                "stage": "AuthorityEmit",
                "status": "unknown",
                "record_refs": ["record:authority"],
                "artifact_refs": ["artifact:source"],
                "artifact_ref_records": [asdict(artifact_a)],
                "proof_refs": ["artifact:proof"],
                "proof_ref_records": [
                    {
                        "proof_id": "artifact:proof",
                        "proof_kind": "kernel",
                        "artifact_ref": "artifact:proof",
                        "source_artifact": "artifact:proof",
                        "source_path": "/proof",
                        "digest": "sha256:proof-a",
                        "status": "accepted",
                    }
                ],
                "blocking_records": [],
                "reason_refs": [],
                "reason_ref_records": [],
            }
        ],
    }
    report_a = PipelineReport(
        bundle_id="bundle:trace-stage-a",
        profile="DFCC-Interop",
        stage_results=(failure,),
        artifact_refs=(artifact_a.artifact_id,),
        artifact_ref_records=(artifact_a,),
        replay_trace=base_trace,
        runtime_summary_digest="sha256:runtime",
    )
    mutated_trace = json.loads(json.dumps(base_trace))
    mutated_trace["stage_traces"][0]["artifact_ref_records"] = [asdict(artifact_b)]
    mutated_trace["stage_traces"][0]["proof_ref_records"][0]["digest"] = "sha256:proof-b"
    report_b = replace(report_a, replay_trace=mutated_trace)

    assert _pipeline_equality_key(report_a)[1] != _pipeline_equality_key(report_b)[1]


def test_pipeline_equality_key_includes_typed_artifact_ref_records() -> None:
    artifact_a = build_artifact_ref(
        {"value": "a"},
        artifact_id="artifact:source",
        artifact_type="json",
    )
    artifact_b = build_artifact_ref(
        {"value": "b"},
        artifact_id="artifact:source",
        artifact_type="json",
    )
    report_a = PipelineReport(
        bundle_id="bundle:artifact-a",
        profile="DFCC-Interop",
        stage_results=(
            ValidationResult(
                ValidationStage.AUTHORITY_EMIT,
                ValidationStatus.PASS,
            ),
        ),
        artifact_refs=(artifact_a.artifact_id,),
        artifact_ref_records=(artifact_a,),
    )
    report_b = replace(report_a, artifact_ref_records=(artifact_b,))

    assert _pipeline_equality_key(report_a)[1] != _pipeline_equality_key(report_b)[1]


def test_primary_conformance_requires_typed_artifact_ref_digest() -> None:
    case = {
        "case_id": "primary-missing-artifact-record",
        "kind": "artifact-bundle",
        "expected": "checker_unknown",
        "expected_digest": "sha256:not-used",
    }
    canonical_reason = reason(
        FailureCode.CHECKER_UNKNOWN,
        Layer.VALIDATION,
        "missing artifact record",
        source_artifact="artifact:source",
        source_path="/reason",
        digest="sha256:" + "0" * 64,
    )
    missing_record = PipelineReport(
        bundle_id="bundle:missing-artifact-record",
        profile="DFCC-Interop",
        stage_results=(
            ValidationResult(
                ValidationStage.AUTHORITY_EMIT,
                ValidationStatus.UNKNOWN,
                reason_refs=(canonical_reason,),
            ),
        ),
    )
    missing_result = _artifact_bundle_trace_contract_failure(case, missing_record)
    assert missing_result is not None
    assert missing_result.expected == "artifact_ref_records"
    assert missing_result.actual == "missing_artifact_ref_records"

    digest_free = build_artifact_ref(
        {"value": "a"},
        artifact_id="artifact:source",
        artifact_type="json",
    )
    digest_free = replace(digest_free, digest_value=None)
    digest_free_report = replace(
        missing_record,
        artifact_refs=(digest_free.artifact_id,),
        artifact_ref_records=(digest_free,),
    )
    digest_free_result = _artifact_bundle_trace_contract_failure(case, digest_free_report)
    assert digest_free_result is not None
    assert digest_free_result.expected == "artifact_ref_record_digest"
    assert digest_free_result.actual == "missing_artifact_ref_record_digest"


def test_primary_conformance_requires_stage_trace_typed_artifact_records() -> None:
    case = {
        "case_id": "primary-missing-stage-artifact-record",
        "kind": "artifact-bundle",
        "fixture": "authority:operational-accept",
        "expected": "checker_unknown",
        "expected_digest": "sha256:not-used",
    }
    bundle = artifact_bundle_from_json(_artifact_bundle_case_source(case))
    report = validate_artifact_bundle(bundle, full_replay=True)
    assert report.replay_trace is not None
    mutated_trace = json.loads(json.dumps(report.replay_trace))
    mutated_trace["stage_traces"][0].pop("artifact_ref_records")
    mutated_report = replace(report, replay_trace=mutated_trace)
    result = _artifact_bundle_trace_contract_failure(case, mutated_report)
    assert result is not None
    assert result.expected == "stage_artifact_ref_records"
    assert result.actual.startswith("missing_stage_artifact_ref_records:")

    digest_free_trace = json.loads(json.dumps(report.replay_trace))
    for record in digest_free_trace["stage_traces"][0]["artifact_ref_records"]:
        record["digest_value"] = None
    digest_free_report = replace(report, replay_trace=digest_free_trace)
    digest_free_result = _artifact_bundle_trace_contract_failure(case, digest_free_report)
    assert digest_free_result is not None
    assert digest_free_result.expected == "stage_artifact_ref_record_digest"
    assert digest_free_result.actual.startswith("missing_stage_artifact_ref_record_digest:")

    missing_proof_trace = json.loads(json.dumps(report.replay_trace))
    missing_proof_trace["stage_traces"][0].pop("proof_ref_records")
    missing_proof_report = replace(report, replay_trace=missing_proof_trace)
    missing_proof_result = _artifact_bundle_trace_contract_failure(case, missing_proof_report)
    assert missing_proof_result is not None
    assert missing_proof_result.expected == "stage_proof_ref_records"
    assert missing_proof_result.actual.startswith("missing_stage_proof_ref_records:")


def test_primary_conformance_requires_artifact_proof_ref_digest() -> None:
    case = {
        "case_id": "primary-missing-proof-digest",
        "kind": "artifact-bundle",
        "fixture": "authority:operational-accept",
        "expected": "checker_unknown",
        "expected_digest": "sha256:not-used",
    }
    bundle = artifact_bundle_from_json(_artifact_bundle_case_source(case))
    report = validate_artifact_bundle(bundle, full_replay=True)
    assert report.authority_view is not None
    mutated_view = replace(
        report.authority_view,
        proof_refs=("artifact:unresolved-proof",),
        ledger_entries=(),
    )
    mutated_report = replace(report, authority_view=mutated_view)
    result = _artifact_bundle_trace_contract_failure(case, mutated_report)
    assert result is not None
    assert result.expected == "artifact_digest_proof_refs"
    assert result.actual == "missing_proof_ref_digest"


def test_primary_conformance_requires_nested_outcome_blocking_records() -> None:
    case = {
        "case_id": "primary-missing-outcome-blocking",
        "kind": "artifact-bundle",
        "fixture": "authority:missing-completion-proof",
        "expected": "checker_unknown",
        "expected_digest": "sha256:not-used",
    }
    bundle = artifact_bundle_from_json(_artifact_bundle_case_source(case))
    report = validate_artifact_bundle(bundle, full_replay=True)
    assert report.authority_view is not None
    assert report.authority_view.blocking_set
    assert report.authority_view.authority_outcome.blocking_set

    mutated_outcome = replace(report.authority_view.authority_outcome, blocking_set=())
    mutated_view = replace(report.authority_view, authority_outcome=mutated_outcome)
    mutated_report = replace(report, authority_view=mutated_view)

    result = _artifact_bundle_trace_contract_failure(case, mutated_report)
    assert result is not None
    assert result.expected == "authority_outcome_blocking_records"
    assert result.actual == "missing_outcome_blocking_records"


def test_authority_equality_key_includes_nested_outcome_blocking_records() -> None:
    case = {
        "case_id": "primary-outcome-blocking-equality",
        "kind": "artifact-bundle",
        "fixture": "authority:missing-completion-proof",
        "expected": "checker_unknown",
        "expected_digest": "sha256:not-used",
    }
    bundle = artifact_bundle_from_json(_artifact_bundle_case_source(case))
    report = validate_artifact_bundle(bundle, full_replay=True)
    assert report.authority_view is not None
    assert report.authority_view.authority_outcome.blocking_set

    mutated_outcome = replace(report.authority_view.authority_outcome, blocking_set=())
    mutated_view = replace(report.authority_view, authority_outcome=mutated_outcome)
    mutated_report = replace(report, authority_view=mutated_view)

    assert _pipeline_equality_key(report)[1] != _pipeline_equality_key(mutated_report)[1]
