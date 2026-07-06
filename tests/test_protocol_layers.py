from __future__ import annotations

import json
from pathlib import Path

import pytest

from dfcc.admission import AdmissionContract, EvidenceArtifact, admit_evidence, validity_view
from dfcc.artifacts import (
    ArtifactRef,
    ArtifactStore,
    ReferenceResolutionContext,
    build_artifact_ref,
    resolve_reference,
    validate_artifact_ref,
)
from dfcc.backend import ReferenceChecker, ResidualContext
from dfcc.bundle import compile_bundle, parse_bundle
from dfcc.claims import (
    ClaimCompileError,
    PredicateRegistry,
    compile_claim,
    default_predicate_registry,
    evaluate_formula,
    field_cmp,
    state_in,
)
from dfcc.cli import main
from dfcc.frame import (
    adjudication_views,
    admit_prefix,
    checked_assoc_view,
    completion_admission,
    completion_interface,
    define_assessment_frame,
    exact_fiber_assoc,
    exact_prefix_set,
    fiber_assoc_view,
    frame_adequacy,
    make_observation_cut,
    operational_completion_fiber,
    operational_prefix_fiber,
    representation_interface,
    status_observation_context,
)
from dfcc.lifecycle import EventOrder, FoldContext, LifecycleEvent, fold_status
from dfcc.records import (
    IntervalRecord,
    ScalarRecord,
    SetRef,
    TimestampRecord,
    interval_record,
    scalar_record,
    set_ref,
    timestamp_record,
    validate_set_ref,
)
from dfcc.schema import list_schemas, load_schema
from dfcc.types import (
    AdequacyDirection,
    AdjudicationCode,
    AssociationStatus,
    FailureCode,
    StatusCode,
    ValidationStage,
    ValidationStatus,
)
from dfcc.validation import validate_pipeline


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


def _bundle() -> dict[str, object]:
    return {
        "bundle_id": "finite-demo",
        "state_space": [{"temp": "70"}, {"temp": "90"}],
        "initial_states": [{"temp": "70"}, {"temp": "90"}],
        "transitions": [
            {"from": {"temp": "70"}, "to": {"temp": "70"}},
            {"from": {"temp": "90"}, "to": {"temp": "90"}},
        ],
    }


def _completion_pass_policy() -> dict[str, object]:
    return {
        "completion_status": "pass",
        "admission_source": "completion-contract:demo",
        "expiry": "unbounded",
        "uncertainty_model": "exact",
        "reference_digest": "sha256:completion",
        "checker_result": "pass",
        "checker_transcript_ref": "artifact:completion-transcript",
    }


def test_claim_language_temporal_paths_and_input_errors() -> None:
    registry = default_predicate_registry()
    eventual = compile_claim(
        {
            "claim_id": "eventual-temp",
            "horizon": 2,
            "formula": {
                "op": "F",
                "a": 0,
                "b": 2,
                "child": {
                    "op": "atom",
                    "name": "field_eq",
                    "args": {"field": "temp", "value": "75"},
                },
            },
        },
        registry,
    )
    assert eventual.satisfies(({"temp": "70"}, {"temp": "75"}, {"temp": "80"}), registry)
    assert not eventual.satisfies(({"temp": "70"},), registry)
    until = {
        "op": "U",
        "a": 1,
        "b": 2,
        "left": {"op": "atom", "name": "true"},
        "right": {
            "op": "atom",
            "name": "field_cmp",
            "args": {"field": "temp", "op": "gt", "value": "74"},
        },
    }
    assert evaluate_formula(until, ({"temp": "70"}, {"temp": "75"}, {"temp": "80"}), 0, 2, registry)

    empty_registry = PredicateRegistry()
    with pytest.raises(ValueError, match="predicate name"):
        empty_registry.register("", lambda *_args: True)
    with pytest.raises(ClaimCompileError, match="unknown predicate"):
        empty_registry.get("missing")
    assert registry.names == ("false", "field_cmp", "field_eq", "state_in", "true")
    assert field_cmp({"temp": "70"}, (), 0, {"field": "temp", "op": "eq", "value": "70"})
    assert field_cmp({"temp": "70"}, (), 0, {"field": "temp", "op": "ne", "value": "80"})
    assert state_in({"temp": "70"}, (), 0, {"values": [{"temp": "70"}]})

    invalid_claims: tuple[dict[str, object], ...] = (
        {"claim_id": "", "horizon": 1, "formula": {"op": "atom", "name": "true"}},
        {"claim_id": "bad", "horizon": -1, "formula": {"op": "atom", "name": "true"}},
        {"claim_id": "bad", "horizon": 1, "formula": []},
        {"claim_id": "bad", "horizon": 1, "formula": {"op": "atom", "name": 1}},
        {
            "claim_id": "bad",
            "horizon": 1,
            "formula": {"op": "atom", "name": "true", "args": []},
        },
        {"claim_id": "bad", "horizon": 1, "formula": {"op": "and", "children": []}},
        {"claim_id": "bad", "horizon": 1, "formula": {"op": "or", "children": [1]}},
        {
            "claim_id": "bad",
            "horizon": 1,
            "formula": {"op": "G", "a": 2, "b": 1, "child": {"op": "atom", "name": "true"}},
        },
        {"claim_id": "bad", "horizon": 1, "formula": {"op": "not", "child": []}},
        {"claim_id": "bad", "horizon": 1, "formula": {"op": "U", "a": 0, "b": 1}},
        {"claim_id": "bad", "horizon": 1, "formula": {"op": "xor"}},
    )
    for source in invalid_claims:
        with pytest.raises(ClaimCompileError):
            compile_claim(source, registry)
    with pytest.raises(ValueError, match="unknown comparison"):
        field_cmp({"temp": "70"}, (), 0, {"field": "temp", "op": "bad", "value": "70"})
    with pytest.raises(ValueError, match="decimal-compatible"):
        field_cmp({"temp": object()}, (), 0, {"field": "temp", "op": "eq", "value": "70"})
    with pytest.raises(ValueError, match="values"):
        state_in({"temp": "70"}, (), 0, {"values": "not-a-list"})
    with pytest.raises(ClaimCompileError, match="unknown formula"):
        evaluate_formula({"op": "xor"}, ({"temp": "70"},), 0, 0, registry)


def test_validation_pipeline_artifact_reference_and_field_failures() -> None:
    assert validate_pipeline(None).status is ValidationStatus.REJECT_INPUT
    assert validate_pipeline(1, required_fields=("x",)).failure_records[0].code is (
        FailureCode.SCHEMA_INVALID
    )
    assert validate_pipeline({"x": 1.2}).failure_records[0].code is (
        FailureCode.CANONICALIZATION_MISMATCH
    )
    required = validate_pipeline({}, required_fields=("claim_id",))
    assert required.failure_records[0].code is FailureCode.SCHEMA_INVALID
    forbidden = validate_pipeline(
        {"authority_outcome": {}}, forbidden_fields=("authority_outcome",)
    )
    assert forbidden.failure_records[0].code is FailureCode.SCHEMA_INVALID
    closed = validate_pipeline({"x": 1}, closed_world_fields=("y",))
    assert closed.failure_records[0].code is FailureCode.SCHEMA_INVALID

    ref = ArtifactRef("artifact:bad", "json", digest_value="sha256:bad")
    digest = validate_pipeline({"x": 1}, artifact_refs=(ref,), artifact_id="artifact:bad")
    assert digest.failure_records[0].code is FailureCode.DIGEST_MISMATCH

    dep_a = ArtifactRef("a", "json", digest_value="sha256:a", provenance_refs=("b",))
    dep_b = ArtifactRef("b", "json", digest_value="sha256:b", provenance_refs=("a",))
    cycle = validate_pipeline({"x": 1}, dependencies=(dep_a, dep_b), artifact_id="a")
    assert cycle.status is ValidationStatus.CONFLICT

    missing_ref = validate_pipeline({"x": 1}, reason_paths=(("artifact:missing", "/x"),))
    assert missing_ref.failure_records[0].code is FailureCode.MISSING_REF
    unsupported = validate_pipeline({"x": 1}, requested_profile="missing-profile")
    assert unsupported.failure_records[0].code is FailureCode.UNSUPPORTED_PROFILE
    full_replay_single_artifact = validate_pipeline(
        {"x": 1},
        artifact_id="artifact:single",
        full_replay=True,
    )
    assert full_replay_single_artifact.status is ValidationStatus.UNKNOWN
    assert full_replay_single_artifact.stage is ValidationStage.REPLAY
    assert full_replay_single_artifact.failure_records[0].code is FailureCode.MISSING_REF
    assert full_replay_single_artifact.reason_refs[0].source_path == "/"


def test_validation_pipeline_wire_records_and_reference_success() -> None:
    artifact = {"x": {"y": "z"}}
    store = ArtifactStore()
    ref = build_artifact_ref(artifact, artifact_id="artifact:x", artifact_type="json")
    store.add(ref, artifact)
    valid = validate_pipeline(
        artifact,
        artifact_refs=(ref,),
        artifact_store=store,
        reference_context=ReferenceResolutionContext("test"),
        reason_paths=(("artifact:x", "/x/y"),),
        scalar_records=(scalar_record("1", "u", "d"),),
        interval_records=(
            interval_record(scalar_record("1", "u", "d"), scalar_record("2", "u", "d")),
        ),
        timestamp_records=(timestamp_record("2026-01-01T00:00:00Z", "utc"),),
        set_refs=(set_ref("carrier", "finite", "constraint", "exact", "soundness"),),
    )
    assert valid.passed
    assert (
        validate_pipeline(
            artifact,
            scalar_records=(ScalarRecord("bad", "u", "d"),),
        )
        .failure_records[0]
        .code
        is FailureCode.SCHEMA_INVALID
    )
    assert (
        validate_pipeline(
            artifact,
            interval_records=(
                IntervalRecord(ScalarRecord("2", "u", "d"), ScalarRecord("1", "u", "d")),
            ),
        )
        .failure_records[0]
        .code
        is FailureCode.SCHEMA_INVALID
    )
    assert (
        validate_pipeline(
            artifact,
            timestamp_records=(TimestampRecord("2026-01-01T00:00:00", "utc"),),
        )
        .failure_records[0]
        .code
        is FailureCode.CLOCK_BOUNDARY_UNKNOWN
    )
    assert (
        validate_pipeline(
            artifact,
            set_refs=(SetRef("carrier", "finite", "constraint", "exact", "soundness", "bad"),),
        )
        .failure_records[0]
        .code
        is FailureCode.DIGEST_MISMATCH
    )
    assert (
        validate_pipeline(
            artifact,
            artifact_store=store,
            reference_context=ReferenceResolutionContext("test"),
            reason_paths=(("artifact:x", "/missing"),),
        )
        .failure_records[0]
        .code
        is FailureCode.MISSING_REF
    )


def test_artifact_store_reference_resolution_and_schema_listing() -> None:
    store = ArtifactStore()
    artifact = {"reason": {"message": "ok"}}
    ref = build_artifact_ref(artifact, artifact_id="artifact:reason", artifact_type="reason")
    store.add(ref, artifact)
    result, value = resolve_reference(
        "artifact:reason",
        "/reason/message",
        store=store,
        context=ReferenceResolutionContext("test"),
    )
    assert result.passed
    assert value == "ok"
    assert validate_artifact_ref(ref, artifact=artifact).stage is ValidationStage.DIGEST_CHECK
    assert "issue-certificate.schema.json" in list_schemas()
    assert load_schema("reason-ref.schema.json")["additionalProperties"] is False


def test_records_set_ref_and_timestamp_validation() -> None:
    scalar = scalar_record("1.5", "degC", "temperature")
    interval = interval_record(scalar, scalar)
    assert interval.lower.decimal() == interval.upper.decimal()
    with pytest.raises(ValueError, match="lower bound"):
        interval_record(scalar_record("2", "u", "d"), scalar_record("1", "u", "d"))
    assert timestamp_record("2026-01-01T00:00:00Z", "utc").time_scale == "UTC"
    good_set = set_ref("carrier", "finite-json", "constraint", "exact", "soundness")
    assert validate_set_ref(good_set).passed
    bad_set = type(good_set)(
        good_set.carrier_ref,
        good_set.encoding_kind,
        good_set.constraint_ref,
        good_set.approximation_kind,
        good_set.soundness_ref,
        "sha256:bad",
    )
    assert validate_set_ref(bad_set).failure_records[0].code is FailureCode.DIGEST_MISMATCH
    empty_set = SetRef("", "finite-json", "constraint", "exact", "soundness", "bad")
    assert validate_set_ref(empty_set).failure_records[0].code is FailureCode.MISSING_REF


def test_admission_contract_allows_only_accepted_evidence() -> None:
    evidence = EvidenceArtifact("evidence:1", "measurement", checker_status="pass")
    contract = AdmissionContract(
        kind="measurement",
        source="evidence:1",
        target="clause:1",
        clause={"temp": "70"},
        validity={"not_before": "2026-01-01T00:00:00Z", "expiry": "2026-01-02T00:00:00Z"},
        checker_transcript_ref="artifact:measurement-transcript",
    )
    accepted = admit_evidence(evidence, contract, {"status_time": "2026-01-01T00:00:00Z"})
    assert accepted.passed
    assert accepted.accepted_clauses == ({"temp": "70"},)
    expired = admit_evidence(evidence, contract, {"status_time": "2026-01-03T00:00:00Z"})
    assert not expired.passed
    bundle = {"validity": {"requirements": ["dep"]}}
    assert validity_view(bundle, None, {"dep": "sha256:a"}, {}, {}).validity_status == "pass"
    assert validity_view(bundle, None, {}, {}, {}).reason_refs


def test_frame_prefix_completion_and_association_views() -> None:
    frame = define_assessment_frame(
        {
            "frame_id": "frame:demo",
            "scope": ["demo"],
            "policy": {"adequacy_direction": "positive"},
            "completion_interface_ref": "completion:demo",
        }
    )
    cut = make_observation_cut(
        (
            {
                "r": 0,
                "represented_prefix": [{"temp": "70"}],
                "operational_prefix": [{"temp": "70"}],
                "operational_completions": [[{"temp": "70"}, {"temp": "70"}]],
                "prefix_adjudication": "accept",
                "target_adjudication": "accept",
                "calibration_ref": "artifact:calibration-demo",
                "latency_ref": "artifact:latency-demo",
                "dependency_ref": "artifact:dependency-demo",
                "event_order_ref": "artifact:event-order-demo",
                "measurement_proof_ref": "artifact:measurement-proof-demo",
                "representation_relation": {
                    "relation_id": "representation:demo",
                    "operational_prefix": [{"temp": "70"}],
                    "represented_prefix": [{"temp": "70"}],
                    "proof_ref": "artifact:representation-proof-demo",
                },
                "representation_proof_ref": "artifact:representation-proof-demo",
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "event-order",
        {"dep": "sha256:a"},
        frame,
        {"policy_id": "policy:test"},
    )
    assert representation_interface(
        {"representation_interface": {}}, frame, {}
    ).projection_coherence
    assert completion_interface(frame, 0, 1).interface_id == "completion:demo:r0:h1"
    assert len(operational_prefix_fiber(cut, frame, 0).prefixes) == 1
    assert len(exact_prefix_set(cut, _bundle(), frame, 0)) == 1
    legacy_representation_cut = make_observation_cut(
        (
            {
                key: value
                for key, value in cut.records[0].items()
                if key != "representation_relation"
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "event-order",
        {"dep": "sha256:a"},
        frame,
        {"policy_id": "policy:test"},
    )
    assert exact_prefix_set(legacy_representation_cut, _bundle(), frame, 0).is_empty()
    no_measurement_proof_cut = make_observation_cut(
        ({key: value for key, value in cut.records[0].items() if key != "measurement_proof_ref"},),
        "2026-01-01T00:00:00Z",
        "utc",
        "event-order",
        {"dep": "sha256:a"},
        frame,
        {"policy_id": "policy:test"},
    )
    assert operational_prefix_fiber(no_measurement_proof_cut, frame, 0).status == "unknown"
    unbound_cut = make_observation_cut(
        (
            {
                **cut.records[0],
                "calibration_ref": "calibration:demo",
                "latency_ref": "latency:demo",
                "dependency_ref": "dependency:demo",
                "event_order_ref": "event-order:demo",
                "representation_relation": {
                    **cut.records[0]["representation_relation"],
                    "proof_ref": "representation-proof:demo",
                },
                "representation_proof_ref": "representation-proof:demo",
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "event-order",
        {"dep": "sha256:a"},
        frame,
        {"policy_id": "policy:test"},
    )
    assert operational_prefix_fiber(unbound_cut, frame, 0).status == "unknown"
    assert exact_prefix_set(unbound_cut, _bundle(), frame, 0).is_empty()
    prefix = admit_prefix(cut, _bundle(), {}, {"r": 0})
    assert prefix.prefix_status == "pass"
    assert status_observation_context(None, cut, {"r": 0}).prefix_view.prefix_status == "pass"
    assert completion_admission(
        prefix, completion_interface(frame, 0, 1), _completion_pass_policy()
    ).passed
    assert not completion_admission(
        prefix,
        completion_interface(frame, 0, 1),
        {
            **_completion_pass_policy(),
            "checker_transcript_ref": "checker:completion",
        },
    ).passed

    claim = compile_claim(_claim())
    compiled = compile_bundle(parse_bundle(_bundle()), claim.horizon)
    trajectories = compiled.enumerate_trajectories()
    residual = ResidualContext(0, trajectories, trajectories, None, trajectories, trajectories)
    assert operational_completion_fiber(cut.records[0], frame, residual).status == "pass"
    assoc = checked_assoc_view(cut.records[0], claim, compiled, residual, frame)
    assert assoc.assoc_status is AssociationStatus.MIXED
    assert (
        exact_fiber_assoc(cut.records[0], claim, compiled, residual, frame).associated
        == trajectories
    )
    assert (
        fiber_assoc_view(cut.records[0], claim, compiled, residual, frame).fiber_status
        is AssociationStatus.MIXED
    )
    views = adjudication_views(
        cut.records[0],
        {"mode": "operational", "scope": ["demo"]},
        {},
        frame,
        {},
    )
    assert views.prefix is AdjudicationCode.ACCEPT
    assert views.usage is AdjudicationCode.ACCEPT
    assert views.target is AdjudicationCode.ACCEPT
    assert frame_adequacy(claim, {}, frame) is AdequacyDirection.POSITIVE


def test_reference_checker_contract_methods() -> None:
    checker = ReferenceChecker()
    scalar = scalar_record("1", "unit", "dimension")
    set_record = set_ref(
        "carrier",
        "finite-json",
        "constraint",
        "exact",
        "artifact:set-soundness-proof#/proof",
    )
    frame = {
        "frame_id": "frame:demo",
        "policy": {
            "adequacy_direction": "positive",
            "adequacy_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:adequacy-proof",
                "proof_kind": "frame_adequacy",
                "artifact_digest": "sha256:adequacy-proof",
                "payload": {"adequacy_direction": "positive", "frame_id": "frame:demo"},
            },
        },
        "checker_transcript_ref": {
            "checker_status": "pass",
            "artifact_ref": "artifact:assessment-frame-transcript",
            "proof_kind": "assessment_frame",
            "artifact_digest": "sha256:assessment-frame",
            "payload": {"frame_id": "frame:demo"},
        },
    }
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
    assert checker.profile_resolution("DFCC-Core", ()).passed
    assert checker.reason_path(None, "/reason").status is ValidationStatus.UNKNOWN
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
    assert checker.scalar_record(scalar).passed
    assert checker.interval_record(interval_record(scalar, scalar)).passed
    assert checker.timestamp_record(timestamp_record("2026-01-01T00:00:00Z", "utc")).passed
    assert checker.set_ref(set_record).passed
    bare_artifact_set_record = set_ref(
        "carrier",
        "finite-json",
        "constraint",
        "exact",
        "artifact:set-soundness-proof",
    )
    assert checker.set_ref(bare_artifact_set_record).failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    unbound_set_record = set_ref("carrier", "finite-json", "constraint", "exact", "soundness")
    assert checker.set_ref(unbound_set_record).failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert checker.assessment_frame(frame).passed
    assert checker.representation_interface({"representation_interface": {}}, frame, {}).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.representation_interface(
        {
            "representation_interface": {
                "projection_coherence": True,
                "projection_coherence_proof_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:projection-coherence",
                    "proof_kind": "projection_coherence",
                    "artifact_digest": "sha256:projection-coherence",
                },
            }
        },
        frame,
        {},
    ).passed
    clock_record = {"clock_id": "utc", "uncertainty_seconds": "0", "source": "clock:lab"}
    assert checker.time_basis(clock_record, None).status is ValidationStatus.UNKNOWN
    assert checker.time_basis(
        {
            **clock_record,
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:time-basis-transcript",
                "proof_kind": "time_basis",
                "artifact_digest": "sha256:time-basis",
                "payload": {
                    "clock_id": "utc",
                    "time_scale": "UTC",
                    "uncertainty_seconds": "0",
                    "source": "clock:lab",
                },
            },
        },
        None,
    ).passed
    assert checker.event_order((), {"allow_empty": True}, {}).status is ValidationStatus.UNKNOWN
    assert checker.event_order(
        (),
        {
            "allow_empty": True,
            "empty_event_set_proof_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:empty-event-order-proof",
                "proof_kind": "event_order",
                "artifact_digest": "sha256:empty-event-order-proof",
            },
        },
        {},
    ).passed
    cut_payload = {
        "status_time": "now",
        "time_basis": "utc",
        "event_order": "order",
        "frame_id": "frame:demo",
    }
    accepted_record = (
        {
            "calibration_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:calibration-demo",
                "proof_kind": "calibration",
                "artifact_digest": "sha256:calibration",
                "payload": cut_payload,
            },
            "latency_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:latency-demo",
                "proof_kind": "latency",
                "artifact_digest": "sha256:latency",
                "payload": cut_payload,
            },
            "dependency_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:dependency-demo",
                "proof_kind": "dependency",
                "artifact_digest": "sha256:dependency",
                "payload": cut_payload,
            },
            "event_order_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:event-order-demo",
                "proof_kind": "event_order",
                "artifact_digest": "sha256:event-order",
                "payload": cut_payload,
            },
        },
    )
    assert checker.observation_cut(accepted_record, "now", "utc", "order", {}, frame).passed
    assert checker.status_observation_context(None, None, {}).status is ValidationStatus.UNKNOWN
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
    assert checker.completion_admission({}, {}, _completion_pass_policy()).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.completion_admission(
        {},
        {},
        {
            **_completion_pass_policy(),
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:completion-transcript",
                "proof_kind": "completion_admission",
                "artifact_digest": "sha256:completion-transcript",
                "payload": {
                    "completion_status": "pass",
                    "admission_source": "completion-contract:demo",
                    "expiry": "unbounded",
                    "uncertainty_model": "exact",
                    "reference_digest": "sha256:completion",
                    "checker_result": "pass",
                },
            },
        },
    ).passed
    assert (
        checker.representation_projection_coherence(
            representation_interface({"representation_interface": {}}, frame, {})
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.representation_projection_coherence(
        representation_interface(
            {
                "representation_interface": {
                    "projection_coherence": True,
                    "projection_coherence_proof_ref": {
                        "checker_status": "pass",
                        "artifact_ref": "artifact:projection-coherence",
                        "proof_kind": "projection_coherence",
                        "artifact_digest": "sha256:projection-coherence",
                    },
                }
            },
            frame,
            {},
        )
    ).passed
    assert checker.prefix_adjudication(
        {
            "prefix_adjudication": "accept",
            "prefix_adjudication_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:prefix-proof",
                "proof_kind": "prefix_adjudication",
                "artifact_digest": "sha256:prefix-proof",
                "payload": {"prefix_adjudication": "accept", "frame_id": "frame:demo"},
            },
        },
        frame,
    ).passed
    assert checker.usage_adjudication({"mode": "assertion"}, frame, {}).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.usage_adjudication(
        {"mode": "assertion"},
        frame,
        {
            "usage_adjudication_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:usage-proof",
                "proof_kind": "usage_adjudication",
                "artifact_digest": "sha256:usage-proof",
                "payload": {
                    "usage_adjudication": "accept",
                    "mode": "assertion",
                    "frame_id": "frame:demo",
                },
            }
        },
    ).passed
    assert (
        checker.usage_adjudication(
            {"mode": "assertion"},
            frame,
            {
                "usage_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:usage-proof",
                    "proof_kind": "usage_adjudication",
                    "artifact_digest": "sha256:usage-proof",
                }
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.target_adjudication(
        {
            "target_adjudication": "accept",
            "target_adjudication_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:target-proof",
                "proof_kind": "target_adjudication",
                "artifact_digest": "sha256:target-proof",
                "payload": {"target_adjudication": "accept", "frame_id": "frame:demo"},
            },
        },
        {},
        frame,
    ).passed
    frame_obj = define_assessment_frame(frame)
    assert checker.frame_adequacy(
        compile_claim(
            {
                "claim_id": "c",
                "horizon": 0,
                "formula": {
                    "op": "atom",
                    "name": "field_cmp",
                    "args": {"field": "temp", "op": "lte", "value": "80"},
                },
            }
        ),
        {},
        frame_obj,
    ).passed


def test_lifecycle_conflict_and_cli_commands(tmp_path: Path, capsys) -> None:
    events = (
        LifecycleEvent.from_json(
            {
                "event_id": "evt-1",
                "certificate_id": "cert",
                "time": "2026-01-01T00:00:00Z",
                "logical_clock": 1,
                "kind": "expire",
            }
        ),
        LifecycleEvent.from_json(
            {
                "event_id": "evt-2",
                "certificate_id": "cert",
                "time": "2026-01-01T00:00:01Z",
                "logical_clock": 1,
                "kind": "revoke",
            }
        ),
    )
    folded = fold_status("cert", events, EventOrder(), FoldContext(policy_version="default"))
    assert folded.dominant_status is StatusCode.CONFLICT

    bundle_file = tmp_path / "bundle.json"
    bundle_file.write_text(json.dumps(_bundle()), encoding="utf-8")
    assert main(["schema", "list"]) == 0
    assert "issue-certificate.schema.json" in capsys.readouterr().out
    schema_file = tmp_path / "schema.json"
    assert main(["schema", "export", "reason-ref.schema.json", "--out", str(schema_file)]) == 0
    assert schema_file.exists()
    assert main(["validate-bundle", str(bundle_file), "--horizon", "1"]) == 0
    assert main(["conformance", "run"]) == 0
    assert main(["golden", "--suite", "primary"]) == 0
    assert main(["golden", "--suite", "legacy"]) == 0
    from dfcc.conformance import run_golden_cases

    assert all(item.passed for item in run_golden_cases())


def test_lifecycle_additional_trace_policies() -> None:
    def event(event_id: str, **extra: object) -> LifecycleEvent:
        source = {
            "event_id": event_id,
            "certificate_id": "cert",
            "time": "2026-01-01T00:00:00Z",
            "logical_clock": 1,
            "kind": "mark-unknown",
        }
        source.update(extra)
        return LifecycleEvent.from_json(source)

    duplicate = fold_status(
        "cert",
        (event("evt"), event("evt")),
        EventOrder(),
        FoldContext(policy_version="default"),
    )
    assert duplicate.dominant_status is StatusCode.CONFLICT
    ancestry = fold_status(
        "cert",
        (event("evt", ancestry=["missing"]),),
        EventOrder(),
        FoldContext(policy_version="default"),
    )
    assert ancestry.dominant_status is StatusCode.CONFLICT
    payload_conflict = fold_status(
        "cert",
        (event("evt-1"), event("evt-2", payload={"conflicts_with": "evt-1"})),
        EventOrder(),
        FoldContext(policy_version="default"),
    )
    assert payload_conflict.dominant_status is StatusCode.CONFLICT
    bare_confluence = fold_status(
        "cert",
        (event("evt-1"), event("evt-2", payload={"conflicts_with": "evt-1"})),
        EventOrder(confluence_proof="proof:confluence"),
        FoldContext(policy_version="default"),
    )
    assert bare_confluence.dominant_status is StatusCode.CONFLICT
    uncovered_confluence = fold_status(
        "cert",
        (event("evt-1"), event("evt-2", payload={"conflicts_with": "evt-1"})),
        EventOrder(
            confluence_proof={
                "proof_status": "accepted",
                "artifact_ref": "artifact:confluence-proof",
                "proof_kind": "confluence",
                "artifact_digest": "sha256:confluence-proof",
            }
        ),
        FoldContext(policy_version="default"),
    )
    assert uncovered_confluence.dominant_status is StatusCode.CONFLICT
    accepted_confluence = fold_status(
        "cert",
        (event("evt-1"), event("evt-2", payload={"conflicts_with": "evt-1"})),
        EventOrder(
            confluence_proof={
                "proof_status": "accepted",
                "artifact_ref": "artifact:confluence-proof",
                "proof_kind": "confluence",
                "artifact_digest": "sha256:confluence-proof",
                "payload": {"event_ids": ["evt-1", "evt-2"]},
            }
        ),
        FoldContext(policy_version="default"),
    )
    assert accepted_confluence.dominant_status is StatusCode.UNKNOWN
    wrong_confluence_kind = fold_status(
        "cert",
        (event("evt-1"), event("evt-2", payload={"conflicts_with": "evt-1"})),
        EventOrder(
            confluence_proof={
                "proof_status": "accepted",
                "artifact_ref": "artifact:not-confluence-proof",
                "proof_kind": "schema_validation",
            }
        ),
        FoldContext(policy_version="default"),
    )
    assert wrong_confluence_kind.dominant_status is StatusCode.CONFLICT
    policy = fold_status(
        "cert",
        (event("evt", payload={"policy_version": "other"}),),
        EventOrder(),
        FoldContext(policy_version="default"),
    )
    assert policy.dominant_status is StatusCode.UNKNOWN
    log_root = fold_status(
        "cert",
        (event("evt", hashes=["other"]),),
        EventOrder(log_root="root"),
        FoldContext(policy_version="default"),
    )
    assert log_root.dominant_status is StatusCode.CONFLICT
    skipped = fold_status(
        "cert",
        (event("evt"),),
        EventOrder(accepted_event_ids=("other",)),
        FoldContext(policy_version="default"),
    )
    assert skipped.dominant_status is StatusCode.CONFLICT
    assert skipped.blocking_set[0].failure_code is FailureCode.TRACE_CONFLICT


def test_cli_issue_check_replay_digest_and_validate(tmp_path: Path, capsys) -> None:
    spec = {
        "claim": _claim(),
        "bundle": _bundle(),
        "anchor": {
            "issue_time": "2026-01-01T00:00:00Z",
            "horizon": 1,
            "step_seconds": 60,
        },
        "time_basis": {"clock_id": "utc", "uncertainty_seconds": "0"},
    }
    spec_file = tmp_path / "spec.json"
    cert_file = tmp_path / "cert.json"
    proposed_file = tmp_path / "use.json"
    status_file = tmp_path / "status.json"
    digest_file = tmp_path / "digest.json"
    spec_file.write_text(json.dumps(spec), encoding="utf-8")
    digest_file.write_text(json.dumps({"x": 1}), encoding="utf-8")
    assert main(["digest", str(digest_file)]) == 0
    assert "sha256:" in capsys.readouterr().out
    assert main(["certify", str(spec_file), "--out", str(cert_file)]) == 0
    proposed_file.write_text(
        json.dumps(
            {"mode": "assertion", "claim": "safe-temp", "horizon": 1, "anchor": "anchor:issue"}
        ),
        encoding="utf-8",
    )
    status_file.write_text(json.dumps({"status_time": "2026-01-01T00:00:00Z"}), encoding="utf-8")
    assert main(["check", str(cert_file), str(proposed_file), str(status_file)]) == 0
    assert main(["replay-status", str(cert_file), str(proposed_file), str(status_file)]) == 0
    assert main(["validate", str(cert_file), "--schema", "issue-certificate.schema.json"]) == 0
