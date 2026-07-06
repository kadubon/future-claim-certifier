from __future__ import annotations

from types import SimpleNamespace

import pytest

import dfcc
import dfcc.api as api
from dfcc.artifacts import (
    ArtifactRef,
    ArtifactStore,
    ReferenceResolutionContext,
    build_artifact_ref,
)
from dfcc.backend import (
    EnclosureResult,
    EnumeratingBackend,
    ReferenceChecker,
    ResidualContext,
    WitnessResult,
)
from dfcc.bundle import compile_bundle, parse_bundle
from dfcc.certificate import certify_claim
from dfcc.claims import ClaimCompileError, compile_claim, default_predicate_registry
from dfcc.frame import make_observation_cut
from dfcc.kernel import kernel_verdict
from dfcc.models import AdjudicationViews, FiberAssocView, IssueCertificate
from dfcc.records import IntervalRecord, ScalarRecord, SetRef, TimestampRecord
from dfcc.sets import FiniteSet
from dfcc.types import (
    AdequacyDirection,
    AdjudicationCode,
    AssociationStatus,
    Direction,
    FailureCode,
    GateDecision,
    Layer,
    OperationalCode,
    ValidationStatus,
    VerdictCode,
    blocking_record,
    reason,
)


def _claim_source(formula: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "claim_id": "claim",
        "horizon": 1,
        "formula": formula
        or {
            "op": "G",
            "a": 0,
            "b": 1,
            "child": {
                "op": "atom",
                "name": "field_cmp",
                "args": {"field": "temp", "op": "lte", "value": "80"},
            },
        },
    }


def _bundle_source() -> dict[str, object]:
    return {
        "bundle_id": "b",
        "state_space": [{"temp": "70"}, {"temp": "90"}],
        "initial_states": [{"temp": "70"}],
        "transitions": [{"from": {"temp": "70"}, "to": {"temp": "70"}}],
        "admissions": ["finite"],
    }


def _anchor() -> dict[str, object]:
    return {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60}


def _time_basis() -> dict[str, object]:
    return {"clock_id": "utc", "uncertainty_seconds": "0"}


def test_public_api_exposes_artifact_bundle_full_replay_entrypoints() -> None:
    source = {
        "bundle_id": "bundle:public-api",
        "manifest": {
            "manifest_id": "manifest:public-api",
            "root_artifact_id": "artifact:root",
            "artifact_refs": [
                {
                    "artifact_id": "artifact:root",
                    "artifact_type": "json",
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
                    "semantic_role": None,
                    "dependency_labels": [],
                }
            ],
            "dependency_order": ["artifact:root"],
        },
        "artifacts": [
            {
                "artifact_ref": {
                    "artifact_id": "artifact:root",
                    "artifact_type": "json",
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
                    "semantic_role": None,
                    "dependency_labels": [],
                },
                "artifact": {"x": 1},
                "role": "root",
            }
        ],
    }
    bundle = api.artifact_bundle_from_json(source)
    assert isinstance(bundle, api.ArtifactBundle)
    report = api.validate_artifact_bundle(bundle, full_replay=True)
    assert isinstance(report, api.PipelineReport)
    assert isinstance(dfcc.artifact_bundle_from_json(source), dfcc.ArtifactBundle)
    assert isinstance(dfcc.validate_artifact_bundle(bundle), dfcc.PipelineReport)


def _completion_pass_policy() -> dict[str, object]:
    return {
        "completion_status": "pass",
        "admission_source": "completion-contract:api",
        "expiry": "unbounded",
        "uncertainty_model": "exact",
        "reference_digest": "sha256:completion",
        "checker_result": "pass",
        "checker_transcript_ref": "artifact:completion-transcript",
    }


def _compiled_residual() -> tuple[object, object, ResidualContext]:
    claim = compile_claim(_claim_source())
    compiled = compile_bundle(parse_bundle(_bundle_source()), claim.horizon)
    p0 = FiniteSet.from_iterable((state,) for state in compiled.initial_set)
    residual = ResidualContext(
        0,
        p0,
        p0,
        None,
        compiled.residual_trajectories(p0, 0),
        compiled.residual_trajectories(p0, 0),
    )
    return claim, compiled, residual


def _certificate() -> IssueCertificate:
    cert = certify_claim(_claim_source(), _bundle_source(), _anchor(), _time_basis())
    assert isinstance(cert, IssueCertificate)
    return cert


def test_normative_api_surface_end_to_end() -> None:
    artifact = {"reason": {"message": "ok"}}
    store = ArtifactStore()
    ref = build_artifact_ref(artifact, artifact_id="artifact:reason", artifact_type="reason")
    store.add(ref, artifact)
    assert api.validate_artifact_ref(ref).passed
    assert api.manifest_digest(artifact, ref).startswith("sha256:")
    context = ReferenceResolutionContext("api")
    assert api.resolve_reference("artifact:reason#/reason/message", context, store=store)[1] == "ok"
    assert api.profile_resolution("DFCC-Core").status == "pass"
    assert api.resolve_reason_path(ref, "/reason/message", store=store).passed

    scalar = api.scalar_record("1", "unit", "dimension")
    assert api.interval_record(scalar, scalar).lower == scalar
    assert api.timestamp_record("2026-01-01T00:00:00Z", "utc").time_basis_ref == "utc"
    assert api.set_ref("carrier", "finite-json", "constraint", "exact", "soundness").digest

    frame = api.define_assessment_frame(
        {
            "frame_id": "frame:api",
            "scope": ["demo"],
            "policy": {"adequacy_direction": "positive"},
        }
    )
    assert api.define_time_basis(_time_basis(), "strict").timestamp_policy == "strict"
    assert api.define_time_basis(_time_basis()).clock_id == "utc"
    order = api.define_event_order(
        ({"event_id": "evt"}, {"event_id": "evt-extra"}),
        {
            "accepted_event_ids": ("evt",),
            "confluence_proof": "proof",
            "trace_class": ("audit",),
            "causal_cut": ("evt-parent",),
        },
        ("root",),
    )
    assert order.accepted_event_ids == ("evt",)
    assert order.trace_class == ("audit",)
    assert order.causal_cut == ("evt-parent",)

    bundle = parse_bundle(_bundle_source())
    compiled = api.compile_bundle(bundle, 1, frame, {})
    initial = api.initial_context(bundle, 1, frame, {})
    assert initial["r"] == 0
    assert api.representation_interface(
        {"representation_interface": {}}, frame, {}
    ).projection_coherence
    completion = api.completion_admission({}, {}, _completion_pass_policy())
    assert completion.passed

    cut = api.make_observation_cut(
        (
            {
                "r": 0,
                "represented_prefix": [{"temp": "70"}],
                "operational_prefix": [{"temp": "70"}],
                "operational_completions": [[{"temp": "70"}, {"temp": "70"}]],
                "prefix_adjudication": "accept",
                "target_adjudication": "accept",
                "calibration_ref": "artifact:calibration-api",
                "latency_ref": "artifact:latency-api",
                "dependency_ref": "artifact:dependency-api",
                "event_order_ref": "artifact:event-order-api",
                "measurement_proof_ref": "artifact:measurement-proof-api",
                "representation_relation": {
                    "relation_id": "representation:api",
                    "operational_prefix": [{"temp": "70"}],
                    "represented_prefix": [{"temp": "70"}],
                    "proof_ref": "artifact:representation-proof-api",
                },
                "representation_proof_ref": "artifact:representation-proof-api",
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "order",
        {},
        frame,
        {},
    )
    prefix = api.admit_prefix(cut, _bundle_source(), {}, {"r": 0})
    assert api.status_observation_context(None, cut, {"r": 0}).prefix_view.prefix_status == "pass"
    assert len(api.operational_prefix_fiber(cut, frame, 0).prefixes) == 1
    assert len(api.exact_prefix_set(cut, _bundle_source(), frame, 0)) == 1

    cert = _certificate()
    residual = api.residual_context(cert, "2026-01-01T00:00:00Z", prefix, prefix.p_star)
    assert api.operational_completion_fiber(cut.records[0], frame, residual).status == "pass"
    empty_exact = api.residual_context(
        cert,
        "2026-01-01T00:00:00Z",
        prefix,
        FiniteSet.from_iterable(()),
        {},
    )
    assert empty_exact.adm_star.is_empty()
    claim = compile_claim(_claim_source())
    assoc = api.checked_assoc_view(cut.records[0], claim, compiled, residual, frame)
    assert assoc.assoc_status is AssociationStatus.POSITIVE
    assert api.exact_fiber_assoc(cut.records[0], claim, compiled, residual, frame).associated
    assert api.fiber_assoc_view(cut.records[0], claim, compiled, residual, frame).fiber_status
    assert api.prefix_adjudication(cut.records[0], frame) is AdjudicationCode.ACCEPT
    assert (
        api.usage_adjudication({"mode": "operational", "scope": ["demo"]}, frame, {})
        is AdjudicationCode.ACCEPT
    )
    assert api.target_adjudication(cut.records[0], {}, frame) is AdjudicationCode.ACCEPT

    checker = ReferenceChecker()
    kernel = kernel_verdict(claim, compiled, residual, EnumeratingBackend(), checker)
    agreement = api.agreement(
        kernel,
        FiberAssocView(AssociationStatus.POSITIVE),
        AdjudicationViews(
            prefix=AdjudicationCode.ACCEPT,
            usage=AdjudicationCode.ACCEPT,
            target=AdjudicationCode.ACCEPT,
        ),
        AdequacyDirection.POSITIVE,
        (),
        GateDecision.ALLOW,
    )
    outcome = api.typed_authority_outcome(None, kernel, agreement, (), GateDecision.ALLOW)
    assert outcome.code == OperationalCode.ACCEPT.value
    negative_agreement = api.agreement(
        SimpleNamespace(direction=Direction.NEGATIVE),
        FiberAssocView(AssociationStatus.NEGATIVE),
        AdjudicationViews(
            prefix=AdjudicationCode.ACCEPT,
            usage=AdjudicationCode.ACCEPT,
            target=AdjudicationCode.REJECT,
        ),
        AdequacyDirection.NEGATIVE,
        (),
        GateDecision.ALLOW,
    )
    negative = api.typed_authority_outcome(
        None, SimpleNamespace(), negative_agreement, (), GateDecision.ALLOW
    )
    assert negative.code == OperationalCode.REJECT.value
    transfer = api.transfer_authority(
        cert,
        {"claim_id": "target"},
        {
            "checker_status": "pass",
            "artifact_ref": "artifact:transfer-proof",
            "artifact_digest": "sha256:transfer-proof",
            "proof_kind": "transfer_authority",
            "payload": {
                "certificate_id": cert.certificate_id,
                "target_claim_id": "target",
            },
        },
        {},
        {},
    )
    assert transfer["decision"] == "translate"
    shallow_transfer = api.transfer_authority(
        cert, {"claim_id": "target"}, {"checker_status": "pass"}, {}, {}
    )
    assert shallow_transfer["decision"] == "block"
    mismatch_transfer = api.transfer_authority(
        cert,
        {"claim_id": "target"},
        {
            "checker_status": "pass",
            "artifact_ref": "artifact:transfer-proof",
            "artifact_digest": "sha256:transfer-proof",
            "proof_kind": "transfer_authority",
            "payload": {
                "certificate_id": cert.certificate_id,
                "target_claim_id": "other",
            },
        },
        {},
        {},
    )
    assert mismatch_transfer["decision"] == "block"
    assert "target_claim_id" in mismatch_transfer["missing_or_mismatched"]
    blocked_transfer = api.transfer_authority(cert, {"claim_id": "target"}, {}, {}, {})
    assert blocked_transfer["decision"] == "block"
    fallback = api.typed_authority_outcome(
        None,
        kernel,
        api.agreement(
            kernel,
            FiberAssocView(AssociationStatus.UNKNOWN),
            AdjudicationViews(),
            AdequacyDirection.UNKNOWN,
            (),
            GateDecision.UNKNOWN,
        ),
        (),
        GateDecision.UNKNOWN,
    )
    assert fallback.layer is Layer.REPRESENTED
    unknown_fallback = api.typed_authority_outcome(
        None,
        SimpleNamespace(),
        api.agreement(
            SimpleNamespace(),
            FiberAssocView(AssociationStatus.UNKNOWN),
            AdjudicationViews(),
            AdequacyDirection.UNKNOWN,
            (),
            GateDecision.UNKNOWN,
        ),
        (),
        GateDecision.UNKNOWN,
    )
    assert unknown_fallback.code == "unknown"
    assert unknown_fallback.blocking_set
    assert unknown_fallback.reason_refs
    deny_fallback = api.typed_authority_outcome(
        None,
        SimpleNamespace(verdict=VerdictCode.DENY, direction=Direction.NEGATIVE),
        api.agreement(
            SimpleNamespace(direction=Direction.NEGATIVE),
            FiberAssocView(AssociationStatus.UNKNOWN),
            AdjudicationViews(),
            AdequacyDirection.UNKNOWN,
            (),
            GateDecision.UNKNOWN,
        ),
        (),
        GateDecision.UNKNOWN,
    )
    assert deny_fallback.code == VerdictCode.DENY.value
    assert deny_fallback.reason_refs
    unknown_block = blocking_record(
        FailureCode.CHECKER_UNKNOWN,
        Layer.STATUS,
        "direct api unknown is blocked",
        source_artifact="artifact:api",
        source_path="/authority",
    )
    kernel_reason = reason(
        FailureCode.CHECKER_UNKNOWN,
        Layer.STATUS,
        "kernel supplied unknown reason",
        source_artifact="artifact:kernel",
        source_path="/verdict",
        digest="sha256:kernel-reason",
    )
    preserved_reason = api.typed_authority_outcome(
        None,
        SimpleNamespace(
            verdict=VerdictCode.UNKNOWN,
            direction=Direction.NONE,
            reason_refs=(kernel_reason,),
        ),
        api.agreement(
            SimpleNamespace(),
            FiberAssocView(AssociationStatus.UNKNOWN),
            AdjudicationViews(),
            AdequacyDirection.UNKNOWN,
            (),
            GateDecision.UNKNOWN,
        ),
        (unknown_block,),
        GateDecision.UNKNOWN,
    )
    assert preserved_reason.blocking_set == (unknown_block,)
    assert kernel_reason in preserved_reason.reason_refs


def test_reference_checker_negative_contract_paths() -> None:
    from dfcc.profiles import ConformanceProfile

    checker = ReferenceChecker()
    assert (
        checker.profile_resolution("missing-profile", ()).status
        is ValidationStatus.INVALID_ARTIFACT
    )
    assert (
        checker.profile_resolution("DFCC-Core", {"DFCC-Interop": {"profile_id": "DFCC-Interop"}})
        .failure_records[0]
        .code
        is FailureCode.UNSUPPORTED_PROFILE
    )
    compatible_profile = api.profile_resolution(
        "DFCC-Experimental",
        {
            "DFCC-Experimental": {
                "profile_id": "DFCC-Experimental",
                "version": "0.1",
                "feature_set": ["finite-claim"],
                "required_checks": ["KernelCheck"],
                "failure_code_set": ["checker_unknown"],
                "compatibility_rule": "maps-to-base-failure-codes",
                "extension_mapping": {"experimental_unknown": "checker_unknown"},
            }
        },
    )
    assert compatible_profile.status == "pass"
    assert compatible_profile.version_relation == "compatible"
    assert compatible_profile.extension_mapping == {"experimental_unknown": "checker_unknown"}
    unmapped_profile_source = {
        "DFCC-Unmapped": {
            "profile_id": "DFCC-Unmapped",
            "version": "0.1",
            "feature_set": ["finite-claim"],
            "required_checks": ["KernelCheck"],
            "failure_code_set": ["experimental_unknown"],
            "compatibility_rule": "maps-to-base-failure-codes",
        }
    }
    unmapped_profile = api.profile_resolution("DFCC-Unmapped", unmapped_profile_source)
    assert unmapped_profile.status == "unsupported_profile"
    assert unmapped_profile.reason_refs == ("profile:unmapped_failure_code:experimental_unknown",)
    checker_unmapped = checker.profile_resolution("DFCC-Unmapped", unmapped_profile_source)
    assert checker_unmapped.failure_records[0].code is FailureCode.UNSUPPORTED_PROFILE
    assert checker_unmapped.reason_refs[0].source_artifact == "artifact:profile-resolution"
    assert checker_unmapped.reason_refs[0].source_path == "/implemented_profiles/DFCC-Unmapped"
    fallback_profile = api.profile_resolution(
        "DFCC-Fallback",
        {
            "DFCC-Fallback": {
                "feature_set": "single-feature",
                "required_checks": "KernelCheck",
                "failure_code_set": "checker_unknown",
                "extension_mapping": "not-a-mapping",
            }
        },
    )
    assert fallback_profile.status == "pass"
    assert fallback_profile.version_relation == "exact"
    assert fallback_profile.implemented_profile == "DFCC-Fallback"
    assert fallback_profile.enabled_features == ("single-feature",)
    assert fallback_profile.extension_mapping == {}
    iterable_profile = api.profile_resolution(
        "DFCC-Object",
        (
            ConformanceProfile(
                profile_id="DFCC-Object",
                version="0.1",
                feature_set=("object-profile",),
                required_checks=("KernelCheck",),
                failure_code_set=("checker_unknown",),
            ),
            "invalid-entry",
            {"version": "0.1"},
        ),
    )
    assert iterable_profile.status == "pass"
    assert iterable_profile.implemented_profile == "DFCC-Object"
    invalid_iterable_profile = api.profile_resolution("DFCC-Core", ("invalid-entry",))
    assert invalid_iterable_profile.status == "unsupported_profile"
    assert invalid_iterable_profile.reason_refs == ("profile:unsupported:DFCC-Core",)
    assert (
        checker.reason_path(None, "not-a-pointer").failure_records[0].code
        is FailureCode.MISSING_REF
    )
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
    assert checker.scalar_record(ScalarRecord("not-decimal", "u", "d")).status is (
        ValidationStatus.INVALID_ARTIFACT
    )
    assert (
        checker.interval_record(
            IntervalRecord(ScalarRecord("2", "u", "d"), ScalarRecord("1", "u", "d"))
        )
        .failure_records[0]
        .code
        is FailureCode.SCHEMA_INVALID
    )
    assert checker.timestamp_record(TimestampRecord("2026-01-01T00:00:00", "utc")).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.set_ref(SetRef("", "", "", "", "", "")).failure_records[0].code is (
        FailureCode.MISSING_REF
    )
    assert checker.assessment_frame({}).failure_records[0].code is FailureCode.CHECKER_UNKNOWN
    assert (
        checker.admission(
            {"artifact_id": "a", "checker_status": "unchecked"},
            {"kind": "k", "source": "b", "target": "t", "clause": {}},
        ).status
        is ValidationStatus.UNKNOWN
    )

    frame = {"frame_id": "frame", "scope": ["allowed"]}
    cut = make_observation_cut((), "2026-01-01T00:00:00Z", "utc", "order", {}, frame, {})
    assert checker.operational_prefix_fiber(cut, frame, 1).status is ValidationStatus.UNKNOWN
    prefix_record = {
        "r": 0,
        "operational_prefix": [{"temp": "70"}],
        "calibration_ref": "calibration:demo",
        "latency_ref": "latency:demo",
        "dependency_ref": "dependency:demo",
        "event_order_ref": "event-order:demo",
    }
    prefix_cut = make_observation_cut(
        (prefix_record,),
        "2026-01-01T00:00:00Z",
        "utc",
        "order",
        {},
        frame,
        {},
    )
    assert checker.operational_prefix_fiber(prefix_cut, frame, 0).status is (
        ValidationStatus.UNKNOWN
    )
    accepted_prefix_cut = make_observation_cut(
        (
            {
                **prefix_record,
                "calibration_ref": "artifact:calibration-demo",
                "latency_ref": "artifact:latency-demo",
                "dependency_ref": "artifact:dependency-demo",
                "event_order_ref": "artifact:event-order-demo",
                "measurement_proof_ref": "artifact:measurement-proof-demo",
                "operational_prefix_fiber_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:operational-prefix-fiber",
                    "proof_kind": "operational_prefix_fiber",
                    "artifact_digest": "sha256:operational-prefix-fiber",
                    "payload": {"fiber_status": "pass"},
                },
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "order",
        {},
        frame,
        {},
    )
    assert checker.operational_prefix_fiber(accepted_prefix_cut, frame, 0).passed
    conflicting_prefix_cut = make_observation_cut(
        (
            {
                **prefix_record,
                "operational_prefix_fiber_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:operational-prefix-fiber-conflict",
                    "proof_kind": "operational_prefix_fiber",
                    "artifact_digest": "sha256:operational-prefix-fiber-conflict",
                    "payload": {"fiber_status": "unknown"},
                },
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "order",
        {},
        frame,
        {},
    )
    assert (
        checker.operational_prefix_fiber(conflicting_prefix_cut, frame, 0).failure_records[0].code
        is FailureCode.ARTIFACT_CONFLICT
    )
    wrong_prefix_cut = make_observation_cut(
        (
            {
                **prefix_record,
                "operational_prefix_fiber_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-operational-prefix-fiber",
                    "proof_kind": "prefix_adjudication",
                },
            },
        ),
        "2026-01-01T00:00:00Z",
        "utc",
        "order",
        {},
        frame,
        {},
    )
    assert checker.operational_prefix_fiber(wrong_prefix_cut, frame, 0).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.completion_admission({}, {}, {}).failure_records[0].code is (
        FailureCode.COMPLETION_MISSING
    )
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
                    "admission_source": "completion-contract:api",
                    "expiry": "unbounded",
                    "uncertainty_model": "exact",
                    "reference_digest": "sha256:completion",
                    "checker_result": "pass",
                },
            },
        },
    ).passed
    assert checker.completion_admission(
        {},
        {},
        {
            **_completion_pass_policy(),
            "c_out_ref": "artifact:completion-set",
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:completion-transcript-with-set",
                "proof_kind": "completion_admission",
                "artifact_digest": "sha256:completion-transcript-with-set",
                "payload": {
                    "completion_status": "pass",
                    "admission_source": "completion-contract:api",
                    "expiry": "unbounded",
                    "uncertainty_model": "exact",
                    "reference_digest": "sha256:completion",
                    "checker_result": "pass",
                    "c_out_ref": "artifact:completion-set",
                },
            },
        },
    ).passed
    assert (
        checker.completion_admission(
            {},
            {},
            {
                **_completion_pass_policy(),
                "c_out_ref": "artifact:completion-set",
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:completion-transcript-wrong-set",
                    "proof_kind": "completion_admission",
                    "artifact_digest": "sha256:completion-transcript-wrong-set",
                    "payload": {
                        "completion_status": "pass",
                        "admission_source": "completion-contract:api",
                        "expiry": "unbounded",
                        "uncertainty_model": "exact",
                        "reference_digest": "sha256:completion",
                        "checker_result": "pass",
                        "c_out_ref": "artifact:other-completion-set",
                    },
                },
            },
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.completion_admission(
            {},
            {},
            {
                **_completion_pass_policy(),
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:completion-transcript-conflict",
                    "proof_kind": "completion_admission",
                    "artifact_digest": "sha256:completion-transcript-conflict",
                    "payload": {
                        "completion_status": "pass",
                        "admission_source": "completion-contract:api",
                        "expiry": "unbounded",
                        "uncertainty_model": "exact",
                        "reference_digest": "sha256:other-completion",
                        "checker_result": "pass",
                    },
                },
            },
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.completion_admission(
            {},
            {},
            {
                **_completion_pass_policy(),
                "completion_admission_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:completion-proof",
                    "proof_kind": "completion_admission",
                },
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.completion_admission(
            {},
            {},
            {
                **_completion_pass_policy(),
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:not-completion-transcript",
                    "proof_kind": "schema_validation",
                },
            },
        )
        .failure_records[0]
        .code
        is FailureCode.COMPLETION_MISSING
    )
    assert checker.representation_projection_coherence(object()).failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert (
        checker.prefix_soundness({"prefix_status": "pass"}, cut, frame).failure_records[0].code
        is FailureCode.CHECKER_UNKNOWN
    )
    assert checker.prefix_soundness(
        {
            "prefix_status": "pass",
            "prefix_soundness_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:prefix-soundness",
                "proof_kind": "prefix_soundness",
                "artifact_digest": "sha256:prefix-soundness",
                "payload": {"prefix_status": "pass"},
            },
        },
        cut,
        frame,
    ).passed
    assert (
        checker.prefix_soundness(
            {
                "prefix_status": "pass",
                "prefix_soundness_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:prefix-soundness-conflict",
                    "proof_kind": "prefix_soundness",
                    "artifact_digest": "sha256:prefix-soundness-conflict",
                    "payload": {"prefix_status": "conflict"},
                },
            },
            cut,
            frame,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.prefix_soundness(
            {
                "prefix_status": "pass",
                "prefix_soundness_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-prefix-soundness",
                    "proof_kind": "completion_admission",
                },
            },
            cut,
            frame,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.prefix_soundness(object(), cut, frame).failure_records[0].code is (
        FailureCode.PREFIX_UNSOUND
    )
    assert (
        checker.usage_adjudication(
            {"mode": "blocked", "scope": ["allowed"]}, frame, {"blocked_modes": ["blocked"]}
        ).status
        is ValidationStatus.CONFLICT
    )
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
                    "frame_id": "frame",
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
                    "payload": {"usage_adjudication": "reject"},
                }
            },
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.usage_adjudication(
            {"mode": "assertion"},
            frame,
            {
                "usage_adjudication_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-usage-proof",
                    "proof_kind": "target_adjudication",
                }
            },
        ).status
        is ValidationStatus.UNKNOWN
    )

    claim, compiled, residual = _compiled_residual()
    trajectories = compiled.enumerate_trajectories()
    positive_residual = ResidualContext(
        0, trajectories, trajectories, None, trajectories, trajectories
    )
    assert checker.checked_assoc_view({}, claim, compiled, positive_residual, frame).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.exact_fiber_assoc({}, claim, compiled, positive_residual, frame).status is (
        ValidationStatus.UNKNOWN
    )
    assoc_record = {
        "checked_assoc_view_proof_ref": {
            "proof_status": "accepted",
            "artifact_ref": "artifact:checked-assoc-view",
            "proof_kind": "checked_assoc_view",
            "artifact_digest": "sha256:checked-assoc-view",
            "payload": {"assoc_status": "positive"},
        },
        "exact_fiber_assoc_proof_ref": {
            "proof_status": "accepted",
            "artifact_ref": "artifact:exact-fiber-assoc",
            "proof_kind": "exact_fiber_assoc",
            "artifact_digest": "sha256:exact-fiber-assoc",
            "payload": {"exact_fiber_assoc": "nonempty"},
        },
    }
    assert checker.checked_assoc_view(
        assoc_record, claim, compiled, positive_residual, frame
    ).passed
    assert checker.exact_fiber_assoc(assoc_record, claim, compiled, positive_residual, frame).passed
    assert checker.fiber_assoc_view(assoc_record, claim, compiled, positive_residual, frame).passed
    missing_assoc_payload = {
        "checked_assoc_view_proof_ref": {
            "proof_status": "accepted",
            "artifact_ref": "artifact:checked-assoc-view",
            "proof_kind": "checked_assoc_view",
            "artifact_digest": "sha256:checked-assoc-view",
        },
        "exact_fiber_assoc_proof_ref": {
            "proof_status": "accepted",
            "artifact_ref": "artifact:exact-fiber-assoc",
            "proof_kind": "exact_fiber_assoc",
            "artifact_digest": "sha256:exact-fiber-assoc",
        },
    }
    assert (
        checker.checked_assoc_view(
            missing_assoc_payload, claim, compiled, positive_residual, frame
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.exact_fiber_assoc(
            missing_assoc_payload, claim, compiled, positive_residual, frame
        ).status
        is ValidationStatus.UNKNOWN
    )
    conflicting_assoc_payload = {
        "checked_assoc_view_proof_ref": {
            "proof_status": "accepted",
            "artifact_ref": "artifact:checked-assoc-view",
            "proof_kind": "checked_assoc_view",
            "artifact_digest": "sha256:checked-assoc-view",
            "payload": {"assoc_status": "negative"},
        },
        "exact_fiber_assoc_proof_ref": {
            "proof_status": "accepted",
            "artifact_ref": "artifact:exact-fiber-assoc",
            "proof_kind": "exact_fiber_assoc",
            "artifact_digest": "sha256:exact-fiber-assoc",
            "payload": {"exact_fiber_assoc": "empty"},
        },
    }
    assert (
        checker.checked_assoc_view(
            conflicting_assoc_payload, claim, compiled, positive_residual, frame
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.exact_fiber_assoc(
            conflicting_assoc_payload, claim, compiled, positive_residual, frame
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    wrong_assoc_record = {
        "checked_assoc_view_proof_ref": {
            "proof_status": "accepted",
            "artifact_ref": "artifact:not-checked-assoc-view",
            "proof_kind": "completion_admission",
        },
        "exact_fiber_assoc_proof_ref": {
            "proof_status": "accepted",
            "artifact_ref": "artifact:not-exact-fiber-assoc",
            "proof_kind": "completion_admission",
        },
    }
    assert (
        checker.checked_assoc_view(
            wrong_assoc_record, claim, compiled, positive_residual, frame
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.exact_fiber_assoc(
            wrong_assoc_record, claim, compiled, positive_residual, frame
        ).status
        is ValidationStatus.UNKNOWN
    )
    empty = ResidualContext(
        0,
        FiniteSet.from_iterable(()),
        FiniteSet.from_iterable(()),
        None,
        FiniteSet.from_iterable(()),
        FiniteSet.from_iterable(()),
    )
    assert checker.checked_assoc_view({}, claim, compiled, empty, frame).failure_records[
        0
    ].code is (FailureCode.ASSOC_EMPTY)
    assert checker.exact_fiber_assoc({}, claim, compiled, empty, frame).failure_records[0].code is (
        FailureCode.ASSOC_EMPTY
    )
    block = blocking_record(FailureCode.POLICY_BLOCK, Layer.POLICY, "blocked")
    kernel = kernel_verdict(claim, compiled, residual, EnumeratingBackend(), checker)
    assert (
        checker.agreement(
            kernel,
            FiberAssocView(AssociationStatus.POSITIVE),
            AdjudicationViews(),
            AdequacyDirection.POSITIVE,
            (block,),
            GateDecision.ALLOW,
        )
        .failure_records[0]
        .code
        is FailureCode.POLICY_BLOCK
    )
    assert checker.artifact_conflict(
        (
            ArtifactRef("same", "json", digest_value="sha256:a"),
            ArtifactRef("same", "json", digest_value="sha256:b"),
        )
    )
    assert checker.frame_adequacy(claim, {}, frame).failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    positive_frame = {
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
    }
    assert checker.frame_adequacy(claim, {}, positive_frame).passed
    assert checker.initial_context({}, {}, {}, {}).status is ValidationStatus.UNKNOWN
    assert (
        checker.initial_context(_bundle_source(), _anchor(), {"frame_id": "frame"}, {}).status
        is ValidationStatus.UNKNOWN
    )
    evidenced_bundle = {
        **_bundle_source(),
        "admissions": [
            {
                "checker_status": "pass",
                "artifact_ref": "artifact:accepted-admission",
                "proof_kind": "admission",
            }
        ],
    }
    assert (
        checker.initial_context(evidenced_bundle, _anchor(), {"frame_id": "frame"}, {}).status
        is ValidationStatus.UNKNOWN
    )
    evidenced_bundle["admissions"][0]["artifact_digest"] = "sha256:accepted-admission"
    assert (
        checker.initial_context(evidenced_bundle, _anchor(), {"frame_id": "frame"}, {}).status
        is ValidationStatus.UNKNOWN
    )
    evidenced_bundle["admissions"][0]["payload"] = {
        "bundle_id": "b",
        "issue_time": "2026-01-01T00:00:00Z",
        "horizon": 1,
        "step_seconds": 60,
        "frame_id": "frame",
    }
    assert checker.initial_context(evidenced_bundle, _anchor(), {"frame_id": "frame"}, {}).passed
    conflicted_bundle = {
        **_bundle_source(),
        "admissions": [
            {
                "checker_status": "pass",
                "artifact_ref": "artifact:accepted-admission",
                "proof_kind": "admission",
                "artifact_digest": "sha256:accepted-admission",
                "payload": {
                    "bundle_id": "b",
                    "issue_time": "2026-01-01T00:00:00Z",
                    "horizon": 2,
                    "step_seconds": 60,
                    "frame_id": "frame",
                },
            }
        ],
    }
    assert (
        checker.initial_context(conflicted_bundle, _anchor(), {"frame_id": "frame"}, {})
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    no_admissions = {key: value for key, value in _bundle_source().items() if key != "admissions"}
    bundle_initial_context = {
        **no_admissions,
        "initial_context_ref": {
            "checker_status": "pass",
            "artifact_ref": "artifact:initial-context",
            "proof_kind": "initial_context",
            "artifact_digest": "sha256:initial-context",
            "payload": {
                "bundle_id": "b",
                "issue_time": "2026-01-01T00:00:00Z",
                "horizon": 1,
                "step_seconds": 60,
                "frame_id": "frame",
            },
        },
    }
    assert checker.initial_context(
        bundle_initial_context,
        _anchor(),
        {"frame_id": "frame"},
        {},
    ).passed
    string_anchor_bundle = {
        "bundle_id": "b",
        "initial_context_ref": {
            "checker_status": "pass",
            "artifact_ref": "artifact:initial-context",
            "proof_kind": "initial_context",
            "artifact_digest": "sha256:initial-context",
            "payload": {
                "bundle_id": "b",
                "anchor": "anchor:demo",
                "frame_id": "frame",
            },
        },
    }
    assert checker.initial_context(
        string_anchor_bundle,
        "anchor:demo",
        {"frame_id": "frame"},
        {},
    ).passed
    assert (
        checker.initial_context(
            no_admissions,
            _anchor(),
            {"frame_id": "frame"},
            {"checker_transcript_ref": "checker:initial-context"},
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert (
        checker.initial_context(
            no_admissions,
            _anchor(),
            {"frame_id": "frame"},
            {
                "checker_transcript_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:initial-context-transcript",
                    "proof_kind": "initial_context",
                }
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.initial_context(
        no_admissions,
        _anchor(),
        {"frame_id": "frame"},
        {
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:initial-context-transcript",
                "proof_kind": "initial_context",
                "artifact_digest": "sha256:initial-context",
                "payload": {
                    "bundle_id": "b",
                    "issue_time": "2026-01-01T00:00:00Z",
                    "horizon": 1,
                    "step_seconds": 60,
                    "frame_id": "frame",
                },
            }
        },
    ).passed
    assert checker.initial_context(
        no_admissions,
        _anchor(),
        {"frame_id": "frame"},
        {
            "policy_id": "policy:demo",
            "checker_transcript_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:initial-context-transcript",
                "proof_kind": "initial_context",
                "artifact_digest": "sha256:initial-context",
                "payload": {
                    "bundle_id": "b",
                    "issue_time": "2026-01-01T00:00:00Z",
                    "horizon": 1,
                    "step_seconds": 60,
                    "frame_id": "frame",
                    "policy_id": "policy:demo",
                },
            },
        },
    ).passed
    assert (
        checker.initial_context(
            no_admissions,
            _anchor(),
            {"frame_id": "frame"},
            {
                "trust_assumption_ref": {
                    "checker_status": "pass",
                    "artifact_ref": "artifact:trust-assumption",
                    "proof_kind": "trust_assumption",
                }
            },
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.initial_context(
        no_admissions,
        _anchor(),
        {"frame_id": "frame"},
        {
            "trust_assumption_ref": {
                "checker_status": "pass",
                "artifact_ref": "artifact:trust-assumption",
                "proof_kind": "trust_assumption",
                "artifact_digest": "sha256:trust-assumption",
                "payload": {
                    "bundle_id": "b",
                    "issue_time": "2026-01-01T00:00:00Z",
                    "horizon": 1,
                    "step_seconds": 60,
                    "frame_id": "frame",
                },
            }
        },
    ).passed
    assert checker.manifest_digest({}, {}, ()).status is ValidationStatus.UNKNOWN
    assert checker.reference_resolution("ref", {}).status is ValidationStatus.UNKNOWN
    assert checker.artifact_ref(
        ArtifactRef("artifact", "json", digest_value="sha256:a"), None, {}
    ).passed
    assert checker.operational_completion_fiber({}, frame, residual).status is (
        ValidationStatus.UNKNOWN
    )
    completion_record = {"operational_completions": [[{"temp": "70"}, {"temp": "70"}]]}
    assert checker.operational_completion_fiber(completion_record, frame, residual).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.operational_completion_fiber(
        {
            **completion_record,
            "operational_completion_fiber_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:operational-completion-fiber",
                "proof_kind": "operational_completion_fiber",
                "artifact_digest": "sha256:operational-completion-fiber",
                "payload": {"fiber_status": "pass"},
            },
        },
        frame,
        residual,
    ).passed
    assert (
        checker.operational_completion_fiber(
            {
                **completion_record,
                "operational_completion_fiber_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:operational-completion-fiber-conflict",
                    "proof_kind": "operational_completion_fiber",
                    "artifact_digest": "sha256:operational-completion-fiber-conflict",
                    "payload": {"fiber_status": "unknown"},
                },
            },
            frame,
            residual,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.operational_completion_fiber(
            {
                **completion_record,
                "operational_completion_fiber_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-operational-completion-fiber",
                    "proof_kind": "completion_admission",
                },
            },
            frame,
            residual,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.prefix_admission(cut, {}, {}).status is ValidationStatus.UNKNOWN
    prefix_like = type("PrefixLike", (), {"prefix_status": "pass"})()
    assert checker.residual_context(None, None, prefix_like, None).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.residual_context(
        None,
        None,
        {
            "prefix_status": "pass",
            "residual_context_proof_ref": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:residual-context",
                "proof_kind": "residual_context",
                "artifact_digest": "sha256:residual-context",
                "payload": {"residual_context_status": "pass"},
            },
        },
        None,
    ).passed
    assert (
        checker.residual_context(
            None,
            None,
            {
                "prefix_status": "pass",
                "residual_context_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:residual-context-conflict",
                    "proof_kind": "residual_context",
                    "artifact_digest": "sha256:residual-context-conflict",
                    "payload": {"residual_context_status": "unknown"},
                },
            },
            None,
        )
        .failure_records[0]
        .code
        is FailureCode.ARTIFACT_CONFLICT
    )
    assert (
        checker.residual_context(
            None,
            None,
            {
                "prefix_status": "pass",
                "residual_context_proof_ref": {
                    "proof_status": "accepted",
                    "artifact_ref": "artifact:not-residual-context",
                    "proof_kind": "prefix_soundness",
                },
            },
            None,
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.fiber_assoc_view({}, claim, compiled, empty, frame).failure_records[0].code is (
        FailureCode.ASSOC_EMPTY
    )
    assert checker.prefix_adjudication({}, frame).failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert (
        checker.prefix_adjudication({"prefix_adjudication": "accept"}, frame)
        .failure_records[0]
        .code
        is FailureCode.CHECKER_UNKNOWN
    )
    assert checker.target_adjudication({}, {}, frame).failure_records[0].code is (
        FailureCode.CHECKER_UNKNOWN
    )
    assert (
        checker.target_adjudication({"target_adjudication": "accept"}, {}, frame)
        .failure_records[0]
        .code
        is FailureCode.CHECKER_UNKNOWN
    )
    assert (
        checker.agreement(
            kernel,
            FiberAssocView(AssociationStatus.POSITIVE),
            AdjudicationViews(),
            AdequacyDirection.POSITIVE,
            (),
            GateDecision.BLOCK,
        )
        .failure_records[0]
        .code
        is FailureCode.POLICY_BLOCK
    )
    assert (
        checker.agreement(
            object(), object(), AdjudicationViews(), None, (), GateDecision.ALLOW
        ).status
        is ValidationStatus.UNKNOWN
    )
    assert checker.typed_authority_outcome(None, None, None, (), GateDecision.ALLOW).status is (
        ValidationStatus.UNKNOWN
    )
    assert checker.typed_authority_outcome(
        {
            "authority_outcome": {
                "layer": "status",
                "code": "unknown",
                "direction": "none",
                "outcome_schema_ref": "status-authority-view",
            },
            "reason_refs": [
                {
                    "reason_id": "reason:unknown",
                    "failure_code": "checker_unknown",
                    "layer": "status",
                    "source_artifact": "artifact:reason",
                    "source_path": "/reason",
                    "message": "typed reason",
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
                            "message": "typed reason",
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
    event_order = type(
        "EventOrderLike",
        (),
        {
            "confluence_proof": {
                "proof_status": "accepted",
                "artifact_ref": "artifact:confluence-proof",
                "proof_kind": "confluence",
                "artifact_digest": "sha256:confluence-proof",
            }
        },
    )()
    assert checker.status_confluence((), (), event_order).passed
    assert checker.enclosure_soundness(EnclosureResult(FiniteSet.from_iterable(()), True, {}))
    assert checker.witness(WitnessResult(), compiled, residual)
    witness_item = next(iter(residual.adm_out))
    assert not checker.witness(
        WitnessResult(satisfying=FiniteSet.from_iterable((witness_item,))),
        compiled,
        residual,
    )
    assert checker.witness(
        WitnessResult(
            satisfying=FiniteSet.from_iterable((witness_item,)),
            metadata={"proof_ref": "sha256:witness-provenance"},
        ),
        compiled,
        residual,
    )
    assert not checker.witness(
        WitnessResult(
            satisfying=FiniteSet.from_iterable((({"temp": "outside"},),)),
            metadata={"proof_ref": "sha256:witness-provenance"},
        ),
        compiled,
        residual,
    )
    assert not checker.infeasibility({"proof_kind": "external", "proof_status": "accepted"})
    assert not checker.infeasibility(
        {
            "proof_kind": "external",
            "proof_status": "accepted",
            "infeasibility_ref": "artifact:infeasibility-proof",
        }
    )
    assert checker.infeasibility(
        {
            "proof_kind": "external",
            "proof_status": "accepted",
            "infeasibility_ref": "artifact:infeasibility-proof#/proof",
        }
    )
    assert checker.infeasibility(
        {
            "proof_kind": "external",
            "proof_status": "accepted",
            "infeasibility_ref": "sha256:abc",
        }
    )
    assert checker.infeasibility(
        {
            "backend": "EnumeratingBackend",
            "proof_kind": "exact-finite-enumeration",
            "proof_status": "accepted",
            "proof_ref": "sha256:finite-enumeration",
        }
    )
    assert not checker.infeasibility(
        {
            "backend": "EnumeratingBackend",
            "proof_kind": "exact-finite-enumeration",
            "proof_status": "accepted",
        }
    )
    assert checker.inclusion(FiniteSet.from_iterable(()), FiniteSet.from_iterable(())) == "yes"
    assert (
        checker.disjointness(FiniteSet.from_iterable((1,)), FiniteSet.from_iterable((2,))) == "yes"
    )
    assert not checker.artifact_conflict((object(),))

    backend = EnumeratingBackend()
    empty_problem = backend.problem(compiled, empty, claim)
    assert backend.feasibility(empty_problem).status == "infeasible"
    assert backend.outer_enclosure(empty_problem).sound
    assert backend.inner_witnesses(empty_problem, claim).metadata
    nonempty_problem = backend.problem(compiled, residual, claim)
    assert checker.witness(backend.inner_witnesses(nonempty_problem, claim), compiled, residual)
    assert backend.proof_object()["backend"] == "EnumeratingBackend"


def test_digest_bound_nested_evidence_helper_paths() -> None:
    evidence = {
        "proof_status": "accepted",
        "artifact_ref": "artifact:usage-proof",
        "proof_kind": "usage_adjudication",
        "artifact_digest": "sha256:usage-proof",
    }
    assert ReferenceChecker._accepted_digest_bound_nested_field(
        {"usage_adjudication_proof_ref": evidence},
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    assert ReferenceChecker._accepted_digest_bound_nested_field(
        {"policy": {"usage_adjudication_proof_ref": evidence}},
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    policy_holder = type(
        "PolicyHolder",
        (),
        {"policy": {"usage_adjudication_proof_ref": evidence}},
    )()
    assert ReferenceChecker._accepted_digest_bound_nested_field(
        policy_holder,
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    assert ReferenceChecker._accepted_nested_field(
        {"usage_adjudication_proof_ref": evidence},
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    assert ReferenceChecker._accepted_nested_field(
        {"policy": {"usage_adjudication_proof_ref": evidence}},
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    assert ReferenceChecker._accepted_nested_field(
        policy_holder,
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    assert not ReferenceChecker._accepted_digest_bound_nested_field(
        {"policy": {"usage_adjudication_proof_ref": {}}},
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    assert not ReferenceChecker._accepted_nested_field(
        {"policy": {"usage_adjudication_proof_ref": {}}},
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    assert not ReferenceChecker._accepted_digest_bound_field(
        object(),
        "usage_adjudication_proof_ref",
        expected_kinds=("usage_adjudication",),
    )
    assert (
        ReferenceChecker._accepted_payload_value(
            evidence,
            "missing_payload_field",
            expected_kinds=("usage_adjudication",),
        )
        is None
    )
    assert (
        ReferenceChecker._accepted_payload_value(
            {},
            "missing_payload_field",
            expected_kinds=("usage_adjudication",),
        )
        is None
    )
    reason_holder = type(
        "ReasonHolder",
        (),
        {
            "reason_id": "reason:typed",
            "failure_code": "checker_unknown",
            "layer": "interop",
            "source_artifact": "artifact:reason",
            "source_path": "/reason",
            "message": "typed reason",
            "digest": "sha256:reason",
        },
    )()
    assert ReferenceChecker._typed_reason_ref(reason_holder)


def test_claim_language_operators_and_errors() -> None:
    trajectory = ({"temp": "70", "mode": "ok"}, {"temp": "75", "mode": "ok"})
    formulas = [
        {"op": "atom", "name": "field_eq", "args": {"field": "mode", "value": "ok"}},
        {"op": "atom", "name": "state_in", "args": {"values": [{"temp": "70", "mode": "ok"}]}},
        {"op": "not", "child": {"op": "atom", "name": "false"}},
        {
            "op": "and",
            "children": [{"op": "atom", "name": "true"}, {"op": "atom", "name": "true"}],
        },
        {
            "op": "or",
            "children": [{"op": "atom", "name": "false"}, {"op": "atom", "name": "true"}],
        },
        {"op": "F", "a": 0, "b": 1, "child": {"op": "atom", "name": "true"}},
        {
            "op": "U",
            "a": 0,
            "b": 1,
            "left": {"op": "atom", "name": "true"},
            "right": {"op": "atom", "name": "field_eq", "args": {"field": "mode", "value": "ok"}},
        },
    ]
    registry = default_predicate_registry()
    for index, formula in enumerate(formulas):
        claim = compile_claim({"claim_id": f"c{index}", "horizon": 1, "formula": formula})
        assert claim.satisfies(trajectory, registry)

    with pytest.raises(ClaimCompileError):
        compile_claim({"claim_id": "", "horizon": 1, "formula": {"op": "atom", "name": "true"}})
    with pytest.raises(ClaimCompileError):
        compile_claim({"claim_id": "bad", "horizon": -1, "formula": {"op": "atom", "name": "true"}})
    with pytest.raises(ClaimCompileError):
        compile_claim({"claim_id": "bad", "horizon": 1, "formula": {"op": "missing"}})
    with pytest.raises(ClaimCompileError):
        compile_claim(
            {
                "claim_id": "bad",
                "horizon": 1,
                "formula": {"op": "atom", "name": "unknown"},
            }
        )
