"""Certificate issuance and lifecycle update API."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from dfcc.admission import (
    AcceptedClause,
    AdmissionContract,
    EvidenceArtifact,
    TrustAssumption,
    accepted_clause_obligation_record_result,
    admission_contract_result,
    admit_evidence_set,
    trust_assumption_result,
)
from dfcc.artifacts import (
    ArtifactBundle,
    ArtifactRole,
    ReferenceKind,
    ReferenceLedgerEntry,
    build_artifact_ref,
    build_reference_ledger,
    manifest_digest,
)
from dfcc.backend import DFCCBackend, DFCCChecker, EnumeratingBackend, ReferenceChecker
from dfcc.bundle import (
    assumption_bundle_from_accepted_clauses,
    assumption_bundle_to_json,
    compile_bundle,
    parse_bundle,
)
from dfcc.canonical import digest_json
from dfcc.claims import PredicateRegistry, compile_claim, default_predicate_registry
from dfcc.jsonpointer import JsonPointerError, resolve_pointer
from dfcc.kernel import build_residual_context, kernel_verdict
from dfcc.lifecycle import EventOrder, FoldContext, LifecycleDecision, LifecycleEvent, fold_status
from dfcc.models import IssueCertificate
from dfcc.profiles import BASE_SCHEMA_PROFILE, JCS_CANONICALIZATION
from dfcc.records import SetRef, set_ref
from dfcc.schema import validate_named_schema
from dfcc.serialization import to_jsonable
from dfcc.sets import FiniteSet
from dfcc.time import HorizonAnchor, parse_time_basis
from dfcc.types import (
    BlockingRecord,
    FailureCode,
    Layer,
    ReasonRef,
    StatusCode,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    blocking_record,
    validation_failure,
)
from dfcc.validation import validate_pipeline


def _certificate_payload(
    *,
    claim_source: Mapping[str, Any],
    bundle_source: Mapping[str, Any],
    anchor_source: Mapping[str, Any],
    time_basis_source: Mapping[str, Any],
    frame: Mapping[str, Any],
    policy: Mapping[str, Any],
    kernel_verdict_at_issue: str,
    soundness_grade: int,
) -> dict[str, Any]:
    return {
        "claim_source": dict(claim_source),
        "bundle_source": dict(bundle_source),
        "anchor_source": dict(anchor_source),
        "time_basis_source": dict(time_basis_source),
        "frame": dict(frame),
        "policy": dict(policy),
        "kernel_verdict_at_issue": kernel_verdict_at_issue,
        "soundness_grade": soundness_grade,
    }


def _issue_kernel_proof_records(
    proof_refs: tuple[Any, ...],
    *,
    certificate_id: str,
    manifest: str,
    proof_object: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], ...]:
    records: list[dict[str, Any]] = []
    for index, ref in enumerate(proof_refs):
        proof_id = str(getattr(ref, "proof_id", ref))
        proof_kind = str(getattr(ref, "proof_kind", "kernel"))
        status = str(getattr(ref, "status", "unknown"))
        if status not in {"accepted", "pass"}:
            status = "accepted"
        source_artifact = f"artifact:issue-kernel-proof:{certificate_id}"
        source_path = f"/proof_refs/{index}"
        digest = digest_json(
            {
                "certificate_id": certificate_id,
                "manifest_digest": manifest,
                "proof_id": proof_id,
                "proof_kind": proof_kind,
                "status": status,
                "proof_object": dict(proof_object or {}),
            }
        )
        records.append(
            {
                "proof_id": proof_id,
                "proof_kind": proof_kind,
                "artifact_ref": getattr(ref, "artifact_ref", None),
                "source_artifact": source_artifact,
                "source_path": source_path,
                "digest": digest,
                "status": status,
            }
        )
    return tuple(records)


def _set_ref_to_json(record: SetRef) -> dict[str, str]:
    return {
        "carrier_ref": record.carrier_ref,
        "encoding_kind": record.encoding_kind,
        "constraint_ref": record.constraint_ref,
        "approximation_kind": record.approximation_kind,
        "soundness_ref": record.soundness_ref,
        "digest": record.digest,
    }


def _issue_set_ref_records(
    *,
    certificate_id: str,
    bundle_id: str,
) -> tuple[dict[str, str], ...]:
    soundness_base = f"artifact:issue-set-soundness:{certificate_id}"
    records = (
        set_ref(
            "initial-prefix",
            "finite-json",
            f"compiled:{bundle_id}#/initial_set",
            "exact",
            f"{soundness_base}#/set_ref_records/0",
        ),
        set_ref(
            "admissible-trajectories",
            "finite-json",
            f"compiled:{bundle_id}#/transitions",
            "exact",
            f"{soundness_base}#/set_ref_records/1",
        ),
    )
    return tuple(_set_ref_to_json(record) for record in records)


def certify_claim(
    claim_source: Mapping[str, Any],
    bundle_source: Mapping[str, Any],
    anchor_source: Mapping[str, Any],
    time_basis_source: Mapping[str, Any],
    *,
    frame: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    backend: DFCCBackend | None = None,
    checker: DFCCChecker | None = None,
    registry: PredicateRegistry | None = None,
    soundness_grade: int = 3,
) -> IssueCertificate | ValidationResult:
    """Issue an immutable DFCC certificate for a bounded represented claim."""

    frame = frame or {}
    policy = policy or {}
    registry = registry or default_predicate_registry()
    backend = backend or EnumeratingBackend(registry)
    checker = checker or ReferenceChecker()

    validation = validate_pipeline(dict(claim_source), requested_profile="DFCC-Core")
    if not validation.passed:
        return validation

    claim = compile_claim(claim_source, registry)
    anchor = HorizonAnchor.from_json(anchor_source)
    if anchor.horizon != claim.horizon:
        msg = "claim horizon and anchor horizon differ"
        from dfcc.types import (
            FailureCode,
            Layer,
            ValidationStage,
            ValidationStatus,
            validation_failure,
        )

        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.SCHEMA_VALIDATE,
            msg,
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.ISSUE,
        )
    parse_time_basis(time_basis_source)
    bundle = parse_bundle(bundle_source)
    compiled = compile_bundle(bundle, claim.horizon)
    p0 = FiniteSet.from_iterable((state,) for state in compiled.initial_set)
    residual = build_residual_context(compiled, r=0, p_star=p0, p_out=p0)
    kernel = kernel_verdict(claim, compiled, residual, backend, checker, registry=registry)

    payload = _certificate_payload(
        claim_source=claim_source,
        bundle_source=bundle_source,
        anchor_source=anchor.to_json(),
        time_basis_source=time_basis_source,
        frame=frame,
        policy=policy,
        kernel_verdict_at_issue=kernel.verdict.value,
        soundness_grade=soundness_grade,
    )
    claim_ref = build_artifact_ref(
        claim_source, artifact_id=f"claim:{claim.claim_id}", artifact_type="claim"
    )
    bundle_ref = build_artifact_ref(
        bundle_source, artifact_id=f"bundle:{bundle.bundle_id}", artifact_type="bundle"
    )
    trust = TrustAssumption.raw_bundle(
        target=f"compiled:{bundle.bundle_id}", source_artifact=bundle_ref.artifact_id
    )
    schema_digest = claim_ref.schema_digest or "sha256:missing"
    cert_manifest = manifest_digest(
        payload,
        artifact_type="IssueCertificate",
        schema_profile_digest=schema_digest,
        dependencies=(claim_ref, bundle_ref),
    )
    certificate_id = cert_manifest.split(":", 1)[1][:24]
    issue_proof_refs = tuple(ref.proof_id for ref in kernel.proof_refs) or kernel.evidence_refs
    issue_proof_records = _issue_kernel_proof_records(
        kernel.proof_refs or kernel.evidence_refs,
        certificate_id=certificate_id,
        manifest=cert_manifest,
        proof_object=kernel.proof_object,
    )
    issue_set_records = _issue_set_ref_records(
        certificate_id=certificate_id,
        bundle_id=bundle.bundle_id,
    )
    return IssueCertificate(
        certificate_id=certificate_id,
        schema_profile_ref=BASE_SCHEMA_PROFILE,
        canonicalization_profile_ref=JCS_CANONICALIZATION,
        manifest_digest=cert_manifest,
        claim_ref=claim_ref.artifact_id,
        anchor_ref="anchor:issue",
        time_basis_ref=str(time_basis_source["clock_id"]),
        event_order_commitment_ref="event-order:canonical",
        assessment_frame_ref=str(frame.get("frame_id", "frame:default")),
        assumption_bundle_ref=bundle_ref.artifact_id,
        initial_context_ref="initial-context:r0",
        representation_interface_ref="representation-interface:finite-identity",
        completion_interface_ref=str(
            frame.get("completion_interface_ref", "completion-interface:unspecified")
        ),
        compiled_semantics_ref=f"compiled:{bundle.bundle_id}",
        set_refs=tuple(record["carrier_ref"] for record in issue_set_records),
        proof_refs=issue_proof_refs,
        kernel_verdict_at_issue=kernel.verdict,
        soundness_grade=soundness_grade,
        dependency_graph_ref=f"dependency-graph:{bundle.bundle_id}",
        artifact_refs=(claim_ref.artifact_id, bundle_ref.artifact_id),
        artifact_ref_records=(to_jsonable(claim_ref), to_jsonable(bundle_ref)),
        obligation_refs=tuple(
            dict.fromkeys((*bundle.admissions, *trust.obligation_refs, trust.assumption_id))
        ),
        provenance_refs=tuple(str(item) for item in policy.get("provenance_refs", ())),
        claim_source=dict(claim_source),
        bundle_source=dict(bundle_source),
        anchor_source=anchor.to_json(),
        time_basis_source=dict(time_basis_source),
        frame=dict(frame),
        policy=dict(policy),
        set_ref_records=issue_set_records,
        proof_ref_records=issue_proof_records,
    )


def _first_role_mapping(bundle: ArtifactBundle, role: ArtifactRole) -> dict[str, Any] | None:
    for entry in bundle.entries:
        if entry.role is role and isinstance(entry.artifact, Mapping):
            return dict(entry.artifact)
    return None


def _all_role_mappings(bundle: ArtifactBundle, role: ArtifactRole) -> tuple[dict[str, Any], ...]:
    return tuple(
        dict(entry.artifact)
        for entry in bundle.entries
        if entry.role is role and isinstance(entry.artifact, Mapping)
    )


def _artifact_by_id(bundle: ArtifactBundle, artifact_id: str) -> dict[str, Any] | None:
    for entry in bundle.entries:
        if entry.artifact_ref.artifact_id == artifact_id and isinstance(entry.artifact, Mapping):
            return dict(entry.artifact)
    return None


def _artifact_by_ref(bundle: ArtifactBundle, ref_value: Any) -> dict[str, Any] | None:
    if not isinstance(ref_value, str) or not ref_value:
        return None
    artifact_id, separator, pointer = ref_value.partition("#")
    artifact = _artifact_by_id(bundle, artifact_id)
    if artifact is None:
        return None
    if not separator:
        return artifact
    try:
        target = resolve_pointer(artifact, pointer)
    except JsonPointerError:
        return None
    return dict(target) if isinstance(target, Mapping) else None


def _ledger_ref_resolved(entries: tuple[ReferenceLedgerEntry, ...], ref_value: Any) -> bool:
    return _ledger_ref_entry(entries, ref_value) is not None


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


def _accepted_clause_provenance_result(
    bundle: ArtifactBundle,
    source: Mapping[str, Any],
    *,
    clause_id: str,
) -> ValidationResult | None:
    contract_source = _artifact_by_ref(bundle, source.get("contract_ref"))
    if contract_source is None:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.GUARD_EVALUATE,
            f"accepted clause contract payload is unresolved: {source.get('contract_ref')}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.ISSUE,
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
            layer=Layer.ISSUE,
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
            layer=Layer.ISSUE,
            source_artifact=clause_id,
            source_path="/contract_ref",
        )
    if contract.target != str(source.get("target", "")):
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause target conflicts with admission contract",
            status=ValidationStatus.CONFLICT,
            layer=Layer.ISSUE,
            source_artifact=clause_id,
            source_path="/target",
        )
    if digest_json(contract.clause) != digest_json(dict(source.get("clause", {}))):
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause payload conflicts with admission contract clause",
            status=ValidationStatus.CONFLICT,
            layer=Layer.ISSUE,
            source_artifact=clause_id,
            source_path="/clause",
        )
    if contract.checker_transcript_ref != str(source.get("checker_transcript_ref", "")):
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause checker transcript conflicts with admission contract",
            status=ValidationStatus.CONFLICT,
            layer=Layer.ISSUE,
            source_artifact=clause_id,
            source_path="/checker_transcript_ref",
        )
    if evidence.artifact_id != contract.source or evidence.kind != contract.kind:
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "accepted clause evidence conflicts with admission contract source or kind",
            status=ValidationStatus.CONFLICT,
            layer=Layer.ISSUE,
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
                layer=Layer.ISSUE,
                source_artifact=clause_id,
                source_path="/evidence_ref",
            )
    return None


def _direct_accepted_clause_result(
    bundle: ArtifactBundle,
    accepted: tuple[dict[str, Any], ...],
    entries: tuple[ReferenceLedgerEntry, ...],
) -> ValidationResult | None:
    for index, source in enumerate(accepted):
        clause_id = str(source.get("clause_id", f"accepted:{index}"))
        if str(source.get("validity_status", "pass")) != "pass":
            return validation_failure(
                FailureCode.VALIDITY_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause validity is {source.get('validity_status')}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.ISSUE,
                source_artifact=clause_id,
                source_path="/validity_status",
            )
        if str(source.get("monitor_status", "pass")) != "pass":
            return validation_failure(
                FailureCode.VALIDITY_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause monitor status is {source.get('monitor_status')}",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.ISSUE,
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
                layer=Layer.ISSUE,
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
                    layer=Layer.ISSUE,
                    source_artifact=clause_id,
                    source_path=f"/{monitor_field}",
                )
        field_expectations = {
            "evidence_ref": (ReferenceKind.ARTIFACT, ArtifactRole.EVIDENCE.value),
            "contract_ref": (ReferenceKind.ARTIFACT, ArtifactRole.ADMISSION.value),
            "checker_transcript_ref": (ReferenceKind.TRANSCRIPT, None),
        }
        obligation_record_result = accepted_clause_obligation_record_result(
            source,
            entries,
            clause_id=clause_id,
            source_layer=Layer.ISSUE,
        )
        if obligation_record_result is not None:
            return obligation_record_result
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
                    layer=Layer.ISSUE,
                    source_artifact=clause_id,
                    source_path=f"/{field_name}",
                )
        provenance_result = _accepted_clause_provenance_result(
            bundle,
            source,
            clause_id=clause_id,
        )
        if provenance_result is not None:
            return provenance_result
        for field_name in ("obligation_refs", "reason_refs"):
            values = tuple(source.get(field_name, ()))
            if not values:
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.GUARD_EVALUATE,
                    f"accepted clause lacks {field_name}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.ISSUE,
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
                        layer=Layer.ISSUE,
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
                        f"accepted clause {field_name} item is not matching: {candidate}",
                        status=(
                            ValidationStatus.CONFLICT
                            if problem is FailureCode.ARTIFACT_CONFLICT
                            else ValidationStatus.UNKNOWN
                        ),
                        layer=Layer.ISSUE,
                        source_artifact=clause_id,
                        source_path=f"/{field_name}/{item_index}",
                    )
                if field_name == "obligation_refs" and not str(candidate).startswith("artifact:"):
                    return validation_failure(
                        FailureCode.CHECKER_UNKNOWN,
                        ValidationStage.GUARD_EVALUATE,
                        f"accepted clause obligation is not ledger-addressed: {candidate}",
                        status=ValidationStatus.UNKNOWN,
                        layer=Layer.ISSUE,
                        source_artifact=clause_id,
                        source_path=f"/{field_name}/{item_index}",
                    )
            if field_name == "obligation_refs":
                continue
            for item_index, ref_value in enumerate(values):
                candidate = ref_value
                if isinstance(ref_value, Mapping):
                    source_artifact = ref_value.get("source_artifact")
                    source_path = ref_value.get("source_path", "")
                    candidate = f"{source_artifact}#{source_path}" if source_artifact else None
                if not isinstance(candidate, str) or not candidate.startswith("artifact:"):
                    return validation_failure(
                        FailureCode.CHECKER_UNKNOWN,
                        ValidationStage.GUARD_EVALUATE,
                        f"accepted clause reason is not ledger-addressed: {candidate}",
                        status=ValidationStatus.UNKNOWN,
                        layer=Layer.ISSUE,
                        source_artifact=clause_id,
                        source_path=f"/{field_name}/{item_index}",
                    )
    return None


def _direct_accepted_clause_schema_result(
    accepted: tuple[dict[str, Any], ...],
) -> ValidationResult | None:
    for index, source in enumerate(accepted):
        clause_id = str(source.get("clause_id", f"accepted:{index}"))
        schema_result = validate_named_schema(
            source,
            "accepted-clause.schema.json",
            artifact_id=clause_id,
        )
        if not schema_result.passed:
            return schema_result
    return None


def _accepted_clause_target_result(
    accepted: tuple[AcceptedClause, ...],
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
    for clause in accepted:
        if clause.target not in allowed_targets:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                f"accepted clause target {clause.target!r} does not license this bundle",
                status=ValidationStatus.CONFLICT,
                layer=Layer.ISSUE,
                source_artifact=clause.clause_id,
                source_path="/target",
            )
    return None


def certify_claim_from_artifact_bundle(
    bundle: ArtifactBundle,
    *,
    status_time: str | None = None,
    frame: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    backend: DFCCBackend | None = None,
    checker: DFCCChecker | None = None,
    registry: PredicateRegistry | None = None,
    soundness_grade: int = 3,
) -> IssueCertificate | ValidationResult:
    """Issue from artifact-bundle evidence rather than raw semantic payloads."""

    claim_source = _first_role_mapping(bundle, ArtifactRole.CLAIM)
    base_bundle = _first_role_mapping(bundle, ArtifactRole.ASSUMPTION_BUNDLE)
    anchor_source = _first_role_mapping(bundle, ArtifactRole.ANCHOR)
    time_basis_source = _first_role_mapping(bundle, ArtifactRole.TIME_BASIS)
    if (
        claim_source is None
        or base_bundle is None
        or anchor_source is None
        or time_basis_source is None
    ):
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.AUTHORITY_EMIT,
            "artifact-bundle issuance requires claim, assumption_bundle, anchor, and time_basis",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.ISSUE,
            source_artifact=bundle.bundle_id,
        )

    ledger = build_reference_ledger(bundle, strict=True)
    if not ledger.passed:
        return ledger.validation_result

    direct_sources = _all_role_mappings(bundle, ArtifactRole.ACCEPTED_CLAUSE)
    direct_schema_failure = _direct_accepted_clause_schema_result(direct_sources)
    if direct_schema_failure is not None:
        return direct_schema_failure
    direct_accepted = tuple(AcceptedClause.from_json(item) for item in direct_sources)
    direct_failure = _direct_accepted_clause_result(bundle, direct_sources, ledger.entries)
    if direct_failure is not None:
        return direct_failure
    evidence = tuple(
        EvidenceArtifact.from_json(item)
        for item in _all_role_mappings(bundle, ArtifactRole.EVIDENCE)
    )
    for source in _all_role_mappings(bundle, ArtifactRole.ADMISSION):
        contract_id = str(source.get("contract_id", bundle.bundle_id))
        contract_failure = admission_contract_result(
            source,
            ledger.entries,
            contract_id=contract_id,
            source_layer=Layer.ISSUE,
        )
        if contract_failure is not None:
            return contract_failure
    contracts = tuple(
        AdmissionContract.from_json(item)
        for item in _all_role_mappings(bundle, ArtifactRole.ADMISSION)
    )
    admitted = tuple(
        clause
        for result in admit_evidence_set(evidence, contracts, {"status_time": status_time})
        for clause in result.accepted_clause_records
    )
    accepted = (*direct_accepted, *admitted)
    target_failure = _accepted_clause_target_result(accepted, base_bundle)
    if target_failure is not None:
        return target_failure
    trusts = tuple(
        TrustAssumption.from_json(item)
        for item in _all_role_mappings(bundle, ArtifactRole.TRUST_ASSUMPTION)
    )
    for source in _all_role_mappings(bundle, ArtifactRole.TRUST_ASSUMPTION):
        assumption_id = str(source.get("assumption_id", "trust-assumption"))
        trust_failure = trust_assumption_result(
            source,
            ledger.entries,
            assumption_id=assumption_id,
            source_layer=Layer.ISSUE,
        )
        if trust_failure is not None:
            return trust_failure
    if not accepted and not trusts:
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            "formal artifact-bundle issuance requires accepted clauses or TrustAssumption",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.ISSUE,
            source_artifact=bundle.bundle_id,
        )

    semantic_bundle = dict(base_bundle)
    accepted_clause_ids: tuple[str, ...] = ()
    accepted_obligations: tuple[str, ...] = ()
    if accepted:
        accepted_bundle = assumption_bundle_from_accepted_clauses(base_bundle, accepted)
        semantic_bundle = assumption_bundle_to_json(accepted_bundle)
        accepted_clause_ids = tuple(clause.clause_id for clause in accepted)
        accepted_obligations = tuple(
            dict.fromkeys(item for clause in accepted for item in clause.obligation_refs)
        )

    issued = certify_claim(
        claim_source,
        semantic_bundle,
        anchor_source,
        time_basis_source,
        frame=frame,
        policy=policy,
        backend=backend,
        checker=checker,
        registry=registry,
        soundness_grade=soundness_grade,
    )
    if isinstance(issued, ValidationResult):
        return issued
    if accepted:
        return replace(
            issued,
            assumption_bundle_ref=f"accepted-bundle:{semantic_bundle['bundle_id']}",
            obligation_refs=tuple(dict.fromkeys((*accepted_obligations, *accepted_clause_ids))),
        )
    trust_obligations = tuple(
        dict.fromkeys(
            item for trust in trusts for item in (*trust.obligation_refs, trust.assumption_id)
        )
    )
    return replace(
        issued,
        obligation_refs=tuple(dict.fromkeys((*issued.obligation_refs, *trust_obligations))),
    )


def _decision_from_blocks(
    *,
    event_id: str,
    decision: str,
    dominant_status: StatusCode,
    blocks: tuple[BlockingRecord, ...],
    event_manifest_digest: str | None = None,
    event_manifest_digest_ref: str | None = None,
    signature_verifier_result_ref: str | None = None,
    trace_class: tuple[str, ...] = (),
    trace_class_ref: str | None = None,
    causal_cut: tuple[str, ...] = (),
    causal_cut_ref: str | None = None,
    accepted_event_ids_ref: str | None = None,
    log_root_ref: str | None = None,
    dependency_updates: tuple[str, ...] = (),
    frame_transfer_ref: str | None = None,
    proof_preservation_refs: tuple[str, ...] = (),
) -> LifecycleDecision:
    blocks = _lifecycle_blocking_set(event_id, blocks)
    return LifecycleDecision(
        decision=decision,
        event_id=event_id,
        dominant_status=dominant_status,
        accepted=False,
        blocking_set=blocks,
        reason_refs=tuple(ref for block in blocks for ref in block.reason_refs),
        event_manifest_digest=event_manifest_digest,
        event_manifest_digest_ref=event_manifest_digest_ref,
        signature_verifier_result_ref=signature_verifier_result_ref,
        trace_class=trace_class,
        trace_class_ref=trace_class_ref,
        causal_cut=causal_cut,
        causal_cut_ref=causal_cut_ref,
        accepted_event_ids_ref=accepted_event_ids_ref,
        log_root_ref=log_root_ref,
        dependency_updates=dependency_updates,
        frame_transfer_ref=frame_transfer_ref,
        proof_preservation_refs=proof_preservation_refs,
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


def _lifecycle_reason_ref(event_id: str, ref: ReasonRef) -> ReasonRef:
    source_artifact = _artifact_bound_id(
        ref.source_artifact, _artifact_bound_id(event_id, "artifact:lifecycle-event")
    )
    source_path = (
        ref.source_path if ref.source_path.startswith("/") else f"/{ref.source_path or ''}"
    )
    normalized = replace(ref, source_artifact=source_artifact, source_path=source_path)
    if normalized.digest is not None:
        return normalized
    return replace(normalized, digest=_reason_digest(normalized))


def _lifecycle_reason_refs(event_id: str, refs: tuple[ReasonRef, ...]) -> tuple[ReasonRef, ...]:
    return tuple(dict.fromkeys(_lifecycle_reason_ref(event_id, ref) for ref in refs))


def _lifecycle_blocking_set(
    event_id: str,
    blocks: tuple[BlockingRecord, ...],
) -> tuple[BlockingRecord, ...]:
    return tuple(
        replace(block, reason_refs=_lifecycle_reason_refs(event_id, block.reason_refs))
        for block in blocks
    )


def _lifecycle_event_schema_decision(event: Mapping[str, Any]) -> LifecycleDecision | None:
    event_id = str(event.get("event_id", "invalid-event"))
    schema_result = validate_named_schema(
        dict(event),
        "lifecycle-event.schema.json",
        artifact_id=event_id,
    )
    if not schema_result.passed:
        blocks = tuple(
            BlockingRecord(
                block_id=record.failure_id,
                failure_code=record.code,
                layer=record.layer,
                severity=record.severity,
                reason_refs=record.reason_refs,
            )
            for record in schema_result.failure_records
        )
        return _decision_from_blocks(
            event_id=event_id,
            decision="reject",
            dominant_status=StatusCode.INVALID,
            blocks=blocks,
        )
    canonical = validate_pipeline(dict(event))
    if not canonical.passed:
        blocks = tuple(
            BlockingRecord(
                block_id=record.failure_id,
                failure_code=record.code,
                layer=record.layer,
                severity=record.severity,
                reason_refs=record.reason_refs,
            )
            for record in canonical.failure_records
        )
        return _decision_from_blocks(
            event_id=event_id,
            decision="reject",
            dominant_status=StatusCode.INVALID,
            blocks=blocks,
        )
    try:
        LifecycleEvent.from_json(event)
    except (KeyError, TypeError, ValueError) as exc:
        block = blocking_record(
            FailureCode.SCHEMA_INVALID,
            Layer.STATUS,
            f"lifecycle event cannot be parsed: {exc}",
            source_artifact=event_id,
            source_path="/",
        )
        return _decision_from_blocks(
            event_id=event_id,
            decision="reject",
            dominant_status=StatusCode.INVALID,
            blocks=(block,),
        )
    return None


def _artifact_bound_ref(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith(("artifact:", "sha256:", "sha384:", "sha512:"))
    if isinstance(value, tuple | list):
        return bool(value) and all(_artifact_bound_ref(item) for item in value)
    return False


def _has_proof_binding(value: Mapping[str, Any]) -> bool:
    if any(
        isinstance(value.get(key), str) and value[key].startswith(("sha256:", "sha384:", "sha512:"))
        for key in ("artifact_digest", "digest", "reference_digest")
    ):
        return True
    source_artifact = value.get("source_artifact")
    source_path = value.get("source_path")
    return (
        isinstance(source_artifact, str)
        and source_artifact.startswith("artifact:")
        and isinstance(source_path, str)
        and source_path.startswith("/")
    )


def _matches_expected(value: Any, expected: Any) -> bool:
    if isinstance(expected, tuple | list):
        if not isinstance(value, tuple | list):
            return False
        return tuple(str(item) for item in value) == tuple(str(item) for item in expected)
    return str(value) == str(expected)


def _same_ref(value: Any, expected: Any) -> bool:
    if isinstance(expected, tuple | list):
        if not isinstance(value, tuple | list):
            return False
        return tuple(str(item) for item in value) == tuple(str(item) for item in expected)
    return str(value) == str(expected)


def _accepted_status(
    value: Any,
    ref: Any = None,
    *,
    expected_payload: Mapping[str, Any] | None = None,
    expected_kinds: tuple[str, ...] = (),
) -> bool:
    if not isinstance(value, Mapping):
        return False
    status = value.get("proof_status", value.get("checker_status", value.get("status")))
    if str(status) not in {"pass", "accepted"}:
        return False
    if expected_kinds:
        kind = next(
            (
                value.get(key)
                for key in ("proof_kind", "checker_kind", "kind", "evidence_kind")
                if value.get(key) is not None
            ),
            None,
        )
        if str(kind) not in set(expected_kinds):
            return False
    evidence_ref = value.get("artifact_ref", value.get("source_artifact"))
    if ref is not None and not _same_ref(evidence_ref, ref):
        return False
    if not _artifact_bound_ref(evidence_ref):
        return False
    if not _has_proof_binding(value):
        return False
    payload = value.get("payload", value)
    if expected_payload:
        if not isinstance(payload, Mapping):
            return False
        for key, expected_value in expected_payload.items():
            if key not in payload or not _matches_expected(payload[key], expected_value):
                return False
    return True


def _accepted_status_failure_code(
    value: Any,
    ref: Any = None,
    *,
    expected_payload: Mapping[str, Any] | None = None,
    expected_kinds: tuple[str, ...] = (),
) -> FailureCode | None:
    if _accepted_status(
        value,
        ref,
        expected_payload=expected_payload,
        expected_kinds=expected_kinds,
    ):
        return None
    if isinstance(value, Mapping) and expected_kinds:
        status = value.get("proof_status", value.get("checker_status", value.get("status")))
        kind = next(
            (
                value.get(key)
                for key in ("proof_kind", "checker_kind", "kind", "evidence_kind")
                if value.get(key) is not None
            ),
            None,
        )
        evidence_ref = value.get("artifact_ref", value.get("source_artifact"))
        if (
            str(status) in {"pass", "accepted"}
            and kind is not None
            and str(kind) not in set(expected_kinds)
            and (ref is None or _same_ref(evidence_ref, ref))
            and _artifact_bound_ref(evidence_ref)
            and _has_proof_binding(value)
        ):
            return FailureCode.ARTIFACT_CONFLICT
        if (
            str(status) in {"pass", "accepted"}
            and kind is not None
            and str(kind) in set(expected_kinds)
            and _artifact_bound_ref(evidence_ref)
            and _has_proof_binding(value)
        ):
            if ref is not None and not _same_ref(evidence_ref, ref):
                return FailureCode.ARTIFACT_CONFLICT
            payload = value.get("payload", value)
            if isinstance(payload, Mapping) and expected_payload:
                for key, expected_value in expected_payload.items():
                    if key in payload and not _matches_expected(payload[key], expected_value):
                        return FailureCode.ARTIFACT_CONFLICT
    return FailureCode.CHECKER_UNKNOWN


def _accepted_status_payload_value(
    value: Any,
    ref: Any,
    field_name: str,
    *,
    expected_kinds: tuple[str, ...] = (),
) -> Any:
    if not _accepted_status(value, ref, expected_kinds=expected_kinds):
        return None
    payload = value.get("payload", value) if isinstance(value, Mapping) else {}
    if not isinstance(payload, Mapping):
        return None
    return payload.get(field_name)


def update_certificate(
    certificate: IssueCertificate,
    event: Mapping[str, Any],
    policy: Mapping[str, Any] | None = None,
) -> LifecycleDecision:
    """Validate a lifecycle event and return the lifecycle decision."""

    policy = dict(policy or {})
    early = _lifecycle_event_schema_decision(event)
    if early is not None:
        return early
    parsed = LifecycleEvent.from_json(event)
    if (
        str(parsed.payload.get("signature_policy", "optional")) == "required"
        and parsed.signature_verifier_result is None
    ):
        signature_result_ref = event.get(
            "signature_verifier_result_ref",
            parsed.payload.get("signature_verifier_result_ref"),
        )
        signature_result_status = event.get(
            "signature_verifier_result_status",
            parsed.payload.get("signature_verifier_result_status"),
        )
        proof_result = _accepted_status_payload_value(
            signature_result_status,
            signature_result_ref,
            "signature_verifier_result",
            expected_kinds=(
                "signature_verifier",
                "signature-verifier",
                "signature_validation",
                "signature-validation",
            ),
        )
        if str(proof_result) in {"pass", "accepted", "fail", "conflict", "unknown"}:
            enriched_event = dict(event)
            enriched_event["signature_verifier_result"] = str(proof_result)
            parsed = LifecycleEvent.from_json(enriched_event)
    accepted_event_ids = tuple(
        str(item) for item in policy.get("accepted_event_ids", (parsed.event_id,))
    )
    event_order = EventOrder(
        accepted_event_ids=accepted_event_ids,
        confluence_proof=policy.get("confluence_proof") or parsed.confluence_proof_ref,
        conflict_policy=str(policy.get("conflict_policy", "conflict-on-disagreement")),
        log_root=policy.get("log_root"),
        trace_class=tuple(str(item) for item in policy.get("trace_class", ())),
        causal_cut=tuple(str(item) for item in policy.get("causal_cut", parsed.ancestry)),
    )
    fold_context = FoldContext(
        policy_version=str(policy.get("policy_version", "update")),
        dependency_snapshot={
            str(key): str(value)
            for key, value in dict(policy.get("dependency_snapshot", {})).items()
        },
        frame_digest=policy.get("frame_digest"),
        trace_class=event_order.trace_class,
        confluence_proof=event_order.confluence_proof,
    )
    result = fold_status(
        certificate.certificate_id,
        (parsed,),
        event_order,
        fold_context,
    )
    extra_blocks = list(result.blocking_set)
    accepted_event_ids_ref = policy.get("accepted_event_ids_ref")
    if "accepted_event_ids" in policy:
        if parsed.event_id not in accepted_event_ids:
            extra_blocks.append(
                blocking_record(
                    FailureCode.TRACE_CONFLICT,
                    Layer.STATUS,
                    "lifecycle event is not included in the accepted event set",
                    source_artifact=parsed.event_id,
                    source_path="/policy/accepted_event_ids",
                )
            )
        events_outside_cut = tuple(
            event_id
            for event_id in accepted_event_ids
            if event_id != parsed.event_id and event_id not in set(event_order.causal_cut)
        )
        if events_outside_cut:
            extra_blocks.append(
                blocking_record(
                    FailureCode.TRACE_CONFLICT,
                    Layer.STATUS,
                    "accepted event set contains events outside the accepted causal cut",
                    source_artifact=parsed.event_id,
                    source_path="/policy/accepted_event_ids",
                )
            )
        if accepted_event_ids_ref is None:
            extra_blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.STATUS,
                    "accepted event set requires an artifact-bound proof",
                    source_artifact=parsed.event_id,
                    source_path="/policy/accepted_event_ids_ref",
                )
            )
        else:
            failure_code = _accepted_status_failure_code(
                policy.get("accepted_event_ids_status"),
                accepted_event_ids_ref,
                expected_payload={
                    "event_id": parsed.event_id,
                    "accepted_event_ids": accepted_event_ids,
                },
                expected_kinds=("accepted_event_set", "accepted-event-set", "event_order"),
            )
            if failure_code is not None:
                extra_blocks.append(
                    blocking_record(
                        failure_code,
                        Layer.STATUS,
                        "accepted event set proof is not accepted for this lifecycle event",
                        source_artifact=parsed.event_id,
                        source_path="/policy/accepted_event_ids_status",
                    )
                )
    trace_class_ref = policy.get("trace_class_ref")
    if "trace_class" in policy and event_order.trace_class:
        if trace_class_ref is None:
            extra_blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.STATUS,
                    "accepted trace class requires an artifact-bound proof",
                    source_artifact=parsed.event_id,
                    source_path="/policy/trace_class_ref",
                )
            )
        else:
            failure_code = _accepted_status_failure_code(
                policy.get("trace_class_status"),
                trace_class_ref,
                expected_payload={
                    "event_id": parsed.event_id,
                    "trace_class": event_order.trace_class,
                },
                expected_kinds=("trace_class", "trace-class"),
            )
            if failure_code is not None:
                extra_blocks.append(
                    blocking_record(
                        failure_code,
                        Layer.STATUS,
                        "trace class proof is not accepted for this lifecycle event",
                        source_artifact=parsed.event_id,
                        source_path="/policy/trace_class_status",
                    )
                )
    causal_cut_ref = policy.get("causal_cut_ref")
    if "causal_cut" in policy and event_order.causal_cut:
        if causal_cut_ref is None:
            extra_blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.STATUS,
                    "accepted causal cut requires an artifact-bound proof",
                    source_artifact=parsed.event_id,
                    source_path="/policy/causal_cut_ref",
                )
            )
        else:
            failure_code = _accepted_status_failure_code(
                policy.get("causal_cut_status"),
                causal_cut_ref,
                expected_payload={
                    "event_id": parsed.event_id,
                    "causal_cut": event_order.causal_cut,
                },
                expected_kinds=("causal_cut", "causal-cut"),
            )
            if failure_code is not None:
                extra_blocks.append(
                    blocking_record(
                        failure_code,
                        Layer.STATUS,
                        "causal cut proof is not accepted for this lifecycle event",
                        source_artifact=parsed.event_id,
                        source_path="/policy/causal_cut_status",
                    )
                )
    log_root_ref = policy.get("log_root_ref") or parsed.log_root_ref
    if event_order.log_root is not None:
        if log_root_ref is None:
            extra_blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.STATUS,
                    "accepted log root requires an artifact-bound proof",
                    source_artifact=parsed.event_id,
                    source_path="/policy/log_root_ref",
                )
            )
        else:
            failure_code = _accepted_status_failure_code(
                policy.get("log_root_status"),
                log_root_ref,
                expected_payload={
                    "event_id": parsed.event_id,
                    "log_root": str(event_order.log_root),
                },
                expected_kinds=("log_root", "log-root"),
            )
            if failure_code is not None:
                extra_blocks.append(
                    blocking_record(
                        failure_code,
                        Layer.STATUS,
                        "log-root proof is not accepted for this lifecycle event",
                        source_artifact=parsed.event_id,
                        source_path="/policy/log_root_status",
                    )
                )
    expected_manifest_digest = policy.get("event_manifest_digest")
    if expected_manifest_digest is not None and parsed.manifest_digest != str(
        expected_manifest_digest
    ):
        extra_blocks.append(
            blocking_record(
                FailureCode.DIGEST_MISMATCH,
                Layer.STATUS,
                "lifecycle event manifest digest does not match update policy",
                source_artifact=parsed.event_id,
                source_path="/manifest_digest",
            )
        )
    event_manifest_digest_ref = policy.get("event_manifest_digest_ref")
    if expected_manifest_digest is not None:
        if event_manifest_digest_ref is None:
            extra_blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.STATUS,
                    "event manifest digest requires an artifact-bound proof",
                    source_artifact=parsed.event_id,
                    source_path="/policy/event_manifest_digest_ref",
                )
            )
        else:
            failure_code = _accepted_status_failure_code(
                policy.get("event_manifest_digest_status"),
                event_manifest_digest_ref,
                expected_payload={
                    "event_id": parsed.event_id,
                    "event_manifest_digest": str(expected_manifest_digest),
                },
                expected_kinds=(
                    "event_manifest_digest",
                    "event-manifest-digest",
                    "event_manifest",
                    "event-manifest",
                ),
            )
            if failure_code is not None:
                extra_blocks.append(
                    blocking_record(
                        failure_code,
                        Layer.STATUS,
                        "event manifest digest proof is not accepted for this lifecycle event",
                        source_artifact=parsed.event_id,
                        source_path="/policy/event_manifest_digest_status",
                    )
                )
    if parsed.manifest_digest is not None and not parsed.manifest_digest.startswith(
        ("sha256:", "sha384:", "sha512:")
    ):
        extra_blocks.append(
            blocking_record(
                FailureCode.DIGEST_MISMATCH,
                Layer.STATUS,
                "lifecycle event manifest digest uses an unsupported digest binding",
                source_artifact=parsed.event_id,
                source_path="/manifest_digest",
            )
        )
    if parsed.manifest_digest is not None:
        manifest_digest_ref = (
            parsed.manifest_digest_ref
            or parsed.event_manifest_ref
            or event.get("manifest_digest_ref")
            or event.get("event_manifest_ref")
        )
        manifest_digest_status = (
            parsed.manifest_digest_status
            or parsed.event_manifest_digest_status
            or event.get("manifest_digest_status")
            or event.get("event_manifest_digest_status")
        )
        if manifest_digest_ref is None and str(expected_manifest_digest) == parsed.manifest_digest:
            manifest_digest_ref = event_manifest_digest_ref
            manifest_digest_status = policy.get("event_manifest_digest_status")
        if manifest_digest_ref is None:
            extra_blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.STATUS,
                    "lifecycle event manifest digest requires an artifact-bound proof",
                    source_artifact=parsed.event_id,
                    source_path="/manifest_digest_ref",
                )
            )
        else:
            failure_code = _accepted_status_failure_code(
                manifest_digest_status,
                manifest_digest_ref,
                expected_payload={
                    "event_id": parsed.event_id,
                    "event_manifest_digest": parsed.manifest_digest,
                },
                expected_kinds=(
                    "event_manifest_digest",
                    "event-manifest-digest",
                    "event_manifest",
                    "event-manifest",
                    "manifest_digest",
                    "manifest-digest",
                ),
            )
            if failure_code is not None:
                extra_blocks.append(
                    blocking_record(
                        failure_code,
                        Layer.STATUS,
                        "lifecycle event manifest digest proof is not accepted",
                        source_artifact=parsed.event_id,
                        source_path="/manifest_digest_status",
                    )
                )
    signature_result_ref = event.get(
        "signature_verifier_result_ref",
        parsed.payload.get("signature_verifier_result_ref"),
    )
    signature_policy = str(parsed.payload.get("signature_policy", "optional"))
    if signature_policy == "required":
        signature_result_status = event.get(
            "signature_verifier_result_status",
            parsed.payload.get("signature_verifier_result_status"),
        )
        if signature_result_ref is None:
            extra_blocks.append(
                blocking_record(
                    FailureCode.CHECKER_UNKNOWN,
                    Layer.STATUS,
                    "required signature verification requires an artifact-bound proof",
                    source_artifact=parsed.event_id,
                    source_path="/signature_verifier_result_ref",
                )
            )
        else:
            failure_code = _accepted_status_failure_code(
                signature_result_status,
                signature_result_ref,
                expected_payload={
                    "event_id": parsed.event_id,
                    "signature_verifier_result": parsed.signature_verifier_result,
                },
                expected_kinds=(
                    "signature_verifier",
                    "signature-verifier",
                    "signature_validation",
                    "signature-validation",
                ),
            )
            if failure_code is not None:
                extra_blocks.append(
                    blocking_record(
                        failure_code,
                        Layer.STATUS,
                        "signature verifier proof is not accepted for this lifecycle event",
                        source_artifact=parsed.event_id,
                        source_path="/signature_verifier_result_status",
                    )
                )
    event_policy_version = parsed.payload.get("policy_version")
    if event_policy_version is None and policy.get("require_policy_version", False):
        extra_blocks.append(
            blocking_record(
                FailureCode.POLICY_BLOCK,
                Layer.STATUS,
                "lifecycle event lacks required policy_version",
                source_artifact=parsed.event_id,
                source_path="/payload/policy_version",
            )
        )
    dependency_updates = tuple(str(item) for item in parsed.payload.get("dependency_updates", ()))
    dependency_transfer_ref = parsed.payload.get("dependency_transfer_ref")
    if dependency_updates and dependency_transfer_ref is None:
        extra_blocks.append(
            blocking_record(
                FailureCode.CHECKER_UNKNOWN,
                Layer.STATUS,
                "dependency graph update lacks accepted transfer proof",
                source_artifact=parsed.event_id,
                source_path="/payload/dependency_transfer_ref",
            )
        )
    if dependency_transfer_ref is not None:
        failure_code = _accepted_status_failure_code(
            parsed.payload.get("dependency_transfer_status"),
            dependency_transfer_ref,
            expected_payload={
                "event_id": parsed.event_id,
                "dependency_updates": dependency_updates,
            },
            expected_kinds=("dependency_transfer", "dependency-transfer"),
        )
        if failure_code is not None:
            extra_blocks.append(
                blocking_record(
                    failure_code,
                    Layer.STATUS,
                    "dependency graph transfer proof is not accepted",
                    source_artifact=parsed.event_id,
                    source_path="/payload/dependency_transfer_status",
                )
            )
    frame_digest = parsed.payload.get("frame_digest")
    frame_transfer_ref = parsed.payload.get("frame_transfer_ref")
    if (
        frame_digest is not None
        and certificate.frame.get("frame_digest") not in {None, frame_digest}
        and frame_transfer_ref is None
    ):
        extra_blocks.append(
            blocking_record(
                FailureCode.OUT_OF_FRAME,
                Layer.STATUS,
                "frame digest changed without transfer proof",
                source_artifact=parsed.event_id,
                source_path="/payload/frame_transfer_ref",
            )
        )
    if frame_transfer_ref is not None:
        failure_code = _accepted_status_failure_code(
            parsed.payload.get("frame_transfer_status"),
            frame_transfer_ref,
            expected_payload={
                "event_id": parsed.event_id,
                "frame_digest": frame_digest,
            },
            expected_kinds=("frame_transfer", "frame-transfer", "assessment_preservation"),
        )
        if failure_code is not None:
            extra_blocks.append(
                blocking_record(
                    failure_code,
                    Layer.STATUS,
                    "frame transfer proof is not accepted",
                    source_artifact=parsed.event_id,
                    source_path="/payload/frame_transfer_status",
                )
            )
    proof_preservation_refs = tuple(
        str(item) for item in parsed.payload.get("proof_preservation_refs", ())
    )
    if parsed.payload.get("requires_proof_preservation") and not proof_preservation_refs:
        extra_blocks.append(
            blocking_record(
                FailureCode.CHECKER_UNKNOWN,
                Layer.STATUS,
                "lifecycle event lacks proof preservation evidence",
                source_artifact=parsed.event_id,
                source_path="/payload/proof_preservation_refs",
            )
        )
    if proof_preservation_refs:
        failure_code = _accepted_status_failure_code(
            parsed.payload.get("proof_preservation_status"),
            proof_preservation_refs,
            expected_payload={
                "event_id": parsed.event_id,
                "proof_preservation_refs": proof_preservation_refs,
            },
            expected_kinds=("proof_preservation", "proof-preservation"),
        )
        if failure_code is not None:
            extra_blocks.append(
                blocking_record(
                    failure_code,
                    Layer.STATUS,
                    "proof preservation evidence is not accepted",
                    source_artifact=parsed.event_id,
                    source_path="/payload/proof_preservation_status",
                )
            )
    if result.dominant_status.value in {"conflict", "unknown", "out_of_frame"}:
        decision = "recompute"
    elif result.dominant_status.value in {"revoked", "superseded", "expired"}:
        decision = result.dominant_status.value
    elif extra_blocks:
        decision = "recompute"
    else:
        decision = "maintain"
    blocking_set = _lifecycle_blocking_set(parsed.event_id, tuple(extra_blocks))
    decision_event_manifest_digest_ref = (
        event_manifest_digest_ref
        or parsed.manifest_digest_ref
        or parsed.event_manifest_ref
        or event.get("manifest_digest_ref")
        or event.get("event_manifest_ref")
    )
    return LifecycleDecision(
        decision=decision,
        event_id=parsed.event_id,
        dominant_status=result.dominant_status,
        accepted=not blocking_set,
        blocking_set=blocking_set,
        reason_refs=tuple(ref for block in blocking_set for ref in block.reason_refs),
        event_manifest_digest=parsed.manifest_digest,
        event_manifest_digest_ref=str(decision_event_manifest_digest_ref)
        if decision_event_manifest_digest_ref is not None
        else None,
        signature_verifier_result_ref=str(signature_result_ref)
        if signature_result_ref is not None
        else None,
        accepted_event_ids=accepted_event_ids,
        accepted_event_ids_ref=str(accepted_event_ids_ref)
        if accepted_event_ids_ref is not None
        else None,
        trace_class=event_order.trace_class,
        trace_class_ref=str(trace_class_ref) if trace_class_ref is not None else None,
        causal_cut=event_order.causal_cut,
        causal_cut_ref=str(causal_cut_ref) if causal_cut_ref is not None else None,
        log_root=str(event_order.log_root) if event_order.log_root is not None else None,
        log_root_ref=str(log_root_ref) if log_root_ref is not None else None,
        dependency_updates=dependency_updates,
        frame_transfer_ref=str(frame_transfer_ref) if frame_transfer_ref is not None else None,
        proof_preservation_refs=proof_preservation_refs,
    )
