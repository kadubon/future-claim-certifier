"""Required guard-set evaluation."""

from __future__ import annotations

from dataclasses import dataclass

from dfcc.types import FailureCode, GuardRecord, GuardStatus, Layer, ReasonRef, reason

BASE_REQUIRED_GUARDS: tuple[str, ...] = (
    "ProfileResolved",
    "FieldPresence",
    "ReferenceResolved",
    "SetRefSound",
    "ContextWellFormed",
    "ArtifactConsistent",
    "ExactPrefixEnclosure",
    "status_active",
    "clock_inside",
    "validity_pass",
    "checker_obligations",
)


@dataclass(frozen=True, slots=True)
class RequiredGuardSet:
    profile: str
    use: str
    guards: tuple[str, ...] = BASE_REQUIRED_GUARDS


def required_guard_set(profile: str, use: str) -> RequiredGuardSet:
    guards = BASE_REQUIRED_GUARDS
    if use in {"operational", "frame-relative assessment", "control_gating"}:
        guards = (
            *guards,
            "completion_admission",
            "fiber_association",
            "prefix_adjudication",
            "usage_adjudication",
            "target_adjudication",
            "adequacy",
            "agreement",
            "policy_gate",
        )
    return RequiredGuardSet(profile=profile, use=use, guards=guards)


def guard_record(
    name: str,
    passed: bool,
    *,
    failure_code: FailureCode = FailureCode.CHECKER_UNKNOWN,
    layer: Layer = Layer.VALIDATION,
    message: str | None = None,
    evidence_refs: tuple[str, ...] = (),
    reason_refs: tuple[ReasonRef, ...] = (),
) -> GuardRecord:
    if passed:
        return GuardRecord(name, GuardStatus.PASS, evidence_refs=evidence_refs)
    refs = reason_refs or (
        reason(failure_code, layer, message or f"guard {name} did not pass", source_path=name),
    )
    return GuardRecord(name, GuardStatus.FAIL, evidence_refs=evidence_refs, reason_refs=refs)


def guard_pass(records: tuple[GuardRecord, ...]) -> bool:
    return all(record.status is GuardStatus.PASS for record in records)


def required_missing_records(
    required: RequiredGuardSet,
    records: tuple[GuardRecord, ...],
) -> tuple[GuardRecord, ...]:
    present = {record.guard_name for record in records}
    return tuple(
        guard_record(
            name,
            False,
            failure_code=FailureCode.CHECKER_UNKNOWN,
            message=f"required guard record is missing: {name}",
        )
        for name in required.guards
        if name not in present
    )
