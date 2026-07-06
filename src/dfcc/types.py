"""Shared DFCC protocol types.

The paper defines most DFCC outputs as typed records rather than bare enums.
This module keeps those records small and serializable so higher-level modules
can preserve blocking reasons instead of collapsing them into a single status.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Layer(StrEnum):
    VALIDATION = "validation"
    INTEROP = "interop"
    ISSUE = "issue"
    REPRESENTED = "represented"
    STATUS = "status"
    OPERATIONAL = "operational"
    POLICY = "policy"


class ValidationStage(StrEnum):
    PARSE = "Parse"
    CANONICALIZE = "Canonicalize"
    SCHEMA_VALIDATE = "SchemaValidate"
    DIGEST_CHECK = "DigestCheck"
    REFERENCE_RESOLVE = "ReferenceResolve"
    PROFILE_RESOLVE = "ProfileResolve"
    REPLAY = "Replay"
    GUARD_EVALUATE = "GuardEvaluate"
    KERNEL_CHECK = "KernelCheck"
    AUTHORITY_EMIT = "AuthorityEmit"


class ValidationStatus(StrEnum):
    PASS = "pass"
    REJECT_INPUT = "reject_input"
    INVALID_ARTIFACT = "invalid_artifact"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class FailureCode(StrEnum):
    SCHEMA_INVALID = "schema_invalid"
    CANONICALIZATION_MISMATCH = "canonicalization_mismatch"
    DIGEST_MISMATCH = "digest_mismatch"
    MISSING_REF = "missing_ref"
    UNSUPPORTED_PROFILE = "unsupported_profile"
    CLOCK_BOUNDARY_UNKNOWN = "clock_boundary_unknown"
    TRACE_CONFLICT = "trace_conflict"
    VALIDITY_UNKNOWN = "validity_unknown"
    VALIDITY_CONFLICT = "validity_conflict"
    PREFIX_UNSOUND = "prefix_unsound"
    EXACT_PREFIX_EMPTY = "exact_prefix_empty"
    COMPLETION_MISSING = "completion_missing"
    ASSOC_EMPTY = "assoc_empty"
    ASSOC_MIXED = "assoc_mixed"
    POLICY_BLOCK = "policy_block"
    OUT_OF_FRAME = "out_of_frame"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"
    ARTIFACT_CONFLICT = "artifact_conflict"
    CHECKER_UNKNOWN = "checker_unknown"


class VerdictCode(StrEnum):
    ASSERT = "assert"
    DENY = "deny"
    INFEASIBLE = "infeasible"
    ABSTAIN = "abstain"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"
    INVALID = "invalid"


class StatusCode(StrEnum):
    ACTIVE = "active"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"
    INVALID = "invalid"
    EXPIRED = "expired"
    OUT_OF_FRAME = "out_of_frame"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"
    NOT_EFFECTIVE = "not_effective"
    BOUNDARY_UNKNOWN = "boundary_unknown"


class OperationalCode(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    INDETERMINATE = "indeterminate"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"
    OUT_OF_FRAME = "out_of_frame"


class Direction(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    INFEASIBLE = "infeasible"
    NEUTRAL = "neutral"
    NONE = "none"


class GateDecision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    UNKNOWN = "unknown"


class GuardStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"
    OUT_OF_FRAME = "out_of_frame"
    EXPIRED = "expired"


class AssociationStatus(StrEnum):
    OUT_OF_FRAME = "out_of_frame"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"
    EMPTY = "empty"
    MIXED = "mixed"
    POSITIVE = "positive"
    NEGATIVE = "negative"
    UNDETERMINED = "undetermined"


class AdjudicationCode(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"
    INDETERMINATE = "indeterminate"
    OUT_OF_FRAME = "out_of_frame"


class AdequacyDirection(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"
    OUT_OF_FRAME = "out_of_frame"


@dataclass(frozen=True, slots=True)
class ReasonRef:
    reason_id: str
    failure_code: FailureCode
    layer: Layer
    source_artifact: str
    source_path: str
    message: str
    digest: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "reason_id": self.reason_id,
            "failure_code": self.failure_code.value,
            "layer": self.layer.value,
            "source_artifact": self.source_artifact,
            "source_path": self.source_path,
            "message": self.message,
            "digest": self.digest,
        }


@dataclass(frozen=True, slots=True)
class FailureRecord:
    failure_id: str
    code: FailureCode
    layer: Layer
    stage: ValidationStage
    severity: str
    blocking: bool
    remediation: str | None = None
    reason_refs: tuple[ReasonRef, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "failure_id": self.failure_id,
            "code": self.code.value,
            "layer": self.layer.value,
            "stage": self.stage.value,
            "severity": self.severity,
            "blocking": self.blocking,
            "remediation": self.remediation,
            "reason_refs": [ref.reason_id for ref in self.reason_refs],
            "reason_ref_records": [ref.to_json() for ref in self.reason_refs],
        }


@dataclass(frozen=True, slots=True)
class BlockingRecord:
    block_id: str
    failure_code: FailureCode
    layer: Layer
    severity: str
    reason_refs: tuple[ReasonRef, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "block_id": self.block_id,
            "failure_code": self.failure_code.value,
            "layer": self.layer.value,
            "severity": self.severity,
            "reason_refs": [ref.reason_id for ref in self.reason_refs],
            "reason_ref_records": [ref.to_json() for ref in self.reason_refs],
        }


@dataclass(frozen=True, slots=True)
class ValidationResult:
    stage: ValidationStage
    status: ValidationStatus
    failure_records: tuple[FailureRecord, ...] = ()
    artifact_refs: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status is ValidationStatus.PASS

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
            "stage": self.stage.value,
            "status": self.status.value,
            "failure_records": [record.to_json() for record in self.failure_records],
            "artifact_refs": list(self.artifact_refs),
            "reason_refs": [ref.reason_id for ref in reason_refs],
            "reason_ref_records": [ref.to_json() for ref in reason_refs],
        }


@dataclass(frozen=True, slots=True)
class StatusCoordinate:
    coordinate: str
    value: str
    evidence_refs: tuple[str, ...] = ()
    schema_profile: str | None = None
    digest: str | None = None
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class GuardRecord:
    guard_name: str
    status: GuardStatus
    evidence_refs: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class AuthorityOutcome:
    layer: Layer
    code: str
    direction: Direction
    blocking_set: tuple[BlockingRecord, ...] = ()
    gate_decision: GateDecision = GateDecision.UNKNOWN
    profile_ref: str | None = None
    outcome_schema_ref: str | None = None
    issued_at_status_time: str | None = None
    reason_refs: tuple[ReasonRef, ...] = ()


def reason(
    failure_code: FailureCode,
    layer: Layer,
    message: str,
    *,
    source_artifact: str = "inline",
    source_path: str = "",
    reason_id: str | None = None,
    digest: str | None = None,
) -> ReasonRef:
    """Create a deterministic-enough reason reference for local checks."""

    if reason_id is None:
        material = "\x1f".join(
            (layer.value, failure_code.value, source_artifact, source_path, message)
        )
        suffix = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
        rid = f"{layer.value}:{failure_code.value}:{suffix}"
    else:
        rid = reason_id
    return ReasonRef(
        reason_id=rid,
        failure_code=failure_code,
        layer=layer,
        source_artifact=source_artifact,
        source_path=source_path,
        message=message,
        digest=digest,
    )


def blocking_record(
    failure_code: FailureCode,
    layer: Layer,
    message: str,
    *,
    severity: str = "error",
    block_id: str | None = None,
    source_artifact: str = "inline",
    source_path: str = "",
) -> BlockingRecord:
    ref = reason(
        failure_code,
        layer,
        message,
        source_artifact=source_artifact,
        source_path=source_path,
    )
    return BlockingRecord(
        block_id=block_id or ref.reason_id,
        failure_code=failure_code,
        layer=layer,
        severity=severity,
        reason_refs=(ref,),
    )


def validation_failure(
    code: FailureCode,
    stage: ValidationStage,
    message: str,
    *,
    status: ValidationStatus,
    layer: Layer = Layer.VALIDATION,
    source_artifact: str = "input",
    source_path: str = "",
) -> ValidationResult:
    ref = reason(
        code,
        layer,
        message,
        source_artifact=source_artifact,
        source_path=source_path,
    )
    failure = FailureRecord(
        failure_id=ref.reason_id,
        code=code,
        layer=layer,
        stage=stage,
        severity="error",
        blocking=True,
        reason_refs=(ref,),
    )
    return ValidationResult(
        stage=stage, status=status, failure_records=(failure,), reason_refs=(ref,)
    )


def pass_validation(stage: ValidationStage = ValidationStage.AUTHORITY_EMIT) -> ValidationResult:
    return ValidationResult(stage=stage, status=ValidationStatus.PASS)


ALLOWED_OUTCOME_DIRECTIONS: dict[Layer, dict[str, set[Direction]]] = {
    Layer.ISSUE: {
        VerdictCode.ASSERT.value: {Direction.POSITIVE},
        VerdictCode.DENY.value: {Direction.NEGATIVE},
        VerdictCode.INFEASIBLE.value: {Direction.INFEASIBLE},
        VerdictCode.ABSTAIN.value: {Direction.NEUTRAL},
        VerdictCode.UNKNOWN.value: {Direction.NONE},
        VerdictCode.CONFLICT.value: {Direction.NONE},
        VerdictCode.INVALID.value: {Direction.NONE},
    },
    Layer.REPRESENTED: {
        VerdictCode.ASSERT.value: {Direction.POSITIVE},
        VerdictCode.DENY.value: {Direction.NEGATIVE},
        VerdictCode.INFEASIBLE.value: {Direction.INFEASIBLE},
        VerdictCode.ABSTAIN.value: {Direction.NEUTRAL},
        VerdictCode.UNKNOWN.value: {Direction.NONE},
        VerdictCode.CONFLICT.value: {Direction.NONE},
        VerdictCode.INVALID.value: {Direction.NONE},
    },
    Layer.OPERATIONAL: {
        OperationalCode.ACCEPT.value: {Direction.POSITIVE},
        OperationalCode.REJECT.value: {Direction.NEGATIVE},
        OperationalCode.INDETERMINATE.value: {Direction.NEUTRAL},
        OperationalCode.UNKNOWN.value: {Direction.NONE},
        OperationalCode.CONFLICT.value: {Direction.NONE},
        OperationalCode.OUT_OF_FRAME.value: {Direction.NONE},
    },
    Layer.STATUS: {
        StatusCode.ACTIVE.value: {Direction.NONE},
        StatusCode.UNKNOWN.value: {Direction.NONE},
        StatusCode.CONFLICT.value: {Direction.NONE},
        StatusCode.OUT_OF_FRAME.value: {Direction.NONE},
        StatusCode.EXPIRED.value: {Direction.NONE},
        StatusCode.REVOKED.value: {Direction.NONE},
        StatusCode.SUPERSEDED.value: {Direction.NONE},
        StatusCode.INVALID.value: {Direction.NONE},
    },
    Layer.POLICY: {
        GateDecision.ALLOW.value: {Direction.NONE},
        GateDecision.BLOCK.value: {Direction.NONE},
        GateDecision.UNKNOWN.value: {Direction.NONE},
    },
}


def validate_authority_outcome(outcome: AuthorityOutcome) -> None:
    allowed = ALLOWED_OUTCOME_DIRECTIONS.get(outcome.layer, {})
    allowed_directions = allowed.get(outcome.code)
    if allowed_directions is None or outcome.direction not in allowed_directions:
        msg = (
            f"invalid authority outcome combination: layer={outcome.layer.value}, "
            f"code={outcome.code}, direction={outcome.direction.value}"
        )
        raise ValueError(msg)
    allow_codes = {
        GateDecision.ALLOW.value,
        OperationalCode.ACCEPT.value,
        VerdictCode.ASSERT.value,
        StatusCode.ACTIVE.value,
    }
    decisive_codes = {
        *allow_codes,
        OperationalCode.REJECT.value,
        VerdictCode.DENY.value,
        VerdictCode.INFEASIBLE.value,
    }
    if outcome.code in allow_codes and outcome.blocking_set:
        msg = f"allow-like authority outcome carries blocking records: code={outcome.code}"
        raise ValueError(msg)
    reason_refs = tuple(outcome.reason_refs) + tuple(
        ref for block in outcome.blocking_set for ref in block.reason_refs
    )
    if outcome.code not in allow_codes and not reason_refs:
        msg = f"non-allow authority outcome lacks reason refs: code={outcome.code}"
        raise ValueError(msg)
    if outcome.code not in decisive_codes and not outcome.blocking_set:
        msg = f"non-decisive authority outcome lacks blocking records: code={outcome.code}"
        raise ValueError(msg)


JsonObject = dict[str, Any]
JsonValue = None | bool | int | float | str | list[Any] | dict[str, Any]
