"""Wire-level scalar, interval, timestamp, and set reference records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from dfcc.canonical import digest_json
from dfcc.types import (
    FailureCode,
    Layer,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    pass_validation,
    validation_failure,
)


@dataclass(frozen=True, slots=True)
class ScalarRecord:
    decimal_string: str
    unit_ref: str
    dimension_ref: str
    exactness: str = "exact"
    uncertainty_ref: str | None = None

    def decimal(self) -> Decimal:
        try:
            return Decimal(self.decimal_string)
        except InvalidOperation as exc:
            raise ValueError(f"invalid decimal string: {self.decimal_string}") from exc


@dataclass(frozen=True, slots=True)
class IntervalRecord:
    lower: ScalarRecord
    upper: ScalarRecord
    lower_closed: bool = True
    upper_closed: bool = True
    uncertainty_ref: str | None = None
    basis_ref: str | None = None


@dataclass(frozen=True, slots=True)
class TimestampRecord:
    lexical_time: str
    time_basis_ref: str
    time_scale: str = "UTC"
    source: str = "unspecified"
    traceability: str | None = None
    uncertainty_ref: str | None = None
    timestamp_policy_ref: str | None = None

    def datetime(self) -> datetime:
        text = self.lexical_time
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            raise ValueError("timestamp must include an explicit offset")
        return dt.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class SetRef:
    carrier_ref: str
    encoding_kind: str
    constraint_ref: str
    approximation_kind: str
    soundness_ref: str
    digest: str


def scalar_record(
    value: str | int | Decimal,
    unit: str,
    dimension: str,
    uncertainty: str | None = None,
    *,
    exactness: str = "exact",
) -> ScalarRecord:
    decimal_string = format(value, "f") if isinstance(value, Decimal) else str(value)
    record = ScalarRecord(decimal_string, unit, dimension, exactness, uncertainty)
    record.decimal()
    return record


def interval_record(
    lower: ScalarRecord,
    upper: ScalarRecord,
    closure: tuple[bool, bool] = (True, True),
    uncertainty: str | None = None,
    basis: str | None = None,
) -> IntervalRecord:
    if lower.decimal() > upper.decimal():
        raise ValueError("interval lower bound must be <= upper bound")
    return IntervalRecord(lower, upper, closure[0], closure[1], uncertainty, basis)


def timestamp_record(
    lexical_time: str, time_basis: str, policy: str | None = None
) -> TimestampRecord:
    record = TimestampRecord(lexical_time, time_basis, timestamp_policy_ref=policy)
    record.datetime()
    return record


def set_ref(
    carrier: str,
    encoding: str,
    constraint: str,
    approximation: str,
    soundness: str,
) -> SetRef:
    digest = digest_json(
        {
            "carrier_ref": carrier,
            "encoding_kind": encoding,
            "constraint_ref": constraint,
            "approximation_kind": approximation,
            "soundness_ref": soundness,
        }
    )
    return SetRef(carrier, encoding, constraint, approximation, soundness, digest)


def validate_scalar_record(record: ScalarRecord) -> ValidationResult:
    try:
        record.decimal()
    except ValueError as exc:
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.SCHEMA_VALIDATE,
            str(exc),
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
        )
    return pass_validation(ValidationStage.SCHEMA_VALIDATE)


def validate_interval_record(record: IntervalRecord) -> ValidationResult:
    try:
        if record.lower.decimal() > record.upper.decimal():
            raise ValueError("interval lower bound must be <= upper bound")
    except ValueError as exc:
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.SCHEMA_VALIDATE,
            str(exc),
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
        )
    return pass_validation(ValidationStage.SCHEMA_VALIDATE)


def validate_timestamp_record(record: TimestampRecord) -> ValidationResult:
    try:
        record.datetime()
    except ValueError as exc:
        return validation_failure(
            FailureCode.CLOCK_BOUNDARY_UNKNOWN,
            ValidationStage.SCHEMA_VALIDATE,
            str(exc),
            status=ValidationStatus.UNKNOWN,
            layer=Layer.STATUS,
        )
    return pass_validation(ValidationStage.SCHEMA_VALIDATE)


def validate_set_ref(record: SetRef) -> ValidationResult:
    expected = digest_json(
        {
            "carrier_ref": record.carrier_ref,
            "encoding_kind": record.encoding_kind,
            "constraint_ref": record.constraint_ref,
            "approximation_kind": record.approximation_kind,
            "soundness_ref": record.soundness_ref,
        }
    )
    if not all(
        (
            record.carrier_ref,
            record.encoding_kind,
            record.constraint_ref,
            record.approximation_kind,
            record.soundness_ref,
        )
    ):
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.REFERENCE_RESOLVE,
            "SetRef contains an empty reference field",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.INTEROP,
        )
    if expected != record.digest:
        return validation_failure(
            FailureCode.DIGEST_MISMATCH,
            ValidationStage.DIGEST_CHECK,
            "SetRef digest does not match canonical SetRef fields",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
        )
    return pass_validation(ValidationStage.DIGEST_CHECK)
