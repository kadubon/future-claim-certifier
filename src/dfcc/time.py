"""Time basis, horizon anchors, and DFCC status clock."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from itertools import pairwise
from typing import Any

from dfcc.types import StatusCode


class TimeBasisError(ValueError):
    """Raised when a time basis or anchor is malformed."""


_MICROSECONDS_PER_SECOND = Decimal(1_000_000)
_RFC3339_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<hour>[01]\d|2[0-3]):"
    r"(?P<minute>[0-5]\d):"
    r"(?P<second>[0-5]\d)"
    r"(?P<fraction>\.\d{1,6})?"
    r"(?P<offset>Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)


def _decimal_seconds(value: Decimal | int | str, *, field_name: str) -> Decimal:
    if isinstance(value, (bool, float)):
        raise TimeBasisError(f"{field_name} must be an exact decimal string or integer")
    try:
        seconds = value if isinstance(value, Decimal) else Decimal(str(value))
    except Exception as exc:
        raise TimeBasisError(f"{field_name} must be a finite decimal") from exc
    if not seconds.is_finite():
        raise TimeBasisError(f"{field_name} must be finite")
    return seconds


def _duration_from_seconds(value: Decimal | int | str, *, field_name: str) -> timedelta:
    seconds = _decimal_seconds(value, field_name=field_name)
    micros = seconds * _MICROSECONDS_PER_SECOND
    integral_micros = micros.to_integral_value()
    if micros != integral_micros:
        raise TimeBasisError(f"{field_name} is finer than microsecond resolution")
    return timedelta(microseconds=int(integral_micros))


def parse_rfc3339(value: str) -> datetime:
    text = value.strip()
    if not _RFC3339_RE.fullmatch(text):
        raise TimeBasisError(
            "timestamp must be RFC3339 with uppercase Z or explicit offset and "
            "at most microsecond precision"
        )
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise TimeBasisError("timestamp must include an explicit timezone offset")
    return dt.astimezone(UTC)


def format_rfc3339(dt: datetime) -> str:
    value = dt.astimezone(UTC)
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class TimeBasis:
    clock_id: str
    time_scale: str = "UTC"
    uncertainty_seconds: Decimal | int | str = Decimal("0")
    source: str = "unspecified"
    traceability: str | None = None
    timestamp_policy: str | None = None

    def uncertainty_interval(self, status_time: datetime) -> tuple[datetime, datetime]:
        uncertainty = _decimal_seconds(self.uncertainty_seconds, field_name="uncertainty_seconds")
        if uncertainty < 0:
            raise TimeBasisError("uncertainty_seconds must be nonnegative")
        delta = _duration_from_seconds(uncertainty, field_name="uncertainty_seconds")
        center = status_time.astimezone(UTC)
        return center - delta, center + delta


@dataclass(frozen=True, slots=True)
class HorizonAnchor:
    issue_time: datetime
    horizon: int
    anchors: tuple[datetime, ...]

    @classmethod
    def from_times(cls, anchors: tuple[datetime, ...]) -> HorizonAnchor:
        if not anchors:
            raise TimeBasisError("anchor list must be nonempty")
        normalized = tuple(anchor.astimezone(UTC) for anchor in anchors)
        for prev, current in pairwise(normalized):
            if not prev < current:
                raise TimeBasisError("horizon anchor must be strictly increasing")
        return cls(issue_time=normalized[0], horizon=len(normalized) - 1, anchors=normalized)

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> HorizonAnchor:
        if "anchors" in source:
            anchors = tuple(parse_rfc3339(str(item)) for item in source["anchors"])
            return cls.from_times(anchors)
        issue_time = parse_rfc3339(str(source["issue_time"]))
        horizon = int(source["horizon"])
        if horizon < 0:
            raise TimeBasisError("horizon must be nonnegative")
        step = _duration_from_seconds(source["step_seconds"], field_name="step_seconds")
        if step <= timedelta(0):
            raise TimeBasisError("step_seconds must be positive")
        anchors = tuple(issue_time + step * index for index in range(horizon + 1))
        return cls.from_times(anchors)

    def end(self) -> datetime:
        return self.anchors[-1]

    def to_json(self) -> dict[str, Any]:
        return {
            "issue_time": format_rfc3339(self.issue_time),
            "horizon": self.horizon,
            "anchors": [format_rfc3339(anchor) for anchor in self.anchors],
        }


@dataclass(frozen=True, slots=True)
class ClockResult:
    status: StatusCode
    index: int | None = None
    margin_microseconds: int | None = None


def status_clock(
    status_time: datetime, time_basis: TimeBasis, anchor: HorizonAnchor
) -> ClockResult:
    lower, upper = time_basis.uncertainty_interval(status_time)
    if upper < anchor.anchors[0]:
        return ClockResult(StatusCode.NOT_EFFECTIVE)
    if lower > anchor.anchors[-1]:
        return ClockResult(StatusCode.EXPIRED)

    indices: set[int] = set()
    for point in (lower, upper):
        completed = 0
        for idx, anchor_time in enumerate(anchor.anchors):
            if anchor_time <= point:
                completed = idx
            else:
                break
        indices.add(completed)
    if len(indices) != 1:
        return ClockResult(StatusCode.BOUNDARY_UNKNOWN)

    index = indices.pop()
    distances = [
        abs(int((status_time.astimezone(UTC) - item).total_seconds() * 1_000_000))
        for item in anchor.anchors
    ]
    margin = min(distances) if distances else None
    return ClockResult(StatusCode.ACTIVE, index=index, margin_microseconds=margin)


def parse_time_basis(source: Mapping[str, Any]) -> TimeBasis:
    return TimeBasis(
        clock_id=str(source["clock_id"]),
        time_scale=str(source.get("time_scale", "UTC")),
        uncertainty_seconds=Decimal(str(source.get("uncertainty_seconds", "0"))),
        source=str(source.get("source", "unspecified")),
        traceability=source.get("traceability"),
        timestamp_policy=source.get("timestamp_policy"),
    )
