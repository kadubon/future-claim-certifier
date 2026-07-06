from __future__ import annotations

import pytest

from dfcc.time import HorizonAnchor, TimeBasis, TimeBasisError, parse_rfc3339, status_clock
from dfcc.types import StatusCode


def test_status_clock_inside() -> None:
    anchor = HorizonAnchor.from_json(
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 2, "step_seconds": 60}
    )
    result = status_clock(parse_rfc3339("2026-01-01T00:01:30Z"), TimeBasis("utc"), anchor)
    assert result.status is StatusCode.ACTIVE
    assert result.index == 1


def test_status_clock_boundary_unknown() -> None:
    anchor = HorizonAnchor.from_json(
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 2, "step_seconds": 60}
    )
    result = status_clock(
        parse_rfc3339("2026-01-01T00:01:00Z"),
        TimeBasis("utc", uncertainty_seconds=1),
        anchor,
    )
    assert result.status is StatusCode.BOUNDARY_UNKNOWN


def test_status_clock_expired() -> None:
    anchor = HorizonAnchor.from_json(
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60}
    )
    result = status_clock(parse_rfc3339("2026-01-01T00:02:00Z"), TimeBasis("utc"), anchor)
    assert result.status is StatusCode.EXPIRED


def test_status_clock_not_effective_and_anchor_serialization() -> None:
    anchor = HorizonAnchor.from_json(
        {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 60}
    )
    result = status_clock(parse_rfc3339("2025-12-31T23:59:00Z"), TimeBasis("utc"), anchor)
    assert result.status is StatusCode.NOT_EFFECTIVE
    assert anchor.end() == parse_rfc3339("2026-01-01T00:01:00Z")
    assert anchor.to_json()["anchors"] == [
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:01:00Z",
    ]


def test_time_basis_rejects_float_precision_inputs() -> None:
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_json(
            {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": 0.1}
        )
    with pytest.raises(TimeBasisError):
        TimeBasis("utc", uncertainty_seconds=0.1).uncertainty_interval(
            parse_rfc3339("2026-01-01T00:00:00Z")
        )


def test_time_basis_rejects_sub_microsecond_decimal() -> None:
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_json(
            {
                "issue_time": "2026-01-01T00:00:00Z",
                "horizon": 1,
                "step_seconds": "0.0000001",
            }
        )


def test_time_basis_rejects_malformed_exact_inputs() -> None:
    with pytest.raises(TimeBasisError):
        parse_rfc3339("2026-01-01T00:00:00")
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_json(
            {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": True}
        )
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_json(
            {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": "NaN"}
        )
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_json(
            {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": "abc"}
        )
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_json(
            {"issue_time": "2026-01-01T00:00:00Z", "horizon": 1, "step_seconds": "0"}
        )
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_json(
            {"issue_time": "2026-01-01T00:00:00Z", "horizon": -1, "step_seconds": "1"}
        )
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_times(())
    with pytest.raises(TimeBasisError):
        HorizonAnchor.from_times(
            (
                parse_rfc3339("2026-01-01T00:00:00Z"),
                parse_rfc3339("2026-01-01T00:00:00Z"),
            )
        )
    with pytest.raises(TimeBasisError):
        TimeBasis("utc", uncertainty_seconds="-1").uncertainty_interval(
            parse_rfc3339("2026-01-01T00:00:00Z")
        )
