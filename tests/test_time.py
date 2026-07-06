from __future__ import annotations

from dfcc.time import HorizonAnchor, TimeBasis, parse_rfc3339, status_clock
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
