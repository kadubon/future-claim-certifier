from __future__ import annotations

from dfcc.authority import check_authority
from dfcc.certificate import certify_claim
from dfcc.models import IssueCertificate, StatusAuthorityView
from dfcc.types import Layer, OperationalCode, StatusCode, ValidationResult, VerdictCode


def claim() -> dict[str, object]:
    return {
        "claim_id": "safe-temp",
        "horizon": 2,
        "formula": {
            "op": "G",
            "a": 0,
            "b": 2,
            "child": {
                "op": "atom",
                "name": "field_cmp",
                "args": {"field": "temp", "op": "lte", "value": "80"},
            },
        },
    }


def bundle() -> dict[str, object]:
    return {
        "bundle_id": "finite-demo",
        "state_space": [{"temp": "70"}, {"temp": "75"}],
        "initial_states": [{"temp": "70"}],
        "transitions": [
            {"from": {"temp": "70"}, "to": {"temp": "75"}},
            {"from": {"temp": "75"}, "to": {"temp": "75"}},
        ],
    }


def anchor() -> dict[str, object]:
    return {"issue_time": "2026-01-01T00:00:00Z", "horizon": 2, "step_seconds": 60}


def time_basis() -> dict[str, object]:
    return {"clock_id": "utc-demo", "uncertainty_seconds": "0"}


def issue() -> IssueCertificate:
    result = certify_claim(claim(), bundle(), anchor(), time_basis())
    assert isinstance(result, IssueCertificate)
    return result


def test_certify_asserts_finite_safe_claim() -> None:
    cert = issue()
    assert cert.kernel_verdict_at_issue is VerdictCode.ASSERT


def test_check_authority_represented_assertion() -> None:
    cert = issue()
    result = check_authority(
        cert,
        {"mode": "assertion", "claim": "safe-temp", "horizon": 2, "anchor": "anchor:issue"},
        {"status_time": "2026-01-01T00:00:00Z"},
    )
    assert isinstance(result, StatusAuthorityView)
    assert result.authority_outcome.layer is Layer.REPRESENTED
    assert result.authority_outcome.code == "assert"


def test_check_authority_expired_blocks() -> None:
    cert = issue()
    result = check_authority(
        cert,
        {"mode": "assertion", "claim": "safe-temp", "horizon": 2, "anchor": "anchor:issue"},
        {"status_time": "2026-01-01T00:03:00Z"},
    )
    assert isinstance(result, StatusAuthorityView)
    assert result.dominant_status is StatusCode.EXPIRED


def test_operational_missing_completion_does_not_accept() -> None:
    cert = issue()
    result = check_authority(
        cert,
        {"mode": "operational", "claim": "safe-temp", "horizon": 2, "anchor": "anchor:issue"},
        {"status_time": "2026-01-01T00:00:00Z"},
    )
    assert isinstance(result, StatusAuthorityView)
    assert result.authority_outcome.code == OperationalCode.UNKNOWN.value


def test_policy_block_returns_policy_layer() -> None:
    cert = issue()
    result = check_authority(
        cert,
        {"mode": "assertion", "claim": "safe-temp", "horizon": 2, "anchor": "anchor:issue"},
        {"status_time": "2026-01-01T00:00:00Z"},
        policy={"blocked_modes": ["assertion"]},
    )
    assert not isinstance(result, ValidationResult)
    assert result.authority_outcome.layer is Layer.POLICY
    assert result.authority_outcome.code == "block"
