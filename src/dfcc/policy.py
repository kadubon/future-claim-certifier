"""Policy gate evaluation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from dfcc.types import BlockingRecord, FailureCode, GateDecision, Layer, blocking_record


def gate_decision(
    policy: Mapping[str, Any],
    *,
    soundness_grade: int,
    blocking_set: tuple[BlockingRecord, ...],
    proposed_mode: str,
) -> tuple[GateDecision, tuple[BlockingRecord, ...]]:
    blocks = list(blocking_set)
    minimum_grade = int(policy.get("minimum_soundness_grade", 1))
    if soundness_grade < minimum_grade:
        blocks.append(
            blocking_record(
                FailureCode.POLICY_BLOCK,
                Layer.POLICY,
                f"soundness grade {soundness_grade} is below policy minimum {minimum_grade}",
                source_artifact="policy",
                source_path="/minimum_soundness_grade",
            )
        )
    blocked_modes = {str(item) for item in policy.get("blocked_modes", ())}
    if proposed_mode in blocked_modes:
        blocks.append(
            blocking_record(
                FailureCode.POLICY_BLOCK,
                Layer.POLICY,
                f"policy blocks proposed mode: {proposed_mode}",
                source_artifact="policy",
                source_path="/blocked_modes",
            )
        )
    if blocks:
        return GateDecision.BLOCK, tuple(blocks)
    if policy.get("unknown", False):
        return GateDecision.UNKNOWN, tuple(blocks)
    return GateDecision.ALLOW, tuple(blocks)
