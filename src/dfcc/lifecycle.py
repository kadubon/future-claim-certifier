"""Lifecycle events and status folding."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from dfcc.canonical import digest_json
from dfcc.time import format_rfc3339, parse_rfc3339
from dfcc.types import (
    BlockingRecord,
    FailureCode,
    Layer,
    ReasonRef,
    StatusCode,
    StatusCoordinate,
    blocking_record,
)

STATUS_PRIORITY: dict[StatusCode, int] = {
    StatusCode.ACTIVE: 0,
    StatusCode.UNKNOWN: 1,
    StatusCode.OUT_OF_FRAME: 2,
    StatusCode.EXPIRED: 3,
    StatusCode.SUPERSEDED: 4,
    StatusCode.REVOKED: 5,
    StatusCode.CONFLICT: 6,
    StatusCode.INVALID: 7,
}


class SignatureVerifier(Protocol):
    def verify(self, event: LifecycleEvent) -> str: ...


class UnknownSignatureVerifier:
    def verify(self, event: LifecycleEvent) -> str:
        del event
        return "unknown"


EVENT_TO_STATUS: dict[str, tuple[StatusCode, FailureCode | None]] = {
    "mark-unknown": (StatusCode.UNKNOWN, FailureCode.VALIDITY_UNKNOWN),
    "mark-conflict": (StatusCode.CONFLICT, FailureCode.TRACE_CONFLICT),
    "mark-out-of-frame": (StatusCode.OUT_OF_FRAME, FailureCode.OUT_OF_FRAME),
    "trigger-block": (StatusCode.UNKNOWN, FailureCode.POLICY_BLOCK),
    "supersede": (StatusCode.SUPERSEDED, FailureCode.SUPERSEDED),
    "expire": (StatusCode.EXPIRED, FailureCode.EXPIRED),
    "revoke": (StatusCode.REVOKED, FailureCode.REVOKED),
    "conflict": (StatusCode.CONFLICT, FailureCode.TRACE_CONFLICT),
}


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    event_id: str
    certificate_id: str
    time: str
    logical_clock: int
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    actor: str | None = None
    inputs: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()
    signature: str | None = None
    manifest_digest: str | None = None
    manifest_digest_ref: str | None = None
    event_manifest_ref: str | None = None
    signature_verifier_result: str | None = None
    signature_verifier_result_ref: str | None = None
    signature_verifier_result_status: dict[str, Any] | None = None
    manifest_digest_status: dict[str, Any] | None = None
    event_manifest_digest_status: dict[str, Any] | None = None
    previous_event_commitment: str | None = None
    confluence_proof_ref: str | None = None
    log_root_ref: str | None = None
    causal_cut_ref: str | None = None
    trace_class_ref: str | None = None
    ancestry: tuple[str, ...] = ()

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> LifecycleEvent:
        return cls(
            event_id=str(source["event_id"]),
            certificate_id=str(source["certificate_id"]),
            time=format_rfc3339(parse_rfc3339(str(source["time"]))),
            logical_clock=int(source["logical_clock"]),
            kind=str(source["kind"]),
            payload=dict(source.get("payload", {})),
            actor=source.get("actor"),
            inputs=tuple(str(item) for item in source.get("inputs", ())),
            hashes=tuple(str(item) for item in source.get("hashes", ())),
            signature=source.get("signature"),
            manifest_digest=source.get("manifest_digest"),
            manifest_digest_ref=source.get("manifest_digest_ref"),
            event_manifest_ref=source.get("event_manifest_ref"),
            signature_verifier_result=source.get("signature_verifier_result"),
            signature_verifier_result_ref=source.get("signature_verifier_result_ref"),
            signature_verifier_result_status=dict(source["signature_verifier_result_status"])
            if isinstance(source.get("signature_verifier_result_status"), Mapping)
            else None,
            manifest_digest_status=dict(source["manifest_digest_status"])
            if isinstance(source.get("manifest_digest_status"), Mapping)
            else None,
            event_manifest_digest_status=dict(source["event_manifest_digest_status"])
            if isinstance(source.get("event_manifest_digest_status"), Mapping)
            else None,
            previous_event_commitment=source.get("previous_event_commitment"),
            confluence_proof_ref=source.get("confluence_proof_ref"),
            log_root_ref=source.get("log_root_ref"),
            causal_cut_ref=source.get("causal_cut_ref"),
            trace_class_ref=source.get("trace_class_ref"),
            ancestry=tuple(str(item) for item in source.get("ancestry", ())),
        )


@dataclass(frozen=True, slots=True)
class EventOrder:
    accepted_event_ids: tuple[str, ...] = ()
    confluence_proof: Any | None = None
    conflict_policy: str = "conflict-on-disagreement"
    log_root: str | None = None
    trace_class: tuple[str, ...] = ()
    causal_cut: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FoldContext:
    policy_version: str
    dependency_snapshot: dict[str, str] = field(default_factory=dict)
    frame_digest: str | None = None
    trace_class: tuple[str, ...] = ()
    confluence_proof: Any | None = None


@dataclass(frozen=True, slots=True)
class FoldResult:
    coordinates: tuple[StatusCoordinate, ...]
    blocking_set: tuple[BlockingRecord, ...]
    dominant_status: StatusCode
    status_reason: str | None = None


@dataclass(frozen=True, slots=True)
class LifecycleDecision:
    decision: str
    event_id: str
    dominant_status: StatusCode
    accepted: bool
    blocking_set: tuple[BlockingRecord, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()
    event_manifest_digest: str | None = None
    event_manifest_digest_ref: str | None = None
    signature_verifier_result_ref: str | None = None
    accepted_event_ids: tuple[str, ...] = ()
    accepted_event_ids_ref: str | None = None
    trace_class: tuple[str, ...] = ()
    trace_class_ref: str | None = None
    causal_cut: tuple[str, ...] = ()
    causal_cut_ref: str | None = None
    log_root: str | None = None
    log_root_ref: str | None = None
    dependency_updates: tuple[str, ...] = ()
    frame_transfer_ref: str | None = None
    proof_preservation_refs: tuple[str, ...] = ()

    def __str__(self) -> str:
        return self.decision

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.decision == other
        if not isinstance(other, LifecycleDecision):
            return False
        return (
            self.decision,
            self.event_id,
            self.dominant_status,
            self.accepted,
            self.blocking_set,
            self.reason_refs,
            self.event_manifest_digest,
            self.event_manifest_digest_ref,
            self.signature_verifier_result_ref,
            self.accepted_event_ids,
            self.accepted_event_ids_ref,
            self.trace_class,
            self.trace_class_ref,
            self.causal_cut,
            self.causal_cut_ref,
            self.log_root,
            self.log_root_ref,
            self.dependency_updates,
            self.frame_transfer_ref,
            self.proof_preservation_refs,
        ) == (
            other.decision,
            other.event_id,
            other.dominant_status,
            other.accepted,
            other.blocking_set,
            other.reason_refs,
            other.event_manifest_digest,
            other.event_manifest_digest_ref,
            other.signature_verifier_result_ref,
            other.accepted_event_ids,
            other.accepted_event_ids_ref,
            other.trace_class,
            other.trace_class_ref,
            other.causal_cut,
            other.causal_cut_ref,
            other.log_root,
            other.log_root_ref,
            other.dependency_updates,
            other.frame_transfer_ref,
            other.proof_preservation_refs,
        )

    def to_json(self) -> dict[str, Any]:
        blocking_records = [
            {
                "block_id": block.block_id,
                "failure_code": block.failure_code.value,
                "layer": block.layer.value,
                "severity": block.severity,
                "reason_ref_records": [
                    {
                        "reason_id": ref.reason_id,
                        "failure_code": ref.failure_code.value,
                        "layer": ref.layer.value,
                        "source_artifact": ref.source_artifact,
                        "source_path": ref.source_path,
                        "message": ref.message,
                        "digest": ref.digest,
                    }
                    for ref in block.reason_refs
                ],
            }
            for block in self.blocking_set
        ]
        reason_ref_records = [
            {
                "reason_id": ref.reason_id,
                "failure_code": ref.failure_code.value,
                "layer": ref.layer.value,
                "source_artifact": ref.source_artifact,
                "source_path": ref.source_path,
                "message": ref.message,
                "digest": ref.digest,
            }
            for ref in self.reason_refs
        ]
        return {
            "decision": self.decision,
            "event_id": self.event_id,
            "dominant_status": self.dominant_status.value,
            "accepted": self.accepted,
            "blocking_set": [block.block_id for block in self.blocking_set],
            "reason_refs": [ref.reason_id for ref in self.reason_refs],
            "blocking_records": blocking_records,
            "reason_ref_records": reason_ref_records,
            "event_manifest_digest": self.event_manifest_digest,
            "event_manifest_digest_ref": self.event_manifest_digest_ref,
            "signature_verifier_result_ref": self.signature_verifier_result_ref,
            "accepted_event_ids": list(self.accepted_event_ids),
            "accepted_event_ids_ref": self.accepted_event_ids_ref,
            "trace_class": list(self.trace_class),
            "trace_class_ref": self.trace_class_ref,
            "causal_cut": list(self.causal_cut),
            "causal_cut_ref": self.causal_cut_ref,
            "log_root": self.log_root,
            "log_root_ref": self.log_root_ref,
            "dependency_updates": list(self.dependency_updates),
            "frame_transfer_ref": self.frame_transfer_ref,
            "proof_preservation_refs": list(self.proof_preservation_refs),
        }


def event_commitment(event: LifecycleEvent) -> str:
    payload = {
        key: value
        for key, value in event.payload.items()
        if key not in {"event_hash", "previous_hash", "signature_policy"}
    }
    return digest_json(
        {
            "event_id": event.event_id,
            "certificate_id": event.certificate_id,
            "time": event.time,
            "logical_clock": event.logical_clock,
            "kind": event.kind,
            "payload": payload,
            "actor": event.actor,
            "inputs": list(event.inputs),
            "ancestry": list(event.ancestry),
        }
    )


def dominant_status(statuses: Iterable[StatusCode]) -> StatusCode:
    return max(statuses, key=lambda item: STATUS_PRIORITY.get(item, 0), default=StatusCode.ACTIVE)


CONFLUENCE_PROOF_KINDS = (
    "confluence",
    "status_confluence",
    "status-confluence",
    "trace_confluence",
    "trace-confluence",
)


def accepted_proof_evidence(value: Any, *, expected_kinds: tuple[str, ...] = ()) -> bool:
    def _purpose_bound(source: Any) -> bool:
        if not expected_kinds:
            return True
        kind = None
        if isinstance(source, Mapping):
            kind = next(
                (
                    source.get(key)
                    for key in ("proof_kind", "checker_kind", "kind", "evidence_kind")
                    if source.get(key) is not None
                ),
                None,
            )
        else:
            kind = next(
                (
                    getattr(source, key, None)
                    for key in ("proof_kind", "checker_kind", "kind", "evidence_kind")
                    if getattr(source, key, None) is not None
                ),
                None,
            )
        return str(kind) in set(expected_kinds)

    if value is None or isinstance(value, str):
        return False
    if hasattr(value, "proof_status"):
        status = value.proof_status
        bound = bool(
            getattr(value, "artifact_ref", None)
            or getattr(value, "artifact_digest", None)
            or getattr(value, "digest", None)
            or getattr(value, "reference_digest", None)
        )
        return str(status) in {"pass", "accepted"} and bound and _purpose_bound(value)
    if not isinstance(value, Mapping):
        return False
    bound = False
    for key in ("artifact_ref", "artifact_digest", "digest", "reference_digest"):
        item = value.get(key)
        if isinstance(item, str) and item:
            bound = True
    source_artifact = value.get("source_artifact")
    source_path = value.get("source_path")
    if (
        isinstance(source_artifact, str)
        and source_artifact.startswith("artifact:")
        and isinstance(source_path, str)
        and source_path.startswith("/")
    ):
        bound = True
    for key in ("proof_status", "checker_status", "status", "result", "checker_result"):
        status = value.get(key)
        if status is not None:
            return str(status) in {"pass", "accepted"} and bound and _purpose_bound(value)
    return False


def _proof_payload(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        payload = value.get("payload")
        return payload if isinstance(payload, Mapping) else value
    payload = getattr(value, "payload", None)
    return payload if isinstance(payload, Mapping) else {}


def _payload_string_set(payload: Mapping[str, Any], *keys: str) -> set[str]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str):
            return {value}
        if isinstance(value, tuple | list | set):
            return {str(item) for item in value}
    return set()


def confluence_proof_covers(value: Any, event_ids: Iterable[str]) -> bool:
    """Return true only when accepted confluence evidence covers the given events."""

    required = {str(event_id) for event_id in event_ids if str(event_id)}
    if not required or not accepted_proof_evidence(value, expected_kinds=CONFLUENCE_PROOF_KINDS):
        return False
    payload = _proof_payload(value)
    covered = _payload_string_set(
        payload,
        "event_ids",
        "covered_event_ids",
        "confluent_event_ids",
        "discharged_event_ids",
    )
    return required.issubset(covered)


def signature_verifier_proof_matches(event: LifecycleEvent, signature_result: str) -> bool:
    status = event.signature_verifier_result_status
    if not isinstance(status, Mapping):
        return False
    if not accepted_proof_evidence(
        status,
        expected_kinds=(
            "signature_verifier",
            "signature-verifier",
            "signature_validation",
            "signature-validation",
        ),
    ):
        return False
    payload = _proof_payload(status)
    if str(payload.get("event_id")) != event.event_id:
        return False
    if str(payload.get("signature_verifier_result")) != str(signature_result):
        return False
    if event.signature_verifier_result_ref is None:
        return False
    artifact_ref = status.get("artifact_ref")
    return str(artifact_ref) == str(event.signature_verifier_result_ref)


def fold_status(
    certificate_id: str,
    event_log: tuple[LifecycleEvent, ...],
    event_order: EventOrder,
    fold_context: FoldContext,
    signature_verifier: SignatureVerifier | None = None,
) -> FoldResult:
    signature_verifier = signature_verifier or UnknownSignatureVerifier()
    accepted = set(event_order.accepted_event_ids) if event_order.accepted_event_ids else None
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    seen_clocks: dict[int, tuple[str, StatusCode]] = {}
    statuses = [StatusCode.ACTIVE]
    coordinates: list[StatusCoordinate] = [
        StatusCoordinate("active", StatusCode.ACTIVE.value, evidence_refs=("issue-certificate",))
    ]
    blocks: list[BlockingRecord] = []
    accepted_seen: set[str] = set()

    for event in sorted(event_log, key=lambda item: (item.logical_clock, item.time, item.event_id)):
        if event.certificate_id != certificate_id:
            continue
        if accepted is not None and event.event_id not in accepted:
            continue
        if accepted is not None:
            accepted_seen.add(event.event_id)
        if event_order.trace_class and event.kind not in event_order.trace_class:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                f"lifecycle event kind is outside accepted trace class: {event.kind}",
                source_artifact=event.event_id,
                source_path="/kind",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            continue
        if event_order.causal_cut and not set(event.ancestry).issubset(set(event_order.causal_cut)):
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                "lifecycle event ancestry is outside the causal cut",
                source_artifact=event.event_id,
                source_path="/ancestry",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            continue
        if event.event_id in seen_ids:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                f"duplicate lifecycle event_id: {event.event_id}",
                source_artifact=event.event_id,
                source_path="/event_id",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            continue
        missing_ancestry = tuple(parent for parent in event.ancestry if parent not in seen_ids)
        if missing_ancestry and not confluence_proof_covers(
            event_order.confluence_proof,
            (event.event_id, *missing_ancestry),
        ):
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                f"lifecycle ancestry is not in accepted cut: {missing_ancestry[0]}",
                source_artifact=event.event_id,
                source_path="/ancestry",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        conflict_event_id = event.payload.get("conflicts_with")
        if conflict_event_id in seen_ids and not confluence_proof_covers(
            event_order.confluence_proof,
            (event.event_id, str(conflict_event_id)),
        ):
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                f"lifecycle event conflicts with accepted event: {event.payload['conflicts_with']}",
                source_artifact=event.event_id,
                source_path="/payload/conflicts_with",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        signature_policy = str(event.payload.get("signature_policy", "optional"))
        if signature_policy == "required" and not event.signature:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                "lifecycle event requires a signature but none is present",
                source_artifact=event.event_id,
                source_path="/signature",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        declared_signature_result = event.signature_verifier_result is not None
        signature_result = event.signature_verifier_result
        if signature_policy == "required" and signature_result is None:
            signature_result = signature_verifier.verify(event)
        if (
            signature_policy == "required"
            and declared_signature_result
            and str(signature_result) in {"pass", "accepted"}
            and not signature_verifier_proof_matches(event, str(signature_result))
        ):
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                "declared signature verifier result lacks accepted proof evidence",
                source_artifact=event.event_id,
                source_path="/signature_verifier_result_status",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        if signature_result in {"fail", "conflict", "unknown"}:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                f"lifecycle signature verifier result is {signature_result}",
                source_artifact=event.event_id,
                source_path="/signature_verifier_result",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        expected_hash = event.payload.get("event_hash")
        actual_hash = event_commitment(event)
        if expected_hash is not None and str(expected_hash) != actual_hash:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                "lifecycle event hash does not match canonical commitment",
                source_artifact=event.event_id,
                source_path="/payload/event_hash",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        if expected_hash is not None and str(expected_hash) not in event.hashes:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                "lifecycle event hash is not included in event hash commitments",
                source_artifact=event.event_id,
                source_path="/hashes",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        previous_hash = event.payload.get("previous_hash")
        if previous_hash is None:
            previous_hash = event.previous_event_commitment
        if previous_hash is not None and str(previous_hash) not in seen_hashes:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                "lifecycle event previous_hash is outside the accepted prefix",
                source_artifact=event.event_id,
                source_path="/payload/previous_hash",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        if event.manifest_digest is not None and event.manifest_digest not in event.hashes:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                "lifecycle event manifest digest is not committed by event hashes",
                source_artifact=event.event_id,
                source_path="/manifest_digest",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        expected_policy = event.payload.get("policy_version")
        if expected_policy is not None and str(expected_policy) != fold_context.policy_version:
            block = blocking_record(
                FailureCode.POLICY_BLOCK,
                Layer.STATUS,
                "lifecycle event was admitted under a different policy version",
                source_artifact=event.event_id,
                source_path="/payload/policy_version",
            )
            blocks.append(block)
            statuses.append(StatusCode.UNKNOWN)
            seen_ids.add(event.event_id)
            continue
        if event_order.log_root is not None and event_order.log_root not in event.hashes:
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                "lifecycle event does not commit to the configured log root",
                source_artifact=event.event_id,
                source_path="/hashes",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            seen_ids.add(event.event_id)
            continue
        seen_ids.add(event.event_id)
        seen_hashes.add(actual_hash)
        seen_hashes.update(event.hashes)
        mapped = EVENT_TO_STATUS.get(event.kind)
        if mapped is None:
            continue
        status, failure = mapped
        prior = seen_clocks.get(event.logical_clock)
        if (
            prior is not None
            and prior[1] is not status
            and event_order.conflict_policy == "conflict-on-disagreement"
            and not confluence_proof_covers(
                event_order.confluence_proof,
                (event.event_id, prior[0]),
            )
        ):
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                f"trace disagreement at logical clock {event.logical_clock}",
                source_artifact=event.event_id,
                source_path="/logical_clock",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)
            continue
        seen_clocks[event.logical_clock] = (event.event_id, status)
        statuses.append(status)
        coordinates.append(
            StatusCoordinate(
                event.kind,
                status.value,
                evidence_refs=(event.event_id,),
            )
        )
        if failure is not None:
            blocks.append(
                blocking_record(
                    failure,
                    Layer.STATUS,
                    f"lifecycle event {event.kind}",
                    source_artifact=event.event_id,
                    source_path="/kind",
                )
            )

    if accepted is not None:
        for missing_event_id in sorted(accepted - accepted_seen):
            block = blocking_record(
                FailureCode.TRACE_CONFLICT,
                Layer.STATUS,
                f"accepted lifecycle event is absent from event log: {missing_event_id}",
                source_artifact=missing_event_id,
                source_path="/accepted_event_ids",
            )
            blocks.append(block)
            statuses.append(StatusCode.CONFLICT)

    dominant = dominant_status(statuses)
    return FoldResult(
        coordinates=tuple(coordinates),
        blocking_set=tuple(blocks),
        dominant_status=dominant,
        status_reason=dominant.value,
    )
