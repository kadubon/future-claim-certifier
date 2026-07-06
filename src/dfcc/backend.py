"""Backend and checker contracts."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from dfcc.bundle import CompiledBundle
from dfcc.canonical import digest_json
from dfcc.claims import ClaimRecord, PredicateRegistry, default_predicate_registry
from dfcc.sets import EMPTY_SET, FiniteSet
from dfcc.types import (
    ALLOWED_OUTCOME_DIRECTIONS,
    Direction,
    FailureCode,
    Layer,
    ReasonRef,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    pass_validation,
    validation_failure,
)


@dataclass(frozen=True, slots=True)
class ResidualContext:
    r: int
    p_star: FiniteSet
    p_out: FiniteSet
    p_in: FiniteSet | None
    adm_star: FiniteSet
    adm_out: FiniteSet


@dataclass(frozen=True, slots=True)
class BackendProblem:
    compiled_bundle: CompiledBundle
    residual_context: ResidualContext
    claim: ClaimRecord


@dataclass(frozen=True, slots=True)
class FeasibilityResult:
    status: str
    evidence_refs: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class EnclosureResult:
    trajectories: FiniteSet
    sound: bool
    metadata: dict[str, Any]
    reason_refs: tuple[ReasonRef, ...] = ()


@dataclass(frozen=True, slots=True)
class WitnessResult:
    satisfying: FiniteSet = EMPTY_SET
    nonsatisfying: FiniteSet = EMPTY_SET
    metadata: dict[str, Any] | None = None


class DFCCBackend(Protocol):
    def problem(
        self,
        compiled_bundle: CompiledBundle,
        residual_context: ResidualContext,
        claim: ClaimRecord,
    ) -> BackendProblem: ...

    def feasibility(self, problem: BackendProblem) -> FeasibilityResult: ...

    def outer_enclosure(self, problem: BackendProblem) -> EnclosureResult: ...

    def inner_witnesses(self, problem: BackendProblem, claim: ClaimRecord) -> WitnessResult: ...

    def proof_object(self) -> dict[str, Any]: ...


class DFCCChecker(Protocol):
    def schema(self, artifact: Any) -> ValidationResult: ...

    def artifact_ref(
        self, artifact_ref: Any, schema_profile: Any, policy: Any
    ) -> ValidationResult: ...

    def manifest_digest(
        self, artifact: Any, schema_profile: Any, dependencies: Any
    ) -> ValidationResult: ...

    def reference_resolution(
        self, ref: Any, reference_resolution_context: Any
    ) -> ValidationResult: ...

    def profile_resolution(
        self, requested_profile: Any, implemented_profiles: Any
    ) -> ValidationResult: ...

    def reason_path(self, artifact_ref: Any, json_pointer: str) -> ValidationResult: ...

    def scalar_record(self, scalar_record: Any) -> ValidationResult: ...

    def interval_record(self, interval_record: Any) -> ValidationResult: ...

    def timestamp_record(self, timestamp_record: Any) -> ValidationResult: ...

    def set_ref(self, set_ref: Any) -> ValidationResult: ...

    def assessment_frame(self, frame_record: Any) -> ValidationResult: ...

    def admission(self, evidence: Any, contract: Any) -> ValidationResult: ...

    def initial_context(
        self, bundle: Any, anchor: Any, frame: Any, policy: Any
    ) -> ValidationResult: ...

    def representation_interface(
        self, bundle: Any, frame: Any, policy: Any
    ) -> ValidationResult: ...

    def time_basis(self, clock_record: Any, timestamp_policy: Any) -> ValidationResult: ...

    def event_order(
        self, events: Any, order_policy: Any, log_commitments: Any
    ) -> ValidationResult: ...

    def observation_cut(
        self,
        records: Any,
        status_time: Any,
        time_basis: Any,
        event_order: Any,
        dependencies: Any,
        frame: Any,
    ) -> ValidationResult: ...

    def status_observation_context(
        self, certificate: Any, observation_cut: Any, policy: Any
    ) -> ValidationResult: ...

    def operational_prefix_fiber(
        self, observation_cut: Any, frame: Any, index: int
    ) -> ValidationResult: ...

    def operational_completion_fiber(
        self, prefix_record: Any, frame: Any, residual_context: Any
    ) -> ValidationResult: ...

    def completion_admission(
        self, prefix_context: Any, completion_interface: Any, policy: Any
    ) -> ValidationResult: ...

    def representation_projection_coherence(
        self, representation_interface: Any
    ) -> ValidationResult: ...

    def prefix_admission(
        self, observation_cut: Any, bundle: Any, anchor: Any
    ) -> ValidationResult: ...

    def prefix_soundness(
        self, prefix_view: Any, observation_cut: Any, frame: Any
    ) -> ValidationResult: ...

    def residual_context(
        self, certificate: Any, status_time: Any, prefix_view: Any, exact_prefix_set: Any
    ) -> ValidationResult: ...

    def checked_assoc_view(
        self,
        observation_record: Any,
        claim: Any,
        compiled_bundle: Any,
        residual_context: Any,
        frame: Any,
    ) -> ValidationResult: ...

    def exact_fiber_assoc(
        self,
        observation_record: Any,
        claim: Any,
        compiled_bundle: Any,
        residual_context: Any,
        frame: Any,
    ) -> ValidationResult: ...

    def fiber_assoc_view(
        self,
        observation_record: Any,
        claim: Any,
        compiled_bundle: Any,
        residual_context: Any,
        frame: Any,
    ) -> ValidationResult: ...

    def prefix_adjudication(self, observation_record: Any, frame: Any) -> ValidationResult: ...

    def usage_adjudication(
        self, proposed_use: Any, frame: Any, policy: Any
    ) -> ValidationResult: ...

    def target_adjudication(
        self, observation_record: Any, target_condition: Any, frame: Any
    ) -> ValidationResult: ...

    def agreement(
        self,
        kernel_view: Any,
        fiber_assoc_view: Any,
        adjudication_views: Any,
        adequacy: Any,
        blocking_set: Any,
        policy_gate: Any,
    ) -> ValidationResult: ...

    def typed_authority_outcome(
        self,
        status_view: Any,
        kernel_view: Any,
        agreement: Any,
        blocking_set: Any,
        gate_decision: Any,
    ) -> ValidationResult: ...

    def status_confluence(
        self, status_coordinates: Any, blocking_sets: Any, event_order: Any
    ) -> ValidationResult: ...

    def enclosure_soundness(self, enclosure: EnclosureResult) -> bool: ...

    def witness(
        self,
        witness: WitnessResult,
        compiled_bundle: CompiledBundle,
        residual_context: ResidualContext,
    ) -> bool: ...

    def infeasibility(self, proof_object: Any) -> bool: ...

    def inclusion(self, outer_enclosure: FiniteSet, satisfaction_set: FiniteSet) -> str: ...

    def disjointness(self, outer_enclosure: FiniteSet, satisfaction_set: FiniteSet) -> str: ...

    def artifact_conflict(self, accepted_artifacts: tuple[Any, ...]) -> bool: ...

    def frame_adequacy(
        self, represented_claim: Any, target_condition: Any, frame: Any
    ) -> ValidationResult: ...


class EnumeratingBackend:
    """Exact finite backend for small bounded systems."""

    def __init__(self, registry: PredicateRegistry | None = None) -> None:
        self.registry = registry or default_predicate_registry()

    def problem(
        self,
        compiled_bundle: CompiledBundle,
        residual_context: ResidualContext,
        claim: ClaimRecord,
    ) -> BackendProblem:
        return BackendProblem(compiled_bundle, residual_context, claim)

    def feasibility(self, problem: BackendProblem) -> FeasibilityResult:
        if problem.residual_context.adm_out.is_empty():
            return FeasibilityResult(
                status="infeasible", evidence_refs=("exact-empty-enumeration",)
            )
        return FeasibilityResult(status="feasible", evidence_refs=("exact-nonempty-enumeration",))

    def outer_enclosure(self, problem: BackendProblem) -> EnclosureResult:
        return EnclosureResult(
            trajectories=problem.residual_context.adm_out,
            sound=True,
            metadata={"kind": "exact-finite-enumeration"},
        )

    def inner_witnesses(self, problem: BackendProblem, claim: ClaimRecord) -> WitnessResult:
        satisfying: list[Any] = []
        nonsatisfying: list[Any] = []
        for trajectory in problem.residual_context.adm_out:
            if claim.satisfies(tuple(trajectory), self.registry):
                satisfying.append(trajectory)
            else:
                nonsatisfying.append(trajectory)
        satisfying_set = FiniteSet.from_iterable(satisfying[:1])
        nonsatisfying_set = FiniteSet.from_iterable(nonsatisfying[:1])
        witness_material = {
            "backend": "EnumeratingBackend",
            "kind": "exact-finite-witness",
            "satisfying": satisfying_set.to_json(),
            "nonsatisfying": nonsatisfying_set.to_json(),
        }
        return WitnessResult(
            satisfying=satisfying_set,
            nonsatisfying=nonsatisfying_set,
            metadata={
                "kind": "exact-finite-witness",
                "proof_ref": digest_json(witness_material),
            },
        )

    def proof_object(self) -> dict[str, Any]:
        proof_material = "EnumeratingBackend\x1fexact-finite-enumeration\x1faccepted"
        return {
            "backend": "EnumeratingBackend",
            "proof_kind": "exact-finite-enumeration",
            "proof_status": "accepted",
            "proof_ref": f"sha256:{hashlib.sha256(proof_material.encode('utf-8')).hexdigest()}",
        }


class ReferenceChecker:
    """Small checker used by the finite reference backend."""

    _BUILTIN_AUTHORITY_OUTCOME_SCHEMAS = frozenset(
        {
            "status-authority-view",
            "status-authority-view.schema.json",
            "https://dfcc.local/schemas/status-authority-view.schema.json",
        }
    )

    def _unknown(self, name: str) -> ValidationResult:
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            f"checker method has no accepted evidence: {name}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.VALIDATION,
            source_path=name,
        )

    @staticmethod
    def _bound_artifact_ref(value: Any) -> bool:
        from collections.abc import Mapping

        if isinstance(value, str):
            base = value.split("#", 1)[0]
            return base.startswith("artifact:")
        if isinstance(value, Mapping):
            artifact_id = value.get("artifact_id")
            digest = value.get("digest_value", value.get("digest"))
            return (
                isinstance(artifact_id, str)
                and artifact_id.startswith("artifact:")
                and ReferenceChecker._bound_digest(digest)
            )
        return False

    @staticmethod
    def _bound_digest(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        return (
            value.startswith(("sha256:", "sha384:", "sha512:")) and len(value.split(":", 1)[1]) > 0
        )

    @classmethod
    def _bound_artifact_pointer_or_digest(cls, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        if cls._bound_digest(value):
            return True
        artifact_id, separator, pointer = value.partition("#")
        return bool(separator) and artifact_id.startswith("artifact:") and pointer.startswith("/")

    @staticmethod
    def _accepted_evidence(value: Any, *, expected_kinds: tuple[str, ...] = ()) -> bool:
        from collections.abc import Mapping

        if not isinstance(value, Mapping):
            return False
        bound = False
        artifact_ref = value.get("artifact_ref")
        if ReferenceChecker._bound_artifact_ref(artifact_ref):
            bound = True
        for digest_key in ("artifact_digest", "digest", "reference_digest"):
            digest = value.get(digest_key)
            if ReferenceChecker._bound_digest(digest):
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
        if expected_kinds:
            kind_value = next(
                (
                    value.get(key)
                    for key in ("proof_kind", "checker_kind", "kind", "evidence_kind")
                    if value.get(key) is not None
                ),
                None,
            )
            if str(kind_value) not in set(expected_kinds):
                return False
        for key in ("checker_status", "proof_status", "status", "result", "checker_result"):
            status = value.get(key)
            if status is not None:
                return str(status) in {"pass", "accepted"} and bound
        return False

    @classmethod
    def _accepted_digest_bound_evidence(
        cls,
        value: Any,
        *,
        expected_kinds: tuple[str, ...] = (),
    ) -> bool:
        from collections.abc import Mapping

        if not cls._accepted_evidence(value, expected_kinds=expected_kinds):
            return False
        if not isinstance(value, Mapping):
            return False
        artifact_ref = value.get("artifact_ref")
        if isinstance(artifact_ref, Mapping) and cls._bound_artifact_ref(artifact_ref):
            return True
        if any(
            cls._bound_digest(value.get(digest_key))
            for digest_key in ("artifact_digest", "digest", "reference_digest")
        ):
            return True
        return (
            isinstance(value.get("source_artifact"), str)
            and str(value["source_artifact"]).startswith("artifact:")
            and isinstance(value.get("source_path"), str)
            and str(value["source_path"]).startswith("/")
            and cls._bound_digest(value.get("digest"))
        )

    @classmethod
    def _accepted_payload_value(
        cls,
        value: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...] = (),
    ) -> Any:
        from collections.abc import Mapping

        if not isinstance(value, Mapping) or not cls._accepted_evidence(
            value, expected_kinds=expected_kinds
        ):
            return None
        payloads: list[Mapping[str, Any]] = [value]
        proof_payload = value.get("proof")
        if isinstance(proof_payload, Mapping):
            payloads.append(proof_payload)
        nested_payload = value.get("payload")
        if isinstance(nested_payload, Mapping):
            payloads.append(nested_payload)
        for payload in payloads:
            for field_name in field_names:
                payload_value = payload.get(field_name)
                if payload_value is not None:
                    return payload_value
        return None

    @classmethod
    def _accepted_payload_binding(
        cls,
        source: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...],
        payload_fields: tuple[str, ...],
        expected_value: Any,
    ) -> str:
        from collections.abc import Mapping

        if not isinstance(source, Mapping):
            return "missing"
        for field_name in field_names:
            value = source.get(field_name)
            if not cls._accepted_digest_bound_evidence(value, expected_kinds=expected_kinds):
                continue
            payload_value = cls._accepted_payload_value(
                value,
                *payload_fields,
                expected_kinds=expected_kinds,
            )
            if payload_value is None:
                return "missing"
            if str(payload_value) != str(expected_value):
                return "conflict"
            return "match"
        return "missing"

    @classmethod
    def _accepted_payload_binding_nested(
        cls,
        source: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...],
        payload_fields: tuple[str, ...],
        expected_value: Any,
    ) -> str:
        from collections.abc import Mapping

        direct = cls._accepted_payload_binding(
            source,
            *field_names,
            expected_kinds=expected_kinds,
            payload_fields=payload_fields,
            expected_value=expected_value,
        )
        if direct != "missing":
            return direct
        if isinstance(source, Mapping):
            policy = source.get("policy")
            nested = cls._accepted_payload_binding(
                policy,
                *field_names,
                expected_kinds=expected_kinds,
                payload_fields=payload_fields,
                expected_value=expected_value,
            )
            if nested != "missing":
                return nested
        policy = getattr(source, "policy", None)
        return cls._accepted_payload_binding(
            policy,
            *field_names,
            expected_kinds=expected_kinds,
            payload_fields=payload_fields,
            expected_value=expected_value,
        )

    @classmethod
    def _accepted_payload_identity_binding(
        cls,
        source: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...],
        expected_values: dict[str, tuple[Any, tuple[str, ...]]],
    ) -> str:
        from collections.abc import Mapping

        if not isinstance(source, Mapping):
            return "missing"
        for field_name in field_names:
            value = source.get(field_name)
            if not cls._accepted_digest_bound_evidence(value, expected_kinds=expected_kinds):
                continue
            for _expected_name, (expected_value, payload_fields) in expected_values.items():
                payload_value = cls._accepted_payload_value(
                    value,
                    *payload_fields,
                    expected_kinds=expected_kinds,
                )
                if payload_value is None:
                    return "missing"
                if str(payload_value) != str(expected_value):
                    return "conflict"
            return "match"
        return "missing"

    @classmethod
    def _accepted_payload_identity_binding_nested(
        cls,
        source: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...],
        expected_values: dict[str, tuple[Any, tuple[str, ...]]],
    ) -> str:
        from collections.abc import Mapping

        direct = cls._accepted_payload_identity_binding(
            source,
            *field_names,
            expected_kinds=expected_kinds,
            expected_values=expected_values,
        )
        if direct != "missing":
            return direct
        if isinstance(source, Mapping):
            policy = source.get("policy")
            nested = cls._accepted_payload_identity_binding(
                policy,
                *field_names,
                expected_kinds=expected_kinds,
                expected_values=expected_values,
            )
            if nested != "missing":
                return nested
        policy = getattr(source, "policy", None)
        return cls._accepted_payload_identity_binding(
            policy,
            *field_names,
            expected_kinds=expected_kinds,
            expected_values=expected_values,
        )

    @classmethod
    def _schema_validation_identity_binding(cls, artifact: Any, evidence: Any) -> str:
        from collections.abc import Mapping

        if not isinstance(artifact, Mapping):
            return "missing"
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {}
        schema_name = artifact.get("schema_name")
        if schema_name is not None:
            expected_values["schema_name"] = (
                schema_name,
                ("schema_name", "target_schema", "validated_schema"),
            )
        artifact_id = artifact.get("artifact_id")
        if artifact_id is not None:
            expected_values["artifact_id"] = (
                artifact_id,
                ("artifact_id", "target_artifact_id", "validated_artifact_id"),
            )
        schema_profile_ref = artifact.get("schema_profile_ref", artifact.get("schema_profile"))
        if schema_profile_ref is not None:
            expected_values["schema_profile_ref"] = (
                schema_profile_ref,
                ("schema_profile_ref", "schema_profile", "target_schema_profile"),
            )
        canonicalization_profile_ref = artifact.get(
            "canonicalization_profile_ref",
            artifact.get("canonicalization"),
        )
        if canonicalization_profile_ref is not None:
            expected_values["canonicalization_profile_ref"] = (
                canonicalization_profile_ref,
                (
                    "canonicalization_profile_ref",
                    "canonicalization",
                    "target_canonicalization_profile",
                ),
            )
        schema_digest = artifact.get("schema_digest")
        if schema_digest is not None:
            expected_values["schema_digest"] = (
                schema_digest,
                ("schema_digest", "target_schema_digest", "validated_schema_digest"),
            )
        if not expected_values:
            return "missing"
        return cls._accepted_payload_identity_binding(
            {"schema_validation_ref": evidence},
            "schema_validation_ref",
            expected_kinds=("schema_validation", "schema"),
            expected_values=expected_values,
        )

    @classmethod
    def _accepted_field(
        cls,
        source: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...] = (),
    ) -> bool:
        from collections.abc import Mapping

        if not isinstance(source, Mapping):
            return False
        return any(
            cls._accepted_evidence(source.get(name), expected_kinds=expected_kinds)
            for name in field_names
        )

    @classmethod
    def _accepted_digest_bound_field(
        cls,
        source: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...] = (),
    ) -> bool:
        from collections.abc import Mapping

        if not isinstance(source, Mapping):
            return False
        return any(
            cls._accepted_digest_bound_evidence(
                source.get(name),
                expected_kinds=expected_kinds,
            )
            for name in field_names
        )

    @classmethod
    def _accepted_nested_field(
        cls,
        source: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...] = (),
    ) -> bool:
        from collections.abc import Mapping

        if cls._accepted_field(source, *field_names, expected_kinds=expected_kinds):
            return True
        if isinstance(source, Mapping):
            policy = source.get("policy")
            if cls._accepted_field(policy, *field_names, expected_kinds=expected_kinds):
                return True
        policy = getattr(source, "policy", None)
        return cls._accepted_field(policy, *field_names, expected_kinds=expected_kinds)

    @classmethod
    def _accepted_digest_bound_nested_field(
        cls,
        source: Any,
        *field_names: str,
        expected_kinds: tuple[str, ...] = (),
    ) -> bool:
        from collections.abc import Mapping

        if cls._accepted_digest_bound_field(source, *field_names, expected_kinds=expected_kinds):
            return True
        if isinstance(source, Mapping):
            policy = source.get("policy")
            if cls._accepted_digest_bound_field(
                policy, *field_names, expected_kinds=expected_kinds
            ):
                return True
        policy = getattr(source, "policy", None)
        return cls._accepted_digest_bound_field(policy, *field_names, expected_kinds=expected_kinds)

    @staticmethod
    def _typed_reason_ref(value: Any) -> bool:
        from collections.abc import Mapping

        def _nonempty(item: Any) -> bool:
            item_value = getattr(item, "value", item)
            return isinstance(item_value, str) and bool(item_value)

        if isinstance(value, str):
            return False
        if hasattr(value, "source_artifact") and hasattr(value, "source_path"):
            return (
                _nonempty(getattr(value, "reason_id", None))
                and _nonempty(getattr(value, "failure_code", None))
                and _nonempty(getattr(value, "layer", None))
                and _nonempty(getattr(value, "message", None))
                and str(value.source_artifact).startswith("artifact:")
                and str(value.source_path).startswith("/")
                and ReferenceChecker._bound_digest(getattr(value, "digest", None))
            )
        if not isinstance(value, Mapping):
            return False
        reason_id = value.get("reason_id")
        failure_code = value.get("failure_code")
        layer = value.get("layer")
        source_artifact = value.get("source_artifact")
        source_path = value.get("source_path")
        message = value.get("message")
        digest = value.get("digest")
        return (
            _nonempty(reason_id)
            and _nonempty(failure_code)
            and _nonempty(layer)
            and _nonempty(message)
            and isinstance(source_artifact, str)
            and source_artifact.startswith("artifact:")
            and isinstance(source_path, str)
            and source_path.startswith("/")
            and ReferenceChecker._bound_digest(digest)
        )

    @classmethod
    def _typed_blocking_record(cls, value: Any) -> bool:
        from collections.abc import Mapping

        def _nonempty(item: Any) -> bool:
            item_value = getattr(item, "value", item)
            return isinstance(item_value, str) and bool(item_value)

        def _reason_id(item: Any) -> str | None:
            if isinstance(item, Mapping):
                reason_id = item.get("reason_id")
            else:
                reason_id = getattr(item, "reason_id", None)
            return str(reason_id) if isinstance(reason_id, str) and reason_id else None

        if hasattr(value, "block_id") and hasattr(value, "failure_code"):
            refs = tuple(getattr(value, "reason_refs", ()))
            return (
                _nonempty(getattr(value, "block_id", None))
                and _nonempty(getattr(value, "failure_code", None))
                and _nonempty(getattr(value, "layer", None))
                and _nonempty(getattr(value, "severity", None))
                and bool(refs)
                and all(cls._typed_reason_ref(item) for item in refs)
            )
        if not isinstance(value, Mapping):
            return False
        block_id = value.get("block_id")
        failure_code = value.get("failure_code")
        layer = value.get("layer")
        severity = value.get("severity")
        reason_ids = tuple(value.get("reason_refs", ()))
        refs = tuple(value.get("reason_ref_records", ()))
        record_ids = tuple(_reason_id(item) for item in refs)
        return (
            _nonempty(block_id)
            and _nonempty(failure_code)
            and _nonempty(layer)
            and _nonempty(severity)
            and bool(reason_ids)
            and all(isinstance(item, str) and bool(item) for item in reason_ids)
            and bool(refs)
            and all(cls._typed_reason_ref(item) for item in refs)
            and record_ids == reason_ids
        )

    @classmethod
    def _typed_proof_ref(cls, value: Any) -> bool:
        from collections.abc import Mapping

        def _nonempty(item: Any) -> bool:
            return isinstance(item, str) and bool(item)

        if hasattr(value, "proof_id") and hasattr(value, "proof_kind"):
            proof_id = getattr(value, "proof_id", None)
            proof_kind = getattr(value, "proof_kind", None)
            status = str(getattr(value, "status", "unknown"))
            digest = getattr(value, "digest", None)
            source_path = str(getattr(value, "source_path", ""))
        elif isinstance(value, Mapping):
            proof_id = value.get("proof_id")
            proof_kind = value.get("proof_kind")
            status = str(value.get("status", "unknown"))
            digest = value.get("digest")
            source_path = str(value.get("source_path", ""))
        else:
            return False
        if not (_nonempty(proof_id) and _nonempty(proof_kind) and _nonempty(status)):
            return False
        if source_path and not source_path.startswith("/"):
            return False
        if status in {"pass", "accepted"}:
            return cls._bound_digest(digest)
        return status not in {"", "unknown", "unchecked"}

    @classmethod
    def _authority_outcome_schema_ref(cls, value: Any) -> bool:
        from collections.abc import Mapping

        if isinstance(value, str):
            if value in cls._BUILTIN_AUTHORITY_OUTCOME_SCHEMAS:
                return True
            return cls._bound_artifact_pointer_or_digest(value)
        if isinstance(value, Mapping):
            return cls._accepted_digest_bound_evidence(
                value,
                expected_kinds=(
                    "authority_outcome_schema",
                    "typed_authority_outcome",
                    "schema_validation",
                    "schema",
                ),
            )
        return False

    def schema(self, artifact: Any) -> ValidationResult:
        if isinstance(artifact, dict):
            for field_name in (
                "schema_validation",
                "schema_validation_ref",
                "checker_transcript",
            ):
                evidence = artifact.get(field_name)
                if not self._accepted_digest_bound_evidence(
                    evidence,
                    expected_kinds=("schema_validation", "schema"),
                ):
                    continue
                identity_binding = self._schema_validation_identity_binding(artifact, evidence)
                if identity_binding == "conflict":
                    return validation_failure(
                        FailureCode.ARTIFACT_CONFLICT,
                        ValidationStage.SCHEMA_VALIDATE,
                        "schema validation transcript targets a different artifact or schema",
                        status=ValidationStatus.CONFLICT,
                        layer=Layer.INTEROP,
                    )
                if identity_binding == "match":
                    return pass_validation(ValidationStage.SCHEMA_VALIDATE)
        return self._unknown("schema")

    def artifact_ref(self, artifact_ref: Any, schema_profile: Any, policy: Any) -> ValidationResult:
        from dfcc.artifacts import validate_artifact_ref

        del schema_profile, policy
        return validate_artifact_ref(artifact_ref)

    def manifest_digest(
        self, artifact: Any, schema_profile: Any, dependencies: Any
    ) -> ValidationResult:
        from collections.abc import Mapping

        from dfcc.artifacts import ArtifactRef, manifest_digest

        if not isinstance(artifact, Mapping):
            return self._unknown("manifest_digest")
        expected = artifact.get("manifest_digest")
        if expected is None:
            return self._unknown("manifest_digest")
        refs = tuple(item for item in dependencies if isinstance(item, ArtifactRef))
        actual = manifest_digest(
            {key: value for key, value in artifact.items() if key != "manifest_digest"},
            artifact_type=str(artifact.get("artifact_type", "manifest")),
            schema_profile_digest=str(schema_profile),
            dependencies=refs,
        )
        if actual == expected:
            return pass_validation(ValidationStage.DIGEST_CHECK)
        return validation_failure(
            FailureCode.DIGEST_MISMATCH,
            ValidationStage.DIGEST_CHECK,
            "checker manifest digest mismatch",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
        )

    def reference_resolution(self, ref: Any, reference_resolution_context: Any) -> ValidationResult:
        from collections.abc import Mapping

        from dfcc.artifacts import ArtifactStore, resolve_reference

        if not isinstance(ref, Mapping):
            return self._unknown("reference_resolution")
        store = ref.get("store")
        artifact_id = ref.get("artifact_id")
        pointer = ref.get("pointer")
        if not isinstance(store, ArtifactStore) or artifact_id is None or pointer is None:
            return self._unknown("reference_resolution")
        result, _ = resolve_reference(
            str(artifact_id),
            str(pointer),
            store=store,
            context=reference_resolution_context,
        )
        return result

    def profile_resolution(
        self, requested_profile: Any, implemented_profiles: Any
    ) -> ValidationResult:
        from dfcc.profiles import resolve_profile

        profile = resolve_profile(str(requested_profile), implemented_profiles)
        if profile.status != "pass":
            return validation_failure(
                FailureCode.UNSUPPORTED_PROFILE,
                ValidationStage.PROFILE_RESOLVE,
                "unsupported profile"
                + (
                    f": {', '.join(profile.reason_refs)}"
                    if profile.reason_refs
                    else f": {requested_profile}"
                ),
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact="artifact:profile-resolution",
                source_path=f"/implemented_profiles/{requested_profile}",
            )
        return pass_validation(ValidationStage.PROFILE_RESOLVE)

    def reason_path(self, artifact_ref: Any, json_pointer: str) -> ValidationResult:
        if json_pointer != "" and not json_pointer.startswith("/"):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.REFERENCE_RESOLVE,
                "reason path is not a JSON Pointer",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
            )
        if not self._accepted_digest_bound_field(
            artifact_ref,
            "reason_path_proof",
            "reason_path_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("reason_path", "reference_resolution", "reason"),
        ):
            return self._unknown("reason_path")
        binding = self._accepted_payload_identity_binding(
            artifact_ref,
            "reason_path_proof",
            "reason_path_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("reason_path", "reference_resolution", "reason"),
            expected_values={
                "json_pointer": (
                    json_pointer,
                    ("json_pointer", "reason_path", "source_path", "pointer"),
                )
            },
        )
        if binding == "match":
            return pass_validation(ValidationStage.REFERENCE_RESOLVE)
        if binding == "conflict":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.REFERENCE_RESOLVE,
                "reason path transcript targets a different JSON Pointer",
                status=ValidationStatus.CONFLICT,
                layer=Layer.INTEROP,
            )
        return self._unknown("reason_path")

    def scalar_record(self, scalar_record: Any) -> ValidationResult:
        from dfcc.records import validate_scalar_record

        return validate_scalar_record(scalar_record)

    def interval_record(self, interval_record: Any) -> ValidationResult:
        if interval_record.lower.decimal() > interval_record.upper.decimal():
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.SCHEMA_VALIDATE,
                "interval lower bound is greater than upper bound",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
            )
        return pass_validation(ValidationStage.SCHEMA_VALIDATE)

    def timestamp_record(self, timestamp_record: Any) -> ValidationResult:
        from dfcc.records import validate_timestamp_record

        return validate_timestamp_record(timestamp_record)

    def set_ref(self, set_ref: Any) -> ValidationResult:
        from dfcc.records import validate_set_ref

        result = validate_set_ref(set_ref)
        if not result.passed:
            return result
        soundness_ref = str(getattr(set_ref, "soundness_ref", ""))
        soundness_base, separator, soundness_pointer = soundness_ref.partition("#")
        if soundness_ref.startswith(("sha256:", "sha384:", "sha512:")) or (
            separator
            and soundness_base.startswith("artifact:")
            and soundness_pointer.startswith("/")
        ):
            return pass_validation(ValidationStage.REFERENCE_RESOLVE)
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.REFERENCE_RESOLVE,
            "set reference soundness is not bound to a proof artifact pointer or digest",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.INTEROP,
        )

    def assessment_frame(self, frame_record: Any) -> ValidationResult:
        if isinstance(frame_record, dict) and frame_record.get("frame_id") is not None:
            binding = self._accepted_payload_binding(
                frame_record,
                "frame_proof",
                "frame_proof_ref",
                "checker_transcript",
                "checker_transcript_ref",
                expected_kinds=("assessment_frame", "frame"),
                payload_fields=("frame_id", "assessment_frame_id", "target_frame_id"),
                expected_value=frame_record.get("frame_id"),
            )
            if binding == "conflict":
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    "assessment frame transcript targets a different frame",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.ISSUE,
                )
            if binding == "match":
                return pass_validation(ValidationStage.GUARD_EVALUATE)
        return self._unknown("assessment_frame")

    def admission(self, evidence: Any, contract: Any) -> ValidationResult:
        from dfcc.admission import admit_evidence

        result = admit_evidence(evidence, contract)
        accepted_records = tuple(result.accepted_clause_records)
        if (
            result.passed
            and accepted_records
            and all(
                self._bound_artifact_pointer_or_digest(record.checker_transcript_ref)
                for record in accepted_records
            )
        ):
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        if result.passed:
            return self._unknown("admission")
        return ValidationResult(
            ValidationStage.GUARD_EVALUATE,
            ValidationStatus.UNKNOWN,
            reason_refs=result.reason_refs,
        )

    def initial_context(
        self, bundle: Any, anchor: Any, frame: Any, policy: Any
    ) -> ValidationResult:
        from collections.abc import Mapping

        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {}
        if isinstance(bundle, Mapping) and bundle.get("bundle_id") is not None:
            expected_values["bundle_id"] = (
                bundle.get("bundle_id"),
                ("bundle_id", "target_bundle_id", "compiled_bundle_id"),
            )
        if isinstance(anchor, Mapping):
            for key in ("issue_time", "horizon", "step_seconds"):
                if anchor.get(key) is not None:
                    expected_values[key] = (
                        anchor.get(key),
                        (key, f"anchor_{key}", f"target_{key}"),
                    )
        elif anchor is not None:
            expected_values["anchor"] = (anchor, ("anchor", "anchor_ref", "target_anchor"))
        if isinstance(frame, Mapping) and frame.get("frame_id") is not None:
            expected_values["frame_id"] = (
                frame.get("frame_id"),
                ("frame_id", "target_frame_id", "assessment_frame_id"),
            )
        if isinstance(policy, Mapping):
            for key in ("policy_id", "policy_version"):
                if policy.get(key) is not None:
                    expected_values[key] = (
                        policy.get(key),
                        (key, f"target_{key}"),
                    )
        if not expected_values:
            return self._unknown("initial_context")

        def _binding_for(source: Any, *field_names: str, expected_kinds: tuple[str, ...]) -> str:
            return self._accepted_payload_identity_binding(
                source,
                *field_names,
                expected_kinds=expected_kinds,
                expected_values=expected_values,
            )

        def _accepted_binding(bindings: tuple[str, ...]) -> ValidationResult | None:
            if "conflict" in bindings:
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    "initial context proof targets different replay coordinates",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.ISSUE,
                )
            if "match" in bindings:
                return pass_validation(ValidationStage.GUARD_EVALUATE)
            return None

        admissions = tuple(bundle.get("admissions", ())) if isinstance(bundle, Mapping) else ()
        admission_bindings = tuple(
            self._accepted_payload_identity_binding(
                {"admission_ref": admission},
                "admission_ref",
                expected_kinds=("admission", "accepted_clause", "initial_context"),
                expected_values=expected_values,
            )
            for admission in admissions
        )
        accepted = _accepted_binding(admission_bindings)
        if accepted is not None:
            return accepted

        initial_context_binding = _binding_for(
            bundle,
            "initial_context",
            "initial_context_ref",
            "initial_context_proof",
            "initial_context_proof_ref",
            expected_kinds=("initial_context",),
        )
        accepted = _accepted_binding((initial_context_binding,))
        if accepted is not None:
            return accepted

        transcript_binding = _binding_for(
            policy,
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("initial_context", "checker_transcript"),
        )
        accepted = _accepted_binding((transcript_binding,))
        if accepted is not None:
            return accepted

        trust_binding = _binding_for(
            policy,
            "trust_assumption",
            "trust_assumption_ref",
            expected_kinds=("trust_assumption",),
        )
        accepted = _accepted_binding((trust_binding,))
        if accepted is not None:
            return accepted
        return self._unknown("initial_context")

    def representation_interface(self, bundle: Any, frame: Any, policy: Any) -> ValidationResult:
        from collections.abc import Mapping

        from dfcc.frame import representation_interface

        interface = representation_interface(bundle, frame, policy)
        explicit = bundle.get("representation_interface", {}) if isinstance(bundle, Mapping) else {}
        accepted_projection = self._accepted_digest_bound_field(
            explicit,
            "projection_coherence_proof",
            "projection_coherence_proof_ref",
            "representation_projection_coherence_proof",
            "representation_projection_coherence_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=(
                "representation_projection_coherence",
                "projection_coherence",
                "representation_interface",
                "checker_transcript",
            ),
        )
        if not accepted_projection:
            return self._unknown("representation_interface")
        return self.representation_projection_coherence(interface)

    def time_basis(self, clock_record: Any, timestamp_policy: Any) -> ValidationResult:
        from collections.abc import Mapping

        from dfcc.time import parse_time_basis

        try:
            basis = parse_time_basis(clock_record)
        except (KeyError, ValueError) as exc:
            return validation_failure(
                FailureCode.CLOCK_BOUNDARY_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                str(exc),
                status=ValidationStatus.UNKNOWN,
                layer=Layer.STATUS,
            )
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {
            "clock_id": (basis.clock_id, ("clock_id", "time_basis_ref", "clock")),
            "time_scale": (basis.time_scale, ("time_scale", "scale")),
            "uncertainty_seconds": (
                basis.uncertainty_seconds,
                ("uncertainty_seconds", "uncertainty", "clock_uncertainty_seconds"),
            ),
        }
        if basis.source is not None:
            expected_values["source"] = (basis.source, ("source", "time_source"))
        if basis.timestamp_policy is not None:
            expected_values["timestamp_policy"] = (
                basis.timestamp_policy,
                ("timestamp_policy", "timestamp_policy_ref"),
            )
        clock_binding = self._accepted_payload_identity_binding(
            clock_record,
            "time_basis_proof",
            "time_basis_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("time_basis", "clock", "timestamp_policy", "checker_transcript"),
            expected_values=expected_values,
        )
        policy_binding = self._accepted_payload_identity_binding(
            timestamp_policy,
            "time_basis_proof",
            "time_basis_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("time_basis", "clock", "timestamp_policy", "checker_transcript"),
            expected_values=expected_values,
        )
        if "conflict" in {clock_binding, policy_binding}:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "time basis proof conflicts with parsed clock record",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
            )
        if "match" in {clock_binding, policy_binding}:
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        if isinstance(clock_record, Mapping) or isinstance(timestamp_policy, Mapping):
            return validation_failure(
                FailureCode.CHECKER_UNKNOWN,
                ValidationStage.GUARD_EVALUATE,
                "time basis lacks accepted clock proof or checker transcript",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.STATUS,
                source_artifact=str(
                    clock_record.get("clock_id", "artifact:time-basis")
                    if isinstance(clock_record, Mapping)
                    else "artifact:time-basis"
                ),
                source_path="/time_basis_proof_ref",
            )
        return self._unknown("time_basis")

    def event_order(self, events: Any, order_policy: Any, log_commitments: Any) -> ValidationResult:
        from collections.abc import Mapping

        from dfcc.lifecycle import EventOrder, FoldContext, LifecycleEvent, fold_status

        expected_event_order_kinds = (
            "event_order",
            "event-order",
            "accepted_event_set",
            "causal_cut",
            "trace_class",
            "log_root",
        )
        accepted_event_order = self._accepted_digest_bound_field(
            order_policy,
            "event_order",
            "event_order_ref",
            "event_order_proof",
            "event_order_proof_ref",
            "accepted_event_ids_status",
            "accepted_event_ids_ref",
            "causal_cut_ref",
            "trace_class_ref",
            "empty_event_set_proof",
            "empty_event_set_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=expected_event_order_kinds,
        ) or self._accepted_digest_bound_field(
            log_commitments,
            "log_root",
            "log_root_ref",
            "event_order",
            "event_order_ref",
            "event_order_proof",
            "event_order_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=expected_event_order_kinds,
        )
        event_items = tuple(events)
        if not event_items:
            if (
                isinstance(order_policy, Mapping)
                and order_policy.get("allow_empty", False)
                and accepted_event_order
            ):
                return pass_validation(ValidationStage.REPLAY)
            return self._unknown("event_order")
        try:
            parsed = tuple(
                item if isinstance(item, LifecycleEvent) else LifecycleEvent.from_json(item)
                for item in event_items
            )
        except (KeyError, TypeError, ValueError) as exc:
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.REPLAY,
                str(exc),
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
            )
        accepted_ids: tuple[str, ...] = ()
        if isinstance(order_policy, Mapping):
            accepted_ids = tuple(str(item) for item in order_policy.get("accepted_event_ids", ()))
        log_root: str | None = None
        if isinstance(log_commitments, Mapping):
            root_value = log_commitments.get("log_root")
            log_root = str(root_value) if root_value is not None else None
        folded = fold_status(
            parsed[0].certificate_id,
            parsed,
            EventOrder(accepted_event_ids=accepted_ids, log_root=log_root),
            FoldContext(policy_version="default"),
        )
        if folded.dominant_status.value == "conflict":
            return validation_failure(
                FailureCode.TRACE_CONFLICT,
                ValidationStage.REPLAY,
                "event order replay produced trace conflict",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
            )
        if not accepted_event_order:
            return self._unknown("event_order")
        return pass_validation(ValidationStage.REPLAY)

    def observation_cut(
        self,
        records: Any,
        status_time: Any,
        time_basis: Any,
        event_order: Any,
        dependencies: Any,
        frame: Any,
    ) -> ValidationResult:
        del dependencies
        if records is None or status_time is None or time_basis is None or event_order is None:
            return self._unknown("observation_cut")
        if not isinstance(frame, dict) or frame.get("frame_id") is None:
            return self._unknown("observation_cut")
        record_items = tuple(records)
        if not record_items:
            return self._unknown("observation_cut")
        required = {"calibration_ref", "latency_ref", "dependency_ref", "event_order_ref"}
        expected_kinds = {
            "calibration_ref": ("calibration",),
            "latency_ref": ("latency",),
            "dependency_ref": ("dependency",),
            "event_order_ref": ("event_order", "event-order"),
        }
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {
            "status_time": (status_time, ("status_time", "observation_time", "time")),
            "time_basis": (time_basis, ("time_basis", "time_basis_ref", "clock", "clock_basis")),
            "event_order": (event_order, ("event_order", "event_order_ref", "order")),
            "frame_id": (
                frame.get("frame_id"),
                ("frame_id", "target_frame_id", "assessment_frame_id"),
            ),
        }
        for record in record_items:
            if not isinstance(record, dict):
                return self._unknown("observation_cut")
            proof_binding = self._accepted_payload_identity_binding(
                record,
                "observation_proof",
                "observation_proof_ref",
                expected_kinds=("observation_cut", "observation"),
                expected_values={
                    "status_time": (
                        status_time,
                        ("status_time", "observation_time", "time"),
                    ),
                    "time_basis": (time_basis, ("time_basis", "clock", "clock_basis")),
                    "event_order": (event_order, ("event_order", "event_order_ref", "order")),
                    "frame_id": (
                        frame.get("frame_id"),
                        ("frame_id", "target_frame_id", "assessment_frame_id"),
                    ),
                },
            )
            if proof_binding == "conflict":
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    "observation cut proof targets different cut coordinates",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.OPERATIONAL,
                )
            if proof_binding == "match":
                continue
            if not required.issubset(record) or not all(
                self._accepted_digest_bound_evidence(
                    record.get(key),
                    expected_kinds=expected_kinds[key],
                )
                for key in required
            ):
                return self._unknown("observation_cut")
            for key in ("calibration_ref", "latency_ref", "dependency_ref", "event_order_ref"):
                proof_binding = self._accepted_payload_identity_binding(
                    record,
                    key,
                    expected_kinds=expected_kinds[key],
                    expected_values=expected_values,
                )
                if proof_binding == "conflict":
                    return validation_failure(
                        FailureCode.ARTIFACT_CONFLICT,
                        ValidationStage.GUARD_EVALUATE,
                        f"observation cut {key} proof targets different cut coordinates",
                        status=ValidationStatus.CONFLICT,
                        layer=Layer.OPERATIONAL,
                    )
                if proof_binding != "match":
                    return self._unknown("observation_cut")
        return pass_validation(ValidationStage.GUARD_EVALUATE)

    def status_observation_context(
        self, certificate: Any, observation_cut: Any, policy: Any
    ) -> ValidationResult:
        del certificate
        if (
            observation_cut is None
            or not isinstance(policy, dict)
            or "r" not in policy
            or getattr(observation_cut, "prefix_view", None) is None
            or (
                policy.get("status_observation_context_ref") is None
                and policy.get("checker_transcript_ref") is None
            )
        ):
            return self._unknown("status_observation_context")
        if not self._accepted_digest_bound_field(
            policy,
            "status_observation_context",
            "status_observation_context_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("status_observation_context",),
        ):
            return self._unknown("status_observation_context")
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {
            "r": (policy.get("r"), ("r", "prefix_index", "residual_index"))
        }
        status_time = getattr(observation_cut, "status_time", None)
        if status_time is not None:
            expected_values["status_time"] = (
                status_time,
                ("status_time", "observation_time", "time"),
            )
        time_basis_ref = getattr(observation_cut, "time_basis_ref", None)
        if time_basis_ref is not None:
            expected_values["time_basis_ref"] = (
                time_basis_ref,
                ("time_basis_ref", "time_basis", "clock", "clock_basis"),
            )
        event_order_ref = getattr(observation_cut, "event_order_ref", None)
        if event_order_ref is not None:
            expected_values["event_order_ref"] = (
                event_order_ref,
                ("event_order_ref", "event_order", "order"),
            )
        frame_id = getattr(observation_cut, "frame_id", None)
        if frame_id is not None:
            expected_values["frame_id"] = (
                frame_id,
                ("frame_id", "target_frame_id", "assessment_frame_id"),
            )
        binding = self._accepted_payload_identity_binding(
            policy,
            "status_observation_context",
            "status_observation_context_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("status_observation_context",),
            expected_values=expected_values,
        )
        if binding == "conflict":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "status observation context transcript targets a different residual index",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
            )
        if binding != "match":
            return self._unknown("status_observation_context")
        return pass_validation(ValidationStage.GUARD_EVALUATE)

    def operational_prefix_fiber(
        self, observation_cut: Any, frame: Any, index: int
    ) -> ValidationResult:
        from dfcc.frame import operational_prefix_fiber

        records = tuple(getattr(observation_cut, "records", ()))
        proof_bindings = tuple(
            self._accepted_payload_binding(
                record,
                "operational_prefix_fiber_proof",
                "operational_prefix_fiber_proof_ref",
                "prefix_fiber_proof",
                "prefix_fiber_proof_ref",
                "checker_transcript",
                "checker_transcript_ref",
                expected_kinds=(
                    "operational_prefix_fiber",
                    "operational-prefix-fiber",
                    "prefix_fiber",
                    "prefix-fiber",
                ),
                payload_fields=(
                    "operational_prefix_fiber",
                    "prefix_fiber",
                    "fiber_status",
                    "status",
                    "result",
                ),
                expected_value="pass",
            )
            for record in records
        )
        if "conflict" in proof_bindings:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "operational prefix fiber proof conflicts with computed fiber status",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        if "match" not in proof_bindings:
            return self._unknown("operational_prefix_fiber")
        fiber = operational_prefix_fiber(observation_cut, frame, index)
        if fiber.status == "pass":
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return ValidationResult(
            ValidationStage.GUARD_EVALUATE, ValidationStatus.UNKNOWN, reason_refs=fiber.reason_refs
        )

    def operational_completion_fiber(
        self, prefix_record: Any, frame: Any, residual_context: Any
    ) -> ValidationResult:
        from dfcc.frame import operational_completion_fiber

        binding = self._accepted_payload_binding(
            prefix_record,
            "operational_completion_fiber_proof",
            "operational_completion_fiber_proof_ref",
            "completion_fiber_proof",
            "completion_fiber_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=(
                "operational_completion_fiber",
                "operational-completion-fiber",
                "completion_fiber",
                "completion-fiber",
            ),
            payload_fields=(
                "operational_completion_fiber",
                "completion_fiber",
                "fiber_status",
                "status",
                "result",
            ),
            expected_value="pass",
        )
        if binding == "conflict":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "operational completion fiber proof conflicts with computed fiber status",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        if binding == "missing":
            return self._unknown("operational_completion_fiber")
        fiber = operational_completion_fiber(prefix_record, frame, residual_context)
        if fiber.status == "pass":
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return ValidationResult(
            ValidationStage.GUARD_EVALUATE, ValidationStatus.UNKNOWN, reason_refs=fiber.reason_refs
        )

    def completion_admission(
        self, prefix_context: Any, completion_interface: Any, policy: Any
    ) -> ValidationResult:
        from dfcc.frame import completion_admission

        result = completion_admission(prefix_context, completion_interface, policy)
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {
            "completion_status": (
                result.completion_status,
                ("completion_status", "status", "result"),
            ),
            "reference_digest": (result.reference_digest, ("reference_digest",)),
            "checker_result": (result.checker_result, ("checker_result",)),
            "admission_source": (result.admission_source, ("admission_source",)),
            "expiry": (result.expiry, ("expiry",)),
            "uncertainty_model": (result.uncertainty_model, ("uncertainty_model",)),
        }
        if result.c_out_ref is not None:
            expected_values["c_out_ref"] = (result.c_out_ref, ("c_out_ref", "completion_set_ref"))
        if result.c_in_ref is not None:
            expected_values["c_in_ref"] = (
                result.c_in_ref,
                ("c_in_ref", "completion_inner_set_ref"),
            )
        if isinstance(policy, Mapping) and policy.get("status_time") is not None:
            expected_values["status_time"] = (policy["status_time"], ("status_time",))
        interface_id = getattr(completion_interface, "interface_id", None)
        if interface_id is None and isinstance(completion_interface, Mapping):
            interface_id = completion_interface.get("interface_id")
        if interface_id is not None:
            expected_values["completion_interface_id"] = (
                interface_id,
                ("completion_interface_id", "interface_id"),
            )
        prefix_index = getattr(prefix_context, "r", None)
        if prefix_index is None and isinstance(prefix_context, Mapping):
            prefix_index = prefix_context.get("r")
        if prefix_index is not None:
            expected_values["r"] = (prefix_index, ("r", "prefix_index", "residual_index"))
        transcript_binding = self._accepted_payload_identity_binding(
            policy,
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("completion_admission", "completion", "checker_transcript"),
            expected_values=expected_values,
        )
        proof_binding = self._accepted_payload_identity_binding(
            policy,
            "completion_admission_proof",
            "completion_admission_proof_ref",
            expected_kinds=("completion_admission", "completion"),
            expected_values=expected_values,
        )
        if "conflict" in {transcript_binding, proof_binding}:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "completion admission proof conflicts with computed admission identity",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        if result.passed and "match" in {transcript_binding, proof_binding}:
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return validation_failure(
            FailureCode.COMPLETION_MISSING,
            ValidationStage.GUARD_EVALUATE,
            "completion admission did not pass",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
        )

    def representation_projection_coherence(
        self, representation_interface: Any
    ) -> ValidationResult:
        obligations = tuple(getattr(representation_interface, "obligations", ()))
        accepted_obligation = any(
            self._bound_artifact_pointer_or_digest(str(obligation)) for obligation in obligations
        )
        if getattr(representation_interface, "projection_coherence", False) and accepted_obligation:
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return validation_failure(
            FailureCode.CHECKER_UNKNOWN,
            ValidationStage.GUARD_EVALUATE,
            "representation projection coherence is not accepted",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
        )

    def prefix_admission(self, observation_cut: Any, bundle: Any, anchor: Any) -> ValidationResult:
        from dfcc.frame import admit_prefix

        records = tuple(getattr(observation_cut, "records", ()))
        if not records:
            return self._unknown("prefix_admission")
        accepted_admission = any(
            self._accepted_digest_bound_field(
                record,
                "prefix_admission_proof",
                "prefix_admission_proof_ref",
                "checker_transcript",
                "checker_transcript_ref",
                expected_kinds=("prefix_admission", "prefix-admission"),
            )
            for record in records
        )
        if not accepted_admission:
            return self._unknown("prefix_admission")
        view = admit_prefix(observation_cut, bundle, anchor, {"r": 0})
        if view.prefix_status == "pass":
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return ValidationResult(
            ValidationStage.GUARD_EVALUATE, ValidationStatus.UNKNOWN, reason_refs=view.reason_refs
        )

    def prefix_soundness(
        self, prefix_view: Any, observation_cut: Any, frame: Any
    ) -> ValidationResult:
        del observation_cut, frame
        from collections.abc import Mapping

        prefix_status = (
            prefix_view.get("prefix_status")
            if isinstance(prefix_view, Mapping)
            else getattr(prefix_view, "prefix_status", None)
        )
        if prefix_status == "pass":
            binding = self._accepted_payload_binding(
                prefix_view,
                "prefix_soundness_proof",
                "prefix_soundness_proof_ref",
                "checker_transcript",
                "checker_transcript_ref",
                expected_kinds=("prefix_soundness", "prefix-soundness", "prefix"),
                payload_fields=(
                    "prefix_soundness",
                    "prefix_status",
                    "status",
                    "result",
                ),
                expected_value="pass",
            )
            if binding == "conflict":
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    "prefix soundness proof conflicts with prefix status",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.OPERATIONAL,
                )
            if binding == "missing":
                return self._unknown("prefix_soundness")
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return validation_failure(
            FailureCode.PREFIX_UNSOUND,
            ValidationStage.GUARD_EVALUATE,
            "prefix view did not pass",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
        )

    def residual_context(
        self, certificate: Any, status_time: Any, prefix_view: Any, exact_prefix_set: Any
    ) -> ValidationResult:
        del certificate, status_time, exact_prefix_set
        from collections.abc import Mapping

        prefix_status = (
            prefix_view.get("prefix_status")
            if isinstance(prefix_view, Mapping)
            else getattr(prefix_view, "prefix_status", None)
        )
        if prefix_status == "pass":
            binding = self._accepted_payload_binding(
                prefix_view,
                "residual_context_proof",
                "residual_context_proof_ref",
                "checker_transcript",
                "checker_transcript_ref",
                expected_kinds=("residual_context", "residual-context"),
                payload_fields=(
                    "residual_context",
                    "residual_context_status",
                    "status",
                    "result",
                ),
                expected_value="pass",
            )
            if binding == "conflict":
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    "residual context proof conflicts with prefix status",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.OPERATIONAL,
                )
            if binding == "missing":
                return self._unknown("residual_context")
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return self._unknown("residual_context")

    def checked_assoc_view(
        self,
        observation_record: Any,
        claim: Any,
        compiled_bundle: Any,
        residual_context: Any,
        frame: Any,
    ) -> ValidationResult:
        from dfcc.frame import checked_assoc_view

        view = checked_assoc_view(
            observation_record, claim, compiled_bundle, residual_context, frame
        )
        if view.assoc_status.value in {"positive", "negative"}:
            binding = self._accepted_payload_binding(
                observation_record,
                "checked_assoc_view_proof",
                "checked_assoc_view_proof_ref",
                "fiber_assoc_proof",
                "fiber_assoc_proof_ref",
                "checker_transcript",
                "checker_transcript_ref",
                expected_kinds=(
                    "checked_assoc_view",
                    "checked-assoc-view",
                    "fiber_assoc",
                    "fiber-assoc",
                    "association",
                ),
                payload_fields=(
                    "assoc_status",
                    "fiber_status",
                    "fiber_assoc",
                    "checked_assoc_view",
                    "association_status",
                    "result",
                ),
                expected_value=view.assoc_status.value,
            )
            if binding == "missing":
                return self._unknown("checked_assoc_view")
            if binding == "conflict":
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    "checked association proof conflicts with computed association status",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.OPERATIONAL,
                )
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return validation_failure(
            FailureCode.ASSOC_MIXED
            if view.assoc_status.value == "mixed"
            else FailureCode.ASSOC_EMPTY,
            ValidationStage.GUARD_EVALUATE,
            f"association status is {view.assoc_status.value}",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
        )

    def exact_fiber_assoc(
        self,
        observation_record: Any,
        claim: Any,
        compiled_bundle: Any,
        residual_context: Any,
        frame: Any,
    ) -> ValidationResult:
        del claim, compiled_bundle, frame
        if not residual_context.adm_star.is_empty():
            binding = self._accepted_payload_binding(
                observation_record,
                "exact_fiber_assoc_proof",
                "exact_fiber_assoc_proof_ref",
                "fiber_assoc_proof",
                "fiber_assoc_proof_ref",
                "checker_transcript",
                "checker_transcript_ref",
                expected_kinds=(
                    "exact_fiber_assoc",
                    "exact-fiber-assoc",
                    "fiber_assoc",
                    "fiber-assoc",
                    "association",
                ),
                payload_fields=(
                    "exact_fiber_assoc",
                    "fiber_assoc",
                    "association_status",
                    "result",
                    "nonempty",
                ),
                expected_value="nonempty",
            )
            if binding == "missing":
                return self._unknown("exact_fiber_assoc")
            if binding == "conflict":
                proof_truth = self._accepted_payload_binding(
                    observation_record,
                    "exact_fiber_assoc_proof",
                    "exact_fiber_assoc_proof_ref",
                    "fiber_assoc_proof",
                    "fiber_assoc_proof_ref",
                    "checker_transcript",
                    "checker_transcript_ref",
                    expected_kinds=(
                        "exact_fiber_assoc",
                        "exact-fiber-assoc",
                        "fiber_assoc",
                        "fiber-assoc",
                        "association",
                    ),
                    payload_fields=("nonempty",),
                    expected_value=True,
                )
                if proof_truth != "match":
                    return validation_failure(
                        FailureCode.ARTIFACT_CONFLICT,
                        ValidationStage.GUARD_EVALUATE,
                        "exact fiber association proof conflicts with nonempty association",
                        status=ValidationStatus.CONFLICT,
                        layer=Layer.OPERATIONAL,
                    )
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return validation_failure(
            FailureCode.ASSOC_EMPTY,
            ValidationStage.GUARD_EVALUATE,
            "exact fiber association is empty",
            status=ValidationStatus.UNKNOWN,
            layer=Layer.OPERATIONAL,
        )

    def fiber_assoc_view(
        self,
        observation_record: Any,
        claim: Any,
        compiled_bundle: Any,
        residual_context: Any,
        frame: Any,
    ) -> ValidationResult:
        return self.checked_assoc_view(
            observation_record, claim, compiled_bundle, residual_context, frame
        )

    def prefix_adjudication(self, observation_record: Any, frame: Any) -> ValidationResult:
        from dfcc.frame import prefix_adjudication

        code = prefix_adjudication(observation_record, frame)
        if code.value != "accept":
            return self._unknown("prefix_adjudication")
        frame_id = (
            frame.get("frame_id") if isinstance(frame, dict) else getattr(frame, "frame_id", None)
        )
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {
            "prefix_adjudication": (
                code.value,
                ("prefix_adjudication", "prefix", "adjudication", "result", "decision"),
            )
        }
        if frame_id is not None:
            expected_values["frame_id"] = (
                frame_id,
                ("frame_id", "target_frame_id", "assessment_frame_id"),
            )
        binding = self._accepted_payload_identity_binding(
            observation_record,
            "prefix_adjudication_proof",
            "prefix_adjudication_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("prefix_adjudication", "prefix-adjudication"),
            expected_values=expected_values,
        )
        if binding == "match":
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        if binding == "conflict":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "prefix adjudication proof conflicts with computed adjudication",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        return self._unknown("prefix_adjudication")

    def usage_adjudication(self, proposed_use: Any, frame: Any, policy: Any) -> ValidationResult:
        from dfcc.frame import usage_adjudication

        code = usage_adjudication(proposed_use, frame, policy)
        frame_id = (
            frame.get("frame_id") if isinstance(frame, dict) else getattr(frame, "frame_id", None)
        )
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {
            "usage_adjudication": (
                code.value,
                ("usage_adjudication", "usage", "adjudication", "result", "decision"),
            )
        }
        if isinstance(proposed_use, dict):
            mode = proposed_use.get("mode")
            if mode is not None:
                expected_values["mode"] = (mode, ("mode", "use_mode"))
        if frame_id is not None:
            expected_values["frame_id"] = (
                frame_id,
                ("frame_id", "target_frame_id", "assessment_frame_id"),
            )
        policy_binding = self._accepted_payload_identity_binding(
            policy,
            "usage_adjudication_proof",
            "usage_adjudication_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("usage_adjudication", "usage-adjudication"),
            expected_values=expected_values,
        )
        proposed_binding = self._accepted_payload_identity_binding(
            proposed_use,
            "usage_adjudication_proof",
            "usage_adjudication_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("usage_adjudication", "usage-adjudication"),
            expected_values=expected_values,
        )
        if code.value == "accept" and "match" in {policy_binding, proposed_binding}:
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        if "conflict" in {policy_binding, proposed_binding}:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "usage adjudication proof conflicts with computed adjudication",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        status = ValidationStatus.CONFLICT if code.value == "reject" else ValidationStatus.UNKNOWN
        return ValidationResult(ValidationStage.GUARD_EVALUATE, status)

    def target_adjudication(
        self, observation_record: Any, target_condition: Any, frame: Any
    ) -> ValidationResult:
        from dfcc.frame import target_adjudication

        code = target_adjudication(observation_record, target_condition, frame)
        if code.value not in {"accept", "reject"}:
            return self._unknown("target_adjudication")
        frame_id = (
            frame.get("frame_id") if isinstance(frame, dict) else getattr(frame, "frame_id", None)
        )
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {
            "target_adjudication": (
                code.value,
                ("target_adjudication", "target", "adjudication", "result", "decision"),
            )
        }
        if frame_id is not None:
            expected_values["frame_id"] = (
                frame_id,
                ("frame_id", "target_frame_id", "assessment_frame_id"),
            )
        if isinstance(target_condition, dict):
            target_id = target_condition.get("target_id", target_condition.get("condition_id"))
            if target_id is not None:
                expected_values["target_id"] = (target_id, ("target_id", "condition_id"))
        binding = self._accepted_payload_identity_binding(
            observation_record,
            "target_adjudication_proof",
            "target_adjudication_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("target_adjudication", "target-adjudication"),
            expected_values=expected_values,
        )
        if binding == "match":
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        if binding == "conflict":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "target adjudication proof conflicts with computed adjudication",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        return self._unknown("target_adjudication")

    def agreement(
        self,
        kernel_view: Any,
        fiber_assoc_view: Any,
        adjudication_views: Any,
        adequacy: Any,
        blocking_set: Any,
        policy_gate: Any,
    ) -> ValidationResult:
        if blocking_set:
            return validation_failure(
                FailureCode.POLICY_BLOCK,
                ValidationStage.GUARD_EVALUATE,
                "blocking set is nonempty",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.POLICY,
            )
        if policy_gate.value != "allow":
            return validation_failure(
                FailureCode.POLICY_BLOCK,
                ValidationStage.GUARD_EVALUATE,
                "policy gate is not allow",
                status=ValidationStatus.UNKNOWN,
                layer=Layer.POLICY,
            )
        kernel_direction = getattr(kernel_view, "direction", None)
        assoc_status = getattr(fiber_assoc_view, "fiber_status", None)
        adequacy_direction = getattr(adequacy, "value", adequacy)
        prefix = getattr(adjudication_views, "prefix", None)
        usage = getattr(adjudication_views, "usage", None)
        target = getattr(adjudication_views, "target", None)
        proof_ref = getattr(adjudication_views, "agreement_proof_ref", None)
        if isinstance(adjudication_views, dict):
            proof_ref = adjudication_views.get("agreement_proof_ref")
            prefix = adjudication_views.get("prefix", prefix)
            usage = adjudication_views.get("usage", usage)
            target = adjudication_views.get("target", target)
        kernel_direction_value = getattr(kernel_direction, "value", kernel_direction)
        assoc_status_value = getattr(assoc_status, "value", assoc_status)
        prefix_value = getattr(prefix, "value", prefix)
        usage_value = getattr(usage, "value", usage)
        target_value = getattr(target, "value", target)
        if not self._accepted_digest_bound_evidence(
            proof_ref,
            expected_kinds=("agreement", "agreement_proof"),
        ):
            return self._unknown("agreement")
        if any(
            item is None
            for item in (
                kernel_direction_value,
                assoc_status_value,
                adequacy_direction,
                prefix_value,
                usage_value,
                target_value,
            )
        ):
            return self._unknown("agreement")
        proof_requirements = {
            "kernel_direction": str(kernel_direction_value),
            "assoc_direction": str(assoc_status_value),
            "adequacy_direction": str(adequacy_direction),
            "prefix": str(prefix_value),
            "usage": str(usage_value),
            "target": str(target_value),
            "gate_decision": str(policy_gate.value),
        }
        for field_name, expected_value in proof_requirements.items():
            proof_value = self._accepted_payload_value(
                proof_ref,
                field_name,
                expected_kinds=("agreement", "agreement_proof"),
            )
            if proof_value is None:
                return self._unknown("agreement")
            if str(proof_value) != expected_value:
                return validation_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    ValidationStage.GUARD_EVALUATE,
                    f"agreement proof {field_name} conflicts with checker inputs",
                    status=ValidationStatus.CONFLICT,
                    layer=Layer.OPERATIONAL,
                )
        positive = (
            str(kernel_direction_value) == "positive"
            and str(assoc_status_value) == "positive"
            and str(adequacy_direction) == "positive"
            and str(prefix_value) == "accept"
            and str(usage_value) == "accept"
            and str(target_value) == "accept"
        )
        negative = (
            str(kernel_direction_value) == "negative"
            and str(assoc_status_value) == "negative"
            and str(adequacy_direction) == "negative"
            and str(prefix_value) == "accept"
            and str(usage_value) == "accept"
            and str(target_value) == "reject"
        )
        if positive or negative:
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.GUARD_EVALUATE,
            "agreement directions are inconsistent",
            status=ValidationStatus.CONFLICT,
            layer=Layer.OPERATIONAL,
        )

    def typed_authority_outcome(
        self,
        status_view: Any,
        kernel_view: Any,
        agreement: Any,
        blocking_set: Any,
        gate_decision: Any,
    ) -> ValidationResult:
        from collections.abc import Mapping

        del kernel_view
        if not isinstance(status_view, Mapping):
            return self._unknown("typed_authority_outcome")
        outcome = status_view.get("authority_outcome")
        if not isinstance(outcome, Mapping):
            return self._unknown("typed_authority_outcome")
        schema_ref = status_view.get("outcome_schema_ref", outcome.get("outcome_schema_ref"))
        if not self._authority_outcome_schema_ref(schema_ref):
            return self._unknown("typed_authority_outcome")
        layer_value = str(outcome.get("layer", status_view.get("layer", "")))
        code = str(outcome.get("code", ""))
        direction_value = str(outcome.get("direction", status_view.get("direction", "")))
        try:
            layer = Layer(layer_value)
            direction = Direction(direction_value)
        except ValueError:
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.AUTHORITY_EMIT,
                "authority outcome layer or direction is outside the normative table",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
            )
        allowed_directions = ALLOWED_OUTCOME_DIRECTIONS.get(layer, {}).get(code)
        if allowed_directions is None or direction not in allowed_directions:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "authority outcome layer/code/direction violates the normative table",
                status=ValidationStatus.CONFLICT,
                layer=layer,
            )
        reasons = tuple(
            status_view.get(
                "reason_ref_records",
                status_view.get("reason_refs", outcome.get("reason_ref_records", ())),
            )
        )
        blocks = tuple(
            blocking_set
            or status_view.get("blocking_records")
            or status_view.get("blocking_set")
            or outcome.get("blocking_records")
            or outcome.get("blocking_set")
            or ()
        )
        obligation_refs = tuple(status_view.get("obligation_refs", ()))
        obligation_records = tuple(status_view.get("obligation_ref_records", ()))
        status_time = (
            outcome.get("issued_at_status_time")
            or status_view.get("status_time")
            or status_view.get("issued_at_status_time")
        )
        if obligation_refs and not obligation_records:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "authority obligation refs lack typed obligation records",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
                source_path="/obligation_ref_records",
            )
        from dfcc.artifacts import ObligationRefRecord

        for index, record in enumerate(obligation_records):
            if not isinstance(record, Mapping):
                return validation_failure(
                    FailureCode.SCHEMA_INVALID,
                    ValidationStage.AUTHORITY_EMIT,
                    "authority obligation record is not an object",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.STATUS,
                    source_path=f"/obligation_ref_records/{index}",
                )
            try:
                obligation = ObligationRefRecord.from_json(record)
            except (KeyError, TypeError, ValueError):
                return validation_failure(
                    FailureCode.SCHEMA_INVALID,
                    ValidationStage.AUTHORITY_EMIT,
                    "authority obligation record is not schema-valid",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.STATUS,
                    source_path=f"/obligation_ref_records/{index}",
                )
            active_status = obligation.active_scope_status_at(
                str(status_time) if status_time is not None else None
            )
            if active_status not in {"pass", "waived"}:
                failure_code = (
                    FailureCode.VALIDITY_UNKNOWN
                    if active_status in {"expired", "invalid"}
                    else FailureCode.CHECKER_UNKNOWN
                )
                return validation_failure(
                    failure_code,
                    ValidationStage.AUTHORITY_EMIT,
                    f"authority obligation record is {active_status}",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.STATUS,
                    source_path=f"/obligation_ref_records/{index}/status",
                )
            if active_status == "pass" and (
                not self._bound_artifact_ref(obligation.source_artifact)
                or not str(obligation.source_path or "").startswith("/")
                or not self._bound_digest(obligation.digest)
            ):
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.AUTHORITY_EMIT,
                    "authority pass obligation lacks artifact, pointer, or digest evidence",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.STATUS,
                    source_path=f"/obligation_ref_records/{index}",
                )
            waiver_reasons = obligation.reason_refs
            if active_status == "waived" and not waiver_reasons:
                return validation_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    ValidationStage.AUTHORITY_EMIT,
                    "authority waived obligation record lacks reason refs",
                    status=ValidationStatus.UNKNOWN,
                    layer=Layer.STATUS,
                    source_path=f"/obligation_ref_records/{index}/reason_refs",
                )
            if active_status == "waived" and (
                not isinstance(waiver_reasons, list | tuple)
                or not all(isinstance(reason, str) and reason for reason in waiver_reasons)
            ):
                return validation_failure(
                    FailureCode.SCHEMA_INVALID,
                    ValidationStage.AUTHORITY_EMIT,
                    "authority waived obligation reason refs are not typed ids",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.STATUS,
                    source_path=f"/obligation_ref_records/{index}/reason_refs",
                )
        proof_refs = tuple(status_view.get("proof_refs", ()))
        proof_records = tuple(status_view.get("proof_ref_records", ()))
        if proof_refs and not proof_records:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "authority proof refs lack typed proof records",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
                source_path="/proof_ref_records",
            )
        proof_record_ids = tuple(
            str(record.get("proof_id", ""))
            if isinstance(record, Mapping)
            else str(getattr(record, "proof_id", ""))
            for record in proof_records
        )
        if proof_refs and not {str(ref) for ref in proof_refs}.issubset(set(proof_record_ids)):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "authority proof refs are not covered by typed proof records",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
                source_path="/proof_ref_records",
            )
        for index, record in enumerate(proof_records):
            if not self._typed_proof_ref(record):
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.AUTHORITY_EMIT,
                    "authority proof record lacks digest-bound proof evidence",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.STATUS,
                    source_path=f"/proof_ref_records/{index}",
                )
        decisive_codes = {"allow", "accept", "reject", "assert", "deny", "infeasible", "active"}
        allow_codes = {"allow", "accept", "assert", "active"}
        reason_required = code not in allow_codes
        blocking_required = code not in decisive_codes
        dominant_status = str(status_view.get("dominant_status", ""))
        status_routed_codes = {
            "expired",
            "revoked",
            "superseded",
            "invalid",
            "conflict",
            "out_of_frame",
            "unknown",
        }
        if dominant_status in status_routed_codes and (
            layer is not Layer.STATUS or code != dominant_status or direction is not Direction.NONE
        ):
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "authority outcome conflicts with dominant status routing",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
            )
        if code in allow_codes and blocks:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "allow authority outcome carries blocking records",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
            )
        gate_value = getattr(gate_decision, "value", gate_decision)
        if gate_value is None:
            gate_value = outcome.get("gate_decision", status_view.get("gate_decision"))
        if gate_value not in {None, "allow", "block", "unknown"}:
            return validation_failure(
                FailureCode.SCHEMA_INVALID,
                ValidationStage.AUTHORITY_EMIT,
                "authority outcome gate decision is outside the normative table",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.POLICY,
            )
        if gate_value in {"block", "unknown"} and code in decisive_codes:
            return validation_failure(
                FailureCode.POLICY_BLOCK,
                ValidationStage.AUTHORITY_EMIT,
                "decisive authority outcome conflicts with policy gate",
                status=ValidationStatus.CONFLICT,
                layer=Layer.POLICY,
            )
        if code in allow_codes and gate_value not in {None, "allow"}:
            return validation_failure(
                FailureCode.POLICY_BLOCK,
                ValidationStage.AUTHORITY_EMIT,
                "allow authority outcome conflicts with policy gate",
                status=ValidationStatus.CONFLICT,
                layer=Layer.POLICY,
            )
        agreement_status = getattr(agreement, "agreement_status", None)
        if isinstance(agreement, Mapping):
            agreement_status = agreement.get("agreement_status", agreement_status)
        agreement_status_value = getattr(agreement_status, "value", agreement_status)
        if agreement_status_value == "positive" and code not in {"accept", "allow"}:
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "positive agreement conflicts with authority outcome",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        if agreement_status_value == "negative" and code != "reject":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "negative agreement conflicts with authority outcome",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        if code == "accept" and agreement_status_value is None:
            return self._unknown("typed_authority_outcome")
        if code == "accept" and agreement_status_value != "positive":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "operational accept lacks positive agreement",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        if code == "reject" and agreement_status_value is None:
            return self._unknown("typed_authority_outcome")
        if code == "reject" and agreement_status_value != "negative":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.AUTHORITY_EMIT,
                "operational reject lacks negative agreement",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        if reason_required and not reasons:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "non-allow authority outcome lacks reason refs",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
            )
        if blocking_required and not blocks:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "non-decisive authority outcome lacks blocking records",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
                source_path="/blocking_records",
            )
        if blocks and not all(self._typed_blocking_record(item) for item in blocks):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "non-allow authority outcome blocking records are not typed",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
            )
        if reason_required and not all(self._typed_reason_ref(item) for item in reasons):
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.AUTHORITY_EMIT,
                "non-allow authority outcome reason refs are not typed artifact pointers",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.STATUS,
            )
        return pass_validation(ValidationStage.AUTHORITY_EMIT)

    def status_confluence(
        self, status_coordinates: Any, blocking_sets: Any, event_order: Any
    ) -> ValidationResult:
        del status_coordinates
        blocks = tuple(blocking_sets)
        confluence_proof = getattr(event_order, "confluence_proof", None)
        from collections.abc import Mapping

        from dfcc.lifecycle import CONFLUENCE_PROOF_KINDS

        if self._accepted_digest_bound_evidence(
            confluence_proof,
            expected_kinds=CONFLUENCE_PROOF_KINDS,
        ):
            payload = (
                confluence_proof.get("payload", confluence_proof)
                if isinstance(confluence_proof, Mapping)
                else {}
            )
            covered_sets = payload.get("blocking_sets", payload.get("trace_blocking_sets"))
            normalized_blocks = tuple(tuple(str(item) for item in block) for block in blocks)
            normalized_covered = (
                tuple(tuple(str(item) for item in block) for block in covered_sets)
                if isinstance(covered_sets, tuple | list)
                else ()
            )
            if not blocks or set(normalized_blocks).issubset(set(normalized_covered)):
                return pass_validation(ValidationStage.REPLAY)
            return validation_failure(
                FailureCode.TRACE_CONFLICT,
                ValidationStage.REPLAY,
                "confluence proof does not cover the blocking status traces",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
            )
        if len(blocks) > 1:
            return validation_failure(
                FailureCode.TRACE_CONFLICT,
                ValidationStage.REPLAY,
                "multiple status traces require a resolved confluence proof",
                status=ValidationStatus.CONFLICT,
                layer=Layer.STATUS,
            )
        return self._unknown("status_confluence")

    def enclosure_soundness(self, enclosure: EnclosureResult) -> bool:
        return enclosure.sound

    def witness(
        self,
        witness: WitnessResult,
        compiled_bundle: CompiledBundle,
        residual_context: ResidualContext,
    ) -> bool:
        del compiled_bundle
        all_witnesses = witness.satisfying.union(witness.nonsatisfying)
        if not all_witnesses.subset_of(residual_context.adm_out):
            return False
        if all_witnesses.is_empty():
            return True
        metadata = witness.metadata or {}
        if any(
            self._bound_artifact_pointer_or_digest(metadata.get(field_name))
            for field_name in (
                "proof_ref",
                "witness_ref",
                "witness_provenance_ref",
                "artifact_digest",
                "digest",
            )
        ):
            return True
        return self._accepted_digest_bound_field(
            metadata,
            "witness_proof",
            "witness_proof_ref",
            "witness_provenance",
            "witness_provenance_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("witness", "witness_provenance", "kernel_witness"),
        )

    def infeasibility(self, proof_object: Any) -> bool:
        from collections.abc import Mapping

        def _bound_ref(value: Any) -> bool:
            if isinstance(value, str):
                if value.startswith(("sha256:", "sha384:", "sha512:")):
                    return True
                if "#" not in value:
                    return False
                artifact_id, pointer = value.split("#", 1)
                return artifact_id.startswith("artifact:") and pointer.startswith("/")
            return self._accepted_digest_bound_evidence(
                value,
                expected_kinds=("infeasibility", "infeasibility_proof", "kernel_proof"),
            )

        if hasattr(proof_object, "proof_status"):
            if proof_object.proof_status not in {"pass", "accepted"}:
                return False
            return any(
                _bound_ref(getattr(proof_object, field_name, None))
                for field_name in (
                    "infeasibility_ref",
                    "proof_ref",
                    "artifact_ref",
                    "artifact_digest",
                    "digest",
                    "checker_transcript_ref",
                )
            )
        if not isinstance(proof_object, Mapping):
            return False
        if proof_object.get("proof_status") not in {"pass", "accepted"}:
            return False
        return any(
            _bound_ref(proof_object.get(field_name))
            for field_name in (
                "infeasibility_ref",
                "proof_ref",
                "artifact_ref",
                "artifact_digest",
                "digest",
                "checker_transcript_ref",
            )
        )

    def inclusion(self, outer_enclosure: FiniteSet, satisfaction_set: FiniteSet) -> str:
        return "yes" if outer_enclosure.subset_of(satisfaction_set) else "no"

    def disjointness(self, outer_enclosure: FiniteSet, satisfaction_set: FiniteSet) -> str:
        return "yes" if outer_enclosure.disjoint_from(satisfaction_set) else "no"

    def artifact_conflict(self, accepted_artifacts: tuple[Any, ...]) -> bool:
        from collections.abc import Mapping

        def identity_and_digest(artifact: Any) -> tuple[tuple[str, str], str] | None:
            source = artifact
            nested_ref = getattr(artifact, "artifact_ref", None)
            if nested_ref is not None:
                source = nested_ref
            if isinstance(artifact, Mapping) and isinstance(artifact.get("artifact_ref"), Mapping):
                source = artifact["artifact_ref"]
            if isinstance(source, Mapping):
                artifact_id = source.get("artifact_id")
                artifact_type = source.get("artifact_type")
                digest = source.get("digest_value", source.get("digest"))
            else:
                artifact_id = getattr(source, "artifact_id", None)
                artifact_type = getattr(source, "artifact_type", None)
                digest = getattr(source, "digest_value", getattr(source, "digest", None))
            if artifact_id is None or artifact_type is None or digest is None:
                return None
            return (str(artifact_type), str(artifact_id)), str(digest)

        digests: dict[tuple[str, str], str] = {}
        for artifact in accepted_artifacts:
            identity = identity_and_digest(artifact)
            if identity is None:
                continue
            key, digest = identity
            if key in digests and digests[key] != digest:
                return True
            digests[key] = digest
        return False

    def frame_adequacy(
        self, represented_claim: Any, target_condition: Any, frame: Any
    ) -> ValidationResult:
        from dfcc.frame import frame_adequacy

        direction = frame_adequacy(represented_claim, target_condition, frame)
        if direction.value not in {"positive", "negative"}:
            return self._unknown("frame_adequacy")
        frame_id = (
            frame.get("frame_id") if isinstance(frame, dict) else getattr(frame, "frame_id", None)
        )
        expected_values: dict[str, tuple[Any, tuple[str, ...]]] = {
            "adequacy_direction": (
                direction.value,
                (
                    "adequacy_direction",
                    "frame_adequacy",
                    "adequacy",
                    "direction",
                    "result",
                    "decision",
                ),
            )
        }
        if frame_id is not None:
            expected_values["frame_id"] = (
                frame_id,
                ("frame_id", "target_frame_id", "assessment_frame_id"),
            )
        binding = self._accepted_payload_identity_binding_nested(
            frame,
            "adequacy_proof",
            "adequacy_proof_ref",
            "checker_transcript",
            "checker_transcript_ref",
            expected_kinds=("frame_adequacy", "frame-adequacy", "adequacy"),
            expected_values=expected_values,
        )
        if binding == "match":
            return pass_validation(ValidationStage.GUARD_EVALUATE)
        if binding == "conflict":
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.GUARD_EVALUATE,
                "frame adequacy proof conflicts with computed adequacy direction",
                status=ValidationStatus.CONFLICT,
                layer=Layer.OPERATIONAL,
            )
        return self._unknown("frame_adequacy")
