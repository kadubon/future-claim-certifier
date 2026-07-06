"""Artifact references, reference resolution, and manifest identity."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any

from dfcc.canonical import digest_json
from dfcc.canonical import manifest_digest as compute_manifest_digest
from dfcc.jsonpointer import JsonPointerError, resolve_pointer
from dfcc.profiles import BASE_SCHEMA_PROFILE, JCS_CANONICALIZATION, SchemaProfile
from dfcc.time import parse_rfc3339
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
class ArtifactRef:
    artifact_id: str
    artifact_type: str
    schema_profile: str = BASE_SCHEMA_PROFILE
    canonicalization: str = JCS_CANONICALIZATION
    media_type: str = "application/json"
    schema_digest: str | None = None
    canonicalization_digest: str | None = None
    digest_algorithm: str = "sha256"
    digest_value: str | None = None
    content_uri: str | None = None
    retrieval_policy: str = "local"
    immutability_policy: str = "digest-addressed"
    provenance_refs: tuple[str, ...] = ()
    semantic_role: str | None = None
    dependency_labels: tuple[str, ...] = ()


class ArtifactRole(StrEnum):
    ROOT = "root"
    ISSUE_CERTIFICATE = "issue_certificate"
    CLAIM = "claim"
    ANCHOR = "anchor"
    TIME_BASIS = "time_basis"
    ASSUMPTION_BUNDLE = "assumption_bundle"
    EVIDENCE = "evidence"
    ADMISSION = "admission"
    ACCEPTED_CLAUSE = "accepted_clause"
    TRUST_ASSUMPTION = "trust_assumption"
    GUARD_RECORD = "guard_record"
    PROPOSED_USE = "proposed_use"
    STATUS = "status"
    STATUS_CONTEXT = "status_context"
    STATUS_AUTHORITY_VIEW = "status_authority_view"
    POLICY = "policy"
    LIFECYCLE_EVENT = "lifecycle_event"
    OBSERVATION = "observation"
    MEASUREMENT_RELATION = "measurement_relation"
    REPRESENTATION_RELATION = "representation_relation"
    KERNEL_PROOF = "kernel_proof"
    REASON = "reason"
    OBLIGATION = "obligation"
    SCHEMA = "schema"
    PROFILE = "profile"
    SET = "set"
    SCALAR_RECORD = "scalar_record"
    INTERVAL_RECORD = "interval_record"
    TIMESTAMP_RECORD = "timestamp_record"
    DEPENDENCY_GRAPH = "dependency_graph"
    PREFIX_VIEW = "prefix_view"
    COMPLETION_ADMISSION = "completion_admission"
    FIBER_ASSOC_VIEW = "fiber_assoc_view"
    AGREEMENT = "agreement"
    PROTOCOL_RECORD = "protocol_record"
    REPLAY_STAGE_TRACE = "replay_stage_trace"
    REPLAY_TRACE = "replay_trace"
    PIPELINE_REPORT = "pipeline_report"
    LIFECYCLE_DECISION = "lifecycle_decision"
    RESOLVED_AUTHORITY_RUNTIME = "resolved_authority_runtime"
    VALIDATION_RESULT = "validation_result"
    OTHER = "other"


class ReferenceKind(StrEnum):
    ARTIFACT = "artifact"
    REASON = "reason"
    OBLIGATION = "obligation"
    SET = "set"
    PROFILE = "profile"
    SCHEMA = "schema"
    TRANSCRIPT = "transcript"
    PROOF = "proof"


@dataclass(frozen=True, slots=True)
class ReferenceResolutionContext:
    snapshot_id: str
    status_time: str | None = None
    retrieval_policy: str = "local"
    dependency_snapshot: dict[str, str] = field(default_factory=dict)
    event_cut: tuple[str, ...] = ()
    profile_ref: str = "DFCC-Interop"
    allowed_retrieval_policies: tuple[str, ...] = ("local",)
    allowed_immutability_policies: tuple[str, ...] = ("digest-addressed", "immutable")
    schema_digests: dict[str, str] = field(default_factory=dict)
    canonicalization_digests: dict[str, str] = field(default_factory=dict)
    semantic_roles: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ArtifactEntry:
    artifact_ref: ArtifactRef
    artifact: Any
    role: ArtifactRole = ArtifactRole.OTHER
    schema_name: str | None = None
    reason_paths: tuple[str, ...] = ()
    obligation_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ManifestRecord:
    manifest_id: str
    root_artifact_id: str
    artifact_refs: tuple[ArtifactRef, ...]
    dependency_order: tuple[str, ...] = ()
    semantic_roles: dict[str, str] = field(default_factory=dict)
    fixed_point_admissions: tuple[str, ...] = ()
    manifest_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ArtifactBundle:
    bundle_id: str
    manifest: ManifestRecord
    entries: tuple[ArtifactEntry, ...]
    reference_context: ReferenceResolutionContext

    def store(self) -> ArtifactStore:
        store = ArtifactStore()
        for entry in self.entries:
            store.add(entry.artifact_ref, entry.artifact)
        return store


@dataclass(frozen=True, slots=True)
class ResolvedReference:
    source_artifact: str
    source_path: str
    target_digest: str


@dataclass(frozen=True, slots=True)
class ReasonRefRecord:
    reason_id: str
    failure_code: str
    layer: str
    source_artifact: str
    source_path: str
    message: str
    digest: str | None = None

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> ReasonRefRecord:
        return cls(
            reason_id=str(source["reason_id"]),
            failure_code=str(source["failure_code"]),
            layer=str(source["layer"]),
            source_artifact=str(source["source_artifact"]),
            source_path=str(source.get("source_path", "")),
            message=str(source["message"]),
            digest=str(source["digest"]) if source.get("digest") is not None else None,
        )


@dataclass(frozen=True, slots=True)
class ObligationRefRecord:
    obligation_id: str
    kind: str
    status: str
    scope: tuple[str, ...] = ()
    checker: str | None = None
    expiry: str | None = None
    reason_refs: tuple[str, ...] = ()
    source_artifact: str | None = None
    source_path: str | None = None
    digest: str | None = None

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> ObligationRefRecord:
        return cls(
            obligation_id=str(source["obligation_id"]),
            kind=str(source["kind"]),
            status=str(source["status"]),
            scope=tuple(str(item) for item in source.get("scope", ())),
            checker=str(source["checker"]) if source.get("checker") is not None else None,
            expiry=str(source["expiry"]) if source.get("expiry") is not None else None,
            reason_refs=tuple(str(item) for item in source.get("reason_refs", ())),
            source_artifact=str(source["source_artifact"])
            if source.get("source_artifact") is not None
            else None,
            source_path=str(source["source_path"])
            if source.get("source_path") is not None
            else None,
            digest=str(source["digest"]) if source.get("digest") is not None else None,
        )

    @property
    def active_scope_status(self) -> str:
        return self.active_scope_status_at(None)

    def active_scope_status_at(self, status_time: str | None) -> str:
        if self.status == "pass":
            base_status = self.status
        elif self.status == "waived":
            base_status = "waived" if self.reason_refs else "inactive"
        else:
            return "inactive"
        if self.expiry is None:
            return base_status
        normalized_expiry = self.expiry.strip().lower()
        if normalized_expiry in {"", "none", "unbounded"}:
            return base_status
        if status_time is None:
            return "not_checked"
        try:
            if parse_rfc3339(str(status_time)) > parse_rfc3339(self.expiry):
                return "expired"
        except ValueError:
            return "invalid"
        return base_status


@dataclass(frozen=True, slots=True)
class ProofRefRecord:
    proof_id: str
    proof_kind: str
    source_path: str
    status: str
    artifact_ref: str | None = None
    source_artifact: str | None = None
    digest: str | None = None

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> ProofRefRecord:
        source_path = str(source.get("source_path", ""))
        if source_path and not source_path.startswith("/"):
            raise ValueError("proof source_path must be empty or a JSON Pointer")
        source_artifact = (
            str(source["source_artifact"]) if source.get("source_artifact") is not None else None
        )
        if source_artifact is not None and not source_artifact.startswith("artifact:"):
            raise ValueError("proof source_artifact must be artifact-bound")
        digest = str(source["digest"]) if source.get("digest") is not None else None
        status = str(source["status"])
        if status in {"accepted", "pass"} and not (
            isinstance(digest, str) and digest.startswith(("sha256:", "sha384:", "sha512:"))
        ):
            raise ValueError("accepted proof records require a SHA-family digest")
        return cls(
            proof_id=str(source["proof_id"]),
            proof_kind=str(source["proof_kind"]),
            source_path=source_path,
            status=status,
            artifact_ref=str(source["artifact_ref"])
            if source.get("artifact_ref") is not None
            else None,
            source_artifact=source_artifact,
            digest=digest,
        )


@dataclass(frozen=True, slots=True)
class SetRefRecord:
    carrier_ref: str
    encoding_kind: str
    constraint_ref: str
    approximation_kind: str
    soundness_ref: str
    digest: str

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> SetRefRecord:
        return cls(
            carrier_ref=str(source["carrier_ref"]),
            encoding_kind=str(source["encoding_kind"]),
            constraint_ref=str(source["constraint_ref"]),
            approximation_kind=str(source["approximation_kind"]),
            soundness_ref=str(source["soundness_ref"]),
            digest=str(source["digest"]),
        )


@dataclass(frozen=True, slots=True)
class ReferenceLedgerEntry:
    ref_value: str
    kind: ReferenceKind
    owner_artifact: str
    owner_path: str
    target_artifact_id: str
    target_path: str
    target_digest: str | None
    semantic_role: str | None = None
    required: bool = True
    resolved: bool = False
    expected_kind: ReferenceKind | None = None
    expected_semantic_role: str | None = None
    expected_digest: str | None = None
    required_stage: ValidationStage = ValidationStage.AUTHORITY_EMIT
    active_scope_status: str = "not_checked"

    def to_json(self) -> dict[str, Any]:
        return {
            "ref_value": self.ref_value,
            "kind": self.kind.value,
            "owner_artifact": self.owner_artifact,
            "owner_path": self.owner_path,
            "target_artifact_id": self.target_artifact_id,
            "target_path": self.target_path,
            "target_digest": self.target_digest,
            "semantic_role": self.semantic_role,
            "required": self.required,
            "resolved": self.resolved,
            "expected_kind": self.expected_kind.value if self.expected_kind is not None else None,
            "expected_semantic_role": self.expected_semantic_role,
            "expected_digest": self.expected_digest,
            "required_stage": self.required_stage.value,
            "active_scope_status": self.active_scope_status,
        }


@dataclass(frozen=True, slots=True)
class ReferenceLedger:
    resolved_refs: tuple[ResolvedReference, ...]
    unresolved_refs: tuple[tuple[str, str], ...]
    validation_result: ValidationResult
    entries: tuple[ReferenceLedgerEntry, ...] = ()

    @property
    def passed(self) -> bool:
        return self.validation_result.passed

    def by_kind(self, kind: ReferenceKind) -> tuple[ReferenceLedgerEntry, ...]:
        return tuple(entry for entry in self.entries if entry.kind is kind)


class ArtifactStore:
    """In-memory store used by the reference resolver and tests.

    The store is deliberately small. Production systems can adapt the same
    interface to content-addressed stores, signed bundles, or offline archives.
    """

    def __init__(self) -> None:
        self._artifacts: dict[str, tuple[ArtifactRef, Any]] = {}

    def add(self, artifact_ref: ArtifactRef, artifact: Any) -> None:
        result = validate_artifact_ref(artifact_ref, artifact=artifact)
        if not result.passed:
            msg = result.reason_refs[0].message if result.reason_refs else "invalid artifact"
            raise ValueError(msg)
        self._artifacts[artifact_ref.artifact_id] = (artifact_ref, artifact)

    def get(self, artifact_id: str) -> tuple[ArtifactRef, Any] | None:
        return self._artifacts.get(artifact_id)

    def resolve_json_pointer(self, artifact_id: str, pointer: str) -> Any:
        item = self.get(artifact_id)
        if item is None:
            raise KeyError(artifact_id)
        _, artifact = item
        return resolve_pointer(artifact, pointer)


def build_artifact_ref(
    artifact: Any,
    *,
    artifact_id: str,
    artifact_type: str,
    schema_profile: SchemaProfile | str = BASE_SCHEMA_PROFILE,
    content_uri: str | None = None,
    digest_algorithm: str = "sha256",
    semantic_role: ArtifactRole | str | None = None,
    dependency_labels: tuple[str, ...] = (),
) -> ArtifactRef:
    profile_id = (
        schema_profile.schema_id if isinstance(schema_profile, SchemaProfile) else schema_profile
    )
    digest_value = digest_json(artifact, digest_algorithm)
    schema_digest = digest_json({"schema_profile": profile_id}, digest_algorithm)
    canonicalization_digest = digest_json(
        {"canonicalization": JCS_CANONICALIZATION}, digest_algorithm
    )
    return ArtifactRef(
        artifact_id=artifact_id,
        artifact_type=artifact_type,
        schema_profile=profile_id,
        schema_digest=schema_digest,
        canonicalization_digest=canonicalization_digest,
        digest_algorithm=digest_algorithm,
        digest_value=digest_value,
        content_uri=content_uri,
        semantic_role=semantic_role.value
        if isinstance(semantic_role, ArtifactRole)
        else semantic_role,
        dependency_labels=dependency_labels,
    )


def artifact_ref_from_json(source: Mapping[str, Any]) -> ArtifactRef:
    provenance = tuple(str(item) for item in source.get("provenance_refs", ()))
    dependency_labels = tuple(str(item) for item in source.get("dependency_labels", ()))
    return ArtifactRef(
        artifact_id=str(source["artifact_id"]),
        artifact_type=str(source["artifact_type"]),
        schema_profile=str(source.get("schema_profile", BASE_SCHEMA_PROFILE)),
        canonicalization=str(source.get("canonicalization", JCS_CANONICALIZATION)),
        media_type=str(source.get("media_type", "application/json")),
        schema_digest=source.get("schema_digest"),
        canonicalization_digest=source.get("canonicalization_digest"),
        digest_algorithm=str(source.get("digest_algorithm", "sha256")),
        digest_value=source.get("digest_value"),
        content_uri=source.get("content_uri"),
        retrieval_policy=str(source.get("retrieval_policy", "local")),
        immutability_policy=str(source.get("immutability_policy", "digest-addressed")),
        provenance_refs=provenance,
        semantic_role=source.get("semantic_role"),
        dependency_labels=dependency_labels,
    )


def _role(value: Any) -> ArtifactRole:
    try:
        return ArtifactRole(str(value))
    except ValueError:
        return ArtifactRole.OTHER


def artifact_bundle_from_json(source: Mapping[str, Any]) -> ArtifactBundle:
    entries: list[ArtifactEntry] = []
    for item in source.get("artifacts", ()):
        if not isinstance(item, Mapping):
            raise TypeError("artifact bundle entries must be objects")
        ref_source = item.get("artifact_ref")
        if not isinstance(ref_source, Mapping):
            raise TypeError("artifact bundle entry lacks artifact_ref")
        role = _role(item.get("role", ref_source.get("semantic_role", ArtifactRole.OTHER.value)))
        reason_paths = tuple(str(path) for path in item.get("reason_paths", ()))
        obligation_refs = tuple(str(ref) for ref in item.get("obligation_refs", ()))
        artifact_ref = artifact_ref_from_json(ref_source)
        if artifact_ref.semantic_role is None and role is not ArtifactRole.OTHER:
            artifact_ref = replace(artifact_ref, semantic_role=role.value)
        entries.append(
            ArtifactEntry(
                artifact_ref=artifact_ref,
                artifact=item.get("artifact"),
                role=role,
                schema_name=item.get("schema_name"),
                reason_paths=reason_paths,
                obligation_refs=obligation_refs,
            )
        )
    manifest_source = source.get("manifest", {})
    if not isinstance(manifest_source, Mapping):
        raise TypeError("artifact bundle manifest must be an object")
    by_id = {entry.artifact_ref.artifact_id: entry.artifact_ref for entry in entries}
    manifest_refs = []
    for item in manifest_source.get("artifact_refs", ()):
        if isinstance(item, str):
            manifest_refs.append(by_id[item])
        elif isinstance(item, Mapping):
            manifest_refs.append(artifact_ref_from_json(item))
        else:
            raise TypeError("manifest artifact_refs must be strings or objects")
    if not manifest_refs:
        manifest_refs = [entry.artifact_ref for entry in entries]
    dependency_order = tuple(str(item) for item in manifest_source.get("dependency_order", ()))
    semantic_roles = {
        str(key): str(value)
        for key, value in dict(manifest_source.get("semantic_roles", {})).items()
    }
    root_artifact_id = str(
        manifest_source.get(
            "root_artifact_id",
            entries[0].artifact_ref.artifact_id if entries else "artifact:root",
        )
    )
    context_source = source.get("reference_context", {})
    if not isinstance(context_source, Mapping):
        raise TypeError("reference_context must be an object")
    context = ReferenceResolutionContext(
        snapshot_id=str(context_source.get("snapshot_id", source.get("bundle_id", "bundle"))),
        status_time=str(context_source["status_time"])
        if context_source.get("status_time") is not None
        else None,
        retrieval_policy=str(context_source.get("retrieval_policy", "local")),
        dependency_snapshot={
            str(key): str(value)
            for key, value in dict(context_source.get("dependency_snapshot", {})).items()
        },
        event_cut=tuple(str(item) for item in context_source.get("event_cut", ())),
        profile_ref=str(context_source.get("profile_ref", "DFCC-Interop")),
        allowed_retrieval_policies=tuple(
            str(item) for item in context_source.get("allowed_retrieval_policies", ("local",))
        ),
        allowed_immutability_policies=tuple(
            str(item)
            for item in context_source.get(
                "allowed_immutability_policies", ("digest-addressed", "immutable")
            )
        ),
        schema_digests={
            str(key): str(value)
            for key, value in dict(context_source.get("schema_digests", {})).items()
        },
        canonicalization_digests={
            str(key): str(value)
            for key, value in dict(context_source.get("canonicalization_digests", {})).items()
        },
        semantic_roles={
            str(key): str(value)
            for key, value in dict(context_source.get("semantic_roles", {})).items()
        },
    )
    manifest = ManifestRecord(
        manifest_id=str(
            manifest_source.get("manifest_id", f"{source.get('bundle_id', 'bundle')}:manifest")
        ),
        root_artifact_id=root_artifact_id,
        artifact_refs=tuple(manifest_refs),
        dependency_order=dependency_order,
        semantic_roles=semantic_roles,
        fixed_point_admissions=tuple(
            str(item) for item in manifest_source.get("fixed_point_admissions", ())
        ),
        manifest_digest=manifest_source.get("manifest_digest"),
    )
    return ArtifactBundle(
        bundle_id=str(source.get("bundle_id", "artifact-bundle")),
        manifest=manifest,
        entries=tuple(entries),
        reference_context=context,
    )


def validate_artifact_ref(
    artifact_ref: ArtifactRef,
    *,
    artifact: Any | None = None,
    policy: dict[str, Any] | None = None,
) -> ValidationResult:
    policy = policy or {}
    if artifact_ref.digest_algorithm not in {"sha256", "sha384", "sha512"}:
        return validation_failure(
            FailureCode.UNSUPPORTED_PROFILE,
            ValidationStage.DIGEST_CHECK,
            f"unsupported digest algorithm: {artifact_ref.digest_algorithm}",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/digest_algorithm",
        )
    if artifact_ref.canonicalization != JCS_CANONICALIZATION:
        return validation_failure(
            FailureCode.CANONICALIZATION_MISMATCH,
            ValidationStage.CANONICALIZE,
            f"unsupported canonicalization profile: {artifact_ref.canonicalization}",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/canonicalization",
        )
    allowed_retrieval = {str(item) for item in policy.get("allowed_retrieval_policies", ("local",))}
    if artifact_ref.retrieval_policy not in allowed_retrieval:
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.REFERENCE_RESOLVE,
            f"retrieval policy is not allowed: {artifact_ref.retrieval_policy}",
            status=ValidationStatus.CONFLICT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/retrieval_policy",
        )
    allowed_immutability = {
        str(item)
        for item in policy.get("allowed_immutability_policies", ("digest-addressed", "immutable"))
    }
    if artifact_ref.immutability_policy not in allowed_immutability:
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.DIGEST_CHECK,
            f"incompatible immutability policy: {artifact_ref.immutability_policy}",
            status=ValidationStatus.CONFLICT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/immutability_policy",
        )
    expected_schema_digest = dict(policy.get("schema_digests", {})).get(artifact_ref.artifact_type)
    if expected_schema_digest is not None and artifact_ref.schema_digest != expected_schema_digest:
        return validation_failure(
            FailureCode.DIGEST_MISMATCH,
            ValidationStage.DIGEST_CHECK,
            "artifact schema digest does not match profile binding",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/schema_digest",
        )
    expected_canon_digest = dict(policy.get("canonicalization_digests", {})).get(
        artifact_ref.canonicalization
    )
    if (
        expected_canon_digest is not None
        and artifact_ref.canonicalization_digest != expected_canon_digest
    ):
        return validation_failure(
            FailureCode.DIGEST_MISMATCH,
            ValidationStage.DIGEST_CHECK,
            "artifact canonicalization digest does not match profile binding",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/canonicalization_digest",
        )
    expected_role = dict(policy.get("semantic_roles", {})).get(artifact_ref.artifact_id)
    if expected_role is not None and artifact_ref.semantic_role not in {None, expected_role}:
        return validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.REFERENCE_RESOLVE,
            "artifact semantic role conflicts with manifest role",
            status=ValidationStatus.CONFLICT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/semantic_role",
        )
    if artifact_ref.provenance_refs and len(artifact_ref.dependency_labels) not in {
        0,
        len(artifact_ref.provenance_refs),
    }:
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.SCHEMA_VALIDATE,
            "dependency labels must match provenance reference arity",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/dependency_labels",
        )
    if artifact_ref.digest_value is None:
        return validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.DIGEST_CHECK,
            "artifact reference lacks digest value",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_ref.artifact_id,
            source_path="/digest_value",
        )
    if artifact is not None:
        actual = digest_json(artifact, artifact_ref.digest_algorithm)
        if artifact_ref.digest_value != actual:
            return validation_failure(
                FailureCode.DIGEST_MISMATCH,
                ValidationStage.DIGEST_CHECK,
                "artifact digest does not match canonical artifact bytes",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=artifact_ref.artifact_id,
                source_path="/digest_value",
            )
    return pass_validation(ValidationStage.DIGEST_CHECK)


def validate_manifest_dependencies(
    dependencies: tuple[ArtifactRef, ...],
    *,
    root_artifact_id: str | None = None,
    dependency_order: tuple[str, ...] = (),
    fixed_point_admissions: tuple[str, ...] = (),
) -> ValidationResult:
    by_id = {ref.artifact_id: ref for ref in dependencies}
    if dependency_order:
        order_positions = {artifact_id: index for index, artifact_id in enumerate(dependency_order)}
        for ref in dependencies:
            ref_position = order_positions.get(ref.artifact_id)
            if ref_position is None:
                return validation_failure(
                    FailureCode.MISSING_REF,
                    ValidationStage.DIGEST_CHECK,
                    f"manifest order omits artifact: {ref.artifact_id}",
                    status=ValidationStatus.INVALID_ARTIFACT,
                    layer=Layer.INTEROP,
                    source_artifact=ref.artifact_id,
                )
            for dep in ref.provenance_refs:
                dep_position = order_positions.get(dep)
                if dep_position is not None and dep_position > ref_position:
                    return validation_failure(
                        FailureCode.ARTIFACT_CONFLICT,
                        ValidationStage.DIGEST_CHECK,
                        "manifest dependency order is not topological",
                        status=ValidationStatus.CONFLICT,
                        layer=Layer.INTEROP,
                        source_artifact=ref.artifact_id,
                        source_path="/manifest/dependency_order",
                    )
    for ref in dependencies:
        if ref.digest_value is None:
            return validation_failure(
                FailureCode.MISSING_REF,
                ValidationStage.DIGEST_CHECK,
                f"dependency lacks digest: {ref.artifact_id}",
                status=ValidationStatus.INVALID_ARTIFACT,
                layer=Layer.INTEROP,
                source_artifact=ref.artifact_id,
                source_path="/digest_value",
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(artifact_id: str) -> bool:
        if artifact_id in visiting:
            return bool(fixed_point_admissions)
        if artifact_id in visited:
            return True
        visiting.add(artifact_id)
        ref = by_id.get(artifact_id)
        if ref is not None:
            for dep in ref.provenance_refs:
                if dep in by_id and not visit(dep):
                    return False
        visiting.remove(artifact_id)
        visited.add(artifact_id)
        return True

    starts = (root_artifact_id,) if root_artifact_id is not None else tuple(by_id)
    for start in starts:
        if start in by_id and not visit(start):
            return validation_failure(
                FailureCode.ARTIFACT_CONFLICT,
                ValidationStage.DIGEST_CHECK,
                "artifact dependency cycle is unsupported without fixed-point admission",
                status=ValidationStatus.CONFLICT,
                layer=Layer.INTEROP,
                source_artifact=start,
                source_path="/manifest/fixed_point_admissions",
            )
    return pass_validation(ValidationStage.DIGEST_CHECK)


def manifest_digest(
    artifact: Any,
    *,
    artifact_type: str,
    schema_profile_digest: str,
    dependencies: tuple[ArtifactRef, ...] = (),
    algorithm: str = "sha256",
) -> str:
    ordered = tuple(
        sorted(ref.digest_value or "" for ref in dependencies if ref.digest_value is not None)
    )
    return compute_manifest_digest(
        artifact,
        domain_tag="DFCC",
        type_tag=artifact_type,
        schema_profile_digest=schema_profile_digest,
        dependencies=ordered,
        algorithm=algorithm,
    )


def resolve_reference(
    artifact_id: str,
    pointer: str,
    *,
    store: ArtifactStore,
    context: ReferenceResolutionContext,
) -> tuple[ValidationResult, Any | None]:
    if context.retrieval_policy not in context.allowed_retrieval_policies:
        result = validation_failure(
            FailureCode.ARTIFACT_CONFLICT,
            ValidationStage.REFERENCE_RESOLVE,
            f"reference context retrieval policy is not allowed: {context.retrieval_policy}",
            status=ValidationStatus.CONFLICT,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
            source_path=pointer,
        )
        return result, None
    try:
        value = store.resolve_json_pointer(artifact_id, pointer)
    except (KeyError, JsonPointerError) as exc:
        result = validation_failure(
            FailureCode.MISSING_REF,
            ValidationStage.REFERENCE_RESOLVE,
            str(exc),
            status=ValidationStatus.UNKNOWN,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
            source_path=pointer,
        )
        return result, None
    return pass_validation(ValidationStage.REFERENCE_RESOLVE), value


def _embedded_artifact_source(source: Mapping[str, Any], artifact_id: str) -> Any | None:
    pairs = (
        ("claim_ref", "claim_source"),
        ("assumption_bundle_ref", "bundle_source"),
        ("anchor_ref", "anchor_source"),
        ("time_basis_ref", "time_basis_source"),
    )
    for ref_field, source_field in pairs:
        if source.get(ref_field) == artifact_id and source.get(source_field) is not None:
            return source[source_field]
    return None


def _reference_kind(owner_path: str) -> ReferenceKind:
    path = owner_path.lower()
    if "reason" in path:
        return ReferenceKind.REASON
    if "obligation" in path:
        return ReferenceKind.OBLIGATION
    if "set" in path or path.endswith("/c_out_ref") or path.endswith("/c_in_ref"):
        return ReferenceKind.SET
    if "schema" in path:
        return ReferenceKind.SCHEMA
    if "profile" in path:
        return ReferenceKind.PROFILE
    if "transcript" in path:
        return ReferenceKind.TRANSCRIPT
    if "proof" in path or any(
        marker in path
        for marker in (
            "verifier",
            "manifest_digest_ref",
            "log_root_ref",
            "causal_cut_ref",
            "trace_class_ref",
            "event_manifest_ref",
        )
    ):
        return ReferenceKind.PROOF
    return ReferenceKind.ARTIFACT


def _expected_semantic_role(kind: ReferenceKind) -> str | None:
    role_by_kind = {
        ReferenceKind.REASON: ArtifactRole.REASON.value,
        ReferenceKind.OBLIGATION: ArtifactRole.OBLIGATION.value,
        ReferenceKind.SET: ArtifactRole.SET.value,
        ReferenceKind.PROFILE: ArtifactRole.PROFILE.value,
        ReferenceKind.SCHEMA: ArtifactRole.SCHEMA.value,
        ReferenceKind.PROOF: "proof",
    }
    return role_by_kind.get(kind)


def _required_stage(owner_path: str) -> ValidationStage:
    kind = _reference_kind(owner_path)
    if kind in {ReferenceKind.SCHEMA, ReferenceKind.PROFILE}:
        return ValidationStage.PROFILE_RESOLVE
    if kind in {ReferenceKind.REASON, ReferenceKind.OBLIGATION, ReferenceKind.SET}:
        return ValidationStage.REFERENCE_RESOLVE
    if kind in {ReferenceKind.PROOF, ReferenceKind.TRANSCRIPT}:
        return ValidationStage.GUARD_EVALUATE
    return ValidationStage.AUTHORITY_EMIT


def _active_scope_status(
    kind: ReferenceKind,
    value: Any,
    *,
    context: ReferenceResolutionContext,
) -> str:
    if kind is not ReferenceKind.OBLIGATION:
        return "not_applicable"
    if not isinstance(value, Mapping):
        return "not_checked"
    try:
        return ObligationRefRecord.from_json(value).active_scope_status_at(context.status_time)
    except (KeyError, TypeError, ValueError):
        return "invalid"


def _proof_scope_status(kind: ReferenceKind, value: Any) -> str:
    if kind is not ReferenceKind.PROOF:
        return "not_applicable"
    if not isinstance(value, Mapping):
        return "invalid"
    status = str(
        value.get(
            "status",
            value.get("proof_status", value.get("checker_status", value.get("result", ""))),
        )
    )
    if status in {"pass", "accepted"}:
        return "pass"
    if status in {"fail", "conflict"}:
        return "fail"
    if status in {"unknown", "unchecked", ""}:
        return "unknown"
    return "invalid"


def _transcript_scope_status(kind: ReferenceKind, value: Any) -> str:
    if kind is not ReferenceKind.TRANSCRIPT:
        return "not_applicable"
    if not isinstance(value, Mapping):
        return "invalid"
    status = str(
        value.get(
            "status",
            value.get(
                "checker_status",
                value.get("result", value.get("transcript", "")),
            ),
        )
    )
    if status in {"pass", "accepted"}:
        return "pass"
    if status in {"fail", "conflict", "rejected"}:
        return "fail"
    if status in {"unknown", "unchecked", ""}:
        return "unknown"
    return "invalid"


def _waiver_reason_refs_resolved(
    kind: ReferenceKind,
    value: Any,
    *,
    store: ArtifactStore,
    context: ReferenceResolutionContext,
) -> bool:
    if kind is not ReferenceKind.OBLIGATION:
        return True
    if not isinstance(value, Mapping):
        return False
    try:
        obligation = ObligationRefRecord.from_json(value)
    except (KeyError, TypeError, ValueError):
        return False
    if obligation.status != "waived":
        return True
    if not obligation.reason_refs:
        return False
    for reason_ref in obligation.reason_refs:
        artifact_id, sep, pointer = reason_ref.partition("#")
        if not sep or not artifact_id.startswith("artifact:") or not pointer.startswith("/"):
            return False
        item = store.get(artifact_id)
        if item is None:
            return False
        artifact_ref, _ = item
        if artifact_ref.semantic_role not in {None, ArtifactRole.REASON.value}:
            return False
        result, _ = resolve_reference(
            artifact_id,
            pointer,
            store=store,
            context=context,
        )
        if not result.passed:
            return False
    return True


def _required_reference(ref_value: str, owner_path: str) -> bool:
    if "#" in ref_value or ref_value.startswith(("artifact:", "synthetic:")):
        return True
    return owner_path in {
        "/claim_ref",
        "/anchor_ref",
        "/time_basis_ref",
        "/assumption_bundle_ref",
        "/evidence_ref",
        "/contract_ref",
        "/checker_transcript_ref",
    }


def _ledger_failure(
    code: FailureCode,
    message: str,
    *,
    source_artifact: str,
    source_path: str,
    status: ValidationStatus = ValidationStatus.UNKNOWN,
) -> ValidationResult:
    return validation_failure(
        code,
        ValidationStage.AUTHORITY_EMIT,
        message,
        status=status,
        layer=Layer.INTEROP,
        source_artifact=source_artifact,
        source_path=source_path,
    )


def _resolve_ledger_ref(
    ref_value: str,
    *,
    expected_digest: str | None,
    bundle: ArtifactBundle,
    store: ArtifactStore,
    resolved: list[ResolvedReference],
    entries: list[ReferenceLedgerEntry],
    unresolved: list[tuple[str, str]],
    owner_artifact: str,
    owner_path: str,
    strict: bool,
) -> ValidationResult | None:
    artifact_id, sep, pointer = ref_value.partition("#")
    pointer = pointer if sep else ""
    kind = _reference_kind(owner_path)
    required = _required_reference(ref_value, owner_path)
    expected_role = _expected_semantic_role(kind)
    required_stage = _required_stage(owner_path)

    def ledger_entry(
        *,
        target_digest: str | None,
        semantic_role: str | None,
        resolved_value: Any | None,
        resolved_flag: bool,
    ) -> ReferenceLedgerEntry:
        return ReferenceLedgerEntry(
            ref_value=ref_value,
            kind=kind,
            owner_artifact=owner_artifact,
            owner_path=owner_path,
            target_artifact_id=artifact_id,
            target_path=pointer,
            target_digest=target_digest,
            semantic_role=semantic_role,
            required=required,
            resolved=resolved_flag,
            expected_kind=kind,
            expected_semantic_role=expected_role,
            expected_digest=expected_digest,
            required_stage=required_stage,
            active_scope_status=_active_scope_status(
                kind,
                resolved_value,
                context=bundle.reference_context,
            ),
        )

    if artifact_id in store._artifacts:
        stored_ref, _ = store._artifacts[artifact_id]
        result, value = resolve_reference(
            artifact_id,
            pointer,
            store=store,
            context=bundle.reference_context,
        )
        if not result.passed:
            unresolved.append((artifact_id, pointer))
            entries.append(
                ledger_entry(
                    target_digest=None,
                    semantic_role=stored_ref.semantic_role,
                    resolved_value=None,
                    resolved_flag=False,
                )
            )
            return result if strict else None
        target_digest = manifest_digest(
            value,
            artifact_type="reference-target",
            schema_profile_digest="DFCC-Interop",
        )
        if expected_digest is not None and target_digest != expected_digest:
            entries.append(
                ledger_entry(
                    target_digest=target_digest,
                    semantic_role=stored_ref.semantic_role,
                    resolved_value=value,
                    resolved_flag=False,
                )
            )
            unresolved.append((artifact_id, pointer))
            if strict:
                return _ledger_failure(
                    FailureCode.DIGEST_MISMATCH,
                    f"reference digest mismatch for {ref_value}",
                    source_artifact=owner_artifact,
                    source_path=owner_path,
                    status=ValidationStatus.INVALID_ARTIFACT,
                )
            return None
        if expected_role is not None and (
            stored_ref.semantic_role != expected_role
            if strict
            else stored_ref.semantic_role not in {None, expected_role}
        ):
            entries.append(
                ledger_entry(
                    target_digest=target_digest,
                    semantic_role=stored_ref.semantic_role,
                    resolved_value=value,
                    resolved_flag=False,
                )
            )
            unresolved.append((artifact_id, pointer))
            if strict:
                return _ledger_failure(
                    FailureCode.ARTIFACT_CONFLICT,
                    f"reference role mismatch for {ref_value}: expected {expected_role}",
                    source_artifact=owner_artifact,
                    source_path=owner_path,
                    status=ValidationStatus.CONFLICT,
                )
            return None
        active_status = _active_scope_status(kind, value, context=bundle.reference_context)
        if active_status not in {"not_applicable", "pass", "waived"}:
            entries.append(
                ledger_entry(
                    target_digest=target_digest,
                    semantic_role=stored_ref.semantic_role,
                    resolved_value=value,
                    resolved_flag=False,
                )
            )
            unresolved.append((artifact_id, pointer))
            if strict:
                return _ledger_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    f"reference obligation is not active: {ref_value}",
                    source_artifact=owner_artifact,
                    source_path=owner_path,
                )
            return None
        if active_status == "waived" and not _waiver_reason_refs_resolved(
            kind,
            value,
            store=store,
            context=bundle.reference_context,
        ):
            entries.append(
                ledger_entry(
                    target_digest=target_digest,
                    semantic_role=stored_ref.semantic_role,
                    resolved_value=value,
                    resolved_flag=False,
                )
            )
            unresolved.append((artifact_id, pointer))
            if strict:
                return _ledger_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    f"waived obligation lacks resolved waiver reason refs: {ref_value}",
                    source_artifact=owner_artifact,
                    source_path=owner_path,
                )
            return None
        proof_status = _proof_scope_status(kind, value)
        if proof_status not in {"not_applicable", "pass"}:
            entries.append(
                ledger_entry(
                    target_digest=target_digest,
                    semantic_role=stored_ref.semantic_role,
                    resolved_value=value,
                    resolved_flag=False,
                )
            )
            unresolved.append((artifact_id, pointer))
            if strict:
                return _ledger_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    f"reference proof is not accepted: {ref_value}",
                    source_artifact=owner_artifact,
                    source_path=owner_path,
                )
            return None
        transcript_status = _transcript_scope_status(kind, value)
        if transcript_status not in {"not_applicable", "pass"}:
            entries.append(
                ledger_entry(
                    target_digest=target_digest,
                    semantic_role=stored_ref.semantic_role,
                    resolved_value=value,
                    resolved_flag=False,
                )
            )
            unresolved.append((artifact_id, pointer))
            if strict:
                return _ledger_failure(
                    FailureCode.CHECKER_UNKNOWN,
                    f"reference transcript is not accepted: {ref_value}",
                    source_artifact=owner_artifact,
                    source_path=owner_path,
                )
            return None
        resolved.append(
            ResolvedReference(
                source_artifact=artifact_id,
                source_path=pointer,
                target_digest=target_digest,
            )
        )
        entries.append(
            ledger_entry(
                target_digest=target_digest,
                semantic_role=stored_ref.semantic_role,
                resolved_value=value,
                resolved_flag=True,
            )
        )
        return None

    for entry in bundle.entries:
        if isinstance(entry.artifact, Mapping):
            embedded = _embedded_artifact_source(entry.artifact, artifact_id)
            if embedded is not None:
                target_digest = manifest_digest(
                    embedded,
                    artifact_type="embedded-reference-target",
                    schema_profile_digest="DFCC-Interop",
                )
                if expected_digest is not None and target_digest != expected_digest:
                    entries.append(
                        ledger_entry(
                            target_digest=target_digest,
                            semantic_role=None,
                            resolved_value=embedded,
                            resolved_flag=False,
                        )
                    )
                    unresolved.append((artifact_id, pointer))
                    if strict:
                        return _ledger_failure(
                            FailureCode.DIGEST_MISMATCH,
                            f"embedded reference digest mismatch for {ref_value}",
                            source_artifact=owner_artifact,
                            source_path=owner_path,
                            status=ValidationStatus.INVALID_ARTIFACT,
                        )
                    return None
                resolved.append(
                    ResolvedReference(
                        source_artifact=artifact_id,
                        source_path=pointer,
                        target_digest=target_digest,
                    )
                )
                entries.append(
                    ledger_entry(
                        target_digest=target_digest,
                        semantic_role=None,
                        resolved_value=embedded,
                        resolved_flag=True,
                    )
                )
                return None

    entries.append(
        ledger_entry(
            target_digest=None,
            semantic_role=None,
            resolved_value=None,
            resolved_flag=False,
        )
    )
    unresolved.append((artifact_id, pointer))
    if strict and required:
        return _ledger_failure(
            FailureCode.MISSING_REF,
            f"reference ledger cannot resolve {ref_value}",
            source_artifact=owner_artifact,
            source_path=owner_path,
        )
    return None


def _ref_digest(value: Mapping[str, Any]) -> str | None:
    digest = value.get("digest")
    return str(digest) if digest is not None else None


def _iter_mapping_refs(entry: ArtifactEntry) -> tuple[tuple[str, str, str, str | None], ...]:
    artifact = entry.artifact
    refs: list[tuple[str, str, str, str | None]] = []
    refs.extend(
        (f"{entry.artifact_ref.artifact_id}#{path}", entry.artifact_ref.artifact_id, path, None)
        for path in entry.reason_paths
    )
    refs.extend(
        (ref, entry.artifact_ref.artifact_id, "/obligation_refs", None)
        for ref in entry.obligation_refs
    )
    if not isinstance(artifact, Mapping):
        return tuple(refs)

    for key in (
        "claim_ref",
        "anchor_ref",
        "time_basis_ref",
        "assumption_bundle_ref",
        "evidence_ref",
        "contract_ref",
        "monitor_evidence_ref",
        "monitor_completeness_ref",
        "compiled_semantics_ref",
        "initial_context_ref",
        "representation_interface_ref",
        "completion_interface_ref",
        "dependency_graph_ref",
        "schema_profile_ref",
        "canonicalization_profile_ref",
        "event_order_commitment_ref",
        "calibration_ref",
        "latency_ref",
        "dependency_ref",
        "event_order_ref",
        "measurement_relation_ref",
        "representation_proof_ref",
        "representation_relation_ref",
        "prefix_adjudication_proof_ref",
        "target_adjudication_proof_ref",
        "adequacy_proof_ref",
        "confluence_proof",
        "confluence_proof_ref",
        "signature_verifier_result_ref",
        "log_root_ref",
        "causal_cut_ref",
        "trace_class_ref",
        "event_manifest_ref",
        "manifest_digest_ref",
    ):
        value = artifact.get(key)
        if isinstance(value, str):
            refs.append((value, entry.artifact_ref.artifact_id, f"/{key}", None))
    event_log = artifact.get("event_log", ())
    if isinstance(event_log, list | tuple):
        for event_index, event in enumerate(event_log):
            if not isinstance(event, Mapping):
                continue
            for key in (
                "confluence_proof_ref",
                "signature_verifier_result_ref",
                "log_root_ref",
                "causal_cut_ref",
                "trace_class_ref",
                "event_manifest_ref",
                "manifest_digest_ref",
            ):
                value = event.get(key)
                if isinstance(value, str):
                    refs.append(
                        (
                            value,
                            entry.artifact_ref.artifact_id,
                            f"/event_log/{event_index}/{key}",
                            None,
                        )
                    )
    observation_records = artifact.get("observation_records", ())
    if isinstance(observation_records, list | tuple):
        for record_index, record in enumerate(observation_records):
            if not isinstance(record, Mapping):
                continue
            for key in (
                "measurement_relation_ref",
                "representation_relation_ref",
                "calibration_ref",
                "latency_ref",
                "dependency_ref",
                "event_order_ref",
                "representation_proof_ref",
                "prefix_adjudication_proof_ref",
                "target_adjudication_proof_ref",
                "adequacy_proof_ref",
            ):
                value = record.get(key)
                if isinstance(value, str):
                    refs.append(
                        (
                            value,
                            entry.artifact_ref.artifact_id,
                            f"/observation_records/{record_index}/{key}",
                            None,
                        )
                    )
    frame = artifact.get("frame")
    frame_policy = frame.get("policy") if isinstance(frame, Mapping) else None
    if isinstance(frame_policy, Mapping):
        value = frame_policy.get("adequacy_proof_ref")
        if isinstance(value, str):
            refs.append(
                (
                    value,
                    entry.artifact_ref.artifact_id,
                    "/frame/policy/adequacy_proof_ref",
                    None,
                )
            )
    for container_key in ("completion_policy", "completion_admission"):
        container = artifact.get(container_key)
        if not isinstance(container, Mapping):
            continue
        for key in (
            "checker_transcript_ref",
            "admission_source",
            "monitor_evidence_ref",
            "c_out_ref",
            "c_in_ref",
        ):
            value = container.get(key)
            if isinstance(value, str):
                refs.append(
                    (value, entry.artifact_ref.artifact_id, f"/{container_key}/{key}", None)
                )
    relation = artifact.get("relation")
    if isinstance(relation, Mapping):
        for key in ("calibration_ref", "latency_ref", "dependency_ref", "event_order_ref"):
            value = relation.get(key)
            if isinstance(value, str):
                refs.append((value, entry.artifact_ref.artifact_id, f"/relation/{key}", None))
        proof_ref = relation.get("proof_ref")
        if isinstance(proof_ref, str):
            refs.append((proof_ref, entry.artifact_ref.artifact_id, "/relation/proof_ref", None))
    relations = artifact.get("relations", ())
    if isinstance(relations, list | tuple):
        for relation_index, relation_item in enumerate(relations):
            if not isinstance(relation_item, Mapping):
                continue
            proof_ref = relation_item.get("proof_ref")
            if isinstance(proof_ref, str):
                refs.append(
                    (
                        proof_ref,
                        entry.artifact_ref.artifact_id,
                        f"/relations/{relation_index}/proof_ref",
                        None,
                    )
                )
    transcript = artifact.get("checker_transcript_ref")
    if isinstance(transcript, str):
        refs.append((transcript, entry.artifact_ref.artifact_id, "/checker_transcript_ref", None))
    proof_payload = artifact.get("proof")
    if isinstance(proof_payload, Mapping):
        for key in ("infeasibility_ref", "inclusion_ref", "disjointness_ref"):
            value = proof_payload.get(key)
            if isinstance(value, str):
                refs.append((value, entry.artifact_ref.artifact_id, f"/proof/{key}", None))
        for key in ("witness_refs", "artifact_conflict_refs", "evidence_refs", "reason_refs"):
            values = proof_payload.get(key, ())
            if isinstance(values, list | tuple):
                for index, value in enumerate(values):
                    if isinstance(value, str):
                        refs.append(
                            (
                                value,
                                entry.artifact_ref.artifact_id,
                                f"/proof/{key}/{index}",
                                None,
                            )
                        )
    witness_refs = artifact.get("witness_provenance_refs", ())
    if isinstance(witness_refs, list | tuple):
        for index, value in enumerate(witness_refs):
            if isinstance(value, str):
                refs.append(
                    (
                        value,
                        entry.artifact_ref.artifact_id,
                        f"/witness_provenance_refs/{index}",
                        None,
                    )
                )
    for key in ("artifact_refs", "set_refs", "obligation_refs", "proof_refs", "provenance_refs"):
        values = artifact.get(key, ())
        if isinstance(values, list | tuple):
            for index, value in enumerate(values):
                if isinstance(value, str):
                    refs.append((value, entry.artifact_ref.artifact_id, f"/{key}/{index}", None))
                elif isinstance(value, Mapping):
                    source_artifact = value.get("source_artifact", value.get("artifact_ref"))
                    source_path = value.get("source_path", "")
                    if source_artifact is not None:
                        refs.append(
                            (
                                f"{source_artifact}#{source_path}",
                                entry.artifact_ref.artifact_id,
                                f"/{key}/{index}",
                                _ref_digest(value),
                            )
                        )
    for key in ("reason_refs",):
        values = artifact.get(key, ())
        if isinstance(values, list | tuple):
            for index, value in enumerate(values):
                if isinstance(value, str):
                    refs.append((value, entry.artifact_ref.artifact_id, f"/{key}/{index}", None))
                elif isinstance(value, Mapping):
                    source_artifact = value.get("source_artifact")
                    source_path = value.get("source_path", "")
                    if source_artifact is not None:
                        refs.append(
                            (
                                f"{source_artifact}#{source_path}",
                                entry.artifact_ref.artifact_id,
                                f"/{key}/{index}",
                                _ref_digest(value),
                            )
                        )
    return tuple(refs)


def build_reference_ledger(bundle: ArtifactBundle, *, strict: bool = False) -> ReferenceLedger:
    store = ArtifactStore()
    for entry in bundle.entries:
        try:
            store.add(entry.artifact_ref, entry.artifact)
        except ValueError as exc:
            result = _ledger_failure(
                FailureCode.ARTIFACT_CONFLICT,
                str(exc),
                source_artifact=entry.artifact_ref.artifact_id,
                source_path="/artifact_ref",
                status=ValidationStatus.CONFLICT,
            )
            return ReferenceLedger((), ((entry.artifact_ref.artifact_id, ""),), result, ())

    resolved: list[ResolvedReference] = []
    entries: list[ReferenceLedgerEntry] = []
    unresolved: list[tuple[str, str]] = []
    for entry in bundle.entries:
        for ref_value, owner_artifact, owner_path, expected_digest in _iter_mapping_refs(entry):
            ref_result = _resolve_ledger_ref(
                ref_value,
                expected_digest=expected_digest,
                bundle=bundle,
                store=store,
                resolved=resolved,
                entries=entries,
                unresolved=unresolved,
                owner_artifact=owner_artifact,
                owner_path=owner_path,
                strict=strict,
            )
            if ref_result is not None and not ref_result.passed:
                return ReferenceLedger(
                    tuple(resolved), tuple(unresolved), ref_result, tuple(entries)
                )
    return ReferenceLedger(
        tuple(resolved),
        tuple(unresolved),
        pass_validation(ValidationStage.AUTHORITY_EMIT),
        tuple(entries),
    )
