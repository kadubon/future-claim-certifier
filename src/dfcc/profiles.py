"""Schema and conformance profile records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

JSON_SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema"
JCS_CANONICALIZATION = "rfc8785-jcs"
BASE_SCHEMA_PROFILE = "dfcc-json/0.1"


@dataclass(frozen=True, slots=True)
class SchemaProfile:
    schema_id: str = BASE_SCHEMA_PROFILE
    dialect: str = JSON_SCHEMA_2020_12
    version: str = "0.1"
    required_fields: tuple[str, ...] = ()
    optional_fields: tuple[str, ...] = ()
    closed_world: bool = True
    compatibility_rule: str | None = None


@dataclass(frozen=True, slots=True)
class ConformanceProfile:
    profile_id: str
    version: str
    feature_set: tuple[str, ...]
    required_checks: tuple[str, ...]
    failure_code_set: tuple[str, ...]
    golden_case_set: tuple[str, ...] = ()
    compatibility_rule: str | None = None


DFCC_INTEROP = ConformanceProfile(
    profile_id="DFCC-Interop",
    version="0.1",
    feature_set=(
        "canonical-json",
        "json-schema",
        "manifest-digest",
        "artifact-ref",
        "json-pointer",
    ),
    required_checks=(
        "Parse",
        "Canonicalize",
        "SchemaValidate",
        "DigestCheck",
        "ReferenceResolve",
        "ProfileResolve",
    ),
    failure_code_set=(
        "schema_invalid",
        "canonicalization_mismatch",
        "digest_mismatch",
        "missing_ref",
        "unsupported_profile",
        "artifact_conflict",
    ),
)


DFCC_CORE = ConformanceProfile(
    profile_id="DFCC-Core",
    version="0.1",
    feature_set=("finite-claim", "issue-certificate", "checked-kernel"),
    required_checks=("GuardEvaluate", "KernelCheck"),
    failure_code_set=(
        "schema_invalid",
        "digest_mismatch",
        "artifact_conflict",
        "checker_unknown",
    ),
)


DFCC_STATUS = ConformanceProfile(
    profile_id="DFCC-Status",
    version="0.1",
    feature_set=("time-basis", "event-order", "status-fold", "blocking-set"),
    required_checks=("Replay", "GuardEvaluate"),
    failure_code_set=(
        "clock_boundary_unknown",
        "trace_conflict",
        "validity_unknown",
        "validity_conflict",
        "expired",
        "revoked",
        "superseded",
    ),
)


DFCC_OPERATIONAL = ConformanceProfile(
    profile_id="DFCC-Operational",
    version="0.1",
    feature_set=("assessment-frame", "prefix-admission", "fiber-association", "adjudication"),
    required_checks=("GuardEvaluate", "AuthorityEmit"),
    failure_code_set=(
        "prefix_unsound",
        "exact_prefix_empty",
        "completion_missing",
        "assoc_empty",
        "assoc_mixed",
        "out_of_frame",
        "policy_block",
    ),
)


IMPLEMENTED_PROFILES: dict[str, ConformanceProfile] = {
    p.profile_id: p for p in (DFCC_INTEROP, DFCC_CORE, DFCC_STATUS, DFCC_OPERATIONAL)
}


@dataclass(frozen=True, slots=True)
class ProfileResolution:
    requested_profile: str
    implemented_profile: str | None
    version_relation: str
    enabled_features: tuple[str, ...] = ()
    closed_world: bool = True
    extension_mapping: dict[str, str] = field(default_factory=dict)
    status: str = "pass"
    reason_refs: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "requested_profile": self.requested_profile,
            "implemented_profile": self.implemented_profile,
            "version_relation": self.version_relation,
            "enabled_features": list(self.enabled_features),
            "closed_world": self.closed_world,
            "extension_mapping": dict(self.extension_mapping),
            "status": self.status,
            "reason_refs": list(self.reason_refs),
        }


@dataclass(frozen=True, slots=True)
class UseFieldPolicy:
    required_fields: tuple[str, ...]
    forbidden_fields: tuple[str, ...] = ()
    not_applicable_fields: tuple[str, ...] = ()


OPERATIONAL_STATUS_REFS = (
    "completion_admission_ref",
    "exact_fiber_assoc_ref",
    "fiber_assoc_view_ref",
    "adjudication_views_ref",
    "agreement_ref",
)


BASE_STATUS_AUTHORITY_FIELDS = (
    "certificate_id",
    "schema_profile_ref",
    "canonicalization_profile_ref",
    "manifest_digest",
    "validation_result_ref",
    "proposed_use_ref",
    "fold_context_ref",
    "status_coordinates_ref",
    "blocking_set_ref",
    "dominant_status",
    "status_observation_context_ref",
    "prefix_view_ref",
    "residual_context_ref",
    "validity_view_ref",
    "kernel_view_ref",
    "gate_decision_ref",
    "authority_outcome",
    "set_refs",
    "artifact_refs",
    "obligation_refs",
    "reason_refs",
)


def status_authority_field_policy(use: str, outcome_code: str) -> UseFieldPolicy:
    operational = use in {"operational", "frame-relative assessment", "control_gating"}
    if operational:
        del outcome_code
        return UseFieldPolicy(
            required_fields=(*BASE_STATUS_AUTHORITY_FIELDS, *OPERATIONAL_STATUS_REFS),
        )
    return UseFieldPolicy(
        required_fields=BASE_STATUS_AUTHORITY_FIELDS,
        not_applicable_fields=OPERATIONAL_STATUS_REFS,
    )


def _string_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable):
        return tuple(str(item) for item in value)
    return ()


def _profile_from_source(source: Any, fallback_id: str | None = None) -> ConformanceProfile | None:
    if isinstance(source, ConformanceProfile):
        return source
    if not isinstance(source, Mapping):
        return None
    profile_id = source.get("profile_id", source.get("id", fallback_id))
    if profile_id is None:
        return None
    return ConformanceProfile(
        profile_id=str(profile_id),
        version=str(source.get("version", "0.1")),
        feature_set=_string_tuple(source.get("feature_set", ())),
        required_checks=_string_tuple(source.get("required_checks", ())),
        failure_code_set=_string_tuple(source.get("failure_code_set", ())),
        golden_case_set=_string_tuple(source.get("golden_case_set", ())),
        compatibility_rule=str(source["compatibility_rule"])
        if source.get("compatibility_rule") is not None
        else None,
    )


def _extension_mapping_from_source(source: Any) -> dict[str, str]:
    if not isinstance(source, Mapping):
        return {}
    value = source.get("extension_mapping", {})
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _implemented_profile_map(
    implemented_profiles: Any | None,
) -> tuple[dict[str, ConformanceProfile], dict[str, dict[str, str]]]:
    if not implemented_profiles:
        return dict(IMPLEMENTED_PROFILES), {key: {} for key in IMPLEMENTED_PROFILES}
    profiles: dict[str, ConformanceProfile] = {}
    extensions: dict[str, dict[str, str]] = {}
    if isinstance(implemented_profiles, Mapping):
        items = implemented_profiles.items()
        for fallback_id, source in items:
            profile = _profile_from_source(source, str(fallback_id))
            if profile is None:
                continue
            profiles[profile.profile_id] = profile
            extensions[profile.profile_id] = _extension_mapping_from_source(source)
    else:
        for source in implemented_profiles:
            profile = _profile_from_source(source)
            if profile is None:
                continue
            profiles[profile.profile_id] = profile
            extensions[profile.profile_id] = _extension_mapping_from_source(source)
    return profiles, extensions


def resolve_profile(
    requested_profile: str,
    implemented_profiles: Any | None = None,
) -> ProfileResolution:
    profiles, extension_mappings = _implemented_profile_map(implemented_profiles)
    profile = profiles.get(requested_profile)
    if profile is None:
        return ProfileResolution(
            requested_profile=requested_profile,
            implemented_profile=None,
            version_relation="unsupported",
            status="unsupported_profile",
            reason_refs=(f"profile:unsupported:{requested_profile}",),
        )
    extension_mapping = extension_mappings.get(profile.profile_id, {})
    if profile.compatibility_rule:
        from dfcc.types import FailureCode

        base_failure_codes = {item.value for item in FailureCode}
        unmapped_failure_codes = tuple(
            failure_code
            for failure_code in profile.failure_code_set
            if failure_code not in base_failure_codes
            and extension_mapping.get(failure_code) not in base_failure_codes
        )
        if unmapped_failure_codes:
            return ProfileResolution(
                requested_profile=requested_profile,
                implemented_profile=profile.profile_id,
                version_relation="unsupported",
                enabled_features=profile.feature_set,
                extension_mapping=extension_mapping,
                status="unsupported_profile",
                reason_refs=tuple(
                    f"profile:unmapped_failure_code:{failure_code}"
                    for failure_code in unmapped_failure_codes
                ),
            )
    version_relation = "compatible" if profile.compatibility_rule else "exact"
    return ProfileResolution(
        requested_profile=requested_profile,
        implemented_profile=profile.profile_id,
        version_relation=version_relation,
        enabled_features=profile.feature_set,
        extension_mapping=extension_mapping,
        status="pass",
    )
