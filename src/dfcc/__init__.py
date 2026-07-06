"""Dynamic Future-Claim Certification reference implementation."""

from dfcc.artifacts import ArtifactBundle, artifact_bundle_from_json
from dfcc.authority import check_authority
from dfcc.certificate import certify_claim, certify_claim_from_artifact_bundle, update_certificate
from dfcc.kernel import KernelProof, ProofRef, kernel_verdict
from dfcc.replay import replay_authority_from_bundle
from dfcc.runtime import ResolvedAuthorityRuntime
from dfcc.types import (
    AuthorityOutcome,
    BlockingRecord,
    Direction,
    FailureCode,
    FailureRecord,
    GateDecision,
    GuardStatus,
    Layer,
    ReasonRef,
    ValidationResult,
    ValidationStatus,
    VerdictCode,
)
from dfcc.validation import PipelineReport, validate_artifact_bundle

__version__ = "1.1.0.dev0"

__all__ = [
    "ArtifactBundle",
    "AuthorityOutcome",
    "BlockingRecord",
    "Direction",
    "FailureCode",
    "FailureRecord",
    "GateDecision",
    "GuardStatus",
    "KernelProof",
    "Layer",
    "PipelineReport",
    "ProofRef",
    "ReasonRef",
    "ResolvedAuthorityRuntime",
    "ValidationResult",
    "ValidationStatus",
    "VerdictCode",
    "__version__",
    "artifact_bundle_from_json",
    "certify_claim",
    "certify_claim_from_artifact_bundle",
    "check_authority",
    "kernel_verdict",
    "replay_authority_from_bundle",
    "update_certificate",
    "validate_artifact_bundle",
]
