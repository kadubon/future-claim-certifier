"""Resolved authority runtime records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from dfcc.artifacts import ArtifactRef, ReferenceLedgerEntry, ResolvedReference
from dfcc.canonical import digest_json
from dfcc.kernel import KernelProofArtifact, ProofRef
from dfcc.records import SetRef
from dfcc.types import BlockingRecord, GuardRecord


def _resolved_reference_record(ref: ResolvedReference) -> dict[str, str]:
    return {
        "source_artifact": ref.source_artifact,
        "source_path": ref.source_path,
        "target_digest": ref.target_digest,
    }


def _proof_ref_record(ref: ProofRef) -> dict[str, str | None]:
    digest = ref.digest
    if digest is None and ref.status in {"accepted", "pass"}:
        digest = (
            ref.proof_id
            if ref.proof_id.startswith("sha")
            else digest_json(
                {
                    "proof_id": ref.proof_id,
                    "proof_kind": ref.proof_kind,
                    "artifact_ref": ref.artifact_ref,
                    "source_artifact": ref.source_artifact,
                    "source_path": ref.source_path,
                    "status": ref.status,
                }
            )
        )
    return {
        "proof_id": ref.proof_id,
        "proof_kind": ref.proof_kind,
        "artifact_ref": ref.artifact_ref,
        "source_artifact": ref.source_artifact,
        "source_path": ref.source_path,
        "digest": digest,
        "status": ref.status,
    }


def _artifact_ref_record(ref: ArtifactRef) -> dict[str, Any]:
    return {
        "artifact_id": ref.artifact_id,
        "artifact_type": ref.artifact_type,
        "schema_profile": ref.schema_profile,
        "canonicalization": ref.canonicalization,
        "media_type": ref.media_type,
        "schema_digest": ref.schema_digest,
        "canonicalization_digest": ref.canonicalization_digest,
        "digest_algorithm": ref.digest_algorithm,
        "digest_value": ref.digest_value,
        "content_uri": ref.content_uri,
        "retrieval_policy": ref.retrieval_policy,
        "immutability_policy": ref.immutability_policy,
        "provenance_refs": list(ref.provenance_refs),
        "semantic_role": ref.semantic_role,
        "dependency_labels": list(ref.dependency_labels),
    }


@dataclass(frozen=True, slots=True)
class ResolvedAuthorityRuntime:
    claim: Any
    compiled: Any
    anchor: Any
    time_basis: Any
    artifact_refs: tuple[ArtifactRef, ...] = ()
    ledger_entries: tuple[ReferenceLedgerEntry, ...] = ()
    resolved_obligations: tuple[ResolvedReference, ...] = ()
    resolved_reason_refs: tuple[ResolvedReference, ...] = ()
    accepted_clause_refs: tuple[str, ...] = ()
    compiled_bundle_ref: str | None = None
    set_ref_records: tuple[SetRef, ...] = ()
    proof_refs: tuple[ProofRef, ...] = ()
    kernel_proof_artifacts: tuple[KernelProofArtifact, ...] = ()
    guard_records: tuple[GuardRecord, ...] = ()
    stage_blockers: tuple[BlockingRecord, ...] = ()
    strict_replay: bool = False
    synthetic_trust: bool = False
    allow_synthetic_trust: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "compiled_bundle_ref": self.compiled_bundle_ref,
            "accepted_clause_refs": list(self.accepted_clause_refs),
            "artifact_refs": [ref.artifact_id for ref in self.artifact_refs],
            "artifact_ref_records": [_artifact_ref_record(ref) for ref in self.artifact_refs],
            "ledger_entries": len(self.ledger_entries),
            "set_ref_records": [
                {
                    "carrier_ref": record.carrier_ref,
                    "encoding_kind": record.encoding_kind,
                    "constraint_ref": record.constraint_ref,
                    "approximation_kind": record.approximation_kind,
                    "soundness_ref": record.soundness_ref,
                    "digest": record.digest,
                }
                for record in self.set_ref_records
            ],
            "resolved_obligations": [
                f"{ref.source_artifact}#{ref.source_path}" for ref in self.resolved_obligations
            ],
            "resolved_obligation_records": [
                _resolved_reference_record(ref) for ref in self.resolved_obligations
            ],
            "resolved_reason_refs": [
                f"{ref.source_artifact}#{ref.source_path}" for ref in self.resolved_reason_refs
            ],
            "resolved_reason_ref_records": [
                _resolved_reference_record(ref) for ref in self.resolved_reason_refs
            ],
            "proof_refs": [ref.proof_id for ref in self.proof_refs],
            "proof_ref_records": [_proof_ref_record(ref) for ref in self.proof_refs],
            "kernel_proof_artifacts": [proof.artifact_id for proof in self.kernel_proof_artifacts],
            "strict_replay": self.strict_replay,
            "synthetic_trust": self.synthetic_trust,
            "allow_synthetic_trust": self.allow_synthetic_trust,
        }
