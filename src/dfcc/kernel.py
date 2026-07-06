"""Checked DFCC kernel verdicts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from dfcc.backend import DFCCBackend, DFCCChecker, EnclosureResult, ResidualContext
from dfcc.bundle import CompiledBundle
from dfcc.canonical import digest_json
from dfcc.claims import ClaimRecord, PredicateRegistry, default_predicate_registry
from dfcc.sets import FiniteSet
from dfcc.types import Direction, FailureCode, Layer, ReasonRef, VerdictCode, reason


def _bound_reference_string(value: str | None) -> bool:
    if value is None:
        return False
    ref = str(value)
    base = ref.split("#", 1)[0]
    return base.startswith("artifact:") or ref.startswith(("sha256:", "sha384:", "sha512:"))


def _optional_bound_reference(source: Mapping[str, Any], field_name: str) -> str | None:
    value = source.get(field_name)
    if value is None:
        return None
    ref = str(value)
    if not _bound_reference_string(ref):
        raise ValueError(f"kernel proof {field_name} must be artifact/digest-bound")
    return ref


def _bound_reference_tuple(values: Any, *, field_name: str) -> tuple[str, ...]:
    refs = tuple(str(item) for item in values or ())
    unbound = [ref for ref in refs if not _bound_reference_string(ref)]
    if unbound:
        raise ValueError(f"kernel proof {field_name} must be artifact/digest-bound")
    return refs


def _reference_tuple(values: Any) -> tuple[str, ...]:
    return tuple(str(item) for item in values or ())


def _bound_metadata_refs(metadata: Mapping[str, Any] | None) -> tuple[str, ...]:
    if metadata is None:
        return ()
    refs: list[str] = []
    for key, value in metadata.items():
        if not isinstance(value, str):
            continue
        if not (key.endswith("_ref") or key.endswith("_refs") or key in {"digest", "proof_ref"}):
            continue
        if _bound_reference_string(value):
            refs.append(value)
    return tuple(dict.fromkeys(refs))


def _finite_relation_ref(kind: str, outer: FiniteSet, satisfaction: FiniteSet, result: str) -> str:
    return digest_json(
        {
            "backend": "EnumeratingBackend",
            "kind": kind,
            "outer_enclosure": outer.to_json(),
            "satisfaction_set": satisfaction.to_json(),
            "result": result,
        }
    )


def _reason_ref_record_from_json(
    item: Any, *, default_artifact: str, default_path: str
) -> ReasonRef:
    if isinstance(item, Mapping):
        try:
            failure_code = FailureCode(str(item.get("failure_code", FailureCode.CHECKER_UNKNOWN)))
        except ValueError:
            failure_code = FailureCode.CHECKER_UNKNOWN
        try:
            layer = Layer(str(item.get("layer", Layer.REPRESENTED)))
        except ValueError:
            layer = Layer.REPRESENTED
        return reason(
            failure_code,
            layer,
            str(item.get("message", "kernel proof provenance")),
            source_artifact=str(item.get("source_artifact", default_artifact)),
            source_path=str(item.get("source_path", default_path)),
            reason_id=str(item["reason_id"]) if item.get("reason_id") is not None else None,
            digest=str(item["digest"]) if item.get("digest") is not None else None,
        )
    return reason(
        FailureCode.CHECKER_UNKNOWN,
        Layer.REPRESENTED,
        str(item),
        source_artifact=default_artifact,
        source_path=default_path,
    )


def _proof_reference_tuple(
    source: Mapping[str, Any],
    field_name: str,
    default: tuple[str, ...],
    *,
    strict_refs: bool,
) -> tuple[str, ...]:
    values = source.get(field_name, default)
    if strict_refs:
        return _bound_reference_tuple(values, field_name=field_name)
    return _reference_tuple(values)


def _optional_proof_reference(
    source: Mapping[str, Any],
    field_name: str,
    *,
    strict_refs: bool,
) -> str | None:
    if strict_refs:
        return _optional_bound_reference(source, field_name)
    value = source.get(field_name)
    return str(value) if value is not None else None


@dataclass(frozen=True, slots=True)
class ProofRef:
    proof_id: str
    proof_kind: str
    artifact_ref: str | None = None
    source_artifact: str | None = None
    source_path: str = ""
    digest: str | None = None
    status: str = "unknown"


@dataclass(frozen=True, slots=True)
class KernelProof:
    backend_identity: str
    proof_kind: str
    proof_status: str
    expected_verdict: str | None = None
    feasibility: str | None = None
    inclusion: str | None = None
    disjointness: str | None = None
    witness_refs: tuple[str, ...] = ()
    infeasibility_ref: str | None = None
    inclusion_ref: str | None = None
    disjointness_ref: str | None = None
    artifact_conflict_refs: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    reason_refs: tuple[str, ...] = ()
    reason_ref_records: tuple[ReasonRef, ...] = ()

    @classmethod
    def from_mapping(
        cls,
        source: Mapping[str, Any],
        *,
        witness_refs: tuple[str, ...] = (),
        evidence_refs: tuple[str, ...] = (),
        reason_refs: tuple[str, ...] = (),
        reason_ref_records: tuple[ReasonRef, ...] = (),
        strict_refs: bool = True,
    ) -> KernelProof:
        parsed_reason_ref_records = tuple(
            _reason_ref_record_from_json(
                item,
                default_artifact=str(source.get("artifact_id", "kernel-proof")),
                default_path=f"/reason_refs/{index}",
            )
            for index, item in enumerate(source.get("reason_ref_records", ()))
        )
        inline_reason_records = tuple(
            _reason_ref_record_from_json(
                item,
                default_artifact=str(source.get("artifact_id", "kernel-proof")),
                default_path=f"/reason_refs/{index}",
            )
            for index, item in enumerate(source.get("reason_refs", ()))
            if isinstance(item, Mapping)
        )
        reason_ref_records = (
            parsed_reason_ref_records or inline_reason_records or reason_ref_records
        )
        return cls(
            backend_identity=str(source.get("backend", source.get("backend_identity", ""))),
            proof_kind=str(source.get("proof_kind", source.get("proof", "unknown"))),
            proof_status=str(source.get("proof_status", source.get("status", "unknown"))),
            expected_verdict=str(source["expected_verdict"])
            if source.get("expected_verdict") is not None
            else None,
            feasibility=str(source["feasibility"])
            if source.get("feasibility") is not None
            else None,
            inclusion=str(source["inclusion"]) if source.get("inclusion") is not None else None,
            disjointness=str(source["disjointness"])
            if source.get("disjointness") is not None
            else None,
            witness_refs=_proof_reference_tuple(
                source,
                "witness_refs",
                witness_refs,
                strict_refs=strict_refs,
            ),
            infeasibility_ref=_optional_proof_reference(
                source,
                "infeasibility_ref",
                strict_refs=strict_refs,
            ),
            inclusion_ref=_optional_proof_reference(
                source,
                "inclusion_ref",
                strict_refs=strict_refs,
            ),
            disjointness_ref=_optional_proof_reference(
                source,
                "disjointness_ref",
                strict_refs=strict_refs,
            ),
            artifact_conflict_refs=_proof_reference_tuple(
                source,
                "artifact_conflict_refs",
                (),
                strict_refs=strict_refs,
            ),
            evidence_refs=_proof_reference_tuple(
                source,
                "evidence_refs",
                evidence_refs,
                strict_refs=strict_refs,
            ),
            reason_refs=tuple(
                str(item.get("reason_id", item)) if isinstance(item, Mapping) else str(item)
                for item in source.get(
                    "reason_refs",
                    tuple(ref.reason_id for ref in reason_ref_records) or reason_refs,
                )
            ),
            reason_ref_records=reason_ref_records,
        )

    def refs(self) -> tuple[ProofRef, ...]:
        refs = [
            ProofRef(
                proof_id=f"{self.backend_identity}:{self.proof_kind}",
                proof_kind=self.proof_kind,
                status=self.proof_status,
            )
        ]
        for field_name, ref in (
            ("witness", self.witness_refs),
            ("infeasibility", (self.infeasibility_ref,) if self.infeasibility_ref else ()),
            ("inclusion", (self.inclusion_ref,) if self.inclusion_ref else ()),
            ("disjointness", (self.disjointness_ref,) if self.disjointness_ref else ()),
            ("artifact_conflict", self.artifact_conflict_refs),
        ):
            refs.extend(
                ProofRef(
                    proof_id=str(item),
                    proof_kind=field_name,
                    artifact_ref=str(item),
                    status=self.proof_status,
                )
                for item in ref
            )
        return tuple(refs)

    def to_json(self) -> dict[str, Any]:
        return {
            "backend_identity": self.backend_identity,
            "proof_kind": self.proof_kind,
            "proof_status": self.proof_status,
            "expected_verdict": self.expected_verdict,
            "feasibility": self.feasibility,
            "inclusion": self.inclusion,
            "disjointness": self.disjointness,
            "witness_refs": list(self.witness_refs),
            "infeasibility_ref": self.infeasibility_ref,
            "inclusion_ref": self.inclusion_ref,
            "disjointness_ref": self.disjointness_ref,
            "artifact_conflict_refs": list(self.artifact_conflict_refs),
            "evidence_refs": list(self.evidence_refs),
            "reason_refs": list(self.reason_refs),
            "reason_ref_records": [ref.to_json() for ref in self.reason_ref_records],
        }


@dataclass(frozen=True, slots=True)
class KernelProofArtifact:
    artifact_id: str
    proof: KernelProof
    checker_transcript_ref: str | None = None
    witness_provenance_refs: tuple[str, ...] = ()
    reason_ref_records: tuple[ReasonRef, ...] = ()

    @classmethod
    def from_json(cls, source: Mapping[str, Any]) -> KernelProofArtifact:
        proof_source = source.get("proof", source)
        if not isinstance(proof_source, Mapping):
            raise TypeError("kernel proof artifact proof must be an object")
        checker_transcript_ref = (
            str(source["checker_transcript_ref"])
            if source.get("checker_transcript_ref") is not None
            else None
        )
        if checker_transcript_ref is not None and not _bound_reference_string(
            checker_transcript_ref
        ):
            raise ValueError("kernel proof checker_transcript_ref must be artifact/digest-bound")
        artifact_reason_ref_records = tuple(
            _reason_ref_record_from_json(
                item,
                default_artifact=str(source.get("artifact_id", "kernel-proof")),
                default_path=f"/reason_ref_records/{index}",
            )
            for index, item in enumerate(source.get("reason_ref_records", ()))
        )
        proof = KernelProof.from_mapping(
            proof_source,
            witness_refs=tuple(str(item) for item in source.get("witness_provenance_refs", ())),
            evidence_refs=tuple(str(item) for item in source.get("evidence_refs", ())),
            reason_refs=tuple(
                str(item.get("reason_id", item)) if isinstance(item, Mapping) else str(item)
                for item in source.get("reason_refs", ())
            ),
            reason_ref_records=artifact_reason_ref_records,
        )
        return cls(
            artifact_id=str(source["artifact_id"]),
            proof=proof,
            checker_transcript_ref=checker_transcript_ref,
            witness_provenance_refs=tuple(
                str(item) for item in source.get("witness_provenance_refs", ())
            ),
            reason_ref_records=artifact_reason_ref_records or proof.reason_ref_records,
        )

    def proof_refs(self) -> tuple[ProofRef, ...]:
        refs = self.proof.refs()
        if self.checker_transcript_ref is None:
            return refs
        return (
            *refs,
            ProofRef(
                proof_id=self.checker_transcript_ref,
                proof_kind="checker_transcript",
                artifact_ref=self.checker_transcript_ref,
                status=self.proof.proof_status,
            ),
        )


@dataclass(frozen=True, slots=True)
class KernelView:
    verdict: VerdictCode
    direction: Direction
    feasibility: str
    inclusion: str
    disjointness: str
    outer_enclosure: EnclosureResult
    satisfaction_set: FiniteSet
    evidence_refs: tuple[str, ...] = ()
    reason_refs: tuple[ReasonRef, ...] = ()
    proof_object: dict[str, object] | None = None
    proof: KernelProof | None = None
    proof_refs: tuple[ProofRef, ...] = ()
    witness_admissible: bool = False


def _direction(verdict: VerdictCode) -> Direction:
    if verdict is VerdictCode.ASSERT:
        return Direction.POSITIVE
    if verdict is VerdictCode.DENY:
        return Direction.NEGATIVE
    if verdict is VerdictCode.INFEASIBLE:
        return Direction.INFEASIBLE
    if verdict is VerdictCode.ABSTAIN:
        return Direction.NEUTRAL
    return Direction.NONE


def build_residual_context(
    compiled_bundle: CompiledBundle,
    *,
    r: int,
    p_star: FiniteSet,
    p_out: FiniteSet,
    p_in: FiniteSet | None = None,
) -> ResidualContext:
    if not p_star.subset_of(p_out):
        raise ValueError("exact prefix set must be a subset of outer prefix set")
    if p_in is not None and not p_in.subset_of(p_star):
        raise ValueError("inner prefix set must be a subset of exact prefix set")
    adm_star = compiled_bundle.residual_trajectories(p_star, r)
    adm_out = compiled_bundle.residual_trajectories(p_out, r)
    return ResidualContext(
        r=r, p_star=p_star, p_out=p_out, p_in=p_in, adm_star=adm_star, adm_out=adm_out
    )


def kernel_verdict(
    claim: ClaimRecord,
    compiled_bundle: CompiledBundle,
    residual_context: ResidualContext,
    backend: DFCCBackend,
    checker: DFCCChecker,
    *,
    registry: PredicateRegistry | None = None,
) -> KernelView:
    """Compute the paper's checked kernel verdict.

    Status, policy, frame, and guard failures are deliberately outside this
    function. Callers must evaluate those before using the returned verdict.
    """

    registry = registry or default_predicate_registry()
    problem = backend.problem(compiled_bundle, residual_context, claim)
    feasibility = backend.feasibility(problem)
    enclosure = backend.outer_enclosure(problem)
    witnesses = backend.inner_witnesses(problem, claim)
    witness_ok = checker.witness(witnesses, compiled_bundle, residual_context)
    proof_object = backend.proof_object()
    witness_refs = _bound_metadata_refs(witnesses.metadata)
    proof = KernelProof.from_mapping(
        proof_object,
        witness_refs=witness_refs,
        evidence_refs=feasibility.evidence_refs,
        reason_refs=tuple(ref.reason_id for ref in feasibility.reason_refs),
        strict_refs=False,
    )
    proof_refs = proof.refs()
    if not checker.enclosure_soundness(enclosure):
        satisfaction = FiniteSet.from_iterable(())
        return KernelView(
            verdict=VerdictCode.ABSTAIN,
            direction=Direction.NEUTRAL,
            feasibility=feasibility.status,
            inclusion="unknown",
            disjointness="unknown",
            outer_enclosure=enclosure,
            satisfaction_set=satisfaction,
            reason_refs=enclosure.reason_refs,
            proof_object=proof_object,
            proof=proof,
            proof_refs=proof_refs,
            witness_admissible=witness_ok,
        )
    if not witness_ok:
        ref = reason(
            FailureCode.CHECKER_UNKNOWN,
            Layer.REPRESENTED,
            "backend witness set is not admissible for the residual context",
        )
        satisfaction = FiniteSet.from_iterable(())
        return KernelView(
            verdict=VerdictCode.UNKNOWN,
            direction=Direction.NONE,
            feasibility=feasibility.status,
            inclusion="unknown",
            disjointness="unknown",
            outer_enclosure=enclosure,
            satisfaction_set=satisfaction,
            reason_refs=(ref,),
            proof_object=proof_object,
            proof=proof,
            proof_refs=proof_refs,
            witness_admissible=False,
        )

    if feasibility.status == "infeasible":
        if not checker.infeasibility(proof_object):
            ref = reason(
                FailureCode.CHECKER_UNKNOWN,
                Layer.REPRESENTED,
                "residual infeasibility proof object was not accepted",
            )
            satisfaction = FiniteSet.from_iterable(())
            return KernelView(
                verdict=VerdictCode.UNKNOWN,
                direction=Direction.NONE,
                feasibility=feasibility.status,
                inclusion="unknown",
                disjointness="unknown",
                outer_enclosure=enclosure,
                satisfaction_set=satisfaction,
                reason_refs=(ref,),
                proof_object=proof_object,
                proof=proof,
                proof_refs=proof_refs,
                witness_admissible=witness_ok,
            )
        satisfaction = FiniteSet.from_iterable(())
        return KernelView(
            verdict=VerdictCode.INFEASIBLE,
            direction=Direction.INFEASIBLE,
            feasibility=feasibility.status,
            inclusion="not_applicable",
            disjointness="not_applicable",
            outer_enclosure=enclosure,
            satisfaction_set=satisfaction,
            evidence_refs=feasibility.evidence_refs,
            reason_refs=feasibility.reason_refs,
            proof_object=proof_object,
            proof=proof,
            proof_refs=proof_refs,
            witness_admissible=witness_ok,
        )

    satisfaction = claim.satisfaction_set(enclosure.trajectories, registry)
    inclusion = checker.inclusion(enclosure.trajectories, satisfaction)
    disjointness = checker.disjointness(enclosure.trajectories, satisfaction)
    inclusion_ref = (
        _finite_relation_ref("inclusion", enclosure.trajectories, satisfaction, inclusion)
        if inclusion == "yes"
        else None
    )
    disjointness_ref = (
        _finite_relation_ref("disjointness", enclosure.trajectories, satisfaction, disjointness)
        if disjointness == "yes"
        else None
    )
    proof = KernelProof.from_mapping(
        {
            **proof_object,
            "inclusion": inclusion,
            "disjointness": disjointness,
            **({"inclusion_ref": inclusion_ref} if inclusion_ref is not None else {}),
            **({"disjointness_ref": disjointness_ref} if disjointness_ref is not None else {}),
        },
        witness_refs=witness_refs,
        evidence_refs=feasibility.evidence_refs,
        reason_refs=tuple(ref.reason_id for ref in feasibility.reason_refs),
        strict_refs=False,
    )
    proof_refs = proof.refs()
    if not enclosure.trajectories.is_empty() and inclusion == "yes" and disjointness == "yes":
        ref = reason(
            FailureCode.ARTIFACT_CONFLICT,
            Layer.REPRESENTED,
            "inclusion and disjointness checkers both accepted a nonempty enclosure",
        )
        return KernelView(
            verdict=VerdictCode.CONFLICT,
            direction=Direction.NONE,
            feasibility=feasibility.status,
            inclusion=inclusion,
            disjointness=disjointness,
            outer_enclosure=enclosure,
            satisfaction_set=satisfaction,
            evidence_refs=feasibility.evidence_refs,
            reason_refs=(ref,),
            proof_object=proof_object,
            proof=proof,
            proof_refs=proof_refs,
            witness_admissible=witness_ok,
        )
    if feasibility.status == "feasible" and inclusion == "yes":
        verdict = VerdictCode.ASSERT
    elif feasibility.status == "feasible" and disjointness == "yes":
        verdict = VerdictCode.DENY
    else:
        verdict = VerdictCode.ABSTAIN
    return KernelView(
        verdict=verdict,
        direction=_direction(verdict),
        feasibility=feasibility.status,
        inclusion=inclusion,
        disjointness=disjointness,
        outer_enclosure=enclosure,
        satisfaction_set=satisfaction,
        evidence_refs=feasibility.evidence_refs,
        reason_refs=feasibility.reason_refs,
        proof_object=proof_object,
        proof=proof,
        proof_refs=proof_refs,
        witness_admissible=witness_ok,
    )
