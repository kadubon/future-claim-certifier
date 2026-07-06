# Architecture

Future Claim Certifier is a replay engine for time-bound claims. It keeps the
record of what was checked, then later recomputes whether that record can still
be used.

The important design rule is conservative authority: if evidence is missing,
expired, conflicting, or outside the declared frame, the system returns a
blocked or unknown result instead of pretending the claim is safe to use.

## Plain-Language Model

1. A claim says something about future states.
2. A certificate records the claim, time basis, assumptions, and proof/checking
   material at issue time.
3. A use request asks whether the certificate can be used now.
4. Replay rebuilds the answer from canonical artifacts.
5. The authority view returns a typed outcome and machine-readable reasons.

## Layers

Interop layer:
Canonical JSON, digesting, JSON Pointer resolution, JSON Schema validation,
artifact references, and conformance profile records.

Core represented layer:
The bounded claim language, assumption bundle compilation, finite trajectory
enumeration, checked kernel verdicts, and issue certificates.

Status layer:
Status time, horizon anchor, lifecycle events, event-order folding, dominant
status, trace conflict handling, and blocking records.

Operational layer:
Observation cuts, measurement and representation relations, completion
admission, prefix/fiber association, adjudication, adequacy, agreement, and
policy gates.

Replay layer:
Artifact bundles, accepted clauses, typed reference ledgers, resolved runtime
records, and final authority emission.

## Trust Boundary

`DFCCBackend` may be a solver, simulator, model checker, reachability engine, or
theorem prover. `DFCCChecker` is the smaller trusted boundary that checks the
evidence needed by the protocol.

The bundled `EnumeratingBackend` and `ReferenceChecker` are exact for small
finite systems. They are a reference implementation and conformance oracle, not
a replacement for every domain-specific proof engine.

## Data Flow

```text
claim + assumptions + time basis
        -> certificate
        -> artifact bundle
        -> replay trace
        -> status and guard checks
        -> kernel and operational checks
        -> authority outcome + reasons
```

Direct dictionary inputs are accepted for compatibility, but the public
authority path normalizes them into a synthetic bundle before checking. The
strict path starts from an `ArtifactBundle` and resolved references.

## Conservative Outcomes

The implementation does not coerce missing information into authority:

- validation failures stop before authority emission;
- raw evidence is audit-only unless admitted into accepted clauses;
- expired or boundary-unknown clocks block represented and operational use;
- lifecycle trace disagreement becomes `trace_conflict` unless a confluence
  proof is resolved;
- missing observation, completion, proof, or relation artifacts block
  operational `accept` and `reject`;
- policy may block a verdict, but it cannot upgrade a failed verdict.

## Extension Points

- Add a domain backend by implementing `DFCCBackend`.
- Add a proof checker by implementing `DFCCChecker`.
- Add signature verification through the lifecycle signature verifier boundary.
- Add new artifact profiles by extending schemas and profile rules without
  letting unknown extensions affect semantics by default.

