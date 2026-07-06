# Agent Usage

DFCC helps an agent decide whether a future-facing statement can be used as
authority. It is useful when an agent must avoid acting on stale, incomplete, or
conflicting evidence.

Use DFCC as a gate. Let it return `assert`, `deny`, `accept`, `reject`,
`unknown`, `expired`, `out_of_frame`, or `conflict`, then branch on that typed
result.

## Recommended Flow

1. Encode the future claim as the JSON claim AST.
2. Encode the assumptions or provide accepted clause artifacts.
3. Issue a certificate from an artifact bundle when the result will be used as
   authority.
4. At use time, call `dfcc validate-bundle --full-replay`,
   `dfcc replay-status --bundle`, or artifact-bundle `check_authority`.
5. Treat only an allowing outcome with an empty blocking set as authority.
6. Preserve the returned `reason_ref_records` and `blocking_records` for audit.

For strict use, prefer artifact-bundle replay:

```bash
uv run dfcc validate-bundle artifact-bundle.json --full-replay
uv run dfcc replay-status --bundle artifact-bundle.json
```

## What The Agent Should Trust

Trust these as authority only when the blocking set is empty:

- `assert`: represented claim can be used as true.
- `deny`: represented claim can be used as false.
- `accept`: operational target is allowed.
- `reject`: operational target is rejected.

Do not treat these as permission to act:

- `unknown`: gather missing proof, dependency, monitor, prefix, or completion
  evidence.
- `expired`: issue a fresh certificate or use a historical-only workflow.
- `out_of_frame`: change the proposed use or obtain a transfer proof.
- `conflict`: resolve artifact or event disagreement before choosing a side.
- `policy_block`: the protocol result exists, but policy does not allow this
  use.

## Minimal Python Example

```python
from dfcc.validation import validate_artifact_bundle

report = validate_artifact_bundle(artifact_bundle, full_replay=True)
view = report.authority_view

if view is not None and view.authority_outcome.code == "assert" and not view.blocking_set:
    use_claim_as_represented_authority()
else:
    store_reasons_for_audit(report.final_result.reason_refs)
```

`certify_claim` and direct `check_authority(certificate, use, status)` are
legacy convenience APIs. They are useful for local experiments, but by default
direct authority inputs return blocking `unknown` because the inputs are
synthetic trust. Passing `allow_synthetic_trust=True` is an explicit migration
choice, not the strict protocol path.

## Operational Use

Operational authority asks more than "is the represented claim true?". It also
requires accepted observation, completion, fiber, adjudication, adequacy,
agreement, and policy evidence.

The implementation does not accept operational declarations by themselves.
Records such as `operational_completions`, `target_adjudication`, or
`adequacy_direction` are fallback audit data unless backed by resolved proof or
checker evidence.

## Failure Handling Table

| Outcome or failure | Agent action |
| --- | --- |
| `schema_invalid` | Fix the JSON shape before retrying. |
| `digest_mismatch` | Re-fetch or reject the artifact; identity changed. |
| `missing_ref` | Add the referenced artifact, reason, obligation, or proof. |
| `checker_unknown` | Ask a checker/prover for accepted evidence. |
| `artifact_conflict` | Stop; two accepted records disagree. |
| `expired` | Re-issue or avoid current-time use. |
| `trace_conflict` | Resolve lifecycle trace disagreement. |
| `policy_block` | Do not override policy with a kernel verdict. |

## Logging Guidance

Agents should log the authority outcome digest, blocking ids, artifact digests,
and JSON Pointer reason paths. Avoid logging secret artifact payloads unless
the deployment policy explicitly allows it.
