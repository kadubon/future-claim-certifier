"""Command-line interface for DFCC."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from dfcc.artifacts import artifact_bundle_from_json
from dfcc.authority import check_authority
from dfcc.bundle import compile_bundle, parse_bundle
from dfcc.canonical import digest_json
from dfcc.certificate import certify_claim, certify_claim_from_artifact_bundle
from dfcc.conformance import run_golden_cases
from dfcc.models import IssueCertificate
from dfcc.schema import list_schemas, load_schema, validate_named_schema
from dfcc.serialization import to_jsonable
from dfcc.types import ValidationResult, pass_validation
from dfcc.validation import validate_artifact_bundle


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path | None, value: Any) -> None:
    text = json.dumps(to_jsonable(value), indent=2, sort_keys=True)
    if path is None:
        print(text)
    else:
        path.write_text(f"{text}\n", encoding="utf-8")


def _cmd_digest(args: argparse.Namespace) -> int:
    value = _read_json(Path(args.file))
    print(digest_json(value, args.algorithm))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    value = _read_json(Path(args.file))
    result = validate_named_schema(value, args.schema, artifact_id=args.file)
    _write_json(Path(args.out) if args.out else None, result)
    return 0 if result.passed else 1


def _cmd_certify(args: argparse.Namespace) -> int:
    spec = _read_json(Path(args.spec))
    result = certify_claim(
        spec["claim"],
        spec["bundle"],
        spec["anchor"],
        spec["time_basis"],
        frame=spec.get("frame"),
        policy=spec.get("policy"),
        soundness_grade=int(spec.get("soundness_grade", 3)),
        allow_synthetic_trust=bool(args.allow_synthetic_trust),
    )
    _write_json(Path(args.out) if args.out else None, result)
    return 0 if not isinstance(result, ValidationResult) or result.passed else 1


def _cmd_certify_bundle(args: argparse.Namespace) -> int:
    value = _read_json(Path(args.bundle))
    result = certify_claim_from_artifact_bundle(
        artifact_bundle_from_json(value),
        status_time=args.status_time,
    )
    _write_json(Path(args.out) if args.out else None, result)
    return 0 if not isinstance(result, ValidationResult) or result.passed else 1


def _cmd_check(args: argparse.Namespace) -> int:
    cert_source = _read_json(Path(args.certificate))
    proposed_use = _read_json(Path(args.proposed_use))
    status_context = _read_json(Path(args.status_context))
    certificate = IssueCertificate.from_json(cert_source)
    result = check_authority(
        certificate,
        proposed_use,
        status_context,
        allow_synthetic_trust=bool(getattr(args, "allow_synthetic_trust", False)),
    )
    _write_json(Path(args.out) if args.out else None, result)
    return 0 if not isinstance(result, ValidationResult) or result.passed else 1


def _cmd_validate_bundle(args: argparse.Namespace) -> int:
    value = _read_json(Path(args.file))
    if isinstance(value, dict) and "artifacts" in value and "manifest" in value:
        artifact_bundle = artifact_bundle_from_json(value)
        report = validate_artifact_bundle(artifact_bundle, full_replay=bool(args.full_replay))
        _write_json(Path(args.out) if args.out else None, report)
        return 0 if report.passed else 1
    if args.horizon is None:
        raise ValueError("--horizon is required for finite assumption bundles")
    assumption_bundle = parse_bundle(value)
    compiled = compile_bundle(assumption_bundle, int(args.horizon))
    payload = {
        "validation": pass_validation(),
        "bundle_id": compiled.bundle_id,
        "horizon": compiled.horizon,
        "state_count": len(compiled.state_space),
        "initial_count": len(compiled.initial_set),
        "obligations": list(compiled.obligations),
        "dependency_graph": list(compiled.dependency_graph),
    }
    _write_json(Path(args.out) if args.out else None, payload)
    return 0


def _cmd_replay_status(args: argparse.Namespace) -> int:
    if args.bundle is not None:
        value = _read_json(Path(args.bundle))
        report = validate_artifact_bundle(
            artifact_bundle_from_json(value),
            full_replay=True,
        )
        _write_json(Path(args.out) if args.out else None, report)
        return 0 if report.passed else 1
    return _cmd_check(args)


def _cmd_golden(args: argparse.Namespace) -> int:
    results = run_golden_cases(
        Path(args.case_dir) if args.case_dir else None,
        suite=args.suite,
    )
    _write_json(None, {"results": results})
    return 0 if all(item.passed for item in results) else 1


def _cmd_conformance(args: argparse.Namespace) -> int:
    if args.action != "run":
        raise ValueError(f"unsupported conformance action: {args.action}")
    results = run_golden_cases(
        Path(args.case_dir) if args.case_dir else None,
        suite=args.suite,
    )
    _write_json(None, {"results": results})
    return 0 if all(item.passed for item in results) else 1


def _cmd_schema(args: argparse.Namespace) -> int:
    if args.action == "list":
        _write_json(None, {"schemas": list_schemas()})
        return 0
    if args.action == "export":
        schema = load_schema(args.name)
        _write_json(Path(args.out) if args.out else None, schema)
        return 0
    raise ValueError(f"unsupported schema action: {args.action}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dfcc", description="Dynamic Future-Claim Certification tools"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    digest = sub.add_parser("digest", help="print a canonical JSON digest")
    digest.add_argument("file")
    digest.add_argument("--algorithm", default="sha256", choices=["sha256", "sha384", "sha512"])
    digest.set_defaults(func=_cmd_digest)

    validate = sub.add_parser("validate", help="validate an artifact against a bundled schema")
    validate.add_argument("file")
    validate.add_argument("--schema", required=True)
    validate.add_argument("--out")
    validate.set_defaults(func=_cmd_validate)

    certify = sub.add_parser(
        "certify",
        help=(
            "issue a legacy-compatible DFCC certificate from a direct JSON spec; "
            "use certify-bundle for strict artifact-bundle issuance"
        ),
    )
    certify.add_argument("spec")
    certify.add_argument("--out")
    certify.add_argument(
        "--allow-synthetic-trust",
        action="store_true",
        help="legacy compatibility only: admit the direct raw bundle as synthetic trust",
    )
    certify.set_defaults(func=_cmd_certify)

    certify_bundle = sub.add_parser(
        "certify-bundle",
        help="issue a DFCC certificate from strict artifact-bundle accepted evidence",
    )
    certify_bundle.add_argument("bundle")
    certify_bundle.add_argument("--status-time")
    certify_bundle.add_argument("--out")
    certify_bundle.set_defaults(func=_cmd_certify_bundle)

    check = sub.add_parser("check", help="recompute status-time authority")
    check.add_argument("certificate")
    check.add_argument("proposed_use")
    check.add_argument("status_context")
    check.add_argument("--out")
    check.add_argument(
        "--allow-synthetic-trust",
        action="store_true",
        help="legacy compatibility only: allow direct synthetic trust to authorize",
    )
    check.set_defaults(func=_cmd_check)

    validate_bundle = sub.add_parser(
        "validate-bundle", help="validate an artifact bundle or compile a finite assumption bundle"
    )
    validate_bundle.add_argument("file")
    validate_bundle.add_argument("--horizon", type=int)
    validate_bundle.add_argument(
        "--full-replay",
        action="store_true",
        help="require artifact-bundle replay through authority recomputation",
    )
    validate_bundle.add_argument("--out")
    validate_bundle.set_defaults(func=_cmd_validate_bundle)

    replay = sub.add_parser("replay-status", help="replay lifecycle/status authority")
    replay.add_argument("certificate", nargs="?")
    replay.add_argument("proposed_use", nargs="?")
    replay.add_argument("status_context", nargs="?")
    replay.add_argument("--bundle")
    replay.add_argument("--out")
    replay.set_defaults(func=_cmd_replay_status)

    schema = sub.add_parser("schema", help="list or export bundled JSON Schemas")
    schema_sub = schema.add_subparsers(dest="action", required=True)
    schema_list = schema_sub.add_parser("list", help="list bundled schemas")
    schema_list.set_defaults(func=_cmd_schema)
    schema_export = schema_sub.add_parser("export", help="export a bundled schema")
    schema_export.add_argument("name")
    schema_export.add_argument("--out")
    schema_export.set_defaults(func=_cmd_schema)

    conformance = sub.add_parser("conformance", help="run DFCC conformance suites")
    conformance_sub = conformance.add_subparsers(dest="action", required=True)
    conformance_run = conformance_sub.add_parser("run", help="run golden cases")
    conformance_run.add_argument("--case-dir")
    conformance_run.add_argument(
        "--suite",
        help="run only a named suite; use 'primary' or 'legacy' for all legacy suites",
    )
    conformance_run.set_defaults(func=_cmd_conformance)

    golden = sub.add_parser("golden", help="run golden conformance cases")
    golden.add_argument("--case-dir")
    golden.add_argument(
        "--suite",
        help="run only a named suite; use 'primary' or 'legacy' for all legacy suites",
    )
    golden.set_defaults(func=_cmd_golden)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:  # pragma: no cover - CLI boundary
        print(f"dfcc: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
