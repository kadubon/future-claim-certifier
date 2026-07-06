"""JSON Schema validation for DFCC artifacts."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from referencing import Registry, Resource

from dfcc.types import (
    FailureCode,
    Layer,
    ValidationResult,
    ValidationStage,
    ValidationStatus,
    pass_validation,
    validation_failure,
)

SCHEMA_PACKAGE = "dfcc.schemas"


def list_schemas() -> tuple[str, ...]:
    root = files(SCHEMA_PACKAGE)
    return tuple(sorted(item.name for item in root.iterdir() if item.name.endswith(".json")))


def load_schema(name: str) -> dict[str, Any]:
    resource = files(SCHEMA_PACKAGE).joinpath(name)
    with resource.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise TypeError(f"schema {name} is not a JSON object")
    return loaded


@lru_cache
def _schema_registry() -> Registry:
    resources: list[tuple[str, Resource[Any]]] = []
    root = files(SCHEMA_PACKAGE)
    for schema_name in list_schemas():
        resource = root.joinpath(schema_name)
        with resource.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            continue
        schema_id = loaded.get("$id")
        if isinstance(schema_id, str) and schema_id:
            resources.append((schema_id, Resource.from_contents(loaded)))
    return Registry().with_resources(resources)


def validate_json_schema(
    instance: Any, schema: dict[str, Any], *, artifact_id: str = "input"
) -> ValidationResult:
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, registry=_schema_registry())
        validator.validate(instance)
    except SchemaError as exc:
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.SCHEMA_VALIDATE,
            f"invalid schema: {exc.message}",
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
        )
    except ValidationError as exc:
        path = "/" + "/".join(str(part) for part in exc.absolute_path)
        if path == "/":
            path = ""
        if exc.validator == "required":
            missing_field = None
            if isinstance(exc.message, str) and exc.message.startswith("'"):
                parts = exc.message.split("'", 2)
                if len(parts) >= 2:
                    missing_field = parts[1]
            if missing_field:
                parent = path.rstrip("/")
                path = f"{parent}/{missing_field}" if parent else f"/{missing_field}"
        return validation_failure(
            FailureCode.SCHEMA_INVALID,
            ValidationStage.SCHEMA_VALIDATE,
            exc.message,
            status=ValidationStatus.INVALID_ARTIFACT,
            layer=Layer.INTEROP,
            source_artifact=artifact_id,
            source_path=path,
        )
    return pass_validation(ValidationStage.SCHEMA_VALIDATE)


def validate_named_schema(
    instance: Any, schema_name: str, *, artifact_id: str = "input"
) -> ValidationResult:
    return validate_json_schema(instance, load_schema(schema_name), artifact_id=artifact_id)
