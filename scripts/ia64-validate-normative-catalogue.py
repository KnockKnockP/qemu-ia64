#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate the independent IA-64 normative catalogue foundation.

The catalogue is deliberately hand-authored from cited specifications.  This
validator checks its versioned schema and cross-row invariants without reading
QEMU decoder or implementation tables.  When a manual directory is supplied,
it also verifies that every cited PDF, extracted text, printed page, and short
citation anchor exists in the local research material.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence


DEFAULT_SCHEMA = Path("tests/ia64-conformance/normative-catalogue.schema.json")
DEFAULT_CATALOGUE = Path("tests/ia64-conformance/normative-catalogue.json")
CPU_EVIDENCE = "E2"


class CatalogueError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CatalogueError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CatalogueError(
            f"invalid JSON in {path}:{exc.lineno}:{exc.colno}: {exc.msg}"
        ) from exc


def json_type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    raise CatalogueError(
        f"validator does not support JSON Schema type {expected!r}"
    )


def resolve_ref(schema_root: dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        raise CatalogueError(
            f"only local JSON Schema references are supported: {ref}"
        )
    value: Any = schema_root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(value, dict) or token not in value:
            raise CatalogueError(f"unresolved JSON Schema reference: {ref}")
        value = value[token]
    return value


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def validate_schema_value(
    value: Any,
    schema: dict[str, Any],
    schema_root: dict[str, Any],
    path: str,
    errors: list[str],
) -> None:
    if "$ref" in schema:
        target = resolve_ref(schema_root, schema["$ref"])
        validate_schema_value(value, target, schema_root, path, errors)

    for branch in schema.get("allOf", []):
        validate_schema_value(value, branch, schema_root, path, errors)

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} is not in {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type is not None and not json_type_matches(
        value, expected_type
    ):
        errors.append(
            f"{path}: expected {expected_type}, got {type(value).__name__}"
        )
        return

    if isinstance(value, dict):
        required = schema.get("required", [])
        for name in required:
            if name not in value:
                errors.append(f"{path}: missing required property {name!r}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for name in value:
                if name not in properties:
                    errors.append(f"{path}: unexpected property {name!r}")
        for name, child_schema in properties.items():
            if name in value:
                validate_schema_value(
                    value[name], child_schema, schema_root,
                    f"{path}.{name}", errors,
                )

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(
                f"{path}: expected at least {schema['minItems']} items, "
                f"got {len(value)}"
            )
        if schema.get("uniqueItems"):
            encoded = [canonical(item) for item in value]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: array items must be unique")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(value):
                validate_schema_value(
                    item, item_schema, schema_root, f"{path}[{index}]", errors
                )

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(
                f"{path}: expected at least {schema['minLength']} characters"
            )
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(pattern, value) is None:
            errors.append(f"{path}: {value!r} does not match {pattern!r}")

    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} is less than {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(
                f"{path}: {value} is greater than {schema['maximum']}"
            )


def validate_schema(catalogue: Any, schema: Any) -> None:
    if not isinstance(schema, dict):
        raise CatalogueError("schema root must be an object")
    errors: list[str] = []
    validate_schema_value(catalogue, schema, schema, "$", errors)
    if errors:
        detail = "\n".join(f"  - {error}" for error in errors)
        raise CatalogueError(f"catalogue schema validation failed:\n{detail}")


def normalize_text(text: str) -> str:
    return " ".join(text.split()).casefold()


def validate_manual_citations(
    rows: list[dict[str, Any]], manual_dir: Path
) -> tuple[int, int]:
    if not manual_dir.is_dir():
        raise CatalogueError(f"manual directory does not exist: {manual_dir}")

    text_cache: dict[Path, list[str]] = {}
    cited_pages: set[tuple[str, str]] = set()
    manual_files: set[str] = set()

    for row in rows:
        citation = row["specification"]
        manual_name = citation["manual_file"]
        if Path(manual_name).name != manual_name:
            raise CatalogueError(f"{row['id']}: manual_file must be a basename")
        pdf_path = manual_dir / manual_name
        text_path = pdf_path.with_suffix(".txt")
        if not pdf_path.is_file():
            raise CatalogueError(
                f"{row['id']}: cited manual is missing: {pdf_path}"
            )
        if not text_path.is_file():
            raise CatalogueError(
                f"{row['id']}: extracted manual text is missing: {text_path}"
            )
        if text_path not in text_cache:
            text_cache[text_path] = text_path.read_text(
                encoding="utf-8", errors="replace"
            ).split("\f")

        chunks = text_cache[text_path]
        selected: list[str] = []
        for page in citation["printed_pages"]:
            page_pattern = re.compile(
                rf"(?<![0-9:]){re.escape(page)}(?![0-9:])"
            )
            page_chunks = [
                chunk for chunk in chunks if page_pattern.search(chunk)
            ]
            if not page_chunks:
                raise CatalogueError(
                    f"{row['id']}: printed page {page} is absent from "
                    f"{text_path.name}"
                )
            selected.extend(page_chunks)
            cited_pages.add((manual_name, page))

        anchor = normalize_text(citation["anchor"])
        cited_text = normalize_text("\n".join(selected))
        if anchor not in cited_text:
            pages = ", ".join(citation["printed_pages"])
            raise CatalogueError(
                f"{row['id']}: anchor {citation['anchor']!r} is absent from "
                f"{manual_name} printed page(s) {pages}"
            )
        manual_files.add(manual_name)

    return len(manual_files), len(cited_pages)


def validate_semantics(catalogue: dict[str, Any]) -> None:
    rows = catalogue["rows"]
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        duplicates = sorted({row_id for row_id in ids if ids.count(row_id) > 1})
        raise CatalogueError(
            f"duplicate normative row IDs: {', '.join(duplicates)}"
        )
    if ids != sorted(ids):
        raise CatalogueError("normative rows must be sorted by stable ID")

    declared_profiles = set(catalogue["profiles"])
    for row in rows:
        row_profiles = set(row["profiles"])
        if not row_profiles <= declared_profiles:
            unknown = ", ".join(sorted(row_profiles - declared_profiles))
            raise CatalogueError(
                f"{row['id']}: undeclared profile(s): {unknown}"
            )
        if row["id"].split("-", 2)[:2] != row["requirement_ids"][0].split("-"):
            raise CatalogueError(
                f"{row['id']}: first requirement ID must own the row namespace"
            )
        if row["interface_kind"].startswith("cpu."):
            if row["required_evidence"] != CPU_EVIDENCE:
                raise CatalogueError(
                    f"{row['id']}: CPU architectural rows require "
                    f"{CPU_EVIDENCE} evidence"
                )
        faults = row["possible_faults"]
        priority = row["fault_priority"]
        if bool(faults) != bool(priority):
            raise CatalogueError(
                f"{row['id']}: possible_faults and fault_priority must both be "
                "empty or both be populated"
            )
        volume = row["specification"]["volume"]
        for printed_page in row["specification"]["printed_pages"]:
            if not printed_page.startswith(f"{volume}:"):
                raise CatalogueError(
                    f"{row['id']}: printed page {printed_page} does not match "
                    f"volume {volume}"
                )


def resolve_path(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(__file__).resolve().parents[1],
        help="QEMU source root",
    )
    parser.add_argument(
        "--schema", type=Path, default=DEFAULT_SCHEMA,
        help="schema path, relative to --root by default",
    )
    parser.add_argument(
        "--catalogue", type=Path, default=DEFAULT_CATALOGUE,
        help="catalogue path, relative to --root by default",
    )
    parser.add_argument(
        "--manual-dir", type=Path,
        help="optional directory containing cited PDF and extracted text files",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = args.root.resolve()
    schema_path = resolve_path(root, args.schema).resolve()
    catalogue_path = resolve_path(root, args.catalogue).resolve()

    try:
        schema = load_json(schema_path)
        catalogue = load_json(catalogue_path)
        validate_schema(catalogue, schema)
        validate_semantics(catalogue)
        manual_summary = "manual citations not requested"
        if args.manual_dir is not None:
            manual_dir = args.manual_dir.resolve()
            manual_count, page_count = validate_manual_citations(
                catalogue["rows"], manual_dir
            )
            manual_summary = (
                f"{manual_count} manual(s), {page_count} unique printed "
                "page(s) checked"
            )
    except CatalogueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(
        f"validated {len(catalogue['rows'])} IA-64 normative rows "
        f"({manual_summary})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
