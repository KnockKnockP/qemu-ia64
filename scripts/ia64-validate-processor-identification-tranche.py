#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate the atomic CPUID fixed-selector contract."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.processor-identification-tranche"
ROW = "REG-003-CPUID-FIXED-SELECTOR-DOMAIN"
IMPLEMENTATION_ROWS = [f"cpu.register.cpuid.{index}" for index in range(5)]
CASE_KEYS = {
    "id", "case_id", "normative_token", "normative_row",
    "implementation_rows", "citation", "preconditions", "inputs",
    "expected_results", "allowed_results", "permitted_state_changes",
    "required_unchanged_state", "expected_faults", "fault_priority",
    "committed_prefix", "restart_action", "applicable_variants",
    "execution", "oracle", "limitations",
}


class TrancheError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrancheError(f"cannot load {path}: {exc}") from exc


def require_keys(value: Any, keys: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise TrancheError(f"{label}: expected exact keys {sorted(keys)}")


def string_list(value: Any, label: str) -> list[str]:
    if (not isinstance(value, list) or not value or
            any(not isinstance(item, str) or not item for item in value) or
            len(value) != len(set(value))):
        raise TrancheError(f"{label}: expected unique nonempty strings")
    return value


def validate(document: Any, catalogue: Any, root: Path) -> None:
    require_keys(document, {
        "$comment", "schema", "schema_version", "profile", "test_id", "cases",
    }, "tranche root")
    if document["$comment"] != "SPDX-License-Identifier: GPL-2.0-or-later":
        raise TrancheError("SPDX declaration changed")
    if (document["schema"] != SCHEMA or document["schema_version"] != 1 or
            document["profile"] != "vibtanium-strict-up" or
            document["test_id"] != 709):
        raise TrancheError("schema, profile, or stable test id changed")
    if not isinstance(document["cases"], list) or len(document["cases"]) != 1:
        raise TrancheError("processor-identification tranche must have one case")

    case = document["cases"][0]
    require_keys(case, CASE_KEYS, "CPUID case")
    if (case["id"] != ROW + "-EXACT" or case["case_id"] != 1 or
            case["normative_token"] != 124 or case["normative_row"] != ROW):
        raise TrancheError("stable CPUID case identity changed")
    if case["implementation_rows"] != IMPLEMENTATION_ROWS:
        raise TrancheError("CPUID implementation mapping changed")

    rows = {row["id"]: row for row in catalogue.get("rows", [])}
    if ROW not in rows or rows[ROW].get("required_evidence") != "E2":
        raise TrancheError("CPUID catalogue row disappeared or changed level")
    specification = rows[ROW]["specification"]
    citation_keys = {"document_id", "section", "printed_pages", "anchor"}
    require_keys(case["citation"], citation_keys, "CPUID citation")
    if case["citation"] != {key: specification[key] for key in citation_keys}:
        raise TrancheError("CPUID citation differs from catalogue")

    for field in (
        "preconditions", "inputs", "expected_results", "allowed_results",
        "permitted_state_changes", "required_unchanged_state",
        "expected_faults", "fault_priority", "applicable_variants",
        "limitations",
    ):
        string_list(case[field], f"CPUID {field}")
    for field in ("committed_prefix", "restart_action"):
        if not isinstance(case[field], str) or not case[field]:
            raise TrancheError(f"CPUID {field} is missing")

    require_keys(case["execution"], {"lane", "probes", "result_observations"},
                 "CPUID execution")
    if (case["execution"]["lane"] != "bare-metal-batch" or
            string_list(case["execution"]["probes"], "CPUID probes") !=
            ["test_cpuid_selector_domain"]):
        raise TrancheError("CPUID execution binding changed")
    string_list(case["execution"]["result_observations"],
                "CPUID result observations")
    require_keys(case["oracle"], {"independence", "derivation"},
                 "CPUID oracle")
    if (case["oracle"]["independence"] != "independent" or
            not isinstance(case["oracle"]["derivation"], str) or
            not case["oracle"]["derivation"]):
        raise TrancheError("CPUID oracle is not independently specified")

    source = root / "tests/unit/test-ia64-system-tcg.py"
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    except (OSError, SyntaxError) as exc:
        raise TrancheError(f"cannot inspect runtime probe: {exc}") from exc
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    if "test_cpuid_selector_domain" not in functions:
        raise TrancheError("CPUID runtime probe is missing")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    root = parse_args(argv).root.resolve()
    try:
        validate(
            load_json(root / "tests/ia64-conformance/processor-identification-tranche.json"),
            load_json(root / "tests/ia64-conformance/normative-catalogue.json"),
            root,
        )
    except TrancheError as exc:
        print(f"Processor-identification tranche validation failed: {exc}",
              file=sys.stderr)
        return 1
    print("Processor-identification tranche metadata is valid: 1 case")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
