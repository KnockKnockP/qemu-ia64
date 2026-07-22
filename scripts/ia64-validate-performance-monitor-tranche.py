#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate atomic performance-monitor selector and discovery contracts."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.performance-monitor-tranche"
SPDX_DECLARATION = "SPDX-" + "License-Identifier: GPL-2.0-or-later"
ROOT_KEYS = {
    "$comment", "schema", "schema_version", "profile", "test_id", "cases",
}
CASE_KEYS = {
    "id", "case_id", "normative_token", "normative_row",
    "implementation_rows", "citation", "preconditions", "inputs",
    "expected_results", "allowed_results", "permitted_state_changes",
    "required_unchanged_state", "expected_faults", "fault_priority",
    "committed_prefix", "restart_action", "applicable_variants",
    "execution", "oracle", "limitations",
}
CITATION_KEYS = {"document_id", "section", "printed_pages", "anchor"}
EXPECTED = {
    "PAL-012-PERF-MON-REGISTER-DISCOVERY": {
        "implementation_rows": ["platform.firmware.pal-perf-mon-info"],
        "probe": "test_pal_performance_monitor_info",
    },
    "REG-006-PMC-INDEX-SPACE": {
        "implementation_rows": [
            "cpu.register.pmc.0", "cpu.register.pmc.1",
            "cpu.register.pmc.2", "cpu.register.pmc.3",
            "cpu.register.pmc.4", "cpu.register.pmc.5",
            "cpu.register.pmc.6", "cpu.register.pmc.7",
        ],
        "probe": "test_performance_register_selector_domains",
    },
    "REG-006-PMD-INDEX-SPACE": {
        "implementation_rows": [
            "cpu.register.pmd.4", "cpu.register.pmd.5",
            "cpu.register.pmd.6", "cpu.register.pmd.7",
        ],
        "probe": "test_performance_register_selector_domains",
    },
}


class TrancheError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrancheError(f"cannot load {path}: {exc}") from exc


def exact_keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise TrancheError(f"{label}: expected an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        raise TrancheError(
            f"{label}: missing={missing or 'none'} extra={extra or 'none'}"
        )


def string_list(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise TrancheError(f"{label}: expected strings")
    if not allow_empty and not value:
        raise TrancheError(f"{label}: must not be empty")
    if len(value) != len(set(value)):
        raise TrancheError(f"{label}: duplicate entry")
    return value


def python_functions(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        raise TrancheError(f"cannot inspect {path}: {exc}") from exc
    return {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def validate(document: Any, catalogue: Any, root: Path) -> int:
    exact_keys(document, ROOT_KEYS, "tranche root")
    if document["$comment"] != SPDX_DECLARATION:
        raise TrancheError("SPDX declaration changed")
    if document["schema"] != SCHEMA or document["schema_version"] != 1:
        raise TrancheError("unsupported tranche schema/version")
    if document["profile"] != "vibtanium-strict-up" or document["test_id"] != 708:
        raise TrancheError("profile or stable test id changed")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    if not set(EXPECTED) <= set(catalogue_rows):
        raise TrancheError("performance-monitor rows disappeared from catalogue")
    functions = python_functions(root / "tests/unit/test-ia64-system-tcg.py")
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED):
        raise TrancheError("performance-monitor tranche must contain three cases")
    identifiers = [case.get("id") for case in cases]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != len(cases):
        raise TrancheError("case ids must be unique and sorted")

    seen_rows: set[str] = set()
    for index, case in enumerate(cases, 1):
        label = f"case {case.get('id', index)}"
        exact_keys(case, CASE_KEYS, label)
        if case["case_id"] != index or case["normative_token"] != index + 120:
            raise TrancheError(f"{label}: stable numeric ids drifted")
        row_id = case["normative_row"]
        if row_id not in EXPECTED or row_id in seen_rows:
            raise TrancheError(f"{label}: unknown or duplicate normative row")
        seen_rows.add(row_id)
        expected = EXPECTED[row_id]
        if case["implementation_rows"] != expected["implementation_rows"]:
            raise TrancheError(f"{label}: implementation mapping changed")

        citation = case["citation"]
        exact_keys(citation, CITATION_KEYS, f"{label} citation")
        specification = catalogue_rows[row_id]["specification"]
        if citation != {key: specification[key] for key in CITATION_KEYS}:
            raise TrancheError(f"{label}: citation differs from catalogue")
        if catalogue_rows[row_id]["required_evidence"] != "E2":
            raise TrancheError(f"{label}: required evidence changed")

        for field in (
            "preconditions", "inputs", "expected_results", "allowed_results",
            "permitted_state_changes", "required_unchanged_state",
            "applicable_variants", "limitations",
        ):
            string_list(case[field], f"{label} {field}")
        string_list(case["expected_faults"], f"{label} expected_faults",
                    allow_empty=True)
        string_list(case["fault_priority"], f"{label} fault_priority",
                    allow_empty=True)
        if bool(case["expected_faults"]) != bool(case["fault_priority"]):
            raise TrancheError(f"{label}: fault and priority metadata disagree")
        for field in ("committed_prefix", "restart_action"):
            if not isinstance(case[field], str) or not case[field]:
                raise TrancheError(f"{label}: {field} must not be empty")

        exact_keys(case["execution"], {"lane", "probes", "result_observations"},
                   f"{label} execution")
        probes = string_list(case["execution"]["probes"], f"{label} probes")
        if case["execution"]["lane"] != "bare-metal-batch":
            raise TrancheError(f"{label}: execution lane changed")
        if probes != [expected["probe"]] or expected["probe"] not in functions:
            raise TrancheError(f"{label}: executable probe is missing or changed")
        string_list(case["execution"]["result_observations"],
                    f"{label} result observations")
        exact_keys(case["oracle"], {"independence", "derivation"},
                   f"{label} oracle")
        if case["oracle"]["independence"] != "independent":
            raise TrancheError(f"{label}: row oracle must be independent")
        if not isinstance(case["oracle"]["derivation"], str) or not case["oracle"]["derivation"]:
            raise TrancheError(f"{label}: oracle derivation is missing")

    if seen_rows != set(EXPECTED):
        raise TrancheError("performance-monitor row coverage is incomplete")
    return len(cases)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    root = parse_args(argv).root.resolve()
    try:
        cases = validate(
            load_json(root / "tests/ia64-conformance/performance-monitor-tranche.json"),
            load_json(root / "tests/ia64-conformance/normative-catalogue.json"),
            root,
        )
    except TrancheError as exc:
        print(f"Performance-monitor tranche validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Performance-monitor tranche metadata is valid: {cases} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
