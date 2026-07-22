#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate the complete IA-64 predicate-and-branch tranche metadata."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.predicate-branch-tranche"
PROFILE = "vibtanium-strict-up"
ROOT_KEYS = {"$comment", "schema", "schema_version", "profile", "test_id", "cases"}
CASE_KEYS = {
    "id", "case_id", "normative_token", "normative_row",
    "implementation_rows", "citation", "preconditions", "inputs",
    "expected_results", "allowed_results", "permitted_state_changes",
    "required_unchanged_state", "expected_faults", "fault_priority",
    "committed_prefix", "restart_action", "applicable_variants",
    "execution", "oracle",
}
CITATION_KEYS = {"document_id", "section", "printed_pages", "anchor"}
EXPECTED = {
    "BR-001-BRANCH-FORMS": ("cpu.branch.forms", [
        "test_predicate_tests_and_direct_branches",
        "test_typed_indirect_and_nonterminal_branches",
        "test_typed_loop_branches", "test_typed_call_branches",
        "test_typed_return_branches"]),
    "BR-002-TAKEN-NOT-TAKEN": ("cpu.branch.outcomes", [
        "test_predicate_tests_and_direct_branches",
        "test_typed_indirect_and_nonterminal_branches",
        "test_typed_loop_branches"]),
    "BR-003-DISPLACEMENT": ("cpu.branch.displacement", [
        "test_predicate_tests_and_direct_branches", "test_typed_call_branches"]),
    "BR-004-REGISTER-TARGET": ("cpu.branch.register-target", [
        "test_typed_indirect_and_nonterminal_branches", "test_typed_call_branches"]),
    "BR-006-LOOP-STATE": ("cpu.branch.loop-state", [
        "test_typed_loop_branches", "test_typed_return_branches"]),
    "BR-008-BRANCH-TRAPS": ("cpu.branch.traps", ["test_typed_return_branches"]),
    "BR-009-EXECUTION-BOUNDARIES": ("cpu.branch.boundaries", [
        "test_predicate_tests_and_direct_branches",
        "test_typed_indirect_and_nonterminal_branches",
        "test_typed_call_branches", "test_typed_return_branches"]),
    "PRD-001-COMPARE-RELATIONS": ("cpu.predicate.compare-relations", [
        "test_integer_compare_conformance"]),
    "PRD-002-UPDATE-COMPLETERS": ("cpu.predicate.update-completers", [
        "test_integer_compare_conformance", "test_predicate_test_conformance"]),
    "PRD-004-PAIRED-ALIAS": ("cpu.predicate.alias", [
        "test_integer_compare_conformance", "test_predicate_test_conformance"]),
    "PRD-005-NAT-COMPARE": ("cpu.predicate.nat", [
        "test_integer_compare_conformance"]),
    "PRD-006-GROUP-PRODUCERS": ("cpu.predicate.group-producers", [
        "test_integer_compare_conformance", "test_predicate_tests_and_direct_branches"]),
    "PRD-007-PREDICATE-ROTATION": ("cpu.predicate.rotation", [
        "test_predicate_register_moves", "test_integer_compare_conformance",
        "test_typed_loop_branches"]),
    "PRD-008-PREDICATE-TESTS": ("cpu.predicate.tests", [
        "test_predicate_test_conformance"]),
}
EXPECTED_IMPLEMENTATION_ROWS = {
    "BR-006-LOOP-STATE": [
        "cpu.branch.loop-state", "cpu.register.ar.65", "cpu.register.ar.66"
    ],
}


class TrancheError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrancheError(f"cannot read {path}: {exc}") from exc


def exact_keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        actual = set(value) if isinstance(value, dict) else set()
        raise TrancheError(
            f"{label}: keys differ (missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)})"
        )


def strings(value: Any, label: str, *, empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not empty):
        raise TrancheError(f"{label}: expected {'possibly empty ' if empty else ''}list")
    if any(not isinstance(item, str) or not item for item in value):
        raise TrancheError(f"{label}: entries must be non-empty strings")
    return value


def harness_functions(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        raise TrancheError(f"cannot inspect {path}: {exc}") from exc
    return {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def validate(document: Any, catalogue: Any, root: Path) -> dict[str, int]:
    exact_keys(document, ROOT_KEYS, "tranche root")
    if document["$comment"] != "SPDX-License-Identifier: GPL-2.0-or-later":
        raise TrancheError("SPDX declaration changed")
    if document["schema"] != SCHEMA or document["schema_version"] != 1:
        raise TrancheError("unsupported tranche schema/version")
    if document["profile"] != PROFILE or document["test_id"] != 702:
        raise TrancheError("profile or stable test id changed")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    missing = sorted(set(EXPECTED) - set(catalogue_rows))
    if missing:
        raise TrancheError("catalogue rows disappeared: " + ", ".join(missing))
    functions = harness_functions(root / "tests/unit/test-ia64-full-tcg.py")
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED):
        raise TrancheError("predicate-and-branch tranche must contain exactly 14 cases")
    ids = [case.get("id") for case in cases]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise TrancheError("case ids must be unique and sorted")

    seen: set[str] = set()
    for index, case in enumerate(cases, 1):
        label = f"case {case.get('id', index)}"
        exact_keys(case, CASE_KEYS, label)
        if case["case_id"] != index or case["normative_token"] != index + 16:
            raise TrancheError(f"{label}: stable numeric ids drifted")
        row_id = case["normative_row"]
        if row_id not in EXPECTED or row_id in seen:
            raise TrancheError(f"{label}: unknown or duplicate normative row")
        seen.add(row_id)
        implementation, probes = EXPECTED[row_id]
        expected_implementation_rows = EXPECTED_IMPLEMENTATION_ROWS.get(
            row_id, [implementation]
        )
        if case["implementation_rows"] != expected_implementation_rows:
            raise TrancheError(f"{label}: implementation mapping changed")
        citation = case["citation"]
        exact_keys(citation, CITATION_KEYS, f"{label} citation")
        specification = catalogue_rows[row_id]["specification"]
        if citation != {key: specification[key] for key in CITATION_KEYS}:
            raise TrancheError(f"{label}: citation differs from catalogue")
        if catalogue_rows[row_id]["required_evidence"] != "E2":
            raise TrancheError(f"{label}: normative row no longer requires E2")

        for field in ("preconditions", "inputs", "expected_results",
                      "allowed_results", "permitted_state_changes",
                      "required_unchanged_state", "applicable_variants"):
            strings(case[field], f"{label} {field}")
        strings(case["expected_faults"], f"{label} expected_faults", empty=True)
        strings(case["fault_priority"], f"{label} fault_priority", empty=True)
        for field in ("committed_prefix", "restart_action"):
            if not isinstance(case[field], str) or not case[field]:
                raise TrancheError(f"{label}: {field} must not be empty")
        exact_keys(case["execution"], {"lane", "probes", "result_observations"},
                   f"{label} execution")
        if case["execution"]["lane"] != "isolated-guest":
            raise TrancheError(f"{label}: unexpected execution lane")
        if case["execution"]["probes"] != probes:
            raise TrancheError(f"{label}: executable probe mapping changed")
        if any(probe not in functions for probe in probes):
            raise TrancheError(f"{label}: executable probe is absent from harness")
        strings(case["execution"]["result_observations"], f"{label} observations")
        exact_keys(case["oracle"], {"independence", "derivation"}, f"{label} oracle")
        if case["oracle"]["independence"] != "independent" or not case["oracle"]["derivation"]:
            raise TrancheError(f"{label}: independent oracle derivation is missing")

    if seen != set(EXPECTED):
        raise TrancheError("predicate-and-branch row coverage is incomplete")
    return {"cases": len(cases), "probes": len({p for _, ps in EXPECTED.values() for p in ps})}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        summary = validate(
            load_json(root / "tests/ia64-conformance/predicate-branch-tranche.json"),
            load_json(root / "tests/ia64-conformance/normative-catalogue.json"), root)
    except TrancheError as exc:
        print(f"predicate-and-branch tranche validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"predicate-and-branch tranche metadata is valid: {summary['cases']} cases, {summary['probes']} unique probes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
