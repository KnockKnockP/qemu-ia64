#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate scalar-integer metadata and its exact current opcode inventory."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.scalar-integer-tranche"
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
    "INT-001-ARITHMETIC-FORMS": ("cpu.integer.arithmetic", ["test_semantic_model_matrix"]),
    "INT-002-LOGICAL-CONSTANT-FORMS": ("cpu.integer.logical", ["test_semantic_model_matrix"]),
    "INT-003-GR-MULTIPLY": ("cpu.integer.multiply-gr", ["test_semantic_model_matrix"]),
    "INT-003-XMA-MULTIPLY-ADD": ("cpu.integer.multiply-xma", ["test_integer_multiply_add_forms"]),
    "INT-004-SHIFT-BITFIELD-EXTEND": ("cpu.integer.bitfield-shift", ["test_semantic_model_matrix"]),
    "INT-005-CHARACTER-BIT-FORMS": ("cpu.integer.character-bit", ["test_semantic_model_matrix", "test_character_byte_forms"]),
    "INT-006-STATE-LEGALITY": ("cpu.integer.legality", ["test_state_legality_matrix"]),
    "INT-007-INDEPENDENT-MODEL": ("cpu.integer.generated-domain", ["test_semantic_model_matrix", "test_state_legality_matrix"]),
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
        raise TrancheError(f"{label}: keys differ (missing={sorted(expected - actual)}, extra={sorted(actual - expected)})")


def strings(value: Any, label: str, *, empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not empty):
        raise TrancheError(f"{label}: expected {'possibly empty ' if empty else ''}list")
    if any(not isinstance(item, str) or not item for item in value):
        raise TrancheError(f"{label}: entries must be non-empty strings")
    return value


def scalar_module_contract(path: Path) -> tuple[set[str], tuple[str, ...]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        raise TrancheError(f"cannot inspect {path}: {exc}") from exc
    functions = {node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    inventory: tuple[str, ...] | None = None
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            value = node.value
            if isinstance(target, ast.Name) and target.id == "SCALAR_OPCODES":
                literal = ast.literal_eval(value)
                if not isinstance(literal, tuple) or any(not isinstance(item, str) for item in literal):
                    raise TrancheError("SCALAR_OPCODES must be a literal string tuple")
                inventory = literal
    if inventory is None:
        raise TrancheError("SCALAR_OPCODES inventory is absent")
    return functions, inventory


def translator_scalar_inventory(path: Path) -> tuple[str, ...]:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TrancheError(f"cannot inspect {path}: {exc}") from exc
    match = re.search(r"switch \(insn->opcode\) \{\s+case IA64_OP_MOVL:", source)
    if match is None:
        raise TrancheError("scalar execution switch is absent")
    end = source.find("    default:\n        g_assert_not_reached();\n    }", match.start())
    if end < 0:
        raise TrancheError("scalar execution switch terminator is absent")
    return tuple(re.findall(r"case (IA64_OP_[A-Z0-9_]+):", source[match.start():end]))


def validate(document: Any, catalogue: Any, root: Path) -> dict[str, int]:
    exact_keys(document, ROOT_KEYS, "tranche root")
    if document["$comment"] != "SPDX-License-Identifier: GPL-2.0-or-later":
        raise TrancheError("SPDX declaration changed")
    if document["schema"] != SCHEMA or document["schema_version"] != 1:
        raise TrancheError("unsupported tranche schema/version")
    if document["profile"] != PROFILE or document["test_id"] != 704:
        raise TrancheError("profile or stable test id changed")

    module_path = root / "tests/unit/test-ia64-scalar-tcg.py"
    functions, declared_opcodes = scalar_module_contract(module_path)
    translated_opcodes = translator_scalar_inventory(root / "target/ia64/translate.c")
    if len(declared_opcodes) != 40 or len(set(declared_opcodes)) != 40:
        raise TrancheError("scalar test inventory must contain exactly 40 unique opcodes")
    if declared_opcodes != translated_opcodes:
        missing = sorted(set(translated_opcodes) - set(declared_opcodes))
        extra = sorted(set(declared_opcodes) - set(translated_opcodes))
        raise TrancheError(f"scalar test/translator inventory differs: missing={missing}, extra={extra}")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    missing_rows = sorted(set(EXPECTED) - set(catalogue_rows))
    if missing_rows:
        raise TrancheError("catalogue rows disappeared: " + ", ".join(missing_rows))
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED):
        raise TrancheError("scalar-integer tranche must contain exactly 8 cases")
    ids = [case.get("id") for case in cases]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise TrancheError("case ids must be unique and sorted")
    seen: set[str] = set()
    for index, case in enumerate(cases, 1):
        label = f"case {case.get('id', index)}"
        exact_keys(case, CASE_KEYS, label)
        if case["case_id"] != index or case["normative_token"] != index + 36:
            raise TrancheError(f"{label}: stable numeric ids drifted")
        row_id = case["normative_row"]
        if row_id not in EXPECTED or row_id in seen:
            raise TrancheError(f"{label}: unknown or duplicate normative row")
        seen.add(row_id)
        implementation, probes = EXPECTED[row_id]
        if case["implementation_rows"] != [implementation]:
            raise TrancheError(f"{label}: implementation mapping changed")
        citation = case["citation"]
        exact_keys(citation, CITATION_KEYS, f"{label} citation")
        specification = catalogue_rows[row_id]["specification"]
        if citation != {key: specification[key] for key in CITATION_KEYS}:
            raise TrancheError(f"{label}: citation differs from catalogue")
        if catalogue_rows[row_id]["required_evidence"] != "E2":
            raise TrancheError(f"{label}: normative row no longer requires E2")
        for field in ("preconditions", "inputs", "expected_results", "allowed_results", "permitted_state_changes", "required_unchanged_state", "applicable_variants"):
            strings(case[field], f"{label} {field}")
        strings(case["expected_faults"], f"{label} expected_faults", empty=True)
        strings(case["fault_priority"], f"{label} fault_priority", empty=True)
        for field in ("committed_prefix", "restart_action"):
            if not isinstance(case[field], str) or not case[field]:
                raise TrancheError(f"{label}: {field} must not be empty")
        exact_keys(case["execution"], {"lane", "probes", "result_observations"}, f"{label} execution")
        if case["execution"]["lane"] != "isolated-guest" or case["execution"]["probes"] != probes:
            raise TrancheError(f"{label}: executable probe mapping changed")
        if any(probe not in functions for probe in probes):
            raise TrancheError(f"{label}: executable probe is absent")
        strings(case["execution"]["result_observations"], f"{label} observations")
        exact_keys(case["oracle"], {"independence", "derivation"}, f"{label} oracle")
        if case["oracle"]["independence"] != "independent" or not case["oracle"]["derivation"]:
            raise TrancheError(f"{label}: independent oracle derivation is missing")
    if seen != set(EXPECTED):
        raise TrancheError("scalar-integer row coverage is incomplete")
    return {"cases": len(cases), "probes": len({p for _, ps in EXPECTED.values() for p in ps}), "opcodes": len(declared_opcodes)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        summary = validate(load_json(root / "tests/ia64-conformance/scalar-integer-tranche.json"), load_json(root / "tests/ia64-conformance/normative-catalogue.json"), root)
    except TrancheError as exc:
        print(f"scalar-integer tranche validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"scalar-integer tranche metadata is valid: {summary['cases']} cases, {summary['probes']} unique probes, {summary['opcodes']} exact scalar opcodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
