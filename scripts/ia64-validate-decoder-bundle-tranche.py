#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate decoder/bundle metadata and its exact production contracts."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.decoder-bundle-tranche"
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
    "BND-004-TEMPLATE-EQUIVALENCE": ("cpu.bundle.template-equivalence", ["test_legal_template_equivalence"]),
    "BND-005-LONG-IMMEDIATE": ("cpu.bundle.long-immediate", ["test_long_immediate_construction"]),
    "BND-006-TEMPLATE-PLACEMENT-LEGALITY": ("cpu.bundle.legality", ["test_template_and_placement_legality"]),
    "BND-007-IGNORED-RESERVED-FIELDS": ("cpu.bundle.field-semantics", ["test_ignored_and_reserved_fields"]),
    "BND-008-IP-RI-TRANSITIONS": ("cpu.bundle.ip-ri", ["test_ip_ri_transition_matrix"]),
    "BND-009-RI-ENTRY-RESUME": ("cpu.bundle.ri-resume", ["test_ri_entry_resume_matrix"]),
    "BND-010-PAGE-TB-EQUIVALENCE": ("cpu.bundle.boundaries", ["test_page_tb_boundary_equivalence"]),
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


def test_contract(path: Path) -> tuple[set[str], tuple]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        raise TrancheError(f"cannot inspect {path}: {exc}") from exc
    functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    matrix = None
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            if isinstance(target, ast.Name) and target.id == "TEMPLATE_MATRIX":
                matrix = ast.literal_eval(node.value)
    if not isinstance(matrix, tuple) or len(matrix) != 32:
        raise TrancheError("TEMPLATE_MATRIX must be a literal 32-entry tuple")
    if tuple(row[0] for row in matrix) != tuple(range(32)):
        raise TrancheError("TEMPLATE_MATRIX indices must be exact and ordered")
    return functions, matrix


def production_template_matrix(path: Path) -> tuple:
    source = path.read_text(encoding="utf-8")
    match = re.search(r"ia64_template_table\[32\] = \{(.*?)\n\};", source, re.S)
    if match is None:
        raise TrancheError("production 32-entry template table is absent")
    rows = []
    pattern = re.compile(r"\[0x([0-9a-f]{2})\] = (?:TEMPL\(\"[^\"]+\",\s*([MLXIFB]),\s*([MLXIFB]),\s*([MLXIFB]),\s*(true|false),\s*(true|false),\s*(true|false),\s*(true|false)\)|RESERVED),")
    for line in match.group(1).splitlines():
        item = pattern.search(line)
        if item is None:
            continue
        index = int(item.group(1), 16)
        if item.group(2) is None:
            rows.append((index, None, None, False))
        else:
            units = "".join(item.group(i) for i in (2, 3, 4))
            stops = tuple(item.group(i) == "true" for i in (5, 6, 7))
            rows.append((index, units, stops, item.group(8) == "true"))
    if len(rows) != 32:
        raise TrancheError(f"production template parser found {len(rows)} entries")
    return tuple(rows)


def validate_translator_guard(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    helper = source.find("static void ia64_tr_emit_invalid_mlx_restart")
    body = source.find("ia64_tr_publish_fault_state(ctx, pc, start_slot", helper)
    raise_call = source.find("gen_helper_raise_illegal_operation(tcg_env)", body)
    main = source.find("if (start_slot == 2 && bundle.info->long_immediate)")
    invalid = source.rfind("ia64_tr_emit_invalid_template", 0, main)
    preflight = source.find("ia64_tr_preflight_rewrite_region(", main)
    if min(helper, body, raise_call, main, invalid, preflight) < 0:
        raise TrancheError("architectural MLX RI=2 fault guard is incomplete")
    if not invalid < main < preflight:
        raise TrancheError("MLX RI=2 guard must follow invalid-template handling and precede typed preflight")


def validate(document: Any, catalogue: Any, root: Path) -> dict[str, int]:
    exact_keys(document, ROOT_KEYS, "tranche root")
    if document["$comment"] != "SPDX-License-Identifier: GPL-2.0-or-later":
        raise TrancheError("SPDX declaration changed")
    if document["schema"] != SCHEMA or document["schema_version"] != 1:
        raise TrancheError("unsupported tranche schema/version")
    if document["profile"] != PROFILE or document["test_id"] != 705:
        raise TrancheError("profile or stable test id changed")

    functions, test_matrix = test_contract(root / "tests/unit/test-ia64-decoder-bundle-tcg.py")
    production_matrix = production_template_matrix(root / "target/ia64/bundle.c")
    if test_matrix != production_matrix:
        raise TrancheError("test-owned template matrix differs from the production 32-entry table")
    validate_translator_guard(root / "target/ia64/translate.c")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED):
        raise TrancheError("decoder/bundle tranche must contain exactly 7 cases")
    ids = [case.get("id") for case in cases]
    if ids != sorted(ids) or len(set(ids)) != len(ids):
        raise TrancheError("case ids must be unique and sorted")
    seen = set()
    for index, case in enumerate(cases, 1):
        label = f"case {case.get('id', index)}"
        exact_keys(case, CASE_KEYS, label)
        if case["case_id"] != index or case["normative_token"] != index + 44:
            raise TrancheError(f"{label}: stable numeric ids drifted")
        row_id = case["normative_row"]
        if row_id not in EXPECTED or row_id in seen or row_id not in catalogue_rows:
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
        raise TrancheError("decoder/bundle row coverage is incomplete")
    return {"cases": len(cases), "probes": len(EXPECTED), "templates": len(test_matrix)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        summary = validate(load_json(root / "tests/ia64-conformance/decoder-bundle-tranche.json"), load_json(root / "tests/ia64-conformance/normative-catalogue.json"), root)
    except (TrancheError, OSError) as exc:
        print(f"decoder/bundle tranche validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"decoder/bundle tranche metadata is valid: {summary['cases']} cases, {summary['probes']} probes, {summary['templates']} exact templates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
