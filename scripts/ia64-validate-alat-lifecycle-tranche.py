#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate atomic ALAT lifecycle and VMState conformance contracts."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.alat-lifecycle-tranche"
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
    "ALT-007-ALAT-MIGRATION-DEBUG-SAFETY": {
        "implementation_rows": [
            "cpu.alat.vmstate",
            "cpu.opcode.ia64_op_chk_a",
            "cpu.opcode.ia64_op_ld8a",
            "cpu.opcode.ia64_op_ldfs",
        ],
        "lane": "bare-metal-batch",
        "probes": ["test_alat_migration_debug_safety"],
        "required_evidence": "E2",
    },
    "ALT-008-ALAT-VMSTATE-VALIDATION": {
        "implementation_rows": ["cpu.alat.vmstate"],
        "lane": "host-unit",
        "probes": [
            "test_alat_target_type_round_trip",
            "test_alat_vmstate_rejects_invalid_entries",
        ],
        "required_evidence": "E1",
    },
    "ALT-009-ALAT-RESET-STATE": {
        "implementation_rows": ["cpu.alat.reset"],
        "lane": "host-unit",
        "probes": ["test_reset_state"],
        "required_evidence": "E1",
    },
    "ALT-010-ALAT-SYSTEM-RESET-SAFETY": {
        "implementation_rows": [
            "cpu.alat.reset",
            "cpu.opcode.ia64_op_chk_a",
            "cpu.opcode.ia64_op_ld8a",
            "cpu.opcode.ia64_op_ldfs",
            "platform.reset.vibtanium",
        ],
        "lane": "bare-metal-batch",
        "probes": ["test_alat_system_reset_safety"],
        "required_evidence": "E2",
    },
    "ALT-011-ALAT-DETERMINISTIC-REPLAY": {
        "implementation_rows": [
            "cpu.alat.reset",
            "cpu.opcode.ia64_op_chk_a",
            "cpu.opcode.ia64_op_ld8a",
            "cpu.opcode.ia64_op_ldfs",
        ],
        "lane": "bare-metal-batch",
        "probes": ["test_alat_deterministic_replay"],
        "required_evidence": "E2",
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


def c_functions(path: Path) -> set[str]:
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TrancheError(f"cannot inspect {path}: {exc}") from exc
    return set(re.findall(
        r"(?m)^static\s+void\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", source
    ))


def validate(document: Any, catalogue: Any, root: Path) -> dict[str, int]:
    exact_keys(document, ROOT_KEYS, "tranche root")
    if document["$comment"] != SPDX_DECLARATION:
        raise TrancheError("SPDX declaration changed")
    if document["schema"] != SCHEMA or document["schema_version"] != 1:
        raise TrancheError("unsupported tranche schema/version")
    if document["profile"] != "vibtanium-strict-up" or document["test_id"] != 707:
        raise TrancheError("profile or stable test id changed")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    if not set(EXPECTED) <= set(catalogue_rows):
        raise TrancheError("ALAT lifecycle rows disappeared from catalogue")
    functions_by_lane = {
        "bare-metal-batch": python_functions(
            root / "tests/unit/test-ia64-full-tcg.py"
        ),
        "host-unit": (
            c_functions(root / "tests/unit/test-ia64-vmstate.c")
            | c_functions(root / "tests/unit/test-ia64-insn.c")
        ),
    }

    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED):
        raise TrancheError(
            "ALAT lifecycle tranche must contain {} cases".format(
                len(EXPECTED)
            )
        )
    identifiers = [case.get("id") for case in cases]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != len(cases):
        raise TrancheError("case ids must be unique and sorted")

    seen_rows: set[str] = set()
    for index, case in enumerate(cases, 1):
        label = f"case {case.get('id', index)}"
        exact_keys(case, CASE_KEYS, label)
        if case["case_id"] != index or case["normative_token"] != index + 115:
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
        if catalogue_rows[row_id]["required_evidence"] != expected["required_evidence"]:
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
        lane = case["execution"]["lane"]
        probes = string_list(case["execution"]["probes"], f"{label} probes")
        if lane != expected["lane"] or probes != expected["probes"]:
            raise TrancheError(f"{label}: execution lane or probes changed")
        missing_probes = sorted(set(probes) - functions_by_lane[lane])
        if missing_probes:
            raise TrancheError(
                f"{label}: executable probes are missing: {missing_probes}"
            )
        string_list(case["execution"]["result_observations"],
                    f"{label} result observations")

        exact_keys(case["oracle"], {"independence", "derivation"},
                   f"{label} oracle")
        if case["oracle"]["independence"] != "independent":
            raise TrancheError(f"{label}: row oracle must be independent")
        derivation = case["oracle"]["derivation"]
        if not isinstance(derivation, str) or not derivation:
            raise TrancheError(f"{label}: oracle derivation is missing")

    if seen_rows != set(EXPECTED):
        raise TrancheError("ALAT lifecycle row coverage is incomplete")
    return {
        "cases": len(cases),
        "faulting": sum(bool(case["expected_faults"]) for case in cases),
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        summary = validate(
            load_json(root / "tests/ia64-conformance/alat-lifecycle-tranche.json"),
            load_json(root / "tests/ia64-conformance/normative-catalogue.json"),
            root,
        )
    except TrancheError as exc:
        print(f"ALAT lifecycle tranche validation failed: {exc}", file=sys.stderr)
        return 1
    print(
        "ALAT lifecycle tranche metadata is valid: "
        f"{summary['cases']} cases ({summary['faulting']} faulting)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
