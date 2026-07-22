#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate atomic debug-register selector, field, and PAL contracts."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.debug-register-tranche"
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
DBRS = [f"cpu.register.dbr.{index}" for index in range(16)]
IBRS = [f"cpu.register.ibr.{index}" for index in range(16)]
SHARED_PROBES = [
    "test_debug_register_selector_domains",
    "test_predicated_admission",
    "test_nat_matrix",
    "test_privilege_matrix",
    "test_reserved_matrix",
]
EXPECTED = {
    "PAL-012-DEBUG-REGISTER-DISCOVERY": {
        "implementation_rows": ["platform.firmware.pal-debug-info"],
        "probes": ["test_pal_debug_info"],
    },
    "REG-006-DBR-INDEX-SPACE": {
        "implementation_rows": [
            "cpu.opcode.ia64_op_mov_dbrgr_indexed",
            "cpu.opcode.ia64_op_mov_grdbr_indexed",
        ] + DBRS,
        "probes": SHARED_PROBES,
    },
    "REG-006-IBR-INDEX-SPACE": {
        "implementation_rows": [
            "cpu.opcode.ia64_op_mov_gribr_indexed",
            "cpu.opcode.ia64_op_mov_ibrgr_indexed",
        ] + IBRS,
        "probes": SHARED_PROBES,
    },
    "REG-007-DBR-FIELD-SEMANTICS": {
        "implementation_rows": DBRS,
        "probes": [
            "test_debug_register_selector_domains",
            "test_architectural_debug_registers",
        ],
    },
    "REG-007-IBR-FIELD-SEMANTICS": {
        "implementation_rows": IBRS,
        "probes": [
            "test_debug_register_selector_domains",
            "test_architectural_debug_registers",
        ],
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
    if document["profile"] != "vibtanium-strict-up" or document["test_id"] != 710:
        raise TrancheError("profile or stable test id changed")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    if not set(EXPECTED) <= set(catalogue_rows):
        raise TrancheError("debug-register rows disappeared from catalogue")
    functions = python_functions(root / "tests/unit/test-ia64-system-tcg.py")
    try:
        surface_source = (root / "scripts/ia64-gen-implementation-surface.py").read_text(
            encoding="utf-8"
        )
        firmware_source = (root / "hw/ia64/firmware.c").read_text(encoding="utf-8")
    except OSError as exc:
        raise TrancheError(f"cannot inspect implementation bindings: {exc}") from exc
    implementation_rows = {
        row for expected in EXPECTED.values()
        for row in expected["implementation_rows"]
    }
    if "platform.firmware.pal-debug-info" not in surface_source:
        raise TrancheError("PAL debug-info implementation surface is missing")
    if ("static IA64FirmwareResult pal_debug_info(" not in firmware_source or
            "dispatch_pal(env, function_id, arg0, arg1, arg2)" not in firmware_source):
        raise TrancheError("PAL debug-info three-argument dispatch binding is missing")
    if not {"platform.firmware.pal-debug-info"} <= implementation_rows:
        raise TrancheError("PAL implementation row is not claimed")

    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED):
        raise TrancheError("debug-register tranche must contain five cases")
    identifiers = [case.get("id") for case in cases]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != len(cases):
        raise TrancheError("case ids must be unique and sorted")

    seen_rows: set[str] = set()
    for index, case in enumerate(cases, 1):
        label = f"case {case.get('id', index)}"
        exact_keys(case, CASE_KEYS, label)
        if case["case_id"] != index or case["normative_token"] != index + 124:
            raise TrancheError(f"{label}: stable numeric ids drifted")
        row_id = case["normative_row"]
        if (case["id"] != row_id + "-EXACT" or row_id not in EXPECTED or
                row_id in seen_rows):
            raise TrancheError(f"{label}: unknown, duplicate, or mismatched row")
        seen_rows.add(row_id)
        expected = EXPECTED[row_id]
        if case["implementation_rows"] != expected["implementation_rows"]:
            raise TrancheError(f"{label}: implementation mapping changed")

        exact_keys(case["citation"], CITATION_KEYS, f"{label} citation")
        specification = catalogue_rows[row_id]["specification"]
        if case["citation"] != {
            key: specification[key] for key in CITATION_KEYS
        }:
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
        if probes != expected["probes"] or not set(probes) <= functions:
            raise TrancheError(f"{label}: executable probe set is missing or changed")
        string_list(case["execution"]["result_observations"],
                    f"{label} result observations")
        exact_keys(case["oracle"], {"independence", "derivation"},
                   f"{label} oracle")
        if (case["oracle"]["independence"] != "independent" or
                not isinstance(case["oracle"]["derivation"], str) or
                not case["oracle"]["derivation"]):
            raise TrancheError(f"{label}: oracle is not independently specified")

    if seen_rows != set(EXPECTED):
        raise TrancheError("debug-register row coverage is incomplete")
    return len(cases)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    root = parse_args(argv).root.resolve()
    try:
        cases = validate(
            load_json(root / "tests/ia64-conformance/debug-register-tranche.json"),
            load_json(root / "tests/ia64-conformance/normative-catalogue.json"),
            root,
        )
    except TrancheError as exc:
        print(f"Debug-register tranche validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Debug-register tranche metadata is valid: {cases} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
