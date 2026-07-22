#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate atomic PKR access, field, uniqueness, and PAL VM contracts."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.protection-key-tranche"
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
PKRS = [f"cpu.register.pkr.{index}" for index in range(16)]
SHARED_PROBES = [
    "test_protection_key_register_file",
    "test_predicated_admission",
    "test_nat_matrix",
    "test_privilege_matrix",
    "test_reserved_matrix",
]
EXPECTED = {
    "MMU-012-PROTECTION-KEY-ACCESS": {
        "implementation_rows": PKRS,
        "probes": ["test_protection_key_permissions"],
    },
    "PAL-008-VM-SUMMARY-PROFILE": {
        "implementation_rows": ["platform.firmware.pal-vm-summary"],
        "probes": ["test_pal_virtual_memory_summary"],
    },
    "REG-006-PKR-INDEX-SPACE": {
        "implementation_rows": [
            "cpu.opcode.ia64_op_mov_grpkr_indexed",
            "cpu.opcode.ia64_op_mov_pkrgr_indexed",
        ] + PKRS,
        "probes": SHARED_PROBES,
    },
    "REG-007-PKR-FIELD-SEMANTICS": {
        "implementation_rows": PKRS,
        "probes": SHARED_PROBES,
    },
    "REG-007-PKR-KEY-UNIQUENESS": {
        "implementation_rows": PKRS,
        "probes": ["test_protection_key_register_file"],
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
    if document["profile"] != "vibtanium-strict-up" or document["test_id"] != 711:
        raise TrancheError("profile or stable test id changed")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    if not set(EXPECTED) <= set(catalogue_rows):
        raise TrancheError("protection-key rows disappeared from catalogue")
    functions = python_functions(root / "tests/unit/test-ia64-system-tcg.py")
    try:
        surface_source = (
            root / "scripts/ia64-gen-implementation-surface.py"
        ).read_text(encoding="utf-8")
        firmware_source = (root / "hw/ia64/firmware.c").read_text(
            encoding="utf-8"
        )
    except OSError as exc:
        raise TrancheError(
            f"cannot inspect implementation bindings: {exc}"
        ) from exc
    if "platform.firmware.pal-vm-summary" not in surface_source:
        raise TrancheError("PAL VM-summary implementation surface is missing")
    if ("static IA64FirmwareResult pal_vm_summary(" not in firmware_source or
            "return pal_vm_summary(arg0, arg1, arg2);" not in firmware_source):
        raise TrancheError("PAL VM-summary three-argument binding is missing")

    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED):
        raise TrancheError("expected exactly five atomic cases")
    row_ids = [case.get("normative_row") for case in cases]
    if row_ids != sorted(EXPECTED):
        raise TrancheError("cases must cover the five rows in stable-ID order")
    if [case.get("case_id") for case in cases] != list(range(1, 6)):
        raise TrancheError("case IDs must be contiguous 1..5")
    if [case.get("normative_token") for case in cases] != list(range(130, 135)):
        raise TrancheError("normative tokens must be contiguous 130..134")

    for case in cases:
        row_id = case["normative_row"]
        label = case.get("id", row_id)
        exact_keys(case, CASE_KEYS, label)
        if case["id"] != row_id + "-EXACT":
            raise TrancheError(f"{label}: unstable case ID")
        expected = EXPECTED[row_id]
        if case["implementation_rows"] != expected["implementation_rows"]:
            raise TrancheError(f"{label}: implementation mapping changed")
        citation = case["citation"]
        exact_keys(citation, CITATION_KEYS, f"{label}.citation")
        catalogue_citation = catalogue_rows[row_id]["specification"]
        for key in CITATION_KEYS:
            if citation[key] != catalogue_citation[key]:
                raise TrancheError(f"{label}: citation {key} drifted")
        for key in (
            "preconditions", "inputs", "expected_results", "allowed_results",
            "permitted_state_changes", "required_unchanged_state",
            "expected_faults", "fault_priority", "applicable_variants",
            "limitations",
        ):
            string_list(
                case[key], f"{label}.{key}",
                allow_empty=key in {"expected_faults", "fault_priority"},
            )
        if bool(case["expected_faults"]) != bool(case["fault_priority"]):
            raise TrancheError(f"{label}: faults and priority must pair")
        execution = case["execution"]
        exact_keys(
            execution, {"lane", "probes", "result_observations"},
            f"{label}.execution",
        )
        if execution["lane"] != "bare-metal-batch":
            raise TrancheError(f"{label}: wrong execution lane")
        if execution["probes"] != expected["probes"]:
            raise TrancheError(f"{label}: executable probe set changed")
        missing = sorted(set(execution["probes"]) - functions)
        if missing:
            raise TrancheError(f"{label}: missing probes {missing}")
        string_list(execution["result_observations"], f"{label}.observations")
        exact_keys(
            case["oracle"], {"independence", "derivation"},
            f"{label}.oracle",
        )
        if case["oracle"]["independence"] != "independent":
            raise TrancheError(f"{label}: oracle is not independent")
        for key in ("committed_prefix", "restart_action"):
            if not isinstance(case[key], str) or not case[key]:
                raise TrancheError(f"{label}.{key}: must be nonempty")
    return len(cases)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = args.root.resolve()
    try:
        count = validate(
            load_json(root / "tests/ia64-conformance/protection-key-tranche.json"),
            load_json(root / "tests/ia64-conformance/normative-catalogue.json"),
            root,
        )
    except TrancheError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"validated {count} atomic protection-key/PAL VM contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
