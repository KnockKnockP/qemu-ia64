#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate atomic RR selector, field, RID-context, and PAL page-size claims."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.region-register-tranche"
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
RRS = [f"cpu.register.rr.{index}" for index in range(8)]
SHARED_PROBES = [
    "test_region_register_file",
    "test_predicated_admission",
    "test_nat_matrix",
    "test_privilege_matrix",
    "test_reserved_matrix",
]
EXPECTED = {
    "MMU-017-RID-CONTEXT-SELECTION": {
        "implementation_rows": ["cpu.register.rr.0"],
        "probes": ["test_region_register_file"],
    },
    "PAL-008-VM-SUPPORTED-PAGE-SIZES": {
        "implementation_rows": ["platform.firmware.pal-vm-page-size"],
        "probes": ["test_pal_virtual_memory_page_sizes"],
    },
    "REG-006-RR-INDEX-SPACE": {
        "implementation_rows": [
            "cpu.opcode.ia64_op_mov_grrr",
            "cpu.opcode.ia64_op_mov_rrgr",
        ] + RRS,
        "probes": SHARED_PROBES,
    },
    "REG-007-RR-FIELD-SEMANTICS": {
        "implementation_rows": RRS,
        "probes": SHARED_PROBES,
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


def string_list(value: Any, label: str,
                *, allow_empty: bool = False) -> list[str]:
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
    if document["profile"] != "vibtanium-strict-up":
        raise TrancheError("unexpected profile")
    if document["test_id"] != 712:
        raise TrancheError("stable test id changed")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    if not set(EXPECTED) <= set(catalogue_rows):
        raise TrancheError("region-register rows disappeared from catalogue")
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
    if "platform.firmware.pal-vm-page-size" not in surface_source:
        raise TrancheError("PAL VM-page-size implementation surface is missing")
    if ("static IA64FirmwareResult pal_vm_page_size(" not in firmware_source or
            "return pal_vm_page_size(arg0, arg1, arg2);" not in firmware_source):
        raise TrancheError("PAL VM-page-size argument binding is missing")

    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != len(EXPECTED):
        raise TrancheError("expected exactly four atomic cases")
    row_ids = [case.get("normative_row") for case in cases]
    if row_ids != sorted(EXPECTED):
        raise TrancheError("cases must cover the four rows in stable-ID order")
    if [case.get("case_id") for case in cases] != list(range(1, 5)):
        raise TrancheError("case IDs must be contiguous 1..4")
    if [case.get("normative_token") for case in cases] != list(range(135, 139)):
        raise TrancheError("normative tokens must be contiguous 135..138")

    for case in cases:
        row_id = case["normative_row"]
        label = case.get("id", row_id)
        exact_keys(case, CASE_KEYS, label)
        if case["id"] != row_id + "-EXACT":
            raise TrancheError(f"{label}: unstable case id")
        if case["implementation_rows"] != EXPECTED[row_id]["implementation_rows"]:
            raise TrancheError(f"{label}: implementation binding changed")

        citation = case["citation"]
        exact_keys(citation, CITATION_KEYS, f"{label}.citation")
        for key in ("document_id", "section", "anchor"):
            if not isinstance(citation[key], str) or not citation[key]:
                raise TrancheError(f"{label}.citation.{key}: missing")
        string_list(citation["printed_pages"],
                    f"{label}.citation.printed_pages")
        for key in (
            "preconditions", "inputs", "expected_results", "allowed_results",
            "permitted_state_changes", "required_unchanged_state",
            "applicable_variants", "limitations",
        ):
            string_list(case[key], f"{label}.{key}")
        string_list(case["expected_faults"], f"{label}.expected_faults",
                    allow_empty=True)
        string_list(case["fault_priority"], f"{label}.fault_priority",
                    allow_empty=True)
        for key in ("committed_prefix", "restart_action"):
            if not isinstance(case[key], str) or not case[key]:
                raise TrancheError(f"{label}.{key}: missing")

        execution = case["execution"]
        exact_keys(execution, {"lane", "probes", "result_observations"},
                   f"{label}.execution")
        if execution["lane"] != "bare-metal-batch":
            raise TrancheError(f"{label}: unexpected execution lane")
        probes = string_list(execution["probes"], f"{label}.execution.probes")
        if probes != EXPECTED[row_id]["probes"]:
            raise TrancheError(f"{label}: probe binding changed")
        if not set(probes) <= functions:
            raise TrancheError(f"{label}: referenced runtime probe is missing")
        string_list(execution["result_observations"],
                    f"{label}.execution.result_observations")

        oracle = case["oracle"]
        exact_keys(oracle, {"independence", "derivation"}, f"{label}.oracle")
        if oracle["independence"] != "independent":
            raise TrancheError(f"{label}: oracle is not independent")
        if not isinstance(oracle["derivation"], str) or not oracle["derivation"]:
            raise TrancheError(f"{label}: oracle derivation is missing")

        row = catalogue_rows[row_id]
        if row.get("required_evidence") != "E2":
            raise TrancheError(f"{row_id}: catalogue row is not E2")
        if row.get("specification", {}).get("document_id") != citation["document_id"]:
            raise TrancheError(f"{row_id}: catalogue citation drift")

    return len(cases)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--tranche", type=Path,
        default=Path("tests/ia64-conformance/region-register-tranche.json"),
    )
    parser.add_argument(
        "--catalogue", type=Path,
        default=Path("tests/ia64-conformance/normative-catalogue.json"),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    tranche = args.tranche if args.tranche.is_absolute() else root / args.tranche
    catalogue = (
        args.catalogue if args.catalogue.is_absolute() else root / args.catalogue
    )
    count = validate(load_json(tranche), load_json(catalogue), root)
    print(
        "IA-64 region-register tranche verified: "
        f"test_id=712 cases={count} tokens=135..138"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, TrancheError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
