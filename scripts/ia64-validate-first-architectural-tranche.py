#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate complete row metadata for the first IA-64 E2 tranche."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.first-architectural-tranche"
SPDX_DECLARATION = "SPDX-" + "License-Identifier: GPL-2.0-or-later"
PROFILE = "vibtanium-strict-up"
ROOT_KEYS = {
    "$comment", "schema", "schema_version", "profile", "test_id", "cases",
}
CASE_KEYS = {
    "id", "case_id", "normative_token", "normative_row",
    "implementation_rows", "citation", "preconditions", "inputs",
    "expected_results", "allowed_results", "permitted_state_changes",
    "required_unchanged_state", "expected_faults", "fault_priority",
    "committed_prefix", "restart_action", "applicable_variants",
    "execution", "oracle",
}
CITATION_KEYS = {
    "document_id", "section", "printed_pages", "anchor",
}
EXPECTED_IMPLEMENTATION = {
    "BND-001-BUNDLE-FORMAT": ["cpu.bundle.format"],
    "BND-001-TEMPLATE-MAP": ["cpu.bundle.template-map"],
    "BND-003-SEQUENTIAL-ORDER": ["cpu.sequencing.sequential-order"],
    "GRP-002-STOP-VISIBILITY": ["cpu.issue-group.stop-visibility"],
    "GRP-004-GROUP-ENTRY-REGISTER": ["cpu.issue-group.entry-register"],
    "GRP-007-FAULT-COMMITMENT": ["cpu.issue-group.fault-commitment"],
    "REG-004-FR0-READ": ["cpu.register.fr.0"],
    "REG-004-FR1-READ": ["cpu.register.fr.1"],
    "REG-004-GR0-READ": ["cpu.register.gr.0"],
    "REG-004-PR0-READ": ["cpu.register.pr.0"],
    "REG-004-PR0-WRITE": ["cpu.register.pr.0"],
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
        raise TrancheError(f"{label}: expected non-empty strings")
    if not allow_empty and not value:
        raise TrancheError(f"{label}: must not be empty")
    if len(value) != len(set(value)):
        raise TrancheError(f"{label}: duplicate entry")
    return value


def validate_literal_bundle_fields() -> None:
    """Exercise a test-owned pack/extract oracle for BND-001."""
    template = 0x01
    slots = (
        (1 << 27) | (0x15555 << 6),
        (1 << 27) | (0x2aaaa << 6),
        (1 << 27) | (0x12345 << 6),
    )
    value = (
        template | (slots[0] << 5) | (slots[1] << 46) | (slots[2] << 87)
    )
    recovered = (
        value & 0x1f,
        (value >> 5) & ((1 << 41) - 1),
        (value >> 46) & ((1 << 41) - 1),
        (value >> 87) & ((1 << 41) - 1),
    )
    if recovered != (template, *slots):
        raise TrancheError("literal 128-bit bundle field oracle failed")
    if value.to_bytes(16, "little").hex() != (
        "01a8aa0a0100a0aa2a0200a068240400"
    ):
        raise TrancheError("literal packed bundle bytes drifted")


def validate(document: Any, catalogue: Any) -> dict[str, int]:
    exact_keys(document, ROOT_KEYS, "tranche root")
    if document["$comment"] != SPDX_DECLARATION:
        raise TrancheError("SPDX declaration changed")
    if document["schema"] != SCHEMA or document["schema_version"] != 1:
        raise TrancheError("unsupported tranche schema/version")
    if document["profile"] != PROFILE or document["test_id"] != 700:
        raise TrancheError("profile or stable test id changed")

    catalogue_rows = {row["id"]: row for row in catalogue.get("rows", [])}
    if set(catalogue_rows) != set(EXPECTED_IMPLEMENTATION):
        raise TrancheError("tranche must cover the complete seed catalogue")
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != 11:
        raise TrancheError("first tranche must contain exactly eleven cases")
    identifiers = [case.get("id") for case in cases]
    if identifiers != sorted(identifiers) or len(set(identifiers)) != 11:
        raise TrancheError("case ids must be unique and sorted")

    seen_rows = set()
    persistent_generations = []
    for index, case in enumerate(cases, 1):
        label = f"case {case.get('id', index)}"
        exact_keys(case, CASE_KEYS, label)
        if case["case_id"] != index or case["normative_token"] != index:
            raise TrancheError(f"{label}: stable numeric ids drifted")
        row_id = case["normative_row"]
        if row_id not in catalogue_rows or row_id in seen_rows:
            raise TrancheError(f"{label}: unknown or duplicate normative row")
        seen_rows.add(row_id)
        if case["implementation_rows"] != EXPECTED_IMPLEMENTATION[row_id]:
            raise TrancheError(f"{label}: implementation mapping changed")

        citation = case["citation"]
        exact_keys(citation, CITATION_KEYS, f"{label} citation")
        specification = catalogue_rows[row_id]["specification"]
        expected_citation = {
            key: specification[key] for key in CITATION_KEYS
        }
        if citation != expected_citation:
            raise TrancheError(f"{label}: citation differs from catalogue")

        for field in (
            "preconditions", "inputs", "expected_results", "allowed_results",
            "permitted_state_changes", "required_unchanged_state",
            "applicable_variants",
        ):
            string_list(case[field], f"{label} {field}")
        string_list(case["expected_faults"], f"{label} expected_faults",
                    allow_empty=True)
        string_list(case["fault_priority"], f"{label} fault_priority",
                    allow_empty=True)
        for field in ("committed_prefix", "restart_action"):
            if not isinstance(case[field], str) or not case[field]:
                raise TrancheError(f"{label}: {field} must not be empty")

        exact_keys(
            case["execution"], {"lane", "generation", "result_observations"},
            f"{label} execution",
        )
        string_list(
            case["execution"]["result_observations"],
            f"{label} result observations",
        )
        lane = case["execution"]["lane"]
        generation = case["execution"]["generation"]
        if lane == "persistent-guest":
            if type(generation) is not int or generation <= 0:
                raise TrancheError(f"{label}: invalid persistent generation")
            persistent_generations.append(generation)
        elif lane == "isolated-repair-retry":
            if row_id != "GRP-007-FAULT-COMMITMENT" or generation != 0:
                raise TrancheError(f"{label}: invalid isolated lane")
        else:
            raise TrancheError(f"{label}: unknown execution lane")

        exact_keys(case["oracle"], {"independence", "derivation"},
                   f"{label} oracle")
        if case["oracle"]["independence"] != "independent":
            raise TrancheError(f"{label}: row oracle must be independent")
        if not isinstance(case["oracle"]["derivation"], str):
            raise TrancheError(f"{label}: oracle derivation is missing")
        if catalogue_rows[row_id]["required_evidence"] != "E2":
            raise TrancheError(f"{label}: seed row no longer requires E2")

    if persistent_generations != list(range(1, 11)):
        raise TrancheError("persistent generations must be exactly 1 through 10")
    validate_literal_bundle_fields()
    return {"cases": len(cases), "persistent": 10, "isolated": 1}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    try:
        summary = validate(
            load_json(root / "tests/ia64-conformance/first-architectural-tranche.json"),
            load_json(root / "tests/ia64-conformance/normative-catalogue.json"),
        )
    except TrancheError as exc:
        print(f"first architectural tranche validation failed: {exc}",
              file=sys.stderr)
        return 1
    print(
        "first architectural tranche metadata is valid: "
        f"{summary['cases']} cases ({summary['persistent']} persistent, "
        f"{summary['isolated']} repair/retry)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
