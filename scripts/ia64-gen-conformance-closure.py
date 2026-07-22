#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Join IA-64 implementation, normative, and test-registration rows.

This report is intentionally conservative.  A registered test is only a
candidate unless the evidence registry explicitly claims an exact normative
row, so broad regression tests cannot accidentally become conformance claims.
"""

from __future__ import annotations

import argparse
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import ModuleType
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.conformance-closure"
SCHEMA_VERSION = 3
MAP_SCHEMA = "vibtanium.ia64.conformance-closure-map"
MAP_SCHEMA_VERSION = 2
NORMATIVE_CATALOGUE = Path(
    "tests/ia64-conformance/normative-catalogue.json"
)
NORMATIVE_SCHEMA = Path(
    "tests/ia64-conformance/normative-catalogue.schema.json"
)
CLOSURE_MAP = Path("tests/ia64-conformance/closure-map.json")
EVIDENCE_MAP = Path("tests/ia64-conformance/evidence-map.json")
BLOCKING_STATES = (
    "advertised-untested",
    "contradiction",
    "implemented-untested",
    "test-infrastructure-failure",
)
ROW_STATES = (
    "implemented-tested",
    "implemented-untested",
    "advertised-tested",
    "advertised-untested",
    "known-unimplemented",
    "unimplemented-unadvertised",
    "reserved-tested",
    "profile-excluded",
    "inherited-dependency-tested",
    "compatibility-extension-tested",
    "contradiction",
    "test-infrastructure-failure",
)
TEST_EXECUTION_STATES = (
    "test-not-defined",
    "test-defined",
    "test-registered",
    "test-not-run",
    "test-passed",
    "test-failed",
    "test-infrastructure-failure",
)
IMPLEMENTED_STATUSES = ("live",)
UNIMPLEMENTED_STATUSES = ("decoder-dead-alias", "illegal")
ADVERTISED_STATUSES = ("runtime-exposed",)
SPDX_DECLARATION = "SPDX-" + "License-Identifier: GPL-2.0-or-later"


class ClosureError(RuntimeError):
    pass


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ClosureError(f"cannot load Python module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ClosureError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ClosureError(
            f"invalid JSON in {path}:{exc.lineno}:{exc.colno}: {exc.msg}"
        ) from exc


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise ClosureError(f"{label}: {'; '.join(details)}")


def string_list(value: Any, label: str, *, allow_empty: bool) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ClosureError(f"{label}: expected a list of non-empty strings")
    if not allow_empty and not value:
        raise ClosureError(f"{label}: list must not be empty")
    if len(value) != len(set(value)):
        raise ClosureError(f"{label}: list entries must be unique")
    if value != sorted(value):
        raise ClosureError(f"{label}: list entries must be sorted")
    return value


def focused_test_registrations(build_dir: Path) -> list[dict[str, Any]]:
    path = build_dir / "meson-info/intro-tests.json"
    records = load_json(path)
    if not isinstance(records, list):
        raise ClosureError(f"Meson test introspection is not a list: {path}")
    focused = []
    for record in records:
        name = record.get("name") if isinstance(record, dict) else None
        if not isinstance(name, str):
            raise ClosureError("Meson test registration is missing a name")
        if not (
            name.startswith("test-ia64-")
            or name.startswith("qtest-ia64/ia64-")
        ):
            continue
        suites = record.get("suite", [])
        if not isinstance(suites, list) or any(
            not isinstance(suite, str) for suite in suites
        ):
            raise ClosureError(f"{name}: Meson suites are malformed")
        focused.append({
            "id": name,
            "protocol": record.get("protocol", "exitcode"),
            "suites": sorted(suites),
            "timeout_seconds": record.get("timeout"),
        })
    focused.sort(key=lambda row: row["id"])
    identifiers = [row["id"] for row in focused]
    if len(identifiers) != len(set(identifiers)):
        raise ClosureError("focused Meson test registration IDs are not unique")
    return focused


def meson_registration_id(name: str) -> str | None:
    marker = "qemu:"
    if marker not in name:
        return None
    return name.rsplit(marker, 1)[1]


def load_test_results(
    path: Path, registration_ids: set[str]
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Load a Meson JSON-lines log without retaining commands or environment."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise ClosureError(f"missing Meson test result log: {path}") from exc

    results: dict[str, dict[str, Any]] = {}
    starts: list[float] = []
    ends: list[float] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ClosureError(
                f"invalid Meson result JSON at {path}:{line_number}: "
                f"{exc.msg}"
            ) from exc
        if not isinstance(record, dict):
            raise ClosureError(
                f"Meson result at {path}:{line_number} is not an object"
            )
        name = record.get("name")
        if not isinstance(name, str):
            raise ClosureError(
                f"Meson result at {path}:{line_number} has no test name"
            )
        test_id = meson_registration_id(name)
        if test_id not in registration_ids:
            continue
        if test_id in results:
            raise ClosureError(f"duplicate Meson result for {test_id}")

        meson_result = record.get("result")
        duration = record.get("duration")
        returncode = record.get("returncode")
        start = record.get("starttime")
        if not isinstance(meson_result, str):
            raise ClosureError(f"{test_id}: Meson result status is malformed")
        if not isinstance(duration, (int, float)) or duration < 0:
            raise ClosureError(f"{test_id}: Meson result duration is malformed")
        if returncode is not None and not isinstance(returncode, int):
            raise ClosureError(f"{test_id}: Meson return code is malformed")
        if isinstance(start, (int, float)):
            starts.append(float(start))
            ends.append(float(start) + float(duration))

        if meson_result == "OK" and returncode == 0:
            state = "test-passed"
        elif meson_result == "SKIP":
            state = "test-not-run"
        elif meson_result in {"FAIL", "UNEXPECTEDPASS", "EXPECTEDFAIL"}:
            state = "test-failed"
        else:
            state = "test-infrastructure-failure"

        result: dict[str, Any] = {
            "state": state,
            "meson_result": meson_result,
            "duration_seconds": round(float(duration), 6),
            "returncode": returncode,
        }
        if state in {"test-failed", "test-infrastructure-failure"}:
            output_parts = []
            for field in ("stdout", "stderr"):
                value = record.get(field)
                if isinstance(value, str) and value.strip():
                    output_parts.append(value.strip())
            output = "\n".join(output_parts)
            result["failure_output"] = output[-4000:]
        results[test_id] = result

    counts = Counter(result["state"] for result in results.values())
    summary = {
        "source": str(path),
        "focused_results": len(results),
        "wall_elapsed_seconds": (
            round(max(ends) - min(starts), 6) if starts else 0.0
        ),
        "by_state": {
            state: counts.get(state, 0) for state in TEST_EXECUTION_STATES
        },
    }
    return results, summary


def row_execution_state(
    closing_evidence: list[dict[str, Any]],
    registrations: dict[str, dict[str, Any]],
    test_results: dict[str, dict[str, Any]] | None,
) -> str:
    if not closing_evidence:
        return "test-not-defined"
    test_ids = [
        entry["test_registration"] for entry in closing_evidence
        if entry["test_registration"] is not None
    ]
    if len(test_ids) != len(closing_evidence) or any(
        test_id not in registrations for test_id in test_ids
    ):
        return "test-defined"
    if test_results is None:
        return "test-registered"
    states = [
        test_results.get(test_id, {"state": "test-not-run"})["state"]
        for test_id in test_ids
    ]
    if "test-infrastructure-failure" in states:
        return "test-infrastructure-failure"
    if "test-failed" in states:
        return "test-failed"
    if "test-not-run" in states:
        return "test-not-run"
    if states and all(state == "test-passed" for state in states):
        return "test-passed"
    return "test-infrastructure-failure"


def blockers_for_execution(state: str) -> list[str]:
    return {
        "test-not-defined": ["no explicit row-closing evidence claim"],
        "test-defined": ["row-closing test is not registered in this build"],
        "test-registered": ["no execution result log was supplied"],
        "test-not-run": ["row-closing test was not run in the selected result set"],
        "test-passed": [],
        "test-failed": ["row-closing test failed in the selected result set"],
        "test-infrastructure-failure": [
            "row-closing test had an infrastructure failure"
        ],
    }[state]


def validate_closure_map(
    closure_map: Any,
    normative_rows: dict[str, dict[str, Any]],
    implementation_rows: dict[str, dict[str, Any]],
    registrations: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(closure_map, dict):
        raise ClosureError("closure-map root must be an object")
    exact_keys(
        closure_map,
        {
            "$comment",
            "schema",
            "schema_version",
            "policy",
            "infrastructure_tests",
            "mappings",
        },
        "closure-map root",
    )
    if closure_map["schema"] != MAP_SCHEMA:
        raise ClosureError(
            f"unexpected closure-map schema: {closure_map['schema']}"
        )
    if closure_map["schema_version"] != MAP_SCHEMA_VERSION:
        raise ClosureError(
            f"unsupported closure-map version: {closure_map['schema_version']}"
        )
    if closure_map["$comment"] != SPDX_DECLARATION:
        raise ClosureError("closure-map SPDX declaration is missing or changed")

    policy = closure_map["policy"]
    if not isinstance(policy, dict):
        raise ClosureError("closure-map policy must be an object")
    exact_keys(
        policy,
        {
            "candidate_tests_close_rows",
            "required_evidence_classified",
            "description",
        },
        "closure-map policy",
    )
    if policy["candidate_tests_close_rows"] is not False:
        raise ClosureError(
            "candidate tests must not close rows at this checkpoint"
        )
    if policy["required_evidence_classified"] is not True:
        raise ClosureError("required evidence must be classified")
    if not isinstance(policy["description"], str) or not policy["description"]:
        raise ClosureError("closure-map policy description must not be empty")

    infrastructure = string_list(
        closure_map["infrastructure_tests"],
        "closure-map infrastructure_tests",
        allow_empty=False,
    )
    missing_infrastructure = sorted(set(infrastructure) - set(registrations))
    if missing_infrastructure:
        raise ClosureError(
            "missing infrastructure test registration(s): "
            + ", ".join(missing_infrastructure)
        )

    mappings = closure_map["mappings"]
    if not isinstance(mappings, list) or not mappings:
        raise ClosureError("closure-map mappings must be a non-empty list")
    expected_mapping_keys = {
        "normative_row",
        "surface_disposition",
        "implementation_rows",
        "inventory_gap",
        "candidate_tests",
    }
    seen_normative: set[str] = set()
    expanded_mappings: list[dict[str, Any]] = []
    for index, mapping in enumerate(mappings):
        label = f"closure-map mappings[{index}]"
        if not isinstance(mapping, dict):
            raise ClosureError(f"{label}: expected an object")
        actual_keys = set(mapping)
        selector_keys = expected_mapping_keys | {"implementation_selector"}
        if actual_keys not in (expected_mapping_keys, selector_keys):
            raise ClosureError(
                f"{label}: keys differ (expected legacy keys or one "
                "implementation_selector)"
            )
        normative_id = mapping["normative_row"]
        if (
            not isinstance(normative_id, str)
            or normative_id not in normative_rows
        ):
            raise ClosureError(
                f"{label}: unknown normative row {normative_id!r}"
            )
        if normative_id in seen_normative:
            raise ClosureError(
                f"duplicate mapping for normative row {normative_id}"
            )
        seen_normative.add(normative_id)

        if mapping["surface_disposition"] != "implemented":
            raise ClosureError(
                f"{normative_id}: seed catalogue rows must be implemented"
            )
        implementation_ids = list(
            string_list(
                mapping["implementation_rows"],
                f"{normative_id} implementation_rows",
                allow_empty=True,
            )
        )
        if "implementation_selector" in mapping:
            selector = mapping["implementation_selector"]
            exact_keys(
                selector,
                {"coverage_group", "exclude_rows"},
                f"{normative_id} implementation_selector",
            )
            group = selector["coverage_group"]
            if not isinstance(group, str) or not group:
                raise ClosureError(
                    f"{normative_id}: coverage_group must be a non-empty string"
                )
            group_ids = sorted(
                row_id for row_id, row in implementation_rows.items()
                if row.get("attributes", {}).get("coverage_group") == group
            )
            if not group_ids:
                raise ClosureError(
                    f"{normative_id}: coverage group {group!r} is empty"
                )
            exclusions = string_list(
                selector["exclude_rows"],
                f"{normative_id} implementation_selector exclude_rows",
                allow_empty=True,
            )
            invalid_exclusions = sorted(set(exclusions) - set(group_ids))
            if invalid_exclusions:
                raise ClosureError(
                    f"{normative_id}: selector exclusion(s) are outside "
                    f"{group}: " + ", ".join(invalid_exclusions)
                )
            implementation_ids.extend(
                row_id for row_id in group_ids if row_id not in exclusions
            )
        if len(implementation_ids) != len(set(implementation_ids)):
            raise ClosureError(
                f"{normative_id}: implementation rows overlap after "
                "selector expansion"
            )
        unknown_implementation = sorted(
            set(implementation_ids) - set(implementation_rows)
        )
        if unknown_implementation:
            raise ClosureError(
                f"{normative_id}: unknown implementation row(s): "
                + ", ".join(unknown_implementation)
            )
        for implementation_id in implementation_ids:
            status = implementation_rows[implementation_id]["status"]
            if status not in IMPLEMENTED_STATUSES:
                raise ClosureError(
                    f"{normative_id}: {implementation_id} has incompatible "
                    f"status {status}"
                )

        gap = mapping["inventory_gap"]
        if implementation_ids and gap is not None:
            raise ClosureError(
                f"{normative_id}: mapped implementation rows cannot have an "
                "inventory gap"
            )
        if not implementation_ids and (
            not isinstance(gap, str) or not gap
        ):
            raise ClosureError(
                f"{normative_id}: an empty implementation mapping requires "
                "an inventory gap"
            )

        candidates = string_list(
            mapping["candidate_tests"],
            f"{normative_id} candidate_tests",
            allow_empty=False,
        )
        missing_tests = sorted(set(candidates) - set(registrations))
        if missing_tests:
            raise ClosureError(
                f"{normative_id}: missing candidate test registration(s): "
                + ", ".join(missing_tests)
            )

        expanded = dict(mapping)
        expanded["implementation_rows"] = implementation_ids
        expanded_mappings.append(expanded)

    mapping_order = [mapping["normative_row"] for mapping in expanded_mappings]
    if mapping_order != sorted(mapping_order):
        raise ClosureError(
            "closure-map mappings must be sorted by normative row"
        )
    missing_normative = sorted(set(normative_rows) - seen_normative)
    extra_normative = sorted(seen_normative - set(normative_rows))
    if missing_normative or extra_normative:
        details = []
        if missing_normative:
            details.append("missing " + ", ".join(missing_normative))
        if extra_normative:
            details.append("extra " + ", ".join(extra_normative))
        raise ClosureError(
            "normative mapping is not complete: " + "; ".join(details)
        )
    return expanded_mappings


def state_for_implementation(row: dict[str, Any]) -> str:
    status = row["status"]
    if status in IMPLEMENTED_STATUSES:
        return "implemented-untested"
    if status in ADVERTISED_STATUSES:
        return "advertised-untested"
    if status in UNIMPLEMENTED_STATUSES:
        return "known-unimplemented"
    raise ClosureError(
        f"{row['id']}: implementation status {status!r} lacks a closure rule"
    )


def blockers_for_state(state: str, *, has_catalogue: bool) -> list[str]:
    if state in ("implemented-untested", "advertised-untested"):
        blockers = []
        if not has_catalogue:
            blockers.append("missing normative catalogue row")
        blockers.append("no explicit row-closing evidence claim")
        return blockers
    return []


def build_report(
    implementation: dict[str, Any],
    catalogue: dict[str, Any],
    closure_map: dict[str, Any],
    evidence_map: dict[str, Any],
    evidence_summary: dict[str, Any],
    registrations: list[dict[str, Any]],
    profile: str,
    test_results: dict[str, dict[str, Any]] | None = None,
    test_result_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if implementation.get("schema") != "vibtanium.ia64.implementation-surface":
        raise ClosureError("implementation input has an unexpected schema")
    if implementation.get("schema_version") != 2:
        raise ClosureError("implementation input has an unsupported version")
    if profile not in implementation.get("profiles", []):
        raise ClosureError(
            f"implementation input does not cover profile {profile}"
        )
    if profile not in catalogue.get("profiles", []):
        raise ClosureError(
            f"normative catalogue does not cover profile {profile}"
        )

    implementation_rows = {
        row["id"]: row for row in implementation["rows"]
    }
    normative_rows = {
        row["id"]: row
        for row in catalogue["rows"]
        if profile in row["profiles"]
    }
    registration_rows = {row["id"]: row for row in registrations}
    mappings = validate_closure_map(
        closure_map, normative_rows, implementation_rows, registration_rows
    )
    evidence_by_registration = {
        entry["test_registration"]: entry
        for entry in evidence_map["entries"]
        if entry["test_registration"] is not None
    }
    evidence_by_normative: dict[str, list[dict[str, Any]]] = {
        row_id: [] for row_id in normative_rows
    }
    for entry in evidence_map["entries"]:
        for row_id in entry["closes_normative_rows"]:
            if row_id in evidence_by_normative:
                evidence_by_normative[row_id].append(entry)

    candidate_for: dict[str, list[str]] = {
        test_id: [] for test_id in registration_rows
    }
    mapped_implementation: set[str] = set()
    joined_rows = []
    for mapping in mappings:
        normative_id = mapping["normative_row"]
        normative = normative_rows[normative_id]
        implementation_ids = mapping["implementation_rows"]
        mapped_implementation.update(implementation_ids)
        for test_id in mapping["candidate_tests"]:
            candidate_for[test_id].append(normative_id)
        closing_evidence = evidence_by_normative[normative_id]
        execution_state = row_execution_state(
            closing_evidence, registration_rows, test_results
        )
        if execution_state == "test-passed":
            state = "implemented-tested"
        elif execution_state == "test-infrastructure-failure":
            state = "test-infrastructure-failure"
        else:
            state = "implemented-untested"
        blockers = blockers_for_execution(execution_state)
        if mapping["inventory_gap"] is not None:
            blockers.insert(0, mapping["inventory_gap"])
        joined_rows.append({
            "id": f"normative:{normative_id}",
            "origin": "normative-catalogue",
            "state": state,
            "interface_kind": normative["interface_kind"],
            "implementation_rows": implementation_ids,
            "normative_rows": [normative_id],
            "test_registrations": mapping["candidate_tests"],
            "required_evidence": normative["required_evidence"],
            "test_execution_state": execution_state,
            "evidence_status": (
                "row-closing-claim-defined" if closing_evidence
                else "classified-no-row-closing-claim"
            ),
            "row_closing_claims": [
                entry["id"] for entry in closing_evidence
            ],
            "inventory_gap": mapping["inventory_gap"],
            "blockers": blockers,
        })

    for implementation_id, row in sorted(implementation_rows.items()):
        if implementation_id in mapped_implementation:
            continue
        state = state_for_implementation(row)
        joined_rows.append({
            "id": f"implementation:{implementation_id}",
            "origin": "implementation-inventory",
            "state": state,
            "interface_kind": row["kind"],
            "implementation_status": row["status"],
            "implementation_rows": [implementation_id],
            "normative_rows": [],
            "test_registrations": [],
            "required_evidence": None,
            "test_execution_state": "test-not-defined",
            "evidence_status": "missing-normative-row",
            "inventory_gap": None,
            "blockers": blockers_for_state(state, has_catalogue=False),
        })
    joined_rows.sort(key=lambda row: row["id"])

    represented_implementation = {
        implementation_id
        for row in joined_rows
        for implementation_id in row["implementation_rows"]
    }
    if represented_implementation != set(implementation_rows):
        raise ClosureError(
            "closure report did not represent every implementation row"
        )
    represented_normative = {
        normative_id
        for row in joined_rows
        for normative_id in row["normative_rows"]
    }
    if represented_normative != set(normative_rows):
        raise ClosureError(
            "closure report did not represent every normative row"
        )

    infrastructure = set(closure_map["infrastructure_tests"])
    report_registrations = []
    for registration in registrations:
        test_id = registration["id"]
        if test_results is None:
            execution_result = {"state": "test-registered"}
        else:
            execution_result = test_results.get(
                test_id, {"state": "test-not-run"}
            )
        report_registrations.append({
            **registration,
            "candidate_for": sorted(candidate_for[test_id]),
            "infrastructure": test_id in infrastructure,
            "evidence": {
                "id": evidence_by_registration[test_id]["id"],
                "primary_level": evidence_by_registration[test_id][
                    "primary_evidence_level"
                ],
                "levels": evidence_by_registration[test_id]["evidence_levels"],
                "ci_tiers": evidence_by_registration[test_id]["ci_tiers"],
                "role": evidence_by_registration[test_id]["conformance_role"],
            },
            "evidence_status": (
                "row-closing-claim" if evidence_by_registration[test_id][
                    "closes_normative_rows"
                ] else "classified-not-row-closing"
            ),
            "execution_result": execution_result,
        })

    state_counts = Counter(row["state"] for row in joined_rows)
    by_state = {state: state_counts.get(state, 0) for state in ROW_STATES}
    blocking_rows = sum(by_state[state] for state in BLOCKING_STATES)
    inventory_gaps = sum(
        row["inventory_gap"] is not None for row in joined_rows
    )
    candidate_links = sum(
        len(row["test_registrations"]) for row in joined_rows
    )
    normative_execution_counts = Counter(
        row["test_execution_state"]
        for row in joined_rows
        if row["origin"] == "normative-catalogue"
    )
    implemented_conformant = blocking_rows == 0
    if implemented_conformant:
        raise ClosureError(
            "foundation report unexpectedly reached a conformance claim"
        )

    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "profile": profile,
        "report_scope": (
            "selected-build runtime closure"
            if test_results is not None else
            "construction-time closure; registrations are not execution results"
        ),
        "inputs": {
            "implementation_surface": {
                "schema_version": implementation["schema_version"],
                "rows": len(implementation_rows),
                "coverage_pending": implementation["coverage"]["pending"],
            },
            "normative_catalogue": {
                "schema_version": catalogue["schema_version"],
                "catalogue_revision": catalogue["catalogue_revision"],
                "rows": len(normative_rows),
            },
            "closure_map": {
                "schema_version": closure_map["schema_version"],
                "candidate_tests_close_rows": False,
                "required_evidence_classified": True,
            },
            "evidence_map": {
                "schema_version": evidence_map["schema_version"],
                "entries": evidence_summary["entries"],
                "row_closing_claims": evidence_summary["row_closing_claims"],
            },
            "test_registrations": {
                "source": "meson-info/intro-tests.json",
                "focused_rows": len(registrations),
            },
            "test_results": test_result_summary,
        },
        "claims": {
            "implemented_surface_conformant": False,
            "declared_profile_consistent": "not-evaluated",
            "profile_complete": "not-evaluated",
            "reason": (
                "blocking implementation rows remain outside the seed "
                "catalogue; explicit seed-row evidence is reported below"
            ),
        },
        "classification_policy": {
            "guest_reachable_live": "implemented-untested",
            "runtime_exposed": "advertised-untested",
            "decoder_dead_alias_or_illegal": "known-unimplemented",
            "candidate_test_registration": "does-not-close-row",
            "classified_evidence": (
                "closes-only-explicitly-claimed-normative-rows"
            ),
            "implemented_tested": (
                "requires-test-passed-for-selected-build-and-profile"
            ),
        },
        "summary": {
            "join_rows": len(joined_rows),
            "implementation_rows": len(implementation_rows),
            "normative_rows": len(normative_rows),
            "test_registrations": len(registrations),
            "evidence_entries": evidence_summary["entries"],
            "row_closing_claims": evidence_summary["row_closing_claims"],
            "candidate_links": candidate_links,
            "inventory_gaps": inventory_gaps,
            "blocking_rows": blocking_rows,
            "by_state": by_state,
            "normative_by_test_execution_state": {
                state: normative_execution_counts.get(state, 0)
                for state in TEST_EXECUTION_STATES
            },
        },
        "test_registrations": report_registrations,
        "rows": joined_rows,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    runtime = report["inputs"]["test_results"]
    lines = [
        "# IA-64 Conformance Closure Report",
        "",
        f"Profile: `{report['profile']}`",
        "",
        f"Scope: `{report['report_scope']}`",
        "",
        "A row is `implemented-tested` only when the evidence registry makes",
        "an explicit, independently validated claim and its row-closing test",
        "passed in the selected build result set.",
        "",
        "## Claims",
        "",
        "- Implemented-surface conformant: **no**",
        "- Declared-profile consistency: **not evaluated**",
        "- Profile completeness: **not evaluated**",
        "",
        "## Inputs",
        "",
        f"- Implementation rows: {summary['implementation_rows']}",
        f"- Normative rows: {summary['normative_rows']}",
        f"- Focused test registrations: {summary['test_registrations']}",
        f"- Classified evidence entries: {summary['evidence_entries']}",
        f"- Row-closing evidence claims: {summary['row_closing_claims']}",
        f"- Candidate test links: {summary['candidate_links']}",
        f"- Joined rows: {summary['join_rows']}",
        "",
    ]
    if runtime is not None:
        runtime_counts = runtime["by_state"]
        lines.extend([
            "## Runtime result set",
            "",
            f"- Focused results: {runtime['focused_results']}",
            f"- Passed: {runtime_counts['test-passed']}",
            f"- Failed: {runtime_counts['test-failed']}",
            "- Infrastructure failures: "
            f"{runtime_counts['test-infrastructure-failure']}",
            f"- Wall elapsed: {runtime['wall_elapsed_seconds']:.3f} seconds",
            "",
        ])
    lines.extend([
        "## Row states",
        "",
        "| State | Count |",
        "| --- | ---: |",
    ])
    for state in ROW_STATES:
        lines.append(f"| `{state}` | {summary['by_state'][state]} |")
    lines.extend([
        "",
        f"Blocking rows: **{summary['blocking_rows']}**",
        "",
        "## Seed catalogue joins",
        "",
        "| Normative row | State | Test execution | Implementation rows | Candidate tests |",
        "| --- | --- | --- | ---: | ---: |",
    ])
    normative_rows = [
        row for row in report["rows"]
        if row["origin"] == "normative-catalogue"
    ]
    for row in normative_rows:
        normative_id = row["normative_rows"][0]
        lines.append(
            f"| `{normative_id}` | `{row['state']}` | "
            f"`{row['test_execution_state']}` | "
            f"{len(row['implementation_rows'])} | "
            f"{len(row['test_registrations'])} |"
        )
    lines.extend([
        "",
        "The JSON report contains every joined row, its exact state, blockers,",
        "implementation and normative references, and candidate registrations.",
        "",
    ])
    return "\n".join(lines)


def resolve_path(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(__file__).resolve().parents[1],
        help="QEMU source root",
    )
    parser.add_argument(
        "--build-dir", type=Path, required=True,
        help="configured IA-64 QEMU build directory",
    )
    parser.add_argument(
        "--binary", type=Path,
        help="qemu-system-ia64 binary (defaults inside --build-dir)",
    )
    parser.add_argument(
        "--profile", default="vibtanium-strict-up",
        help="profile to report",
    )
    parser.add_argument(
        "--catalogue", type=Path, default=NORMATIVE_CATALOGUE,
        help="normative catalogue, relative to --root by default",
    )
    parser.add_argument(
        "--catalogue-schema", type=Path, default=NORMATIVE_SCHEMA,
        help="normative catalogue schema, relative to --root by default",
    )
    parser.add_argument(
        "--closure-map", type=Path, default=CLOSURE_MAP,
        help="closure mapping, relative to --root by default",
    )
    parser.add_argument(
        "--evidence-map", type=Path, default=EVIDENCE_MAP,
        help="evidence classification, relative to --root by default",
    )
    parser.add_argument(
        "--test-log", type=Path,
        help="Meson JSON-lines test log for the selected build and run",
    )
    parser.add_argument("--output", type=Path, help="write JSON report")
    parser.add_argument(
        "--summary-output", type=Path,
        help="write Markdown summary",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="validate and summarize without writing a report",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.check and (args.output or args.summary_output):
        raise ClosureError("--check cannot be combined with report outputs")
    root = args.root.resolve()
    build_dir = args.build_dir.resolve()
    binary = (
        args.binary.resolve() if args.binary else
        build_dir / (
            "qemu-system-ia64.exe" if os.name == "nt" else "qemu-system-ia64"
        )
    )

    implementation_module = load_module(
        root / "scripts/ia64-gen-implementation-surface.py",
        "_ia64_implementation_surface",
    )
    normative_module = load_module(
        root / "scripts/ia64-validate-normative-catalogue.py",
        "_ia64_normative_catalogue",
    )
    evidence_module = load_module(
        root / "scripts/ia64-validate-evidence-map.py",
        "_ia64_evidence_map",
    )
    try:
        implementation = implementation_module.build_surface(
            root, build_dir, binary
        )
    except Exception as exc:
        raise ClosureError(f"implementation inventory failed: {exc}") from exc

    catalogue_path = resolve_path(root, args.catalogue).resolve()
    catalogue_schema_path = resolve_path(
        root, args.catalogue_schema
    ).resolve()
    catalogue = load_json(catalogue_path)
    catalogue_schema = load_json(catalogue_schema_path)
    try:
        normative_module.validate_schema(catalogue, catalogue_schema)
        normative_module.validate_semantics(catalogue)
    except Exception as exc:
        raise ClosureError(f"normative catalogue failed: {exc}") from exc

    closure_map = load_json(resolve_path(root, args.closure_map).resolve())
    registrations = focused_test_registrations(build_dir)
    test_results = None
    test_result_summary = None
    if args.test_log is not None:
        test_results, test_result_summary = load_test_results(
            args.test_log.resolve(), {row["id"] for row in registrations}
        )
        test_result_summary["selected_build"] = str(build_dir)
        test_result_summary["command"] = (
            "scripts/ia64-run-required-conformance.sh"
        )
    evidence_map = load_json(resolve_path(root, args.evidence_map).resolve())
    try:
        evidence_summary = evidence_module.validate_evidence_map(
            evidence_map,
            [row["id"] for row in registrations],
            {row["id"]: row for row in catalogue["rows"]},
            {"qemu-ia64": root},
        )
    except Exception as exc:
        raise ClosureError(f"evidence classification failed: {exc}") from exc
    report = build_report(
        implementation, catalogue, closure_map, evidence_map,
        evidence_summary, registrations, args.profile,
        test_results, test_result_summary,
    )
    if args.check:
        counts = report["summary"]["by_state"]
        if test_result_summary is None:
            execution = "execution-results=not-supplied"
        else:
            execution_counts = test_result_summary["by_state"]
            execution = (
                f"execution-results={test_result_summary['focused_results']}; "
                f"test-passed={execution_counts['test-passed']}; "
                f"test-failed={execution_counts['test-failed']}; "
                "test-infrastructure-failure="
                f"{execution_counts['test-infrastructure-failure']}"
            )
        print(
            "IA-64 conformance closure verified: "
            f"{report['summary']['join_rows']} rows; "
            f"implemented-untested={counts['implemented-untested']}; "
            f"advertised-untested={counts['advertised-untested']}; "
            f"known-unimplemented={counts['known-unimplemented']}; "
            f"{execution}; "
            f"blocking={report['summary']['blocking_rows']}"
        )
        return 0

    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    if args.summary_output:
        args.summary_output.parent.mkdir(parents=True, exist_ok=True)
        args.summary_output.write_text(
            render_markdown(report), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ClosureError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
