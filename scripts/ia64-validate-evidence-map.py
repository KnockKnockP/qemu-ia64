#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate the IA-64 conformance evidence and CI classification registry."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.evidence-map"
SCHEMA_VERSION = 1
SPDX_DECLARATION = "SPDX-" + "License-Identifier: GPL-2.0-or-later"
EVIDENCE_LEVELS = ("E0", "E1", "E2", "E3", "E4")
CI_TIERS = ("affected-edit", "required", "nightly", "release", "soak")
ORACLES = (
    "implementation-coupled",
    "partially-independent",
    "integration-milestone",
    "independent",
)
ROLES = (
    "supporting", "candidate", "integration-only", "diagnostic-only",
    "row-closing",
)
KIND_LANE_LEVEL = {
    "source-check": ("manifest-static", "E0"),
    "infrastructure": ("manifest-static", "E0"),
    "host-unit": ("host-unit", "E1"),
    "bare-metal": ("bare-metal-batch", "E2"),
    "migration": ("multi-process", "E2"),
    "efi-bit": ("efi-bit", "E3"),
    "qtest": ("qtest-platform", "E3"),
    "os-sentinel": ("os-sentinel", "E4"),
    "os-workload": ("os-sentinel", "E4"),
    "performance-diagnostic": ("performance-diagnostic", "E4"),
}
REQUIRED_STANDALONE_IDS = {
    "standalone:efi-bit",
}
REQUIRED_GAP_IDS = {"sentinel:bsd"}
ENTRY_KEYS = {
    "id", "kind", "lane", "primary_evidence_level", "evidence_levels",
    "ci_tiers", "test_registration", "source_paths", "invocation", "scope",
    "oracle_independence", "conformance_role", "closes_normative_rows",
    "limitations",
}
GAP_KEYS = {"id", "expected_level", "ci_tiers", "status", "reason"}


class EvidenceError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise EvidenceError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise EvidenceError(
            f"invalid JSON in {path}:{exc.lineno}:{exc.colno}: {exc.msg}"
        ) from exc


def exact_keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise EvidenceError(f"{label}: expected an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise EvidenceError(f"{label}: {'; '.join(details)}")


def ordered_string_list(
    value: Any, allowed: tuple[str, ...] | None, label: str,
    *, allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise EvidenceError(f"{label}: expected a list of non-empty strings")
    if not allow_empty and not value:
        raise EvidenceError(f"{label}: list must not be empty")
    if len(value) != len(set(value)):
        raise EvidenceError(f"{label}: entries must be unique")
    if allowed is None:
        expected = sorted(value)
    else:
        unknown = sorted(set(value) - set(allowed))
        if unknown:
            raise EvidenceError(
                f"{label}: unknown value(s): {', '.join(unknown)}"
            )
        expected = sorted(value, key=allowed.index)
    if value != expected:
        raise EvidenceError(f"{label}: entries are not in canonical order")
    return value


def focused_registrations(build_dir: Path) -> list[str]:
    records = load_json(build_dir / "meson-info/intro-tests.json")
    if not isinstance(records, list):
        raise EvidenceError("Meson test introspection must be a list")
    names = []
    for record in records:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("name"), str)
        ):
            raise EvidenceError("Meson test registration is missing a name")
        name = record["name"]
        if (
            name.startswith("test-ia64-")
            or name.startswith("qtest-ia64/ia64-")
        ):
            names.append(name)
    if len(names) != len(set(names)):
        raise EvidenceError("focused Meson registrations are not unique")
    return sorted(names)


def validate_evidence_map(
    document: Any,
    registrations: list[str],
    normative_rows: dict[str, dict[str, Any]],
    repository_roots: dict[str, Path | None],
) -> dict[str, Any]:
    exact_keys(
        document,
        {"$comment", "schema", "schema_version", "policy", "entries", "gaps"},
        "evidence-map root",
    )
    if document["$comment"] != SPDX_DECLARATION:
        raise EvidenceError(
            "evidence-map SPDX declaration is missing or changed"
        )
    if (
        document["schema"] != SCHEMA
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise EvidenceError("unsupported evidence-map schema or version")
    policy = document["policy"]
    exact_keys(
        policy,
        {
            "classification_does_not_imply_pass",
            "row_closure_requires_normative_claim",
            "row_closing_claims_expected",
        },
        "evidence-map policy",
    )
    if policy["classification_does_not_imply_pass"] is not True:
        raise EvidenceError("classification must not imply a passing result")
    if policy["row_closure_requires_normative_claim"] is not True:
        raise EvidenceError(
            "row closure must require an explicit normative claim"
        )
    expected_claims = policy["row_closing_claims_expected"]
    if type(expected_claims) is not int or expected_claims < 0:
        raise EvidenceError(
            "row_closing_claims_expected must be a non-negative integer"
        )

    entries = document["entries"]
    if not isinstance(entries, list) or not entries:
        raise EvidenceError("evidence-map entries must be a non-empty list")
    entry_ids = [
        entry.get("id") if isinstance(entry, dict) else None
        for entry in entries
    ]
    if any(not isinstance(item, str) or not item for item in entry_ids):
        raise EvidenceError("every evidence entry needs a non-empty id")
    if len(entry_ids) != len(set(entry_ids)):
        raise EvidenceError("evidence entry ids must be unique")
    if entry_ids != sorted(entry_ids):
        raise EvidenceError("evidence entries must be sorted by id")
    missing_standalone = sorted(REQUIRED_STANDALONE_IDS - set(entry_ids))
    if missing_standalone:
        raise EvidenceError(
            "missing standalone evidence entries: "
            + ", ".join(missing_standalone)
        )

    classified_registrations: list[str] = []
    claims = 0
    deferred_paths = 0
    for index, entry in enumerate(entries):
        label = f"evidence entry {entry_ids[index]}"
        exact_keys(entry, ENTRY_KEYS, label)
        kind = entry["kind"]
        if kind not in KIND_LANE_LEVEL:
            raise EvidenceError(f"{label}: unknown kind {kind!r}")
        lane, primary = KIND_LANE_LEVEL[kind]
        if (
            entry["lane"] != lane
            or entry["primary_evidence_level"] != primary
        ):
            raise EvidenceError(
                f"{label}: {kind} requires lane {lane} and primary level "
                f"{primary}"
            )
        levels = ordered_string_list(
            entry["evidence_levels"], EVIDENCE_LEVELS,
            f"{label} evidence_levels",
        )
        if primary not in levels:
            raise EvidenceError(
                f"{label}: primary evidence level is not listed"
            )
        ordered_string_list(entry["ci_tiers"], CI_TIERS, f"{label} ci_tiers")
        registration = entry["test_registration"]
        if registration is not None:
            if not isinstance(registration, str) or not registration:
                raise EvidenceError(f"{label}: invalid test_registration")
            classified_registrations.append(registration)
        for field in ("invocation", "scope"):
            if not isinstance(entry[field], str) or not entry[field]:
                raise EvidenceError(f"{label}: {field} must not be empty")
        if entry["oracle_independence"] not in ORACLES:
            raise EvidenceError(f"{label}: unknown oracle independence")
        if entry["conformance_role"] not in ROLES:
            raise EvidenceError(f"{label}: unknown conformance role")
        ordered_string_list(entry["limitations"], None, f"{label} limitations")

        sources = entry["source_paths"]
        if not isinstance(sources, list) or not sources:
            raise EvidenceError(f"{label}: source_paths must not be empty")
        source_order = []
        for source in sources:
            exact_keys(source, {"repository", "path"}, f"{label} source path")
            repository = source["repository"]
            path_text = source["path"]
            if (
                repository not in repository_roots
                or not isinstance(path_text, str)
            ):
                raise EvidenceError(
                    f"{label}: unknown repository or invalid path"
                )
            path = PurePosixPath(path_text)
            if (
                path.is_absolute()
                or path.as_posix() != path_text
                or "\\" in path_text
                or not path.parts
                or any(
                part in ("", ".", "..") for part in path.parts
                )
            ):
                raise EvidenceError(
                    f"{label}: source path is not safely relative"
                )
            source_order.append((repository, path_text))
            repository_root = repository_roots[repository]
            if repository_root is None:
                deferred_paths += 1
            elif not (repository_root / Path(*path.parts)).is_file():
                raise EvidenceError(
                    f"{label}: missing source path {repository}/{path_text}"
                )
        if source_order != sorted(source_order):
            raise EvidenceError(f"{label}: source_paths are not sorted")

        closures = ordered_string_list(
            entry["closes_normative_rows"], None,
            f"{label} closes_normative_rows", allow_empty=True,
        )
        unknown_rows = sorted(set(closures) - set(normative_rows))
        if unknown_rows:
            raise EvidenceError(
                f"{label}: unknown normative row(s): "
                + ", ".join(unknown_rows)
            )
        if closures:
            claims += len(closures)
            if entry["conformance_role"] != "row-closing":
                raise EvidenceError(
                    f"{label}: normative claims require row-closing role"
                )
            if entry["oracle_independence"] != "independent":
                raise EvidenceError(
                    f"{label}: row-closing evidence must be independent"
                )
            for row_id in closures:
                if normative_rows[row_id]["required_evidence"] not in levels:
                    raise EvidenceError(
                        f"{label}: claim {row_id} lacks its required "
                        "evidence level"
                    )

    if len(classified_registrations) != len(set(classified_registrations)):
        raise EvidenceError(
            "Meson test registrations are classified more than once"
        )
    missing = sorted(set(registrations) - set(classified_registrations))
    unknown = sorted(set(classified_registrations) - set(registrations))
    if missing or unknown:
        details = []
        if missing:
            details.append("unclassified " + ", ".join(missing))
        if unknown:
            details.append("not registered " + ", ".join(unknown))
        raise EvidenceError(
            "Meson registration coverage mismatch: " + "; ".join(details)
        )
    if claims != expected_claims:
        raise EvidenceError(
            f"expected {expected_claims} row-closing claims, found {claims}"
        )

    gaps = document["gaps"]
    if not isinstance(gaps, list) or not gaps:
        raise EvidenceError("evidence-map gaps must be a non-empty list")
    gap_ids = []
    for gap in gaps:
        exact_keys(gap, GAP_KEYS, "evidence gap")
        gap_ids.append(gap["id"])
        if gap["status"] != "not-present":
            raise EvidenceError(f"{gap['id']}: unsupported gap status")
        if gap["expected_level"] not in EVIDENCE_LEVELS:
            raise EvidenceError(f"{gap['id']}: invalid expected level")
        ordered_string_list(
            gap["ci_tiers"], CI_TIERS, f"{gap['id']} ci_tiers"
        )
        if not isinstance(gap["reason"], str) or not gap["reason"]:
            raise EvidenceError(f"{gap['id']}: reason must not be empty")
    if len(gap_ids) != len(set(gap_ids)) or gap_ids != sorted(gap_ids):
        raise EvidenceError("evidence gaps must have unique, sorted ids")
    missing_gaps = sorted(REQUIRED_GAP_IDS - set(gap_ids))
    if missing_gaps:
        raise EvidenceError(
            "missing required evidence gaps: " + ", ".join(missing_gaps)
        )

    level_counts = Counter(
        entry["primary_evidence_level"] for entry in entries
    )
    lane_counts = Counter(entry["lane"] for entry in entries)
    tier_counts = Counter(
        tier for entry in entries for tier in entry["ci_tiers"]
    )
    return {
        "entries": len(entries),
        "registrations": len(classified_registrations),
        "row_closing_claims": claims,
        "deferred_paths": deferred_paths,
        "by_primary_level": {
            level: level_counts[level] for level in EVIDENCE_LEVELS
        },
        "by_lane": dict(sorted(lane_counts.items())),
        "by_ci_tier": {tier: tier_counts[tier] for tier in CI_TIERS},
    }


def resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument(
        "--evidence-map", type=Path,
        default=Path("tests/ia64-conformance/evidence-map.json"),
    )
    parser.add_argument(
        "--catalogue", type=Path,
        default=Path("tests/ia64-conformance/normative-catalogue.json"),
    )
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    catalogue = load_json(resolve(root, args.catalogue).resolve())
    normative_rows = {row["id"]: row for row in catalogue["rows"]}
    summary = validate_evidence_map(
        load_json(resolve(root, args.evidence_map).resolve()),
        focused_registrations(args.build_dir.resolve()),
        normative_rows,
        {"qemu-ia64": root},
    )
    levels = ", ".join(
        f"{level}={count}"
        for level, count in summary["by_primary_level"].items()
    )
    print(
        f"IA-64 evidence map verified: {summary['entries']} entries; "
        f"{summary['registrations']} Meson registrations; {levels}; "
        f"row-closing={summary['row_closing_claims']}; "
        f"deferred-paths={summary['deferred_paths']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, KeyError, OSError, TypeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
