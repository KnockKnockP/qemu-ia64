#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate the executable matrix for construction-order step 7."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.correctness-lessons"
SPDX_DECLARATION = "SPDX-" + "License-Identifier: GPL-2.0-or-later"
ROOT_KEYS = {
    "$comment", "schema", "schema_version", "plan_section", "plan_step",
    "scope", "limitations", "probes", "lessons",
}
PROBE_KEYS = {"id", "module", "callable", "assertion"}
LESSON_KEYS = {"id", "plan_text", "probe_ids"}
MODULE_PATHS = {
    "full-tcg": "tests/unit/test-ia64-full-tcg.py",
    "memory-tcg": "tests/unit/test-ia64-memory-tcg.py",
    "tcp-migration": "tests/unit/test-ia64-tcp-migration.py",
}
REQUIRED_LESSONS = (
    ("group-entry-state", "group-entry state"),
    ("forwarding", "forwarding"),
    ("nat", "NaT"),
    ("application-register-boundaries",
     "AR.PFS and application-register boundaries"),
    ("rse-state", "RSE state"),
    ("prior-slot-commitment", "prior-slot commitment"),
    ("memory-safepoints", "current memory safepoints"),
    ("timer-interrupt-observation", "timer and interrupt observation"),
    ("special-modes-and-migration", "replay, plugin, and migration"),
)


class MatrixError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MatrixError(f"cannot load {path}: {exc}") from exc


def exact_keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise MatrixError(f"{label}: expected an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        raise MatrixError(
            f"{label}: missing={missing or 'none'} extra={extra or 'none'}"
        )


def nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MatrixError(f"{label}: expected a non-empty string")
    return value


def string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise MatrixError(f"{label}: expected non-empty strings")
    if len(value) != len(set(value)):
        raise MatrixError(f"{label}: duplicate entry")
    return value


def defined_functions(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        raise MatrixError(f"cannot inspect {path}: {exc}") from exc
    return {
        node.name for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def validate(document: Any, root: Path) -> dict[str, int]:
    exact_keys(document, ROOT_KEYS, "matrix root")
    if document["$comment"] != SPDX_DECLARATION:
        raise MatrixError("SPDX declaration changed")
    if document["schema"] != SCHEMA or document["schema_version"] != 1:
        raise MatrixError("unsupported matrix schema/version")
    if document["plan_section"] != "29" or document["plan_step"] != 7:
        raise MatrixError("matrix must identify construction-order step 7")
    nonempty_string(document["scope"], "scope")
    limitations = string_list(document["limitations"], "limitations")
    if not any("does not close normative" in item for item in limitations):
        raise MatrixError("matrix must disclaim normative row closure")
    if not any("not the exhaustive" in item for item in limitations):
        raise MatrixError("matrix must disclaim exhaustive section 10.3 coverage")

    probes = document["probes"]
    if not isinstance(probes, list) or not probes:
        raise MatrixError("probes must be a non-empty list")
    probe_ids = [probe.get("id") for probe in probes]
    if probe_ids != sorted(probe_ids) or len(probe_ids) != len(set(probe_ids)):
        raise MatrixError("probe ids must be unique and sorted")
    module_functions = {
        module: defined_functions(root / relative)
        for module, relative in MODULE_PATHS.items()
    }
    for index, probe in enumerate(probes):
        label = f"probe {probe_ids[index]}"
        exact_keys(probe, PROBE_KEYS, label)
        nonempty_string(probe["id"], f"{label} id")
        nonempty_string(probe["assertion"], f"{label} assertion")
        module = probe["module"]
        function = probe["callable"]
        if module not in module_functions:
            raise MatrixError(f"{label}: unknown module {module!r}")
        if function not in module_functions[module]:
            raise MatrixError(
                f"{label}: callable {function!r} is absent from "
                f"{MODULE_PATHS[module]}"
            )

    lessons = document["lessons"]
    if not isinstance(lessons, list):
        raise MatrixError("lessons must be a list")
    actual_lessons = [
        (lesson.get("id"), lesson.get("plan_text"))
        if isinstance(lesson, dict) else (None, None)
        for lesson in lessons
    ]
    if actual_lessons != list(REQUIRED_LESSONS):
        raise MatrixError("lesson identities/text do not exactly match plan step 7")
    used_probes: set[str] = set()
    for lesson in lessons:
        label = f"lesson {lesson['id']}"
        exact_keys(lesson, LESSON_KEYS, label)
        references = string_list(lesson["probe_ids"], f"{label} probe_ids")
        unknown = sorted(set(references) - set(probe_ids))
        if unknown:
            raise MatrixError(f"{label}: unknown probes {unknown}")
        used_probes.update(references)
    unused = sorted(set(probe_ids) - used_probes)
    if unused:
        raise MatrixError(f"unmapped probes: {unused}")

    return {
        "lessons": len(lessons),
        "probes": len(probes),
        "modules": len({probe["module"] for probe in probes}),
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
            load_json(root / "tests/ia64-conformance/correctness-lessons.json"),
            root,
        )
    except MatrixError as exc:
        print(f"correctness-lesson matrix validation failed: {exc}",
              file=sys.stderr)
        return 1
    print(
        "correctness-lesson matrix is valid: "
        f"{summary['lessons']} lessons, {summary['probes']} executable probes, "
        f"{summary['modules']} harness modules"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
