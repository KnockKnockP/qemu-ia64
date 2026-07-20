#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent E2 execution for the IA-64 memory-boundary tranche."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Callable, Sequence


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.source_root.resolve()
    qemu = args.binary.resolve()
    manifest = json.loads(
        (root / "tests/ia64-conformance/memory-boundary-tranche.json")
        .read_text(encoding="utf-8")
    )
    harness = load_module(
        root / "tests/unit/test-ia64-memory-tcg.py",
        "_ia64_memory_boundary_tranche_harness",
    )
    cases: list[tuple[dict, Callable[[Path], str]]] = [
        (case, getattr(harness, case["execution"]["probe"]))
        for case in manifest["cases"]
    ]

    print("TAP version 13")
    print(f"1..{len(cases)}")
    if not qemu.is_file():
        for index, (case, _) in enumerate(cases, 1):
            print(f"not ok {index} - {case['normative_row']}")
        print(f"# QEMU executable does not exist: {qemu}")
        return 1

    failures = 0
    for index, (case, probe) in enumerate(cases, 1):
        try:
            detail = probe(qemu)
            print(f"ok {index} - {case['normative_row']}")
            print(f"# normative-token: {case['normative_token']}")
            for line in detail.splitlines():
                print("# " + line)
        except Exception as exc:
            failures += 1
            print(f"not ok {index} - {case['normative_row']}")
            for line in str(exc).splitlines() or [repr(exc)]:
                print("# " + line)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
