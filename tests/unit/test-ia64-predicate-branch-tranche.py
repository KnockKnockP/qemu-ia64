#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent E2 execution for the IA-64 predicate-and-branch tranche."""

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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args(argv)
    root = args.source_root.resolve()
    qemu = args.binary.resolve()
    manifest = json.loads(
        (root / "tests/ia64-conformance/predicate-branch-tranche.json")
        .read_text(encoding="utf-8")
    )
    harness = load_module(
        root / "tests/unit/test-ia64-full-tcg.py",
        "_ia64_predicate_branch_tranche_harness",
    )
    probes: dict[str, Callable[[Path], str]] = {
        name: getattr(harness, name)
        for case in manifest["cases"] for name in case["execution"]["probes"]
    }

    print("TAP version 13")
    print(f"1..{len(manifest['cases'])}")
    if not qemu.is_file():
        for index, case in enumerate(manifest["cases"], 1):
            print(f"not ok {index} - {case['normative_row']}")
        print(f"# QEMU executable does not exist: {qemu}")
        return 1

    cache: dict[str, tuple[bool, str]] = {}
    failures = 0
    for index, case in enumerate(manifest["cases"], 1):
        case_results: list[tuple[str, bool, str, bool]] = []
        for name in case["execution"]["probes"]:
            cached = name in cache
            if not cached:
                try:
                    cache[name] = (True, probes[name](qemu))
                except Exception as exc:
                    cache[name] = (False, "\n".join(str(exc).splitlines() or [repr(exc)]))
            ok, detail = cache[name]
            case_results.append((name, ok, detail, cached))
        passed = all(result[1] for result in case_results)
        if not passed:
            failures += 1
        print(f"{'ok' if passed else 'not ok'} {index} - {case['normative_row']}")
        print(f"# normative-token: {case['normative_token']}")
        for name, ok, detail, cached in case_results:
            print(f"# probe {name}: {'pass' if ok else 'FAIL'}{' (cached)' if cached else ''}")
            if not ok or not cached:
                for line in detail.splitlines():
                    print("# " + line)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
