#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Focused executable gate for IA-64 construction-order step 7."""

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
    manifest_path = root / "tests/ia64-conformance/correctness-lessons.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    modules = {
        "full-tcg": load_module(
            root / "tests/unit/test-ia64-full-tcg.py",
            "_ia64_correctness_full_tcg",
        ),
        "memory-tcg": load_module(
            root / "tests/unit/test-ia64-memory-tcg.py",
            "_ia64_correctness_memory_tcg",
        ),
        "tcp-migration": load_module(
            root / "tests/unit/test-ia64-tcp-migration.py",
            "_ia64_correctness_tcp_migration",
        ),
    }
    probes: list[tuple[str, str, Callable[[Path], str]]] = []
    for record in manifest["probes"]:
        function = getattr(modules[record["module"]], record["callable"])
        probes.append((record["id"], record["assertion"], function))

    print("TAP version 13")
    print(f"1..{len(probes)}")
    if not qemu.is_file():
        for index, (probe_id, _, _) in enumerate(probes, 1):
            print(f"not ok {index} - {probe_id}")
        print(f"# QEMU executable does not exist: {qemu}")
        return 1

    failures = 0
    for index, (probe_id, assertion, function) in enumerate(probes, 1):
        try:
            detail = function(qemu)
            print(f"ok {index} - {probe_id}")
            print(f"# contract: {assertion}")
            for line in detail.splitlines():
                print("# " + line)
        except Exception as exc:
            failures += 1
            print(f"not ok {index} - {probe_id}")
            for line in str(exc).splitlines() or [repr(exc)]:
                print("# " + line)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
