#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run the manifest-mapped IA-64 decoder/bundle conformance tranche."""

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
    root, qemu = args.source_root.resolve(), args.binary.resolve()
    manifest = json.loads((root / "tests/ia64-conformance/decoder-bundle-tranche.json").read_text(encoding="utf-8"))
    harness = load_module(root / "tests/unit/test-ia64-full-tcg.py",
                          "_ia64_decoder_bundle_tranche_harness")
    module = load_module(root / "tests/unit/test-ia64-decoder-bundle-tcg.py",
                         "_ia64_decoder_bundle_tranche_probes")
    probes: dict[str, Callable[[ModuleType, Path], str]] = {
        name: getattr(module, name)
        for case in manifest["cases"] for name in case["execution"]["probes"]
    }
    print("TAP version 13")
    print(f"1..{len(manifest['cases'])}")
    if not qemu.is_file():
        print(f"not ok 1 - QEMU executable does not exist: {qemu}")
        return 1
    cache: dict[str, tuple[bool, str]] = {}
    failures = 0
    for index, case in enumerate(manifest["cases"], 1):
        results = []
        for name in case["execution"]["probes"]:
            cached = name in cache
            if not cached:
                try:
                    cache[name] = (True, probes[name](harness, qemu))
                except Exception as exc:
                    cache[name] = (False, "\n".join(str(exc).splitlines() or [repr(exc)]))
            ok, detail = cache[name]
            results.append((name, ok, detail, cached))
        passed = all(result[1] for result in results)
        failures += not passed
        print(f"{'ok' if passed else 'not ok'} {index} - {case['normative_row']}")
        print(f"# normative-token: {case['normative_token']}")
        for name, ok, detail, cached in results:
            print(f"# probe {name}: {'pass' if ok else 'FAIL'}{' (cached)' if cached else ''}")
            if not ok or not cached:
                for line in detail.splitlines():
                    print("# " + line)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
