#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent no-OS index and anti-alias matrices for IA-64 registers."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType
from typing import Callable, Sequence


PSR_DFL = 1 << 18
PSR_DFH = 1 << 19
GR_VALUES = tuple(range(1, 128))
FR_INDICES = tuple(range(2, 128))
PR_CODEWORDS = tuple(
    1 | sum(((register >> bit) & 1) << register for register in range(1, 64))
    for bit in range(6)
)
BR_VALUES = tuple(0x100 + register for register in range(8))


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def validate_contract(root: Path) -> str:
    manifest_path = root / "tests/ia64-conformance/register-semantic-tranche.json"
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_rows = {
        "REG-005-GR-INDEX-SPACE": ("cpu.register.gr.all-indices", ["cpu.register.gr.0"]),
        "REG-006-FR-INDEX-SPACE": ("cpu.register.fr.all-indices", ["cpu.register.fr.0", "cpu.register.fr.1"]),
        "REG-006-PR-INDEX-SPACE": ("cpu.register.pr.all-indices", ["cpu.register.pr.0"]),
        "REG-006-BR-INDEX-SPACE": ("cpu.register.br.all-indices", []),
    }
    if document.get("schema") != "vibtanium.ia64.register-semantic-tranche" or document.get("schema_version") != 1:
        raise AssertionError("register tranche schema/version drift")
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != len(expected_rows):
        raise AssertionError("register tranche must contain four cases")
    for case in cases:
        row = case.get("normative_row")
        if row not in expected_rows:
            raise AssertionError(f"unexpected register tranche row: {row!r}")
        selector = case.get("implementation_selector")
        group, exclusions = expected_rows[row]
        if selector != {"coverage_group": group, "exclude_rows": exclusions}:
            raise AssertionError(f"{row}: implementation selector drift")
        if case.get("oracle", {}).get("independence") != "independent":
            raise AssertionError(f"{row}: oracle is not independent")
    if len(set(GR_VALUES)) != 127 or GR_VALUES[-1] != 127:
        raise AssertionError("GR matrix does not cover r1-r127 exactly")
    if len(set(FR_INDICES)) != 126 or FR_INDICES[-1] != 127:
        raise AssertionError("FR matrix does not cover f2-f127 exactly")
    signatures = {register: tuple((word >> register) & 1 for word in PR_CODEWORDS) for register in range(1, 64)}
    if len(set(signatures.values())) != 63:
        raise AssertionError("predicate codewords do not distinguish p1-p63")
    if len(set(BR_VALUES)) != 8:
        raise AssertionError("branch-register values are not unique")
    return "127 GR, 126 FR, 63 PR, and 8 BR indices have complete anti-alias vectors"


def general_register_program(h: ModuleType):
    bundles = []
    address = 0x10
    bundles.append(h.Bundle(address, 0x01, h.alloc(31, 96, 96, 0), h.nop_i(), h.nop_i()))
    address += 0x10
    for register in GR_VALUES:
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.adds(register, register, 0), h.nop_i()))
        address += 0x10

    compare_addresses = []
    for register in GR_VALUES:
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.cmp_imm(6, 7, register, register, "eq"), h.nop_i()))
        address += 0x10
        compare_addresses.append(address)
        address += 0x10
    skip_failure = address
    failure = address + 0x10
    terminal = address + 0x20
    branch_index = len(GR_VALUES) + 2
    for source in compare_addresses:
        bundles.insert(branch_index, h.Bundle(source, 0x11, h.nop_m(), h.nop_i(), h.br_cond(source, failure, qp=7)))
        branch_index += 2
    bundles.append(h.Bundle(skip_failure, 0x11, h.nop_m(), h.nop_i(), h.br_cond(skip_failure, terminal)))
    bundles.append(h.Bundle(failure, 0x01, h.nop_m(), h.adds(14, 0, 0), h.nop_i()))
    bundles.append(h.spin_bundle(terminal))
    return h.Program("complete GR index and anti-alias matrix", tuple(bundles), terminal)


def test_general_register_indices(h: ModuleType, qemu: Path) -> str:
    program = general_register_program(h)
    snapshot = h.run_program(qemu, program, compact_loader=True)
    if snapshot.ip != program.terminal_ip:
        raise AssertionError("GR matrix missed its terminal bundle")
    failures = [f"r{register}=0x{snapshot.gr[register]:x}" for register in GR_VALUES if snapshot.gr[register] != register]
    if failures:
        raise AssertionError("GR write/read/alias mismatch: " + ", ".join(failures[:8]))
    if snapshot.nat_low or snapshot.nat_high:
        raise AssertionError("GR matrix unexpectedly introduced NaT state")
    if (snapshot.cfm & 0x7f) != 96 or ((snapshot.cfm >> 7) & 0x7f) != 96:
        raise AssertionError(f"GR matrix lost its 96-register frame: CFM=0x{snapshot.cfm:x}")
    return "guest comparisons and the final image distinguish every writable r1-r127 index in a 96-register frame"


def floating_register_program(h: ModuleType, fp: ModuleType, selected: tuple[int, ...]):
    bundles = []
    address = 0x10
    bundles.append(h.Bundle(address, 0x01, h.rsm(PSR_DFL | PSR_DFH), h.nop_i(), h.nop_i()))
    address += 0x10
    for register in FR_INDICES:
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.adds(2, register, 0), h.nop_i()))
        address += 0x10
        bundles.append(h.Bundle(address, 0x01, fp.raw_setf("sig", register, 2), h.nop_i(), h.nop_i()))
        address += 0x10
    for output, register in enumerate(selected, 8):
        bundles.append(h.Bundle(address, 0x01, fp.raw_getf("sig", output, register), h.nop_i(), h.nop_i()))
        address += 0x10
    bundles.append(h.spin_bundle(address))
    return h.Program("complete FR index and anti-alias chunk", tuple(bundles), address)


def test_floating_register_indices(h: ModuleType, fp: ModuleType, qemu: Path) -> str:
    checked = 0
    for start in range(0, len(FR_INDICES), 24):
        selected = FR_INDICES[start:start + 24]
        snapshot = h.run_program(
            qemu, floating_register_program(h, fp, selected),
            compact_loader=True,
        )
        failures = [f"f{register}->r{output}=0x{snapshot.gr[output]:x}" for output, register in enumerate(selected, 8) if snapshot.gr[output] != register]
        if failures:
            raise AssertionError("FR write/read/alias mismatch: " + ", ".join(failures[:8]))
        checked += len(selected)
    if checked != 126:
        raise AssertionError(f"FR witness count is {checked}, expected 126")
    return "six full-file initialization chunks distinguish and round-trip every writable f2-f127 index"


def predicate_register_program(h: ModuleType):
    bundles = []
    data = []
    address = 0x10
    for bit, word in enumerate(PR_CODEWORDS):
        data_address = 0x1000 + bit * 8
        data.append(h.DataWord(data_address, word, 8))
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.adds(2, data_address, 0), h.nop_i()))
        address += 0x10
        bundles.append(h.Bundle(address, 0x01, h.ld8(3, 2), h.nop_i(), h.nop_i()))
        address += 0x10
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.mov_grpr(3, 0x1fffe), h.nop_i()))
        address += 0x10
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.mov_prgr(8 + bit), h.nop_i()))
        address += 0x10
    bundles.append(h.spin_bundle(address))
    return h.Program("complete PR index codeword matrix", tuple(bundles), address, tuple(data))


def test_predicate_register_indices(h: ModuleType, qemu: Path) -> str:
    snapshot = h.run_program(qemu, predicate_register_program(h), compact_loader=True)
    failures = [f"codeword{bit}=0x{snapshot.gr[8 + bit]:016x}" for bit, expected in enumerate(PR_CODEWORDS) if snapshot.gr[8 + bit] != expected]
    if failures:
        raise AssertionError("PR codeword mismatch: " + ", ".join(failures))
    if snapshot.pr != PR_CODEWORDS[-1]:
        raise AssertionError("final PR image differs from the sixth codeword")
    return "six independent bit-index codewords distinguish p1-p63 while preserving architectural p0=true"


def branch_register_program(h: ModuleType):
    bundles = []
    address = 0x10
    for register, value in enumerate(BR_VALUES):
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.adds(2, value, 0), h.nop_i()))
        address += 0x10
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.mov_grbr(register, 2), h.nop_i()))
        address += 0x10
    for register in range(8):
        bundles.append(h.Bundle(address, 0x01, h.nop_m(), h.mov_brgr(8 + register, register), h.nop_i()))
        address += 0x10
    bundles.append(h.spin_bundle(address))
    return h.Program("complete BR index and anti-alias matrix", tuple(bundles), address)


def test_branch_register_indices(h: ModuleType, qemu: Path) -> str:
    snapshot = h.run_program(qemu, branch_register_program(h), compact_loader=True)
    if snapshot.br != BR_VALUES:
        raise AssertionError(f"BR final image expected {BR_VALUES!r}, got {snapshot.br!r}")
    failures = [f"b{register}->r{8 + register}=0x{snapshot.gr[8 + register]:x}" for register, expected in enumerate(BR_VALUES) if snapshot.gr[8 + register] != expected]
    if failures:
        raise AssertionError("BR round-trip mismatch: " + ", ".join(failures))
    return "unique values round-trip through every b0-b7 destination and source encoding"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--qemu", type=Path)
    parser.add_argument("--harness", type=Path)
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    root = args.source_root.resolve()
    contract = validate_contract(root)
    if args.self_check:
        print("IA-64 register runtime contract passed: " + contract)
        return 0
    if args.qemu is None or args.harness is None:
        parser.error("--qemu and --harness are required unless --self-check is used")
    harness = load_module(args.harness, "_ia64_register_tcg_harness")
    floating = load_module(root / "tests/unit/test-ia64-fp-tcg.py", "_ia64_register_tcg_fp")
    tests: tuple[tuple[str, Callable[[], str]], ...] = (
        ("complete GR index space", lambda: test_general_register_indices(harness, args.qemu.resolve())),
        ("complete FR index space", lambda: test_floating_register_indices(harness, floating, args.qemu.resolve())),
        ("complete PR index space", lambda: test_predicate_register_indices(harness, args.qemu.resolve())),
        ("complete BR index space", lambda: test_branch_register_indices(harness, args.qemu.resolve())),
    )
    print("TAP version 13")
    print(f"1..{len(tests)}")
    failures = 0
    for number, (name, function) in enumerate(tests, 1):
        try:
            detail = function()
            print(f"ok {number} - {name}")
            print("# " + detail)
        except Exception as exc:
            failures += 1
            print(f"not ok {number} - {name}")
            print("# " + str(exc).replace("\n", "\n# "))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
