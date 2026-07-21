#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent no-OS index, rename, and bank matrices for IA-64 registers."""

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
PSR_BN = 1 << 44
GR_VALUES = tuple(range(1, 128))
FR_INDICES = tuple(range(2, 128))
GR_ROTATING_SIZES = tuple(range(8, 97, 8))
FR_ROTATING_INDICES = tuple(range(32, 128))
PR_ROTATING_INDICES = tuple(range(16, 64))
PR_CODEWORDS = tuple(
    1 | sum(((register >> bit) & 1) << register for register in range(1, 64))
    for bit in range(6)
)
BR_VALUES = tuple(0x100 + register for register in range(8))
AR_IGNORED_INDICES = frozenset((*range(48, 64), *range(112, 128)))
AR_M_INDICES = frozenset((
    *range(0, 8), *range(16, 20), 21, *range(24, 31), 32, 36, 40, 44,
))
AR_I_INDICES = frozenset((64, 65, 66))
AR_RESERVED_INDICES = frozenset(range(128)) - (
    AR_IGNORED_INDICES | AR_M_INDICES | AR_I_INDICES
)


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
    expected_groups = {
        "REG-005-GR-INDEX-SPACE": ("cpu.register.gr.all-indices", ["cpu.register.gr.0"]),
        "REG-006-FR-INDEX-SPACE": ("cpu.register.fr.all-indices", ["cpu.register.fr.0", "cpu.register.fr.1"]),
        "REG-006-PR-INDEX-SPACE": ("cpu.register.pr.all-indices", ["cpu.register.pr.0"]),
        "REG-006-BR-INDEX-SPACE": ("cpu.register.br.all-indices", []),
        "REG-006-AR-INDEX-SPACE": ("cpu.register.ar.all-indices", []),
        "REG-007-AR-ACCESS-CLASSES": ("cpu.register.ar.all-indices", []),
    }
    expected_rows = {
        "REG-003-CPUID-RUC-AR45": ["cpu.register.ar.45", "cpu.register.cpuid.4"],
        "REG-009-GR-BANK-SWITCH": ["cpu.register.gr.bank-switch"],
        "REG-010-FR-ROTATION": ["cpu.register.rotation.fr"],
        "REG-010-GR-ROTATION": ["cpu.register.rotation.gr"],
        "REG-010-PR-ROTATION": ["cpu.register.rotation.pr"],
    }
    if document.get("schema") != "vibtanium.ia64.register-semantic-tranche" or document.get("schema_version") != 1:
        raise AssertionError("register tranche schema/version drift")
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != 11:
        raise AssertionError("register tranche must contain eleven cases")
    for case in cases:
        row = case.get("normative_row")
        if row in expected_groups:
            group, exclusions = expected_groups[row]
            selector = case.get("implementation_selector")
            if selector != {
                "coverage_group": group,
                "exclude_rows": exclusions,
            }:
                raise AssertionError(f"{row}: implementation selector drift")
        elif row in expected_rows:
            if case.get("implementation_rows") != expected_rows[row]:
                raise AssertionError(f"{row}: implementation row drift")
        else:
            raise AssertionError(f"unexpected register tranche row: {row!r}")
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
    if (AR_IGNORED_INDICES | AR_M_INDICES | AR_I_INDICES |
            AR_RESERVED_INDICES) != frozenset(range(128)):
        raise AssertionError("AR selector classes do not cover ar0-ar127")
    if sum(map(len, (
        AR_IGNORED_INDICES, AR_M_INDICES, AR_I_INDICES,
        AR_RESERVED_INDICES,
    ))) != 128:
        raise AssertionError("AR selector classes overlap")
    if GR_ROTATING_SIZES != tuple(range(8, 97, 8)):
        raise AssertionError("GR rotating-size matrix drift")
    rotating_signatures = {
        register: tuple((word >> register) & 1 for word in PR_CODEWORDS)
        for register in PR_ROTATING_INDICES
    }
    if len(set(rotating_signatures.values())) != 48:
        raise AssertionError("rotating predicate codewords are not unique")
    return (
        "complete GR/FR/PR/BR indices, 12 GR rotating sizes, 96 FR bases, "
        "48 PR bases, all 128 AR selectors in both units, and "
        "interruption/RFI bank transitions"
    )


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


def append_failure_branch(h: ModuleType, bundles: list[object],
                          address: int, failure: int,
                          predicate: int = 7) -> int:
    bundles.append(h.Bundle(
        address, 0x11, h.nop_m(), h.nop_i(),
        h.br_cond(address, failure, qp=predicate),
    ))
    return address + 0x10


def append_gr_check(h: ModuleType, bundles: list[object], address: int,
                    register: int, expected: int, failure: int) -> int:
    bundles.append(h.Bundle(
        address, 0x01, h.nop_m(),
        h.cmp_imm(6, 7, expected, register, "eq"), h.nop_i(),
    ))
    return append_failure_branch(h, bundles, address + 0x10, failure)


def append_tnat_check(h: ModuleType, bundles: list[object], address: int,
                      register: int, expected: bool, failure: int) -> int:
    bundles.append(h.Bundle(
        address, 0x01, h.nop_m(),
        h.predicate_test(
            "tnat", 6, 7, relation="z", update="normal", r3=register
        ),
        h.nop_i(),
    ))
    # tnat.z sets p7 for NaT and p6 for ordinary data.
    fail_predicate = 6 if expected else 7
    return append_failure_branch(
        h, bundles, address + 0x10, failure, fail_predicate
    )


def append_gr_pair_check(h: ModuleType, bundles: list[object], address: int,
                         left: int, right: int, failure: int) -> int:
    bundles.append(h.Bundle(
        address, 0x01, h.nop_m(),
        h.cmp_rr(6, 7, left, right, "eq"), h.nop_i(),
    ))
    return append_failure_branch(h, bundles, address + 0x10, failure)


def finish_checked_program(h: ModuleType, name: str, bundles: list[object],
                           address: int, *, failure: int = 0x10000,
                           terminal: int = 0x10030,
                           data: tuple[object, ...] = (), entry: int = 0x10):
    if address >= failure or failure + 0x20 >= terminal:
        raise AssertionError("checked-program control addresses overlap")
    bundles.append(h.Bundle(
        address, 0x01, h.nop_m(), h.adds(14, 1, 0), h.nop_i()
    ))
    address += 0x10
    bundles.append(h.Bundle(
        address, 0x11, h.nop_m(), h.nop_i(),
        h.br_cond(address, terminal),
    ))
    bundles.append(h.Bundle(
        failure, 0x01, h.nop_m(), h.adds(14, 0, 0), h.nop_i()
    ))
    bundles.append(h.Bundle(
        failure + 0x10, 0x11, h.nop_m(), h.nop_i(),
        h.br_cond(failure + 0x10, terminal),
    ))
    bundles.append(h.spin_bundle(terminal))
    for word in data:
        data_start = word.address
        data_end = data_start + word.size
        if any(
            bundle.address < data_end
            and data_start < bundle.address + 0x10
            for bundle in bundles
        ):
            raise AssertionError(
                f"{name}: data at 0x{data_start:x} overlaps generated code"
            )
    return h.Program(name, tuple(bundles), terminal, data, entry)


def ar_selector_is_legal(unit: str, selector: int) -> bool:
    if selector in AR_IGNORED_INDICES:
        return True
    if unit == "M":
        return selector in AR_M_INDICES
    if unit == "I":
        return selector in AR_I_INDICES
    raise AssertionError(f"unknown AR execution unit {unit!r}")


def application_register_selector_program(h: ModuleType,
                                          system: ModuleType, unit: str,
                                          selectors: Sequence[int],
                                          forms: Sequence[str] = (
                                              "write", "false-write",
                                              "false-read", "read",
                                          )):
    failure = 0x70000
    terminal = 0x70030
    entry = 0x10000
    bundles: list[object] = []
    address = entry

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> int:
        nonlocal address
        result = address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10
        return result

    def emit_movl(register: int, value: int) -> int:
        nonlocal address
        result = address
        bundles.append(system.movl_bundle(h, address, register, value))
        address += 0x10
        return result

    def raw_access(unit: str, selector: int, write: bool,
                   predicate: int) -> int:
        if unit == "M":
            return (h.mov_m_grar(selector, 29, qp=predicate) if write else
                    h.mov_m_argr(30, selector, qp=predicate))
        return (h.mov_i_grar(selector, 29, qp=predicate) if write else
                h.mov_argr(30, selector, qp=predicate))

    def append_access(unit: str, selector: int, write: bool,
                      qualified: bool, expect_fault: bool,
                      source: int = 0,
                      expected_read: int | None = None) -> None:
        nonlocal address
        # Two MOVL bundles and three setup bundles precede the access.  The
        # handler independently checks the saved IIP and complete ISR image.
        access_ip = address + 0x50
        emit_movl(21, access_ip)
        emit_movl(24, (0 if unit == "M" else 1 << h.IA64_ISR_EI_SHIFT))
        diagnostic = (
            (selector << 4) | (int(unit == "I") << 3) |
            (int(write) << 2) | (int(qualified) << 1) |
            int(expect_fault)
        )
        emit(0x01, h.nop_m(), h.adds(8, selector, 0),
             h.adds(9, diagnostic, 0))
        emit(0x01, h.nop_m(), h.adds(20, 0, 0),
             h.adds(29, source, 0))
        predicate_setup = h.cmp_rr(
            1, 2, 0, 0, "eq" if qualified else "lt"
        )
        emit(0x01, h.nop_m(), h.adds(30, 0x55, 0), predicate_setup)
        actual_ip = address
        bundles.append(system.raw_bundle(
            h, address, unit,
            raw_access(unit, selector, write, predicate=1),
        ))
        address += 0x10
        if actual_ip != access_ip:
            raise AssertionError("AR access address accounting drift")
        address = append_gr_check(
            h, bundles, address, 20, int(expect_fault), failure
        )
        if not write:
            if expect_fault or not qualified:
                address = append_gr_check(
                    h, bundles, address, 30, 0x55, failure
                )
            elif expected_read is not None:
                address = append_gr_check(
                    h, bundles, address, 30, expected_read, failure
                )

    emit(0x01, h.ssm(h.IA64_PSR_IC), h.nop_i(), h.nop_i())
    emit(0x01, h.srlz_i(), h.nop_i(), h.nop_i())
    emit(0x01, h.nop_m(), h.adds(3, 4, 0), h.nop_i())
    bundles.append(system.raw_bundle(
        h, address, "M", system.m_system(0x17, r1=4, r2=0, r3=3)
    ))
    address += 0x10
    selector_tuple = tuple(selectors)
    form_set = frozenset(forms)
    if unit not in ("M", "I") or not selector_tuple:
        raise AssertionError("invalid AR selector shard")
    if not form_set or not form_set <= {
        "write", "false-write", "false-read", "read",
    }:
        raise AssertionError("invalid AR selector form shard")
    for selector in selector_tuple:
        legal = ar_selector_is_legal(unit, selector)
        write_fault = not legal or selector == 17
        read_fault = not legal

        # Zero is legal for every writable defined AR and gives an exact
        # readback oracle for all but the clock-backed ITC.
        if "write" in form_set:
            append_access(
                unit, selector, True, True, write_fault, source=0
            )
        # Every selector/form is also exercised false-qualified with a
        # nonzero source and poison destination.
        if "false-write" in form_set:
            append_access(
                unit, selector, True, False, False, source=0x5a
            )
        if "false-read" in form_set:
            append_access(
                unit, selector, False, False, False
            )
        expected_read = 0 if legal and selector != 44 else None
        if "read" in form_set:
            append_access(
                unit, selector, False, True, read_fault,
                expected_read=expected_read,
            )

    handler = h.IA64_GENERAL_EXCEPTION_VECTOR
    bundles.append(system.raw_bundle(
        h, handler, "M", system.m_system(0x24, r1=22, r3=19)
    ))
    handler = append_gr_pair_check(
        h, bundles, handler + 0x10, 22, 21, failure
    )
    bundles.append(system.raw_bundle(
        h, handler, "M", system.m_system(0x24, r1=23, r3=17)
    ))
    handler = append_gr_pair_check(
        h, bundles, handler + 0x10, 23, 24, failure
    )
    bundles.append(h.Bundle(
        handler, 0x01, h.nop_m(), h.adds(20, 1, 0),
        h.cmp_rr(1, 2, 0, 0, "lt"),
    ))
    handler += 0x10
    bundles.append(h.Bundle(
        handler, 0x11, h.nop_m(), h.nop_i(), h.rfi()
    ))

    return finish_checked_program(
        h,
        "AR {} selector shard {}-{} {}".format(
            unit, selector_tuple[0], selector_tuple[-1],
            "+".join(forms),
        ),
        bundles,
        address,
        failure=failure,
        terminal=terminal,
        entry=entry,
    )


def test_application_register_selectors(h: ModuleType, system: ModuleType,
                                        qemu: Path) -> str:
    for unit in ("M", "I"):
        for first in range(0, 128, 32):
            selectors = range(first, first + 32)
            forms = ("write", "false-write", "false-read", "read")
            label = (
                f"AR {unit} selectors {first}-{first + 31} "
                f"{'+'.join(forms)}"
            )
            try:
                snapshot = h.run_program(
                    qemu,
                    application_register_selector_program(
                        h, system, unit, selectors, forms
                    ),
                    compact_loader=True,
                    preserve_fault_slot=True,
                )
            except Exception as exc:
                raise AssertionError(f"{label}: {exc}") from exc
            if snapshot.gr[14] != 1:
                raise AssertionError(
                    f"{label} failed: marker={snapshot.gr[14]} "
                    f"selector={snapshot.gr[8]} "
                    f"form=0x{snapshot.gr[9]:x} ip=0x{snapshot.ip:x} "
                    f"expected-iip=0x{snapshot.gr[21]:x} "
                    f"actual-iip=0x{snapshot.cr_iip:x} "
                    f"expected-isr=0x{snapshot.gr[24]:x} "
                    f"actual-isr=0x{snapshot.cr_isr:x} "
                    f"exception={snapshot.exception_kind}"
                )
            if snapshot.gr[4] & (1 << 3):
                raise AssertionError(
                    "CPUID[4].ru advertises RUC but the selected AR45 "
                    "matrix is the reserved-feature profile"
                )
    return (
        "all 128 AR selectors pass enabled and false-qualified M/I read/write "
        "classification, exact Illegal Operation restart state, ignored "
        "zero/discard behavior, and BSP read-only behavior"
    )


def general_register_rotation_program(h: ModuleType, size: int):
    failure = 0x10000
    bundles: list[object] = []
    address = 0x10

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> int:
        nonlocal address
        result = address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10
        return result

    emit(0x01, h.alloc(31, 96, 96, size // 8), h.nop_i(), h.nop_i())
    # Initialize the entire current frame so each SOR case also proves that
    # stacked registers above the selected rotating region remain unchanged.
    for offset in range(96):
        emit(0x01, h.nop_m(), h.adds(32 + offset, offset + 1, 0), h.nop_i())
    # The spill/fill UNAT selector is address bits 8:3.  Address 0x1800 is
    # outside generated code and selects bit zero, matching the AR.UNAT seed.
    emit(0x01, h.nop_m(), h.adds(8, 1, 0), h.adds(9, 0x1800, 0))
    emit(0x01, h.mov_m_grar(36, 8), h.nop_i(), h.nop_i())
    emit(0x01, h.ld8_fill(32, 9), h.nop_i(), h.nop_i())
    emit(0x03, h.nop_m(), h.cmp_rr(6, 7, 0, 0, "eq"), h.nop_i())
    branch_ip = address
    emit(0x11, h.nop_m(), h.nop_i(),
         h.br_loop("wtop", branch_ip, branch_ip + 0x10, qp=6))

    address = append_tnat_check(h, bundles, address, 32, False, failure)
    address = append_tnat_check(h, bundles, address, 33, True, failure)
    for offset in range(96):
        register = 32 + offset
        if register == 33:
            continue
        if offset < size:
            expected = size if offset == 0 else offset
        else:
            expected = offset + 1
        address = append_gr_check(
            h, bundles, address, register, expected, failure
        )
    return finish_checked_program(
        h,
        "GR one-position rotation SOR={}".format(size),
        bundles,
        address,
        data=(h.DataWord(0x1800, 1, 8),),
    )


def test_general_register_rotation(h: ModuleType, qemu: Path) -> str:
    for size in GR_ROTATING_SIZES:
        program = general_register_rotation_program(h, size)
        snapshot = h.run_program(qemu, program, compact_loader=True)
        if snapshot.gr[14] != 1:
            raise AssertionError(
                f"SOR={size} guest rotation check failed: "
                f"CFM=0x{snapshot.cfm:x}, GR32..={snapshot.gr[32:32 + size]!r}, "
                f"NaT=0x{snapshot.nat_low:x}"
            )
        expected_rotating = tuple(
            size if offset == 0 else offset for offset in range(size)
        )
        expected_values = expected_rotating + tuple(range(size + 1, 97))
        actual_values = snapshot.gr[32:128]
        if actual_values != expected_values:
            raise AssertionError(
                f"SOR={size} logical GR image mismatch: {actual_values!r}"
            )
        expected_cfm = (
            96 | (96 << 7) | ((size // 8) << 14)
            | ((size - 1) << 18) | (95 << 25) | (47 << 32)
        )
        if snapshot.cfm != expected_cfm:
            raise AssertionError(
                f"SOR={size} expected CFM=0x{expected_cfm:x}, "
                f"got 0x{snapshot.cfm:x}"
            )
    return (
        "all 12 legal SOR sizes rotate every value one position with wrap, "
        "carry the r32 NaT to r33, and publish exact RRBs"
    )


def append_fr_check(h: ModuleType, fp: ModuleType, bundles: list[object],
                    address: int, register: int, expected: int,
                    failure: int) -> int:
    bundles.append(h.Bundle(
        address, 0x01, fp.raw_getf("sig", 3, register),
        h.nop_i(), h.nop_i(),
    ))
    return append_gr_check(h, bundles, address + 0x10, 3, expected, failure)


def floating_register_rotation_program(h: ModuleType, fp: ModuleType):
    failure = 0x10000
    bundles: list[object] = []
    address = 0x10

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> int:
        nonlocal address
        result = address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10
        return result

    emit(0x01, h.rsm(PSR_DFL | PSR_DFH), h.nop_i(), h.nop_i())
    for offset, register in enumerate(FR_ROTATING_INDICES):
        emit(0x01, h.nop_m(), h.adds(2, offset + 1, 0), h.nop_i())
        emit(0x01, fp.raw_setf("sig", register, 2), h.nop_i(), h.nop_i())

    for rotation in range(1, 97):
        emit(0x03, h.nop_m(), h.cmp_rr(6, 7, 0, 0, "eq"), h.nop_i())
        branch_ip = address
        emit(0x11, h.nop_m(), h.nop_i(),
             h.br_loop("wtop", branch_ip, branch_ip + 0x10, qp=6))
        indices = range(96) if rotation in (1, 96) else (0, 95)
        for offset in indices:
            expected = ((offset - rotation) % 96) + 1
            address = append_fr_check(
                h, fp, bundles, address, 32 + offset, expected, failure
            )
    for register in range(2, 32):
        address = append_fr_check(
            h, fp, bundles, address, register, 0, failure
        )
    return finish_checked_program(
        h, "FR complete rotating-base matrix", bundles, address
    )


def test_floating_register_rotation(h: ModuleType, fp: ModuleType,
                                    qemu: Path) -> str:
    program = floating_register_rotation_program(h, fp)
    snapshot = h.run_program(qemu, program, compact_loader=True)
    if snapshot.gr[14] != 1:
        raise AssertionError("FR rotating-base guest matrix failed")
    if snapshot.cfm != 0:
        raise AssertionError(
            f"96 FR rotations did not wrap every RRB: CFM=0x{snapshot.cfm:x}"
        )
    return (
        "unique f32-f127 values pass full base-95/base-0 images and both "
        "boundary reads at every one of 96 RRB.FR positions"
    )


def append_pr_check(h: ModuleType, bundles: list[object], address: int,
                    register: int, expected: int, failure: int) -> int:
    bundles.append(h.Bundle(
        address, 0x01, h.nop_m(), h.adds(3, 0, 0), h.nop_i()
    ))
    address += 0x10
    bundles.append(h.Bundle(
        address, 0x01, h.nop_m(),
        h.adds(3, 1, 0, qp=register), h.nop_i(),
    ))
    return append_gr_check(h, bundles, address + 0x10, 3, expected, failure)


def predicate_register_rotation_program(h: ModuleType, system: ModuleType,
                                        word: int, number: int):
    failure = 0x10000
    bundles: list[object] = []
    address = 0x10

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> int:
        nonlocal address
        result = address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10
        return result

    bundles.append(system.movl_bundle(h, address, 3, word))
    address += 0x10
    emit(0x01, h.nop_m(), h.mov_grpr(3, 0x10000), h.nop_i())
    for rotation in range(1, 49):
        emit(0x03, h.nop_m(), h.cmp_rr(6, 7, 0, 0, "eq"), h.nop_i())
        branch_ip = address
        emit(0x11, h.nop_m(), h.nop_i(),
             h.br_loop("wtop", branch_ip, branch_ip + 0x10, qp=6))
        offsets = range(48) if rotation in (1, 48) else (0, 47)
        for offset in offsets:
            # WTOP first writes false to the old logical p63 and then
            # rotates.  The injected false appears at p16; surviving values
            # advance toward p63 without wrapping the overwritten endpoint.
            expected = (
                0 if offset < rotation
                else (word >> (16 + offset - rotation)) & 1
            )
            address = append_pr_check(
                h, bundles, address, 16 + offset, expected, failure
            )
    return finish_checked_program(
        h,
        "PR rotating-base codeword {}".format(number),
        bundles,
        address,
    )


def test_predicate_register_rotation(h: ModuleType, system: ModuleType,
                                     qemu: Path) -> str:
    high_mask = ((1 << 64) - 1) ^ ((1 << 16) - 1)
    for number, word in enumerate(PR_CODEWORDS):
        program = predicate_register_rotation_program(h, system, word, number)
        snapshot = h.run_program(qemu, program, compact_loader=True)
        if snapshot.gr[14] != 1:
            raise AssertionError(
                f"PR codeword {number} rotation failed: "
                f"CFM=0x{snapshot.cfm:x}, PR=0x{snapshot.pr:016x}"
            )
        expected_cfm = 48 << 25
        if snapshot.cfm != expected_cfm:
            raise AssertionError(
                f"PR codeword {number} expected CFM=0x{expected_cfm:x}, "
                f"got 0x{snapshot.cfm:x}"
            )
        if snapshot.pr & high_mask:
            raise AssertionError(
                f"PR codeword {number} did not complete the zero-fill cycle"
            )
        if snapshot.pr & 0xffff != (1 | (1 << 6)):
            raise AssertionError(
                f"PR codeword {number} changed a static predicate: "
                f"PR=0x{snapshot.pr:016x}"
            )
    return (
        "six unique codewords prove the complete one-step p16-p63 shift and "
        "both logical boundaries through all 48 zero-fill/RRB.PR positions"
    )


def bank_switch_program(h: ModuleType, system: ModuleType):
    failure = 0x6200
    terminal = 0x6230
    bundles: list[object] = []
    address = 0x10

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> int:
        nonlocal address
        result = address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10
        return result

    for register in range(17, 32):
        emit(0x01, h.nop_m(), h.adds(register, register, 0), h.nop_i())
    emit(0x01, h.nop_m(), h.adds(8, 1, 0), h.adds(9, 0x1000, 0))
    emit(0x01, h.mov_m_grar(36, 8), h.nop_i(), h.nop_i())
    emit(0x01, h.ld8_fill(16, 9), h.nop_i(), h.nop_i())
    bundles.append(system.raw_bundle(
        h, address, "B", system.encode_system_opcode("IA64_OP_BSW1")
    ))
    address += 0x10
    for register in range(16, 31):
        emit(0x01, h.nop_m(), h.adds(register, register + 32, 0), h.nop_i())
    emit(0x01, h.nop_m(), h.adds(8, 2, 0), h.adds(9, 0x1008, 0))
    emit(0x01, h.mov_m_grar(36, 8), h.nop_i(), h.nop_i())
    emit(0x01, h.ld8_fill(31, 9), h.nop_i(), h.nop_i())
    emit(0x03, h.nop_m(), h.cmp_rr(1, 2, 0, 0, "eq"), h.nop_i())
    emit(0x01, h.ssm(h.IA64_PSR_IC), h.nop_i(), h.nop_i())
    emit(0x01, h.srlz_i(), h.nop_i(), h.nop_i())
    fault_ip = address
    emit(0x01, h.nop_m(), h.cmp_rr(12, 12, 0, 0, "eq", qp=1),
         h.adds(13, 0x55, 0))

    for register in range(16, 31):
        address = append_gr_check(
            h, bundles, address, register, register + 32, failure
        )
    address = append_tnat_check(h, bundles, address, 30, False, failure)
    address = append_tnat_check(h, bundles, address, 31, True, failure)
    bundles.append(system.raw_bundle(
        h, address, "M", system.m_system(0x25, r1=4)
    ))
    address += 0x10
    bundles.append(system.raw_bundle(
        h, address, "B", system.encode_system_opcode("IA64_OP_BSW0")
    ))
    address += 0x10
    for register in range(17, 32):
        address = append_gr_check(
            h, bundles, address, register, register, failure
        )
    address = append_tnat_check(h, bundles, address, 16, True, failure)
    address = append_tnat_check(h, bundles, address, 17, False, failure)
    bundles.append(system.raw_bundle(
        h, address, "M", system.m_system(0x25, r1=5)
    ))
    address += 0x10
    bundles.append(h.Bundle(
        address, 0x01, h.nop_m(), h.adds(14, 1, 0), h.nop_i()
    ))
    address += 0x10
    bundles.append(h.Bundle(
        address, 0x11, h.nop_m(), h.nop_i(), h.br_cond(address, terminal)
    ))

    handler = h.IA64_GENERAL_EXCEPTION_VECTOR
    bundles.append(system.raw_bundle(
        h, handler, "M", system.m_system(0x25, r1=3)
    ))
    handler += 0x10
    bundles.append(system.raw_bundle(
        h, handler, "M",
        system.m_system(0x24, r1=10, r3=system.CR_IPSR),
    ))
    handler += 0x10
    bundles.append(h.Bundle(
        handler, 0x03, h.nop_m(),
        h.cmp_rr(1, 2, 0, 0, "lt"), h.nop_i(),
    ))
    handler += 0x10
    for register in range(17, 32):
        handler = append_gr_check(
            h, bundles, handler, register, register, failure
        )
    handler = append_tnat_check(h, bundles, handler, 16, True, failure)
    handler = append_tnat_check(h, bundles, handler, 17, False, failure)
    bundles.append(h.Bundle(
        handler, 0x11, h.nop_m(), h.nop_i(), h.rfi()
    ))

    bundles.append(h.Bundle(
        failure, 0x01, h.nop_m(), h.adds(14, 0, 0), h.nop_i()
    ))
    bundles.append(h.Bundle(
        failure + 0x10, 0x11, h.nop_m(), h.nop_i(),
        h.br_cond(failure + 0x10, terminal),
    ))
    bundles.append(h.spin_bundle(terminal))
    return h.Program(
        "interruption and RFI GR bank transition matrix",
        tuple(bundles),
        terminal,
        (h.DataWord(0x1000, 16, 8), h.DataWord(0x1008, 63, 8)),
    ), fault_ip


def test_interruption_bank_switch(h: ModuleType, system: ModuleType,
                                  qemu: Path) -> str:
    program, fault_ip = bank_switch_program(h, system)
    snapshot = h.run_program(
        qemu,
        program,
        compact_loader=True,
        preserve_fault_slot=True,
    )
    if snapshot.gr[14] != 1 or snapshot.gr[13] != 0x55:
        raise AssertionError(
            "bank transition matrix failed or RFI did not resume the suffix"
        )
    if snapshot.gr[3] & PSR_BN:
        raise AssertionError("interruption handler did not select bank zero")
    if not (snapshot.gr[10] & PSR_BN):
        raise AssertionError("collected IPSR did not preserve bank one")
    if not (snapshot.gr[4] & PSR_BN) or snapshot.gr[5] & PSR_BN:
        raise AssertionError("RFI/BSW did not expose bank one then bank zero")
    expected_bank0 = tuple(range(16, 32))
    if snapshot.gr[16:32] != expected_bank0:
        raise AssertionError(
            f"final bank-zero image mismatch: {snapshot.gr[16:32]!r}"
        )
    if (snapshot.nat_low & (((1 << 16) | (1 << 31)))) != (1 << 16):
        raise AssertionError("bank-zero NaT state was not preserved")
    if snapshot.gr[0] != 0 or any(snapshot.gr[32:128]):
        raise AssertionError("bank transition changed a nonbanked GR")
    if snapshot.cr_iip != fault_ip:
        raise AssertionError(
            f"collected IIP expected 0x{fault_ip:x}, got 0x{snapshot.cr_iip:x}"
        )
    return (
        "an enabled precise fault selects bank zero, preserves both value/NaT "
        "images, and RFI restores IPSR.bn=1 before an explicit BSW.0"
    )


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
    system = load_module(
        root / "tests/unit/test-ia64-system-tcg.py",
        "_ia64_register_tcg_system",
    )
    tests: tuple[tuple[str, Callable[[], str]], ...] = (
        ("complete GR index space", lambda: test_general_register_indices(harness, args.qemu.resolve())),
        ("complete FR index space", lambda: test_floating_register_indices(harness, floating, args.qemu.resolve())),
        ("complete PR index space", lambda: test_predicate_register_indices(harness, args.qemu.resolve())),
        ("complete BR index space", lambda: test_branch_register_indices(harness, args.qemu.resolve())),
        ("complete GR rotation", lambda: test_general_register_rotation(harness, args.qemu.resolve())),
        ("complete FR rotation", lambda: test_floating_register_rotation(harness, floating, args.qemu.resolve())),
        ("complete PR rotation", lambda: test_predicate_register_rotation(harness, system, args.qemu.resolve())),
        ("interruption and RFI GR banks", lambda: test_interruption_bank_switch(harness, system, args.qemu.resolve())),
        ("complete AR selector space", lambda: test_application_register_selectors(harness, system, args.qemu.resolve())),
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
