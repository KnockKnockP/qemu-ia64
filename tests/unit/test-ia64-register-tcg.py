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
U64_MASK = (1 << 64) - 1


def bit_mask(*bits_or_ranges: int | range) -> int:
    mask = 0
    for item in bits_or_ranges:
        if isinstance(item, range):
            for bit in item:
                mask |= 1 << bit
        else:
            mask |= 1 << item
    return mask


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
CR_DEFINED_INDICES = frozenset((
    0, 1, 2, 8, 16, 17, *range(19, 28),
    *range(64, 75), 80, 81,
))
CR_READ_ONLY_INDICES = frozenset((65, *range(68, 72)))
CR_INTERRUPTION_INDICES = frozenset((16, 17, *range(19, 28)))
CR_RESERVED_INDICES = frozenset(range(128)) - CR_DEFINED_INDICES
CR_WRITE_VALUES = {
    0: 0x2,
    1: 0x101,
    # Keep IVA at zero so every later precise-fault probe reaches the common
    # vector installed at the architectural 0x5400 offset.
    2: 0,
    8: 0x3c,
    16: 1 << 13,
    17: 0x11,
    19: 0x130,
    20: 0x140,
    21: 0x150,
    22: 0x160,
    23: 0x17,
    24: 0x18,
    25: 0x190,
    26: 0x1a0,
    27: 0x1b0,
    64: 0x400000,
    66: 0x10040,
    67: 0x67,
    72: 0x10048,
    73: 0x10049,
    74: 0x1004a,
    80: 0x10050,
    81: 0x10051,
}
CR_EXPECTED_READS = {
    **CR_WRITE_VALUES,
    65: 0x0f,
    68: 0,
    69: 0,
    70: 0,
    71: 0,
    67: 0,
}
CR_ALIAS_WRITE_VALUES = {**CR_WRITE_VALUES, 2: 0x10000}
CR_ALIAS_EXPECTED_READS = {
    **CR_ALIAS_WRITE_VALUES,
    65: 0x0f,
    68: 0,
    69: 0,
    70: 0,
    71: 0,
    67: 0,
}
CR_FIELD_WRITABLE_INDICES = frozenset(CR_WRITE_VALUES)
CR_LITERAL_RESERVED_MASKS = {
    0: bit_mask(range(3, 8), range(15, 64)),
    8: bit_mask(1, range(9, 15)),
    16: bit_mask(0, range(6, 13), 16, range(28, 32), range(46, 64)),
    17: bit_mask(range(24, 32), range(44, 64)),
    23: bit_mask(range(38, 63)),
    64: bit_mask(range(0, 16)),
    66: bit_mask(range(8, 16)),
    72: bit_mask(range(8, 12), range(13, 16)),
    73: bit_mask(range(8, 12), range(13, 16)),
    74: bit_mask(range(8, 12), range(13, 16)),
    80: bit_mask(11, 14),
    81: bit_mask(11, 14),
}
CR_LITERAL_IGNORED_MASKS = {
    2: bit_mask(range(0, 15)),
    25: bit_mask(0, 1),
    64: bit_mask(range(32, 64)),
    66: bit_mask(range(0, 4), range(17, 64)),
    67: U64_MASK,
    72: bit_mask(12, range(17, 64)),
    73: bit_mask(12, range(17, 64)),
    74: bit_mask(12, range(17, 64)),
    80: bit_mask(12, range(17, 64)),
    81: bit_mask(12, range(17, 64)),
}
CR_FIELD_BASELINES = {8: 15 << 2}
CR_CONDITIONAL_SINGLETON_BITS = {
    8: frozenset(range(2, 8)),
    80: frozenset(range(8, 11)),
    81: frozenset(range(8, 11)),
}
CR_FIELD_IMPLEMENTATION_ROWS = tuple(
    f"cpu.register.cr.{selector}"
    for selector in sorted(CR_FIELD_WRITABLE_INDICES)
)
CR_SYSTEM_FIELD_IMPLEMENTATION_ROWS = tuple(
    row for row in CR_FIELD_IMPLEMENTATION_ROWS
    if int(row.rsplit(".", 1)[1]) < 64
)
CR_LOCAL_FIELD_IMPLEMENTATION_ROWS = tuple(
    row for row in CR_FIELD_IMPLEMENTATION_ROWS
    if int(row.rsplit(".", 1)[1]) >= 64
)
AR_RSC_RESERVED_MASK = bit_mask(range(5, 16), range(30, 64))
AR_FPSR_LITERAL_RESERVED_MASK = bit_mask(12, range(58, 64))
AR_FPSR_PC_LSB_BITS = frozenset(8 + 13 * field for field in range(4))
AR_PFS_LITERAL_RESERVED_MASK = bit_mask(range(38, 52), range(58, 62))
AR_RSC_FIELD_IMPLEMENTATION_ROWS = ("cpu.register.ar.16",)
AR_BSPSTORE_RNAT_FIELD_IMPLEMENTATION_ROWS = (
    "cpu.register.ar.18", "cpu.register.ar.19",
)
AR_BSPSTORE_REBASE_IMPLEMENTATION_ROWS = (
    "cpu.register.ar.17", "cpu.register.ar.18",
)
AR_PLAIN_FIELD_IMPLEMENTATION_ROWS = (
    "cpu.register.ar.32", "cpu.register.ar.36",
    "cpu.register.ar.65", "cpu.register.ar.66",
)
AR_FPSR_FIELD_IMPLEMENTATION_ROWS = ("cpu.register.ar.40",)
AR_PFS_FIELD_IMPLEMENTATION_ROWS = ("cpu.register.ar.64",)
AR_CCV_EFFECT_IMPLEMENTATION_ROWS = (
    "cpu.opcode.ia64_op_cmpxchg1",
    "cpu.opcode.ia64_op_cmpxchg2",
    "cpu.opcode.ia64_op_cmpxchg4",
    "cpu.opcode.ia64_op_cmpxchg8",
    "cpu.register.ar.32",
)
AR_UNAT_EFFECT_IMPLEMENTATION_ROWS = (
    "cpu.opcode.ia64_op_ld8fill",
    "cpu.opcode.ia64_op_st8spill",
    "cpu.register.ar.36",
)
AR_PFS_CALL_EFFECT_IMPLEMENTATION_ROWS = (
    "cpu.opcode.ia64_op_br_call",
    "cpu.opcode.ia64_op_br_call_indirect",
    "cpu.opcode.ia64_op_brl_call",
    "cpu.register.ar.64",
    "cpu.register.ar.66",
    "cpu.register.scalar.cfm",
)
AR_PFS_RETURN_EFFECT_IMPLEMENTATION_ROWS = (
    "cpu.opcode.ia64_op_br_ret",
    "cpu.register.ar.64",
    "cpu.register.ar.66",
    "cpu.register.scalar.cfm",
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
        "REG-006-CR-INDEX-SPACE": ("cpu.register.cr.all-indices", []),
        "REG-007-CR-ACCESS-CLASSES": ("cpu.register.cr.all-indices", []),
    }
    expected_rows = {
        "REG-003-CPUID-RUC-AR45": ["cpu.register.ar.45", "cpu.register.cpuid.4"],
        "REG-009-GR-BANK-SWITCH": ["cpu.register.gr.bank-switch"],
        "REG-010-FR-ROTATION": ["cpu.register.rotation.fr"],
        "REG-010-GR-ROTATION": ["cpu.register.rotation.gr"],
        "REG-010-PR-ROTATION": ["cpu.register.rotation.pr"],
        "REG-007-CR-FIELD-SEMANTICS": list(
            CR_SYSTEM_FIELD_IMPLEMENTATION_ROWS
        ),
        "REG-007-LOCAL-CR-FIELD-SEMANTICS": list(
            CR_LOCAL_FIELD_IMPLEMENTATION_ROWS
        ),
        "REG-007-RSC-FIELD-SEMANTICS": list(
            AR_RSC_FIELD_IMPLEMENTATION_ROWS
        ),
        "REG-007-FPSR-FIELD-SEMANTICS": list(
            AR_FPSR_FIELD_IMPLEMENTATION_ROWS
        ),
        "REG-007-PFS-FIELD-SEMANTICS": list(
            AR_PFS_FIELD_IMPLEMENTATION_ROWS
        ),
        "REG-008-BSPSTORE-RNAT-FIELDS": list(
            AR_BSPSTORE_RNAT_FIELD_IMPLEMENTATION_ROWS
        ),
        "REG-008-BSPSTORE-BSP-REBASE-EFFECT": list(
            AR_BSPSTORE_REBASE_IMPLEMENTATION_ROWS
        ),
        "REG-008-PLAIN-AR-FIELDS": list(
            AR_PLAIN_FIELD_IMPLEMENTATION_ROWS
        ),
        "REG-008-CCV-CMPXCHG-EFFECT": list(
            AR_CCV_EFFECT_IMPLEMENTATION_ROWS
        ),
        "REG-008-UNAT-SPILL-FILL-EFFECT": list(
            AR_UNAT_EFFECT_IMPLEMENTATION_ROWS
        ),
        "REG-008-PFS-CALL-EFFECT": list(
            AR_PFS_CALL_EFFECT_IMPLEMENTATION_ROWS
        ),
        "REG-008-PFS-RETURN-EFFECT": list(
            AR_PFS_RETURN_EFFECT_IMPLEMENTATION_ROWS
        ),
    }
    expected_effect_probes = {
        "REG-008-BSPSTORE-BSP-REBASE-EFFECT": [
            "test_application_register_bspstore_rebase"
        ],
        "REG-008-PFS-CALL-EFFECT": ["test_typed_call_branches"],
        "REG-008-PFS-RETURN-EFFECT": ["test_typed_return_branches"],
    }
    if document.get("schema") != "vibtanium.ia64.register-semantic-tranche" or document.get("schema_version") != 1:
        raise AssertionError("register tranche schema/version drift")
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != 25:
        raise AssertionError("register tranche must contain twenty-five cases")
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
        if row in expected_effect_probes and case.get(
                "execution", {}).get("probes") != expected_effect_probes[row]:
            raise AssertionError(f"{row}: execution probe binding drift")
    full_source = (
        root / "tests/unit/test-ia64-full-tcg.py"
    ).read_text(encoding="utf-8")
    for probe in ("test_typed_call_branches", "test_typed_return_branches"):
        if f"def {probe}(" not in full_source:
            raise AssertionError(f"missing full-TCG PFS effect probe: {probe}")
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
    if (CR_DEFINED_INDICES | CR_RESERVED_INDICES) != frozenset(range(128)):
        raise AssertionError("CR selector classes do not cover cr0-cr127")
    if CR_DEFINED_INDICES & CR_RESERVED_INDICES:
        raise AssertionError("CR defined/reserved selector classes overlap")
    if not CR_READ_ONLY_INDICES < CR_DEFINED_INDICES:
        raise AssertionError("CR read-only selectors are not a defined subset")
    if not CR_INTERRUPTION_INDICES < CR_DEFINED_INDICES:
        raise AssertionError("CR interruption selectors are not a defined subset")
    if set(CR_WRITE_VALUES) != CR_DEFINED_INDICES - CR_READ_ONLY_INDICES:
        raise AssertionError("CR safe-write oracle does not cover every writable CR")
    if set(CR_EXPECTED_READS) != CR_DEFINED_INDICES:
        raise AssertionError("CR read oracle does not cover every defined CR")
    if (set(CR_ALIAS_WRITE_VALUES) !=
            CR_DEFINED_INDICES - CR_READ_ONLY_INDICES or
            set(CR_ALIAS_EXPECTED_READS) != CR_DEFINED_INDICES):
        raise AssertionError("CR anti-alias oracle does not cover its full file")
    if CR_FIELD_WRITABLE_INDICES != CR_DEFINED_INDICES - CR_READ_ONLY_INDICES:
        raise AssertionError("CR field oracle does not cover every writable CR")
    for selector in CR_FIELD_WRITABLE_INDICES:
        reserved = CR_LITERAL_RESERVED_MASKS.get(selector, 0)
        ignored = CR_LITERAL_IGNORED_MASKS.get(selector, 0)
        if reserved & ignored or (reserved | ignored) & ~U64_MASK:
            raise AssertionError(
                f"CR{selector} reserved/ignored bit partition is invalid"
            )
    if len(CR_FIELD_IMPLEMENTATION_ROWS) != 23:
        raise AssertionError("named writable CR inventory is not 23 registers")
    if (len(CR_SYSTEM_FIELD_IMPLEMENTATION_ROWS) != 15 or
            len(CR_LOCAL_FIELD_IMPLEMENTATION_ROWS) != 8):
        raise AssertionError("named writable CR architecture groups drifted")
    if AR_RSC_RESERVED_MASK != bit_mask(range(5, 16), range(30, 64)):
        raise AssertionError("RSC reserved-field oracle drifted")
    if AR_FPSR_LITERAL_RESERVED_MASK & sum(
            1 << bit for bit in AR_FPSR_PC_LSB_BITS):
        raise AssertionError("FPSR literal and encoded reserved sets overlap")
    if len(AR_PLAIN_FIELD_IMPLEMENTATION_ROWS) != 4:
        raise AssertionError("plain named-AR field group drifted")
    if (len(application_register_ccv_effect_cases()) != 20 or
            {case[0] for case in application_register_ccv_effect_cases()} !=
            {1, 2, 4, 8}):
        raise AssertionError("CCV/cmpxchg effect matrix drifted")
    if application_register_unat_expected_image() != 0x5555555555555555:
        raise AssertionError("UNAT selector effect matrix drifted")
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
        "48 PR bases, all 128 AR selectors in both units, all 128 CR "
        "selectors, interruption-access states, complete nine-register AR "
        "and named CR field partitions, all 64 BSPSTORE rebase offsets, "
        "exact PFS call/return metadata, CCV effects across twenty cmpxchg "
        "cases, all 64 UNAT spill/fill selectors, and "
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


def control_register_selector_program(h: ModuleType, system: ModuleType,
                                      selectors: Sequence[int]):
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

    def set_ic(enabled: bool) -> None:
        emit(
            0x01,
            h.ssm(h.IA64_PSR_IC) if enabled else h.rsm(h.IA64_PSR_IC),
            h.nop_i(), h.nop_i(),
        )
        emit(0x01, h.srlz_i(), h.nop_i(), h.nop_i())

    def append_access(selector: int, *, write: bool, qualified: bool,
                      ic_enabled: bool, expect_fault: bool,
                      form_code: int, source: int = 0,
                      expected_read: int | None = None) -> None:
        nonlocal address
        set_ic(ic_enabled)
        # Six setup bundles precede the M-slot access.  The vector verifies
        # the independently calculated saved IIP and full Illegal Operation
        # ISR image before nullifying the retry through p1.
        access_ip = address + 0x60
        emit_movl(21, access_ip)
        emit_movl(24, 0)
        diagnostic = (selector << 4) | form_code
        emit(0x01, h.nop_m(), h.adds(8, selector, 0),
             h.adds(9, diagnostic, 0))
        emit(0x01, h.nop_m(), h.adds(20, 0, 0), h.nop_i())
        emit_movl(29, source)
        predicate_setup = h.cmp_rr(
            1, 2, 0, 0, "eq" if qualified else "lt"
        )
        emit(0x01, h.nop_m(), h.adds(30, 0x55, 0), predicate_setup)
        actual_ip = address
        raw = (
            system.m_system(0x2C, r2=29, r3=selector, qp=1)
            if write else
            system.m_system(0x24, r1=30, r3=selector, qp=1)
        )
        bundles.append(system.raw_bundle(h, address, "M", raw))
        address += 0x10
        if actual_ip != access_ip:
            raise AssertionError("CR access address accounting drift")
        if write and qualified and not expect_fault:
            emit(0x01, h.srlz_d(), h.nop_i(), h.nop_i())
        address = append_gr_check(
            h, bundles, address, 20, int(expect_fault), failure
        )
        if not write:
            if expect_fault or not qualified:
                address = append_gr_check(
                    h, bundles, address, 30, 0x55, failure
                )
            elif expected_read is not None:
                emit_movl(28, expected_read)
                address = append_gr_pair_check(
                    h, bundles, address, 30, 28, failure
                )

    selector_tuple = tuple(selectors)
    if not selector_tuple:
        raise AssertionError("invalid CR selector shard")
    for selector in selector_tuple:
        defined = selector in CR_DEFINED_INDICES
        read_only = selector in CR_READ_ONLY_INDICES
        interruption = selector in CR_INTERRUPTION_INDICES

        if interruption:
            append_access(
                selector, write=True, qualified=True, ic_enabled=True,
                expect_fault=True, form_code=0x1, source=0,
            )
            append_access(
                selector, write=False, qualified=True, ic_enabled=True,
                expect_fault=True, form_code=0x2,
            )

        write_fault = not defined or read_only
        append_access(
            selector, write=True, qualified=True,
            ic_enabled=not interruption, expect_fault=write_fault,
            form_code=0x3, source=CR_WRITE_VALUES.get(selector, 0),
        )
        append_access(
            selector, write=True, qualified=False, ic_enabled=True,
            expect_fault=False, form_code=0x4, source=0x5a,
        )
        append_access(
            selector, write=False, qualified=False, ic_enabled=True,
            expect_fault=False, form_code=0x5,
        )
        append_access(
            selector, write=False, qualified=True,
            ic_enabled=not interruption, expect_fault=not defined,
            form_code=0x6,
            expected_read=CR_EXPECTED_READS.get(selector),
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
        "CR selector shard {}-{}".format(
            selector_tuple[0], selector_tuple[-1]
        ),
        bundles,
        address,
        failure=failure,
        terminal=terminal,
        entry=entry,
    )


def control_register_alias_program(h: ModuleType, system: ModuleType):
    failure = 0x70000
    terminal = 0x70030
    entry = 0x10000
    bundles: list[object] = []
    address = entry

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> None:
        nonlocal address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10

    def emit_movl(register: int, value: int) -> None:
        nonlocal address
        bundles.append(system.movl_bundle(h, address, register, value))
        address += 0x10

    def set_ic(enabled: bool) -> None:
        emit(
            0x01,
            h.ssm(h.IA64_PSR_IC) if enabled else h.rsm(h.IA64_PSR_IC),
            h.nop_i(), h.nop_i(),
        )
        emit(0x01, h.srlz_i(), h.nop_i(), h.nop_i())

    # No illegal access follows the IVA write in this program, so the
    # complete-file pass can use a nonzero aligned IVA label as well as
    # distinct safe values for every ordinary storage-backed writable CR.
    for selector in sorted(CR_ALIAS_WRITE_VALUES):
        set_ic(selector not in CR_INTERRUPTION_INDICES)
        emit(0x01, h.nop_m(), h.adds(8, selector, 0), h.adds(9, 1, 0))
        emit_movl(29, CR_ALIAS_WRITE_VALUES[selector])
        bundles.append(system.raw_bundle(
            h, address, "M",
            system.m_system(0x2C, r2=29, r3=selector),
        ))
        address += 0x10
        emit(0x01, h.srlz_d(), h.nop_i(), h.nop_i())

    for selector in sorted(CR_DEFINED_INDICES):
        set_ic(selector not in CR_INTERRUPTION_INDICES)
        emit(0x01, h.nop_m(), h.adds(8, selector, 0), h.adds(9, 2, 0))
        bundles.append(system.raw_bundle(
            h, address, "M",
            system.m_system(0x24, r1=30, r3=selector),
        ))
        address += 0x10
        emit_movl(28, CR_ALIAS_EXPECTED_READS[selector])
        address = append_gr_pair_check(
            h, bundles, address, 30, 28, failure
        )

    return finish_checked_program(
        h, "CR complete-file distinct-value anti-alias pass", bundles,
        address, failure=failure, terminal=terminal, entry=entry,
    )


def test_control_register_selectors(h: ModuleType, system: ModuleType,
                                    qemu: Path) -> str:
    combinations = 0
    for first in range(0, 128, 32):
        selectors = range(first, first + 32)
        label = f"CR selectors {first}-{first + 31}"
        try:
            snapshot = h.run_program(
                qemu,
                control_register_selector_program(h, system, selectors),
                compact_loader=True,
                preserve_fault_slot=True,
            )
        except Exception as exc:
            raise AssertionError(f"{label}: {exc}") from exc
        if snapshot.gr[14] != 1:
            raise AssertionError(
                f"{label} failed: marker={snapshot.gr[14]} "
                f"selector={snapshot.gr[8]} form=0x{snapshot.gr[9]:x} "
                f"ip=0x{snapshot.ip:x} expected-iip=0x{snapshot.gr[21]:x} "
                f"actual-iip=0x{snapshot.cr_iip:x} "
                f"expected-isr=0x{snapshot.gr[24]:x} "
                f"actual-isr=0x{snapshot.cr_isr:x} "
                f"exception={snapshot.exception_kind}"
            )
        combinations += 32 * 4
        combinations += 2 * len(
            CR_INTERRUPTION_INDICES & frozenset(selectors)
        )
    if combinations != 534:
        raise AssertionError(
            f"CR selector matrix covered {combinations}, expected 534 forms"
        )
    alias_snapshot = h.run_program(
        qemu,
        control_register_alias_program(h, system),
        compact_loader=True,
        preserve_fault_slot=True,
    )
    if alias_snapshot.gr[14] != 1:
        raise AssertionError(
            "CR full-file anti-alias pass failed: "
            f"selector={alias_snapshot.gr[8]} "
            f"phase={alias_snapshot.gr[9]} ip=0x{alias_snapshot.ip:x} "
            f"exception={alias_snapshot.exception_kind}"
        )
    return (
        "all 128 CR selectors pass 512 enabled/false-qualified read/write "
        "forms plus 22 PSR.ic restriction forms, including exact Illegal "
        "Operation restart, read-only IVR/IRR behavior, IIB0/IIB1, and a "
        "separate complete-file distinct-value anti-alias pass"
    )


def control_register_field_fault_cases() -> tuple[tuple[int, int, str], ...]:
    cases: list[tuple[int, int, str]] = []
    for selector in sorted(CR_FIELD_WRITABLE_INDICES):
        baseline = CR_FIELD_BASELINES.get(selector, 0)
        reserved = CR_LITERAL_RESERVED_MASKS.get(selector, 0)
        for bit in range(64):
            if reserved & (1 << bit):
                cases.append((
                    selector, baseline | (1 << bit),
                    f"CR{selector} reserved bit {bit}",
                ))
    cases.extend((
        (8, 0 << 2, "PTA size 0 below architectural minimum"),
        (8, 14 << 2, "PTA size 14 below architectural minimum"),
        (16, 3 << 41, "IPSR reserved RI encoding 3"),
        (17, 3 << 41, "ISR reserved EI encoding 3"),
        (23, (1 << 63) | 97, "IFS valid with SOF 97"),
        (23, (1 << 63) | (1 << 7), "IFS valid with SOL above SOF"),
        (23, (1 << 63) | (1 << 14), "IFS valid with SOR above SOF"),
        (23, (1 << 63) | 8 | (1 << 14) | (8 << 18),
         "IFS valid with RRB.GR outside SOR"),
        (23, (1 << 63) | (1 << 18),
         "IFS valid with nonzero RRB.GR and zero SOR"),
        (23, (1 << 63) | (96 << 25),
         "IFS valid with RRB.FR 96"),
        (23, (1 << 63) | (48 << 32),
         "IFS valid with RRB.PR 48"),
    ))
    for selector in (80, 81):
        for delivery_mode in (1, 3, 6):
            cases.append((
                selector, delivery_mode << 8,
                f"CR{selector} reserved delivery mode {delivery_mode}",
            ))
    return tuple(cases)


def control_register_field_legal_cases() -> tuple[
        tuple[int, int, int, str], ...]:
    cases: list[tuple[int, int, int, str]] = []
    for selector in sorted(CR_FIELD_WRITABLE_INDICES):
        baseline = CR_FIELD_BASELINES.get(selector, 0)
        reserved = CR_LITERAL_RESERVED_MASKS.get(selector, 0)
        ignored = CR_LITERAL_IGNORED_MASKS.get(selector, 0)
        conditional = CR_CONDITIONAL_SINGLETON_BITS.get(selector, frozenset())
        for bit in range(64):
            if reserved & (1 << bit) or bit in conditional:
                continue
            source = baseline | (1 << bit)
            expected = source & ~ignored & U64_MASK
            cases.append((
                selector, source, expected,
                f"CR{selector} bit {bit} preserved/ignored",
            ))

    for size in (15, 16, 31, 32, 52):
        value = size << 2
        cases.append((8, value, value, f"PTA short-format size {size}"))
    for size in (15, 16, 31, 32, 52, 61):
        value = (size << 2) | (1 << 8)
        cases.append((8, value, value, f"PTA long-format size {size}"))

    valid_ifs_max = (
        (1 << 63) | 96 | (96 << 7) | (12 << 14) |
        (95 << 18) | (95 << 25) | (47 << 32)
    )
    cases.extend((
        (23, 1 << 63, 1 << 63, "IFS valid empty frame"),
        (23, valid_ifs_max, valid_ifs_max, "IFS valid maximum frame"),
        (21, U64_MASK, U64_MASK,
         "ITIR selected checked-on-insert full-width value"),
    ))
    for selector in (80, 81):
        for delivery_mode in (0, 2, 4, 5, 7):
            value = (delivery_mode << 8) | 0x50
            cases.append((
                selector, value, value,
                f"CR{selector} legal delivery mode {delivery_mode}",
            ))
    return tuple(cases)


def control_register_field_program(h: ModuleType, system: ModuleType):
    failure = 0x70000
    terminal = 0x70030
    entry = 0x10000
    bundles: list[object] = []
    address = entry

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> None:
        nonlocal address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10

    def emit_movl(register: int, value: int) -> None:
        nonlocal address
        bundles.append(system.movl_bundle(h, address, register, value))
        address += 0x10

    emit(0x01, h.rsm(h.IA64_PSR_IC), h.nop_i(), h.nop_i())
    emit(0x01, h.srlz_i(), h.nop_i(), h.nop_i())

    # Predicate qualification precedes reserved-field validation.  The reset
    # DCR is zero, so the following poisoned write must leave it unchanged.
    emit(0x01, h.nop_m(), h.adds(8, 0, 0), h.adds(9, 0, 0))
    emit_movl(29, 1 << 3)
    emit(0x01, h.nop_m(), h.nop_i(), h.cmp_rr(1, 2, 0, 0, "lt"))
    bundles.append(system.raw_bundle(
        h, address, "M", system.m_system(0x2C, r2=29, r3=0, qp=1)
    ))
    address += 0x10
    bundles.append(system.raw_bundle(
        h, address, "M", system.m_system(0x24, r1=30, r3=0)
    ))
    address += 0x10
    address = append_gr_check(h, bundles, address, 30, 0, failure)

    # Repeat the qualification rule in the local-interrupt register group
    # without relying on its reset image: establish a legal LID value first,
    # then prove that a false-qualified reserved bit cannot replace it.
    emit_movl(29, 0x12340000)
    bundles.append(system.raw_bundle(
        h, address, "M", system.m_system(0x2C, r2=29, r3=64)
    ))
    address += 0x10
    emit(0x01, h.srlz_d(), h.nop_i(), h.nop_i())
    emit_movl(29, 1 << 32)
    emit(0x01, h.nop_m(), h.nop_i(), h.cmp_rr(1, 2, 0, 0, "lt"))
    bundles.append(system.raw_bundle(
        h, address, "M", system.m_system(0x2C, r2=29, r3=64, qp=1)
    ))
    address += 0x10
    bundles.append(system.raw_bundle(
        h, address, "M", system.m_system(0x24, r1=30, r3=64)
    ))
    address += 0x10
    emit_movl(28, 0x12340000)
    address = append_gr_pair_check(
        h, bundles, address, 30, 28, failure
    )

    expected_nested_isr = (1 << 39) | 0x30
    fault_cases = control_register_field_fault_cases()
    for number, (selector, value, _name) in enumerate(fault_cases, 1):
        continuation = address + 0x60
        emit_movl(21, continuation)
        emit_movl(24, expected_nested_isr)
        emit(0x01, h.nop_m(), h.adds(8, selector, 0),
             h.adds(20, 0, 0))
        emit(0x01, h.nop_m(), h.adds(9, number, 0), h.nop_i())
        emit_movl(29, value)
        bundles.append(system.raw_bundle(
            h, address, "M", system.m_system(0x2C, r2=29, r3=selector)
        ))
        address += 0x10
        if address != continuation:
            raise AssertionError("CR field-fault continuation accounting drift")
        address = append_gr_check(h, bundles, address, 20, 1, failure)

    legal_cases = control_register_field_legal_cases()
    for number, (selector, source, expected, _name) in enumerate(
            legal_cases, 1):
        emit(0x01, h.nop_m(), h.adds(8, selector, 0),
             h.adds(9, number, 0))
        emit_movl(29, source)
        bundles.append(system.raw_bundle(
            h, address, "M", system.m_system(0x2C, r2=29, r3=selector)
        ))
        address += 0x10
        emit(0x01, h.srlz_d(), h.nop_i(), h.nop_i())
        bundles.append(system.raw_bundle(
            h, address, "M", system.m_system(0x24, r1=30, r3=selector)
        ))
        address += 0x10
        emit_movl(28, expected)
        address = append_gr_pair_check(
            h, bundles, address, 30, 28, failure
        )

    handler = h.IA64_GENERAL_EXCEPTION_VECTOR
    bundles.append(system.raw_bundle(
        h, handler, "M", system.m_system(0x24, r1=23, r3=17)
    ))
    handler = append_gr_pair_check(
        h, bundles, handler + 0x10, 23, 24, failure
    )
    bundles.append(h.Bundle(
        handler, 0x01, h.nop_m(), h.mov_grbr(6, 21),
        h.adds(20, 1, 0),
    ))
    handler += 0x10
    bundles.append(h.Bundle(
        handler, 0x11, h.nop_m(), h.nop_i(), h.br_ret(6)
    ))

    return (
        finish_checked_program(
            h, "complete named CR literal field matrix", bundles, address,
            failure=failure, terminal=terminal, entry=entry,
        ),
        len(fault_cases), len(legal_cases),
    )


def control_register_nat_field_priority_program(h: ModuleType,
                                                system: ModuleType):
    return h.Program(
        "CR source NaT precedes reserved-field validation",
        (
            h.Bundle(0x10, 0x01, h.ssm(h.IA64_PSR_IC),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x20, 0x01, h.srlz_i(), h.nop_i(), h.nop_i()),
            h.Bundle(0x30, 0x01, h.nop_m(), h.adds(8, 1, 0),
                     h.adds(9, 0x1000, 0)),
            h.Bundle(0x40, 0x01, h.mov_m_grar(36, 8),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x50, 0x01, h.ld8_fill(29, 9),
                     h.nop_i(), h.nop_i()),
            system.raw_bundle(
                h, 0x60, "M", system.m_system(0x2C, r2=29, r3=0)
            ),
            h.spin_bundle(0x5600),
        ),
        0x5600,
        (h.DataWord(0x1000, 1 << 3, 8),),
    )


def control_register_privilege_field_priority_program(h: ModuleType,
                                                      system: ModuleType):
    return h.Program(
        "CR privilege precedes source NaT and reserved field",
        system.lower_cpl_prefix(h, 0x80) + (
            h.Bundle(0x80, 0x01, h.nop_m(), h.adds(8, 1, 0),
                     h.adds(9, 0x1000, 0)),
            h.Bundle(0x90, 0x01, h.mov_m_grar(36, 8),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0xa0, 0x01, h.ld8_fill(29, 9),
                     h.nop_i(), h.nop_i()),
            system.raw_bundle(
                h, 0xb0, "M", system.m_system(0x2C, r2=29, r3=0)
            ),
            h.spin_bundle(h.IA64_GENERAL_EXCEPTION_VECTOR),
        ),
        h.IA64_GENERAL_EXCEPTION_VECTOR,
        (h.DataWord(0x1000, 1 << 3, 8),),
    )


def control_register_ic_field_priority_program(h: ModuleType,
                                               system: ModuleType):
    return h.Program(
        "CR PSR.ic legality precedes privilege and reserved field",
        system.lower_cpl_prefix(h, 0x80) + (
            system.movl_bundle(h, 0x80, 29, 1),
            system.raw_bundle(
                h, 0x90, "M", system.m_system(0x2C, r2=29, r3=16)
            ),
            h.spin_bundle(h.IA64_GENERAL_EXCEPTION_VECTOR),
        ),
        h.IA64_GENERAL_EXCEPTION_VECTOR,
    )


def test_control_register_fields(h: ModuleType, system: ModuleType,
                                 qemu: Path) -> str:
    program, fault_count, legal_count = control_register_field_program(
        h, system
    )
    result = h.run_program(
        qemu, program, compact_loader=True, preserve_fault_slot=True
    )
    if result.gr[14] != 1:
        raise AssertionError(
            "named CR field matrix failed: "
            f"selector={result.gr[8]} case={result.gr[9]} "
            f"marker={result.gr[20]} ip=0x{result.ip:x} "
            f"isr=0x{result.cr_isr:x} exception={result.exception_kind}"
        )

    nat = h.run_program(
        qemu, control_register_nat_field_priority_program(h, system),
        preserve_fault_slot=True,
    )
    if (nat.ip != 0x5600 or nat.cr_iip != 0x60 or
            (nat.cr_isr & 0xffff) != 0x10):
        raise AssertionError("CR source NaT did not precede reserved fields")

    privilege = h.run_program(
        qemu, control_register_privilege_field_priority_program(h, system),
        preserve_fault_slot=True,
    )
    if (privilege.ip != h.IA64_GENERAL_EXCEPTION_VECTOR or
            (privilege.cr_isr & 0xffff) != 0x10 or
            ((privilege.cr_ipsr >> 32) & 3) != 3 or
            privilege.cr_iip != 0xb0):
        raise AssertionError(
            "CR privilege did not precede source NaT/reserved fields"
        )

    ic = h.run_program(
        qemu, control_register_ic_field_priority_program(h, system),
        preserve_fault_slot=True,
    )
    if (ic.ip != h.IA64_GENERAL_EXCEPTION_VECTOR or
            (ic.cr_isr & 0xffff) != 0 or ic.cr_iip != 0x90):
        raise AssertionError(
            "CR PSR.ic legality did not precede privilege/reserved fields"
        )
    return (
        f"{fault_count} reserved-field values and {legal_count} singleton/"
        "boundary values pass exact fault, preserve, ignore, predicate, NaT, "
        "privilege, and PSR.ic priority rules across all 23 writable CRs"
    )


def application_register_ccv_effect_cases() -> tuple[
        tuple[int, bool, bool, bool], ...]:
    return (
        tuple(
            (width, release, match, True)
            for width in (1, 2, 4, 8)
            for release in (False, True)
            for match in (False, True)
        )
        + tuple((width, False, True, False) for width in (1, 2, 4, 8))
    )


def application_register_ccv_effect_program(h: ModuleType,
                                            system: ModuleType,
                                            data_plane: ModuleType):
    bundles: list[object] = []
    data: list[object] = []
    expectations: list[tuple[int, int, int, int, str]] = []
    address = 0x10000

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> None:
        nonlocal address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10

    def emit_movl(register: int, value: int) -> None:
        nonlocal address
        bundles.append(system.movl_bundle(h, address, register, value))
        address += 0x10

    emit(0x01, h.alloc(31, 96, 96, 0), h.nop_i(), h.nop_i())
    emit(0x01, h.nop_m(), h.nop_i(),
         h.cmp_rr(1, 2, 0, 0, "lt"))
    for index, (width, release, match, qualified) in enumerate(
            application_register_ccv_effect_cases()):
        memory_address = 0x1800 + index * 8
        mask = (1 << (width * 8)) - 1
        initial = (0x8877665544332210 + index) & U64_MASK
        old = initial & mask
        replacement = 0x70 + index
        compare = old if match else old ^ 1
        result_register = 20 + index * 2
        memory_register = result_register + 1
        predicate = 0 if qualified else 1
        sentinel = 0x5a

        data.append(h.DataWord(memory_address, initial, 8))
        emit_movl(12, compare)
        emit(0x01, h.nop_m(), h.adds(10, memory_address, 0),
             h.adds(11, replacement, 0))
        emit(0x01, h.mov_m_grar(32, 12),
             h.adds(result_register, sentinel, 0), h.nop_i())
        emit(0x01, data_plane.atomic(
            f"IA64_OP_CMPXCHG{width}", r1=result_register,
            r2=11, r3=10, qp=predicate, release=release,
        ), h.nop_i(), h.nop_i())
        emit(0x01, h.ld8(memory_register, 10), h.nop_i(), h.nop_i())

        expected_result = old if qualified else sentinel
        expected_memory = initial
        if qualified and match:
            expected_memory = (initial & ~mask) | (replacement & mask)
        expectations.append((
            result_register, memory_register, expected_result,
            expected_memory,
            f"cmpxchg{width}.{'rel' if release else 'acq'} "
            f"{'match' if match else 'mismatch'} "
            f"{'enabled' if qualified else 'false-qualified'}",
        ))

    bundles.append(h.spin_bundle(address))
    return (
        h.Program(
            "complete CCV compare-exchange effect matrix",
            tuple(bundles), address, tuple(data), entry=0x10000,
        ),
        tuple(expectations),
    )


def test_application_register_ccv_effect(h: ModuleType,
                                         system: ModuleType,
                                         data_plane: ModuleType,
                                         qemu: Path) -> str:
    program, expectations = application_register_ccv_effect_program(
        h, system, data_plane
    )
    snapshot = h.run_program(qemu, program, compact_loader=True)
    if snapshot.ip != program.terminal_ip or snapshot.exception_pending:
        raise AssertionError(
            "CCV effect matrix did not terminate cleanly: "
            f"ip=0x{snapshot.ip:x} exception={snapshot.exception_kind}"
        )
    failures = []
    for result, memory, expected_result, expected_memory, label in expectations:
        if (snapshot.gr[result], snapshot.gr[memory]) != (
                expected_result, expected_memory):
            failures.append(
                f"{label}: result=0x{snapshot.gr[result]:x}/"
                f"0x{expected_result:x} memory=0x{snapshot.gr[memory]:x}/"
                f"0x{expected_memory:x}"
            )
    if failures:
        raise AssertionError("CCV effect mismatch: " + "; ".join(failures[:4]))
    return (
        "twenty literal CCV cases cover cmpxchg1/2/4/8 acquire and release "
        "match/mismatch outcomes plus false qualification at every width"
    )


def application_register_unat_expected_image() -> int:
    return sum(1 << selector for selector in range(0, 64, 2))


def application_register_unat_effect_program(h: ModuleType,
                                             data_plane: ModuleType):
    failure = 0x70000
    terminal = 0x70030
    address = 0x10000
    bundles: list[object] = []

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> None:
        nonlocal address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10

    # Construct one NaT source and one ordinary source, then clear UNAT so the
    # spill pairs alone construct the complete expected 64-bit collection.
    emit(0x01, h.nop_m(), h.adds(8, 1, 0), h.adds(9, 0x1c00, 0))
    emit(0x01, h.mov_m_grar(36, 8), h.nop_i(), h.nop_i())
    emit(0x01, h.ld8_fill(20, 9), h.adds(21, 0x66, 0), h.nop_i())
    emit(0x01, h.nop_m(), h.adds(8, 0, 0), h.nop_i())
    emit(0x01, h.mov_m_grar(36, 8), h.nop_i(), h.nop_i())

    # Each no-stop MMI pair sets an even selector from NaT(r20) and clears the
    # adjacent odd selector from ordinary r21.  The address bits 8:3 enumerate
    # every UNAT bit exactly once.
    for selector in range(0, 64, 2):
        even_address = 0x1800 + selector * 8
        odd_address = even_address + 8
        emit(0x01, h.nop_m(), h.adds(10, even_address, 0),
             h.adds(11, odd_address, 0))
        emit(0x09,
             data_plane.integer_spill(8, r2=20, r3=10),
             data_plane.integer_spill(8, r2=21, r3=11),
             h.nop_i())

    # A false spill cannot alter either the selected UNAT bit or memory; a
    # false fill cannot alter its destination value or NaT.
    emit(0x01, h.nop_m(), h.adds(10, 0x1808, 0),
         h.cmp_rr(1, 2, 0, 0, "lt"))
    emit(0x01, data_plane.integer_spill(8, r2=20, r3=10, qp=1),
         h.adds(24, 0x77, 0), h.nop_i())
    emit(0x01, h.ld8_fill(24, 10, qp=1), h.nop_i(), h.nop_i())
    address = append_gr_check(h, bundles, address, 24, 0x77, failure)
    address = append_tnat_check(h, bundles, address, 24, False, failure)

    # Load every pair back through architectural fill behavior and check both
    # the stored payload and the NaT bit before reusing the destinations.
    for selector in range(0, 64, 2):
        even_address = 0x1800 + selector * 8
        odd_address = even_address + 8
        emit(0x01, h.nop_m(), h.adds(10, even_address, 0),
             h.adds(11, odd_address, 0))
        emit(0x09, h.ld8_fill(22, 10), h.ld8_fill(23, 11), h.nop_i())
        address = append_gr_check(h, bundles, address, 22, 0x55, failure)
        address = append_tnat_check(h, bundles, address, 22, True, failure)
        address = append_gr_check(h, bundles, address, 23, 0x66, failure)
        address = append_tnat_check(h, bundles, address, 23, False, failure)

    emit(0x01, h.mov_m_argr(30, 36), h.nop_i(), h.nop_i())
    expected = application_register_unat_expected_image()
    # Compare the full image in the host as well as every selector's guest
    # fill result; a MOVL is unnecessary in this already-large guest program.
    return (
        finish_checked_program(
            h, "complete UNAT spill/fill selector matrix", bundles, address,
            failure=failure, terminal=terminal,
            data=(h.DataWord(0x1c00, 0x55, 8),), entry=0x10000,
        ),
        expected,
    )


def test_application_register_unat_effect(h: ModuleType,
                                          data_plane: ModuleType,
                                          qemu: Path) -> str:
    program, expected = application_register_unat_effect_program(h, data_plane)
    snapshot = h.run_program(qemu, program, compact_loader=True)
    if snapshot.gr[14] != 1 or snapshot.ip != program.terminal_ip:
        raise AssertionError(
            "UNAT effect matrix failed: "
            f"ip=0x{snapshot.ip:x} marker={snapshot.gr[14]}"
        )
    if snapshot.unat != expected or snapshot.gr[30] != expected:
        raise AssertionError(
            f"UNAT effect image expected 0x{expected:x}, got "
            f"state=0x{snapshot.unat:x} read=0x{snapshot.gr[30]:x}"
        )
    return (
        "all 64 address selectors pass paired same-group spill set/clear, "
        "payload and NaT fill recovery, false qualification, and exact UNAT "
        "readback"
    )


def application_register_bspstore_rebase_program(h: ModuleType):
    failure = 0x30000
    terminal = 0x30030
    address = 0x10000
    bundles: list[object] = []

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> None:
        nonlocal address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10

    def emit_value(register: int, value: int) -> None:
        # Every selected address is below the signed ADDs immediate ceiling.
        emit(0x01, h.nop_m(), h.adds(register, value, 0), h.nop_i())

    def check_pair(store: int, bsp: int) -> None:
        nonlocal address
        emit_value(28, store)
        address = append_gr_pair_check(
            h, bundles, address, 20, 28, failure
        )
        emit_value(28, bsp)
        address = append_gr_pair_check(
            h, bundles, address, 21, 28, failure
        )

    # With an empty dirty partition, all 64 possible address-bit {8:3}
    # values independently select the next store/BSP relationship.  Low bits
    # cycle through every ignored pattern without changing that selector.  A
    # pointer at offset 63 names the RNAT collection word, so BSP skips it.
    for selector in range(64):
        aligned = 0x1800 + selector * 8
        presented = aligned | (selector & 7)
        expected_bsp = aligned + (8 if selector == 63 else 0)
        emit_value(29, presented)
        emit(0x01, h.mov_m_grar(18, 29), h.nop_i(), h.nop_i())
        emit(0x09, h.mov_m_argr(20, 18), h.mov_m_argr(21, 17), h.nop_i())
        check_pair(aligned, expected_bsp)

    # A false-qualified rebase is completely inert after the final offset-63
    # case, including its implicit BSP destination.
    emit(0x03, h.nop_m(), h.cmp_rr(1, 2, 0, 0, "lt"), h.nop_i())
    emit_value(29, 0x1a80)
    emit(0x01, h.mov_m_grar(18, 29, qp=1), h.nop_i(), h.nop_i())
    emit(0x09, h.mov_m_argr(20, 18), h.mov_m_argr(21, 17), h.nop_i())
    check_pair(0x19f8, 0x1a00)

    # The implicit BSP destination participates in the same issue-group
    # source epoch as BSPSTORE itself.  Reads before the stop see the old
    # image; reads in the following group see the fully rebased image.
    emit_value(29, 0x1800)
    emit(0x01, h.mov_m_grar(18, 29), h.nop_i(), h.nop_i())
    emit_value(29, 0x19f8)
    emit(0x08, h.mov_m_grar(18, 29), h.mov_m_argr(22, 17), h.nop_i())
    emit(0x09, h.mov_m_argr(23, 18), h.nop_m(), h.nop_i())
    emit_value(28, 0x1800)
    address = append_gr_pair_check(
        h, bundles, address, 22, 28, failure
    )
    address = append_gr_pair_check(
        h, bundles, address, 23, 28, failure
    )
    emit(0x09, h.mov_m_argr(20, 18), h.mov_m_argr(21, 17), h.nop_i())
    check_pair(0x19f8, 0x1a00)

    return finish_checked_program(
        h,
        "complete BSPSTORE/BSP rebase selector matrix",
        bundles,
        address,
        failure=failure,
        terminal=terminal,
        entry=0x10000,
    )


def test_application_register_bspstore_rebase(h: ModuleType,
                                              qemu: Path) -> str:
    program = application_register_bspstore_rebase_program(h)
    snapshot = h.run_program(qemu, program, compact_loader=True)
    if snapshot.gr[14] != 1 or snapshot.ip != program.terminal_ip:
        raise AssertionError(
            "BSPSTORE/BSP rebase matrix failed: "
            f"ip=0x{snapshot.ip:x} marker={snapshot.gr[14]} "
            f"BSPSTORE=0x{snapshot.rse_bspstore:x} "
            f"BSP=0x{snapshot.rse_bsp:x}"
        )
    if (snapshot.rse_bspstore != 0x19f8 or
            snapshot.rse_bspload != 0x19f8 or
            snapshot.rse_bsp != 0x1a00):
        raise AssertionError(
            "final offset-63 rebase expected BSPSTORE/BSPLOAD/BSP "
            "0x19f8/0x19f8/0x1a00, got "
            f"0x{snapshot.rse_bspstore:x}/"
            f"0x{snapshot.rse_bspload:x}/0x{snapshot.rse_bsp:x}"
        )
    return (
        "all 64 BSPSTORE address offsets and all ignored low-bit patterns "
        "pass exact BSP rebasing, offset-63 RNAT-slot skipping, false "
        "qualification, same-group old-image visibility, and BSPLOAD state"
    )


def application_register_field_fault_cases() -> tuple[
        tuple[int, int, str], ...]:
    cases: list[tuple[int, int, str]] = []
    for selector, reserved in (
        (16, AR_RSC_RESERVED_MASK),
        (40, AR_FPSR_LITERAL_RESERVED_MASK),
        (64, AR_PFS_LITERAL_RESERVED_MASK),
    ):
        for bit in range(64):
            if reserved & (1 << bit):
                cases.append((
                    selector, 1 << bit,
                    f"AR{selector} reserved bit {bit}",
                ))
    for bit in sorted(AR_FPSR_PC_LSB_BITS):
        cases.append((40, 1 << bit, f"FPSR.sf PC encoding 01 at bit {bit}"))
    cases.extend((
        (64, 97, "PFS PFM SOF 97"),
        (64, 1 << 7, "PFS PFM SOL above SOF"),
        (64, 1 << 14, "PFS PFM SOR above SOF"),
        (64, 1 << 18, "PFS PFM nonzero RRB.GR with zero SOR"),
        (64, 8 | (1 << 14) | (8 << 18),
         "PFS PFM RRB.GR outside SOR"),
        (64, 96 << 25, "PFS PFM RRB.FR 96"),
        (64, 48 << 32, "PFS PFM RRB.PR 48"),
    ))
    return tuple(cases)


def application_register_field_legal_cases() -> tuple[
        tuple[int, int, int, str], ...]:
    cases: list[tuple[int, int, int, str]] = []

    for bit in range(64):
        if not (AR_RSC_RESERVED_MASK & (1 << bit)):
            cases.append((16, 1 << bit, 1 << bit, f"RSC field bit {bit}"))

    for bit in range(64):
        if (AR_FPSR_LITERAL_RESERVED_MASK & (1 << bit) or
                bit in AR_FPSR_PC_LSB_BITS):
            continue
        cases.append((40, 1 << bit, 1 << bit, f"FPSR field bit {bit}"))
    for bit in sorted(AR_FPSR_PC_LSB_BITS):
        value = 3 << bit
        cases.append((40, value, value, f"FPSR.sf PC encoding 11 at bit {bit}"))

    for bit in range(0, 7):
        cases.append((64, 1 << bit, 1 << bit, f"PFS SOF bit {bit}"))
    for bit in range(7, 14):
        value = 96 | (1 << bit)
        cases.append((64, value, value, f"PFS SOL bit {bit}"))
    for bit in range(14, 18):
        value = 96 | (1 << bit)
        cases.append((64, value, value, f"PFS SOR bit {bit}"))
    for bit in range(18, 25):
        value = 96 | (12 << 14) | (1 << bit)
        cases.append((64, value, value, f"PFS RRB.GR bit {bit}"))
    for bit in range(25, 32):
        value = 96 | (1 << bit)
        cases.append((64, value, value, f"PFS RRB.FR bit {bit}"))
    for bit in range(32, 38):
        value = 96 | (1 << bit)
        cases.append((64, value, value, f"PFS RRB.PR bit {bit}"))
    for bit in (*range(52, 58), *range(62, 64)):
        cases.append((64, 1 << bit, 1 << bit, f"PFS outer field bit {bit}"))
    max_pfs = (
        96 | (96 << 7) | (12 << 14) | (95 << 18) |
        (95 << 25) | (47 << 32) | (63 << 52) | (3 << 62)
    )
    cases.extend((
        (64, 0, 0, "PFS empty frame"),
        (64, max_pfs, max_pfs, "PFS maximum legal fields"),
    ))

    for selector, name in ((19, "RNAT"), (32, "CCV"), (36, "UNAT"),
                           (65, "LC"), (66, "EC")):
        for bit in range(64):
            source = 1 << bit
            if selector == 19:
                expected = source & ~(1 << 63)
            elif selector == 66:
                expected = source & 0x3f
            else:
                expected = source
            cases.append((
                selector, source, expected, f"{name} field bit {bit}",
            ))

    # BSPSTORE's pointer field is 63:3 and its low three bits are ignored.
    # Exercise every pointer bit, then every nonzero ignored-bit combination
    # against an independently established aligned pointer.
    for bit in range(3, 64):
        cases.append((18, 1 << bit, 1 << bit, f"BSPSTORE pointer bit {bit}"))
    for low in range(1, 8):
        cases.append((
            18, 0x4000 | low, 0x4000,
            f"BSPSTORE ignored low bits {low}",
        ))
    return tuple(cases)


def application_register_field_program(h: ModuleType, system: ModuleType):
    failure = 0x70000
    terminal = 0x70030
    entry = 0x10000
    bundles: list[object] = []
    address = entry

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> None:
        nonlocal address
        bundles.append(h.Bundle(address, template, slot0, slot1, slot2))
        address += 0x10

    def emit_movl(register: int, value: int) -> None:
        nonlocal address
        bundles.append(system.movl_bundle(h, address, register, value))
        address += 0x10

    def unit(selector: int) -> str:
        return "I" if selector in AR_I_INDICES else "M"

    def write(selector: int, source: int = 29, predicate: int = 0) -> None:
        nonlocal address
        insn = (h.mov_i_grar(selector, source, qp=predicate)
                if unit(selector) == "I" else
                h.mov_m_grar(selector, source, qp=predicate))
        bundles.append(system.raw_bundle(h, address, unit(selector), insn))
        address += 0x10

    def read(selector: int, target: int = 30) -> None:
        nonlocal address
        insn = (h.mov_argr(target, selector)
                if unit(selector) == "I" else
                h.mov_m_argr(target, selector))
        bundles.append(system.raw_bundle(h, address, unit(selector), insn))
        address += 0x10

    emit(0x01, h.rsm(h.IA64_PSR_IC), h.nop_i(), h.nop_i())
    emit(0x01, h.srlz_i(), h.nop_i(), h.nop_i())

    # Qualification suppresses reserved-field validation independently for
    # every field-validated named AR.  Establish zero explicitly so the check
    # does not rely on reset state.
    for selector, poison in ((16, 1 << 5), (40, 1 << 58), (64, 1 << 38)):
        emit_movl(29, 0)
        write(selector)
        emit_movl(29, poison)
        emit(0x01, h.nop_m(), h.nop_i(), h.cmp_rr(1, 2, 0, 0, "lt"))
        write(selector, predicate=1)
        read(selector)
        address = append_gr_check(h, bundles, address, 30, 0, failure)

    expected_base_isr = (1 << 39) | 0x30
    fault_cases = application_register_field_fault_cases()
    for number, (selector, value, _name) in enumerate(fault_cases, 1):
        continuation = address + 0x60
        expected_isr = expected_base_isr
        if unit(selector) == "I":
            expected_isr |= 1 << h.IA64_ISR_EI_SHIFT
        emit_movl(21, continuation)
        emit_movl(24, expected_isr)
        emit(0x01, h.nop_m(), h.adds(8, selector, 0),
             h.adds(9, number, 0))
        emit(0x01, h.nop_m(), h.adds(20, 0, 0), h.nop_i())
        emit_movl(29, value)
        write(selector)
        if address != continuation:
            raise AssertionError("AR field-fault continuation accounting drift")
        address = append_gr_check(h, bundles, address, 20, 1, failure)

    legal_cases = application_register_field_legal_cases()
    for number, (selector, source, expected, _name) in enumerate(
            legal_cases, 1):
        emit(0x01, h.nop_m(), h.adds(8, selector, 0),
             h.adds(9, number, 0))
        emit_movl(29, source)
        write(selector)
        read(selector)
        emit_movl(28, expected)
        address = append_gr_pair_check(
            h, bundles, address, 30, 28, failure
        )
        if selector == 16:
            emit(0x01, h.nop_m(), h.adds(29, 0, 0), h.nop_i())
            write(16)

    handler = h.IA64_GENERAL_EXCEPTION_VECTOR
    bundles.append(system.raw_bundle(
        h, handler, "M", system.m_system(0x24, r1=23, r3=17)
    ))
    handler = append_gr_pair_check(
        h, bundles, handler + 0x10, 23, 24, failure
    )
    bundles.append(h.Bundle(
        handler, 0x01, h.nop_m(), h.mov_grbr(6, 21), h.adds(20, 1, 0)
    ))
    handler += 0x10
    bundles.append(h.Bundle(
        handler, 0x11, h.nop_m(), h.nop_i(), h.br_ret(6)
    ))

    return (
        finish_checked_program(
            h, "complete named AR literal field matrix", bundles, address,
            failure=failure, terminal=terminal, entry=entry,
        ),
        len(fault_cases), len(legal_cases),
    )


def application_register_nat_field_priority_program(h: ModuleType,
                                                    selector: int,
                                                    poison: int):
    unit = "I" if selector in AR_I_INDICES else "M"
    write = (h.mov_i_grar(selector, 29) if unit == "I" else
             h.mov_m_grar(selector, 29))
    write_bundle = (h.Bundle(0x60, 0x01, h.nop_m(), write, h.nop_i())
                    if unit == "I" else
                    h.Bundle(0x60, 0x01, write, h.nop_i(), h.nop_i()))
    return h.Program(
        f"AR{selector} source NaT precedes field processing",
        (
            h.Bundle(0x10, 0x01, h.ssm(h.IA64_PSR_IC),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x20, 0x01, h.srlz_i(), h.nop_i(), h.nop_i()),
            h.Bundle(0x30, 0x01, h.nop_m(), h.adds(8, 1, 0),
                     h.adds(9, 0x1000, 0)),
            h.Bundle(0x40, 0x01, h.mov_m_grar(36, 8),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x50, 0x01, h.ld8_fill(29, 9),
                     h.nop_i(), h.nop_i()),
            write_bundle,
            h.spin_bundle(h.IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
        ),
        h.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        (h.DataWord(0x1000, poison, 8),),
    )


def application_register_mode_priority_program(h: ModuleType):
    return h.Program(
        "AR RSE-mode legality precedes source NaT",
        (
            h.Bundle(0x10, 0x01, h.ssm(h.IA64_PSR_IC),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x20, 0x01, h.srlz_i(), h.nop_i(), h.nop_i()),
            h.Bundle(0x30, 0x01, h.nop_m(), h.adds(29, 1, 0), h.nop_i()),
            h.Bundle(0x40, 0x01, h.mov_m_grar(16, 29),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x50, 0x01, h.nop_m(), h.adds(8, 1, 0),
                     h.adds(9, 0x1000, 0)),
            h.Bundle(0x60, 0x01, h.mov_m_grar(36, 8),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x70, 0x01, h.ld8_fill(29, 9),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x80, 0x01, h.mov_m_grar(19, 29),
                     h.nop_i(), h.nop_i()),
            h.spin_bundle(h.IA64_GENERAL_EXCEPTION_VECTOR),
        ),
        h.IA64_GENERAL_EXCEPTION_VECTOR,
        (h.DataWord(0x1000, 0, 8),),
    )


def application_register_rsc_pl_program(h: ModuleType, system: ModuleType):
    return h.Program(
        "RSC prevents illegal privilege promotion",
        system.lower_cpl_prefix(h, 0x80) + (
            h.Bundle(0x80, 0x01, h.nop_m(), h.adds(29, 0, 0), h.nop_i()),
            h.Bundle(0x90, 0x01, h.mov_m_grar(16, 29),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0xa0, 0x01, h.mov_m_argr(10, 16),
                     h.nop_i(), h.nop_i()),
            h.spin_bundle(0xb0),
        ),
        0xb0,
    )


def test_application_register_fields(h: ModuleType, system: ModuleType,
                                     qemu: Path) -> str:
    program, fault_count, legal_count = application_register_field_program(
        h, system
    )
    result = h.run_program(
        qemu, program, compact_loader=True, preserve_fault_slot=True
    )
    if result.gr[14] != 1:
        raise AssertionError(
            "named AR field matrix failed: "
            f"selector={result.gr[8]} case={result.gr[9]} "
            f"marker={result.gr[20]} ip=0x{result.ip:x} "
            f"isr=0x{result.cr_isr:x} exception={result.exception_kind}"
        )

    for selector, poison in (
        (16, 1 << 5),
        (18, 0),
        (19, 1 << 63),
        (32, 0),
        (36, 0),
        (40, 1 << 58),
        (64, 1 << 38),
        (65, 0),
        (66, 1 << 6),
    ):
        nat = h.run_program(
            qemu,
            application_register_nat_field_priority_program(
                h, selector, poison
            ),
            preserve_fault_slot=True,
        )
        expected_isr = 0x10
        if selector in AR_I_INDICES:
            expected_isr |= 1 << h.IA64_ISR_EI_SHIFT
        if (nat.ip != h.IA64_REGISTER_NAT_CONSUMPTION_VECTOR or
                nat.cr_iip != 0x60 or
                nat.cr_isr != expected_isr):
            raise AssertionError(
                f"AR{selector} source NaT did not precede field processing: "
                f"ip=0x{nat.ip:x} iip=0x{nat.cr_iip:x} "
                f"isr=0x{nat.cr_isr:x} exception={nat.exception_kind}"
            )

    mode = h.run_program(
        qemu, application_register_mode_priority_program(h),
        preserve_fault_slot=True,
    )
    if (mode.ip != h.IA64_GENERAL_EXCEPTION_VECTOR or
            mode.cr_iip != 0x80 or
            (mode.cr_isr & 0xffff) != 0):
        raise AssertionError("AR RSE-mode legality did not precede source NaT")

    pl = h.run_program(
        qemu, application_register_rsc_pl_program(h, system),
        preserve_fault_slot=True,
    )
    if pl.ip != 0xb0 or pl.gr[10] != 3 << 2:
        raise AssertionError(
            f"RSC permitted illegal privilege promotion: 0x{pl.gr[10]:x}"
        )
    return (
        f"{fault_count} reserved-field values and {legal_count} singleton/"
        "boundary values pass exact fault, preserve, ignore, predicate, NaT, "
        "RSE-mode priority, and RSC privilege-clamp rules across nine named ARs"
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
    data_plane = load_module(
        root / "tests/unit/ia64_data_plane_tcg_spec.py",
        "_ia64_register_tcg_data_plane_spec",
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
        ("complete named AR field semantics", lambda: test_application_register_fields(harness, system, args.qemu.resolve())),
        ("BSPSTORE/BSP rebase effects", lambda: test_application_register_bspstore_rebase(harness, args.qemu.resolve())),
        ("CCV compare-exchange effects", lambda: test_application_register_ccv_effect(harness, system, data_plane, args.qemu.resolve())),
        ("UNAT spill/fill effects", lambda: test_application_register_unat_effect(harness, data_plane, args.qemu.resolve())),
        ("complete CR selector space", lambda: test_control_register_selectors(harness, system, args.qemu.resolve())),
        ("complete named CR field semantics", lambda: test_control_register_fields(harness, system, args.qemu.resolve())),
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
