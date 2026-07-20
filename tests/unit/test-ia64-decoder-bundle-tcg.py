#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent E2 probes for IA-64 decoding, bundles, and IP/RI state."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Sequence


U64_MASK = (1 << 64) - 1

# This literal is intentionally independent of target/ia64/bundle.c.  The
# static tranche validator compares every entry with the production table.
TEMPLATE_MATRIX = (
    (0x00, "MII", (False, False, False), False),
    (0x01, "MII", (False, False, True), False),
    (0x02, "MII", (False, True, False), False),
    (0x03, "MII", (False, True, True), False),
    (0x04, "MLX", (False, False, False), True),
    (0x05, "MLX", (False, False, True), True),
    (0x06, None, None, False),
    (0x07, None, None, False),
    (0x08, "MMI", (False, False, False), False),
    (0x09, "MMI", (False, False, True), False),
    (0x0A, "MMI", (True, False, False), False),
    (0x0B, "MMI", (True, False, True), False),
    (0x0C, "MFI", (False, False, False), False),
    (0x0D, "MFI", (False, False, True), False),
    (0x0E, "MMF", (False, False, False), False),
    (0x0F, "MMF", (False, False, True), False),
    (0x10, "MIB", (False, False, False), False),
    (0x11, "MIB", (False, False, True), False),
    (0x12, "MBB", (False, False, False), False),
    (0x13, "MBB", (False, False, True), False),
    (0x14, None, None, False),
    (0x15, None, None, False),
    (0x16, "BBB", (False, False, False), False),
    (0x17, "BBB", (False, False, True), False),
    (0x18, "MMB", (False, False, False), False),
    (0x19, "MMB", (False, False, True), False),
    (0x1A, None, None, False),
    (0x1B, None, None, False),
    (0x1C, "MFB", (False, False, False), False),
    (0x1D, "MFB", (False, False, True), False),
    (0x1E, None, None, False),
    (0x1F, None, None, False),
)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def bitfield(value: int, low: int, width: int) -> int:
    return (value & ((1 << width) - 1)) << low


def op(major: int) -> int:
    return bitfield(major, 37, 4)


def movl_bundle(h: ModuleType, address: int, reg: int, value: int,
                qp: int = 0):
    value &= U64_MASK
    l_slot = (value >> 22) & ((1 << 41) - 1)
    x_slot = (bitfield(reg, 6, 7) | bitfield(value, 13, 7) |
              bitfield(value >> 21, 21, 1) |
              bitfield(value >> 16, 22, 5) |
              bitfield(value >> 7, 27, 9) |
              bitfield(value >> 63, 36, 1) | op(6) |
              bitfield(qp, 0, 6))
    return h.Bundle(address, 0x05, h.nop_m(), l_slot, x_slot)


def raw_count(r1: int, r3: int = 3, qp: int = 0,
              reserved_r2: int = 0) -> int:
    return (op(7) | bitfield(0x12, 27, 6) | bitfield(3, 33, 3) |
            bitfield(r3, 20, 7) | bitfield(reserved_r2, 13, 7) |
            bitfield(r1, 6, 7) | bitfield(qp, 0, 6))


def test_legal_template_equivalence(h: ModuleType, qemu: Path) -> str:
    slots = {"M": h.nop_m(), "I": h.nop_i(), "F": h.nop_i(),
             "B": 2 << 37}
    bundles = []
    address = 0x10
    for template, units, _stops, long_immediate in TEMPLATE_MATRIX:
        if units is None:
            continue
        encoded = ((slots["M"], 0, h.nop_i()) if long_immediate else
                   tuple(slots[unit] for unit in units))
        bundles.append(h.Bundle(address, template, *encoded))
        address += 0x10
    bundles.extend((
        h.Bundle(address, 0x01, h.nop_m(), h.adds(30, 24, 0), h.nop_i()),
        h.spin_bundle(address + 0x10),
    ))
    snapshot = h.run_program(qemu, h.Program(
        name="all 24 legal template encodings", bundles=tuple(bundles),
        terminal_ip=address + 0x10))
    if snapshot.exception_pending or snapshot.gr[30] != 24:
        raise AssertionError("a legal template faulted or failed to retire")
    return "all 24 legal templates executed with independent unit encodings"


def _brl_with_ignored_bits(h: ModuleType, source: int, target: int):
    displacement = target - source
    if displacement & 0xF:
        raise ValueError("long branch target is not bundle aligned")
    field = (displacement >> 4) & ((1 << 60) - 1)
    # L bits 1:0 are ignored by X3 and are deliberately forced to one.
    l_slot = bitfield((field >> 20) & ((1 << 39) - 1), 2, 39) | 3
    x_slot = (op(0xC) | bitfield(field & 0xFFFFF, 13, 20) |
              bitfield((field >> 59) & 1, 36, 1))
    return l_slot, x_slot


def test_long_immediate_construction(h: ModuleType, qemu: Path) -> str:
    values = (0xFEDCBA9876543210, 0x0000000000402001)
    program = h.Program(
        name="independent MOVL immediate reconstruction",
        bundles=(movl_bundle(h, 0x10, 20, values[0]),
                 movl_bundle(h, 0x20, 21, values[1]),
                 h.spin_bundle(0x30)), terminal_ip=0x30)
    snapshot = h.run_program(qemu, program)
    if snapshot.exception_pending or (snapshot.gr[20], snapshot.gr[21]) != values:
        raise AssertionError("MOVL did not reconstruct its split L/X immediate")

    far = 0x02000040
    l_slot, x_slot = _brl_with_ignored_bits(h, 0x40, far)
    forward = h.Program(
        name="forward X3 imm60 with ignored L bits",
        bundles=(h.Bundle(0x40, 0x05, h.nop_m(), l_slot, x_slot),
                 h.spin_bundle(0x50), h.spin_bundle(far)),
        terminal_ip=far, entry=0x40)
    if h.run_program(qemu, forward).ip != far:
        raise AssertionError("forward BRL did not reconstruct its imm60 target")
    l_slot, x_slot = _brl_with_ignored_bits(h, far, 0x40)
    backward = h.Program(
        name="backward X3 signed imm60 with ignored L bits",
        bundles=(h.spin_bundle(0x40),
                 h.Bundle(far, 0x05, h.nop_m(), l_slot, x_slot),
                 h.spin_bundle(far + 0x10)), terminal_ip=0x40, entry=far)
    if h.run_program(qemu, backward).ip != 0x40:
        raise AssertionError("backward BRL did not sign-extend its imm60 target")
    return "MOVL and forward/backward BRL reconstruct independent L/X immediates"


def _mlx_ri2_rfi_program(h: ModuleType):
    saved_psr = h.IA64_PSR_IC | (2 << h.IA64_PSR_RI_SHIFT)
    vector = h.IA64_GENERAL_EXCEPTION_VECTOR
    return h.Program(
        name="RFI to illegal MLX continuation RI=2",
        bundles=(
            movl_bundle(h, 0x10, 8, 0x100),
            movl_bundle(h, 0x20, 9, saved_psr),
            h.Bundle(0x30, 0x01, h.mov_grcr(h.IA64_CR_IIP, 8),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x40, 0x01, h.mov_grcr(h.IA64_CR_IPSR, 9),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x50, 0x11, h.nop_m(), h.nop_i(), h.rfi()),
            movl_bundle(h, 0x100, 31, 0x12345678),
            h.spin_bundle(vector),
        ), terminal_ip=vector)


def test_template_and_placement_legality(h: ModuleType, qemu: Path) -> str:
    vector = h.IA64_GENERAL_EXCEPTION_VECTOR
    reserved = [row[0] for row in TEMPLATE_MATRIX if row[1] is None]
    for template in reserved:
        program = h.Program(
            name=f"reserved template 0x{template:02x}",
            bundles=(
                h.Bundle(0x10, 0x01, h.ssm(h.IA64_PSR_IC),
                         h.nop_i(), h.nop_i()),
                h.Bundle(0x20, 0x01, h.srlz_i(), h.nop_i(), h.nop_i()),
                h.Bundle(0x30, template, 0, 0, 0), h.spin_bundle(vector),
            ), terminal_ip=vector)
        snapshot = h.run_program(qemu, program, preserve_fault_slot=True)
        if (snapshot.ip != vector or
                snapshot.exception_kind != "illegal-operation" or
                snapshot.cr_iip != 0x30 or snapshot.slot_ri != 0):
            raise AssertionError(f"reserved template 0x{template:02x} was not precise")

    snapshot = h.run_program(qemu, _mlx_ri2_rfi_program(h),
                             preserve_fault_slot=True,
                             typed_rfi_traces=(0x50,), one_bundle_per_tb=True)
    expected_ri = 2 << h.IA64_PSR_RI_SHIFT
    expected_ei = 2 << h.IA64_ISR_EI_SHIFT
    if (snapshot.ip != vector or snapshot.exception_kind != "illegal-operation" or
            snapshot.cr_iip != 0x100 or snapshot.cr_ipsr !=
            (h.IA64_PSR_IC | expected_ri) or snapshot.cr_isr != expected_ei or
            not snapshot.slot_valid or snapshot.slot_ip != 0x100 or
            snapshot.slot_ri != 2 or snapshot.gr[31] != 0):
        raise AssertionError("RFI to MLX RI=2 lost precise Illegal Operation state")
    return "all eight reserved templates and architectural MLX RI=2 placement fault precisely"


def test_ignored_and_reserved_fields(h: ModuleType, qemu: Path) -> str:
    # The long-branch half of the ignored-field rule is exercised separately
    # from target reconstruction to keep the legality oracle explicit here.
    source, target = 0x20, 0x60
    l_slot, x_slot = _brl_with_ignored_bits(h, source, target)
    ignored = h.Program(
        name="ignored X3 L bits do not fault",
        bundles=(h.Bundle(source, 0x05, h.nop_m(), l_slot, x_slot),
                 h.spin_bundle(0x30), h.spin_bundle(target)),
        terminal_ip=target, entry=source)
    result = h.run_program(qemu, ignored)
    if result.ip != target or result.exception_pending:
        raise AssertionError("architecturally ignored X3 bits changed execution")

    vector = h.IA64_GENERAL_EXCEPTION_VECTOR
    fault = h.Program(
        name="enabled POPCNT reserved r2",
        bundles=(
            h.Bundle(0x10, 0x01, h.ssm(h.IA64_PSR_IC),
                     h.nop_i(), h.nop_i()),
            h.Bundle(0x20, 0x01, h.srlz_i(), h.nop_i(), h.nop_i()),
            movl_bundle(h, 0x30, 31, 0x123),
            h.Bundle(0x40, 0x03, h.nop_m(),
                     raw_count(31, reserved_r2=1), h.adds(30, 0x456, 0)),
            h.spin_bundle(vector),
        ), terminal_ip=vector)
    result = h.run_program(qemu, fault, preserve_fault_slot=True)
    if (result.exception_kind != "illegal-operation" or result.cr_iip != 0x40 or
            result.slot_ri != 1 or result.gr[31] != 0x123 or result.gr[30] != 0):
        raise AssertionError("enabled reserved field did not fault precisely")

    nullified = h.Program(
        name="false-qualified POPCNT reserved r2",
        bundles=(movl_bundle(h, 0x10, 31, 0xABC),
                 h.Bundle(0x20, 0x03, h.nop_m(),
                          raw_count(31, qp=1, reserved_r2=1), h.nop_i()),
                 h.spin_bundle(0x30)), terminal_ip=0x30)
    result = h.run_program(qemu, nullified)
    if result.exception_pending or result.gr[31] != 0xABC:
        raise AssertionError("false qualifier failed to suppress reserved field")
    return "ignored X3 bits execute; enabled reserved POPCNT faults and false qp suppresses it"


def _ri_resume_program(h: ModuleType):
    return h.Program(
        name="MII architectural RI entry",
        bundles=(h.Bundle(0x10, 0x03, h.adds(10, 0x10, 0),
                          h.adds(11, 0x11, 0), h.adds(12, 0x12, 0)),
                 h.spin_bundle(0x20)), terminal_ip=0x20)


def test_ri_entry_resume_matrix(h: ModuleType, qemu: Path) -> str:
    expected = ((0x10, 0x11, 0x12), (0, 0x11, 0x12), (0, 0, 0x12))
    for ri, golden in enumerate(expected):
        snapshot, _trace = h.run_ri_restart(qemu, _ri_resume_program(h), ri)
        actual = (snapshot.gr[10], snapshot.gr[11], snapshot.gr[12])
        if actual != golden or ((snapshot.psr >> h.IA64_PSR_RI_SHIFT) & 3) != 0:
            raise AssertionError(f"RI={ri} resumed {actual}, expected {golden}")
    return "RI 0/1/2 entry executes exactly the named suffix and branch completion restores RI=0"


def test_ip_ri_transition_matrix(h: ModuleType, qemu: Path) -> str:
    normal = h.run_program(qemu, h.Program(
        name="sequential IP/RI completion",
        bundles=(h.Bundle(0x10, 0x03, h.nop_m(), h.adds(20, 1, 0),
                          h.adds(21, 2, 0)), h.spin_bundle(0x20)),
        terminal_ip=0x20))
    if normal.exception_pending or (normal.gr[20], normal.gr[21]) != (1, 2):
        raise AssertionError("sequential slot completion changed IP/RI ordering")

    program, _pfs = h.typed_return_trap_program(
        h.IA64_PSR_IC | h.IA64_PSR_TB, h.IA64_TAKEN_BRANCH_TRAP_VECTOR)
    trap = h.run_program(qemu, program, typed_return_traces=((0xA0, 3),),
                         one_bundle_per_tb=True)
    expected_isr = (2 << h.IA64_ISR_EI_SHIFT) | 4
    if (trap.exception_kind != "taken-branch-trap" or trap.cr_iip != 0x100 or
            trap.cr_iipa != 0xA0 or trap.cr_isr != expected_isr):
        raise AssertionError("taken branch trap lost target IP/RI attribution")

    timer = h.run_program(qemu, h.timer_external_interrupt_rfi_program(),
                          typed_rfi_traces=(0x3010,), one_bundle_per_tb=True)
    if (timer.ip != 0xA0 or timer.gr[20] != 1 or timer.gr[15] != 0x40 or
            timer.exception_kind != "external-interrupt" or
            timer.exception_vector != 0x3000):
        raise AssertionError("external interruption/RFI lost resume state")
    return "sequential completion, taken-branch trap, external interruption, and RFI preserve exact IP/RI"


def test_page_tb_boundary_equivalence(h: ModuleType, qemu: Path) -> str:
    first = h.test_typed_group_tb_continuation(qemu)
    second = h.test_page_crossing_overlay_continuation(qemu)
    return "TB segmentation and page crossing are equivalent: " + first + "; " + second


PROBES = (
    test_legal_template_equivalence,
    test_long_immediate_construction,
    test_template_and_placement_legality,
    test_ignored_and_reserved_fields,
    test_ip_ri_transition_matrix,
    test_ri_entry_resume_matrix,
    test_page_tb_boundary_equivalence,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args(argv)
    root, qemu = args.source_root.resolve(), args.binary.resolve()
    h = load_module(root / "tests/unit/test-ia64-full-tcg.py",
                    "_ia64_decoder_bundle_harness")
    print("TAP version 13")
    print(f"1..{len(PROBES)}")
    failures = 0
    for index, probe in enumerate(PROBES, 1):
        try:
            detail = probe(h, qemu)
            print(f"ok {index} - {probe.__name__}")
            print(f"# {detail}")
        except Exception as exc:
            failures += 1
            print(f"not ok {index} - {probe.__name__}")
            for line in str(exc).splitlines():
                print("# " + line)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
