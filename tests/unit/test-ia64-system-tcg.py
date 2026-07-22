#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""No-OS architectural gates for the IA-64 system/control TCG tranche.

The large matrices are generated from ``ia64_system_tcg_spec``.  They use the
generic full-TCG loader/HMP harness, but all expected values, fault classes and
raw system encodings are defined here rather than copied from the interpreter.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Dict, Iterable, List, Sequence, Tuple


sys.path.insert(0, str(Path(__file__).resolve().parent))
from ia64_system_tcg_spec import (  # noqa: E402
    SPEC_BY_OPCODE,
    SYSTEM_OPCODE_SPECS,
    SYSTEM_OPCODES,
    SystemOpcodeSpec,
    bitfield,
    br_ia,
    brp,
    break_m,
    encode_system_opcode,
    m_mask,
    m_serial,
    m_system,
    mov_immar,
)


U64_MASK = (1 << 64) - 1
GENERAL_VECTOR = 0x5400
NAT_VECTOR = 0x5600
BREAK_VECTOR = 0x2C00
ALT_DTLB_VECTOR = 0x1000
ALT_ITLB_VECTOR = 0x0C00
DEBUG_VECTOR = 0x5900
UNALIGNED_VECTOR = 0x5A00
INSTRUCTION_KEY_MISS_VECTOR = 0x1800
DATA_KEY_MISS_VECTOR = 0x1C00
KEY_PERMISSION_VECTOR = 0x5100
PSR_BE = 1 << 1
PSR_AC = 1 << 3
PSR_IC = 1 << 13
PSR_I = 1 << 14
PSR_PK = 1 << 15
PSR_DT = 1 << 17
PSR_DI = 1 << 22
PSR_SI = 1 << 23
PSR_DB = 1 << 24
PSR_IT = 1 << 36
PSR_BN = 1 << 44
PSR_CPL_SHIFT = 32
AR_RSC = 16
AR_BSP = 17
AR_BSPSTORE = 18
AR_RNAT = 19
AR_CCV = 32
AR_UNAT = 36
AR_FPSR = 40
AR_ITC = 44
AR_RUC = 45
AR_PFS = 64
AR_LC = 65
AR_EC = 66
CR_IFA = 20
CR_ITIR = 21
CR_IIM = 24
CR_IVR = 65
CR_ITM = 1
CR_IPSR = 16
CR_IIP = 19
CR_ITV = 72
ISR_CODE_MASK = 0xFFFF
ISR_X = 1 << 32
ISR_W = 1 << 33
ISR_R = 1 << 34
ISR_NA = 1 << 35
ISR_NI = 1 << 39
ISR_PRIVILEGED_OPERATION = 0x10
ISR_PRIVILEGED_REGISTER = 0x20
ISR_RESERVED_REGISTER_FIELD = 0x30
ISR_DISABLED_ISA_TRANSITION = 0x40
PKR_MASK = 0x00000000FFFFFF0F

# Intel SDM Vol. 3, itr/itc operation pseudocode: PSR.ic == 1 takes
# Illegal Operation before privilege, operand-NaT, and reserved-field checks.
# Tests for those lower-priority paths must therefore disable collection and
# expect ISR.ni rather than architected CR.IIP/CR.IIPA collection.
IC_CLEAR_INSERT_OPCODES = frozenset({
    "IA64_OP_ITR_D", "IA64_OP_ITR_I", "IA64_OP_ITC_D", "IA64_OP_ITC_I",
})


class TestFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)


def load_harness(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("ia64_full_tcg_harness", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import IA-64 harness from {}".format(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def movl_bundle(harness: ModuleType, address: int, reg: int, value: int):
    value &= U64_MASK
    l_slot = (value >> 22) & ((1 << 41) - 1)
    x_slot = (
        bitfield(reg, 6, 7) | bitfield(value & 0x7F, 13, 7)
        | bitfield((value >> 21) & 1, 21, 1)
        | bitfield((value >> 16) & 0x1F, 22, 5)
        | bitfield((value >> 7) & 0x1FF, 27, 9)
        | bitfield((value >> 63) & 1, 36, 1) | bitfield(6, 37, 4)
    )
    return harness.Bundle(address, 0x05, harness.nop_m(), l_slot, x_slot)


def opcode_bundle(harness: ModuleType, address: int, spec: SystemOpcodeSpec,
                  raw: int):
    if spec.unit == "M":
        if spec.must_end_group:
            # M_MI supplies the architecturally mandatory stop directly after
            # slot 0.  Slot 1 is an M slot and begins the following group.
            return harness.Bundle(address, 0x0B, raw, harness.nop_m(),
                                  harness.nop_i())
        return harness.Bundle(address, 0x01, raw, harness.nop_i(),
                              harness.nop_i())
    if spec.unit == "I":
        return harness.Bundle(address, 0x01, harness.nop_m(), raw,
                              harness.nop_i())
    if spec.unit == "B":
        return harness.Bundle(address, 0x11, harness.nop_m(), harness.nop_i(),
                              raw)
    raise ValueError("unsupported system test unit: " + spec.unit)


def raw_bundle(harness: ModuleType, address: int, unit: str, raw: int):
    synthetic = SystemOpcodeSpec("raw", "raw", unit, True, "none", "none",
                                 "continue", "focused")
    return opcode_bundle(harness, address, synthetic, raw)


def test_predicated_admission(harness: ModuleType, qemu: Path) -> str:
    """Every predicable row must admit while a poisoned false qp suppresses it."""
    bundles: List[object] = [movl_bundle(harness, 0x10, 20,
                                        0xBAD0BAD0BAD0BAD0)]
    address = 0x20
    traced: List[int] = []
    covered: List[str] = []
    for spec in SYSTEM_OPCODE_SPECS:
        if not spec.predicable:
            continue
        raw = encode_system_opcode(spec.opcode, qp=1)
        bundles.append(opcode_bundle(harness, address, spec, raw))
        traced.append(address)
        covered.append(spec.opcode)
        address += 0x10
    bundles.append(harness.spin_bundle(address))
    program = harness.Program(
        name="57-row system plane false-predicate admission",
        bundles=tuple(bundles), terminal_ip=address,
    )
    snapshot = harness.run_program(
        qemu, program, typed_direct_trace_ips=tuple(traced)
    )
    require(snapshot.gr[20] == 0xBAD0BAD0BAD0BAD0,
            "false system qualifier modified the poisoned destination")
    require(not snapshot.exception_pending,
            "false system qualifier raised an architectural fault")
    require(snapshot.psr == 0,
            "false system qualifier changed processor/user-mask state")
    require(len(covered) == 51,
            "predicated system admission covered {} rows, not 51".format(
                len(covered)))
    return "51 predicable rows admitted with fault and side effects suppressed"


def test_control_rows(harness: ModuleType, qemu: Path) -> str:
    """Exercise safe unpredicated BSW/EPC/BRP behavior and bank visibility."""
    bundles = (
        harness.Bundle(0x10, 0x01, harness.nop_m(),
                       harness.adds(16, 0x111, 0), harness.nop_i()),
        raw_bundle(harness, 0x20, "B", encode_system_opcode("IA64_OP_BSW1")),
        harness.Bundle(0x30, 0x01, harness.nop_m(),
                       harness.adds(16, 0x222, 0), harness.nop_i()),
        harness.Bundle(0x40, 0x01, harness.nop_m(),
                       harness.adds(40, 0, 16), harness.nop_i()),
        # The reference guest firmware verifies its SAL bank switch through
        # mov =psr before entering an EFI image.  Preserve that ABI explicitly.
        raw_bundle(harness, 0x50, "M", m_system(0x25, r1=41)),
        raw_bundle(harness, 0x60, "B", encode_system_opcode("IA64_OP_BSW0")),
        raw_bundle(harness, 0x70, "B", encode_system_opcode("IA64_OP_EPC")),
        raw_bundle(harness, 0x80, "B", encode_system_opcode("IA64_OP_BRP")),
        raw_bundle(harness, 0x90, "B", brp(False)),
        raw_bundle(harness, 0xA0, "B", brp(False, return_form=True)),
        harness.spin_bundle(0xB0),
    )
    snapshot = harness.run_program(
        qemu,
        harness.Program(name="BSW EPC BRP control semantics", bundles=bundles,
                        terminal_ip=0xB0),

        typed_direct_trace_ips=(0x20, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0),
    )
    require(snapshot.gr[40] == 0x222,
            "bank-1 value was not visible between BSW.1 and BSW.0")
    require(snapshot.gr[16] == 0x111,
            "BSW.0 did not restore the retained bank-0 r16")
    require(snapshot.gr[41] & PSR_BN,
            "MOV_PSRGR did not expose the firmware-visible bank selector")
    require(((snapshot.psr >> PSR_CPL_SHIFT) & 3) == 0,
            "EPC with instruction translation disabled did not select CPL0")
    return "BSW bank retention, IT-off EPC and architectural BRP no-op pass"


@dataclasses.dataclass
class MoveProgram:
    program: object
    expected: Dict[int, int]
    trace_ips: Tuple[int, ...]
    current_ip_reg: int


def build_move_roundtrip(harness: ModuleType) -> MoveProgram:
    bundles: List[object] = []
    trace: List[int] = []
    expected: Dict[int, int] = {}
    address = 0x10

    def emit_movl(reg: int, value: int) -> None:
        nonlocal address
        bundles.append(movl_bundle(harness, address, reg, value))
        address += 0x10

    def emit_m(raw: int) -> int:
        nonlocal address
        here = address
        bundles.append(raw_bundle(harness, address, "M", raw))
        trace.append(address)
        address += 0x10
        return here

    def emit_serial(instruction: bool = False) -> None:
        emit_m(m_serial(0x31 if instruction else 0x30))

    # Poison every system-read destination first.  Each subsequent read must
    # overwrite both the value and its NaT, rather than merely inheriting the
    # reset state where all destination NaTs happen to be clear.
    emit_movl(30, 1)
    emit_movl(31, 0x1000)
    bundles.append(harness.Bundle(address, 0x01,
                                  harness.mov_m_grar(AR_UNAT, 30),
                                  harness.nop_i(), harness.nop_i()))
    address += 0x10
    for destination in (7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
                        18, 19, 20, 21):
        bundles.append(harness.Bundle(address, 0x01,
                                      harness.ld8_fill(destination, 31),
                                      harness.nop_i(), harness.nop_i()))
        address += 0x10

    # MOV_IMMAR, followed by the already-typed AR-to-GR instruction.
    bundles.append(raw_bundle(harness, address, "I",
                              mov_immar(AR_LC, 0x2A, unit="I")))
    trace.append(address)
    address += 0x10
    bundles.append(harness.Bundle(address, 0x03, harness.nop_m(),
                                  harness.mov_argr(8, AR_LC),
                                  harness.nop_i()))
    address += 0x10
    expected[8] = 0x2A

    # CR.IFA write/read.
    emit_movl(2, 0x12345000)
    emit_m(m_system(0x2C, r2=2, r3=CR_IFA))
    emit_serial()
    emit_m(m_system(0x24, r1=9, r3=CR_IFA))
    expected[9] = 0x12345000

    # Read PSR, then restore its architected lower part from a full saved PSR
    # image.  MOV PSR.L consumes only bits 31:0; Linux legitimately leaves
    # high PSR.it/PSR.bn bits in the source GR while installing boot ITRs.
    emit_m(m_mask(4, PSR_AC))
    emit_m(m_system(0x25, r1=7))
    emit_movl(2, PSR_BN | PSR_IT | PSR_AC)
    emit_m(m_system(0x2D, r2=2))
    emit_serial()
    emit_m(m_system(0x25, r1=10))
    expected[7] = PSR_AC
    expected[10] = PSR_AC

    rr_value = 1 | (12 << 2) | (0x123 << 8)
    emit_movl(2, rr_value)
    emit_movl(3, 7 << 61)
    emit_m(m_system(0x00, r2=2, r3=3))
    emit_serial(instruction=True)
    emit_m(m_system(0x10, r1=11, r3=3))
    expected[11] = rr_value

    # All indexed banks use index zero so implementation-dependent bank sizes
    # do not weaken the semantic golden.
    emit_movl(3, 0)
    bank_rows = (
        (0x03, 0x13, 12, 0x0000000000012301,
         0x0000000000012301),  # PKR
        (0x02, 0x12, 14, 0x0000000000001234,
         0x0000000000001234),  # IBR
        (0x01, 0x11, 15, 0x0000000000005678,
         0x0000000000005678),  # DBR
        (0x04, 0x14, 16, 0x00000000000009AB,
         0x00000000000000A1),  # PMC0 architected writable bits
        (0x05, 0x15, 17, 0x0000000000000DEF,
         0x0000000000000000),  # PMD0 is not implemented
    )
    for write_x6, read_x6, destination, value, readback in bank_rows:
        emit_movl(2, value)
        emit_m(m_system(write_x6, r2=2, r3=3))
        if write_x6 == 0x02:       # IBR affects instruction breakpoints.
            emit_serial(instruction=True)
        elif write_x6 in {0x03, 0x01}:  # PKR/DBR affect data access.
            emit_serial()
        emit_m(m_system(read_x6, r1=destination, r3=3))
        expected[destination] = readback

    # User mask is independently writable at every CPL.
    emit_movl(2, PSR_BE)
    emit_m(m_system(0x29, r2=2))
    emit_m(m_system(0x21, r1=13))
    expected[13] = PSR_BE

    emit_m(m_system(0x17, r1=18, r2=0, r3=3))
    expected[18] = 0x49656E69756E6547  # CPUID[0], "GenuineI"
    emit_m(m_system(0x20, r1=19, r2=0x55, r3=3)
           | bitfield(1, 36, 1))
    expected[19] = 0  # DAHR reset value, implemented bits 10:0

    msr_value = 0x123456789ABCDEF0
    emit_movl(2, msr_value)
    emit_m(m_system(0x06, r2=2, r3=3))
    emit_serial()
    emit_m(m_system(0x16, r1=20, r2=0, r3=3))
    expected[20] = msr_value

    current_ip = address
    bundles.append(raw_bundle(harness, address, "I",
                              encode_system_opcode(
                                  "IA64_OP_MOV_CURRENT_IP", r1=21)))
    trace.append(address)
    address += 0x10
    expected[21] = current_ip
    bundles.append(harness.spin_bundle(address))
    return MoveProgram(
        harness.Program(name="system register read/write round trips",
                        bundles=tuple(bundles), terminal_ip=address,
                        data=(harness.DataWord(0x1000,
                                               0xBAD0BAD0BAD0BAD0, 8),)),
        expected, tuple(trace), 21,
    )


def test_move_roundtrips(harness: ModuleType, qemu: Path) -> str:
    matrix = build_move_roundtrip(harness)
    snapshot = harness.run_program(
        qemu, matrix.program,
        typed_direct_trace_ips=matrix.trace_ips,
    )
    for reg, expected in matrix.expected.items():
        require(snapshot.gr[reg] == expected,
                "system move r{} expected 0x{:016x}, got 0x{:016x}".format(
                    reg, expected, snapshot.gr[reg]))
        require(not (snapshot.nat_low & (1 << reg)),
                "system read did not clear r{} NaT".format(reg))
    require(snapshot.gr[10] == snapshot.gr[7],
            "MOV_GRPSR/MOV_PSRGR did not preserve the readable PSR part")
    require(not (snapshot.nat_low & ((1 << 7) | (1 << 10))),
            "MOV_PSRGR did not clear a PSR destination NaT")
    return "all 24 AR/CR/system-register move rows match independent goldens"


def performance_register_domain_program(harness: ModuleType, bank: str):
    if bank == "pmc":
        write_x6, read_x6 = 0x04, 0x14
        expected_changes = {0: 0xF1, 1: 0, 4: 0xFF7F, 8: 0}
    elif bank == "pmd":
        write_x6, read_x6 = 0x05, 0x15
        expected_changes = {0: 0, 4: (1 << 60) - 1, 8: 0}
    else:
        raise ValueError("unknown performance register bank: " + bank)

    bundles: List[object] = [
        movl_bundle(harness, 0x10, 2, U64_MASK),
        harness.Bundle(0x20, 0x01, harness.nop_m(),
                       harness.adds(3, 0, 0), harness.adds(20, 0, 0)),
    ]
    address = 0x30
    for index in range(256):
        if index in expected_changes:
            bundles.append(movl_bundle(
                harness, address, 5, expected_changes[index]
            ))
            address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(write_x6, r2=2, r3=3)
        ))
        address += 0x10
        bundles.append(raw_bundle(harness, address, "M", m_serial(0x30)))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(read_x6, r1=4, r3=3)
        ))
        address += 0x10
        bundles.append(harness.Bundle(
            address, 0x01, harness.nop_m(),
            harness.cmp_rr(1, 2, 4, 5, "eq"), harness.nop_i()
        ))
        address += 0x10
        bundles.append(harness.Bundle(
            address, 0x01, harness.nop_m(),
            harness.adds(20, 1, 20, qp=2), harness.adds(3, 1, 3)
        ))
        address += 0x10
    bundles.append(harness.spin_bundle(address))
    return harness.Program(
        name="{} complete selector domain".format(bank.upper()),
        bundles=tuple(bundles), terminal_ip=address,
    )


def test_performance_register_selector_domains(harness: ModuleType,
                                               qemu: Path) -> str:
    for bank in ("pmc", "pmd"):
        program = performance_register_domain_program(harness, bank)
        snapshot = harness.run_program(qemu, program, compact_loader=True)
        require(not snapshot.exception_pending,
                bank.upper() + " selector matrix raised an exception")
        require(snapshot.gr[3] == 256,
                bank.upper() + " selector matrix did not cover 256 indices")
        require(snapshot.gr[20] == 0,
                "{} selector matrix found {} mismatches".format(
                    bank.upper(), snapshot.gr[20]))
    return ("all 256 PMC and 256 PMD selectors obey independent implemented, "
            "masked, ignored, and zero-read expectations")


def cpuid_selector_domain_program(harness: ModuleType):
    expected = (
        0x49656E69756E6547,
        0x000000006C65746E,
        0,
        0x0000000200000004,
        0x0000000300000001,
    )
    bundles: List[object] = [
        raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
        raw_bundle(harness, 0x20, "M", m_serial(0x31)),
        harness.Bundle(0x30, 0x01, harness.nop_m(),
                       harness.adds(8, 0, 0), harness.adds(9, 0, 0)),
    ]
    address = 0x40
    for selector, destination in enumerate(range(16, 21)):
        bundles.append(movl_bundle(harness, address, 3, selector))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x17, r1=destination, r3=3)
        ))
        address += 0x10

    for selector, destination in ((0x100, 21), ((1 << 63) | 4, 22)):
        bundles.append(movl_bundle(harness, address, 3, selector))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x17, r1=destination, r3=3)
        ))
        address += 0x10

    for selector in range(5, 256):
        bundles.append(movl_bundle(harness, address, 3, selector))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x17, r1=5, r3=3)
        ))
        address += 0x10

    terminal_ip = address
    bundles.extend((
        harness.spin_bundle(terminal_ip),
        raw_bundle(harness, GENERAL_VECTOR, "M",
                   harness.mov_crgr(10, 17)),
        raw_bundle(harness, GENERAL_VECTOR + 0x10, "I",
                   harness.extr(12, 10, 0, 16)),
        harness.Bundle(GENERAL_VECTOR + 0x20, 0x01, harness.nop_m(),
                       harness.cmp_imm(1, 2, ISR_RESERVED_REGISTER_FIELD,
                                       12, "eq"), harness.nop_i()),
        harness.Bundle(GENERAL_VECTOR + 0x30, 0x01, harness.nop_m(),
                       harness.adds(8, 1, 8, qp=2),
                       harness.adds(9, 1, 9)),
        raw_bundle(harness, GENERAL_VECTOR + 0x40, "M",
                   harness.mov_crgr(11, CR_IIP)),
        harness.Bundle(GENERAL_VECTOR + 0x50, 0x01, harness.nop_m(),
                       harness.adds(11, 16, 11), harness.nop_i()),
        raw_bundle(harness, GENERAL_VECTOR + 0x60, "M",
                   harness.mov_grcr(CR_IIP, 11)),
        harness.Bundle(GENERAL_VECTOR + 0x70, 0x11, harness.nop_m(),
                       harness.nop_i(), harness.rfi()),
    ))
    return harness.Program(
        name="CPUID fixed and reserved selector domain",
        bundles=tuple(bundles), terminal_ip=terminal_ip,
    ), expected


def test_cpuid_selector_domain(harness: ModuleType, qemu: Path) -> str:
    program, expected = cpuid_selector_domain_program(harness)
    snapshot = harness.run_program(qemu, program, compact_loader=True)
    require(snapshot.ip == program.terminal_ip,
            "CPUID selector-domain program stopped at 0x{:x} after {} faults"
            .format(snapshot.ip, snapshot.gr[9]))
    require(snapshot.exception_pending and
            snapshot.exception_kind == "general-exception" and
            snapshot.exception_vector == GENERAL_VECTOR,
            "CPUID traversal did not retain the final fault observation")
    require(snapshot.gr[16:21] == expected,
            "CPUID fixed-register profile mismatch: {}".format(
                tuple("0x{:016x}".format(value)
                      for value in snapshot.gr[16:21])))
    require(snapshot.gr[21] == expected[0] and snapshot.gr[22] == expected[4],
            "CPUID indirect access did not ignore selector bits above bit 7")
    require(snapshot.gr[9] == 251,
            "CPUID reserved domain raised {} faults, expected 251".format(
                snapshot.gr[9]))
    require(snapshot.gr[8] == 0,
            "CPUID reserved domain produced {} wrong ISR codes".format(
                snapshot.gr[8]))
    return ("CPUID0-4 match the synthetic profile, high selector bits are "
            "ignored, and every selector 5-255 faults and resumes exactly once")


def debug_register_selector_domain_program(harness: ModuleType, bank: str):
    if bank == "ibr":
        write_x6, read_x6 = 0x02, 0x12
        ignored_mask = 7 << 60
        enabled_bits = 1 << 63
        serialization = 0x31
    elif bank == "dbr":
        write_x6, read_x6 = 0x01, 0x11
        ignored_mask = 3 << 60
        enabled_bits = (1 << 63) | (1 << 62)
        serialization = 0x30
    else:
        raise ValueError("unknown debug-register bank: " + bank)

    def register_value(index: int) -> int:
        if index % 2 == 0:
            return 0x1000000000000000 | (index << 12)
        return enabled_bits | (((index // 2) + 1) << 56) | \
            0x0000FFFFFFFFFF00 | index

    bundles: List[object] = [
        raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
        raw_bundle(harness, 0x20, "M", m_serial(0x31)),
        harness.Bundle(0x30, 0x01, harness.nop_m(),
                       harness.adds(8, 0, 0), harness.adds(9, 0, 0)),
        harness.Bundle(0x40, 0x01, harness.nop_m(),
                       harness.adds(20, 0, 0), harness.nop_i()),
    ]
    address = 0x50

    # Give every implemented register a distinct independently derived image.
    # Reading all images back only after the bank is populated detects aliasing
    # between any pair, rather than merely proving one selector at a time.
    for index in range(16):
        bundles.append(movl_bundle(
            harness, address, 2, register_value(index)
        ))
        address += 0x10
        bundles.append(movl_bundle(harness, address, 3, index))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(write_x6, r2=2, r3=3)
        ))
        address += 0x10
    bundles.append(raw_bundle(
        harness, address, "M", m_serial(serialization)
    ))
    address += 0x10

    for index in range(16):
        bundles.append(movl_bundle(harness, address, 3, index))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(read_x6, r1=4, r3=3)
        ))
        address += 0x10
        bundles.append(movl_bundle(
            harness, address, 5, register_value(index)
        ))
        address += 0x10
        bundles.append(harness.Bundle(
            address, 0x01, harness.nop_m(),
            harness.cmp_rr(1, 2, 4, 5, "eq"), harness.nop_i()
        ))
        address += 0x10
        bundles.append(harness.Bundle(
            address, 0x01, harness.nop_m(),
            harness.adds(20, 1, 20, qp=2), harness.nop_i()
        ))
        address += 0x10

    # An all-ones write independently checks every ignored control bit.  The
    # two selectors deliberately differ above bit 7 and must both select one.
    alias_value = U64_MASK & ~ignored_mask
    bundles.append(movl_bundle(harness, address, 2, U64_MASK))
    address += 0x10
    bundles.append(movl_bundle(harness, address, 3, 0x101))
    address += 0x10
    bundles.append(raw_bundle(
        harness, address, "M", m_system(write_x6, r2=2, r3=3)
    ))
    address += 0x10
    bundles.append(raw_bundle(
        harness, address, "M", m_serial(serialization)
    ))
    address += 0x10
    bundles.append(movl_bundle(harness, address, 3, (1 << 63) | 1))
    address += 0x10
    bundles.append(raw_bundle(
        harness, address, "M", m_system(read_x6, r1=4, r3=3)
    ))
    address += 0x10
    bundles.append(movl_bundle(harness, address, 5, alias_value))
    address += 0x10
    bundles.append(harness.Bundle(
        address, 0x01, harness.nop_m(),
        harness.cmp_rr(1, 2, 4, 5, "eq"), harness.nop_i()
    ))
    address += 0x10
    bundles.append(harness.Bundle(
        address, 0x01, harness.nop_m(),
        harness.adds(20, 1, 20, qp=2), harness.nop_i()
    ))
    address += 0x10

    # Both access directions must reject every low-byte selector outside the
    # sixteen-register product bank.  The common handler validates the exact
    # Reserved Register/Field ISR code and resumes at the following bundle.
    for selector in range(16, 256):
        bundles.append(movl_bundle(harness, address, 3, selector))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(read_x6, r1=4, r3=3)
        ))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(write_x6, r2=2, r3=3)
        ))
        address += 0x10

    terminal_ip = address
    require(terminal_ip < GENERAL_VECTOR,
            "debug-register selector program overlaps General vector")
    bundles.extend((
        harness.spin_bundle(terminal_ip),
        raw_bundle(harness, GENERAL_VECTOR, "M",
                   harness.mov_crgr(10, 17)),
        raw_bundle(harness, GENERAL_VECTOR + 0x10, "I",
                   harness.extr(12, 10, 0, 16)),
        harness.Bundle(GENERAL_VECTOR + 0x20, 0x01, harness.nop_m(),
                       harness.cmp_imm(1, 2, ISR_RESERVED_REGISTER_FIELD,
                                       12, "eq"), harness.nop_i()),
        harness.Bundle(GENERAL_VECTOR + 0x30, 0x01, harness.nop_m(),
                       harness.adds(8, 1, 8, qp=2),
                       harness.adds(9, 1, 9)),
        raw_bundle(harness, GENERAL_VECTOR + 0x40, "M",
                   harness.mov_crgr(11, CR_IIP)),
        harness.Bundle(GENERAL_VECTOR + 0x50, 0x01, harness.nop_m(),
                       harness.adds(11, 16, 11), harness.nop_i()),
        raw_bundle(harness, GENERAL_VECTOR + 0x60, "M",
                   harness.mov_grcr(CR_IIP, 11)),
        harness.Bundle(GENERAL_VECTOR + 0x70, 0x11, harness.nop_m(),
                       harness.nop_i(), harness.rfi()),
    ))
    return harness.Program(
        name="{} complete selector domain".format(bank.upper()),
        bundles=tuple(bundles), terminal_ip=terminal_ip,
    )


def test_debug_register_selector_domains(harness: ModuleType,
                                         qemu: Path) -> str:
    for bank in ("ibr", "dbr"):
        program = debug_register_selector_domain_program(harness, bank)
        snapshot = harness.run_program(qemu, program, compact_loader=True)
        require(snapshot.ip == program.terminal_ip,
                "{} selector traversal stopped at 0x{:x}".format(
                    bank.upper(), snapshot.ip))
        require(snapshot.exception_pending and
                snapshot.exception_kind == "general-exception" and
                snapshot.exception_vector == GENERAL_VECTOR,
                bank.upper() + " traversal did not retain its final fault")
        require(snapshot.gr[9] == 480,
                "{} reserved selectors raised {} faults, expected 480".format(
                    bank.upper(), snapshot.gr[9]))
        require(snapshot.gr[8] == 0,
                "{} reserved selectors produced {} wrong ISR codes".format(
                    bank.upper(), snapshot.gr[8]))
        require(snapshot.gr[20] == 0,
                "{} implemented bank produced {} value/alias mismatches".format(
                    bank.upper(), snapshot.gr[20]))
    return ("all 16 IBRs and DBRs are distinct with exact control masks; high "
            "selector bits are ignored and all 480 reserved read/write forms "
            "fault and resume per bank")


def protection_key_selector_domain_program(harness: ModuleType):
    def register_value(index: int) -> int:
        return ((0x100 + index) << 8) | 1 | ((index & 7) << 1)

    bundles: List[object] = [
        raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
        raw_bundle(harness, 0x20, "M", m_serial(0x31)),
        harness.Bundle(0x30, 0x01, harness.nop_m(),
                       harness.adds(8, 0, 0), harness.adds(9, 0, 0)),
        harness.Bundle(0x40, 0x01, harness.nop_m(),
                       harness.adds(20, 0, 0), harness.nop_i()),
    ]
    address = 0x50

    for index in range(16):
        bundles.append(movl_bundle(
            harness, address, 2, register_value(index)
        ))
        address += 0x10
        bundles.append(movl_bundle(harness, address, 3, index))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x03, r2=2, r3=3)
        ))
        address += 0x10
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x30)))
    address += 0x10
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x31)))
    address += 0x10

    for index in range(16):
        bundles.append(movl_bundle(harness, address, 3, index))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x13, r1=4, r3=3)
        ))
        address += 0x10
        bundles.append(movl_bundle(
            harness, address, 5, register_value(index)
        ))
        address += 0x10
        bundles.append(harness.Bundle(
            address, 0x01, harness.nop_m(),
            harness.cmp_rr(1, 2, 4, 5, "eq"), harness.nop_i()
        ))
        address += 0x10
        bundles.append(harness.Bundle(
            address, 0x01, harness.nop_m(),
            harness.adds(20, 1, 20, qp=2), harness.nop_i()
        ))
        address += 0x10

    # Both high-bit forms select PKR15.  The all-implemented-bits value also
    # checks v/wd/rd/xd and every one of the product's 24 key bits.
    bundles.append(movl_bundle(harness, address, 2, PKR_MASK))
    address += 0x10
    bundles.append(movl_bundle(harness, address, 3, 0x10F))
    address += 0x10
    bundles.append(raw_bundle(
        harness, address, "M", m_system(0x03, r2=2, r3=3)
    ))
    address += 0x10
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x30)))
    address += 0x10
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x31)))
    address += 0x10
    bundles.append(movl_bundle(harness, address, 3, (1 << 63) | 15))
    address += 0x10
    bundles.append(raw_bundle(
        harness, address, "M", m_system(0x13, r1=4, r3=3)
    ))
    address += 0x10
    bundles.append(movl_bundle(harness, address, 5, PKR_MASK))
    address += 0x10
    bundles.append(harness.Bundle(
        address, 0x01, harness.nop_m(),
        harness.cmp_rr(1, 2, 4, 5, "eq"), harness.nop_i()
    ))
    address += 0x10
    bundles.append(harness.Bundle(
        address, 0x01, harness.nop_m(),
        harness.adds(20, 1, 20, qp=2), harness.nop_i()
    ))
    address += 0x10

    # Every nonexistent low-byte selector must fault in both directions.
    for selector in range(16, 256):
        bundles.append(movl_bundle(harness, address, 3, selector))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x13, r1=4, r3=3)
        ))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x03, r2=2, r3=3)
        ))
        address += 0x10

    # PKR15 is the commitment sentinel for every reserved-field write.
    bundles.append(movl_bundle(harness, address, 3, 15))
    address += 0x10
    for bit in tuple(range(4, 8)) + tuple(range(32, 64)):
        bundles.append(movl_bundle(harness, address, 2, 1 << bit))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x03, r2=2, r3=3)
        ))
        address += 0x10
    bundles.append(raw_bundle(
        harness, address, "M", m_system(0x13, r1=4, r3=3)
    ))
    address += 0x10
    bundles.append(movl_bundle(harness, address, 5, PKR_MASK))
    address += 0x10
    bundles.append(harness.Bundle(
        address, 0x01, harness.nop_m(),
        harness.cmp_rr(1, 2, 4, 5, "eq"), harness.nop_i()
    ))
    address += 0x10
    bundles.append(harness.Bundle(
        address, 0x01, harness.nop_m(),
        harness.adds(20, 1, 20, qp=2), harness.nop_i()
    ))
    address += 0x10

    terminal_ip = address
    require(terminal_ip < GENERAL_VECTOR,
            "PKR selector program overlaps General vector")
    bundles.extend((
        harness.spin_bundle(terminal_ip),
        raw_bundle(harness, GENERAL_VECTOR, "M",
                   harness.mov_crgr(10, 17)),
        raw_bundle(harness, GENERAL_VECTOR + 0x10, "I",
                   harness.extr(12, 10, 0, 16)),
        harness.Bundle(GENERAL_VECTOR + 0x20, 0x01, harness.nop_m(),
                       harness.cmp_imm(1, 2, ISR_RESERVED_REGISTER_FIELD,
                                       12, "eq"), harness.nop_i()),
        harness.Bundle(GENERAL_VECTOR + 0x30, 0x01, harness.nop_m(),
                       harness.adds(8, 1, 8, qp=2),
                       harness.adds(9, 1, 9)),
        raw_bundle(harness, GENERAL_VECTOR + 0x40, "M",
                   harness.mov_crgr(11, CR_IIP)),
        harness.Bundle(GENERAL_VECTOR + 0x50, 0x01, harness.nop_m(),
                       harness.adds(11, 16, 11), harness.nop_i()),
        raw_bundle(harness, GENERAL_VECTOR + 0x60, "M",
                   harness.mov_grcr(CR_IIP, 11)),
        harness.Bundle(GENERAL_VECTOR + 0x70, 0x11, harness.nop_m(),
                       harness.nop_i(), harness.rfi()),
    ))
    return harness.Program(
        name="PKR complete selector and field domain",
        bundles=tuple(bundles), terminal_ip=terminal_ip,
    )


def protection_key_uniqueness_program(harness: ModuleType):
    key = 0x654321 << 8
    first = key | 1 | 2
    second = key | 1 | 4
    invalid = key | 8
    final = key | 1 | 8
    bundles: List[object] = []
    address = 0x10

    def write(index: int, value: int) -> None:
        nonlocal address
        bundles.append(movl_bundle(harness, address, 2, value))
        address += 0x10
        bundles.append(movl_bundle(harness, address, 3, index))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M", m_system(0x03, r2=2, r3=3)
        ))
        address += 0x10

    def read(index: int, destination: int) -> None:
        nonlocal address
        bundles.append(movl_bundle(harness, address, 3, index))
        address += 0x10
        bundles.append(raw_bundle(
            harness, address, "M",
            m_system(0x13, r1=destination, r3=3)
        ))
        address += 0x10

    write(0, first)
    write(1, second)
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x30)))
    address += 0x10
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x31)))
    address += 0x10
    read(0, 20)
    read(1, 21)
    write(2, invalid)
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x30)))
    address += 0x10
    read(1, 22)
    read(2, 23)
    write(15, final)
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x30)))
    address += 0x10
    bundles.append(raw_bundle(harness, address, "M", m_serial(0x31)))
    address += 0x10
    read(0, 24)
    read(1, 25)
    read(2, 26)
    read(15, 27)
    bundles.append(harness.spin_bundle(address))
    expected = (first & ~1, second, second, invalid,
                first & ~1, second & ~1, invalid, final)
    return harness.Program(
        name="PKR duplicate-key invalidation",
        bundles=tuple(bundles), terminal_ip=address,
    ), expected


def test_protection_key_register_file(harness: ModuleType,
                                      qemu: Path) -> str:
    domain = protection_key_selector_domain_program(harness)
    snapshot = harness.run_program(qemu, domain, compact_loader=True)
    require(snapshot.ip == domain.terminal_ip,
            "PKR selector traversal stopped at 0x{:x}".format(snapshot.ip))
    require(snapshot.exception_pending and
            snapshot.exception_kind == "general-exception" and
            snapshot.exception_vector == GENERAL_VECTOR,
            "PKR traversal did not retain its final field fault")
    require(snapshot.gr[9] == 516,
            "PKR traversal raised {} faults, expected 516".format(
                snapshot.gr[9]))
    require(snapshot.gr[8] == 0 and snapshot.gr[20] == 0,
            "PKR traversal found {} ISR and {} value mismatches".format(
                snapshot.gr[8], snapshot.gr[20]))

    uniqueness, expected = protection_key_uniqueness_program(harness)
    result = harness.run_program(qemu, uniqueness)
    require(not result.exception_pending and result.gr[20:28] == expected,
            "PKR duplicate-key transition mismatch: {}".format(
                tuple("0x{:x}".format(value) for value in result.gr[20:28])))
    return ("all 16 PKRs are distinct; high selector bits are ignored; 480 "
            "reserved accesses and all 36 reserved field bits fault; valid "
            "duplicate keys invalidate only prior v bits")


def protection_key_data_program(harness: ModuleType, *, access: str,
                                initial_pkr: int, fault_vector: int | None,
                                enable_pk: bool = True):
    virtual = 0x8000
    physical = 0x4000
    key = 0x123456
    pte = physical | 0x661
    itir = (12 << 2) | (key << 8)
    repair = (key << 8) | 1
    stored = 0xCAFEBABE11223344
    bundles: List[object] = [
        movl_bundle(harness, 0x10, 2, pte),
        movl_bundle(harness, 0x20, 7, virtual),
        movl_bundle(harness, 0x30, 4, itir),
        movl_bundle(harness, 0x40, 5, stored),
        raw_bundle(harness, 0x50, "M",
                   m_system(0x2C, r2=7, r3=CR_IFA)),
        raw_bundle(harness, 0x60, "M",
                   m_system(0x2C, r2=4, r3=CR_ITIR)),
        opcode_bundle(harness, 0x70, SPEC_BY_OPCODE["IA64_OP_ITC_D"],
                      m_system(0x2E, r2=2)),
        raw_bundle(harness, 0x80, "M", m_serial(0x30)),
        movl_bundle(harness, 0x90, 2, initial_pkr),
        movl_bundle(harness, 0xA0, 3, 0),
        raw_bundle(harness, 0xB0, "M",
                   m_system(0x03, r2=2, r3=3)),
        raw_bundle(harness, 0xC0, "M", m_serial(0x30)),
        raw_bundle(harness, 0xD0, "M", m_serial(0x31)),
        raw_bundle(harness, 0xE0, "M",
                   m_mask(6, PSR_DT | PSR_IC |
                          (PSR_PK if enable_pk else 0))),
        raw_bundle(harness, 0xF0, "M", m_serial(0x31)),
    ]
    fault_ip = 0x100
    if access == "read":
        bundles.append(harness.Bundle(
            fault_ip, 0x01, harness.ld8(20, 7),
            harness.nop_i(), harness.nop_i()
        ))
        terminal_ip = 0x110
    elif access == "write":
        bundles.extend((
            harness.Bundle(fault_ip, 0x01, harness.st8(5, 7),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x110, 0x01, harness.ld8(20, 7),
                           harness.nop_i(), harness.nop_i()),
        ))
        terminal_ip = 0x120
    else:
        raise ValueError("unknown protection-key data access: " + access)
    bundles.append(harness.spin_bundle(terminal_ip))
    if fault_vector is not None:
        bundles.extend((
            movl_bundle(harness, fault_vector, 2, repair),
            movl_bundle(harness, fault_vector + 0x10, 3, 0),
            raw_bundle(harness, fault_vector + 0x20, "M",
                       m_system(0x03, r2=2, r3=3)),
            raw_bundle(harness, fault_vector + 0x30, "M", m_serial(0x30)),
            harness.Bundle(fault_vector + 0x40, 0x11, harness.nop_m(),
                           harness.nop_i(), harness.rfi()),
        ))
    return harness.Program(
        name="PKR {} {}".format(
            access, "bypass" if fault_vector is None else "repair"),
        bundles=tuple(bundles), terminal_ip=terminal_ip,
        data=(harness.DataWord(physical, 0x8877665544332211, 8),),
    ), fault_ip, virtual, stored


def protection_key_instruction_program(
        harness: ModuleType, *, initial_pkr: int,
        fault_vector: int | None, enable_pk: bool = True):
    virtual = 0x8000
    physical = 0x2000
    key = 0x123456
    itir = (12 << 2) | (key << 8)
    repair = (key << 8) | 1
    bundles: List[object] = []
    address = 0x10

    def emit_movl(reg: int, value: int) -> None:
        nonlocal address
        bundles.append(movl_bundle(harness, address, reg, value))
        address += 0x10

    def emit_raw(raw: int) -> None:
        nonlocal address
        bundles.append(raw_bundle(harness, address, "M", raw))
        address += 0x10

    def write_pkr(slot: int, value: int) -> None:
        emit_movl(9, value)
        emit_movl(3, slot)
        emit_raw(m_system(0x03, r2=9, r3=3))

    def install_itr(slot: int, mapped_virtual: int,
                    mapped_physical: int, mapped_itir: int) -> None:
        nonlocal address
        emit_movl(2, mapped_physical | 0x661)
        emit_movl(7, mapped_virtual)
        emit_movl(4, mapped_itir)
        emit_movl(3, slot)
        emit_raw(m_system(0x2C, r2=7, r3=CR_IFA))
        emit_raw(m_system(0x2C, r2=4, r3=CR_ITIR))
        bundles.append(opcode_bundle(
            harness, address, SPEC_BY_OPCODE["IA64_OP_ITR_I"],
            m_system(0x0F, r2=2, r3=3)
        ))
        address += 0x10

    write_pkr(0, initial_pkr)
    if fault_vector is not None:
        # Interruption delivery preserves PSR.it and PSR.pk.  Give the
        # handler page its own identity ITR and non-conflicting valid key so
        # the handler itself cannot recursively take a key or TLB fault.
        handler_key = 0xABCDEF
        write_pkr(1, (handler_key << 8) | 1)
    emit_raw(m_serial(0x30))
    emit_raw(m_serial(0x31))
    install_itr(0, virtual, physical, itir)
    if fault_vector is not None:
        handler_page = fault_vector & ~0xFFF
        install_itr(1, fault_vector, handler_page,
                    (12 << 2) | (handler_key << 8))

    emit_movl(8, PSR_IT | PSR_IC | (PSR_PK if enable_pk else 0))
    emit_raw(m_system(0x2C, r2=8, r3=CR_IPSR))
    emit_movl(7, virtual)
    emit_raw(m_system(0x2C, r2=7, r3=CR_IIP))
    entry_rfi_ip = address
    bundles.append(harness.Bundle(
        address, 0x11, harness.nop_m(), harness.nop_i(), harness.rfi()
    ))
    address += 0x10
    require(address < INSTRUCTION_KEY_MISS_VECTOR,
            "PKR instruction setup overlaps interruption vectors")
    bundles.extend((
        harness.Bundle(physical, 0x01, harness.nop_m(),
                       harness.adds(20, 0x5A, 0), harness.nop_i()),
        harness.Bundle(physical + 0x10, 0x11, harness.nop_m(),
                       harness.nop_i(),
                       harness.br_cond(virtual + 0x10, virtual + 0x10)),
    ))
    if fault_vector is not None:
        bundles.extend((
            movl_bundle(harness, fault_vector, 2, repair),
            movl_bundle(harness, fault_vector + 0x10, 3, 0),
            raw_bundle(harness, fault_vector + 0x20, "M",
                       m_system(0x03, r2=2, r3=3)),
            raw_bundle(harness, fault_vector + 0x30, "M", m_serial(0x31)),
            harness.Bundle(fault_vector + 0x40, 0x11, harness.nop_m(),
                           harness.nop_i(), harness.rfi()),
        ))
    return harness.Program(
        name="PKR instruction {} vector {}".format(
            "bypass" if fault_vector is None else "repair",
            "none" if fault_vector is None else "0x{:x}".format(
                fault_vector)),
        bundles=tuple(bundles), terminal_ip=virtual + 0x10,
    ), virtual, entry_rfi_ip


def test_protection_key_permissions(harness: ModuleType,
                                    qemu: Path) -> str:
    key = 0x123456 << 8
    data_cases = (
        ("read", key | 1 | 4, KEY_PERMISSION_VECTOR,
         "key-permission", ISR_R, 0x8877665544332211),
        ("write", key | 1 | 2, KEY_PERMISSION_VECTOR,
         "key-permission", ISR_W, 0xCAFEBABE11223344),
        ("read", (0x654321 << 8) | 1, DATA_KEY_MISS_VECTOR,
         "data-key-miss", ISR_R, 0x8877665544332211),
    )
    for access, pkr, vector, kind, isr_access, expected in data_cases:
        program, fault_ip, virtual, _stored = protection_key_data_program(
            harness, access=access, initial_pkr=pkr, fault_vector=vector
        )
        result = harness.run_program(
            qemu, program, one_bundle_per_tb=True,
            typed_rfi_traces=(vector + 0x40,),
        )
        require(result.ip == program.terminal_ip and result.gr[20] == expected,
                program.name + " did not repair, retry, and complete")
        require(result.exception_kind == kind and
                result.exception_vector == vector and
                result.cr_iip == fault_ip and result.cr_ifa == virtual and
                (result.cr_isr & (ISR_R | ISR_W | ISR_X)) == isr_access,
                program.name + " published wrong interruption metadata")

    instruction_cases = (
        (key | 1 | 8, KEY_PERMISSION_VECTOR,
         "key-permission"),
        ((0x654321 << 8) | 1, INSTRUCTION_KEY_MISS_VECTOR,
         "instruction-key-miss"),
    )
    for pkr, vector, kind in instruction_cases:
        program, virtual, entry_rfi_ip = protection_key_instruction_program(
            harness, initial_pkr=pkr, fault_vector=vector
        )
        result = harness.run_program(
            qemu, program, one_bundle_per_tb=True,
            typed_rfi_traces=(entry_rfi_ip, vector + 0x40),
        )
        require(result.ip == program.terminal_ip and result.gr[20] == 0x5A,
                program.name + " did not repair and execute mapped code")
        require(result.exception_kind == kind and
                result.exception_vector == vector and
                result.cr_iip == virtual and
                (result.cr_isr & (ISR_R | ISR_W | ISR_X)) == ISR_X,
                program.name + " published wrong fetch-fault metadata")

    data_bypass, _fault_ip, _virtual, _stored = protection_key_data_program(
        harness, access="read", initial_pkr=key | 1 | 4,
        fault_vector=None, enable_pk=False,
    )
    bypass = harness.run_program(qemu, data_bypass)
    require(not bypass.exception_pending and
            bypass.gr[20] == 0x8877665544332211,
            "PSR.pk=0 did not bypass data PKR checks")
    instruction_bypass, _virtual, entry_rfi_ip = (
        protection_key_instruction_program(
            harness, initial_pkr=key | 1 | 8,
            fault_vector=None, enable_pk=False,
        )
    )
    fetch = harness.run_program(
        qemu, instruction_bypass, typed_rfi_traces=(entry_rfi_ip,),
        one_bundle_per_tb=True,
    )
    require(not fetch.exception_pending and fetch.gr[20] == 0x5A,
            "PSR.pk=0 did not bypass instruction PKR checks")
    return ("read, write, and execute disables plus data/instruction key "
            "misses publish exact faults, repair through RFI, and PSR.pk=0 "
            "bypasses both translated access classes")


def pal_perf_mon_program(harness: ModuleType, buffer: int,
                         *, observe_buffer: bool):
    bundles: List[object] = [
        movl_bundle(harness, 0x10, 28, 15),
        movl_bundle(harness, 0x20, 29, buffer),
        harness.Bundle(0x30, 0x01, harness.nop_m(),
                       harness.adds(30, 0, 0), harness.adds(31, 0, 0)),
        harness.Bundle(0x40, 0x11, harness.nop_m(), harness.nop_i(),
                       harness.br_call(0x40, 0x8F000, 0)),
    ]
    address = 0x50
    if observe_buffer:
        bundles.append(movl_bundle(harness, address, 13, 0x1800))
        address += 0x10
        destinations = tuple(range(14, 28)) + (6, 7)
        for destination in destinations:
            bundles.append(harness.Bundle(
                address, 0x01, harness.ld8(destination, 13),
                harness.adds(13, 8, 13), harness.nop_i()
            ))
            address += 0x10
    bundles.append(harness.spin_bundle(address))
    return harness.Program(
        name="PAL_PERF_MON_INFO buffer 0x{:x}".format(buffer),
        bundles=tuple(bundles), terminal_ip=address,
        data=tuple(
            harness.DataWord(0x1800 + offset, 0xA5A5A5A5A5A5A5A5, 8)
            for offset in range(0, 128, 8)
        ),
    )


def test_pal_performance_monitor_info(harness: ModuleType, qemu: Path) -> str:
    valid = harness.run_program(
        qemu, pal_perf_mon_program(harness, 0x1800, observe_buffer=True)
    )
    observed = tuple(valid.gr[reg] for reg in tuple(range(14, 28)) + (6, 7))
    expected = (0xFF, 0, 0, 0, 0xF0) + (0,) * 11
    require(not valid.exception_pending and valid.gr[8] == 0,
            "valid PAL_PERF_MON_INFO call failed")
    require(valid.gr[9] == 4 | (60 << 8) and
            valid.gr[10] == 0 and valid.gr[11] == 0,
            "PAL_PERF_MON_INFO did not return packed generic/width metadata")
    require(observed == expected,
            "PAL_PERF_MON_INFO mask buffer mismatch: {}".format(
                tuple("0x{:x}".format(value) for value in observed)))

    invalid_status = U64_MASK - 1
    for buffer in (0, 0x1801):
        result = harness.run_program(
            qemu,
            pal_perf_mon_program(
                harness, buffer, observe_buffer=(buffer != 0)
            ),
        )
        require(not result.exception_pending and result.gr[8] == invalid_status,
                "PAL_PERF_MON_INFO accepted buffer 0x{:x}".format(buffer))
        require(result.gr[9] == 0 and result.gr[10] == 0 and
                result.gr[11] == 0,
                "invalid PAL_PERF_MON_INFO call returned payload data")
        if buffer != 0:
            observed_invalid = tuple(
                result.gr[reg] for reg in tuple(range(14, 28)) + (6, 7)
            )
            require(observed_invalid == (0xA5A5A5A5A5A5A5A5,) * 16,
                    "misaligned PAL buffer was modified")
    return ("PAL_PERF_MON_INFO packs four 60-bit pairs, publishes exact "
            "PMC/PMD masks, zeroes unadvertised event masks, and rejects "
            "null or misaligned buffers")


def pal_debug_info_program(harness: ModuleType, arg0: int, arg1: int,
                           arg2: int):
    return harness.Program(
        name="PAL_DEBUG_INFO args {:x}/{:x}/{:x}".format(arg0, arg1, arg2),
        bundles=(
            movl_bundle(harness, 0x10, 28, 11),
            movl_bundle(harness, 0x20, 29, arg0),
            movl_bundle(harness, 0x30, 30, arg1),
            movl_bundle(harness, 0x40, 31, arg2),
            harness.Bundle(0x50, 0x11, harness.nop_m(), harness.nop_i(),
                           harness.br_call(0x50, 0x8F000, 0)),
            harness.spin_bundle(0x60),
        ), terminal_ip=0x60,
    )


def test_pal_debug_info(harness: ModuleType, qemu: Path) -> str:
    valid = harness.run_program(
        qemu, pal_debug_info_program(harness, 0, 0, 0)
    )
    require(not valid.exception_pending and valid.gr[8] == 0,
            "valid PAL_DEBUG_INFO call failed")
    require((valid.gr[9], valid.gr[10], valid.gr[11]) == (8, 8, 0),
            "PAL_DEBUG_INFO did not publish eight IBR/DBR pairs")

    invalid_status = U64_MASK - 1
    for arguments in ((1, 0, 0), (0, 1, 0), (0, 0, 1)):
        result = harness.run_program(
            qemu, pal_debug_info_program(harness, *arguments)
        )
        require(not result.exception_pending and
                result.gr[8] == invalid_status,
                "PAL_DEBUG_INFO accepted reserved arguments {}".format(
                    arguments))
        require((result.gr[9], result.gr[10], result.gr[11]) == (0, 0, 0),
                "invalid PAL_DEBUG_INFO call returned payload data")
    return ("PAL_DEBUG_INFO reports the exact eight implemented IBR/DBR "
            "pairs and rejects each nonzero reserved argument with -2")


def pal_vm_summary_program(harness: ModuleType, arg0: int, arg1: int,
                           arg2: int):
    return harness.Program(
        name="PAL_VM_SUMMARY args {:x}/{:x}/{:x}".format(
            arg0, arg1, arg2),
        bundles=(
            movl_bundle(harness, 0x10, 28, 8),
            movl_bundle(harness, 0x20, 29, arg0),
            movl_bundle(harness, 0x30, 30, arg1),
            movl_bundle(harness, 0x40, 31, arg2),
            harness.Bundle(0x50, 0x11, harness.nop_m(), harness.nop_i(),
                           harness.br_call(0x50, 0x8F000, 0)),
            harness.spin_bundle(0x60),
        ), terminal_ip=0x60,
    )


def test_pal_virtual_memory_summary(harness: ModuleType,
                                    qemu: Path) -> str:
    expected_info1 = (
        1 | (44 << 1) | (24 << 8) | (15 << 16) | (18 << 24) |
        (7 << 32) | (7 << 40) | (1 << 48) | (1 << 56)
    )
    expected_info2 = 50 | (18 << 8)
    valid = harness.run_program(
        qemu, pal_vm_summary_program(harness, 0, 0, 0)
    )
    require(not valid.exception_pending and valid.gr[8] == 0,
            "valid PAL_VM_SUMMARY call failed")
    require((valid.gr[9], valid.gr[10], valid.gr[11]) ==
            (expected_info1, expected_info2, 0),
            "PAL_VM_SUMMARY returned an incorrect VM profile")

    invalid_status = U64_MASK - 1
    for arguments in ((1, 0, 0), (0, 1, 0), (0, 0, 1)):
        result = harness.run_program(
            qemu, pal_vm_summary_program(harness, *arguments)
        )
        require(not result.exception_pending and
                result.gr[8] == invalid_status,
                "PAL_VM_SUMMARY accepted reserved arguments {}".format(
                    arguments))
        require((result.gr[9], result.gr[10], result.gr[11]) == (0, 0, 0),
                "invalid PAL_VM_SUMMARY call returned payload data")
    return ("PAL_VM_SUMMARY reports max indices 15/7/7 for the implemented "
            "PKR/DTR/ITR banks, the exact VM profile, and rejects every "
            "nonzero reserved argument with -2")


def nat_operands(spec: SystemOpcodeSpec) -> Tuple[str, ...]:
    if spec.nat == "none" or spec.nat.startswith("propagate"):
        return ()
    return tuple(spec.nat.split(","))


def nat_operand_register(name: str) -> int:
    return 21 if name in {"value", "size", "level"} else 22


def nat_raw(spec: SystemOpcodeSpec, operand: str) -> int:
    if spec.opcode == "IA64_OP_MOV_GRCR":
        # CR.DCR is legal while PSR.ic=1.  The loaded value is deliberately
        # NaT, so value-reserved checks remain lower priority.
        return m_system(0x2C, r2=21, r3=0)
    if spec.opcode == "IA64_OP_PROBE_R" and operand == "level":
        return m_system(0x38, r1=20, r2=21, r3=22)
    if spec.opcode == "IA64_OP_PROBE_W" and operand == "level":
        return m_system(0x39, r1=20, r2=21, r3=22)
    return encode_system_opcode(spec.opcode, r1=20, r2=21, r3=22)


def build_nat_program(harness: ModuleType, spec: SystemOpcodeSpec,
                      operand: str):
    nat_reg = nat_operand_register(operand)
    psr_mask_opcode = 7 if spec.opcode in IC_CLEAR_INSERT_OPCODES else 6
    return harness.Program(
        name="{} {} NaT consumption".format(spec.opcode, operand),
        bundles=(
            raw_bundle(harness, 0x10, "M",
                       m_mask(psr_mask_opcode, PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            harness.Bundle(0x30, 0x01, harness.nop_m(),
                           harness.adds(8, 1, 0),
                           harness.adds(9, 0x1000, 0)),
            harness.Bundle(0x40, 0x01,
                           harness.mov_m_grar(AR_UNAT, 8),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x50, 0x01, harness.ld8_fill(nat_reg, 9),
                           harness.nop_i(), harness.nop_i()),
            opcode_bundle(harness, 0x60, spec, nat_raw(spec, operand)),
            harness.spin_bundle(NAT_VECTOR),
        ),
        terminal_ip=NAT_VECTOR,
        data=(harness.DataWord(0x1000, 0x1122334455667788, 8),),
    )


def nat_isr_extra(spec: SystemOpcodeSpec) -> int:
    if spec.opcode == "IA64_OP_TPA":
        return ISR_NA
    if spec.opcode == "IA64_OP_TAK":
        return ISR_NA | 3
    if spec.opcode == "IA64_OP_PROBE_R":
        return ISR_NA | ISR_R | 2
    if spec.opcode == "IA64_OP_PROBE_W":
        return ISR_NA | ISR_W | 2
    if spec.opcode == "IA64_OP_PROBE_RW":
        return ISR_NA | ISR_R | ISR_W | 5
    return 0


def test_nat_matrix(harness: ModuleType, qemu: Path) -> str:
    checked = 0
    for spec in SYSTEM_OPCODE_SPECS:
        for operand in nat_operands(spec):
            snapshot = harness.run_program(
                qemu, build_nat_program(harness, spec, operand),
                preserve_fault_slot=True,
                typed_direct_trace_ips=(0x10, 0x20, 0x60),
            )
            require(snapshot.ip == NAT_VECTOR,
                    "{} {} did not take Register NaT Consumption".format(
                        spec.opcode, operand))
            isr_mask = ISR_CODE_MASK | ISR_W | ISR_R | ISR_NA
            expected_isr = 0x10 | nat_isr_extra(spec)
            require((snapshot.cr_isr & isr_mask) == expected_isr,
                    "{} {} expected NaT ISR 0x{:x}, got 0x{:x}".format(
                        spec.opcode, operand, expected_isr,
                        snapshot.cr_isr & isr_mask))
            if spec.opcode in IC_CLEAR_INSERT_OPCODES:
                precise_collection = (
                    (snapshot.cr_isr & ISR_NI) != 0 and
                    snapshot.cr_iip == 0 and snapshot.cr_iipa == 0
                )
            else:
                precise_collection = (
                    (snapshot.cr_isr & ISR_NI) == 0 and
                    snapshot.cr_iip == 0x60 and snapshot.cr_iipa == 0x50
                )
            require(precise_collection and snapshot.slot_valid and
                    snapshot.slot_ip == 0x60 and snapshot.slot_ri == 0,
                    "{} {} lost precise NaT fault metadata".format(
                        spec.opcode, operand))
            checked += 1

    # THASH/TTAG do not consume a NaT source: they produce NaT results.
    propagation = harness.Program(
        name="THASH TTAG NaT propagation",
        bundles=(
            harness.Bundle(0x10, 0x01, harness.nop_m(),
                           harness.adds(8, 1, 0),
                           harness.adds(9, 0x1000, 0)),
            harness.Bundle(0x20, 0x01,
                           harness.mov_m_grar(AR_UNAT, 8),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x30, 0x01, harness.ld8_fill(22, 9),
                           harness.nop_i(), harness.nop_i()),
            raw_bundle(harness, 0x40, "M", m_system(0x1A, r1=20, r3=22)),
            raw_bundle(harness, 0x50, "M", m_system(0x1B, r1=21, r3=22)),
            harness.spin_bundle(0x60),
        ),
        terminal_ip=0x60,
        data=(harness.DataWord(0x1000, 0x8000, 8),),
    )
    result = harness.run_program(
        qemu, propagation, typed_direct_trace_ips=(0x40, 0x50)
    )
    require(result.nat_low & (1 << 20) and result.nat_low & (1 << 21),
            "THASH/TTAG consumed or cleared a NaT source instead of propagating")
    require(checked >= 35,
            "generated system NaT matrix unexpectedly checked only {} paths".format(
                checked))
    return "{} consuming operands fault and THASH/TTAG propagate NaT".format(
        checked)


def lower_cpl_prefix(harness: ModuleType, target: int, *,
                     collect_interrupt_state: bool = True
                     ) -> Tuple[object, ...]:
    psr_mask_opcode = 6 if collect_interrupt_state else 7
    return (
        raw_bundle(harness, 0x10, "M",
                   m_mask(psr_mask_opcode, PSR_IC)),
        raw_bundle(harness, 0x20, "M", m_serial(0x31)),
        movl_bundle(harness, 0x30, 10, 3 << 62),
        movl_bundle(harness, 0x40, 4, target),
        harness.Bundle(0x50, 0x01, harness.nop_m(),
                       harness.mov_i_grar(AR_PFS, 10),
                       harness.mov_grbr(6, 4)),
        harness.Bundle(0x60, 0x11, harness.nop_m(), harness.nop_i(),
                       harness.br_ret(6)),
        harness.spin_bundle(0x70),
    )


def build_privilege_program(harness: ModuleType, spec: SystemOpcodeSpec):
    selector = 1 if spec.opcode in {
        "IA64_OP_MOV_CRGR", "IA64_OP_MOV_GRCR"
    } else 22
    raw = encode_system_opcode(spec.opcode, r1=20, r2=21, r3=selector)
    return harness.Program(
        name=spec.opcode + " CPL3 privileged-operation",
        bundles=lower_cpl_prefix(
            harness, 0x80,
            collect_interrupt_state=(
                spec.opcode not in IC_CLEAR_INSERT_OPCODES
            ),
        ) + (
            opcode_bundle(harness, 0x80, spec, raw),
            harness.spin_bundle(GENERAL_VECTOR),
        ),
        terminal_ip=GENERAL_VECTOR,
    )


def test_privilege_matrix(harness: ModuleType, qemu: Path) -> str:
    privileged = [spec for spec in SYSTEM_OPCODE_SPECS
                  if spec.privilege == "always"]
    for spec in privileged:
        snapshot = harness.run_program(
            qemu, build_privilege_program(harness, spec),
            preserve_fault_slot=True,
            typed_direct_trace_ips=(0x10, 0x20, 0x80),
        )
        require(snapshot.ip == GENERAL_VECTOR,
                spec.opcode + " executed at CPL3")
        expected_isr = ISR_PRIVILEGED_OPERATION
        if spec.opcode == "IA64_OP_TAK":
            expected_isr |= ISR_NA | 3
        elif spec.opcode == "IA64_OP_TPA":
            expected_isr |= ISR_NA
        if spec.opcode in IC_CLEAR_INSERT_OPCODES:
            expected_isr |= ISR_NI
        require((snapshot.cr_isr & (ISR_CODE_MASK | ISR_NA | ISR_NI)) ==
                expected_isr,
                "{} expected privileged-operation ISR, got 0x{:x}".format(
                    spec.opcode, snapshot.cr_isr))
        if spec.opcode in IC_CLEAR_INSERT_OPCODES:
            require(snapshot.cr_ipsr == 0,
                    spec.opcode + " collected IPSR while PSR.ic was clear")
        else:
            require(((snapshot.cr_ipsr >> PSR_CPL_SHIFT) & 3) == 3,
                    spec.opcode + " did not collect faulting CPL3 in IPSR")
        expected_ri = 2 if spec.unit == "B" else 0
        if spec.opcode in IC_CLEAR_INSERT_OPCODES:
            expected_iip = 0
            expected_iipa = 0
        else:
            expected_iip = 0x80
            expected_iipa = 0x80 if expected_ri != 0 else 0x60
        require(snapshot.cr_iip == expected_iip and
                snapshot.cr_iipa == expected_iipa and
                snapshot.slot_valid and snapshot.slot_ip == 0x80 and
                snapshot.slot_ri == expected_ri,
                spec.opcode + " lost precise privileged fault metadata")

    # MOV_IMMAR is conditionally a Privileged Register fault.  Use its M-unit
    # form so AR.KR0 is a legal unit/register pairing before CPL is checked.
    ar_program = harness.Program(
        name="MOV_IMMAR kernel AR privileged-register",
        bundles=lower_cpl_prefix(harness, 0x80) + (
            raw_bundle(harness, 0x80, "M", mov_immar(0, 1, unit="M")),
            harness.spin_bundle(GENERAL_VECTOR),
        ), terminal_ip=GENERAL_VECTOR,
    )
    ar_fault = harness.run_program(
        qemu, ar_program, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x10, 0x20, 0x80),
    )
    require((ar_fault.cr_isr & ISR_CODE_MASK) == ISR_PRIVILEGED_REGISTER,
            "kernel AR immediate write did not take Privileged Register fault")
    require(ar_fault.cr_iip == 0x80 and ar_fault.cr_iipa == 0x60 and
            ar_fault.slot_valid and ar_fault.slot_ri == 0,
            "MOV_IMMAR privileged-register fault metadata is imprecise")

    # Generic PMD4 is user-readable when PSR.sp and PMC4.pm are both clear.
    # PMD reads never raise Privileged Register at nonzero CPL.
    pmd_program = harness.Program(
        name="MOV_PMDGR conditional privileged-register",
        bundles=(
            raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            movl_bundle(harness, 0x30, 2, 0),
            movl_bundle(harness, 0x40, 3, 4),
            raw_bundle(harness, 0x50, "M",
                       m_system(0x04, r2=2, r3=3)),
            movl_bundle(harness, 0x60, 2, 0x1234),
            raw_bundle(harness, 0x70, "M",
                       m_system(0x05, r2=2, r3=3)),
            raw_bundle(harness, 0x80, "M", m_serial(0x30)),
            movl_bundle(harness, 0x90, 10, 3 << 62),
            movl_bundle(harness, 0xA0, 4, 0xE0),
            harness.Bundle(0xB0, 0x01, harness.nop_m(),
                           harness.mov_i_grar(AR_PFS, 10),
                           harness.mov_grbr(6, 4)),
            harness.Bundle(0xC0, 0x11, harness.nop_m(), harness.nop_i(),
                           harness.br_ret(6)),
            harness.spin_bundle(0xD0),
            raw_bundle(harness, 0xE0, "M",
                       m_system(0x15, r1=20, r3=3)),
            harness.spin_bundle(0xF0),
        ), terminal_ip=0xF0,
    )
    pmd_fault = harness.run_program(
        qemu, pmd_program,
        typed_direct_trace_ips=(0x10, 0x20, 0x50, 0x70, 0x80, 0xE0),
    )
    require(not pmd_fault.exception_pending and pmd_fault.gr[20] == 0x1234,
            "user-readable generic PMD4 did not return its value at CPL3")
    return ("{} unconditional CPL0 checks plus conditional AR/PMD policy "
            "pass".format(len(privileged)))


@dataclasses.dataclass(frozen=True)
class FaultCase:
    name: str
    raw: int
    unit: str
    setup: Tuple[Tuple[int, int], ...]
    isr_code: int
    requires_ic_clear: bool = False


def reserved_cases() -> Tuple[FaultCase, ...]:
    return (
        FaultCase("MOV_IMMAR wrong-unit AR8", mov_immar(8, 1, unit="I"),
                  "I", (), 0),
        FaultCase("MOV_CRGR reserved CR3", m_system(0x24, r1=20, r3=3),
                  "M", (), 0),
        FaultCase("MOV_GRCR read-only IVR", m_system(0x2C, r2=2, r3=65),
                  "M", (), 0),
        FaultCase("SSM reserved mask", m_mask(6, 1), "M", (),
                  ISR_RESERVED_REGISTER_FIELD),
        FaultCase("RSM reserved mask", m_mask(7, 1), "M", (),
                  ISR_RESERVED_REGISTER_FIELD),
        FaultCase("SUM reserved mask", m_mask(4, 1 << 6), "M", (),
                  ISR_RESERVED_REGISTER_FIELD),
        FaultCase("RUM reserved mask", m_mask(5, 1 << 6), "M", (),
                  ISR_RESERVED_REGISTER_FIELD),
        FaultCase("MOV_GRPSR reserved PSR bit", m_system(0x2D, r2=2),
                  "M", ((2, 1),), ISR_RESERVED_REGISTER_FIELD),
        FaultCase("MOV_GRRR invalid page size", m_system(0x00, r2=2, r3=3),
                  "M", ((2, 0), (3, 0)), ISR_RESERVED_REGISTER_FIELD),
        FaultCase("PKR index out of range", m_system(0x13, r1=20, r3=3),
                  "M", ((3, 16),), ISR_RESERVED_REGISTER_FIELD),
        FaultCase("IBR index out of range", m_system(0x12, r1=20, r3=3),
                  "M", ((3, 16),), ISR_RESERVED_REGISTER_FIELD),
        FaultCase("DBR index out of range", m_system(0x11, r1=20, r3=3),
                  "M", ((3, 16),), ISR_RESERVED_REGISTER_FIELD),
        FaultCase("CPUID index out of range", m_system(0x17, r1=20,
                                                        r2=0, r3=3),
                  "M", ((3, 5),), ISR_RESERVED_REGISTER_FIELD),
        FaultCase("PKR reserved value", m_system(0x03, r2=2, r3=3),
                  "M", ((2, 1 << 63), (3, 0)),
                  ISR_RESERVED_REGISTER_FIELD),
        FaultCase("ITR slot out of range", m_system(0x0E, r2=2, r3=3),
                  "M", ((2, 0), (3, 16)), ISR_RESERVED_REGISTER_FIELD,
                  True),
        FaultCase("CR.DCR reserved value", m_system(0x2C, r2=2, r3=0),
                  "M", ((2, 1 << 3),), ISR_RESERVED_REGISTER_FIELD),
    )


def build_fault_program(harness: ModuleType, case: FaultCase,
                        predicate: int = 0):
    bundles: List[object] = [
        raw_bundle(harness, 0x10, "M",
                   m_mask(7 if case.requires_ic_clear else 6, PSR_IC)),
        raw_bundle(harness, 0x20, "M", m_serial(0x31)),
    ]
    address = 0x30
    for reg, value in case.setup:
        bundles.append(movl_bundle(harness, address, reg, value))
        address += 0x10
    raw = (case.raw & ~0x3F) | predicate
    bundles.append(raw_bundle(harness, address, case.unit, raw))
    fault_ip = address
    address += 0x10
    if predicate:
        bundles.append(harness.spin_bundle(address))
        terminal = address
    else:
        bundles.append(harness.spin_bundle(GENERAL_VECTOR))
        terminal = GENERAL_VECTOR
    return (harness.Program(name=case.name, bundles=tuple(bundles),
                            terminal_ip=terminal), fault_ip)


def test_reserved_matrix(harness: ModuleType, qemu: Path) -> str:
    cases = reserved_cases()
    for case in cases:
        program, fault_ip = build_fault_program(harness, case)
        snapshot = harness.run_program(
            qemu, program, preserve_fault_slot=True,
            typed_direct_trace_ips=(0x10, 0x20, fault_ip),
        )
        require(snapshot.ip == GENERAL_VECTOR,
                case.name + " did not take General Exception")
        require((snapshot.cr_isr & ISR_CODE_MASK) == case.isr_code,
                "{} expected ISR code 0x{:x}, got 0x{:x}".format(
                    case.name, case.isr_code, snapshot.cr_isr))
        expected_ri = 1 if case.unit == "I" else 0
        if case.requires_ic_clear:
            expected_iip = 0
            expected_iipa = 0
            require((snapshot.cr_isr & ISR_NI) != 0,
                    case.name + " did not report disabled collection")
        else:
            expected_iip = fault_ip
            expected_iipa = fault_ip if expected_ri != 0 else fault_ip - 0x10
        require(snapshot.cr_iip == expected_iip and
                snapshot.cr_iipa == expected_iipa and
                snapshot.slot_valid and snapshot.slot_ip == fault_ip and
                snapshot.slot_ri == expected_ri,
                case.name + " lost precise reserved/illegal fault metadata")

    # The same otherwise-faulting forms must be inert when p1 is false.
    for case in cases:
        program, fault_ip = build_fault_program(harness, case, predicate=1)
        snapshot = harness.run_program(
            qemu, program,
            typed_direct_trace_ips=(0x10, 0x20, fault_ip),
        )
        require(snapshot.ip == program.terminal_ip,
                case.name + " checked reserved fields before predicate")
        expected_psr = 0 if case.requires_ic_clear else PSR_IC
        require(not snapshot.exception_pending and snapshot.psr == expected_psr,
                case.name + " had a false-predicate fault or PSR side effect")
    return "{} reserved/illegal forms fault and are predicate-suppressed".format(
        len(cases))


def build_tlb_program(harness: ModuleType, purge_opcode: str,
                      pinned: bool = False):
    virtual = 0x8000
    physical = 0x2000
    pte = physical | 0x661
    value = 0xA1B2C3D4E5F60718
    bundles: List[object] = [
        movl_bundle(harness, 0x10, 2, pte),
        movl_bundle(harness, 0x20, 7, virtual),
        harness.Bundle(0x30, 0x01, harness.nop_m(),
                       harness.adds(4, 12 << 2, 0),
                       harness.adds(5, 12 << 2, 0)),
        raw_bundle(harness, 0x40, "M", m_system(0x2C, r2=7, r3=CR_IFA)),
        raw_bundle(harness, 0x50, "M", m_system(0x2C, r2=4, r3=CR_ITIR)),
    ]
    bundles.append(harness.Bundle(0x60, 0x01, harness.nop_m(),
                                  harness.adds(6, 0, 0), harness.nop_i()))
    if pinned:
        insert = m_system(0x0E, r2=2, r3=6)
    else:
        insert = m_system(0x2E, r2=2)
    insert_spec = SPEC_BY_OPCODE[
        "IA64_OP_ITR_D" if pinned else "IA64_OP_ITC_D"
    ]
    bundles.extend((
        opcode_bundle(harness, 0x70, insert_spec, insert),
        raw_bundle(harness, 0x80, "M", m_serial(0x30)),
        raw_bundle(harness, 0x90, "M", m_mask(6, PSR_DT | PSR_IC)),
        raw_bundle(harness, 0xA0, "M", m_serial(0x31)),
        harness.Bundle(0xB0, 0x01, harness.ld8(20, 7),
                       harness.nop_i(), harness.nop_i()),
        raw_bundle(harness, 0xC0, "M",
                   m_system(0x1E, r1=21, r3=7) | bitfield(1, 36, 1)),
        raw_bundle(harness, 0xD0, "M", m_system(0x18, r1=22, r2=0, r3=7)),
        raw_bundle(harness, 0xE0, "M",
                   m_system(0x1F, r1=23, r2=0x55, r3=7)
                   | bitfield(1, 36, 1)),
        raw_bundle(harness, 0xF0, "M",
                   m_system(0x1A, r1=24, r2=0x55, r3=7)
                   | bitfield(1, 36, 1)),
        raw_bundle(harness, 0x100, "M",
                   m_system(0x1B, r1=25, r2=0x55, r3=7)
                   | bitfield(1, 36, 1)),
        raw_bundle(harness, 0x110, "M",
                   m_system(0x19, r1=27, r2=0, r3=7)),
        raw_bundle(harness, 0x120, "M",
                   m_system(0x38, r1=28, r2=6, r3=7)),
        raw_bundle(harness, 0x130, "M",
                   m_system(0x39, r1=29, r2=6, r3=7)),
        raw_bundle(harness, 0x140, "M",
                   m_system(0x32, r2=0, r3=7)
                   | bitfield(1, 36, 1)
                   | bitfield(0x1F, 15, 5)
                   | bitfield(0x7F, 6, 7)),
        raw_bundle(harness, 0x150, "M",
                   m_system(0x33, r2=0, r3=7)),
        raw_bundle(harness, 0x160, "M",
                   m_system(0x31, r2=0, r3=7)),
    ))
    if purge_opcode == "IA64_OP_PTC_E":
        purge = m_system(0x34, r3=7)
    elif purge_opcode == "IA64_OP_PTR_D":
        purge = m_system(0x0C, r2=5, r3=7)
    else:
        x6 = {
            "IA64_OP_PTC_L": 0x09,
            "IA64_OP_PTC_G": 0x0A,
            "IA64_OP_PTC_GA": 0x0B,
        }[purge_opcode]
        purge = m_system(x6, r2=5, r3=7)
    bundles.extend((
        opcode_bundle(harness, 0x170, SPEC_BY_OPCODE[purge_opcode], purge),
        raw_bundle(harness, 0x180, "M", m_serial(0x30)),
        harness.Bundle(0x190, 0x01, harness.ld8(26, 7),
                       harness.nop_i(), harness.nop_i()),
        harness.spin_bundle(ALT_DTLB_VECTOR),
    ))
    trace = (0x40, 0x50, 0x70, 0x80, 0x90, 0xA0, 0xC0, 0xD0, 0xE0,
             0xF0, 0x100, 0x110, 0x120, 0x130, 0x140, 0x150, 0x160,
             0x170, 0x180)
    return (
        harness.Program(
            name=purge_opcode + " translated data lifecycle",
            bundles=tuple(bundles), terminal_ip=ALT_DTLB_VECTOR,
            data=(harness.DataWord(physical, value, 8),),
        ), value, physical, trace,
    )


def test_tlb_lifecycle(harness: ModuleType, qemu: Path) -> str:
    modes = (
        ("IA64_OP_PTC_L", False),
        ("IA64_OP_PTC_G", False),
        ("IA64_OP_PTC_GA", False),
        ("IA64_OP_PTC_E", False),
        ("IA64_OP_PTR_D", True),
    )
    for opcode, pinned in modes:
        program, value, physical, trace = build_tlb_program(
            harness, opcode, pinned=pinned
        )
        snapshot = harness.run_program(
            qemu, program, typed_direct_trace_ips=trace,
        )
        require(snapshot.gr[20] == value,
                opcode + " baseline translated load failed")
        require(snapshot.gr[21] == physical,
                opcode + " TPA returned the wrong physical address")
        require(snapshot.gr[22] == 1,
                opcode + " regular read probe did not grant access")
        require(snapshot.gr[27:30] == (1, 1, 1),
                opcode + " write/register probe forms did not grant access")
        require(snapshot.gr[23] == 0,
                opcode + " TAK did not return ITIR key zero")
        require(snapshot.gr[24] == 0,
                opcode + " THASH ignored the reset PTA base/size")
        require(snapshot.gr[25] == 8,
                opcode + " TTAG did not return the reset-RR page tag")
        require(snapshot.ip == ALT_DTLB_VECTOR,
                opcode + " purge remained usable after srlz.d")
    return "ITC/ITR install, query, five purge modes and srlz.d visibility pass"


def build_instruction_tlb_program(harness: ModuleType, *, pinned: bool,
                                  purge: bool = False):
    virtual = 0x8000
    physical = 0x2000
    translation = physical | 0x661
    marker = 0x71 if pinned else 0x72
    insert = (m_system(0x0F, r2=2, r3=6) if pinned else
              m_system(0x2F, r2=2))
    bundles: List[object] = [
        movl_bundle(harness, 0x10, 2, translation),
        movl_bundle(harness, 0x20, 7, virtual),
        harness.Bundle(0x30, 0x01, harness.nop_m(),
                       harness.adds(4, 12 << 2, 0),
                       harness.adds(6, 0, 0)),
        raw_bundle(harness, 0x40, "M",
                   m_system(0x2C, r2=7, r3=CR_IFA)),
        raw_bundle(harness, 0x50, "M",
                   m_system(0x2C, r2=4, r3=CR_ITIR)),
        # M_MI stops after the insertion but resumes at slot 1.  Slot 2 is a
        # visible proof that NEXT_SLOT did not skip the suffix.
        harness.Bundle(0x60, 0x0B, insert, harness.nop_m(),
                       harness.adds(20, marker, 0)),
        movl_bundle(harness, 0x70, 8, PSR_IT | PSR_IC),
        raw_bundle(harness, 0x80, "M",
                   m_system(0x2C, r2=8, r3=CR_IPSR)),
        raw_bundle(harness, 0x90, "M",
                   m_system(0x2C, r2=7, r3=CR_IIP)),
        harness.Bundle(0xA0, 0x11, harness.nop_m(), harness.nop_i(),
                       harness.rfi()),
    ]
    if purge:
        require(pinned, "PTR.I lifecycle requires a pinned ITR entry")
        bundles.extend((
            harness.Bundle(physical, 0x01,
                           m_system(0x0D, r2=4, r3=7),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(physical + 0x10, 0x11, harness.nop_m(),
                           harness.nop_i(),
                           harness.br_cond(virtual + 0x10,
                                           virtual + 0x10)),
            harness.spin_bundle(ALT_ITLB_VECTOR),
        ))
        terminal = ALT_ITLB_VECTOR
    else:
        bundles.extend((
            harness.Bundle(physical, 0x01, harness.nop_m(),
                           harness.adds(21, marker + 0x10, 0),
                           harness.nop_i()),
            harness.Bundle(physical + 0x10, 0x11, harness.nop_m(),
                           harness.nop_i(),
                           harness.br_cond(virtual + 0x10,
                                           virtual + 0x10)),
        ))
        terminal = virtual + 0x10
    return harness.Program(
        name=("ITR.I/PTR.I" if purge else
              ("ITR.I" if pinned else "ITC.I")) + " fetch lifecycle",
        bundles=tuple(bundles), terminal_ip=terminal,
    ), marker


def test_instruction_tlb_lifecycle(harness: ModuleType, qemu: Path) -> str:
    for pinned in (False, True):
        program, marker = build_instruction_tlb_program(
            harness, pinned=pinned)
        result = harness.run_program(
            qemu, program,
            typed_direct_trace_ips=(0x40, 0x50, 0x60, 0x80, 0x90),
            typed_rfi_traces=(0xA0,), one_bundle_per_tb=True,
        )
        require(result.ip == program.terminal_ip and
                result.gr[20] == marker and
                result.gr[21] == marker + 0x10,
                program.name + " did not resume its suffix and fetch mapping")

    purge_program, marker = build_instruction_tlb_program(
        harness, pinned=True, purge=True)
    purged = harness.run_program(
        qemu, purge_program,
        typed_direct_trace_ips=(0x40, 0x50, 0x60, 0x80, 0x90, 0x8000),
        typed_rfi_traces=(0xA0,), one_bundle_per_tb=True,
    )
    require(purged.ip == ALT_ITLB_VECTOR and purged.gr[20] == marker,
            "PTR.I did not invalidate the fetched pinned translation")
    require(purged.exception_kind == "alternate-instruction-tlb-miss" and
            purged.cr_iip == 0x8010,
            "PTR.I invalidation did not produce the precise next-fetch miss")
    return ("ITC.I and ITR.I resume at the exact next slot and fetch mapped "
            "code; PTR.I invalidates the pinned fetch mapping")


def test_active_mask_controls(harness: ModuleType, qemu: Path) -> str:
    program = harness.Program(
        name="active RSM RUM state changes",
        bundles=(
            raw_bundle(harness, 0x10, "M",
                       m_mask(6, PSR_IC | PSR_I)),
            raw_bundle(harness, 0x20, "M", m_mask(7, PSR_I)),
            raw_bundle(harness, 0x30, "M", m_mask(7, PSR_IC)),
            raw_bundle(harness, 0x40, "M", m_system(0x25, r1=20)),
            raw_bundle(harness, 0x50, "M", m_mask(4, PSR_AC)),
            raw_bundle(harness, 0x60, "M", m_system(0x21, r1=21)),
            raw_bundle(harness, 0x70, "M", m_mask(5, PSR_AC)),
            raw_bundle(harness, 0x80, "M", m_system(0x21, r1=22)),
            harness.spin_bundle(0x90),
        ), terminal_ip=0x90,
    )
    result = harness.run_program(
        qemu, program,
        typed_direct_trace_ips=(0x10, 0x20, 0x30, 0x40, 0x50,
                                0x60, 0x70, 0x80),
    )
    require((result.gr[20] & (PSR_IC | PSR_I)) == 0,
            "RSM did not clear PSR.ic/PSR.i")
    require(result.gr[21] == PSR_AC and result.gr[22] == 0,
            "SUM/RUM did not set and clear PSR.ac")
    return "active SSM/RSM and SUM/RUM mask transitions pass"


def build_debug_register_program(harness: ModuleType, *, instruction: bool,
                                 match_address: int, access_address: int = 0,
                                 unaligned: bool = False):
    """Install pair zero through real indexed system moves and trigger it."""
    control = ((1 << 63) | (1 << 56) |
               0x00FFFFFFFFFFFFFF)
    if not instruction:
        control |= 1 << 62
    write_x6 = 0x02 if instruction else 0x01
    bundles: List[object] = [
        movl_bundle(harness, 0x10, 2, match_address),
        movl_bundle(harness, 0x20, 3, 0),
        raw_bundle(harness, 0x30, "M",
                   m_system(write_x6, r2=2, r3=3)),
        movl_bundle(harness, 0x40, 2, control),
        movl_bundle(harness, 0x50, 3, 1),
        raw_bundle(harness, 0x60, "M",
                   m_system(write_x6, r2=2, r3=3)),
    ]
    if not instruction:
        bundles.append(movl_bundle(harness, 0x70, 7, access_address))
    else:
        bundles.append(movl_bundle(harness, 0x70, 7, 0))
    bundles.extend((
        movl_bundle(harness, 0x80, 2,
                    PSR_DB | PSR_IC | (PSR_AC if unaligned else 0)),
        raw_bundle(harness, 0x90, "M", m_system(0x2D, r2=2)),
        raw_bundle(harness, 0xA0, "M", m_serial(0x31)),
    ))
    if instruction:
        require(match_address == 0xB0,
                "instruction debug canary target drifted")
        bundles.extend((
            harness.Bundle(0xB0, 0x01, harness.nop_m(),
                           harness.adds(20, 0x55, 0), harness.nop_i()),
            harness.spin_bundle(DEBUG_VECTOR),
        ))
        trigger_ip = 0xB0
    else:
        # A data serialization boundary is separately required after DBR
        # replacement; srlz.i above closes the PSR.ic transition.
        bundles.extend((
            raw_bundle(harness, 0xB0, "M", m_serial(0x30)),
            harness.Bundle(0xC0, 0x01, harness.ld8(20, 7),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(DEBUG_VECTOR),
        ))
        trigger_ip = 0xC0
    return harness.Program(
        name=("IBR execution" if instruction else
              ("DBR unaligned priority" if unaligned else "DBR read")),
        bundles=tuple(bundles), terminal_ip=DEBUG_VECTOR,
        data=(() if instruction else
              (harness.DataWord(access_address & ~7,
                                0x8877665544332211, 8),)),
    ), trigger_ip


def test_architectural_debug_registers(harness: ModuleType, qemu: Path) -> str:
    mask_program = harness.Program(
        name="IBR DBR odd-control masks and selector truncation",
        bundles=(
            movl_bundle(harness, 0x10, 2, U64_MASK),
            movl_bundle(harness, 0x20, 3, 0x101),
            raw_bundle(harness, 0x30, "M",
                       m_system(0x02, r2=2, r3=3)),
            raw_bundle(harness, 0x40, "M", m_serial(0x31)),
            raw_bundle(harness, 0x50, "M",
                       m_system(0x12, r1=20, r3=3)),
            raw_bundle(harness, 0x60, "M",
                       m_system(0x01, r2=2, r3=3)),
            raw_bundle(harness, 0x70, "M", m_serial(0x30)),
            raw_bundle(harness, 0x80, "M",
                       m_system(0x11, r1=21, r3=3)),
            harness.spin_bundle(0x90),
        ), terminal_ip=0x90,
    )
    masked = harness.run_program(
        qemu, mask_program,
        typed_direct_trace_ips=(0x30, 0x40, 0x50, 0x60, 0x70, 0x80),
    )
    require(masked.gr[20] == U64_MASK & ~(7 << 60) and
            masked.gr[21] == U64_MASK & ~(3 << 60),
            "odd IBR/DBR ignored bits or eight-bit selector truncation drifted")

    instruction_program, instruction_ip = build_debug_register_program(
        harness, instruction=True, match_address=0xB0)
    instruction = harness.run_program(
        qemu, instruction_program,
        typed_direct_trace_ips=(0x30, 0x60, 0x90, 0xA0),
        one_bundle_per_tb=True,
    )
    require(instruction.exception_kind == "instruction-debug" and
            instruction.exception_vector == DEBUG_VECTOR,
            "enabled IBR did not take Instruction Debug")
    require(instruction.cr_isr == ISR_X | 1 and
            instruction.cr_iip == instruction_ip and
            instruction.exception_source == instruction_ip and
            instruction.exception_address == instruction_ip,
            "Instruction Debug ISR or precise address metadata is wrong")
    require(instruction.gr[20] == 0,
            "IBR match executed the target bundle before faulting")

    data_address = 0x4000
    data_program, data_ip = build_debug_register_program(
        harness, instruction=False, match_address=data_address,
        access_address=data_address)
    data = harness.run_program(
        qemu, data_program,
        typed_direct_trace_ips=(0x30, 0x60, 0x90, 0xA0, 0xB0, data_ip),
        one_bundle_per_tb=True,
    )
    require(data.exception_kind == "data-debug" and
            data.exception_vector == DEBUG_VECTOR and
            data.cr_isr == ISR_R,
            "enabled read DBR did not take Data Debug with R/code0")
    require(data.cr_iip == data_ip and data.cr_ifa == data_address and
            data.exception_source == data_ip and
            data.exception_address == data_address,
            "Data Debug lost its precise instruction/address metadata")
    require(data.gr[20] == 0,
            "DBR match performed the load before faulting")

    unaligned_address = data_address + 1
    priority_program, priority_ip = build_debug_register_program(
        harness, instruction=False, match_address=unaligned_address,
        access_address=unaligned_address, unaligned=True)
    priority = harness.run_program(
        qemu, priority_program,
        typed_direct_trace_ips=(0x30, 0x60, 0x90, 0xA0, 0xB0, priority_ip),
        one_bundle_per_tb=True,
    )
    require(priority.exception_kind == "data-debug" and
            priority.exception_vector == DEBUG_VECTOR and
            priority.cr_isr == ISR_R and
            priority.cr_ifa == unaligned_address,
            "DBR did not outrank an otherwise-faulting unaligned load")

    # probe.r.fault at PL3 performs its lookup with effective
    # max(current-CPL, requested-PL).  A PL3-only DBR must therefore match
    # even though the probe instruction itself executes at CPL0.
    pl3_control = (1 << 63) | (1 << 59) | 0x00FFFFFFFFFFFFFF
    probe_program = harness.Program(
        name="fault-form probe effective-PL DBR",
        bundles=(
            movl_bundle(harness, 0x10, 2, data_address),
            movl_bundle(harness, 0x20, 3, 0),
            raw_bundle(harness, 0x30, "M",
                       m_system(0x01, r2=2, r3=3)),
            movl_bundle(harness, 0x40, 2, pl3_control),
            movl_bundle(harness, 0x50, 3, 1),
            raw_bundle(harness, 0x60, "M",
                       m_system(0x01, r2=2, r3=3)),
            movl_bundle(harness, 0x70, 7, data_address),
            movl_bundle(harness, 0x80, 2, PSR_DB | PSR_IC),
            raw_bundle(harness, 0x90, "M", m_system(0x2D, r2=2)),
            raw_bundle(harness, 0xA0, "M", m_serial(0x31)),
            raw_bundle(harness, 0xB0, "M", m_serial(0x30)),
            raw_bundle(harness, 0xC0, "M",
                       m_system(0x32, r2=3, r3=7)),
            harness.spin_bundle(DEBUG_VECTOR),
        ), terminal_ip=DEBUG_VECTOR,
        data=(harness.DataWord(data_address, 0x123456789ABCDEF0, 8),),
    )
    probe = harness.run_program(
        qemu, probe_program,
        typed_direct_trace_ips=(0x30, 0x60, 0x90, 0xA0, 0xB0, 0xC0),
        one_bundle_per_tb=True,
    )
    require(probe.exception_kind == "data-debug" and
            probe.exception_vector == DEBUG_VECTOR and
            probe.cr_isr == ISR_NA | ISR_R | 5 and
            probe.cr_iip == 0xC0 and probe.cr_ifa == data_address,
            "fault-form probe ignored effective PL or published wrong ISR")
    return ("odd-control masks/selector truncation and real IBR/DBR faults "
            "pass; DBR outranks Unaligned and uses fault-probe effective PL")


def test_unaligned_translation_priority(harness: ModuleType,
                                        qemu: Path) -> str:
    address = 0x8001
    program = harness.Program(
        name="translation outranks unaligned without DBR",
        bundles=(
            movl_bundle(harness, 0x10, 7, address),
            movl_bundle(harness, 0x20, 2, PSR_DT | PSR_IC | PSR_AC),
            raw_bundle(harness, 0x30, "M", m_system(0x2D, r2=2)),
            raw_bundle(harness, 0x40, "M", m_serial(0x31)),
            harness.Bundle(0x50, 0x01, harness.ld8(20, 7),
                           harness.nop_i(), harness.nop_i()),
            # Make a wrong Unaligned outcome terminate too, so the assertion
            # reports its architectural mismatch rather than timing out.
            harness.Bundle(UNALIGNED_VECTOR, 0x11, harness.nop_m(),
                           harness.nop_i(),
                           harness.br_cond(ALT_DTLB_VECTOR,
                                           ALT_DTLB_VECTOR)),
            harness.spin_bundle(ALT_DTLB_VECTOR),
        ), terminal_ip=ALT_DTLB_VECTOR,
    )
    result = harness.run_program(
        qemu, program,
        typed_direct_trace_ips=(0x30, 0x40, 0x50),
        one_bundle_per_tb=True,
    )
    require(result.exception_kind == "alternate-data-tlb-miss" and
            result.exception_vector == ALT_DTLB_VECTOR,
            "unmapped+unaligned load raised {} instead of alternate DTLB miss"
            .format(result.exception_kind))
    require(result.cr_iip == 0x50 and result.cr_ifa == address and
            result.exception_source == 0x50 and
            result.exception_address == address,
            "translation-before-Unaligned fault metadata is imprecise")
    return "translation/protection probe outranks Unaligned without a DBR match"


def test_group_alias_and_barriers(harness: ModuleType, qemu: Path) -> str:
    program = harness.Program(
        name="system group-entry alias and barrier rows",
        bundles=(
            movl_bundle(harness, 0x10, 2, PSR_AC),
            # Internal source-visibility invariant, not a legal guest RAW/WAR
            # dependency golden: the translator must retain the first saved
            # r2 image when a later slot stages a same-group replacement.
            harness.Bundle(0x20, 0x01, m_system(0x29, r2=2),
                           harness.adds(2, 0, 0), harness.nop_i()),
            raw_bundle(harness, 0x30, "M", m_system(0x21, r1=13)),
            raw_bundle(harness, 0x40, "M", m_serial(0x22)),
            raw_bundle(harness, 0x50, "M", m_serial(0x23)),
            raw_bundle(harness, 0x60, "M", m_serial(0x33)),
            harness.spin_bundle(0x70),
        ), terminal_ip=0x70,
    )
    snapshot = harness.run_program(
        qemu, program,
        typed_direct_trace_ips=(0x20, 0x30, 0x40, 0x50, 0x60),
    )
    require(snapshot.gr[2] == 0 and snapshot.gr[13] == PSR_AC,
            "system source selected live r2 instead of the saved entry image")
    return ("same-group source-overlay invariant holds; MF/MF.A/SYNC.I rows "
            "execute directly")


def test_application_register_plane(harness: ModuleType, qemu: Path) -> str:
    """Exercise the full M/I application-register contract."""
    success = harness.Program(
        name="application-register legal selectors and normalization",
        bundles=(
            movl_bundle(harness, 0x10, 2, 0x1234),
            harness.Bundle(0x20, 0x01,
                           harness.mov_m_grar(AR_CCV, 2),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x30, 0x01,
                           harness.mov_m_argr(20, AR_CCV),
                           harness.nop_i(), harness.nop_i()),
            movl_bundle(harness, 0x40, 3, 0xFF),
            raw_bundle(harness, 0x50, "I",
                       harness.mov_i_grar(AR_EC, 3)),
            raw_bundle(harness, 0x60, "I",
                       harness.mov_argr(21, AR_EC)),
            movl_bundle(harness, 0x70, 4, 0xABC),
            harness.Bundle(0x80, 0x01,
                           harness.mov_m_grar(48, 4),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x90, 0x01,
                           harness.mov_m_argr(22, 48),
                           harness.nop_i(), harness.nop_i()),
            raw_bundle(harness, 0xA0, "I",
                       harness.mov_i_grar(112, 4)),
            raw_bundle(harness, 0xB0, "I",
                       harness.mov_argr(23, 112)),
            movl_bundle(harness, 0xC0, 5, U64_MASK),
            harness.Bundle(0xD0, 0x01,
                           harness.mov_m_grar(AR_RNAT, 5),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xE0, 0x01,
                           harness.mov_m_argr(24, AR_RNAT),
                           harness.nop_i(), harness.nop_i()),
            movl_bundle(harness, 0xF0, 6, 0x11),
            harness.Bundle(0x100, 0x01,
                           harness.mov_m_grar(AR_CCV, 6),
                           harness.nop_i(), harness.nop_i()),
            movl_bundle(harness, 0x110, 6, 0x22),
            # Template 0x09 is MMI with no internal stop.  The read in slot 1
            # must select the group-entry CCV image, while the next group sees
            # the staged replacement.
            harness.Bundle(0x120, 0x09,
                           harness.mov_m_grar(AR_CCV, 6),
                           harness.mov_m_argr(25, AR_CCV), harness.nop_i()),
            harness.Bundle(0x130, 0x01,
                           harness.mov_m_argr(26, AR_CCV),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(0x140),
        ), terminal_ip=0x140,
    )
    success_result = harness.run_program(
        qemu, success,
        typed_direct_trace_ips=(0x20, 0x30, 0x50, 0x60, 0x80, 0x90,
                                0xA0, 0xB0, 0xD0, 0xE0, 0x100, 0x120,
                                0x130),
    )
    require(success_result.gr[20] == 0x1234,
            "M-unit CCV write/read did not round-trip")
    require(success_result.gr[21] == 0x3F,
            "I-unit EC write did not apply the six-bit mask")
    require(success_result.gr[22] == 0 and success_result.gr[23] == 0,
            "architecturally ignored application registers retained writes")
    require(success_result.gr[24] == (U64_MASK >> 1),
            "RNAT write did not clear its reserved high bit")
    require(success_result.gr[25] == 0x11 and
            success_result.gr[26] == 0x22,
            "same-group application-register source overlay is incorrect")

    # BSPSTORE aligns its input and rebases both BSP/BspLoad.  Starting on an
    # RNAT collection slot makes the architecturally required BSP skip visible
    # even though the dirty partition is empty.  RNAT masks bit 63, while the
    # complete legal RSC image remains readable after mode becomes non-zero.
    valid_rsc = (0x2A5 << 16) | (1 << 4) | (2 << 2) | 3
    rse_state = harness.Program(
        name="RSE application-register state transitions",
        bundles=(
            movl_bundle(harness, 0x10, 2, 0x61FF),
            harness.Bundle(0x20, 0x01,
                           harness.mov_m_grar(AR_BSPSTORE, 2),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x30, 0x01,
                           harness.mov_m_argr(20, AR_BSPSTORE),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x40, 0x01,
                           harness.mov_m_argr(21, AR_BSP),
                           harness.nop_i(), harness.nop_i()),
            movl_bundle(harness, 0x50, 3, U64_MASK),
            harness.Bundle(0x60, 0x01,
                           harness.mov_m_grar(AR_RNAT, 3),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x70, 0x01,
                           harness.mov_m_argr(22, AR_RNAT),
                           harness.nop_i(), harness.nop_i()),
            movl_bundle(harness, 0x80, 4, valid_rsc),
            harness.Bundle(0x90, 0x01,
                           harness.mov_m_grar(AR_RSC, 4),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xA0, 0x01,
                           harness.mov_m_argr(23, AR_RSC),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xB0, 0x01,
                           harness.mov_m_argr(24, AR_BSP),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(0xC0),
        ), terminal_ip=0xC0,
    )
    rse_state_result = harness.run_program(
        qemu, rse_state,
        typed_direct_trace_ips=(0x20, 0x30, 0x40, 0x60, 0x70, 0x90,
                                0xA0, 0xB0),
    )
    require(rse_state_result.rse_bspstore == 0x61F8 and
            rse_state_result.rse_bspload == 0x61F8 and
            rse_state_result.rse_bsp == 0x6200 and
            rse_state_result.gr[20] == 0x61F8 and
            rse_state_result.gr[21] == 0x6200 and
            rse_state_result.gr[24] == 0x6200,
            "BSPSTORE did not align and rebase BSP across an RNAT slot")
    require(rse_state_result.rse_rnat == (U64_MASK >> 1) and
            rse_state_result.gr[22] == (U64_MASK >> 1),
            "RNAT state/readback did not clear bit 63")
    require(rse_state_result.rse_rsc == valid_rsc and
            rse_state_result.gr[23] == valid_rsc,
            "RSC legal fields did not round-trip with mode non-zero")

    # BSPSTORE has three architectural write resources: BSPSTORE itself, BSP,
    # and the now-undefined RNAT image.  Reads later in the same instruction
    # group still select all three entry images; the next group observes the
    # retired BSPSTORE/BSP values.  Span two MMI bundles to exercise the full
    # implicit destination set, rather than only the named selector.
    bspstore_overlay = harness.Program(
        name="BSPSTORE implicit application-register source overlay",
        bundles=(
            movl_bundle(harness, 0x10, 2, 0x61FF),
            movl_bundle(harness, 0x20, 3, 0x55),
            harness.Bundle(0x30, 0x01,
                           harness.mov_m_grar(AR_RNAT, 3),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x40, 0x08,
                           harness.mov_m_grar(AR_BSPSTORE, 2),
                           harness.mov_m_argr(20, AR_BSP), harness.nop_i()),
            harness.Bundle(0x50, 0x09,
                           harness.mov_m_argr(21, AR_BSPSTORE),
                           harness.mov_m_argr(22, AR_RNAT), harness.nop_i()),
            harness.Bundle(0x60, 0x09,
                           harness.mov_m_argr(23, AR_BSP),
                           harness.mov_m_argr(24, AR_BSPSTORE),
                           harness.nop_i()),
            harness.spin_bundle(0x70),
        ), terminal_ip=0x70,
    )
    bspstore_overlay_result = harness.run_program(
        qemu, bspstore_overlay,
        typed_direct_trace_ips=(0x30, 0x40, 0x50, 0x60),
    )
    require(bspstore_overlay_result.gr[20] == 0 and
            bspstore_overlay_result.gr[21] == 0 and
            bspstore_overlay_result.gr[22] == 0x55,
            "BSPSTORE implicit writes escaped the issue-group source overlay")
    require(bspstore_overlay_result.gr[23] == 0x6200 and
            bspstore_overlay_result.gr[24] == 0x61F8,
            "BSPSTORE/BSP writes were not visible after the group stop")

    pfs_immediate = harness.Program(
        name="MOV_IMMAR PFS issue-group overlay",
        bundles=(
            movl_bundle(harness, 0x10, 2, 0x11),
            raw_bundle(harness, 0x20, "I",
                       harness.mov_i_grar(AR_PFS, 2)),
            harness.Bundle(0x30, 0x00, harness.nop_m(),
                           mov_immar(AR_PFS, 0x22, unit="I"),
                           harness.mov_argr(31, AR_PFS)),
            harness.Bundle(0x40, 0x01, harness.nop_m(),
                           harness.nop_i(), harness.nop_i()),
            raw_bundle(harness, 0x50, "I",
                       harness.mov_argr(30, AR_PFS)),
            harness.Bundle(0x60, 0x01, harness.nop_m(),
                           harness.cmp_rr(1, 2, 0, 0, "lt"),
                           harness.nop_i()),
            raw_bundle(harness, 0x70, "I",
                       mov_immar(AR_PFS, 0x33, qp=1, unit="I")),
            raw_bundle(harness, 0x80, "I",
                       harness.mov_argr(29, AR_PFS)),
            harness.spin_bundle(0x90),
        ), terminal_ip=0x90,
    )
    pfs_immediate_result = harness.run_program(
        qemu, pfs_immediate,
        typed_direct_trace_ips=(0x20, 0x30, 0x50),
    )
    require(pfs_immediate_result.gr[31] == 0x11 and
            pfs_immediate_result.gr[30] == 0x22 and
            pfs_immediate_result.gr[29] == 0x22,
            "MOV_IMMAR PFS violated ordinary or false-qualified visibility")

    # RSC.pl cannot be made more privileged than the current CPL.  Return to
    # CPL3, request PL0, and observe the clamped PL3 image.
    rsc_pl = harness.Program(
        name="RSC privilege-level clamp",
        bundles=lower_cpl_prefix(harness, 0x80) + (
            movl_bundle(harness, 0x80, 2, 0),
            harness.Bundle(0x90, 0x01,
                           harness.mov_m_grar(AR_RSC, 2),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xA0, 0x01,
                           harness.mov_m_argr(27, AR_RSC),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(0xB0),
        ), terminal_ip=0xB0,
    )
    rsc_result = harness.run_program(
        qemu, rsc_pl,
        typed_direct_trace_ips=(0x10, 0x20, 0x90, 0xA0),
    )
    require(rsc_result.gr[27] == 0xC,
            "RSC.pl write at CPL3 was not clamped to PL3")

    def check_general(program: object, fault_ip: int, code: int,
                      message: str) -> object:
        result = harness.run_program(
            qemu, program, preserve_fault_slot=True,
            typed_direct_trace_ips=(0x10, 0x20, fault_ip),
        )
        require(result.ip == GENERAL_VECTOR and
                (result.cr_isr & ISR_CODE_MASK) == code,
                message + " produced the wrong fault class")
        require(result.cr_iip == fault_ip and result.slot_valid and
                result.slot_ip == fault_ip,
                message + " lost precise fault metadata")
        return result

    # A false predicate suppresses unit/selector illegality; the identical
    # p0 form faults before touching its destination.
    invalid_raw = harness.mov_argr(28, AR_UNAT)
    invalid_false = harness.Program(
        name="false-predicate invalid I-unit AR selector",
        bundles=(
            movl_bundle(harness, 0x10, 28, 0xBAD),
            raw_bundle(harness, 0x20, "I", invalid_raw | 1),
            harness.spin_bundle(0x30),
        ), terminal_ip=0x30,
    )
    invalid_false_result = harness.run_program(
        qemu, invalid_false, typed_direct_trace_ips=(0x20,)
    )
    require(not invalid_false_result.exception_pending and
            invalid_false_result.gr[28] == 0xBAD,
            "false predicate did not suppress invalid AR selector")
    invalid_true = harness.Program(
        name="true-predicate invalid I-unit AR selector",
        bundles=(
            raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            raw_bundle(harness, 0x30, "I", invalid_raw),
            harness.spin_bundle(GENERAL_VECTOR),
        ), terminal_ip=GENERAL_VECTOR,
    )
    check_general(invalid_true, 0x30, 0,
                  "true-predicate invalid I-unit AR selector")

    for destination in (0, 32):
        invalid_target = harness.Program(
            name="MOV_ARGR invalid target r{}".format(destination),
            bundles=(
                raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
                raw_bundle(harness, 0x20, "M", m_serial(0x31)),
                harness.Bundle(0x30, 0x01,
                               harness.mov_m_argr(destination, AR_CCV),
                               harness.nop_i(), harness.nop_i()),
                harness.spin_bundle(GENERAL_VECTOR),
            ), terminal_ip=GENERAL_VECTOR,
        )
        check_general(invalid_target, 0x30, 0,
                      "MOV_ARGR invalid target r{}".format(destination))

    reserved_values = (
        ("RSC", AR_RSC, 1 << 5, "M"),
        ("FPSR", AR_FPSR, 1 << 12, "M"),
        ("PFS", AR_PFS, 1 << 58, "I"),
    )
    for name, selector, value, unit in reserved_values:
        write = (harness.mov_i_grar(selector, 2) if unit == "I" else
                 harness.mov_m_grar(selector, 2))
        program = harness.Program(
            name="reserved application-register value " + name,
            bundles=(
                raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
                raw_bundle(harness, 0x20, "M", m_serial(0x31)),
                movl_bundle(harness, 0x30, 2, value),
                raw_bundle(harness, 0x40, unit, write),
                harness.spin_bundle(GENERAL_VECTOR),
            ), terminal_ip=GENERAL_VECTOR,
        )
        check_general(program, 0x40, ISR_RESERVED_REGISTER_FIELD,
                      "reserved " + name + " write")

    # BSPSTORE and RNAT cannot be read or written while RSC.mode is non-zero.
    for name, selector, write in (
        ("BSPSTORE read", AR_BSPSTORE, False),
        ("BSPSTORE write", AR_BSPSTORE, True),
        ("RNAT read", AR_RNAT, False),
        ("RNAT write", AR_RNAT, True),
    ):
        access = (harness.mov_m_grar(selector, 3) if write else
                  harness.mov_m_argr(29, selector))
        source = 0x61FF if selector == AR_BSPSTORE else U64_MASK
        program = harness.Program(
            name="RSC mode blocks " + name,
            bundles=(
                raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
                raw_bundle(harness, 0x20, "M", m_serial(0x31)),
                movl_bundle(harness, 0x30, 2, 1),
                harness.Bundle(0x40, 0x01,
                               harness.mov_m_grar(AR_RSC, 2),
                               harness.nop_i(), harness.nop_i()),
                movl_bundle(harness, 0x50, 3, source),
                raw_bundle(harness, 0x60, "M", access),
                harness.spin_bundle(GENERAL_VECTOR),
            ), terminal_ip=GENERAL_VECTOR,
        )
        mode_fault = check_general(
            program, 0x60, 0, "non-zero RSC.mode " + name)
        require(mode_fault.rse_rsc == 1 and
                mode_fault.rse_bsp == 0 and
                mode_fault.rse_bspstore == 0 and
                mode_fault.rse_bspload == 0 and
                mode_fault.rse_rnat == 0,
                "non-zero RSC.mode {} partially changed RSE state".format(
                    name))

    # AR.BSP is a legal read selector but read-only.  Its write illegality is
    # diagnosed before consuming a NaT source and cannot partially rebase RSE.
    bsp_nat_write = harness.Program(
        name="BSP read-only legality precedes source NaT",
        bundles=(
            raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            harness.Bundle(0x30, 0x01, harness.nop_m(),
                           harness.adds(8, 1, 0),
                           harness.adds(9, 0x1000, 0)),
            harness.Bundle(0x40, 0x01,
                           harness.mov_m_grar(AR_UNAT, 8),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x50, 0x01, harness.ld8_fill(2, 9),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x60, 0x01,
                           harness.mov_m_grar(AR_BSP, 2),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(GENERAL_VECTOR),
        ), terminal_ip=GENERAL_VECTOR,
        data=(harness.DataWord(0x1000, 0x1234, 8),),
    )
    bsp_nat_fault = check_general(
        bsp_nat_write, 0x60, 0, "BSP write with a NaT source")
    require(bsp_nat_fault.rse_bsp == 0 and
            bsp_nat_fault.rse_bspstore == 0 and
            bsp_nat_fault.rse_bspload == 0 and
            bsp_nat_fault.rse_rnat == 0,
            "illegal BSP write partially changed RSE state")

    # For a legal writable selector source NaT consumption instead precedes
    # the selector's reserved-value check.  The loaded payload poisons RSC bit
    # 5 so a reversed implementation would report Reserved Register Field.
    rsc_nat_write = harness.Program(
        name="RSC source NaT precedes reserved-value validation",
        bundles=(
            raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            harness.Bundle(0x30, 0x01, harness.nop_m(),
                           harness.adds(8, 1, 0),
                           harness.adds(9, 0x1000, 0)),
            harness.Bundle(0x40, 0x01,
                           harness.mov_m_grar(AR_UNAT, 8),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x50, 0x01, harness.ld8_fill(2, 9),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x60, 0x01,
                           harness.mov_m_grar(AR_RSC, 2),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(NAT_VECTOR),
        ), terminal_ip=NAT_VECTOR,
        data=(harness.DataWord(0x1000, 1 << 5, 8),),
    )
    rsc_nat_fault = harness.run_program(
        qemu, rsc_nat_write, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x10, 0x20, 0x60),
    )
    require(rsc_nat_fault.ip == NAT_VECTOR and
            (rsc_nat_fault.cr_isr & ISR_CODE_MASK) == 0x10 and
            rsc_nat_fault.cr_iip == 0x60 and
            rsc_nat_fault.slot_valid and rsc_nat_fault.slot_ip == 0x60,
            "RSC write checked reserved fields before source NaT")
    require(rsc_nat_fault.rse_rsc == 0,
            "NaT-consuming RSC write partially changed RSC")

    # Register NaT Consumption precedes reserved-value and privilege checks
    # for MOV-to-AR.  Construct the NaT after the privilege transition.
    itc_write = harness.Program(
        name="ITC source NaT precedes privilege",
        bundles=lower_cpl_prefix(harness, 0x80) + (
            harness.Bundle(0x80, 0x01, harness.nop_m(),
                           harness.adds(8, 1, 0),
                           harness.adds(9, 0x1000, 0)),
            harness.Bundle(0x90, 0x01,
                           harness.mov_m_grar(AR_UNAT, 8),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xA0, 0x01, harness.ld8_fill(2, 9),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xB0, 0x01,
                           harness.mov_m_grar(AR_ITC, 2),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(NAT_VECTOR),
        ), terminal_ip=NAT_VECTOR,
        data=(harness.DataWord(0x1000, 0x1234, 8),),
    )
    itc_write_result = harness.run_program(
        qemu, itc_write, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x10, 0x20, 0xB0),
    )
    require(itc_write_result.ip == NAT_VECTOR and
            (itc_write_result.cr_isr & ISR_CODE_MASK) == 0x10 and
            itc_write_result.cr_iip == 0xB0 and
            itc_write_result.slot_valid and
            itc_write_result.slot_ip == 0xB0,
            "CPL3 ITC write checked privilege before source NaT")

    # PSR.si makes ITC/RUC reads privileged outside CPL0.
    itc_read = harness.Program(
        name="PSR.si protects ITC reads",
        bundles=(
            raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            movl_bundle(harness, 0x30, 2, PSR_IC | PSR_SI),
            raw_bundle(harness, 0x40, "M", m_system(0x2D, r2=2)),
            raw_bundle(harness, 0x50, "M", m_serial(0x31)),
            movl_bundle(harness, 0x60, 10, 3 << 62),
            movl_bundle(harness, 0x70, 4, 0xB0),
            harness.Bundle(0x80, 0x01, harness.nop_m(),
                           harness.mov_i_grar(AR_PFS, 10),
                           harness.mov_grbr(6, 4)),
            harness.Bundle(0x90, 0x11, harness.nop_m(), harness.nop_i(),
                           harness.br_ret(6)),
            harness.spin_bundle(0xA0),
            harness.Bundle(0xB0, 0x01,
                           harness.mov_m_argr(30, AR_ITC),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(GENERAL_VECTOR),
        ), terminal_ip=GENERAL_VECTOR,
    )
    check_general(itc_read, 0xB0, ISR_PRIVILEGED_REGISTER,
                  "CPL3 PSR.si ITC read")
    return ("M/I selectors, RSE AR state transitions and mode legality, "
            "same-group visibility, reserved values, NaT and privilege "
            "priority pass")


def test_break_vmsw_bria_epc(harness: ModuleType, qemu: Path) -> str:
    immediate21 = 0x15555
    immediate62 = 0x123456789ABCDE & ((1 << 62) - 1)
    break_forms = (
        ("M", immediate21, 0,
         harness.Bundle(0x30, 0x03, break_m(immediate21),
                        harness.nop_i(), harness.nop_i())),
        ("I", immediate21, 1,
         harness.Bundle(0x30, 0x03, harness.nop_m(),
                        break_m(immediate21), harness.nop_i())),
        ("F", immediate21, 1,
         harness.Bundle(0x30, 0x0D, harness.nop_m(),
                        break_m(immediate21), harness.nop_i())),
        ("B", 0, 2,
         harness.Bundle(0x30, 0x11, harness.nop_m(),
                        harness.nop_i(), 0)),
        ("X", immediate62, 1,
         harness.Bundle(0x30, 0x05, harness.nop_m(),
                        immediate62 >> 21,
                        break_m(immediate62 & ((1 << 21) - 1)))),
    )
    for unit, expected_iim, expected_ri, fault_bundle in break_forms:
        break_program = harness.Program(
            name="typed BREAK.{} immediate fault".format(unit),
            bundles=(
                raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
                raw_bundle(harness, 0x20, "M", m_serial(0x31)),
                fault_bundle,
                raw_bundle(harness, BREAK_VECTOR, "M",
                           m_system(0x24, r1=30, r3=CR_IIM)),
                harness.spin_bundle(BREAK_VECTOR + 0x10),
            ), terminal_ip=BREAK_VECTOR + 0x10,
        )
        broke = harness.run_program(
            qemu, break_program, preserve_fault_slot=True,
            typed_direct_trace_ips=(0x10, 0x20, 0x30, BREAK_VECTOR),
        )
        require(broke.ip == BREAK_VECTOR + 0x10,
                "BREAK.{} did not execute its vector handler".format(unit))
        require(broke.gr[30] == expected_iim,
                "BREAK.{} recorded IIM 0x{:x}, expected 0x{:x}".format(
                    unit, broke.gr[30], expected_iim))
        expected_iipa = 0x20 if expected_ri == 0 else 0x30
        require(broke.cr_iip == 0x30 and
                broke.cr_iipa == expected_iipa,
                "BREAK.{} published incorrect IIP/IIPA".format(unit))

        # Reading CR.IIM in the first run is itself a potentially faulting
        # system instruction, so inspect the original transient slot in a
        # second run whose vector is the helper-free terminal spin.
        precise_program = harness.Program(
            name="typed BREAK.{} precise slot".format(unit),
            bundles=(
                raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
                raw_bundle(harness, 0x20, "M", m_serial(0x31)),
                fault_bundle,
                harness.spin_bundle(BREAK_VECTOR),
            ), terminal_ip=BREAK_VECTOR,
        )
        precise = harness.run_program(
            qemu, precise_program, preserve_fault_slot=True,
            typed_direct_trace_ips=(0x10, 0x20, 0x30),
        )
        require(precise.cr_iip == 0x30 and
                precise.cr_iipa == expected_iipa and
                precise.slot_valid and precise.slot_ip == 0x30 and
                precise.slot_ri == expected_ri,
                "BREAK.{} lost its precise fault-slot metadata".format(unit))

    # The target intentionally advertises no virtual-machine architecture.
    # VMSW therefore has the architected optional-feature Illegal Operation
    # behavior, rather than silently changing an unimplemented PSR.vm state.
    vmsw_program = harness.Program(
        name="VMSW unsupported optional feature",
        bundles=(
            raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            raw_bundle(harness, 0x30, "B",
                       encode_system_opcode("IA64_OP_VMSW")),
            harness.spin_bundle(GENERAL_VECTOR),
        ),
        terminal_ip=GENERAL_VECTOR,
    )
    vmsw = harness.run_program(
        qemu, vmsw_program, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x10, 0x20, 0x30),
    )
    require(vmsw.ip == GENERAL_VECTOR and
            (vmsw.cr_isr & ISR_CODE_MASK) == 0,
            "unsupported VMSW did not take Illegal Operation")
    require(vmsw.cr_iip == 0x30 and vmsw.cr_iipa == 0x30 and
            vmsw.slot_valid and vmsw.slot_ri == 2,
            "unsupported VMSW fault metadata is imprecise")

    vmsw_one_program = harness.Program(
        name="VMSW.1 unsupported optional feature",
        bundles=(
            raw_bundle(harness, 0x10, "M", m_mask(6, PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            raw_bundle(harness, 0x30, "B", bitfield(0x19, 27, 6)),
            harness.spin_bundle(GENERAL_VECTOR),
        ), terminal_ip=GENERAL_VECTOR,
    )
    vmsw_one = harness.run_program(
        qemu, vmsw_one_program, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x10, 0x20, 0x30),
    )
    require(vmsw_one.ip == GENERAL_VECTOR and
            (vmsw_one.cr_isr & ISR_CODE_MASK) == 0,
            "unsupported VMSW.1 did not take Illegal Operation")
    require(vmsw_one.cr_iip == 0x30 and vmsw_one.cr_iipa == 0x30 and
            vmsw_one.slot_valid and vmsw_one.slot_ri == 2,
            "unsupported VMSW.1 fault metadata is imprecise")

    vmsw_cpl3_program = harness.Program(
        name="VMSW unsupported feature precedes privilege",
        bundles=lower_cpl_prefix(harness, 0x80) + (
            raw_bundle(harness, 0x80, "B",
                       encode_system_opcode("IA64_OP_VMSW")),
            harness.spin_bundle(GENERAL_VECTOR),
        ), terminal_ip=GENERAL_VECTOR,
    )
    vmsw_cpl3 = harness.run_program(
        qemu, vmsw_cpl3_program, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x10, 0x20, 0x80),
    )
    require((vmsw_cpl3.cr_isr & ISR_CODE_MASK) == 0 and
            ((vmsw_cpl3.cr_ipsr >> PSR_CPL_SHIFT) & 3) == 3,
            "VMSW checked CPL before unsupported optional feature")
    require(vmsw_cpl3.cr_iip == 0x80 and vmsw_cpl3.cr_iipa == 0x80 and
            vmsw_cpl3.slot_valid and vmsw_cpl3.slot_ri == 2,
            "CPL3 VMSW fault metadata is imprecise")

    bria_program = harness.Program(
        name="BR_IA disabled transition",
        bundles=(
            raw_bundle(harness, 0x10, "M", m_mask(6, PSR_DI | PSR_IC)),
            raw_bundle(harness, 0x20, "M", m_serial(0x31)),
            movl_bundle(harness, 0x30, 4, 0x100),
            harness.Bundle(0x40, 0x01, harness.nop_m(),
                           harness.mov_grbr(6, 4), harness.nop_i()),
            raw_bundle(harness, 0x50, "B", br_ia(6)),
            harness.spin_bundle(GENERAL_VECTOR),
        ), terminal_ip=GENERAL_VECTOR,
    )
    bria = harness.run_program(
        qemu, bria_program, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x10, 0x20, 0x50),
    )
    require((bria.cr_isr & ISR_CODE_MASK) == ISR_DISABLED_ISA_TRANSITION,
            "BR_IA with PSR.di did not take Disabled ISA Transition")
    require(bria.cr_iip == 0x50 and bria.cr_iipa == 0x50 and
            bria.slot_valid and bria.slot_ri == 2,
            "BR_IA disabled-transition fault metadata is imprecise")

    epc_program = harness.Program(
        name="EPC promotes CPL3 with IT disabled",
        bundles=lower_cpl_prefix(harness, 0x80) + (
            raw_bundle(harness, 0x80, "B", encode_system_opcode("IA64_OP_EPC")),
            raw_bundle(harness, 0x90, "M", m_system(0x25, r1=20)),
            harness.spin_bundle(0xA0),
        ), terminal_ip=0xA0,
    )
    epc = harness.run_program(
        qemu, epc_program,
        typed_direct_trace_ips=(0x10, 0x20, 0x80, 0x90),
    )
    require(((epc.psr >> PSR_CPL_SHIFT) & 3) == 0,
            "EPC did not promote CPL3 to CPL0 with PSR.it clear")
    return ("five BREAK forms/IIM, optional VMSW, disabled BR_IA, and EPC "
            "control paths pass")


def test_timer_interrupt(harness: ModuleType, qemu: Path) -> str:
    # Reuse only the generic program-building primitives from the common
    # harness.  Assertions and the expanded system-row trace are local.
    program = harness.timer_external_interrupt_rfi_program()
    snapshot = harness.run_program(
        qemu, program,
        typed_direct_trace_ips=(0x20, 0x30, 0x40, 0x3000),
        typed_rfi_traces=(0x3010,), one_bundle_per_tb=True,
    )
    require(snapshot.ip == program.terminal_ip and snapshot.gr[20] == 1,
            "timer interrupt handler did not run and return")
    require(snapshot.gr[15] == 0x40,
            "MOV_CRGR(IVR) did not consume timer vector 0x40")
    return "CR.ITM/ITV writes, SSM(IC|I), HARD delivery, IVR read and RFI pass"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    args = parser.parse_args()
    harness = load_harness(args.harness.resolve())
    qemu = args.qemu.resolve()

    require(len(SYSTEM_OPCODES) == 57 and len(SPEC_BY_OPCODE) == 57,
            "runtime system inventory is not exactly 57 unique rows")
    tests = (
        ("predicated 57-row admission", test_predicated_admission),
        ("unpredicated control rows", test_control_rows),
        ("system-register round trips", test_move_roundtrips),
        ("performance register selector domains",
         test_performance_register_selector_domains),
        ("CPUID fixed and reserved selector domain",
         test_cpuid_selector_domain),
        ("debug register selector domains",
         test_debug_register_selector_domains),
        ("protection key register file",
         test_protection_key_register_file),
        ("protection key permissions", test_protection_key_permissions),
        ("PAL performance monitor discovery",
         test_pal_performance_monitor_info),
        ("PAL debug-register discovery", test_pal_debug_info),
        ("PAL virtual-memory summary", test_pal_virtual_memory_summary),
        ("generated NaT matrix", test_nat_matrix),
        ("generated privilege matrix", test_privilege_matrix),
        ("reserved and predicate priority", test_reserved_matrix),
        ("translation lifecycle", test_tlb_lifecycle),
        ("instruction translation lifecycle", test_instruction_tlb_lifecycle),
        ("active mask controls", test_active_mask_controls),
        ("architectural debug registers", test_architectural_debug_registers),
        ("unaligned translation priority", test_unaligned_translation_priority),
        ("group alias and barriers", test_group_alias_and_barriers),
        ("application-register plane", test_application_register_plane),
        ("exceptional control rows", test_break_vmsw_bria_epc),
        ("timer interrupt and serialization", test_timer_interrupt),
    )
    print("TAP version 13")
    print("1..{}".format(len(tests)))
    failed = False
    for number, (name, function) in enumerate(tests, 1):
        try:
            detail = function(harness, qemu)
            print("ok {} - {}".format(number, name))
            print("# " + detail)
        except Exception as exc:
            failed = True
            print("not ok {} - {}".format(number, name))
            print("# " + str(exc).replace("\n", "\n# "))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
