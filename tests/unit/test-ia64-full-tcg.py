#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""No-OS architectural tests for the typed IA-64 TCG translator.

The test injects hand-encoded bundles with QEMU's generic loader, runs them on
the vibtanium machine, and reads architectural state through a TCP HMP monitor.
Each program runs in a fresh QEMU process so architectural state, migration
state, and TCG operation traces remain isolated between cases.
"""

import argparse
import dataclasses
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Sequence, Set, Tuple


SLOT_MASK = (1 << 41) - 1
U64_MASK = (1 << 64) - 1
IA64_ALTERNATE_DATA_TLB_VECTOR = 0x1000
IA64_DATA_NESTED_TLB_VECTOR = 0x1400
IA64_GENERAL_EXCEPTION_VECTOR = 0x5400
IA64_REGISTER_NAT_CONSUMPTION_VECTOR = 0x5600
IA64_UNALIGNED_DATA_REFERENCE_VECTOR = 0x5A00
IA64_LOWER_PRIVILEGE_TRANSFER_VECTOR = 0x5E00
IA64_TAKEN_BRANCH_TRAP_VECTOR = 0x5F00
IA64_PSR_IC = 1 << 13
IA64_PSR_I = 1 << 14
IA64_PSR_DT = 1 << 17
IA64_PSR_LP = 1 << 25
IA64_PSR_TB = 1 << 26
IA64_PSR_RT = 1 << 27
IA64_ISR_R = 1 << 34
IA64_ISR_RS = 1 << 37
IA64_ISR_IR = 1 << 38
IA64_PSR_RI_SHIFT = 41
IA64_ISR_NI = 1 << 39
IA64_ISR_EI_SHIFT = 41
IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION = 0x10
IA64_SLOT_TYPE_M = 1
IA64_SLOT_TYPE_I = 2
IA64_AR_PFS = 64
IA64_AR_LC = 65
IA64_AR_ITC = 44
IA64_CR_ITM = 1
IA64_CR_IVR = 65
IA64_CR_EOI = 67
IA64_CR_ITV = 72
IA64_CR_IPSR = 16
IA64_CR_ISR = 17
IA64_CR_IIP = 19
IA64_CR_IFA = 20
IA64_CR_ITIR = 21
IA64_CR_IIPA = 22
IA64_CR_IFS = 23
IA64_GDB_IP_REGNUM = 128
IA64_GDB_PSR_REGNUM = 129
MONITOR_CONNECT_TIMEOUT = 5.0
PROGRAM_TIMEOUT = 5.0
PROCESS_EXIT_TIMEOUT = 2.0
MIGRATION_TIMEOUT = 15.0
SOURCE_ROOT = Path(__file__).resolve().parents[2]
FIRMWARE_DIR = SOURCE_ROOT / "pc-bios"


class HarnessError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class Bundle:
    address: int
    template: int
    slot0: int
    slot1: int
    slot2: int


@dataclasses.dataclass(frozen=True)
class DataWord:
    address: int
    value: int
    size: int


@dataclasses.dataclass(frozen=True)
class Snapshot:
    ip: int
    psr: int
    psr_ic_inflight: bool
    pr: int
    cfm: int
    rse_rsc: int
    rse_bsp: int
    rse_bspstore: int
    rse_bspload: int
    rse_rnat: int
    rse_base: int
    nat_high: int
    nat_low: int
    unat: int
    nat_rnat: int
    cr_iva: int
    cr_iip: int
    cr_isr: int
    cr_ifa: int
    cr_iipa: int
    cr_ipsr: int
    exception_pending: bool
    exception_kind: str
    exception_vector: int
    exception_source: int
    exception_address: int
    slot_valid: bool
    slot_ip: int
    slot_ri: int
    slot_type: int
    slot_raw: int
    gr: Tuple[int, ...]
    br: Tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class MigrationResult:
    checkpoint: Snapshot
    restored: Snapshot
    final: Snapshot
    source_trace: str
    destination_trace: str


@dataclasses.dataclass(frozen=True)
class Program:
    name: str
    bundles: Tuple[Bundle, ...]
    terminal_ip: int
    data: Tuple[DataWord, ...] = ()
    entry: int = 0x10


@dataclasses.dataclass(frozen=True)
class LoopExpectation:
    label: str
    output_base: int
    old_marker: int
    new_marker: int
    taken: bool
    rotated: bool
    injected: bool
    final_lc: int
    final_ec: int


def bitfield(value: int, low: int, width: int) -> int:
    return (value & ((1 << width) - 1)) << low


def op(major: int) -> int:
    return bitfield(major, 37, 4)


def nop_m() -> int:
    return bitfield(1, 27, 4)


def nop_i() -> int:
    return bitfield(1, 27, 6)


def _processor_mask(x6: int, mask: int, qp: int = 0) -> int:
    if x6 not in (0x06, 0x07):
        raise ValueError("processor-mask opcode must be SSM or RSM")
    if not 0 <= mask < (1 << 24):
        raise ValueError("processor mask must fit in 24 bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        bitfield(x6, 27, 6)
        | bitfield(mask & 0x7f, 6, 7)
        | bitfield((mask >> 7) & 0x7f, 13, 7)
        | bitfield((mask >> 14) & 0x7f, 20, 7)
        | bitfield((mask >> 21) & 0x3, 31, 2)
        | bitfield((mask >> 23) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def ssm(mask: int, qp: int = 0) -> int:
    return _processor_mask(0x06, mask, qp)


def rsm(mask: int, qp: int = 0) -> int:
    return _processor_mask(0x07, mask, qp)


def mov_gr_to_psr_l(r2: int, qp: int = 0) -> int:
    """Encode M35 ``mov psr.l = r2`` for branch-trap setup."""
    if not 0 <= r2 < 128:
        raise ValueError("PSR.l source must be a GR")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        op(1)
        | bitfield(0x2d, 27, 6)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def mov_crgr(r1: int, cr: int, qp: int = 0) -> int:
    """Encode M32 ``mov r1 = cr``."""
    if not 0 <= r1 < 128 or not 0 <= cr < 128:
        raise ValueError("control-register move operands must fit in seven bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        op(1)
        | bitfield(0x24, 27, 6)
        | bitfield(cr, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_grcr(cr: int, r2: int, qp: int = 0) -> int:
    """Encode M33 ``mov cr = r2``."""
    if not 0 <= cr < 128 or not 0 <= r2 < 128:
        raise ValueError("control-register move operands must fit in seven bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        op(1)
        | bitfield(0x2c, 27, 6)
        | bitfield(cr, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def itc_d(r2: int, qp: int = 0) -> int:
    """Encode M42 ``itc.d r2`` for a data-translation-cache entry."""
    if not 0 <= r2 < 128:
        raise ValueError("translation source must fit in seven bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        op(1)
        | bitfield(0x2e, 27, 6)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def _serialization_m(x6: int, qp: int = 0) -> int:
    if x6 not in (0x30, 0x31, 0x33):
        raise ValueError("M serialization opcode must be srlz.d/i or sync.i")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return bitfield(x6, 27, 6) | bitfield(qp, 0, 6)


def srlz_d(qp: int = 0) -> int:
    return _serialization_m(0x30, qp)


def srlz_i(qp: int = 0) -> int:
    return _serialization_m(0x31, qp)


def sync_i(qp: int = 0) -> int:
    return _serialization_m(0x33, qp)


def rfi() -> int:
    return bitfield(0x08, 27, 6)


def alloc(r1: int, sof: int, sol: int, sor: int, qp: int = 0) -> int:
    return (
        op(1)
        | bitfield(6, 33, 3)
        | bitfield(sor, 27, 4)
        | bitfield(sol, 20, 7)
        | bitfield(sof, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def adds(r1: int, immediate: int, r3: int, qp: int = 0) -> int:
    encoded = immediate & 0x3fff
    return (
        op(8)
        | bitfield(2, 34, 2)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield((encoded >> 7) & 0x3f, 27, 6)
        | bitfield((encoded >> 13) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def alu(x4: int, x2b: int, r1: int, r2: int, r3: int,
        qp: int = 0) -> int:
    return (
        op(8)
        | bitfield(x4, 29, 4)
        | bitfield(x2b, 27, 2)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def add(r1: int, r2: int, r3: int, qp: int = 0) -> int:
    return alu(0, 0, r1, r2, r3, qp)


# These encoders are derived from the policy-free decoder and the GPL-2.0+
# reference vectors in external-src/qemu-system-ia64-main/tests/unit.
def shl_var(r1: int, value: int, count: int, qp: int = 0) -> int:
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(8, 27, 6)
        | bitfield(count, 20, 7)
        | bitfield(value, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def shru_var(r1: int, value: int, count: int, qp: int = 0) -> int:
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(1, 33, 1)
        | bitfield(0, 27, 6)
        | bitfield(value, 20, 7)
        | bitfield(count, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def shr_var(r1: int, value: int, count: int, qp: int = 0) -> int:
    return shru_var(r1, value, count, qp) | bitfield(4, 27, 6)


def shl_imm(r1: int, r3: int, count: int, qp: int = 0) -> int:
    if not 0 <= count <= 63:
        raise ValueError("immediate shift must be in [0, 63]")
    # The architectural alias is canonically decoded as dep.z.
    return depz(r1, r3, count, 64 - count, qp)


def shrp_imm(r1: int, r2: int, r3: int, count: int,
             qp: int = 0) -> int:
    return (
        op(5)
        | bitfield(3, 34, 2)
        | bitfield(count, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def dep(r1: int, r2: int, r3: int, pos: int, length: int,
        qp: int = 0) -> int:
    cpos = 63 - pos
    return (
        op(4)
        | bitfield(length - 1, 27, 4)
        | bitfield(cpos & 0x3, 31, 2)
        | bitfield((cpos >> 2) & 1, 33, 1)
        | bitfield((cpos >> 3) & 0x3, 34, 2)
        | bitfield((cpos >> 5) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def depz(r1: int, r2: int, pos: int, length: int, qp: int = 0) -> int:
    return (
        op(5)
        | bitfield(r1, 6, 7)
        | bitfield(r2, 13, 7)
        | bitfield(63 - pos, 20, 7)
        | bitfield(length - 1, 27, 6)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(qp, 0, 6)
    )


def depz_imm(r1: int, immediate: int, pos: int, length: int,
             qp: int = 0) -> int:
    encoded = immediate & 0xff
    return (
        op(5)
        | bitfield(r1, 6, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(127 - pos, 20, 7)
        | bitfield(length - 1, 27, 6)
        | bitfield(1, 33, 1)
        | bitfield(1, 34, 2)
        | bitfield(encoded >> 7, 36, 1)
        | bitfield(qp, 0, 6)
    )


def dep_imm(r1: int, fill: int, r3: int, pos: int, length: int,
            qp: int = 0) -> int:
    return (
        op(5)
        | bitfield(r1, 6, 7)
        | bitfield((63 - pos) << 1, 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(length - 1, 27, 6)
        | bitfield(1, 33, 1)
        | bitfield(3, 34, 2)
        | bitfield(fill, 36, 1)
        | bitfield(qp, 0, 6)
    )


def extr(r1: int, r3: int, pos: int, length: int,
         signed: bool = False, qp: int = 0) -> int:
    return (
        op(5)
        | bitfield(r1, 6, 7)
        | bitfield((pos << 1) | int(signed), 13, 7)
        | bitfield(r3, 20, 7)
        | bitfield(length - 1, 27, 6)
        | bitfield(1, 34, 2)
        | bitfield(qp, 0, 6)
    )


def integer_extend(r1: int, r3: int, width: int, signed: bool,
                   qp: int = 0) -> int:
    x6 = ({1: 0x14, 2: 0x15, 4: 0x16}[width]
          if signed else {1: 0x10, 2: 0x11, 4: 0x12}[width])
    return (
        op(0)
        | bitfield(x6, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def popcnt(r1: int, r3: int, qp: int = 0) -> int:
    return (
        op(7)
        | bitfield(0x12, 27, 6)
        | bitfield(3, 33, 3)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def clz(r1: int, r3: int, qp: int = 0) -> int:
    return popcnt(r1, r3, qp) ^ bitfield(0x08, 27, 6)


def mpy4(r1: int, r2: int, r3: int, high_left: bool = False,
         qp: int = 0) -> int:
    return (
        op(7)
        | bitfield(1, 36, 1)
        | bitfield(0x1e if high_left else 0x1a, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def shladdp4(r1: int, r2: int, shift: int, r3: int,
             qp: int = 0) -> int:
    return alu(6, shift - 1, r1, r2, r3, qp)


def addp4(r1: int, r2: int, r3: int, qp: int = 0) -> int:
    return alu(2, 0, r1, r2, r3, qp)


def addp4_imm(r1: int, immediate: int, r3: int, qp: int = 0) -> int:
    encoded = immediate & 0x3fff
    return (
        op(8)
        | bitfield(3, 34, 2)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield((encoded >> 7) & 0x3f, 27, 6)
        | bitfield((encoded >> 13) & 1, 36, 1)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def cmp_rr(p1: int, p2: int, r2: int, r3: int, relation: str,
           width: int = 8, unc: bool = False, qp: int = 0) -> int:
    major = {"lt": 0xc, "ltu": 0xd, "eq": 0xe}.get(relation)
    if major is None:
        raise ValueError("A6 comparison relation must be lt, ltu, or eq")
    if width not in (4, 8):
        raise ValueError("A6 comparison width must be four or eight bytes")
    return (
        op(major)
        | bitfield(1 if width == 4 else 0, 34, 2)
        | bitfield(p2, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(int(unc), 12, 1)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_imm(p1: int, p2: int, immediate: int, r3: int, relation: str,
            width: int = 8, unc: bool = False, qp: int = 0) -> int:
    """Encode canonical A8 ``cmp[4].{lt,ltu,eq}[.unc] imm8,r3``."""
    major = {"lt": 0xc, "ltu": 0xd, "eq": 0xe}.get(relation)
    if major is None:
        raise ValueError("A8 comparison relation must be lt, ltu, or eq")
    if width not in (4, 8):
        raise ValueError("A8 comparison width must be four or eight bytes")
    if not -128 <= immediate <= 127:
        raise ValueError("A8 comparison immediate must fit signed imm8")
    encoded = immediate & 0xff
    return (
        op(major)
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(3 if width == 4 else 2, 34, 2)
        | bitfield(p2, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(int(unc), 12, 1)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )


def _cmp_merge_major(completer: str) -> int:
    major = {"and": 0xc, "or": 0xd, "or.andcm": 0xe}.get(completer)
    if major is None:
        raise ValueError(
            "parallel comparison completer must be and, or, or or.andcm"
        )
    return major


def cmp_merge_rr(p1: int, p2: int, r2: int, r3: int, completer: str,
                 relation: str, width: int = 8, qp: int = 0) -> int:
    """Encode A6 ``cmp[4].{eq,ne}.{and,or,or.andcm}``.

    Parallel register compares have tb=0 and ta=1.  Unlike normal A6, bit 12
    selects eq/ne rather than the ``unc`` completer.
    """
    if relation not in ("eq", "ne"):
        raise ValueError("parallel A6 comparison relation must be eq or ne")
    if width not in (4, 8):
        raise ValueError("parallel A6 comparison width must be four or eight")
    return (
        op(_cmp_merge_major(completer))
        | bitfield(1 if width == 4 else 0, 34, 2)
        | bitfield(1, 33, 1)
        | bitfield(p2, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(int(relation == "ne"), 12, 1)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_merge_imm(p1: int, p2: int, immediate: int, r3: int,
                  completer: str, relation: str, width: int = 8,
                  qp: int = 0) -> int:
    """Encode A8 ``cmp[4].{eq,ne}.{and,or,or.andcm} imm8,r3``."""
    if relation not in ("eq", "ne"):
        raise ValueError("parallel A8 comparison relation must be eq or ne")
    if width not in (4, 8):
        raise ValueError("parallel A8 comparison width must be four or eight")
    if not -128 <= immediate <= 127:
        raise ValueError("parallel A8 immediate must fit signed imm8")
    encoded = immediate & 0xff
    return (
        op(_cmp_merge_major(completer))
        | bitfield((encoded >> 7) & 1, 36, 1)
        | bitfield(3 if width == 4 else 2, 34, 2)
        | bitfield(1, 33, 1)
        | bitfield(p2, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(encoded & 0x7f, 13, 7)
        | bitfield(int(relation == "ne"), 12, 1)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )


def cmp_merge_zero(p1: int, p2: int, r3: int, completer: str,
                   relation: str, width: int = 8, qp: int = 0) -> int:
    """Encode A7 ``cmp[4].rel.{and,or,or.andcm} p1,p2=0,r3``."""
    selector = {
        "gt": (0, 0),
        "le": (0, 1),
        "ge": (1, 0),
        "lt": (1, 1),
    }.get(relation)
    if selector is None:
        raise ValueError("parallel A7 relation must be gt, le, ge, or lt")
    if width not in (4, 8):
        raise ValueError("parallel A7 comparison width must be four or eight")
    ta, c = selector
    return (
        op(_cmp_merge_major(completer))
        | bitfield(1, 36, 1)
        | bitfield(1 if width == 4 else 0, 34, 2)
        | bitfield(ta, 33, 1)
        | bitfield(p2, 27, 6)
        | bitfield(r3, 20, 7)
        | bitfield(c, 12, 1)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )


def predicate_test(kind: str, p1: int, p2: int, *, relation: str,
                   update: str, r3: int = 0, immediate: int = 0,
                   unc: bool = False, qp: int = 0) -> int:
    """Encode canonical I16/I17/I30 predicate tests.

    This literal c/ta/tb mapping is independent of the production decoder.
    Normal assignment has only a ``z`` opcode; ``nz`` belongs to the three
    parallel merge classes.
    """
    if kind not in ("tbit", "tnat", "tf"):
        raise ValueError("predicate test must be tbit, tnat, or tf")
    if relation not in ("z", "nz"):
        raise ValueError("predicate-test relation must be z or nz")
    if update not in ("normal", "and", "or", "or.andcm"):
        raise ValueError("invalid predicate-test update")
    if update == "normal":
        if relation != "z":
            raise ValueError("normal predicate tests only encode relation z")
        c, ta, tb = int(unc), 0, 0
    else:
        if unc:
            raise ValueError("parallel predicate tests cannot use .unc")
        c = int(relation == "nz")
        ta, tb = {
            "and": (0, 1),
            "or": (1, 0),
            "or.andcm": (1, 1),
        }[update]

    raw = (
        op(5)
        | bitfield(tb, 36, 1)
        | bitfield(ta, 33, 1)
        | bitfield(p2, 27, 6)
        | bitfield(c, 12, 1)
        | bitfield(p1, 6, 6)
        | bitfield(qp, 0, 6)
    )
    if kind == "tbit":
        if not 0 <= r3 < 128 or not 0 <= immediate < 64:
            raise ValueError("tbit requires GR r3 and a six-bit position")
        return raw | bitfield(r3, 20, 7) | bitfield(immediate, 14, 6)
    if kind == "tnat":
        if not 0 <= r3 < 128 or immediate != 0:
            raise ValueError("tnat requires GR r3 and no immediate")
        return raw | bitfield(r3, 20, 7) | bitfield(1, 13, 1)
    if r3 != 0 or not 32 <= immediate < 64:
        raise ValueError("tf requires r3=0 and CPUID[4] bit 32..63")
    return (
        raw
        | bitfield(1, 19, 1)
        | bitfield(immediate - 32, 14, 5)
        | bitfield(1, 13, 1)
    )


def mov_i_grar(ar: int, r2: int, qp: int = 0) -> int:
    return (
        op(0)
        | bitfield(0x2a, 27, 6)
        | bitfield(ar, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def mov_current_ip(r1: int, qp: int = 0) -> int:
    """Encode I25 ``mov r1 = ip``."""
    if not 0 <= r1 < 128:
        raise ValueError("current-IP destination must be a GR")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return bitfield(0x30, 27, 6) | bitfield(r1, 6, 7) | qp


def mov_argr(r1: int, ar: int, qp: int = 0) -> int:
    """Encode I28 ``mov r1 = ar`` for loop-counter readback."""
    if not 0 <= r1 < 128 or not 0 <= ar < 128:
        raise ValueError("AR-to-GR move operands must fit in seven bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        bitfield(0x32, 27, 6)
        | bitfield(ar, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_pfs_to_gr(r1: int, qp: int = 0) -> int:
    """Encode the legal I28 ``mov.i r1 = ar.pfs`` specialization."""
    return mov_argr(r1, IA64_AR_PFS, qp)


def mov_gr_to_pfs(r2: int, qp: int = 0) -> int:
    """Encode the legal I26 ``mov.i ar.pfs = r2`` specialization."""
    return mov_i_grar(IA64_AR_PFS, r2, qp)


def mov_prgr(r1: int, qp: int = 0) -> int:
    """Encode I25 ``mov r1 = pr``."""
    if not 0 <= r1 < 128:
        raise ValueError("predicate-image destination must be a GR")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        bitfield(0x33, 27, 6)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_grpr(r2: int, mask17: int, qp: int = 0) -> int:
    """Encode I23 ``mov pr = r2, mask17``.

    Bit zero cannot select p0.  Encoded mask bit 16 is sign-extended by the
    architecture and therefore selects either all or none of p16..p63.
    """
    if not 0 <= r2 < 128:
        raise ValueError("predicate-image source must be a GR")
    if not 0 <= mask17 < (1 << 17):
        raise ValueError("predicate mask must fit in 17 bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        bitfield(3, 33, 3)
        | bitfield((mask17 >> 16) & 1, 36, 1)
        | bitfield(1, 32, 1)
        | bitfield((mask17 >> 8) & 0xff, 24, 8)
        | bitfield(r2, 13, 7)
        | bitfield((mask17 >> 1) & 0x7f, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_pr_rot_imm(immediate: int, qp: int = 0) -> int:
    """Encode I24 ``mov pr.rot = imm44`` with its implicit low 16 zeros."""
    if not -(1 << 43) <= immediate < (1 << 43):
        raise ValueError("rotating-predicate immediate must fit signed imm44")
    if immediate & 0xffff:
        raise ValueError("rotating-predicate immediate must have 16 low zeros")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")

    encoded = (immediate >> 16) & ((1 << 28) - 1)
    return (
        bitfield((encoded >> 27) & 1, 36, 1)
        | bitfield(2, 33, 3)
        | bitfield((encoded >> 26) & 1, 32, 1)
        | bitfield((encoded >> 18) & 0xff, 24, 8)
        | bitfield((encoded >> 14) & 0xf, 20, 4)
        | bitfield((encoded >> 7) & 0x7f, 13, 7)
        | bitfield(encoded & 0x7f, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_brgr(r1: int, b2: int, qp: int = 0) -> int:
    """Encode I21 ``mov r1 = b2`` using the canonical zero hints."""
    if not 0 <= r1 < 128:
        raise ValueError("branch-register move destination must be a GR")
    if not 0 <= b2 < 8:
        raise ValueError("branch-register source must fit in three bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        bitfield(0x31, 27, 6)
        | bitfield(b2, 13, 3)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_grbr(b1: int, r2: int, qp: int = 0) -> int:
    """Encode I22 ``mov b1 = r2`` using the canonical zero hints."""
    if not 0 <= b1 < 8:
        raise ValueError("branch-register destination must fit in three bits")
    if not 0 <= r2 < 128:
        raise ValueError("branch-register move source must be a GR")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        bitfield(7, 33, 3)
        | bitfield(r2, 13, 7)
        | bitfield(b1, 6, 3)
        | bitfield(qp, 0, 6)
    )


def ld8(r1: int, r3: int, qp: int = 0) -> int:
    """Encode the ordinary M1 ``ld8 r1 = [r3]`` form."""
    return (
        op(4)
        | bitfield(0x03, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def mov_m_grar(ar: int, r2: int, qp: int = 0) -> int:
    """Encode M29 ``mov.m ar = r2`` (the M-unit AR subset)."""
    return (
        op(1)
        | bitfield(0x2a, 27, 6)
        | bitfield(ar, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def mov_m_argr(r1: int, ar: int, qp: int = 0) -> int:
    """Encode M31 ``mov.m r1 = ar`` (the M-unit AR subset)."""
    return (
        op(1)
        | bitfield(0x22, 27, 6)
        | bitfield(ar, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def st8(r2: int, r3: int, qp: int = 0) -> int:
    """Encode the ordinary M4 ``st8 [r3] = r2`` form."""
    if not 0 <= r2 < 128 or not 0 <= r3 < 128:
        raise ValueError("store GR operands must fit in seven bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        op(4)
        | bitfield(0x33, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7)
        | bitfield(qp, 0, 6)
    )


def ld8_fill(r1: int, r3: int, qp: int = 0) -> int:
    return (
        op(4)
        | bitfield(0x1b, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def ld8_advanced(r1: int, r3: int, qp: int = 0) -> int:
    """Encode M1 ``ld8.a r1 = [r3]`` for call-frame ALAT testing."""
    if not 0 <= r1 < 128 or not 0 <= r3 < 128:
        raise ValueError("advanced-load GR operands must fit in seven bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        op(4)
        | bitfield((2 << 2) | 3, 30, 6)
        | bitfield(r3, 20, 7)
        | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def chk_a(r2: int, source: int, target: int, *,
          clear: bool = False, qp: int = 0) -> int:
    """Encode integer M22 ``chk.a[.clr] r2,target``."""
    if not 0 <= r2 < 128:
        raise ValueError("advanced-check source must fit in seven bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    field = branch_target_field(source, target)
    return (
        bitfield(5 if clear else 4, 33, 3)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(r2, 6, 7)
        | bitfield(qp, 0, 6)
    )


def branch_target_field(source: int, target: int) -> int:
    displacement = target - source
    if displacement & 0xf:
        raise ValueError("IA-64 branch target must be bundle aligned")
    return (displacement >> 4) & 0x1fffff


def br_cond(source: int, target: int, qp: int = 0) -> int:
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def br_call(source: int, target: int, b1: int, qp: int = 0) -> int:
    """Encode B3 ``br.call b1 = target`` with canonical hint fields."""
    if not 0 <= b1 < 8:
        raise ValueError("call link register must fit in three bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    field = branch_target_field(source, target)
    return (
        op(5)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(b1, 6, 3)
        | bitfield(qp, 0, 6)
    )


def br_indirect(b2: int, qp: int = 0) -> int:
    """Encode B4 ``br.cond b2`` with canonical zero hints."""
    if not 0 <= b2 < 8:
        raise ValueError("indirect branch source must fit in three bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        bitfield(0x20, 27, 6)
        | bitfield(b2, 13, 3)
        | bitfield(qp, 0, 6)
    )


def br_call_indirect(b1: int, b2: int, qp: int = 0) -> int:
    """Encode B5 ``br.call b1 = b2`` with canonical hint fields."""
    if not 0 <= b1 < 8 or not 0 <= b2 < 8:
        raise ValueError("indirect-call BR operands must fit in three bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        op(1)
        | bitfield(1, 32, 1)
        | bitfield(b2, 13, 3)
        | bitfield(b1, 6, 3)
        | bitfield(qp, 0, 6)
    )


def br_ret(b2: int, qp: int = 0) -> int:
    """Encode B4 ``br.ret b2`` for controlled CPL setup."""
    if not 0 <= b2 < 8:
        raise ValueError("return target register must fit in three bits")
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    return (
        bitfield(0x21, 27, 6)
        | bitfield(b2, 13, 3)
        | bitfield(4, 6, 3)
        | bitfield(qp, 0, 6)
    )


def br_loop(kind: str, source: int, target: int, qp: int = 0) -> int:
    """Encode one of the five B1/B2 loop-branch forms."""
    btype = {
        "wexit": 2,
        "wtop": 3,
        "cloop": 5,
        "cexit": 6,
        "ctop": 7,
    }.get(kind)
    if btype is None:
        raise ValueError("loop branch must be wexit/wtop/cloop/cexit/ctop")
    if kind in ("cloop", "cexit", "ctop") and qp != 0:
        raise ValueError("counted loop branches fix their low six bits to zero")
    if not 0 <= qp < 64:
        raise ValueError("while-loop condition must fit in six bits")
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(btype, 6, 3)
        | bitfield(qp, 0, 6)
    )


def brl_cond(source: int, target: int,
             qp: int = 0) -> Tuple[int, int]:
    """Encode X3 ``brl.cond`` as its logical L/X slot pair."""
    displacement = target - source
    if displacement & 0xf:
        raise ValueError("IA-64 long-branch target must be bundle aligned")
    scaled = displacement >> 4
    if not -(1 << 59) <= scaled < (1 << 59):
        raise ValueError("IA-64 brl immediate does not fit signed imm60")
    field = scaled & ((1 << 60) - 1)
    l_slot = bitfield((field >> 20) & ((1 << 39) - 1), 2, 39)
    x_slot = (
        op(0xc)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 59) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )
    return l_slot, x_slot


def brl_call(source: int, target: int, b1: int,
             qp: int = 0) -> Tuple[int, int]:
    """Encode X4 ``brl.call b1 = target`` as its logical L/X pair."""
    if not 0 <= b1 < 8:
        raise ValueError("long-call link register must fit in three bits")
    l_slot, x_slot = brl_cond(source, target, qp)
    x_slot &= ~bitfield(0xf, 37, 4)
    x_slot |= op(0xd) | bitfield(b1, 6, 3)
    return l_slot, x_slot


def br_ctop(source: int, target: int, qp: int = 0) -> int:
    """Encode B2 ``br.ctop`` with btype 7 and a signed imm21 target."""
    field = branch_target_field(source, target)
    return (
        op(4)
        | bitfield(field & 0xfffff, 13, 20)
        | bitfield((field >> 20) & 1, 36, 1)
        | bitfield(7, 6, 3)
        | bitfield(qp, 0, 6)
    )


def bundle_words(bundle: Bundle) -> Tuple[int, int]:
    slots = (bundle.slot0, bundle.slot1, bundle.slot2)
    if bundle.address & 0xf:
        raise ValueError("IA-64 bundle address must be 16-byte aligned")
    if not 0 <= bundle.template < 32:
        raise ValueError("IA-64 bundle template must fit in five bits")
    if any(slot < 0 or slot > SLOT_MASK for slot in slots):
        raise ValueError("IA-64 instruction slot must fit in 41 bits")

    raw = (
        bundle.template
        | (bundle.slot0 << 5)
        | (bundle.slot1 << 46)
        | (bundle.slot2 << 87)
    )
    return raw & ((1 << 64) - 1), raw >> 64


def spin_bundle(address: int) -> Bundle:
    return Bundle(
        address, 0x11, nop_m(), nop_i(), br_cond(address, address)
    )


def core_program() -> Program:
    return Program(
        name="core integer equality",
        bundles=(
            # Keep the terminal branch separate so the core bundle's scalar
            # TCG trace remains independent of control-flow lowering.
            Bundle(0x10, 0x01, nop_m(), adds(1, 42, 0), adds(2, 7, 0)),
            Bundle(0x20, 0x11, nop_m(), nop_i(), br_cond(0x20, 0x20)),
        ),
        terminal_ip=0x20,
    )


def stacked_gr_pair_program() -> Program:
    return Program(
        name="stacked GR value/NaT pair and preserved writer",
        bundles=(
            # ALLOC is a dedicated frame-setup transaction.  It creates six
            # stacked registers with no rotating subset.
            Bundle(0x10, 0x01, alloc(34, 6, 4, 0), nop_i(), nop_i()),
            Bundle(0x20, 0x01, nop_m(), adds(32, 5, 0),
                   adds(33, 7, 0)),
            # The first bundle overwrites r32 without a stop.  The next
            # bundle must read the saved group-entry value twice, pairing its
            # NaT with that value, then retire a stacked r34 destination.
            Bundle(0x30, 0x00, nop_m(), adds(32, 1, 0), nop_i()),
            Bundle(0x40, 0x01, nop_m(), add(34, 32, 32), nop_i()),
            # A false-predicated stacked writer must not resolve or dirty a
            # physical RSE slot at runtime.
            Bundle(0x50, 0x01, nop_m(), adds(35, 99, 0, qp=1), nop_i()),
            Bundle(0x60, 0x11, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        ),
        terminal_ip=0x60,
    )


def ordinary_source_overlay_program() -> Program:
    return Program(
        name="ordinary-source overlay invariant",
        bundles=(
            Bundle(0x10, 0x03, nop_m(), adds(1, 5, 0),
                   adds(4, 9, 0)),
            # This two-bundle group deliberately exercises the implementation's
            # saved ordinary-source view.  Ordinary same-group GR RAW is not an
            # Intel architectural golden; it is a deterministic internal
            # invariant proving repeated writers retain the first saved value.
            Bundle(0x20, 0x00, nop_m(), adds(1, 1, 0),
                   adds(1, 2, 0)),
            Bundle(0x30, 0x01, nop_m(), adds(2, 0, 1), nop_i()),
            # Seed p1=true at a stop, overwrite it in the next group, and prove
            # the ordinary (non-branch-forwarded) qualifier uses the old image.
            Bundle(0x40, 0x03, nop_m(),
                   cmp_rr(1, 2, 4, 4, "eq"), nop_i()),
            Bundle(0x50, 0x01, nop_m(),
                   cmp_rr(1, 2, 4, 4, "lt"),
                   adds(3, 11, 0, qp=1)),
            # A stop exposes the final live GR and PR images to the next group.
            Bundle(0x60, 0x03, nop_m(), adds(5, 0, 1),
                   adds(6, 12, 0, qp=2)),
            Bundle(0x70, 0x11, nop_m(), nop_i(), br_cond(0x70, 0x70)),
        ),
        terminal_ip=0x70,
    )


def nat_program() -> Program:
    data_value = 0x123456789abcdef0
    return Program(
        name="NaT architectural golden",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, 0x1000, 0)),
            # AR.UNAT is application register 36.  Bit zero describes the
            # spill/fill slot at 0x1000, so ld8.fill seeds NaT(r10).
            Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8_fill(10, 9), nop_i(), nop_i()),
            # This is the bundle under test.  The MI_I template supplies the
            # required stop between the dependent ADD and ADDS groups; the
            # second group must observe both r11 and its propagated NaT.
            Bundle(0x40, 0x03, nop_m(), add(11, 10, 0), adds(12, 1, 11)),
            Bundle(0x50, 0x03, nop_m(), shl_var(13, 10, 8),
                   depz(14, 10, 4, 60)),
            Bundle(0x60, 0x03, nop_m(), extr(15, 10, 0, 8),
                   integer_extend(16, 10, 1, signed=True)),
            Bundle(0x70, 0x03, nop_m(), popcnt(17, 10),
                   addp4_imm(18, -1, 10)),
            Bundle(0x80, 0x03, nop_m(), depz_imm(19, -1, 0, 8),
                   shl_var(20, 8, 10)),
            Bundle(0x90, 0x03, nop_m(), shrp_imm(21, 10, 8, 4),
                   dep(22, 8, 10, 0, 8)),
            Bundle(0xa0, 0x03, nop_m(), mpy4(23, 10, 8),
                   addp4(24, 8, 10)),
            Bundle(0xb0, 0x11, nop_m(), nop_i(), br_cond(0xb0, 0xb0)),
        ),
        terminal_ip=0xb0,
        data=(DataWord(0x1000, data_value, 8),),
    )


def ordinary_source_nat_overlay_program() -> Program:
    data_value = 0x0fedcba987654321
    return Program(
        name="ordinary-source NaT overlay invariant",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, 0x1000, 0)),
            Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8_fill(10, 9), nop_i(), nop_i()),
            # Internal shadow invariant, not an architectural RAW golden: the
            # first ADD clears live NaT(r10), while the second must select the
            # saved group-entry value and NaT together.
            Bundle(0x40, 0x01, nop_m(), adds(10, 1, 0),
                   adds(11, 0, 10)),
            Bundle(0x50, 0x11, nop_m(), nop_i(), br_cond(0x50, 0x50)),
        ),
        terminal_ip=0x50,
        data=(DataWord(0x1000, data_value, 8),),
    )


def stopped_i_program(name: str, instructions: Sequence[int]) -> Program:
    bundles: List[Bundle] = []
    address = 0x10

    for index in range(0, len(instructions), 2):
        slot1 = instructions[index]
        slot2 = (instructions[index + 1]
                 if index + 1 < len(instructions) else nop_i())
        # MI_I: slot 1 and slot 2 end separate instruction groups.
        bundles.append(Bundle(address, 0x03, nop_m(), slot1, slot2))
        address += 0x10
    bundles.append(Bundle(address, 0x11, nop_m(), nop_i(),
                          br_cond(address, address)))
    return Program(name=name, bundles=tuple(bundles), terminal_ip=address)


def scalar_shift_bitfield_program() -> Program:
    instructions = (
        adds(1, 1, 0),
        adds(2, 4, 0),
        adds(3, -1, 0),
        adds(4, 0x1234, 0),
        adds(5, 64, 0),
        adds(6, 0x80, 0),
        adds(7, 0x7f, 0),
        adds(8, 0, 0),
        adds(9, 3, 0),
        adds(10, 5, 0),
        adds(11, 32, 0),
        adds(12, 0x100, 0),
        shl_var(13, 1, 2),
        shru_var(14, 3, 2),
        shr_var(15, 3, 2),
        shl_var(16, 1, 5),
        shru_var(17, 3, 5),
        shr_var(18, 3, 5),
        shl_imm(19, 1, 40),
        shrp_imm(20, 4, 6, 4),
        depz(21, 4, 8, 12),
        depz_imm(22, -1, 4, 12),
        dep(23, 7, 4, 8, 8),
        dep_imm(24, 1, 4, 16, 4),
        extr(25, 4, 4, 8),
        extr(26, 6, 0, 8, signed=True),
        integer_extend(27, 6, 1, signed=True),
        integer_extend(28, 3, 1, signed=False),
        popcnt(29, 3),
        clz(30, 8),
        addp4(31, 9, 10),
    )
    return stopped_i_program("scalar shift/bitfield equality", instructions)


def scalar_multiply_extension_program() -> Program:
    instructions = (
        adds(1, 3, 0),
        adds(2, 5, 0),
        adds(3, -1, 0),
        adds(4, 2, 0),
        adds(5, 32, 0),
        adds(6, 0x80, 0),
        adds(7, 0x1234, 0),
        adds(18, 77, 0),
        adds(19, 0x12, 0),
        shl_imm(8, 1, 32),
        mpy4(9, 3, 2),
        mpy4(10, 8, 2, high_left=True),
        shladdp4(11, 1, 2, 2),
        addp4(12, 1, 2),
        addp4_imm(13, -1, 2),
        integer_extend(14, 3, 2, signed=True),
        integer_extend(15, 3, 4, signed=True),
        integer_extend(16, 3, 2, signed=False),
        integer_extend(17, 3, 4, signed=False),
        shl_var(18, 1, 4, qp=1),
        shl_var(19, 19, 4),
    )
    return stopped_i_program("scalar multiply/extension equality",
                             instructions)


def predicate_compare_program() -> Program:
    return Program(
        name="predicate transaction and A6 compare",
        bundles=(
            Bundle(0x10, 0x03, nop_m(), adds(1, 5, 0),
                   adds(2, 5, 0)),
            Bundle(0x20, 0x03, nop_m(), adds(3, -1, 0),
                   adds(4, 1, 0)),
            # MII has no internal stop.  Each successful compare retires in
            # order, while the ordinary-source overlay keeps subsequent
            # non-forwarded reads on the group-entry PR image until the stop.
            Bundle(0x30, 0x01, nop_m(),
                   cmp_rr(1, 2, 1, 2, "eq"),
                   cmp_rr(3, 4, 1, 2, "lt")),
            Bundle(0x40, 0x01, nop_m(),
                   cmp_rr(5, 6, 4, 3, "ltu"),
                   cmp_rr(7, 8, 3, 4, "lt", width=4)),
            Bundle(0x50, 0x01, nop_m(),
                   cmp_rr(9, 10, 3, 4, "ltu", width=4),
                   cmp_rr(11, 12, 1, 2, "eq", width=4)),
            # Seed p13=true/p14=false, then prove that a false qualifying
            # predicate still makes cmp.unc clear both destinations.
            Bundle(0x60, 0x03, nop_m(),
                   cmp_rr(13, 14, 1, 2, "eq"),
                   cmp_rr(13, 14, 1, 2, "eq", unc=True, qp=14)),
            Bundle(0x70, 0x03, nop_m(), adds(20, 101, 0, qp=1),
                   adds(21, 102, 0, qp=2)),
            Bundle(0x80, 0x03, nop_m(), adds(22, 104, 0, qp=4),
                   adds(23, 105, 0, qp=5)),
            Bundle(0x90, 0x03, nop_m(), adds(24, 107, 0, qp=7),
                   adds(25, 110, 0, qp=10)),
            Bundle(0xa0, 0x03, nop_m(), adds(26, 111, 0, qp=11),
                   adds(27, 113, 0, qp=13)),
            Bundle(0xb0, 0x11, nop_m(), nop_i(), br_cond(0xb0, 0xb0)),
        ),
        terminal_ip=0xb0,
    )


def normal_compare_conformance_program() -> Tuple[Program, Tuple[int, ...]]:
    """Build literal normal-assignment A6/A8 comparison goldens."""
    bundles: List[Bundle] = []
    compare_ips: List[int] = []
    address = 0x10
    data_value = 0x123456789abcdef0

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> int:
        nonlocal address
        bundle_ip = address
        bundles.append(Bundle(bundle_ip, template, slot0, slot1, slot2))
        address += 0x10
        return bundle_ip

    # r1 seeds p6:p7=11, r5=-1, and r7=zero_ext32(-1).  The latter
    # distinguishes 64-bit signed/unsigned comparisons from cmp4.
    emit(0x01, nop_m(), adds(1, (1 << 6) | (1 << 7), 0),
         adds(4, 1, 0))
    emit(0x01, nop_m(), adds(5, -1, 0), adds(10, 0x1000, 0))
    emit(0x01, nop_m(), integer_extend(7, 5, 4, signed=False), nop_i())
    # UNAT bit zero describes 0x1000, so ld8.fill creates a valid NaT r11.
    emit(0x01, mov_m_grar(36, 4), nop_i(), nop_i())
    emit(0x01, ld8_fill(11, 10), nop_i(), nop_i())

    # Every canonical A8 normal opcode is represented once.  Alternate M/I
    # placement while keeping each comparison in its own completed group.
    cases = (
        # sign_ext8(-1) < 0 is true.
        (cmp_imm(6, 7, -1, 0, "lt"), "M"),
        # As uint64, sign_ext8(-1) is greater than zero_ext32(-1).
        (cmp_imm(6, 7, -1, 7, "ltu"), "I"),
        (cmp_imm(6, 7, -1, 5, "eq"), "M"),
        # cmp4 observes signed low32(r7) == -1.
        (cmp_imm(6, 7, 0, 7, "lt", width=4), "I"),
        # The same low32 is 0xffffffff for unsigned cmp4.
        (cmp_imm(6, 7, 0, 7, "ltu", width=4), "M"),
        (cmp_imm(6, 7, -1, 7, "eq", width=4), "I"),
    )
    for index, (raw, unit) in enumerate(cases):
        if unit == "M":
            compare_ips.append(emit(0x01, raw, nop_i(), nop_i()))
        else:
            compare_ips.append(emit(0x01, nop_m(), raw, nop_i()))
        emit(0x01, nop_m(), mov_prgr(12 + index), nop_i())

    # cmp.unc clears both unequal targets even when p5 is false.
    emit(0x01, nop_m(), mov_grpr(1, 0xfffe), nop_i())
    compare_ips.append(emit(
        0x01, cmp_imm(6, 7, 0, 0, "eq", unc=True, qp=5),
        nop_i(), nop_i(),
    ))
    emit(0x01, nop_m(), mov_prgr(18), nop_i())

    # A successful normal A6 compare consumes NaT as an unordered source: it
    # clears both predicates and does not raise Register NaT Consumption.
    emit(0x01, nop_m(), mov_grpr(1, 0xfffe), nop_i())
    compare_ips.append(emit(
        0x01, nop_m(), cmp_rr(6, 7, 11, 0, "eq"), nop_i(),
    ))
    emit(0x01, nop_m(), mov_prgr(19), nop_i())

    terminal_ip = address
    emit(0x11, nop_m(), nop_i(), br_cond(terminal_ip, terminal_ip))
    return (
        Program(
            name="normal A6/A8 compare architectural conformance",
            bundles=tuple(bundles),
            terminal_ip=terminal_ip,
            data=(DataWord(0x1000, data_value, 8),),
        ),
        tuple(compare_ips),
    )


def parallel_compare_conformance_program() -> Tuple[Program, Tuple[int, ...]]:
    """Build independent A6/A7/A8 merge and transaction goldens.

    Each of the first twelve cases resets p1..p15 from a literal GR image,
    executes one parallel compare, and snapshots the complete predicate image
    into r12..r23.  Every expected image is computed independently from the
    instruction implementation.
    """
    bundles: List[Bundle] = []
    compare_ips: List[int] = []
    address = 0x10
    data_value = 0x123456789abcdef0

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> int:
        nonlocal address
        bundle_ip = address
        bundles.append(Bundle(bundle_ip, template, slot0, slot1, slot2))
        address += 0x10
        return bundle_ip

    # Literal predicate seed images: r1=10, r2=01, and r3=11 for p6:p7.
    emit(0x01, nop_m(), adds(1, 1 << 6, 0), adds(2, 1 << 7, 0))
    emit(0x01, nop_m(), adds(3, (1 << 6) | (1 << 7), 0),
         adds(4, 1, 0))
    emit(0x01, nop_m(), adds(5, -1, 0), adds(6, 32, 0))
    # r7 and r8 distinguish cmp4 from their 64-bit counterparts.
    emit(0x01, nop_m(), integer_extend(7, 5, 4, signed=False),
         shl_var(8, 4, 6))
    emit(0x01, nop_m(), adds(10, 0x1000, 0), adds(28, 134, 0))
    # AR.UNAT bit zero and ld8.fill produce an architecturally valid NaT r11.
    emit(0x01, mov_m_grar(36, 4), nop_i(), nop_i())
    emit(0x01, ld8_fill(11, 10), nop_i(), nop_i())

    # (raw, seed GR, execution unit).  The corresponding literal expected
    # images live in test_integer_compare_conformance, not in this encoder.
    cases = (
        # 1: A8 sign-extended -1 != 0; AND true preserves seed 11.
        (cmp_merge_imm(6, 7, -1, 0, "and", "ne"), 3, "I"),
        # 2: 0 <= -1 is false; AND must clear *both* outputs.
        (cmp_merge_zero(6, 7, 5, "and", "le"), 3, "M"),
        # 3: a NaT register operand clears both AND outputs.
        (cmp_merge_rr(6, 7, 11, 0, "and", "eq"), 3, "I"),
        # 4: low32(2^32) == 0, but false p5 nullifies the AND.
        (cmp_merge_rr(6, 7, 8, 0, "and", "ne", width=4, qp=5),
         1, "M"),
        # 5: cmp4(-1, 0x00000000ffffffff) is equal; OR sets both.
        (cmp_merge_imm(6, 7, -1, 7, "or", "eq", width=4), 0, "I"),
        # 6: 0 != 0 is false; OR must leave both outputs clear.
        (cmp_merge_rr(6, 7, 0, 0, "or", "ne"), 0, "M"),
        # 7: a NaT r3 makes OR a no-op.
        (cmp_merge_zero(6, 7, 11, "or", "lt"), 0, "I"),
        # 8: a true relation is still nullified by false p5.
        (cmp_merge_imm(6, 7, 1, 0, "or", "ne", qp=5), 1, "M"),
        # 9: signed low32(0xffffffff) is -1; 0 > -1 is true.
        (cmp_merge_zero(6, 7, 7, "or.andcm", "gt", width=4),
         2, "M"),
        # 10: low32(2^32) != 0 is false; OR.ANDCM is a no-op.
        (cmp_merge_rr(6, 7, 8, 0, "or.andcm", "ne", width=4),
         2, "I"),
        # 11: a NaT r3 makes immediate OR.ANDCM a no-op.
        (cmp_merge_imm(6, 7, 0, 11, "or.andcm", "eq"), 2, "M"),
        # 12: false p5 preserves the 01 seed independent of relation.
        (cmp_merge_zero(6, 7, 4, "or.andcm", "ge", qp=5), 2, "I"),
    )

    for index, (raw, seed_reg, unit) in enumerate(cases):
        # Mask 0xfffe resets every static predicate except hard-wired p0.
        emit(0x01, nop_m(), mov_grpr(seed_reg, 0xfffe), nop_i())
        if unit == "M":
            compare_ips.append(emit(0x01, raw, nop_i(), nop_i()))
        else:
            compare_ips.append(emit(0x01, nop_m(), raw, nop_i()))
        emit(0x01, nop_m(), mov_prgr(12 + index), nop_i())

    # Same-target WAWs span a no-stop bundle boundary.  The first bundle has
    # identity/no-op results and the second has the effective updates.
    emit(0x01, nop_m(), mov_grpr(28, 0xfffe), nop_i())
    compare_ips.append(emit(
        0x00,
        cmp_merge_rr(1, 2, 0, 0, "and", "eq"),
        cmp_merge_rr(3, 4, 0, 4, "or", "eq"),
        cmp_merge_rr(6, 7, 0, 4, "or.andcm", "eq"),
    ))
    compare_ips.append(emit(
        0x01,
        cmp_merge_rr(1, 2, 0, 4, "and", "eq"),
        cmp_merge_rr(3, 4, 0, 0, "or", "eq"),
        cmp_merge_rr(6, 7, 0, 0, "or.andcm", "eq"),
    ))
    emit(0x01, nop_m(), mov_prgr(24), nop_i())

    # The first compare clears live p6.  The second compare is in the same
    # group across a TB boundary and must still qualify from entry p6=true.
    emit(0x01, nop_m(), mov_grpr(3, 0xfffe), nop_i())
    compare_ips.append(emit(
        0x00, cmp_merge_rr(6, 7, 0, 4, "and", "eq"),
        nop_i(), nop_i(),
    ))
    compare_ips.append(emit(
        0x01, nop_m(),
        cmp_merge_rr(8, 9, 0, 0, "or", "eq", qp=6), nop_i(),
    ))
    emit(0x01, nop_m(), mov_prgr(25), nop_i())

    # Writes to p0 are ignored, while the nonzero partner still updates.
    emit(0x01, nop_m(), mov_grpr(1, 0xfffe), nop_i())
    compare_ips.append(emit(
        0x01, cmp_merge_rr(0, 6, 0, 4, "and", "eq"),
        nop_i(), nop_i(),
    ))
    emit(0x01, nop_m(), mov_prgr(26), nop_i())
    compare_ips.append(emit(
        0x01, nop_m(), cmp_merge_rr(6, 0, 0, 0, "or", "eq"),
        nop_i(),
    ))
    emit(0x01, nop_m(), mov_prgr(27), nop_i())

    terminal_ip = address
    emit(0x11, nop_m(), nop_i(), br_cond(terminal_ip, terminal_ip))
    return (
        Program(
            name="parallel compare architectural conformance",
            bundles=tuple(bundles),
            terminal_ip=terminal_ip,
            data=(DataWord(0x1000, data_value, 8),),
        ),
        tuple(compare_ips),
    )


def rotating_parallel_compare_program() -> Program:
    """Rotate rrb_pr once, then update and consume logical p16/p17."""
    compare = cmp_merge_rr(17, 16, 0, 0, "or.andcm", "eq")
    return Program(
        name="rotating parallel compare destinations",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(1, 1, 0), nop_i()),
            Bundle(0x20, 0x01, nop_m(), mov_i_grar(65, 1), nop_i()),
            # LC=1 makes br.ctop rotate once.  A target equal to fallthrough
            # avoids a loop while still setting logical p16 and rrb_pr=47.
            Bundle(0x30, 0x11, nop_m(), nop_i(), br_ctop(0x30, 0x40)),
            # At rrb_pr=47, logical p16 is physical p63 and logical p17 is
            # physical p16.  A true OR.ANDCM must set the latter and clear the
            # former without flattening the rename base.
            Bundle(0x40, 0x01, compare, nop_i(), nop_i()),
            Bundle(0x50, 0x01, nop_m(), adds(29, 0x66, 0, qp=17),
                   adds(30, 0x77, 0, qp=16)),
            Bundle(0x60, 0x11, nop_m(), nop_i(), br_cond(0x60, 0x60)),
        ),
        terminal_ip=0x60,
    )


def same_bundle_branch_forward_true_program() -> Program:
    return Program(
        name="same-bundle true compare-to-branch forwarding",
        bundles=(
            Bundle(0x10, 0x11, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"),
                   br_cond(0x10, 0x30, qp=6)),
            spin_bundle(0x20),
            spin_bundle(0x30),
        ),
        terminal_ip=0x30,
    )


def same_bundle_branch_forward_false_program() -> Program:
    return Program(
        name="same-bundle false compare-to-branch forwarding",
        bundles=(
            Bundle(0x10, 0x03, nop_m(), adds(1, 1, 0),
                   cmp_rr(6, 7, 0, 0, "eq")),
            Bundle(0x20, 0x11, nop_m(),
                   cmp_rr(6, 7, 1, 0, "eq"),
                   br_cond(0x20, 0x40, qp=6)),
            spin_bundle(0x30),
            spin_bundle(0x40),
        ),
        terminal_ip=0x30,
    )


def nullified_branch_producer_program() -> Program:
    return Program(
        name="nullified compare leaves branch provenance untouched",
        bundles=(
            Bundle(0x10, 0x01, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"), nop_i()),
            Bundle(0x20, 0x11, nop_m(),
                   cmp_rr(6, 7, 0, 0, "lt", qp=1),
                   br_cond(0x20, 0x40, qp=6)),
            spin_bundle(0x30),
            spin_bundle(0x40),
        ),
        terminal_ip=0x40,
    )


def cross_page_branch_forward_program(taken: bool) -> Program:
    if taken:
        return Program(
            name="cross-page true compare-to-branch forwarding",
            bundles=(
                Bundle(0xff0, 0x00,
                       cmp_rr(6, 7, 0, 0, "eq"), nop_i(), nop_i()),
                Bundle(0x1000, 0x11, nop_m(), nop_i(),
                       br_cond(0x1000, 0x1020, qp=6)),
                spin_bundle(0x1010),
                spin_bundle(0x1020),
            ),
            terminal_ip=0x1020,
            entry=0xff0,
        )
    return Program(
        name="cross-page false compare-to-branch forwarding",
        bundles=(
            Bundle(0xfe0, 0x03, nop_m(), adds(1, 1, 0),
                   cmp_rr(6, 7, 0, 0, "eq")),
            Bundle(0xff0, 0x00,
                   cmp_rr(6, 7, 1, 0, "eq"), nop_i(), nop_i()),
            Bundle(0x1000, 0x11, nop_m(), nop_i(),
                   br_cond(0x1000, 0x1020, qp=6)),
            spin_bundle(0x1010),
            spin_bundle(0x1020),
        ),
        terminal_ip=0x1010,
        entry=0xfe0,
    )


def rotating_branch_forward_program(taken: bool) -> Program:
    compare = (
        cmp_rr(17, 16, 0, 0, "eq")
        if taken else cmp_rr(16, 17, 1, 0, "eq")
    )
    branch_qp = 17 if taken else 16
    terminal = 0x60 if taken else 0x50
    return Program(
        name="rotating {} compare-to-branch forwarding".format(
            "true" if taken else "false"
        ),
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(1, 1, 0), nop_i()),
            Bundle(0x20, 0x01, nop_m(), mov_i_grar(65, 1), nop_i()),
            Bundle(0x30, 0x11, nop_m(), nop_i(), br_ctop(0x30, 0x40)),
            Bundle(0x40, 0x11, nop_m(), compare,
                   br_cond(0x40, 0x60, qp=branch_qp)),
            spin_bundle(0x50),
            spin_bundle(0x60),
        ),
        terminal_ip=terminal,
    )


def no_stop_branch_epoch_program(taken: bool) -> Program:
    if taken:
        return Program(
            name="taken no-stop branch starts a fresh source epoch",
            bundles=(
                Bundle(0x10, 0x10, adds(1, 1, 0),
                       cmp_rr(6, 7, 0, 0, "eq"),
                       br_cond(0x10, 0x30, qp=6)),
                spin_bundle(0x20),
                Bundle(0x30, 0x01, nop_m(), adds(2, 0, 1), nop_i()),
                spin_bundle(0x40),
            ),
            terminal_ip=0x40,
        )
    return Program(
        name="not-taken no-stop branch preserves its source epoch",
        bundles=(
            Bundle(0x10, 0x10, adds(1, 1, 0), nop_i(),
                   br_cond(0x10, 0x40, qp=1)),
            Bundle(0x20, 0x01, nop_m(), adds(2, 0, 1), nop_i()),
            spin_bundle(0x30),
            spin_bundle(0x40),
        ),
        terminal_ip=0x30,
    )


def predicate_test_branch_program(kind: str) -> Program:
    test = predicate_test(
        kind, 6, 7, relation="nz", update="or.andcm",
        r3=10 if kind == "tnat" else 1 if kind == "tbit" else 0,
        immediate=32 if kind == "tf" else 0,
    )
    if kind == "tbit":
        return Program(
            name="tbit result forwards directly to branch",
            bundles=(
                Bundle(0x10, 0x01, nop_m(), adds(1, 1, 0), nop_i()),
                Bundle(0x20, 0x11, nop_m(), test,
                       br_cond(0x20, 0x40, qp=6)),
                spin_bundle(0x30),
                spin_bundle(0x40),
            ),
            terminal_ip=0x40,
        )
    if kind == "tnat":
        return Program(
            name="tnat result forwards directly to branch",
            bundles=(
                Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
                       adds(9, 0x1000, 0)),
                Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
                Bundle(0x30, 0x01, ld8_fill(10, 9), nop_i(), nop_i()),
                Bundle(0x40, 0x11, nop_m(), test,
                       br_cond(0x40, 0x60, qp=6)),
                spin_bundle(0x50),
                spin_bundle(0x60),
            ),
            terminal_ip=0x60,
            data=(DataWord(0x1000, 0x123456789abcdef0, 8),),
        )
    return Program(
        name="tf CPUID[4] result forwards directly to branch",
        bundles=(
            Bundle(0x10, 0x11, nop_m(), test,
                   br_cond(0x10, 0x30, qp=6)),
            spin_bundle(0x20),
            spin_bundle(0x30),
        ),
        terminal_ip=0x30,
    )


def predicate_test_conformance_program() \
        -> Tuple[Program, Tuple[Tuple[str, int, int, int], ...]]:
    """Build independent predicate-test rows and snapshot each PR image."""
    data_address = 0x1000
    data_value = 0x123456789abcdef0
    rows = (
        ("tbit.z normal NaT", 0xc0,
         predicate_test("tbit", 6, 7, relation="z", update="normal",
                        r3=11, immediate=0), 0x001),
        ("tnat.z treats NaT as data", 0xc0,
         predicate_test("tnat", 6, 7, relation="z", update="normal",
                        r3=11), 0x081),
        ("tbit.z.and NaT clears", 0xc0,
         predicate_test("tbit", 6, 7, relation="z", update="and",
                        r3=11, immediate=0), 0x001),
        ("tbit.z.or NaT does not write", 0x40,
         predicate_test("tbit", 6, 7, relation="z", update="or",
                        r3=11, immediate=0), 0x041),
        ("tbit.z.or.andcm NaT does not write", 0x80,
         predicate_test("tbit", 6, 7, relation="z", update="or.andcm",
                        r3=11, immediate=0), 0x081),
        ("tbit.nz.or active arm", 0x00,
         predicate_test("tbit", 6, 7, relation="nz", update="or",
                        r3=8, immediate=0), 0x0c1),
        ("false-qp tbit.z.unc clears", 0xc0,
         predicate_test("tbit", 6, 7, relation="z", update="normal",
                        r3=8, immediate=0, unc=True, qp=5), 0x001),
        ("tf.z advertised CPUID[4] bit 32", 0xc0,
         predicate_test("tf", 6, 7, relation="z", update="normal",
                        immediate=32), 0x081),
        ("tf.z absent CPUID[4] bit 34", 0x00,
         predicate_test("tf", 6, 7, relation="z", update="normal",
                        immediate=34), 0x041),
    )
    bundles: List[Bundle] = [
        Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
               adds(9, data_address, 0)),
        Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
        Bundle(0x30, 0x01, ld8_fill(11, 9), nop_i(), nop_i()),
    ]
    observations: List[Tuple[str, int, int, int]] = []
    address = 0x40
    for index, (label, seed, test, expected) in enumerate(rows):
        output = 20 + index
        bundles.extend((
            Bundle(address, 0x01, nop_m(), adds(12, seed, 0), nop_i()),
            Bundle(address + 0x10, 0x01, nop_m(),
                   mov_grpr(12, 0xfffe), nop_i()),
            Bundle(address + 0x20, 0x01, nop_m(), test, nop_i()),
            Bundle(address + 0x30, 0x01, nop_m(), mov_prgr(output), nop_i()),
        ))
        observations.append((label, output, expected, address + 0x20))
        address += 0x40
    bundles.append(spin_bundle(address))
    return (
        Program(
            name="predicate-test direct semantic matrix",
            bundles=tuple(bundles),
            terminal_ip=address,
            data=(DataWord(data_address, data_value, 8),),
        ),
        tuple(observations),
    )


def far_long_branch_program(mode: str) -> Program:
    far = 0x02000040
    if mode == "forwarded":
        l_slot, x_slot = brl_cond(0x20, far, qp=6)
        return Program(
            name="far brl with same-MLX compare forwarding",
            bundles=(
                Bundle(0x20, 0x05,
                       cmp_rr(6, 7, 0, 0, "eq"), l_slot, x_slot),
                spin_bundle(0x30),
                spin_bundle(far),
            ),
            terminal_ip=far,
            entry=0x20,
        )
    if mode == "false":
        l_slot, x_slot = brl_cond(0x20, far, qp=1)
        return Program(
            name="false-qualified far brl exact fallthrough",
            bundles=(
                Bundle(0x20, 0x05, nop_m(), l_slot, x_slot),
                spin_bundle(0x30),
                spin_bundle(far),
            ),
            terminal_ip=0x30,
            entry=0x20,
        )
    if mode == "backward":
        source = far
        l_slot, x_slot = brl_cond(source, 0x40)
        return Program(
            name="backward brl signed imm60",
            bundles=(
                spin_bundle(0x40),
                Bundle(source, 0x05, nop_m(), l_slot, x_slot),
                spin_bundle(source + 0x10),
            ),
            terminal_ip=0x40,
            entry=source,
        )
    raise ValueError("long-branch mode must be forwarded, false, or backward")


def predicate_register_move_program() -> Program:
    data_address = 0x1000
    return Program(
        name="direct predicate-register moves",
        bundles=(
            Bundle(0x10, 0x03, nop_m(), adds(8, 1, 0),
                   adds(9, data_address, 0)),
            Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            # Seed two independent NaT destinations from the same UNAT slot.
            # The true PR->GR move clears r20's NaT; the false-qualified
            # GR->PR move below must neither consume nor clear r24's NaT.
            Bundle(0x30, 0x01, ld8_fill(20, 9), nop_i(), nop_i()),
            Bundle(0x40, 0x01, ld8_fill(24, 9), nop_i(), nop_i()),
            Bundle(0x50, 0x03, nop_m(), adds(10, 0x2a, 0),
                   adds(11, 0x14, 0)),
            Bundle(0x60, 0x03, nop_m(), adds(25, 99, 0), nop_i()),
            # p0 is deliberately zero in r10.  A masked packed write must
            # nevertheless leave p0 set and establish p1/p3/p5.
            Bundle(0x70, 0x03, nop_m(), mov_grpr(10, 0x3e), nop_i()),
            # The write changes p1..p4 to r11's 0b10100, preserving p5.  The
            # same-group ordinary PR read must still select the entry image
            # 0x2b and must clear the pre-existing NaT on r20.
            Bundle(0x80, 0x00, nop_m(), mov_grpr(11, 0x1e),
                   mov_prgr(20)),
            # Close the open group before observing its final packed image.
            Bundle(0x90, 0x03, nop_m(), nop_i(), mov_prgr(21)),
            # -0x10000 is the all-ones negative imm44.  Correct decode and
            # direct lowering sign-extend it through physical p16..p63.
            Bundle(0xa0, 0x03, nop_m(), mov_pr_rot_imm(-0x10000),
                   mov_prgr(22)),
            # I23 mask bit 16 represents the complete high-48 predicate
            # image.  Clear it from r0, then restore it from r22.
            Bundle(0xb0, 0x03, nop_m(), mov_grpr(0, 0x10000),
                   mov_prgr(27)),
            Bundle(0xc0, 0x03, nop_m(), mov_grpr(22, 0x10000),
                   mov_prgr(23)),
            # p1 is false in 0x35.  Cover nullification of every move form;
            # the false GR->PR source is NaT, so predication must precede the
            # Register NaT Consumption check as well as the packed write.
            Bundle(0xd0, 0x03, nop_m(), mov_pr_rot_imm(0, qp=1),
                   mov_grpr(24, 0x3e, qp=1)),
            Bundle(0xe0, 0x03, nop_m(), mov_prgr(25, qp=1),
                   mov_prgr(26)),
            Bundle(0xf0, 0x11, nop_m(), nop_i(), br_cond(0xf0, 0xf0)),
            _exception_vector_spin(IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
        ),
        terminal_ip=0xf0,
        data=(DataWord(data_address, 0, 8),),
    )


def predicate_register_nat_fault_program(mask: int = 0x3e) -> Program:
    data_address = 0x1000
    fault = mov_grpr(4, mask, qp=6)
    return Program(
        name="qualified MOV_GRPR mask 0x{:x} Register NaT Consumption".format(
            mask
        ),
        bundles=(
            *_interruption_collection_setup(),
            Bundle(0x30, 0x03, nop_m(), adds(2, 1, 0),
                   adds(3, data_address, 0)),
            Bundle(0x40, 0x01, mov_m_grar(36, 2), nop_i(), nop_i()),
            Bundle(0x50, 0x01, ld8_fill(4, 3), nop_i(), nop_i()),
            # Establish a true qualifier and an independently known PR image.
            Bundle(0x60, 0x03, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"), nop_i()),
            # Overwrite r4+NaT and r23 earlier in the same no-stop group.  The
            # writes must commit before the fault, while MOV_GRPR must still
            # consume the group's entry r4+NaT image rather than the newer
            # live value.  The faulting instruction must not modify PR.
            Bundle(0x70, 0x00, nop_m(), adds(4, 85, 0),
                   adds(23, 66, 0)),
            Bundle(0x80, 0x01, nop_m(), nop_i(), fault),
            Bundle(0x90, 0x11, nop_m(), nop_i(), br_cond(0x90, 0x90)),
            _exception_vector_spin(IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
        ),
        terminal_ip=IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(DataWord(data_address, 0x2a, 8),),
    )


def branch_register_move_program() -> Program:
    data_address = 0x1000
    data_value = 0x123456789abcdef0
    return Program(
        name="direct branch-register moves",
        bundles=(
            # Seed two independent NaT destinations.  The qualified
            # BR-to-GR move clears r30's NaT, while the false-qualified move
            # and false-qualified GR-to-BR source must leave r31 untouched.
            Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, data_address, 0)),
            Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8_fill(30, 9), nop_i(), nop_i()),
            Bundle(0x40, 0x01, ld8_fill(31, 9), nop_i(), nop_i()),
            Bundle(0x50, 0x01, nop_m(), adds(10, 0x111, 0),
                   adds(11, 0x222, 0)),
            Bundle(0x60, 0x01, nop_m(), adds(12, 0x333, 0),
                   adds(23, 0x555, 0)),
            Bundle(0x70, 0x01, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"), nop_i()),

            # Cover unconditional and true/false-qualified GR-to-BR moves.
            Bundle(0x80, 0x01, nop_m(), mov_grbr(1, 10),
                   mov_grbr(2, 11)),
            Bundle(0x90, 0x01, nop_m(), mov_grbr(3, 12, qp=6),
                   mov_grbr(4, 12, qp=7)),
            # Cover the matching BR-to-GR qualification matrix.
            Bundle(0xa0, 0x01, nop_m(), mov_brgr(20, 1),
                   mov_brgr(21, 2)),
            Bundle(0xb0, 0x01, nop_m(), mov_brgr(22, 3, qp=6),
                   mov_brgr(23, 1, qp=7)),
            Bundle(0xc0, 0x01, nop_m(), mov_brgr(30, 1, qp=6),
                   mov_brgr(31, 1, qp=7)),

            # Same-destination WAWs exercise ordered retirement for both
            # state classes.  The second qualified writer must win.
            Bundle(0xd0, 0x01, nop_m(), mov_grbr(6, 10),
                   mov_grbr(6, 11)),
            Bundle(0xe0, 0x01, nop_m(), mov_brgr(24, 1),
                   mov_brgr(24, 2)),

            # This open group is deliberately split at a TB boundary.  The
            # live b5 update retires at 0x100, but ordinary BR-to-GR sources
            # in 0x110 must still read the group-entry value 0x111.
            Bundle(0xf0, 0x01, nop_m(), mov_grbr(5, 10), nop_i()),
            Bundle(0x100, 0x00, nop_m(), mov_grbr(5, 11), nop_i()),
            Bundle(0x110, 0x01, nop_m(), mov_brgr(25, 5),
                   mov_brgr(26, 5, qp=6)),

            # Qualification must precede NaT consumption.  p7 is false, so
            # neither b7 nor r31/NaT may change and no interruption may fire.
            Bundle(0x120, 0x01, nop_m(), mov_grbr(7, 31, qp=7), nop_i()),
            Bundle(0x130, 0x11, nop_m(), nop_i(),
                   br_cond(0x130, 0x130)),
            _exception_vector_spin(IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
        ),
        terminal_ip=0x130,
        data=(DataWord(data_address, data_value, 8),),
    )


def branch_register_nat_fault_program() -> Program:
    data_address = 0x1000
    fault = mov_grbr(2, 4, qp=6)
    return Program(
        name="qualified MOV_GRBR Register NaT Consumption",
        bundles=(
            *_interruption_collection_setup(),
            Bundle(0x30, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, data_address, 0)),
            Bundle(0x40, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0x50, 0x01, ld8_fill(4, 9), nop_i(), nop_i()),
            Bundle(0x60, 0x01, nop_m(), adds(10, 0x111, 0),
                   adds(12, 0x333, 0)),
            Bundle(0x70, 0x01, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"), mov_grbr(3, 12)),
            # Retire a visible prefix while preserving r4's group-entry NaT.
            # The fault must consume that old pair even though live r4 has
            # already become 85/NaT-clear.  Slot 2 at 0x90 is the suffix.
            Bundle(0x80, 0x00, nop_m(), adds(4, 85, 0),
                   mov_grbr(1, 10)),
            Bundle(0x90, 0x01, nop_m(), fault, mov_grbr(3, 10)),
            Bundle(0xa0, 0x11, nop_m(), nop_i(), br_cond(0xa0, 0xa0)),
            _exception_vector_spin(IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
        ),
        terminal_ip=IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(DataWord(data_address, 0x2a, 8),),
    )


def branch_register_migration_program() -> Program:
    return Program(
        name="typed branch-register shadow save/load resume",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(10, 0x111, 0),
                   adds(11, 0x222, 0)),
            Bundle(0x20, 0x01, nop_m(), mov_grbr(5, 10), nop_i()),
            # The checkpoint is at 0x40 after this producer has retired.
            # It must serialize live b5, saved entry b5, its validity bit,
            # and the branch-only forwarding provenance bit.
            Bundle(0x30, 0x00, nop_m(), mov_grbr(5, 11), nop_i()),
            Bundle(0x40, 0x01, nop_m(), mov_brgr(20, 5),
                   mov_brgr(21, 5)),
            Bundle(0x50, 0x11, nop_m(), nop_i(), br_cond(0x50, 0x50)),
        ),
        terminal_ip=0x50,
    )


def pfs_register_move_program() -> Program:
    """Exercise both legal I-unit AR.PFS move forms and their overlay."""
    data_address = 0x1000
    data_value = 0x123456789abcdef0
    return Program(
        name="typed AR.PFS register moves",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, data_address, 0)),
            Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            # Keep two NaT-tagged registers for the false-source and
            # destination-NaT tests below.
            Bundle(0x30, 0x01, ld8_fill(30, 9), nop_i(), nop_i()),
            Bundle(0x40, 0x01, ld8_fill(31, 9), nop_i(), nop_i()),
            Bundle(0x50, 0x01, nop_m(), adds(10, 0x111, 0),
                   adds(11, 0x222, 0)),
            Bundle(0x60, 0x01, nop_m(), adds(12, 0x333, 0),
                   adds(13, 0x444, 0)),
            # Establish p6=true/p7=false and an observable false-destination
            # sentinel at a completed group boundary.
            Bundle(0x70, 0x01, nop_m(), adds(28, 0x555, 0),
                   cmp_rr(6, 7, 0, 0, "eq")),

            # Seed PFS=A.  In the next no-stop group, the read before and the
            # read after the PFS=B write must both select group-entry A.
            Bundle(0x80, 0x01, nop_m(), mov_gr_to_pfs(10), nop_i()),
            Bundle(0x90, 0x00, nop_m(), mov_pfs_to_gr(20),
                   mov_gr_to_pfs(11)),
            Bundle(0xa0, 0x01, nop_m(), mov_pfs_to_gr(21), nop_i()),
            Bundle(0xb0, 0x01, nop_m(), mov_pfs_to_gr(22), nop_i()),

            # A qualified first writer followed by an unconditional writer
            # exercises the runtime first-actual-write guard.  The final live
            # value is D, while ordinary reads retain the first saved B.
            Bundle(0xc0, 0x00, nop_m(), mov_gr_to_pfs(12, qp=6),
                   mov_gr_to_pfs(13)),
            Bundle(0xd0, 0x01, nop_m(), mov_pfs_to_gr(23), nop_i()),
            Bundle(0xe0, 0x01, nop_m(), mov_pfs_to_gr(24), nop_i()),

            # p7=false must guard both NaT consumption and every PFS overlay
            # side effect.  The following ordinary reads therefore retain D,
            # and the false PFS-to-GR move retains its destination sentinel.
            Bundle(0xf0, 0x00, nop_m(), mov_gr_to_pfs(31, qp=7),
                   mov_pfs_to_gr(25)),
            Bundle(0x100, 0x01, nop_m(), mov_pfs_to_gr(26),
                   mov_pfs_to_gr(28, qp=7)),
            Bundle(0x110, 0x01, nop_m(), mov_pfs_to_gr(27, qp=6),
                   nop_i()),

            # r0 is a legal GR source.  The same-group read still sees D;
            # after the stop, live PFS=0 and a true read clears NaT(r30).
            Bundle(0x120, 0x01, nop_m(), mov_gr_to_pfs(0),
                   mov_pfs_to_gr(29)),
            Bundle(0x130, 0x01, nop_m(), mov_pfs_to_gr(30), nop_i()),
            spin_bundle(0x140),
            _exception_vector_spin(IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
        ),
        terminal_ip=0x140,
        data=(DataWord(data_address, data_value, 8),),
    )


def pfs_register_nat_fault_program() -> Program:
    """Fault before a qualified NaT-tagged source can alter AR.PFS."""
    data_address = 0x1000
    fault = mov_gr_to_pfs(4, qp=6)
    return Program(
        name="typed AR.PFS Register NaT Consumption",
        bundles=(
            *_interruption_collection_setup(),
            Bundle(0x30, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, data_address, 0)),
            Bundle(0x40, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0x50, 0x01, ld8_fill(4, 9), nop_i(), nop_i()),
            Bundle(0x60, 0x01, nop_m(), adds(10, 0x111, 0),
                   cmp_rr(6, 7, 0, 0, "eq")),
            Bundle(0x70, 0x01, nop_m(), mov_gr_to_pfs(10), nop_i()),
            # Retire the r4/NaT overwrite and r23 marker in an open group.
            # The fault must consume the saved entry pair and publish only
            # this prefix; slot 2 must never read or change architectural PFS.
            Bundle(0x80, 0x00, nop_m(), adds(4, 85, 0),
                   adds(23, 66, 0)),
            Bundle(0x90, 0x01, nop_m(), fault, mov_pfs_to_gr(25)),
            # Continue through a tiny handler so PFS itself is observable
            # after the exception, without relying on a debug-only AR dump.
            Bundle(IA64_REGISTER_NAT_CONSUMPTION_VECTOR, 0x01,
                   nop_m(), mov_pfs_to_gr(24), nop_i()),
            spin_bundle(IA64_REGISTER_NAT_CONSUMPTION_VECTOR + 0x10),
        ),
        terminal_ip=IA64_REGISTER_NAT_CONSUMPTION_VECTOR + 0x10,
        data=(DataWord(data_address, 0x2a, 8),),
    )


def pfs_register_migration_program() -> Program:
    """Checkpoint an open PFS overlay and resume it in a fresh QEMU."""
    return Program(
        name="typed AR.PFS shadow save/load resume",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(10, 0x111, 0),
                   adds(11, 0x222, 0)),
            Bundle(0x20, 0x01, nop_m(), mov_gr_to_pfs(10), nop_i()),
            # The checkpoint at 0x40 must contain live B, saved entry A,
            # validity, forwarding provenance, and typed ownership.
            Bundle(0x30, 0x00, nop_m(), mov_gr_to_pfs(11), nop_i()),
            Bundle(0x40, 0x01, nop_m(), mov_pfs_to_gr(20),
                   mov_pfs_to_gr(21)),
            Bundle(0x50, 0x01, nop_m(), mov_pfs_to_gr(22), nop_i()),
            spin_bundle(0x60),
        ),
        terminal_ip=0x60,
    )


def typed_return_clean_program(mode: str) -> Tuple[Program, int]:
    """Return through same-group BR/PFS forwarding without a frame fill."""
    predicate = {"p0": 0, "true": 6, "false": 7}.get(mode)
    if predicate is None:
        raise ValueError("return mode must be p0/true/false")

    data_address = 0x1000
    restored_cfm = 4
    restored_pfs = restored_cfm | (0x2a << 52)
    raw_target = 0x107
    taken = mode != "false"
    terminal_ip = 0x110 if taken else 0xb0
    observation = Bundle(
        0x100 if taken else 0xa0,
        0x01,
        nop_m(),
        mov_argr(22, 66),
        mov_pfs_to_gr(23),
    )
    poison = spin_bundle(0xa0 if taken else 0x100)

    return (
        Program(
            name="typed BR_RET clean-frame {} predicate".format(mode),
            bundles=(
                Bundle(0x10, 0x01, nop_m(), adds(9, data_address, 0),
                       adds(8, data_address + 8, 0)),
                Bundle(0x20, 0x01, ld8(10, 9), nop_i(), nop_i()),
                Bundle(0x30, 0x01, ld8(13, 8), nop_i(), nop_i()),
                Bundle(0x40, 0x01, nop_m(), adds(11, 0x111, 0),
                       adds(12, 0x187, 0)),
                Bundle(0x50, 0x01, nop_m(), mov_gr_to_pfs(11),
                       mov_grbr(6, 12)),
                Bundle(0x60, 0x01, nop_m(),
                       cmp_rr(6, 7, 0, 0, "eq"), nop_i()),

                # Ordinary reads retain the stopped values while BR_RET is
                # the designated same-group consumer of both live writes.
                Bundle(0x70, 0x00, nop_m(), mov_gr_to_pfs(10),
                       mov_pfs_to_gr(20)),
                Bundle(0x80, 0x00, nop_m(), mov_grbr(6, 13),
                       mov_brgr(21, 6)),
                Bundle(0x90, 0x11, nop_m(), nop_i(),
                       br_ret(6, qp=predicate)),
                poison,
                observation,
                spin_bundle(terminal_ip),
            ),
            terminal_ip=terminal_ip,
            data=(
                DataWord(data_address, restored_pfs, 8),
                DataWord(data_address + 8, raw_target, 8),
            ),
        ),
        restored_pfs,
    )


def typed_return_trap_program(psr_bits: int, vector: int) \
        -> Tuple[Program, int]:
    """Return to CPL3 with an enabled architectural branch trap."""
    if vector not in (IA64_LOWER_PRIVILEGE_TRANSFER_VECTOR,
                      IA64_TAKEN_BRANCH_TRAP_VECTOR):
        raise ValueError("unsupported return trap vector")

    data_address = 0x1000
    restored_pfs = 4 | (0x2a << 52) | (3 << 62)
    raw_target = 0x107
    return (
        Program(
            name="typed BR_RET trap-priority vector 0x{:x}".format(vector),
            bundles=(
                Bundle(0x10, 0x01, nop_m(), adds(9, data_address, 0),
                       adds(8, data_address + 8, 0)),
                Bundle(0x20, 0x01, ld8(10, 9), nop_i(), nop_i()),
                Bundle(0x30, 0x01, ld8(11, 8), nop_i(), nop_i()),
                Bundle(0x40, 0x01, nop_m(), adds(12, 0x111, 0),
                       adds(13, 0x187, 0)),
                Bundle(0x50, 0x01, nop_m(), mov_gr_to_pfs(12),
                       mov_grbr(6, 13)),
                Bundle(0x60, 0x01, mov_gr_to_psr_l(11),
                       nop_i(), nop_i()),
                Bundle(0x70, 0x01, srlz_i(), adds(14, raw_target, 0),
                       nop_i()),

                # Retain ordinary old-value witnesses while the return uses
                # both eligible same-group live values.
                Bundle(0x80, 0x00, nop_m(), mov_gr_to_pfs(10),
                       mov_pfs_to_gr(20)),
                Bundle(0x90, 0x00, nop_m(), mov_grbr(6, 14),
                       mov_brgr(21, 6)),
                Bundle(0xa0, 0x11, nop_m(), nop_i(), br_ret(6)),
                spin_bundle(0xb0),
                spin_bundle(0x100),
                Bundle(IA64_LOWER_PRIVILEGE_TRANSFER_VECTOR, 0x01,
                       nop_m(), mov_argr(22, 66), mov_pfs_to_gr(23)),
                spin_bundle(IA64_LOWER_PRIVILEGE_TRANSFER_VECTOR + 0x10),
                Bundle(IA64_TAKEN_BRANCH_TRAP_VECTOR, 0x01,
                       nop_m(), mov_argr(22, 66), mov_pfs_to_gr(23)),
                spin_bundle(IA64_TAKEN_BRANCH_TRAP_VECTOR + 0x10),
            ),
            terminal_ip=vector + 0x10,
            data=(
                DataWord(data_address, restored_pfs, 8),
                DataWord(data_address + 8, psr_bits, 8),
            ),
        ),
        restored_pfs,
    )


def _typed_return_backing_values() -> Tuple[int, ...]:
    return (
        0xa100000000000001,
        0xb200000000000002,
        0xc300000000000003,
        0xd400000000000004,
    )


def _typed_return_incomplete_handler(vector: int) -> Tuple[Bundle, ...]:
    """Observe the still-unconsumed backing words after a branch trap."""
    return (
        Bundle(vector, 0x01, ld8(24, 15), mov_argr(22, 66),
               mov_pfs_to_gr(23)),
        Bundle(vector + 0x10, 0x01, ld8(25, 16), nop_i(), nop_i()),
        Bundle(vector + 0x20, 0x01, ld8(26, 17), nop_i(), nop_i()),
        Bundle(vector + 0x30, 0x01, ld8(27, 18), nop_i(), nop_i()),
        spin_bundle(vector + 0x40),
    )


def typed_return_incomplete_fill_program() \
        -> Tuple[Program, int, Tuple[int, ...]]:
    """Restore four non-resident locals and complete their mandatory fills."""
    config_address = 0x1800
    backing_start = 0xfd8
    restored_cfm = 4 | (4 << 7)
    restored_pfs = restored_cfm | (0x2a << 52)
    backing = _typed_return_backing_values()
    return (
        Program(
            name="typed BR_RET mandatory four-register frame fill",
            bundles=(
                Bundle(0x10, 0x01, nop_m(), adds(2, 0x1000, 0),
                       adds(9, config_address, 0)),
                Bundle(0x20, 0x09, ld8(10, 9), mov_m_grar(18, 2),
                       adds(14, 0x107, 0)),
                Bundle(0x30, 0x01, nop_m(), mov_gr_to_pfs(10),
                       mov_grbr(6, 14)),
                Bundle(0x40, 0x11, nop_m(), nop_i(), br_ret(6)),
                spin_bundle(0x50),
                Bundle(0x100, 0x01, nop_m(), mov_argr(22, 66),
                       mov_pfs_to_gr(23)),
                spin_bundle(0x110),
            ),
            terminal_ip=0x110,
            data=(
                DataWord(config_address, restored_pfs, 8),
                *(DataWord(backing_start + index * 8, value, 8)
                  for index, value in enumerate(backing)),
                DataWord(0xff8, 0, 8),
            ),
        ),
        restored_pfs,
        backing,
    )


def typed_return_incomplete_trap_program(psr_bits: int, vector: int) \
        -> Tuple[Program, int, Tuple[int, ...]]:
    """Trap after restoring an incomplete SOL4 frame but before any fill."""
    if vector not in (IA64_LOWER_PRIVILEGE_TRANSFER_VECTOR,
                      IA64_TAKEN_BRANCH_TRAP_VECTOR):
        raise ValueError("unsupported incomplete-return trap vector")

    config_address = 0x1800
    backing_start = 0xfd8
    restored_cfm = 4 | (4 << 7)
    restored_pfs = restored_cfm | (0x2a << 52) | (3 << 62)
    backing = _typed_return_backing_values()
    return (
        Program(
            name="typed incomplete BR_RET trap vector 0x{:x}".format(
                vector
            ),
            bundles=(
                Bundle(0x10, 0x01, nop_m(), adds(2, 0x1000, 0),
                       adds(9, config_address, 0)),
                Bundle(0x20, 0x09, ld8(10, 9), mov_m_grar(18, 2),
                       adds(8, config_address + 8, 0)),
                Bundle(0x30, 0x01, ld8(11, 8), adds(14, 0x107, 0),
                       adds(15, backing_start, 0)),
                Bundle(0x40, 0x01, nop_m(), adds(16, backing_start + 8, 0),
                       adds(17, backing_start + 16, 0)),
                Bundle(0x50, 0x01, nop_m(),
                       adds(18, backing_start + 24, 0),
                       mov_gr_to_pfs(10)),
                Bundle(0x60, 0x01, mov_gr_to_psr_l(11),
                       mov_grbr(6, 14), nop_i()),
                Bundle(0x70, 0x01, srlz_i(), nop_i(), nop_i()),
                Bundle(0x80, 0x11, nop_m(), nop_i(), br_ret(6)),
                spin_bundle(0x90),
                spin_bundle(0x100),
                *_typed_return_incomplete_handler(
                    IA64_LOWER_PRIVILEGE_TRANSFER_VECTOR
                ),
                *_typed_return_incomplete_handler(
                    IA64_TAKEN_BRANCH_TRAP_VECTOR
                ),
            ),
            terminal_ip=vector + 0x40,
            data=(
                DataWord(config_address, restored_pfs, 8),
                DataWord(config_address + 8, psr_bits, 8),
                *(DataWord(backing_start + index * 8, value, 8)
                  for index, value in enumerate(backing)),
                DataWord(0xff8, 0, 8),
            ),
        ),
        restored_pfs,
        backing,
    )


def typed_return_register_fill_fault_program() \
        -> Tuple[Program, int, Tuple[int, ...], int]:
    """Fault the first mandatory register read and resume it through RFI.

    The Alternate Data TLB handler changes the faulting backing word before
    returning.  The completed frame must consume that replacement, proving
    the failed read committed neither a value nor an RSE partition step.  The
    handler clears only saved PSR.rt; CR.IFS remains invalid so RFI resumes the
    already-restored frame instead of uncovering it a second time.
    """
    config_address = 0x1800
    backing_start = 0x8000
    backing_end = 0x8020
    fault_address = 0x8018
    replacement = 0x4d4
    restored_cfm = 4 | (4 << 7)
    restored_pfs = restored_cfm | (0x2a << 52)
    backing = _typed_return_backing_values()

    return (
        Program(
            name="typed BR_RET first-register SoftMMU fault/RFI resume",
            bundles=(
                Bundle(0x10, 0x01, nop_m(), adds(15, 1, 0),
                       adds(9, config_address, 0)),
                Bundle(0x20, 0x01, ld8(10, 9),
                       shl_imm(15, 15, 15), adds(14, 0x107, 0)),
                Bundle(0x30, 0x01, nop_m(),
                       adds(2, backing_end - backing_start, 15),
                       adds(3, fault_address - backing_start, 15)),
                Bundle(0x40, 0x01, nop_m(), adds(4, replacement, 0),
                       adds(13, 1, 0)),
                Bundle(0x50, 0x01, mov_m_grar(18, 2),
                       mov_gr_to_pfs(10), nop_i()),
                Bundle(0x60, 0x01, nop_m(), shl_imm(13, 13, 27), nop_i()),
                Bundle(0x70, 0x01, nop_m(),
                       dep_imm(13, 1, 13, 13, 1), mov_grbr(6, 14)),
                Bundle(0x80, 0x01, mov_gr_to_psr_l(13), nop_i(), nop_i()),
                Bundle(0x90, 0x01, srlz_i(), nop_i(), nop_i()),
                Bundle(0xa0, 0x11, nop_m(), nop_i(), br_ret(6)),
                spin_bundle(0xb0),
                Bundle(0x100, 0x01, ld8(25, 3), mov_argr(22, 66),
                       mov_pfs_to_gr(23)),
                spin_bundle(0x110),

                # Capture the interruption resources in unbanked registers,
                # retain the original IPSR separately, and clear only RT in
                # the value written back for IFS.v=0 RFI continuation.
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR, 0x01,
                       mov_crgr(7, IA64_CR_IPSR), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x10, 0x01,
                       mov_crgr(5, IA64_CR_IFS), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x20, 0x01,
                       mov_crgr(6, IA64_CR_ISR), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x30, 0x01,
                       nop_m(), adds(12, 0, 7),
                       dep_imm(7, 0, 7, 27, 1)),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x40, 0x01,
                       mov_grcr(IA64_CR_IPSR, 7), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x50, 0x01,
                       st8(4, 3), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x60, 0x11,
                       nop_m(), nop_i(), rfi()),
            ),
            terminal_ip=0x110,
            data=(
                DataWord(config_address, restored_pfs, 8),
                *(DataWord(backing_start + index * 8, value, 8)
                  for index, value in enumerate(backing)),
            ),
        ),
        restored_pfs,
        backing,
        replacement,
    )


def typed_return_rnat_fill_fault_program() \
        -> Tuple[Program, int, Tuple[int, ...], Tuple[int, ...]]:
    """Fault an RNAT read after a three-register committed fill prefix.

    A 4 KiB identity DTC mapping admits the high-page prefix at 0x8010,
    0x8008 and 0x8000.  The following RNAT access at 0x7ff8 misses.  The
    physical handler poisons those three already-consumed words and supplies
    a new RNAT value before clearing saved RT and executing RFI.  A correct
    prefix-resume keeps the original r33-r35 values, consumes the new RNAT for
    r32, and loads the final low-page word exactly once.
    """
    config_address = 0x1800
    page_base = 0x8000
    backing_start = 0x7ff0
    rnat_address = 0x7ff8
    backing_end = 0x8018
    restored_cfm = 4 | (4 << 7)
    restored_pfs = restored_cfm | (0x2a << 52)
    backing = _typed_return_backing_values()
    poison = (0x611, 0x722, 0x833)
    translation = page_base | 0x661
    itir = 12 << 2

    return (
        Program(
            name="typed BR_RET RNAT SoftMMU prefix fault/RFI resume",
            bundles=(
                Bundle(0x10, 0x01, nop_m(), adds(15, 1, 0),
                       adds(9, config_address, 0)),
                Bundle(0x20, 0x01, ld8(10, 9),
                       shl_imm(15, 15, 15), adds(14, 0x207, 0)),
                Bundle(0x30, 0x01, nop_m(),
                       adds(2, backing_end - page_base, 15),
                       adds(3, 0x10, 15)),
                Bundle(0x40, 0x01, nop_m(), adds(4, 8, 15),
                       adds(5, 0, 15)),
                Bundle(0x50, 0x01, nop_m(), adds(6, poison[0], 0),
                       adds(7, poison[1], 0)),
                Bundle(0x60, 0x01, nop_m(), adds(8, poison[2], 0),
                       adds(12, itir, 0)),
                Bundle(0x70, 0x01, nop_m(),
                       adds(13, translation - page_base, 15),
                       mov_grbr(6, 14)),
                Bundle(0x80, 0x01, mov_m_grar(18, 2),
                       mov_gr_to_pfs(10), nop_i()),
                Bundle(0x90, 0x01, mov_grcr(IA64_CR_IFA, 15),
                       adds(2, rnat_address - page_base, 15),
                       adds(9, 1, 0)),
                Bundle(0xa0, 0x01, mov_grcr(IA64_CR_ITIR, 12),
                       shl_imm(9, 9, 62), nop_i()),
                # ITC.D must terminate its instruction group.  M_MI supplies
                # the required stop immediately after the M-slot operation.
                Bundle(0xb0, 0x0b, itc_d(13), nop_m(), nop_i()),
                Bundle(0xc0, 0x01, srlz_d(), nop_i(), nop_i()),
                Bundle(0xd0, 0x01, nop_m(), adds(13, 1, 0), nop_i()),
                Bundle(0xe0, 0x01, nop_m(), shl_imm(13, 13, 27), nop_i()),
                Bundle(0xf0, 0x01, nop_m(),
                       dep_imm(13, 1, 13, 13, 1), nop_i()),
                Bundle(0x100, 0x01, mov_gr_to_psr_l(13), nop_i(), nop_i()),
                Bundle(0x110, 0x01, srlz_i(), nop_i(), nop_i()),
                Bundle(0x120, 0x11, nop_m(), nop_i(), br_ret(6)),
                spin_bundle(0x130),
                Bundle(0x200, 0x01, ld8(25, 3), mov_argr(22, 66),
                       mov_pfs_to_gr(23)),
                Bundle(0x210, 0x01, ld8(26, 4),
                       predicate_test("tnat", 6, 7, relation="z",
                                      update="normal", r3=32),
                       nop_i()),
                Bundle(0x220, 0x01, ld8(27, 5), nop_i(), nop_i()),
                Bundle(0x230, 0x01, ld8(28, 2), nop_i(), nop_i()),
                spin_bundle(0x240),

                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR, 0x01,
                       mov_crgr(1, IA64_CR_IPSR), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x10, 0x01,
                       mov_crgr(10, IA64_CR_IFS), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x20, 0x01,
                       mov_crgr(11, IA64_CR_ISR), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x30, 0x01,
                       nop_m(), adds(12, 0, 1),
                       dep_imm(1, 0, 1, 27, 1)),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x40, 0x01,
                       mov_grcr(IA64_CR_IPSR, 1), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x50, 0x01,
                       st8(6, 3), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x60, 0x01,
                       st8(7, 4), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x70, 0x01,
                       st8(8, 5), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x80, 0x01,
                       st8(9, 2), nop_i(), nop_i()),
                Bundle(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x90, 0x11,
                       nop_m(), nop_i(), rfi()),
            ),
            terminal_ip=0x240,
            data=(
                DataWord(config_address, restored_pfs, 8),
                DataWord(backing_start, backing[0], 8),
                DataWord(rnat_address, 0, 8),
                DataWord(page_base, backing[1], 8),
                DataWord(page_base + 8, backing[2], 8),
                DataWord(page_base + 16, backing[3], 8),
            ),
        ),
        restored_pfs,
        backing,
        poison,
    )


def indirect_branch_forwarding_program() -> Program:
    """Contrast ordinary BR reads with branch-only forwarding."""
    return Program(
        name="typed indirect BR forwarding and target alignment",
        bundles=(
            # b1's stopped group-entry value has different low bits and an
            # entirely different aligned target from its later live value.
            Bundle(0x10, 0x01, nop_m(), adds(10, 0x73, 0),
                   adds(11, 0x97, 0)),
            Bundle(0x20, 0x01, nop_m(), mov_grbr(1, 10), nop_i()),

            # Split this no-stop producer/consumer pair into separate TBs.
            # MOV_BRGR is an ordinary source and must read saved b1=0x73;
            # BR_INDIRECT is the special architectural consumer of the
            # eligible same-group MOV_GRBR and must select live b1=0x97,
            # align it down, and transfer to 0x90.
            Bundle(0x30, 0x00, nop_m(), mov_grbr(1, 11), nop_i()),
            Bundle(0x40, 0x10, nop_m(), mov_brgr(20, 1),
                   br_indirect(1)),

            # A false-qualified writer must neither change live b2 nor set
            # branch-forward provenance.  The following ordinary read and
            # p0 branch consequently both select the stopped 0xf3 value;
            # only the branch masks its low bits, transferring to 0xf0.
            Bundle(0x90, 0x01, nop_m(), adds(12, 0x117, 0),
                   adds(13, 0xf3, 0)),
            Bundle(0xa0, 0x01, nop_m(), mov_grbr(2, 13), nop_i()),
            Bundle(0xb0, 0x00, nop_m(), mov_grbr(2, 12, qp=7), nop_i()),
            Bundle(0xc0, 0x10, nop_m(), mov_brgr(21, 2),
                   br_indirect(2)),
            spin_bundle(0xd0),
            spin_bundle(0xe0),
            spin_bundle(0xf0),
        ),
        terminal_ip=0xf0,
    )


def nonterminal_indirect_suppression_program() -> Program:
    """Exercise both ordered edges of a two-branch MBB CFG."""
    return Program(
        name="taken nonterminal indirect branch suppresses later slot",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(10, 0x83, 0),
                   adds(11, 0xb7, 0)),
            Bundle(0x20, 0x01, nop_m(), adds(12, 0x77, 0),
                   mov_grbr(1, 10)),
            Bundle(0x30, 0x01, nop_m(), mov_grbr(2, 11),
                   mov_grbr(3, 12)),
            # Establish p6=true and p7=false explicitly.
            Bundle(0x40, 0x01, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"), nop_i()),
            # The false p7 arm must reach and execute the later p0 branch.
            # Its b3=0x77 target also proves alignment on the second arm;
            # sequential fallthrough reaches the poison spin at 0x60.
            Bundle(0x50, 0x12, nop_m(), br_indirect(2, qp=7),
                   br_indirect(3)),
            spin_bundle(0x60),
            # MBB exposes an actual intra-bundle CFG.  The true p6 branch in
            # slot 1 at 0x70 transfers to 0x80.  The unconditional slot-2
            # branch to poison 0xb0 must be present in IR but never execute.
            Bundle(0x70, 0x12, nop_m(), br_indirect(1, qp=6),
                   br_indirect(2)),
            Bundle(0x80, 0x01, nop_m(), adds(22, 0x55, 0), nop_i()),
            spin_bundle(0x90),
            spin_bundle(0xb0),
        ),
        terminal_ip=0x90,
    )


def nonterminal_indirect_frontier_program() -> Program:
    """Exercise false branch arms on both sides of a stop frontier."""
    return Program(
        name="nonterminal indirect stop and no-stop frontiers",
        bundles=(
            # p7 is explicitly false.  Seed r1=10 at the same stop.
            Bundle(0x10, 0x01, nop_m(), adds(1, 10, 0),
                   cmp_rr(6, 7, 0, 0, "eq")),
            # The write retires but leaves the old r1=10 as this open
            # group's ordinary source across a forced TB continuation.
            Bundle(0x20, 0x00, nop_m(), adds(1, 1, 1), nop_i()),
            # Both conditional indirect branches are false.  With MBB's
            # no-stop template, slot 2 falls through without closing the
            # source epoch, so 0x40 must still consume saved r1=10.
            Bundle(0x30, 0x12, nop_m(), br_indirect(0, qp=7),
                   br_indirect(1, qp=7)),
            Bundle(0x40, 0x01, nop_m(), adds(2, 0, 1), nop_i()),

            Bundle(0x50, 0x01, nop_m(), adds(3, 20, 0), nop_i()),
            Bundle(0x60, 0x00, nop_m(), adds(3, 1, 3), nop_i()),
            # The same two false arms now use MBB's slot-2 stop.  Reaching
            # that frontier closes the group, so 0x80 must consume live
            # r3=21 rather than its former group-entry image.
            Bundle(0x70, 0x13, nop_m(), br_indirect(0, qp=7),
                   br_indirect(1, qp=7)),
            Bundle(0x80, 0x01, nop_m(), adds(4, 0, 3), nop_i()),
            spin_bundle(0x90),
        ),
        terminal_ip=0x90,
    )


def _loop_matrix_rows(kind: str) -> Tuple[Tuple[int, int, bool, bool], ...]:
    """Return ``(LC, EC, condition, forwarded)`` audit rows."""
    if kind == "cloop":
        return tuple((lc, 0x55, False, False) for lc in (0, 1, 2))
    if kind in ("ctop", "cexit"):
        return tuple(
            (lc, ec, False, False)
            for lc in (0, 1)
            for ec in (0, 1, 2, U64_MASK)
        )
    if kind in ("wtop", "wexit"):
        return tuple(
            # Make the true/EC=0 row consume a same-group forwarded p6.
            (2, ec, predicate, predicate and ec == 0)
            for predicate in (False, True)
            for ec in (0, 1, 2, U64_MASK)
        )
    raise ValueError("unknown loop branch kind {!r}".format(kind))


def application_move_forced_tb_ri_program() -> Program:
    """Keep a successful AR helper from leaking its slot into the next TB."""
    return Program(
        name="application move forced-TB RI canonicalization",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(2, 0x55, 0), nop_i()),
            # The same-group read observes EC's entry image; the following
            # bundle must begin at RI=0 and observe the normalized live EC.
            Bundle(0x20, 0x01, nop_m(), mov_i_grar(66, 2),
                   mov_argr(20, 66)),
            Bundle(0x30, 0x01, nop_m(), mov_argr(21, 66), nop_i()),
            spin_bundle(0x40),
        ),
        terminal_ip=0x40,
    )


def loop_matrix_program(kind: str) -> Tuple[
        Program, Tuple[LoopExpectation, ...],
        Tuple[Tuple[int, int, bool], ...], int]:
    """Build one target==fallthrough truth-table program per loop form."""
    bundles: List[Bundle] = []
    expectations: List[LoopExpectation] = []
    traces: List[Tuple[int, int, bool]] = []
    address = 0x10
    rotation_count = 0

    def emit(template: int, slot0: int, slot1: int, slot2: int) -> int:
        nonlocal address
        bundle_ip = address
        bundles.append(Bundle(bundle_ip, template, slot0, slot1, slot2))
        address += 0x10
        return bundle_ip

    # Forty stacked outputs cover all eight five-field boundary rows without
    # involving the rotating-GR subset used by the dedicated stress case.
    emit(0x01, alloc(31, 80, 80, 0), nop_i(), nop_i())

    for index, (initial_lc, initial_ec, predicate, forwarded) in enumerate(
            _loop_matrix_rows(kind)):
        output = 32 + index * 5
        old_marker = 0x100 + index
        new_marker = 0x200 + index
        # AR.EC is a six-bit architectural register.  The deliberately wide
        # source rows still exercise normalization, but loop semantics and
        # the later mov-from-AR observe only the stored low six bits.
        live_ec = initial_ec & 0x3f

        if kind == "cloop":
            taken = initial_lc != 0
            rotated = False
            injected = False
            final_lc = initial_lc - 1 if taken else 0
            final_ec = live_ec
        elif kind in ("ctop", "cexit"):
            active = initial_lc != 0 or live_ec > 1
            taken = active if kind == "ctop" else not active
            rotated = initial_lc != 0 or live_ec != 0
            injected = initial_lc != 0
            final_lc = initial_lc - 1 if initial_lc != 0 else 0
            final_ec = (
                live_ec
                if initial_lc != 0 or live_ec == 0
                else live_ec - 1
            )
        else:
            active = predicate or live_ec > 1
            taken = active if kind == "wtop" else not active
            rotated = predicate or live_ec != 0
            injected = False
            final_lc = initial_lc
            final_ec = (
                live_ec
                if predicate or live_ec == 0
                else live_ec - 1
            )
        rotation_count += int(rotated)

        expectations.append(LoopExpectation(
            label="{} LC={} EC={} P={}".format(
                kind, initial_lc, hex(initial_ec), int(predicate)
            ),
            output_base=output,
            old_marker=old_marker,
            new_marker=new_marker,
            taken=taken,
            rotated=rotated,
            injected=injected,
            final_lc=final_lc,
            final_ec=final_ec,
        ))

        # ADDS -1 is an independent literal UINT64_MAX constructor.
        lc_imm = -1 if initial_lc == U64_MASK else initial_lc
        ec_imm = -1 if initial_ec == U64_MASK else initial_ec
        emit(0x01, nop_m(), adds(1, lc_imm, 0), adds(2, ec_imm, 0))
        emit(0x01, nop_m(), mov_i_grar(65, 1), mov_i_grar(66, 2))

        # Clear the full rotating PR bank, then seed logical p62=1,p63=0.
        # After one rotation p63 observes old p62 and therefore records that
        # this exact row rotated.  The injected old p63 value appears at p16.
        emit(0x01, nop_m(), mov_grpr(0, 0x10000), nop_i())
        emit(0x01, nop_m(), cmp_rr(62, 63, 0, 0, "eq"), nop_i())

        initial_predicate = predicate and not forwarded
        condition_setup = (
            cmp_rr(6, 7, 0, 0, "eq")
            if initial_predicate else cmp_rr(6, 7, 0, 0, "lt")
        )
        emit(0x01, nop_m(), adds(5, old_marker, 0), condition_setup)
        emit(0x01, nop_m(), adds(output + 1, 0, 0),
             adds(output + 2, 0, 0))

        # This write opens the source epoch.  One while-loop row also writes
        # p6=true here, proving the branch treats qp as a forwarded condition
        # rather than as ordinary instruction nullification.
        forwarded_compare = (
            cmp_rr(6, 7, 0, 0, "eq") if forwarded else nop_i()
        )
        emit(0x00, nop_m(), adds(5, new_marker, 0), forwarded_compare)

        branch_ip = address
        branch_target = branch_ip + 0x10
        emit(0x10, nop_m(), nop_i(), br_loop(
            kind, branch_ip, branch_target,
            qp=6 if kind in ("wtop", "wexit") else 0,
        ))
        traces.append((branch_ip, branch_target, kind != "cloop"))

        # Target equals fallthrough.  The first read is nevertheless distinct:
        # a taken arm starts a fresh epoch and sees new_marker, while an
        # untaken no-stop arm retains the immutable old_marker source.
        emit(0x03, nop_m(), adds(output, 0, 5),
             adds(output + 1, 1, 0, qp=63))
        emit(0x01, nop_m(), adds(output + 2, 1, 0, qp=16),
             mov_argr(output + 3, 65))
        emit(0x01, nop_m(), mov_argr(output + 4, 66), nop_i())

    terminal_ip = address
    bundles.append(spin_bundle(terminal_ip))
    return (
        Program(
            name="{} complete loop-branch truth table".format(kind),
            bundles=tuple(bundles),
            terminal_ip=terminal_ip,
        ),
        tuple(expectations),
        tuple(traces),
        rotation_count,
    )


def loop_rotation_wrap_program() -> Tuple[
        Program, Tuple[Tuple[int, int, bool], ...]]:
    """Rotate 49 times to cross PR/FR wrap and move a dirty NaT pair."""
    data_address = 0x1000
    data_value = 0x123456789abcdef0
    bundles: List[Bundle] = [
        Bundle(0x10, 0x01, alloc(31, 8, 8, 1), nop_i(), nop_i()),
        Bundle(0x20, 0x01, nop_m(), adds(8, 1, 0),
               adds(9, data_address, 0)),
        Bundle(0x30, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
        Bundle(0x40, 0x01, ld8_fill(32, 9), adds(39, 0x777, 0), nop_i()),
        Bundle(0x50, 0x01, nop_m(), adds(1, 49, 0), adds(2, 0, 0)),
        Bundle(0x60, 0x01, nop_m(), mov_i_grar(65, 1),
               mov_i_grar(66, 2)),
        Bundle(0x70, 0x01, nop_m(), mov_grpr(0, 0x10000), nop_i()),
    ]
    traces: List[Tuple[int, int, bool]] = []
    address = 0x80
    for _ in range(49):
        target = address + 0x10
        bundles.append(Bundle(
            address, 0x11, nop_m(), nop_i(),
            br_loop("ctop", address, target),
        ))
        traces.append((address, target, True))
        address = target

    bundles.append(Bundle(
        address, 0x01, nop_m(), mov_argr(20, 65), nop_i()
    ))
    address += 0x10
    # cpu_dump exposes static NaTs, not rse.logical_nat.  Project the rotated
    # logical r33 value/NaT pair through typed arithmetic without weakening
    # the architectural NaT assertion in the harness.
    bundles.append(Bundle(
        address, 0x01, nop_m(), adds(21, 0, 33), nop_i()
    ))
    terminal_ip = address + 0x10
    bundles.append(spin_bundle(terminal_ip))
    return (
        Program(
            name="49-rotation logical GR/NaT and RRB wrap",
            bundles=tuple(bundles),
            terminal_ip=terminal_ip,
            data=(DataWord(data_address, data_value, 8),),
        ),
        tuple(traces),
    )


def loop_rotating_overlay_program() -> Program:
    """Rotate an open typed GR/NaT source overlay on a false loop arm."""
    data_address = 0x1000
    data_value = 0x123456789abcdef0
    return Program(
        name="false rotating loop preserves the open ordinary-source view",
        bundles=(
            Bundle(0x10, 0x01, alloc(31, 8, 8, 1), nop_i(), nop_i()),
            Bundle(0x20, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, data_address, 0)),
            Bundle(0x30, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            # The stopped fill establishes old logical r32 with NaT=1.
            Bundle(0x40, 0x01, ld8_fill(32, 9), nop_i(), nop_i()),
            # LC=0/EC=1 makes CTOP false while still requesting one epilog
            # rotation and decrementing EC to zero.
            Bundle(0x50, 0x01, nop_m(), adds(1, 0, 0), adds(2, 1, 0)),
            Bundle(0x60, 0x01, nop_m(), mov_i_grar(65, 1),
                   mov_i_grar(66, 2)),
            # This no-stop write forces saved r32/value+NaT in the typed
            # ordinary-source overlay.  The subsequent modulo rotation must
            # rotate that hidden entry to logical r33 along with its mask.
            Bundle(0x70, 0x00, nop_m(), adds(32, 0x555, 0), nop_i()),
            Bundle(0x80, 0x10, nop_m(), nop_i(),
                   br_loop("ctop", 0x80, 0xc0)),
            # False/no-stop fallthrough retains the source epoch.  The read
            # before MI_I's internal stop must therefore consume rotated
            # saved r33 (old r32), including its NaT, not live 0x555.
            Bundle(0x90, 0x03, nop_m(), adds(20, 0, 33),
                   mov_argr(21, 66)),
            # Once the internal stop closes the overlay, r33 exposes the live
            # writer that underwent the same one-position rotation.
            Bundle(0xa0, 0x01, nop_m(), adds(22, 0, 33), nop_i()),
            spin_bundle(0xb0),
            spin_bundle(0xc0),
        ),
        terminal_ip=0xb0,
        data=(DataWord(data_address, data_value, 8),),
    )


def loop_first_taken_suppression_program() -> Program:
    """An earlier taken direct branch suppresses a later CTOP update."""
    return Program(
        name="first-taken branch suppresses later loop branch",
        bundles=(
            Bundle(0x10, 0x01, alloc(31, 8, 8, 1), nop_i(), nop_i()),
            Bundle(0x20, 0x01, nop_m(), adds(1, 1, 0), adds(2, 0, 0)),
            Bundle(0x30, 0x01, nop_m(), mov_i_grar(65, 1),
                   mov_i_grar(66, 2)),
            Bundle(0x40, 0x01, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"), nop_i()),
            # Slot 1 takes the fresh-target arm.  The translator must retain
            # slot 2 in IR but runtime control flow must bypass its LC update,
            # p63 injection, modulo rotation, and encoded stop.
            Bundle(0x50, 0x13, nop_m(), br_cond(0x50, 0x80, qp=6),
                   br_loop("ctop", 0x50, 0xa0)),
            Bundle(0x80, 0x01, nop_m(), mov_argr(20, 65), nop_i()),
            spin_bundle(0x90),
            spin_bundle(0xa0),
        ),
        terminal_ip=0x90,
    )


def call_frame_architectural_program() -> Program:
    """Exercise a taken B3 call's complete link/PFS/RSE transition."""
    pfs_cpl3 = 3 << 62
    output_nat_value = 0x123456789abcdef0
    advanced_value = 0x0fedcba987654321
    return Program(
        name="B3 call frame, dirty outputs, NaT, PFS, BSP, and ALAT",
        bundles=(
            # Establish a nonzero backing-store base while still at CPL0.
            # The synthetic br.ret restores only CPL=3 (zero-sized CFM), so
            # the call later has a nontrivial old privilege level to pack.
            Bundle(0x10, 0x01, nop_m(), adds(2, 0x1000, 0),
                   adds(9, 0x1800, 0)),
            Bundle(0x20, 0x09, ld8_fill(10, 9),
                   mov_m_grar(18, 2), adds(4, 0x60, 0)),
            Bundle(0x30, 0x01, nop_m(), mov_i_grar(64, 10),
                   mov_grbr(6, 4)),
            Bundle(0x40, 0x11, nop_m(), nop_i(), br_ret(6)),
            spin_bundle(0x50),

            # Caller CFM=SOF6/SOL4 gives two outputs.  EC=0x2a and CPL=3
            # must be captured in PFS; preserving four locals must advance
            # frame base and BSP by exactly four RSE registers.
            Bundle(0x60, 0x01, alloc(31, 6, 4, 0), nop_i(), nop_i()),
            Bundle(0x70, 0x01, nop_m(), adds(1, 0x2a, 0),
                   adds(8, 4, 0)),
            Bundle(0x80, 0x01, mov_m_grar(36, 8),
                   mov_i_grar(66, 1), nop_i()),
            Bundle(0x90, 0x01, nop_m(), adds(9, 0x1810, 0),
                   adds(11, 0x1820, 0)),
            # Dirty output r36 and NaT-tagged output r37 become callee
            # r32/r33.  The advanced load creates a stale caller-local ALAT
            # entry for logical r32 which a call-frame remap must invalidate.
            Bundle(0xa0, 0x01, ld8_fill(37, 9), adds(36, 0x666, 0), nop_i()),
            Bundle(0xb0, 0x01, ld8_advanced(32, 11),
                   adds(33, 0x333, 0), nop_i()),
            Bundle(0xc0, 0x11, nop_m(), nop_i(),
                   br_call(0xc0, 0x120, 2)),
            spin_bundle(0xd0),

            # Project the remapped output value/NaT pairs into static GRs so
            # HMP can observe both.  Read back the packed PFS and live EC.
            Bundle(0x120, 0x03, nop_m(), adds(20, 0, 32),
                   adds(21, 0, 33)),
            Bundle(0x130, 0x01, nop_m(), mov_argr(22, 64),
                   mov_argr(23, 66)),
            # A stale ALAT entry for caller r32 would incorrectly fall
            # through.  Correct frame-entry invalidation takes recovery.
            Bundle(0x140, 0x01, chk_a(32, 0x140, 0x170),
                   nop_i(), nop_i()),
            Bundle(0x150, 0x01, nop_m(), adds(24, 2, 0), nop_i()),
            Bundle(0x160, 0x11, nop_m(), nop_i(),
                   br_cond(0x160, 0x180)),
            Bundle(0x170, 0x01, nop_m(), adds(24, 1, 0), nop_i()),
            spin_bundle(0x180),
        ),
        terminal_ip=0x180,
        data=(
            DataWord(0x1800, pfs_cpl3, 8),
            DataWord(0x1810, output_nat_value, 8),
            DataWord(0x1820, advanced_value, 8),
        ),
    )


def b3_backward_forwarded_call_program() -> Program:
    """A same-bundle compare forwards true to a backward B3 call."""
    return Program(
        name="backward B3 call with forwarded true predicate",
        bundles=(
            spin_bundle(0x10),
            Bundle(0x40, 0x10, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"),
                   br_call(0x40, 0x10, 1, qp=6)),
        ),
        terminal_ip=0x10,
        entry=0x40,
    )


def x4_equal_fallthrough_call_program(mode: str) -> Program:
    """Contrast taken, false, and nullified-predicate X4 call arms."""
    if mode == "true":
        compare = cmp_rr(6, 7, 0, 0, "eq")
    elif mode == "false":
        compare = cmp_rr(6, 7, 0, 0, "lt")
    elif mode == "nullified":
        # If this false-p5 compare executes by mistake it changes p6 to false.
        compare = cmp_rr(6, 7, 0, 0, "lt", qp=5)
    else:
        raise ValueError("X4 call mode must be true, false, or nullified")
    l_slot, x_slot = brl_call(0x60, 0x70, 2, qp=6)
    return Program(
        name="{} X4 call with target equal to fallthrough".format(mode),
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(1, 10, 0),
                   adds(2, 0x555, 0)),
            Bundle(0x20, 0x01, nop_m(), mov_i_grar(64, 2),
                   adds(3, 0x777, 0)),
            # Seed p6=true and p5=false at completed boundaries.  The MLX
            # compare then supplies true/false provenance or is nullified.
            Bundle(0x30, 0x01, nop_m(), mov_grbr(2, 3),
                   cmp_rr(6, 7, 0, 0, "eq")),
            Bundle(0x40, 0x01, nop_m(),
                   cmp_rr(5, 4, 0, 0, "lt"), nop_i()),
            Bundle(0x50, 0x00, nop_m(), adds(1, 11, 0), nop_i()),
            Bundle(0x60, 0x04, compare, l_slot, x_slot),
            # Taken target and false fallthrough share 0x70.  Only the taken
            # arm starts a fresh source epoch and performs link/frame effects.
            Bundle(0x70, 0x03, nop_m(), adds(20, 0, 1),
                   mov_argr(21, 64)),
            spin_bundle(0x80),
        ),
        terminal_ip=0x80,
    )


def x4_far_backward_call_program() -> Program:
    """Exercise the signed high portion of a backward X4 imm60 call."""
    source = 0x02000000
    l_slot, x_slot = brl_call(source, 0x10, 4)
    return Program(
        name="far backward unconditional X4 call",
        bundles=(
            spin_bundle(0x10),
            Bundle(source, 0x05, nop_m(), l_slot, x_slot),
        ),
        terminal_ip=0x10,
        entry=source,
    )


def indirect_alias_forwarded_call_program() -> Program:
    """Latch a forwarded B5 target before a b1==b2 link overwrite."""
    return Program(
        name="B5 forwarded target, ordinary shadow, alias, and alignment",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(4, 0x187, 0),
                   adds(5, 0x20d, 0)),
            Bundle(0x20, 0x01, nop_m(), mov_grbr(3, 4), nop_i()),
            # Ordinary mov r20=b3 must retain old 0x187 while the following
            # call consumes MOV_GRBR's explicit branch-forward value 0x20d.
            Bundle(0x30, 0x00, nop_m(), mov_grbr(3, 5), mov_brgr(20, 3)),
            Bundle(0x40, 0x10, nop_m(),
                   cmp_rr(6, 7, 0, 0, "eq"),
                   br_call_indirect(3, 3, qp=6)),
            spin_bundle(0x50),
            Bundle(0x200, 0x01, nop_m(), mov_argr(21, 64), nop_i()),
            spin_bundle(0x210),
        ),
        terminal_ip=0x210,
    )


def indirect_false_call_program() -> Program:
    """A stopped false B5 leaves link/frame state and closes the epoch."""
    return Program(
        name="false B5 call preserves link, PFS, and open source epoch",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(1, 10, 0),
                   adds(4, 0x55, 0)),
            Bundle(0x20, 0x01, nop_m(), mov_grbr(5, 4),
                   adds(3, 0x777, 0)),
            Bundle(0x30, 0x01, nop_m(), mov_grbr(2, 3),
                   mov_i_grar(64, 4)),
            Bundle(0x40, 0x00, nop_m(), adds(1, 11, 0), nop_i()),
            # The encoded stop distinguishes this from the false/no-stop X4
            # case: the call remains nullified, but its successful retirement
            # closes the issue group, so 0x60 reads the new r1 value.
            Bundle(0x50, 0x11, nop_m(),
                   cmp_rr(6, 7, 0, 0, "lt"),
                   br_call_indirect(2, 5, qp=6)),
            Bundle(0x60, 0x03, nop_m(), adds(20, 0, 1),
                   mov_argr(21, 64)),
            spin_bundle(0x70),
        ),
        terminal_ip=0x70,
    )


def call_first_taken_suppression_program() -> Program:
    """An earlier taken branch suppresses a later unconditional B3 call."""
    return Program(
        name="first taken branch suppresses call-frame suffix",
        bundles=(
            Bundle(0x10, 0x01, alloc(31, 6, 4, 0), nop_i(), nop_i()),
            Bundle(0x20, 0x01, nop_m(), adds(1, 1, 0),
                   adds(2, 0x555, 0)),
            Bundle(0x30, 0x01, nop_m(), mov_i_grar(66, 1),
                   mov_i_grar(64, 2)),
            Bundle(0x40, 0x01, nop_m(), adds(3, 0x777, 0),
                   cmp_rr(6, 7, 0, 0, "eq")),
            Bundle(0x50, 0x01, nop_m(), mov_grbr(2, 3), nop_i()),
            Bundle(0x60, 0x13, nop_m(), br_cond(0x60, 0x90, qp=6),
                   br_call(0x60, 0xb0, 2)),
            spin_bundle(0x70),
            Bundle(0x90, 0x01, nop_m(), mov_argr(20, 64),
                   mov_argr(21, 66)),
            spin_bundle(0xa0),
            spin_bundle(0xb0),
        ),
        terminal_ip=0xa0,
    )


def long_no_stop_scalar_program(bundle_count: int) -> Program:
    """Build one scalar issue group spanning exactly *bundle_count* bundles."""
    if not 1 <= bundle_count <= 31:
        raise ValueError("long scalar group needs from one to 31 bundles")

    bundles: List[Bundle] = []
    for index in range(bundle_count):
        address = 0x10 + index * 0x10
        # MII has no stop in template 0x00.  Only the final bundle uses the
        # otherwise-identical template 0x01, whose slot-2 stop closes the
        # complete multi-bundle issue group.
        template = 0x01 if index + 1 == bundle_count else 0x00
        bundles.append(
            Bundle(
                address,
                template,
                nop_m(),
                adds(index + 1, 0x100 + index, 0),
                nop_i(),
            )
        )

    terminal_ip = 0x10 + bundle_count * 0x10
    bundles.append(
        Bundle(
            terminal_ip,
            0x11,
            nop_m(),
            nop_i(),
            br_cond(terminal_ip, terminal_ip),
        )
    )
    return Program(
        name="{}-bundle no-stop scalar group".format(bundle_count),
        bundles=tuple(bundles),
        terminal_ip=terminal_ip,
    )


def page_crossing_overlay_continuation_program() -> Program:
    """Contrast an independent group with a page-crossing dependency."""
    data_address = 0x1800
    data_value = 0x123456789abcdef0
    return Program(
        name="page-crossing ordinary-source overlay continuation",
        bundles=(
            # Neither destination is read again in this completed issue
            # group.  This is the IR negative control: typed retirement may
            # update live r1/p1/p2, but must not touch saved_gr_mask[] or the
            # pr_saved validity byte.  The later setup deliberately rewrites
            # p1/p2 in a separate group so the final architectural golden is
            # unchanged by this control.
            Bundle(0xfa0, 0x01, nop_m(), adds(1, 5, 0),
                   cmp_rr(1, 2, 0, 0, "eq")),
            # The spill/fill address selects AR.UNAT bit zero.  Complete each
            # setup group before reaching the group whose continuation is
            # under test.
            Bundle(0xfb0, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, data_address, 0)),
            Bundle(0xfc0, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0xfd0, 0x01, ld8_fill(10, 9), nop_i(), nop_i()),
            # Seed p1=true and p2=false at an architectural stop.
            Bundle(0xfe0, 0x01, nop_m(),
                   cmp_rr(1, 2, 0, 0, "eq"), nop_i()),
            # No stop: these writes retire at 0xff0 while preserving the
            # issue-group-entry r10/NaT and PR images for ordinary consumers
            # in the next TB and on the next guest page.
            Bundle(0xff0, 0x00, nop_m(), adds(10, 1, 0),
                   cmp_rr(1, 2, 0, 0, "lt")),
            # The final stop closes the group.  Both consumers must select the
            # saved images even though live r10 and p1 changed in the previous
            # bundle/TB.  r11 must receive the saved NaT together with r10.
            Bundle(0x1000, 0x01, nop_m(), adds(11, 0, 10),
                   adds(12, 99, 0, qp=1)),
            Bundle(0x1010, 0x11, nop_m(), nop_i(),
                   br_cond(0x1010, 0x1010)),
        ),
        terminal_ip=0x1010,
        data=(DataWord(data_address, data_value, 8),),
        entry=0xfa0,
    )


def internal_stop_typed_handoff_program() -> Program:
    """Close an incoming typed group, then run a fresh typed suffix."""
    return Program(
        name="typed owner continuation at an internal bundle stop",
        bundles=(
            # r3 makes an accidental restart from slot zero observable: the
            # typed prefix below must increment it exactly once.
            Bundle(0xfe0, 0x01, nop_m(), adds(3, 10, 0),
                   adds(8, 1, 0)),
            # Open a typed-owned group without creating any saved GR/NaT/PR
            # overlay entries at runtime.  p1 is false after reset, so these
            # supported instructions are nullified.  The forced TB split must
            # therefore carry ownership through typed_active itself rather
            # than inferring it from nonempty overlay masks.
            # Placing this fresh group at the last bundle of its instruction
            # page makes typed ownership legitimate without peeking through
            # the semantic fetch boundary at the unsupported next bundle.
            Bundle(0xff0, 0x00, nop_m(), adds(1, 42, 0, qp=1),
                   adds(2, 7, 0, qp=1)),
            # MI_I stops after slot 1 and slot 2.  Slots 0/1 are the final
            # typed prefix of the incoming group.  Slot 2 starts a fresh typed
            # group, so lowering must resume at RI=2 after the prefix closes.
            Bundle(0x1000, 0x03, nop_m(), adds(3, 1, 3),
                   mov_current_ip(8)),
            Bundle(0x1010, 0x11, nop_m(), nop_i(),
                   br_cond(0x1010, 0x1010)),
        ),
        terminal_ip=0x1010,
        entry=0xfe0,
    )


def nonempty_overlay_internal_stop_handoff_program() -> Program:
    data_address = 0x1800
    data_value = 0x123456789abcdef0
    return Program(
        name="nonempty overlay continuation at an internal bundle stop",
        bundles=(
            Bundle(0xfa0, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, data_address, 0)),
            Bundle(0xfb0, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0xfc0, 0x01, ld8_fill(10, 9), nop_i(), nop_i()),
            # Keep NaT(r10), but make the suffix's AR.UNAT write observable.
            Bundle(0xfd0, 0x01, mov_m_grar(36, 0), nop_i(), nop_i()),
            Bundle(0xfe0, 0x01, nop_m(),
                   cmp_rr(1, 2, 0, 0, "eq"), nop_i()),
            # These writes create both a saved GR+NaT entry and a saved PR
            # image before the forced TB split.  The live post-write state is
            # r10=1/NaT-clear and p1=false,p2=true.
            Bundle(0xff0, 0x00, nop_m(), adds(10, 1, 0),
                   cmp_rr(1, 2, 0, 0, "lt")),
            # The prefix consumes the saved GR+NaT and closes the typed epoch.
            # The fresh suffix is qualified by live p2.  It can execute only
            # if close cleared every saved mask/image and typed_active first.
            Bundle(0x1000, 0x03, nop_m(), adds(11, 0, 10),
                   mov_current_ip(12, qp=2)),
            Bundle(0x1010, 0x11, nop_m(), nop_i(),
                   br_cond(0x1010, 0x1010)),
        ),
        terminal_ip=0x1010,
        data=(DataWord(data_address, data_value, 8),),
        entry=0xfa0,
    )


def typed_epoch_migration_program() -> Program:
    return Program(
        name="typed epoch save/load migration resume",
        bundles=(
            # The source is stopped before 0x20.  This no-stop bundle has then
            # retired r1/r4 while preserving their group-entry values in the
            # migrated ordinary-source overlay.
            Bundle(0x10, 0x00, nop_m(), adds(1, 5, 0), adds(4, 9, 0)),
            # A destination that loses the saved r1 image computes r2=5.  A
            # restored typed owner must instead keep the group-entry r1=0 and
            # close the epoch with r2=0.
            Bundle(0x20, 0x01, nop_m(), adds(2, 0, 1), adds(3, 7, 0)),
            Bundle(0x30, 0x11, nop_m(), nop_i(), br_cond(0x30, 0x30)),
        ),
        terminal_ip=0x30,
    )


def typed_branch_forward_migration_program() -> Program:
    return Program(
        name="typed compare-to-branch forwarding save/load resume",
        bundles=(
            # The no-stop compare retires p6=true but preserves the group-entry
            # predicate image.  A branch is the one architectural consumer
            # allowed to observe the forwarded result in this same group.
            Bundle(0x10, 0x00, nop_m(), nop_i(),
                   cmp_rr(6, 7, 0, 0, "eq")),
            Bundle(0x20, 0x11, nop_m(), nop_i(),
                   br_cond(0x20, 0x40, qp=6)),
            spin_bundle(0x30),
            spin_bundle(0x40),
        ),
        terminal_ip=0x40,
    )


def typed_application_move_ri_restart_program() -> Program:
    data_address = 0x1000
    data_value = 0x123456789abcdef0
    return Program(
        name="typed application-move restart at RI=2",
        bundles=(
            # The test enters this ordinary typed bundle at RI=2.  Slots 0
            # and 1 are deliberately visible and non-idempotent: replaying
            # either one makes the final register image fail.  Slot 2 writes
            # the legal I-unit AR.LC application register; the next bundle
            # reads it back to provide a positive suffix-execution proof.
            Bundle(0x10, 0x03, ld8_fill(5, 9), adds(1, 1, 1),
                   mov_i_grar(IA64_AR_LC, 8)),
            Bundle(0x20, 0x11, nop_m(), mov_argr(10, IA64_AR_LC),
                   br_cond(0x20, 0x30)),
            spin_bundle(0x30),
        ),
        terminal_ip=0x30,
        data=(DataWord(data_address, data_value, 8),),
    )


def typed_short_branch_ri_restart_program() -> Program:
    return Program(
        name="typed B1 restart at RI=2",
        bundles=(
            # Architectural RI=2 must suppress both poison producers while
            # still admitting the terminal B-slot branch into direct TCG.
            Bundle(0x10, 0x11,
                   cmp_rr(6, 7, 0, 0, "eq"),
                   adds(5, 1, 0),
                   br_cond(0x10, 0x30)),
            spin_bundle(0x20),
            spin_bundle(0x30),
        ),
        terminal_ip=0x30,
    )


def typed_long_branch_ri_restart_program() -> Program:
    l_slot, x_slot = brl_cond(0x10, 0x30)
    return Program(
        name="typed X3 restart at RI=1",
        bundles=(
            # RI=1 names the logical L/X instruction.  The M-slot compare is
            # poison: replaying it would make p6 true and p7 false.
            Bundle(0x10, 0x05,
                   cmp_rr(6, 7, 0, 0, "eq"), l_slot, x_slot),
            spin_bundle(0x20),
            spin_bundle(0x30),
        ),
        terminal_ip=0x30,
    )


def _exception_vector_spin(vector: int) -> Bundle:
    return Bundle(
        vector,
        0x11,
        nop_m(),
        nop_i(),
        br_cond(vector, vector),
    )


def _illegal_vector_spin() -> Bundle:
    return _exception_vector_spin(IA64_GENERAL_EXCEPTION_VECTOR)


def _interruption_collection_setup() -> Tuple[Bundle, Bundle]:
    # CR.IIP/ISR/IIPA/IPSR are architecturally collected only with PSR.ic=1.
    # Serialize the explicit SSM before entering the typed group under test.
    return (
        Bundle(0x10, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
        Bundle(0x20, 0x01, srlz_i(), nop_i(), nop_i()),
    )


def invalid_alloc_plan_boundary_program(spans_next_bundle: bool) -> Program:
    """Make a statically faulting alloc terminate a typed rewrite plan."""
    fault_ip = 0x30
    fault = alloc(34, 1, 1, 0)
    bundles: List[Bundle] = [*_interruption_collection_setup()]

    # With SOF=1 only r32 is in-frame; alloc r34 must raise Illegal Operation.
    # The one-bundle form used to leave two planned suffix instructions behind
    # (rewrite_plan_index != rewrite_plan_emit_count).  The no-stop form also
    # made preflight look through the following bundle, so lowering's precise
    # fault exit contradicted rewrite_region_bundles_left.
    bundles.append(
        Bundle(fault_ip, 0x00 if spans_next_bundle else 0x01,
               fault, adds(20, 77, 0), nop_i())
    )
    if spans_next_bundle:
        bundles.append(
            Bundle(0x40, 0x01, nop_m(), adds(21, 88, 0), nop_i())
        )
    bundles.append(_illegal_vector_spin())
    return Program(
        name="invalid alloc {} rewrite plan".format(
            "multi-bundle" if spans_next_bundle else "single-bundle"
        ),
        bundles=tuple(bundles),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
    )


def psr_ic_illegal_program(name: str, transition_boundary: int) -> Program:
    """Raise Illegal Operation after an explicit IC transition boundary."""
    accepted = (srlz_d(), srlz_i(), sync_i())
    if transition_boundary not in accepted:
        raise ValueError("unsupported PSR.ic transition boundary")

    fault = cmp_rr(12, 12, 0, 0, "eq")
    bundles: List[Bundle] = [
        Bundle(0x10, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
    ]
    bundles.append(
        Bundle(0x20, 0x01, transition_boundary, nop_i(), nop_i())
    )
    fault_ip = 0x30
    bundles.extend((
        Bundle(fault_ip, 0x01, nop_m(), fault, nop_i()),
        _illegal_vector_spin(),
    ))
    return Program(
        name=name,
        bundles=tuple(bundles),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
    )


def psr_ic_data_tlb_program(name: str, transition_boundary: int,
                            expected_vector: int) -> Program:
    """Raise a translated data miss with visible IC=0.

    The initial srlz.i establishes IC=1/clear-inflight with data translation
    enabled.  RSM(IC) then creates visible IC=0/inflight, and the supplied
    boundary either preserves or serializes that transition before ld8.fill.
    Instruction translation remains disabled, so the physical vector stub is
    reachable after the translated data access misses.
    """
    if transition_boundary not in (srlz_d(), sync_i()):
        raise ValueError("data-TLB boundary must be srlz.d or sync.i")
    if expected_vector not in (
            IA64_ALTERNATE_DATA_TLB_VECTOR,
            IA64_DATA_NESTED_TLB_VECTOR):
        raise ValueError("unexpected data-TLB vector")

    return Program(
        name=name,
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(9, 0x1000, 0), nop_i()),
            Bundle(0x20, 0x01, ssm(IA64_PSR_IC | IA64_PSR_DT),
                   nop_i(), nop_i()),
            Bundle(0x30, 0x01, srlz_i(), nop_i(), nop_i()),
            Bundle(0x40, 0x01, rsm(IA64_PSR_IC), nop_i(), nop_i()),
            Bundle(0x50, 0x01, transition_boundary, nop_i(), nop_i()),
            Bundle(0x60, 0x01, ld8_fill(10, 9), nop_i(), nop_i()),
            _exception_vector_spin(expected_vector),
        ),
        terminal_ip=expected_vector,
    )


def psr_ic_immediate_fault_program() -> Program:
    return Program(
        name="fault immediately after IC toggle",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(9, 0xFFF, 0), nop_i()),
            # MMI: the unaligned load is the instruction immediately after
            # SSM; all earlier successful instructions had pre-execution IC=0.
            Bundle(0x20, 0x09, ssm(IA64_PSR_IC), ld8_fill(10, 9), nop_i()),
            _exception_vector_spin(IA64_UNALIGNED_DATA_REFERENCE_VECTOR),
        ),
        terminal_ip=IA64_UNALIGNED_DATA_REFERENCE_VECTOR,
    )


def psr_ic_rfi_serialization_program() -> Program:
    first_fault = cmp_rr(11, 11, 0, 0, "eq", qp=1)
    second_fault = cmp_rr(12, 12, 0, 0, "eq")
    return Program(
        name="RFI implicitly serializes an IC transition",
        bundles=(
            Bundle(0x10, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
            Bundle(0x20, 0x01, srlz_i(), nop_i(), nop_i()),
            # p1 selects the first-entry handler path; p2 is its complement.
            Bundle(0x30, 0x03, nop_m(),
                   cmp_rr(1, 2, 0, 0, "eq"), nop_i()),
            # The slot-0 increment commits before the slot-1 fault.  RFI must
            # restore IPSR.ri=1; losing RI would replay slot 0 and increment
            # r8 a second time before the now-nullified fault.
            Bundle(0x40, 0x01, adds(8, 1, 8), first_fault, nop_i()),
            Bundle(0x50, 0x01, nop_m(), second_fault, nop_i()),
            # First entry (p1=true) branches to a path that clears p1, toggles
            # IC from the delivery state, and executes RFI.  On return the
            # first fault is nullified; the second fault re-enters with p1
            # false and falls through to the terminal spin.
            Bundle(0x5400, 0x11, nop_m(), nop_i(),
                   br_cond(0x5400, 0x5420, qp=1)),
            Bundle(0x5410, 0x11, nop_m(), nop_i(),
                   br_cond(0x5410, 0x5410)),
            Bundle(0x5420, 0x03, nop_m(),
                   cmp_rr(1, 2, 0, 0, "lt"), nop_i()),
            Bundle(0x5430, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
            Bundle(0x5440, 0x11, nop_m(), nop_i(), rfi()),
        ),
        terminal_ip=0x5410,
    )


def psr_ic_migration_program() -> Program:
    return Program(
        name="in-flight PSR.ic migration",
        bundles=(
            Bundle(0x10, 0x01, ssm(IA64_PSR_IC),
                   adds(9, 0xFFF, 0), nop_i()),
            Bundle(0x20, 0x01, sync_i(), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8_fill(10, 9), nop_i(), nop_i()),
            _exception_vector_spin(IA64_UNALIGNED_DATA_REFERENCE_VECTOR),
        ),
        terminal_ip=IA64_UNALIGNED_DATA_REFERENCE_VECTOR,
    )


def equal_target_predicated_off_program() -> Program:
    return Program(
        name="normal equal-target compare with false qp",
        bundles=(
            *_interruption_collection_setup(),
            # Seed p10=true and p11=false in a completed group.
            Bundle(0x30, 0x03, nop_m(),
                   cmp_rr(10, 11, 0, 0, "eq"), nop_i()),
            # If the equal-target compare executes instead of being nullified,
            # its true result would try to clear p10 through its p2 write.
            Bundle(0x40, 0x01, nop_m(),
                   cmp_rr(10, 10, 0, 0, "eq", qp=11),
                   adds(22, 0x55, 0)),
            Bundle(0x50, 0x11, nop_m(), nop_i(), br_cond(0x50, 0x50)),
            _illegal_vector_spin(),
        ),
        terminal_ip=0x50,
    )


def equal_target_prefix_fault_program() -> Program:
    fault = cmp_rr(12, 12, 0, 0, "eq")
    return Program(
        name="normal equal-target precise prefix fault",
        bundles=(
            *_interruption_collection_setup(),
            # Preserve a true destination across the faulting instruction.
            Bundle(0x30, 0x03, nop_m(),
                   cmp_rr(12, 13, 0, 0, "eq"), nop_i()),
            # This group deliberately spans bundles.  Both the PR write and
            # GR write precede the fault and therefore must become visible.
            Bundle(0x40, 0x00, nop_m(),
                   cmp_rr(1, 2, 0, 0, "eq"), adds(20, 77, 0)),
            # Slot 2 is later in the same group and must not execute.
            Bundle(0x50, 0x01, nop_m(), fault, adds(21, 88, 0)),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
    )


def equal_target_unc_nat_fault_program() -> Program:
    data_value = 0x123456789abcdef0
    fault = cmp_rr(14, 14, 4, 4, "eq", unc=True, qp=15)
    return Program(
        name="unconditional equal-target false-qp NaT-source fault",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(2, 1, 0),
                   adds(3, 0x1000, 0)),
            Bundle(0x20, 0x01, mov_m_grar(36, 2), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8_fill(4, 3), nop_i(), nop_i()),
            # Seed p14=true and p15=false before the .unc instruction.
            Bundle(0x40, 0x03, nop_m(),
                   cmp_rr(14, 15, 0, 0, "eq"), nop_i()),
            Bundle(0x50, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
            Bundle(0x60, 0x01, srlz_i(), nop_i(), nop_i()),
            # The Illegal Operation check has priority over reading the NaT
            # source, and happens before cmp.unc can clear p14.
            Bundle(0x70, 0x01, nop_m(), adds(23, 66, 0), fault),
            Bundle(0x80, 0x01, nop_m(), adds(24, 99, 0), nop_i()),
            Bundle(0x90, 0x11, nop_m(), nop_i(), br_cond(0x90, 0x90)),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
        data=(DataWord(0x1000, data_value, 8),),
    )


def equal_target_old_true_alias_program() -> Program:
    fault = cmp_rr(9, 9, 0, 0, "eq", qp=9)
    return Program(
        name="normal equal-target old-true qp alias fault",
        bundles=(
            # p9 is simultaneously the old-true qualifier and both targets.
            Bundle(0x10, 0x03, nop_m(),
                   cmp_rr(9, 10, 0, 0, "eq"), nop_i()),
            # Leave PSR.ic clear in this case to verify ISR.ni without
            # treating the interruption-collection CRs as defined outputs.
            Bundle(0x20, 0x01, nop_m(), fault, adds(26, 111, 0)),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
    )


def merge_equal_target_fault_program() -> Program:
    fault = cmp_merge_rr(10, 10, 0, 0, "and", "eq")
    return Program(
        name="qualified parallel equal-target compare fault",
        bundles=(
            *_interruption_collection_setup(),
            # Slot 1 retires before the qualified slot-2 fault.  No predicate
            # write belongs to the faulting equal-target instruction.
            Bundle(0x30, 0x01, nop_m(), adds(20, 77, 0), fault),
            Bundle(0x40, 0x01, nop_m(), adds(21, 88, 0), nop_i()),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
    )


def merge_equal_target_predicated_off_program() -> Program:
    compare = cmp_merge_rr(10, 10, 0, 0, "or", "eq", qp=11)
    return Program(
        name="false-qp parallel equal-target compare",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(1, 1 << 10, 0), nop_i()),
            Bundle(0x20, 0x01, nop_m(), mov_grpr(1, 0xfffe), nop_i()),
            # p11 is false.  Equal-target legality is therefore not tested,
            # p10 remains set, and the following slot executes normally.
            Bundle(0x30, 0x01, nop_m(), compare, adds(22, 0x55, 0)),
            Bundle(0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ),
        terminal_ip=0x40,
    )


def a7_equal_target_fault_program() -> Program:
    fault = cmp_merge_zero(10, 10, 0, "and", "gt")
    return Program(
        name="qualified A7 equal-target compare fault",
        bundles=(
            *_interruption_collection_setup(),
            Bundle(0x30, 0x01, nop_m(), adds(20, 77, 0), fault),
            Bundle(0x40, 0x01, nop_m(), adds(21, 88, 0), nop_i()),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
    )


def a8_cmp4_equal_target_fault_program() -> Program:
    fault = cmp_imm(12, 12, -1, 0, "eq", width=4)
    return Program(
        name="qualified A8 cmp4 equal-target compare fault",
        bundles=(
            *_interruption_collection_setup(),
            Bundle(0x30, 0x01, nop_m(), adds(23, 91, 0), fault),
            Bundle(0x40, 0x01, nop_m(), adds(24, 92, 0), nop_i()),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
    )


def a8_cmp4_equal_target_predicated_off_program() -> Program:
    compare = cmp_imm(12, 12, -1, 0, "eq", width=4, qp=13)
    return Program(
        name="false-qp A8 cmp4 equal-target compare",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(1, 1 << 12, 0), nop_i()),
            Bundle(0x20, 0x01, nop_m(), mov_grpr(1, 0xfffe), nop_i()),
            # p13 is false, so equal-target legality is not tested and the
            # following slot must execute without changing p12.
            Bundle(0x30, 0x01, nop_m(), compare, adds(22, 0x55, 0)),
            Bundle(0x40, 0x11, nop_m(), nop_i(), br_cond(0x40, 0x40)),
        ),
        terminal_ip=0x40,
    )


def predicate_test_equal_target_alias_fault_program() -> Program:
    data_value = 0x123456789abcdef0
    fault = predicate_test(
        "tbit", 10, 10, relation="z", update="normal",
        r3=11, immediate=0, qp=10,
    )
    return Program(
        name="predicate-test equal-target old-true qualifier fault",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, 0x1000, 0)),
            Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8_fill(11, 9), nop_i(), nop_i()),
            Bundle(0x40, 0x03, nop_m(),
                   cmp_rr(10, 11, 0, 0, "eq"), nop_i()),
            Bundle(0x50, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
            Bundle(0x60, 0x01, srlz_i(), nop_i(), nop_i()),
            Bundle(0x70, 0x01, nop_m(), adds(20, 77, 0), fault),
            Bundle(0x80, 0x01, nop_m(), adds(21, 88, 0), nop_i()),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
        data=(DataWord(0x1000, data_value, 8),),
    )


def predicate_test_equal_target_predicated_off_program() -> Program:
    data_value = 0x123456789abcdef0
    test = predicate_test(
        "tbit", 10, 10, relation="z", update="normal",
        r3=11, immediate=0, qp=5,
    )
    return Program(
        name="predicate-test equal target with false qp",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, 0x1000, 0)),
            Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8_fill(11, 9), nop_i(), nop_i()),
            Bundle(0x40, 0x01, nop_m(), adds(12, 1 << 10, 0), nop_i()),
            Bundle(0x50, 0x01, nop_m(), mov_grpr(12, 0xfffe), nop_i()),
            Bundle(0x60, 0x01, nop_m(), test, adds(22, 0x55, 0)),
            spin_bundle(0x70),
            _illegal_vector_spin(),
        ),
        terminal_ip=0x70,
        data=(DataWord(0x1000, data_value, 8),),
    )


def predicate_test_equal_target_unc_fault_program() -> Program:
    data_value = 0x123456789abcdef0
    fault = predicate_test(
        "tbit", 10, 10, relation="z", update="normal",
        r3=11, immediate=0, unc=True, qp=5,
    )
    return Program(
        name="predicate-test equal-target false-qp unconditional fault",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(8, 1, 0),
                   adds(9, 0x1000, 0)),
            Bundle(0x20, 0x01, mov_m_grar(36, 8), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8_fill(11, 9), nop_i(), nop_i()),
            Bundle(0x40, 0x01, nop_m(), adds(12, 1 << 10, 0), nop_i()),
            Bundle(0x50, 0x01, nop_m(), mov_grpr(12, 0xfffe), nop_i()),
            Bundle(0x60, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
            Bundle(0x70, 0x01, srlz_i(), nop_i(), nop_i()),
            Bundle(0x80, 0x01, nop_m(), adds(23, 66, 0), fault),
            Bundle(0x90, 0x01, nop_m(), adds(24, 99, 0), nop_i()),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
        data=(DataWord(0x1000, data_value, 8),),
    )


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _connect_gdb(process: subprocess.Popen, port: int) -> socket.socket:
    deadline = time.monotonic() + MONITOR_CONNECT_TIMEOUT
    last_error: Optional[OSError] = None

    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise HarnessError(
                "QEMU exited before its GDB stub became available "
                "(status {})".format(process.returncode)
            )
        try:
            return socket.create_connection(
                ("127.0.0.1", port), timeout=0.2
            )
        except OSError as exc:
            last_error = exc
            time.sleep(0.025)

    raise HarnessError("could not connect to QEMU GDB stub: {}".format(
        last_error
    ))


def _gdb_rsp_send(gdb: socket.socket, payload: str) -> None:
    encoded = payload.encode("ascii")
    packet = b"$" + encoded + b"#" + (
        "{:02x}".format(sum(encoded) & 0xff).encode("ascii")
    )
    gdb.sendall(packet)
    gdb.settimeout(MONITOR_CONNECT_TIMEOUT)
    acknowledgement = gdb.recv(1)
    if acknowledgement != b"+":
        raise HarnessError(
            "GDB stub did not acknowledge {!r}: {!r}".format(
                payload, acknowledgement
            )
        )


def _gdb_rsp_receive(gdb: socket.socket,
                     timeout: float = MONITOR_CONNECT_TIMEOUT) -> str:
    gdb.settimeout(timeout)
    while True:
        byte = gdb.recv(1)
        if not byte:
            raise HarnessError("GDB stub closed before returning a packet")
        if byte == b"$":
            break

    payload = bytearray()
    while True:
        byte = gdb.recv(1)
        if not byte:
            raise HarnessError("GDB stub closed inside a packet")
        if byte == b"#":
            break
        payload.extend(byte)
    checksum_text = gdb.recv(2)
    try:
        expected_checksum = int(checksum_text, 16)
    except ValueError as exc:
        raise HarnessError(
            "GDB stub returned an invalid checksum {!r}".format(
                checksum_text
            )
        ) from exc
    actual_checksum = sum(payload) & 0xff
    if actual_checksum != expected_checksum:
        gdb.sendall(b"-")
        raise HarnessError(
            "GDB response checksum mismatch: expected 0x{:02x}, "
            "got 0x{:02x}".format(expected_checksum, actual_checksum)
        )
    gdb.sendall(b"+")
    return payload.decode("ascii", errors="replace")


def _gdb_rsp_command(gdb: socket.socket, payload: str,
                     timeout: float = MONITOR_CONNECT_TIMEOUT) -> str:
    _gdb_rsp_send(gdb, payload)
    return _gdb_rsp_receive(gdb, timeout)


def _gdb_write_u64(gdb: socket.socket, register: int, value: int) -> None:
    encoded = (value & ((1 << 64) - 1)).to_bytes(8, "little").hex()
    response = _gdb_rsp_command(gdb, "P{:x}={}".format(register, encoded))
    if response != "OK":
        raise HarnessError(
            "GDB stub rejected register {} write: {}".format(
                register, response
            )
        )


def _recv_hmp_prompt(monitor: socket.socket,
                     timeout: float = MONITOR_CONNECT_TIMEOUT) -> str:
    deadline = time.monotonic() + timeout
    response = bytearray()

    while not bytes(response).rstrip().endswith(b"(qemu)"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HarnessError("timed out waiting for the HMP prompt")
        monitor.settimeout(remaining)
        try:
            chunk = monitor.recv(8192)
        except socket.timeout as exc:
            raise HarnessError("timed out waiting for the HMP prompt") from exc
        if not chunk:
            raise HarnessError("HMP monitor closed before returning a prompt")
        response.extend(chunk)
        if len(response) > 2 * 1024 * 1024:
            raise HarnessError("HMP response exceeded two MiB")

    return response.decode("utf-8", errors="replace").replace("\r", "")


def _hmp_command(monitor: socket.socket, command: str) -> str:
    monitor.sendall((command + "\n").encode("ascii"))
    return _recv_hmp_prompt(monitor)


def _required_match(pattern: str, output: str, description: str) -> re.Match:
    match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
    if match is None:
        raise HarnessError(
            "could not parse {} from HMP info registers:\n{}".format(
                description, output
            )
        )
    return match


def parse_snapshot(output: str) -> Snapshot:
    ip_match = _required_match(r"^IP\s+([0-9a-f]+)\s*$", output, "IP")
    header = _required_match(
        r"^PSR\s+([0-9a-f]+)\s+PR\s+([0-9a-f]+)\s+"
        r"CFM\s+([0-9a-f]+)\s*$",
        output,
        "PSR/PR/CFM",
    )
    psr_ic = _required_match(
        r"^PSR\.IC-INFLIGHT\s+([01])\s*$",
        output,
        "PSR.ic in-flight state",
    )
    rse = _required_match(
        r"^RSE\s+RSC\s+([0-9a-f]+)\s+BSP\s+([0-9a-f]+)\s+"
        r"BSPSTORE\s+([0-9a-f]+)\s+BSPLOAD\s+([0-9a-f]+)\s+"
        r"RNAT\s+([0-9a-f]+)\s+BASE\s+([0-9]+)\s*$",
        output,
        "RSE state",
    )
    nat = _required_match(
        r"^NaT\s+([0-9a-f]+):([0-9a-f]+)\s+UNAT\s+([0-9a-f]+)\s+"
        r"RNAT\s+([0-9a-f]+)\s*$",
        output,
        "NaT state",
    )
    control = _required_match(
        r"^CR\.IVA\s+([0-9a-f]+)\s+CR\.IIP\s+([0-9a-f]+)\s+"
        r"CR\.ISR\s+([0-9a-f]+)\s+CR\.IFA\s+([0-9a-f]+)\s+"
        r"CR\.IIPA\s+([0-9a-f]+)\s+CR\.IPSR\s+([0-9a-f]+)\s*$",
        output,
        "control-register state",
    )
    exception = _required_match(
        r"^EXC\s+PENDING\s+([01])\s+KIND\s+([a-z0-9-]+)\s+"
        r"VECTOR\s+([0-9a-f]+)\s+SOURCE\s+([0-9a-f]+)\s+"
        r"ADDRESS\s+([0-9a-f]+)\s*$",
        output,
        "exception record",
    )
    slot = _required_match(
        r"^SLOT\s+VALID\s+([01])\s+IP\s+([0-9a-f]+)\s+"
        r"RI\s+([0-2])\s+TYPE\s+([0-9]+)\s+RAW\s+([0-9a-f]+)\s*$",
        output,
        "current-slot state",
    )

    gr_values: Dict[int, int] = {}
    for number, value in re.findall(
        r"\br([0-9]+)\s+([0-9a-f]{16})", output, re.IGNORECASE
    ):
        gr_values[int(number)] = int(value, 16)
    br_values: Dict[int, int] = {}
    for number, value in re.findall(
        r"\bb([0-9]+)\s+([0-9a-f]{16})", output, re.IGNORECASE
    ):
        br_values[int(number)] = int(value, 16)

    missing_gr = [reg for reg in range(128) if reg not in gr_values]
    missing_br = [reg for reg in range(8) if reg not in br_values]
    if missing_gr or missing_br:
        raise HarnessError(
            "incomplete HMP register dump: missing GRs {!r}, BRs {!r}".format(
                missing_gr, missing_br
            )
        )

    return Snapshot(
        ip=int(ip_match.group(1), 16),
        psr=int(header.group(1), 16),
        psr_ic_inflight=bool(int(psr_ic.group(1), 10)),
        pr=int(header.group(2), 16),
        cfm=int(header.group(3), 16),
        rse_rsc=int(rse.group(1), 16),
        rse_bsp=int(rse.group(2), 16),
        rse_bspstore=int(rse.group(3), 16),
        rse_bspload=int(rse.group(4), 16),
        rse_rnat=int(rse.group(5), 16),
        rse_base=int(rse.group(6), 10),
        nat_high=int(nat.group(1), 16),
        nat_low=int(nat.group(2), 16),
        unat=int(nat.group(3), 16),
        nat_rnat=int(nat.group(4), 16),
        cr_iva=int(control.group(1), 16),
        cr_iip=int(control.group(2), 16),
        cr_isr=int(control.group(3), 16),
        cr_ifa=int(control.group(4), 16),
        cr_iipa=int(control.group(5), 16),
        cr_ipsr=int(control.group(6), 16),
        exception_pending=bool(int(exception.group(1), 10)),
        exception_kind=exception.group(2).lower(),
        exception_vector=int(exception.group(3), 16),
        exception_source=int(exception.group(4), 16),
        exception_address=int(exception.group(5), 16),
        slot_valid=bool(int(slot.group(1), 10)),
        slot_ip=int(slot.group(2), 16),
        slot_ri=int(slot.group(3), 10),
        slot_type=int(slot.group(4), 10),
        slot_raw=int(slot.group(5), 16),
        gr=tuple(gr_values[reg] for reg in range(128)),
        br=tuple(br_values[reg] for reg in range(8)),
    )


def _loader_arguments(program: Program) -> List[str]:
    arguments: List[str] = []
    for bundle in program.bundles:
        low, high = bundle_words(bundle)
        arguments.extend(
            [
                "-device",
                "loader,data=0x{:016x},data-len=8,addr=0x{:x}".format(
                    low, bundle.address
                ),
                "-device",
                "loader,data=0x{:016x},data-len=8,addr=0x{:x}".format(
                    high, bundle.address + 8
                ),
            ]
        )
    for word in program.data:
        if word.size < 1 or word.size > 8:
            raise ValueError("generic loader data length must be from 1 to 8")
        arguments.extend(
            [
                "-device",
                "loader,data=0x{:x},data-len={},addr=0x{:x}".format(
                    word.value, word.size, word.address
                ),
            ]
        )
    arguments.extend(
        ["-device", "loader,addr=0x{:x},cpu-num=0".format(program.entry)]
    )
    return arguments


def _child_environment(state_cache: bool = False) -> Dict[str, str]:
    environment = os.environ.copy()
    # Strip inherited debug/performance knobs so every case starts from the
    # production typed translator configuration.
    for name in list(environment):
        if name.startswith("VIBTANIUM_"):
            del environment[name]
    if state_cache:
        environment.update(
            {
                "VIBTANIUM_TCG_STATE_CACHE": "1",
                "VIBTANIUM_TCG_STATE_CACHE_MIN_BUNDLES": "0",
                "VIBTANIUM_TCG_STATE_CACHE_GRS": "8",
            }
        )
    return environment


def _connect_monitor(process: subprocess.Popen, port: int) -> socket.socket:
    deadline = time.monotonic() + MONITOR_CONNECT_TIMEOUT
    last_error: Optional[OSError] = None

    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise HarnessError(
                "QEMU exited before its HMP monitor became available "
                "(status {})".format(process.returncode)
            )
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=0.2)
        except OSError as exc:
            last_error = exc
            time.sleep(0.025)

    raise HarnessError("could not connect to QEMU HMP monitor: {}".format(
        last_error
    ))


def _terminate_child(process: subprocess.Popen) -> str:
    if process.poll() is None:
        process.terminate()
    try:
        output, _ = process.communicate(timeout=PROCESS_EXIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        process.kill()
        output, _ = process.communicate(timeout=PROCESS_EXIT_TIMEOUT)
    return output or ""


def _tcg_op_sections(trace: str, bundle_ip: int) -> List[str]:
    marker = re.compile(r"(?m)^ ---- ([0-9a-fA-F]{16})\b")
    matches = list(marker.finditer(trace))
    sections: List[str] = []
    for index, match in enumerate(matches):
        if int(match.group(1), 16) != bundle_ip:
            continue
        finish = (
            matches[index + 1].start()
            if index + 1 < len(matches) else len(trace)
        )
        sections.append(trace[match.start():finish])
    if not sections:
        raise HarnessError(
            "TCG op trace has no translated bundle at 0x{:x}".format(bundle_ip)
        )
    return sections


def _require_typed_fault_trace(trace: str, bundle_ip: int) -> None:
    """Prove that the tested bundle received typed fault lowering.

    QEMU's deterministic ``-d op`` dump places every guest bundle under a
    ``---- <ip>`` marker.  An equal-target A6 compare contains the direct
    Illegal Operation helper and no generic raw-dispatch call.
    """
    for section in _tcg_op_sections(trace, bundle_ip):
        if not re.search(r"(?m)^\s*call raise_illegal_operation,", section):
            raise HarnessError(
                "bundle 0x{:x} lacks typed Illegal Operation lowering in "
                "the TCG op trace".format(bundle_ip)
            )
        if re.search(r"(?m)^\s*call (?:exec_bundle|exec_slot),", section):
            raise HarnessError(
                "bundle 0x{:x} reached a generic execution helper in the "
                "TCG op trace".format(bundle_ip)
            )


def _require_typed_nat_fault_trace(trace: str, bundle_ip: int) -> None:
    """Require dedicated direct lowering for Register NaT Consumption."""
    for section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "bundle 0x{:x} lacks the typed-owner insn_start marker"
                .format(bundle_ip)
            )
        if not re.search(
                r"(?m)^\s*call raise_register_nat_consumption,", section):
            raise HarnessError(
                "bundle 0x{:x} lacks the dedicated Register NaT "
                "Consumption helper in the TCG op trace".format(bundle_ip)
            )
        if re.search(r"(?m)^\s*call (?:exec_bundle|exec_slot),", section):
            raise HarnessError(
                "bundle 0x{:x} reached a generic execution helper in the "
                "TCG op trace".format(bundle_ip)
            )


def _require_typed_direct_trace(trace: str, bundle_ip: int) -> None:
    """Reject generic raw dispatch for a successful typed bundle."""
    for section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "bundle 0x{:x} lacks the typed-owner insn_start marker"
                .format(bundle_ip)
            )
        if re.search(r"(?m)^\s*call (?:exec_bundle|exec_slot),", section):
            raise HarnessError(
                "bundle 0x{:x} reached a generic execution helper in the "
                "TCG op trace".format(bundle_ip)
            )
        if not re.search(r"(?m)^\s*(?:add|mov|movi)_i64\b", section):
            raise HarnessError(
                "bundle 0x{:x} lacks direct scalar TCG operations".format(
                    bundle_ip
                )
            )


def _require_typed_branch_trace(trace: str, bundle_ip: int, target: int,
                                fallthrough: Optional[int]) -> None:
    """Require a typed branch split with exact direct exit constants."""
    for section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "branch bundle 0x{:x} lacks the typed-owner marker".format(
                    bundle_ip
                )
            )
        forbidden = re.search(
            r"(?m)^\s*call (?:exec_bundle|exec_slot|"
            r"finish_direct_branch_bundle|finish_indirect_branch_bundle),",
            section,
        )
        if forbidden is not None:
            raise HarnessError(
                "branch bundle 0x{:x} used a generic helper: {}".format(
                    bundle_ip, forbidden.group(0).strip()
                )
            )
        if fallthrough is not None and not re.search(
                r"(?m)^\s*brcond_i64\b", section):
            raise HarnessError(
                "conditional branch bundle 0x{:x} lacks a TCG predicate "
                "split".format(bundle_ip)
            )
        destinations = (target,) if fallthrough is None else (
            target, fallthrough
        )
        for destination in destinations:
            if not re.search(
                    r"(?m)^\s*mov_i64\s+ip,\$0x{:x}\s*$".format(
                        destination
                    ), section):
                raise HarnessError(
                    "branch bundle 0x{:x} lacks exact exit IP 0x{:x}"
                    .format(bundle_ip, destination)
                )
        if not re.search(
                r"(?m)^\s*(?:goto_tb|goto_ptr|lookup_and_goto_ptr)\b",
                section):
            raise HarnessError(
                "branch bundle 0x{:x} lacks a direct chained/lookup exit"
                .format(bundle_ip)
            )


def _require_typed_indirect_trace(trace: str, bundle_ip: int,
                                  minimum_branches: int,
                                  minimum_predicate_splits: int) -> None:
    """Require helper-free dynamic-target CFG lowering for one bundle."""
    for section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "indirect branch bundle 0x{:x} lacks the typed-owner marker"
                .format(bundle_ip)
            )
        forbidden = re.search(
            r"(?m)^\s*call (?:exec_bundle(?:_lookup_ptr)?|exec_slot|"
            r"finish_direct_branch_bundle|"
            r"finish_indirect_branch_bundle),",
            section,
        )
        if forbidden is not None:
            raise HarnessError(
                "indirect branch bundle 0x{:x} used generic helper: {}"
                .format(bundle_ip, forbidden.group(0).strip())
            )

        alignments = re.findall(
            r"(?m)^\s*and_i64\s+[^,\s]+,[^,\s]+,"
            r"\$0xfffffffffffffff0\s*$",
            section,
        )
        if len(alignments) < minimum_branches:
            raise HarnessError(
                "indirect branch bundle 0x{:x} has {} target-alignment "
                "operations, expected at least {}".format(
                    bundle_ip, len(alignments), minimum_branches
                )
            )
        splits = re.findall(r"(?m)^\s*brcond_i64\b", section)
        if len(splits) < minimum_predicate_splits:
            raise HarnessError(
                "indirect branch bundle 0x{:x} has {} predicate/CFG "
                "splits, expected at least {}".format(
                    bundle_ip, len(splits), minimum_predicate_splits
                )
            )
        if not re.search(r"(?m)^\s*mov_i64\s+ip,", section):
            raise HarnessError(
                "indirect branch bundle 0x{:x} never commits a dynamic IP"
                .format(bundle_ip)
            )
        exits = re.findall(
            r"(?m)^\s*(?:goto_ptr|lookup_and_goto_ptr)\b", section
        )
        if len(exits) < minimum_branches:
            raise HarnessError(
                "indirect branch bundle 0x{:x} has {} dynamic exits, "
                "expected at least {}".format(
                    bundle_ip, len(exits), minimum_branches
                )
            )


def _require_typed_loop_trace(trace: str, bundle_ip: int, target: int,
                              expect_rotation_helper: bool) -> None:
    """Require direct loop arithmetic plus only the focused rotation helper."""
    for trace_section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            trace_section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "loop branch bundle 0x{:x} lacks the typed-owner marker"
                .format(bundle_ip)
            )

        forbidden = re.search(
            r"(?m)^\s*call (?:exec_bundle(?:_lookup_ptr)?|exec_slot|"
            r"finish_direct_branch_bundle|finish_indirect_branch_bundle|"
            r"loop_counted_update|loop_while_update|"
            r"rse_sync_logical_in|rse_sync_logical_out),",
            trace_section,
        )
        if forbidden is not None:
            raise HarnessError(
                "loop branch bundle 0x{:x} used a generic/full-sync "
                "helper: {}".format(
                    bundle_ip, forbidden.group(0).strip()
                )
            )

        rotations = re.findall(
            r"(?m)^\s*call rotate_modulo_registers,", trace_section
        )
        expected_rotations = 1 if expect_rotation_helper else 0
        if len(rotations) != expected_rotations:
            raise HarnessError(
                "loop branch bundle 0x{:x} has {} focused rotation helper "
                "calls, expected {}".format(
                    bundle_ip, len(rotations), expected_rotations
                )
            )

        # These are structural IR assertions, independent of which runtime
        # truth-table arm this particular invocation follows.  LC/EC updates,
        # loop activity, and the conditional rotation guard all stay in TCG.
        if not re.search(r"(?m)^\s*brcond_i64\b", trace_section):
            raise HarnessError(
                "loop branch bundle 0x{:x} lacks a direct TCG control split"
                .format(bundle_ip)
            )
        if not re.search(r"(?m)^\s*ld_i64\b", trace_section):
            raise HarnessError(
                "loop branch bundle 0x{:x} lacks a direct LC/EC load"
                .format(bundle_ip)
            )
        decrement = re.search(
            r"(?m)^\s*(?:"
            r"sub_i64\s+[^,\s]+,[^,\s]+,\$0x0*1|"
            r"add_i64\s+[^,\s]+,[^,\s]+,"
            r"\$0xffffffffffffffff)\s*$",
            trace_section,
        )
        if decrement is None:
            raise HarnessError(
                "loop branch bundle 0x{:x} lacks a direct counter decrement"
                .format(bundle_ip)
            )
        if not re.search(r"(?m)^\s*st_i64\b", trace_section):
            raise HarnessError(
                "loop branch bundle 0x{:x} lacks a direct counter/PR store"
                .format(bundle_ip)
            )
        if not re.search(
                r"(?m)^\s*mov_i64\s+ip,\$0x{:x}\s*$".format(target),
                trace_section):
            raise HarnessError(
                "loop branch bundle 0x{:x} lacks exact exit IP 0x{:x}"
                .format(bundle_ip, target)
            )
        if not re.search(
                r"(?m)^\s*(?:goto_tb|goto_ptr|lookup_and_goto_ptr)\b",
                trace_section):
            raise HarnessError(
                "loop branch bundle 0x{:x} lacks a direct chained/lookup "
                "exit".format(bundle_ip)
            )


def _require_typed_call_trace(trace: str, bundle_ip: int,
                              target: Optional[int], indirect: bool,
                              minimum_predicate_splits: int) -> None:
    """Require a direct-TCG call CFG with one focused frame transition.

    ``-d op`` records the generated CFG, not just the runtime-selected arm.
    Consequently a false-predicate execution still has exactly one helper
    call site in its unreachable taken arm.  Architectural sentinels in the
    semantic tests below independently prove that false arms do not execute
    that site.
    """
    link = bundle_ip + 0x10
    for trace_section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            trace_section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "call bundle 0x{:x} lacks the typed-owner marker".format(
                    bundle_ip
                )
            )

        forbidden = re.search(
            r"(?m)^\s*call (?:exec_bundle(?:_lookup_ptr)?|exec_slot|"
            r"finish_direct_branch_bundle|finish_indirect_branch_bundle|"
            r"branch_call_effects|rse_sync_logical_in|"
            r"rse_sync_logical_out),",
            trace_section,
        )
        if forbidden is not None:
            raise HarnessError(
                "call bundle 0x{:x} used a generic/full-sync helper: {}"
                .format(bundle_ip, forbidden.group(0).strip())
            )

        frame_calls = list(re.finditer(
            r"(?m)^\s*call enter_call_frame,", trace_section
        ))
        if len(frame_calls) != 1:
            raise HarnessError(
                "call bundle 0x{:x} has {} focused frame-transition sites, "
                "expected exactly one".format(bundle_ip, len(frame_calls))
            )

        splits = re.findall(r"(?m)^\s*brcond_i64\b", trace_section)
        if len(splits) < minimum_predicate_splits:
            raise HarnessError(
                "call bundle 0x{:x} has {} predicate/CFG splits, expected "
                "at least {}".format(
                    bundle_ip, len(splits), minimum_predicate_splits
                )
            )

        if not re.search(
                r"(?m)^\s*mov_i64\s+loc[0-9]+,\$0x{:x}\s*$".format(
                    link
                ), trace_section):
            raise HarnessError(
                "call bundle 0x{:x} does not materialize exact link 0x{:x}"
                .format(bundle_ip, link)
            )
        if not re.search(r"(?m)^\s*st_i64\b", trace_section):
            raise HarnessError(
                "call bundle 0x{:x} lacks a direct BR/link store".format(
                    bundle_ip
                )
            )

        helper_end = frame_calls[0].end()
        if indirect:
            if target is not None:
                raise HarnessError("indirect call trace supplied a target")
            if not re.search(
                    r"(?m)^\s*and_i64\s+[^,\s]+,[^,\s]+,"
                    r"\$0xfffffffffffffff0\s*$", trace_section):
                raise HarnessError(
                    "indirect call bundle 0x{:x} lacks low-bit target "
                    "alignment".format(bundle_ip)
                )
            taken_commit = re.search(
                r"(?m)^\s*mov_i64\s+ip,loc[0-9]+\s*$",
                trace_section[helper_end:],
            )
            if taken_commit is None:
                raise HarnessError(
                    "indirect call bundle 0x{:x} lacks a dynamic taken IP "
                    "commit after its frame transition".format(bundle_ip)
                )
        else:
            if target is None:
                raise HarnessError("direct call trace lacks an exact target")
            taken_commit = re.search(
                r"(?m)^\s*mov_i64\s+ip,\$0x{:x}\s*$".format(target),
                trace_section[helper_end:],
            )
            if taken_commit is None:
                raise HarnessError(
                    "direct call bundle 0x{:x} lacks exact taken IP 0x{:x} "
                    "after its frame transition".format(bundle_ip, target)
                )

        exit_pattern = (
            r"(?m)^\s*(?:goto_ptr|lookup_and_goto_ptr)\b" if indirect else
            r"(?m)^\s*(?:goto_tb|goto_ptr|lookup_and_goto_ptr)\b"
        )
        if not re.search(exit_pattern, trace_section[helper_end:]):
            raise HarnessError(
                "call bundle 0x{:x} lacks a taken direct/lookup exit after "
                "its frame transition".format(bundle_ip)
            )


def _require_typed_return_trace(trace: str, bundle_ip: int,
                                minimum_predicate_splits: int) -> None:
    """Require direct BR_RET selection plus its ordered focused helpers."""
    for trace_section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            trace_section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "return bundle 0x{:x} lacks the typed-owner marker".format(
                    bundle_ip
                )
            )

        forbidden = re.search(
            r"(?m)^\s*call (?:exec_bundle(?:_lookup_ptr)?|exec_slot|"
            r"finish_fast_bundle|finish_direct_branch_bundle|"
            r"finish_indirect_branch_bundle|return_from_call_frame|"
            r"rse_sync_logical_in|rse_sync_logical_out),",
            trace_section,
        )
        if forbidden is not None:
            raise HarnessError(
                "return bundle 0x{:x} used a generic/full-sync helper: {}"
                .format(bundle_ip, forbidden.group(0).strip())
            )

        helper_names = (
            "return_frame_from_pfs",
            "raise_lower_privilege_transfer_trap",
            "raise_taken_branch_trap",
            "complete_rse_frame_loads",
            "return_chain_ok",
        )
        helper_sites = []
        for name in helper_names:
            sites = list(re.finditer(
                r"(?m)^\s*call {},".format(name), trace_section
            ))
            if len(sites) != 1:
                raise HarnessError(
                    "return bundle 0x{:x} has {} {} sites, expected one"
                    .format(bundle_ip, len(sites), name)
                )
            helper_sites.append(sites[0].start())
        if helper_sites != sorted(helper_sites):
            raise HarnessError(
                "return bundle 0x{:x} does not order frame restore, LP, TB, "
                "mandatory-fill, and chain-authorization helpers".format(
                    bundle_ip
                )
            )

        frame_site = helper_sites[0]
        alignment = re.search(
            r"(?m)^\s*and_i64\s+[^,\s]+,[^,\s]+,"
            r"\$0xfffffffffffffff0\s*$",
            trace_section[:frame_site],
        )
        if alignment is None:
            raise HarnessError(
                "return bundle 0x{:x} lacks direct low-bit target alignment"
                .format(bundle_ip)
            )
        commit = re.search(
            r"(?m)^\s*mov_i64\s+ip,loc[0-9]+\s*$",
            trace_section[:frame_site],
        )
        if commit is None:
            raise HarnessError(
                "return bundle 0x{:x} does not commit its dynamic target "
                "before frame restoration".format(bundle_ip)
            )
        late_fast_finish = next((
            site for site in re.finditer(
                r"(?m)^\s*call finish_fast_tb,", trace_section
            ) if site.start() >= commit.start()
        ), None)
        if late_fast_finish is not None:
            raise HarnessError(
                "return bundle 0x{:x} polls the generic fast-TB finisher "
                "on or after its taken-arm target commit".format(bundle_ip)
            )

        selectors = re.findall(
            r"(?m)^\s*movcond_i64\b", trace_section[:frame_site]
        )
        if len(selectors) < 2:
            raise HarnessError(
                "return bundle 0x{:x} has {} live/ordinary selectors, "
                "expected BR and AR.PFS selection".format(
                    bundle_ip, len(selectors)
                )
            )
        splits = re.findall(r"(?m)^\s*brcond_i(?:32|64)\b", trace_section)
        if len(splits) < minimum_predicate_splits:
            raise HarnessError(
                "return bundle 0x{:x} has {} predicate/trap splits, "
                "expected at least {}".format(
                    bundle_ip, len(splits), minimum_predicate_splits
                )
            )

        lookup = re.search(
            r"(?m)^\s*(?:goto_ptr|lookup_and_goto_ptr)\b",
            trace_section[helper_sites[-1]:],
        )
        if lookup is None:
            raise HarnessError(
                "return bundle 0x{:x} lacks a dynamic exit after mandatory "
                "frame loads".format(bundle_ip)
            )


def _require_typed_rfi_trace(trace: str, bundle_ip: int) -> None:
    """Require direct RFI selection and its shared ordered helper chain."""
    for trace_section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            trace_section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "RFI bundle 0x{:x} lacks the typed-owner marker".format(
                    bundle_ip
                )
            )

        forbidden = re.search(
            r"(?m)^\s*call (?:exec_bundle(?:_lookup_ptr)?|exec_slot|"
            r"finish_fast_bundle|finish_direct_branch_bundle|"
            r"finish_indirect_branch_bundle|rfi_chain_ok|"
            r"rse_sync_logical_in|rse_sync_logical_out|"
            r"complete_pending_fill|schedule_pending_fill),",
            trace_section,
        )
        if forbidden is not None:
            raise HarnessError(
                "RFI bundle 0x{:x} used a forbidden generic helper: {}".format(
                    bundle_ip, forbidden.group(0).strip()
                )
            )

        restore_sites = list(re.finditer(
            r"(?m)^\s*call rfi,", trace_section
        ))
        chain_sites = list(re.finditer(
            r"(?m)^\s*call return_chain_ok,", trace_section
        ))
        if len(restore_sites) != 1 or len(chain_sites) != 1:
            raise HarnessError(
                "RFI bundle 0x{:x} has {} restore and {} chain sites; "
                "expected one of each".format(
                    bundle_ip, len(restore_sites), len(chain_sites)
                )
            )
        if restore_sites[0].start() >= chain_sites[0].start():
            raise HarnessError(
                "RFI bundle 0x{:x} authorizes chaining before restoring "
                "interruption state".format(bundle_ip)
            )

        lookup = re.search(
            r"(?m)^\s*(?:goto_ptr|lookup_and_goto_ptr)\b",
            trace_section[chain_sites[0].end():],
        )
        if lookup is None:
            raise HarnessError(
                "RFI bundle 0x{:x} lacks a dynamic exit after its shared "
                "chain check".format(bundle_ip)
            )


def _require_branch_forward_savevm_trace(source_trace: str,
                                         destination_trace: str,
                                         producer_ip: int, branch_ip: int,
                                         predicate: int) -> None:
    """Tie the restored branch selection to the serialized forward mask."""
    source = _tcg_op_sections(source_trace, producer_ip)[0]
    destination = _tcg_op_sections(destination_trace, branch_ip)[0]
    producer_marker = "{:016x}".format(producer_ip)
    branch_marker = "{:016x}".format(branch_ip)

    if re.search(r"(?m)^ ---- {}\b".format(branch_marker), source_trace):
        raise HarnessError(
            "source translated branch 0x{:x} before its savevm breakpoint"
            .format(branch_ip)
        )
    if re.search(r"(?m)^ ---- {}\b".format(producer_marker),
                 destination_trace):
        raise HarnessError(
            "destination replayed producer 0x{:x} after loadvm".format(
                producer_ip
            )
        )

    # Learn the VMState field offset from destination IR rather than copying a
    # C-structure constant into the test.  The predicate's physical mask bit
    # must gate live-vs-ordinary PR selection, and the producer must store that
    # same field before the checkpoint.
    temp = r"[A-Za-z_][A-Za-z0-9_]*"
    select = re.search(
        r"(?ms)^\s*mov_i64\s+(?P<bit>{}),\$0x{:x}\s*$\n"
        r"^\s*ld_i64\s+(?P<mask>{}),env,\$(?P<offset>0x[0-9a-f]+)\s*$\n"
        r"^\s*and_i64\s+(?P=mask),(?P=mask),(?P=bit)\s*$.*?"
        r"^\s*movcond_i64\s+{},(?P=mask),\$0x0,{},{},ne\s*$"
        .format(temp, 1 << predicate, temp, temp, temp, temp),
        destination,
    )
    if select is None:
        raise HarnessError(
            "restored branch 0x{:x} lacks an explicit p{} forward-mask "
            "live/ordinary selection".format(branch_ip, predicate)
        )
    offset = re.escape(select.group("offset"))
    if re.search(
            r"(?m)^\s*st_i64\s+{},env,\${}\s*$".format(temp, offset),
            source) is None:
        raise HarnessError(
            "producer 0x{:x} did not persist the forward-mask field loaded "
            "by restored branch 0x{:x}".format(producer_ip, branch_ip)
        )


def _require_br_shadow_savevm_trace(source_trace: str,
                                    destination_trace: str,
                                    producer_ip: int, consumer_ip: int,
                                    branch_reg: int) -> None:
    """Tie a restored ordinary BR read to saved BR state and provenance."""
    source = _tcg_op_sections(source_trace, producer_ip)[0]
    destination = _tcg_op_sections(destination_trace, consumer_ip)[0]
    producer_marker = "{:016x}".format(producer_ip)
    consumer_marker = "{:016x}".format(consumer_ip)
    bit = 1 << branch_reg

    if re.search(r"(?m)^ ---- {}\b".format(consumer_marker), source_trace):
        raise HarnessError(
            "source translated BR consumer 0x{:x} before its savevm "
            "breakpoint".format(consumer_ip)
        )
    if re.search(r"(?m)^ ---- {}\b".format(producer_marker),
                 destination_trace):
        raise HarnessError(
            "destination replayed BR producer 0x{:x} after loadvm".format(
                producer_ip
            )
        )

    temp = r"[A-Za-z_][A-Za-z0-9_]*"
    select = re.search(
        r"(?m)^\s*ld_i64\s+(?P<live>{}),env,\$0x[0-9a-f]+\s*$\n"
        r"^\s*ld_i64\s+(?P<saved>{}),env,\$"
        r"(?P<saved_offset>0x[0-9a-f]+)\s*$\n"
        r"^\s*ld8u_i64\s+(?P<mask>{}),env,\$"
        r"(?P<mask_offset>0x[0-9a-f]+)\s*$\n"
        r"^\s*and_i64\s+(?P=mask),(?P=mask),\$0x{:x}\s*$\n"
        r"^\s*movcond_i64\s+{},(?P=mask),\$0x0,(?P=saved),"
        r"(?P=live),ne\s*$".format(temp, temp, temp, bit, temp),
        destination,
    )
    if select is None:
        raise HarnessError(
            "restored ordinary b{} consumer 0x{:x} lacks an explicit "
            "saved/live selection".format(branch_reg, consumer_ip)
        )

    saved_offset = re.escape(select.group("saved_offset"))
    mask_offset = re.escape(select.group("mask_offset"))
    if re.search(
            r"(?m)^\s*st_i64\s+{},env,\${}\s*$".format(
                temp, saved_offset
            ), source) is None:
        raise HarnessError(
            "BR producer 0x{:x} did not persist saved b{} at the offset "
            "selected after loadvm".format(producer_ip, branch_reg)
        )
    if re.search(
            r"(?m)^\s*st8_i64\s+\$0x{:x},env,\${}\s*$".format(
                bit, mask_offset
            ), source) is None:
        raise HarnessError(
            "BR producer 0x{:x} did not persist saved_br_mask bit 0x{:x}"
            .format(producer_ip, bit)
        )

    # The branch-only forward mask is a separate physical byte.  Learn it
    # from the producer's clear/set/store sequence and require the restored
    # continuation to clear both migrated metadata fields when the group
    # closes.  This avoids baking CPUIA64State offsets into the test.
    forward = re.search(
        r"(?m)^\s*ld8u_i64\s+(?P<value>{}),env,\$"
        r"(?P<offset>0x[0-9a-f]+)\s*$\n"
        r"^\s*and_i64\s+(?P=value),(?P=value),\$0x{:x}\s*$\n"
        r"^\s*or_i64\s+(?P=value),(?P=value),\$0x{:x}\s*$\n"
        r"^\s*st8_i64\s+(?P=value),env,\$(?P=offset)\s*$".format(
            temp, 0xff & ~bit, bit
        ),
        source,
    )
    if forward is None:
        raise HarnessError(
            "BR producer 0x{:x} lacks explicit b{} forward-provenance "
            "update".format(producer_ip, branch_reg)
        )
    forward_offset = forward.group("offset")
    if forward_offset == select.group("mask_offset"):
        raise HarnessError(
            "saved BR validity and branch-forward provenance alias one "
            "metadata byte"
        )
    for label, offset in (
        ("saved_br_mask", select.group("mask_offset")),
        ("branch_br_forward_mask", forward_offset),
    ):
        if re.search(
                r"(?m)^\s*st8_i32\s+\$0x0,env,\${}\s*$".format(
                    re.escape(offset)
                ), destination) is None:
            raise HarnessError(
                "restored continuation did not clear migrated {} at "
                "env+{}".format(label, offset)
            )


def _require_typed_pfs_move_trace(trace: str, bundle_ip: int,
                                  require_read: bool,
                                  require_write: bool,
                                  require_overlay_select: bool,
                                  require_nat_fault_path: bool) -> None:
    """Require direct AR.PFS TCG plus only the precise NaT fault seam."""
    for trace_section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            trace_section,
        )
        if marker is None or not (int(marker.group(1), 16) & 2):
            raise HarnessError(
                "AR.PFS move bundle 0x{:x} lacks the typed-owner marker"
                .format(bundle_ip)
            )

        forbidden = re.search(
            r"(?m)^\s*call (?:exec_bundle(?:_lookup_ptr)?|exec_slot|"
            r"finish_fast_bundle|finish_direct_branch_bundle|"
            r"finish_indirect_branch_bundle|rse_sync_logical_in|"
            r"rse_sync_logical_out),",
            trace_section,
        )
        if forbidden is not None:
            raise HarnessError(
                "AR.PFS move bundle 0x{:x} used a generic helper: {}"
                .format(bundle_ip, forbidden.group(0).strip())
            )

        env_loads = re.findall(
            r"(?m)^\s*ld_i64\s+[^,\s]+,env,\$0x[0-9a-fA-F]+\s*$",
            trace_section,
        )
        env_stores = re.findall(
            r"(?m)^\s*st_i64\s+[^,\s]+,env,\$0x[0-9a-fA-F]+\s*$",
            trace_section,
        )
        if require_read and not env_loads:
            raise HarnessError(
                "AR.PFS read bundle 0x{:x} lacks a direct env load".format(
                    bundle_ip
                )
            )
        if require_write and not env_stores:
            raise HarnessError(
                "AR.PFS write bundle 0x{:x} lacks a direct env store".format(
                    bundle_ip
                )
            )

        selector = re.search(
            r"(?m)^\s*ld_i64\s+(?P<live>[^,\s]+),env,"
            r"\$0x[0-9a-fA-F]+\s*$\n"
            r"^\s*ld_i64\s+(?P<saved>[^,\s]+),env,"
            r"\$0x[0-9a-fA-F]+\s*$\n"
            r"^\s*ld8u_i64\s+(?P<valid>[^,\s]+),env,"
            r"\$0x[0-9a-fA-F]+\s*$\n"
            r"^\s*movcond_i64\s+[^,\s]+,(?P=valid),\$0x0,"
            r"(?P=saved),(?P=live),ne\s*$",
            trace_section,
        )
        if require_overlay_select and selector is None:
            raise HarnessError(
                "AR.PFS consumer 0x{:x} lacks explicit saved/live overlay "
                "selection".format(bundle_ip)
            )

        nat_helpers = list(re.finditer(
            r"(?m)^\s*call raise_register_nat_consumption,",
            trace_section,
        ))
        if require_nat_fault_path and not nat_helpers:
            raise HarnessError(
                "AR.PFS write bundle 0x{:x} lacks its precise conditional "
                "Register NaT Consumption path".format(bundle_ip)
            )
        if not require_nat_fault_path and nat_helpers:
            raise HarnessError(
                "read-only AR.PFS bundle 0x{:x} unexpectedly emitted a "
                "Register NaT Consumption path".format(bundle_ip)
            )
        for helper in nat_helpers:
            branch = trace_section.rfind("brcond_i64", 0, helper.start())
            direct_store = trace_section.find("st_i64", helper.end())
            if branch < 0 or direct_store < 0:
                raise HarnessError(
                    "AR.PFS NaT helper at 0x{:x} is not isolated before "
                    "the direct write path".format(bundle_ip)
                )


def _require_pfs_shadow_savevm_trace(source_trace: str,
                                     destination_trace: str,
                                     producer_ip: int,
                                     consumer_ip: int) -> None:
    """Tie restored PFS ordinary reads to all serialized overlay fields."""
    source = _tcg_op_sections(source_trace, producer_ip)[0]
    destination = _tcg_op_sections(destination_trace, consumer_ip)[0]
    producer_marker = "{:016x}".format(producer_ip)
    consumer_marker = "{:016x}".format(consumer_ip)

    if re.search(r"(?m)^ ---- {}\b".format(consumer_marker), source_trace):
        raise HarnessError(
            "source translated PFS consumer 0x{:x} before savevm".format(
                consumer_ip
            )
        )
    if re.search(r"(?m)^ ---- {}\b".format(producer_marker),
                 destination_trace):
        raise HarnessError(
            "destination replayed PFS producer 0x{:x} after loadvm".format(
                producer_ip
            )
        )

    temp = r"[A-Za-z_][A-Za-z0-9_]*"
    selector = re.search(
        r"(?m)^\s*ld_i64\s+(?P<live>{}),env,\$"
        r"(?P<ar_offset>0x[0-9a-f]+)\s*$\n"
        r"^\s*ld_i64\s+(?P<saved>{}),env,\$"
        r"(?P<saved_offset>0x[0-9a-f]+)\s*$\n"
        r"^\s*ld8u_i64\s+(?P<valid>{}),env,\$"
        r"(?P<valid_offset>0x[0-9a-f]+)\s*$\n"
        r"^\s*movcond_i64\s+{},(?P=valid),\$0x0,(?P=saved),"
        r"(?P=live),ne\s*$".format(temp, temp, temp, temp),
        destination,
    )
    if selector is None:
        raise HarnessError(
            "restored PFS consumer 0x{:x} lacks saved/live selection"
            .format(consumer_ip)
        )

    ar_offset = re.escape(selector.group("ar_offset"))
    saved_offset = re.escape(selector.group("saved_offset"))
    valid_offset = re.escape(selector.group("valid_offset"))
    preserve = re.search(
        r"(?m)^\s*ld_i64\s+(?P<old>{}),env,\${}\s*$\n"
        r"^\s*st_i64\s+(?P=old),env,\${}\s*$\n"
        r"^\s*st8_i32\s+\$0x1,env,\${}\s*$".format(
            temp, ar_offset, saved_offset, valid_offset
        ),
        source,
    )
    if preserve is None:
        raise HarnessError(
            "PFS producer 0x{:x} did not preserve its first live value "
            "before writing".format(producer_ip)
        )
    live_write = re.search(
        r"(?m)^\s*st_i64\s+{},env,\${}\s*$\n"
        r"^\s*st8_i32\s+\$0x1,env,\$"
        r"(?P<forward_offset>0x[0-9a-f]+)\s*$".format(temp, ar_offset),
        source,
    )
    if live_write is None:
        raise HarnessError(
            "PFS producer 0x{:x} lacks a direct AR.PFS store followed by "
            "forward-provenance publication".format(producer_ip)
        )
    forward_offset = live_write.group("forward_offset")
    if forward_offset == selector.group("valid_offset"):
        raise HarnessError(
            "PFS validity and branch-forward provenance alias one byte"
        )
    for label, offset in (
        ("pfs_saved", selector.group("valid_offset")),
        ("branch_pfs_forwarded", forward_offset),
    ):
        if re.search(
                r"(?m)^\s*st8_i32\s+\$0x0,env,\${}\s*$".format(
                    re.escape(offset)
                ), destination) is None:
            raise HarnessError(
                "restored continuation did not clear migrated {} at env+{}"
                .format(label, offset)
            )


def _require_source_visibility_trace(trace: str, bundle_ip: int,
                                     expected_state: int) -> None:
    for section in _tcg_op_sections(trace, bundle_ip):
        marker = re.search(
            r"(?m)^ ---- [0-9a-fA-F]{16} [0-9a-fA-F]{16} "
            r"([0-9a-fA-F]{16})\b",
            section,
        )
        if marker is None:
            raise HarnessError(
                "bundle 0x{:x} lacks insn_start source-visibility data"
                .format(bundle_ip)
            )
        actual = int(marker.group(1), 16)
        if actual != expected_state:
            raise HarnessError(
                "bundle 0x{:x} expected source-visibility marker 0x{:x}, "
                "got 0x{:x}".format(bundle_ip, expected_state, actual)
            )


def _tcg_env_memory_accesses(section: str) -> List[Tuple[str, int, str]]:
    accesses: List[Tuple[str, int, str]] = []
    pattern = re.compile(
        r"^\s*((?:ld|st)[A-Za-z0-9_]*)\s+.+?,env,\$"
        r"(0x[0-9a-fA-F]+)\s*$"
    )
    for line in section.splitlines():
        match = pattern.match(line)
        if match is not None:
            accesses.append(
                (match.group(1), int(match.group(2), 16), line.strip())
            )
    return accesses


def _require_overlay_dependency_trace(trace: str, dependency_free_ip: int,
                                      producer_ip: int,
                                      consumer_ip: int) -> None:
    """Reject overlay metadata traffic when no later ordinary read exists.

    Numeric ``env`` offsets are learned from the required cross-page witness,
    rather than frozen to one CPUIA64State layout.  Its producer must persist
    a GR+NaT source and PR image, and its consumer must select both.  Those
    same saved-mask and PR-validity offsets must be completely absent from the
    independent completed group.
    """
    sections: Dict[int, str] = {}
    for bundle_ip in (dependency_free_ip, producer_ip, consumer_ip):
        matches = _tcg_op_sections(trace, bundle_ip)
        if len(matches) != 1:
            raise HarnessError(
                "overlay traffic bundle 0x{:x} expected one translation, "
                "got {}".format(bundle_ip, len(matches))
            )
        sections[bundle_ip] = matches[0]

    producer = sections[producer_ip]
    consumer = sections[consumer_ip]
    mask_pattern = re.compile(
        r"(?m)^\s*ld_i64\s+(?P<temp>[^,\s]+),env,\$"
        r"(?P<offset>0x[0-9a-fA-F]+)\s*\n"
        r"\s*and_i64\s+(?P=temp),(?P=temp),\$0x[1-9a-fA-F]"
        r"[0-9a-fA-F]*\s*\n"
        r"\s*movcond_i64\s+[^,]+,(?P=temp),\$0x0,[^\n]+,ne\s*$"
    )
    mask_offsets = {
        int(match.group("offset"), 16)
        for match in mask_pattern.finditer(consumer)
    }
    if len(mask_offsets) != 1:
        raise HarnessError(
            "cross-page consumer 0x{:x} did not expose exactly one "
            "saved_gr_mask selection offset: {}".format(
                consumer_ip,
                ", ".join("0x{:x}".format(value)
                          for value in sorted(mask_offsets)) or "none",
            )
        )
    mask_offset = next(iter(mask_offsets))

    pr_pattern = re.compile(
        r"(?m)^\s*ld8u_i64\s+(?P<temp>[^,\s]+),env,\$"
        r"(?P<offset>0x[0-9a-fA-F]+)\s*\n"
        r"\s*movcond_i64\s+[^,]+,(?P=temp),\$0x0,[^\n]+,ne\s*$"
    )
    pr_offsets = {
        int(match.group("offset"), 16)
        for match in pr_pattern.finditer(consumer)
    }
    if len(pr_offsets) != 1:
        raise HarnessError(
            "cross-page consumer 0x{:x} did not expose exactly one pr_saved "
            "selection offset: {}".format(
                consumer_ip,
                ", ".join("0x{:x}".format(value)
                          for value in sorted(pr_offsets)) or "none",
            )
        )
    pr_offset = next(iter(pr_offsets))

    producer_accesses = _tcg_env_memory_accesses(producer)
    consumer_accesses = _tcg_env_memory_accesses(consumer)
    for label, offset in (
        ("saved_gr_mask consumer", mask_offset),
        ("pr_saved consumer", pr_offset),
    ):
        _require(
            any(operation.startswith("ld") and address == offset
                for operation, address, _line in consumer_accesses),
            "true-dependency witness lacks {} load at env+0x{:x}".format(
                label, offset
            ),
        )
    _require(
        any(operation.startswith("st") and address == mask_offset
            for operation, address, _line in producer_accesses),
        "true GR+NaT dependency did not persist saved_gr_mask at "
        "env+0x{:x}".format(mask_offset),
    )
    _require(
        any(operation.startswith("st") and address == pr_offset
            for operation, address, _line in producer_accesses),
        "true PR dependency did not persist pr_saved at env+0x{:x}".format(
            pr_offset
        ),
    )

    metadata_fields = {
        mask_offset: "saved_gr_mask[0]",
        mask_offset + 8: "saved_gr_mask[1]",
        pr_offset: "pr_saved",
    }
    unexpected: Dict[Tuple[str, int], int] = {}
    for operation, address, _line in _tcg_env_memory_accesses(
        sections[dependency_free_ip]
    ):
        if address in metadata_fields:
            key = (operation, address)
            unexpected[key] = unexpected.get(key, 0) + 1
    if unexpected:
        details = ", ".join(
            "{} env+0x{:x} ({}) x{}".format(
                operation, address, metadata_fields[address], count
            )
            for (operation, address), count in sorted(
                unexpected.items(), key=lambda item: (item[0][1], item[0][0])
            )
        )
        raise HarnessError(
            "dependency-free typed group 0x{:x} emitted issue_group "
            "overlay metadata traffic: {}".format(
                dependency_free_ip, details
            )
        )


def _require_internal_stop_handoff_trace(trace: str, bundle_ip: int) -> None:
    """Prove one callback closes a typed prefix then emits a typed suffix."""
    generic_helper = re.compile(r"(?m)^\s*call (?:exec_bundle|exec_slot),")
    direct_prefix = re.compile(r"(?m)^\s*(?:add|mov|movi)_i64\b")
    typed_suffix = re.compile(r"(?m)^\s*call system_preflight,")
    sections = _tcg_op_sections(trace, bundle_ip)

    if len(sections) != 1:
        raise HarnessError(
            "bundle 0x{:x} expected one same-callback handoff trace "
            "section, got {}".format(bundle_ip, len(sections))
        )
    section = sections[0]
    marker = re.search(
        r"(?m)^ ---- [0-9a-fA-F]{16} ([0-9a-fA-F]{16}) "
        r"([0-9a-fA-F]{16})\b",
        section,
    )
    if marker is None:
        raise HarnessError(
            "bundle 0x{:x} lacks RI/source-visibility trace data"
            .format(bundle_ip)
        )
    ri = int(marker.group(1), 16)
    visibility = int(marker.group(2), 16)
    if ri != 0:
        raise HarnessError(
            "bundle 0x{:x} handoff must stay in its RI=0 translator "
            "callback; found a translated RI={} section".format(
                bundle_ip, ri
            )
        )
    if visibility != 2:
        raise HarnessError(
            "bundle 0x{:x} typed-owner entry expected visibility 0x2, "
            "got 0x{:x}".format(bundle_ip, visibility)
        )

    direct = direct_prefix.search(section)
    suffix = typed_suffix.search(section)
    if direct is None:
        raise HarnessError(
            "bundle 0x{:x} typed prefix lacks direct scalar TCG".format(
                bundle_ip
            )
        )
    if suffix is None:
        raise HarnessError(
            "bundle 0x{:x} fresh post-stop MOV_CURRENT_IP suffix lacks its "
            "typed system preflight".format(bundle_ip)
        )
    if direct.start() >= suffix.start():
        raise HarnessError(
            "bundle 0x{:x} typed suffix appears before the direct prefix"
            .format(bundle_ip)
        )
    if generic_helper.search(section) is not None:
        raise HarnessError(
            "bundle 0x{:x} unexpectedly used a generic bundle helper"
            .format(bundle_ip)
        )


def _require_typed_application_move_restart_trace(
        trace: str, bundle_ip: int, start_slot: int,
        readback_ip: int) -> None:
    """Require typed RI suffix ownership and focused AR.LC move seams."""
    sections = _tcg_op_sections(trace, bundle_ip)
    if len(sections) != 1:
        raise HarnessError(
            "typed restart bundle 0x{:x} expected one translation, got {}"
            .format(bundle_ip, len(sections))
        )

    section = sections[0]
    marker = re.search(
        r"(?m)^ ---- [0-9a-fA-F]{16} ([0-9a-fA-F]{16}) "
        r"([0-9a-fA-F]{16})\b",
        section,
    )
    if marker is None:
        raise HarnessError(
            "typed restart bundle 0x{:x} lacks RI/visibility data".format(
                bundle_ip
            )
        )
    ri = int(marker.group(1), 16)
    visibility = int(marker.group(2), 16)
    if ri != start_slot:
        raise HarnessError(
            "typed restart bundle 0x{:x} expected RI={}, got RI={}"
            .format(bundle_ip, start_slot, ri)
        )
    if not (visibility & 2):
        raise HarnessError(
            "typed restart bundle 0x{:x} lacks typed-owner visibility: "
            "0x{:x}".format(bundle_ip, visibility)
        )

    _require_typed_direct_trace(trace, bundle_ip)
    _require_typed_direct_trace(trace, readback_ip)

    writer_helpers = (
        "application_register_write_legality",
        "application_register_write",
    )
    for helper in writer_helpers:
        if not re.search(
                r"(?m)^\s*call {},[^\n]*env,\$0x41(?:,|\s*$)".format(
                    helper
                ), section):
            raise HarnessError(
                "typed restart bundle 0x{:x} lacks its AR.LC {} seam"
                .format(bundle_ip, helper)
            )

    readback_sections = _tcg_op_sections(trace, readback_ip)
    if len(readback_sections) != 1:
        raise HarnessError(
            "typed AR.LC readback bundle 0x{:x} expected one translation, "
            "got {}".format(readback_ip, len(readback_sections))
        )
    readback = readback_sections[0]
    for helper in ("application_register_preflight",
                   "application_register_read"):
        if not re.search(
                r"(?m)^\s*call {},[^\n]*env,\$0x41(?:,|\s*$)".format(
                    helper
                ), readback):
            raise HarnessError(
                "typed readback bundle 0x{:x} lacks its AR.LC {} seam"
                .format(readback_ip, helper)
            )


def _require_automatic_segmentation_trace(
    trace: str, bundle_ips: Sequence[int]
) -> None:
    """Require one same-page group to occupy multiple ordinary TCG TBs."""
    wanted = set(bundle_ips)
    if not wanted:
        raise HarnessError("automatic segmentation trace has no bundle IPs")

    segment_hits: List[Set[int]] = []
    for block in re.split(r"(?m)(?=^OP:[ \t]*$)", trace):
        translated = {
            int(value, 16)
            for value in re.findall(
                r"(?m)^ ---- ([0-9a-fA-F]{16})\b", block
            )
        }
        hits = translated & wanted
        if hits:
            segment_hits.append(hits)

    seen = set().union(*segment_hits) if segment_hits else set()
    missing = sorted(wanted - seen)
    if missing:
        raise HarnessError(
            "automatic segmentation trace is missing bundles: {}".format(
                ", ".join("0x{:x}".format(ip) for ip in missing)
            )
        )
    if len(segment_hits) < 2 or any(hits == wanted
                                    for hits in segment_hits):
        raise HarnessError(
            "same-page {}-bundle group was not split across multiple "
            "ordinary TCG TBs".format(len(wanted))
        )


def run_program(qemu: Path, program: Program,
                preserve_fault_slot: bool = False,
                typed_fault_trace_ip: Optional[int] = None,
                typed_nat_fault_trace_ip: Optional[int] = None,
                typed_direct_trace_ips: Sequence[int] = (),
                typed_visibility_states: Sequence[Tuple[int, int]] = (),
                internal_stop_handoffs: Sequence[int] = (),
                automatic_segment_trace_ips: Sequence[int] = (),
                overlay_dependency_trace: Optional[Tuple[int, int, int]] = None,
                typed_branch_traces: Sequence[
                    Tuple[int, int, Optional[int]]
                ] = (),
                typed_indirect_traces: Sequence[
                    Tuple[int, int, int]
                ] = (),
                typed_loop_traces: Sequence[
                    Tuple[int, int, bool]
                ] = (),
                typed_call_traces: Sequence[
                    Tuple[int, Optional[int], bool, int]
                ] = (),
                typed_return_traces: Sequence[Tuple[int, int]] = (),
                typed_rfi_traces: Sequence[int] = (),
                typed_pfs_move_traces: Sequence[
                    Tuple[int, bool, bool, bool, bool]
                ] = (),
                one_bundle_per_tb: bool = False,
                state_cache: bool = False) -> Snapshot:
    port = _free_tcp_port()
    monitor_spec = (
        "tcp:127.0.0.1:{},server=on,wait=off,nodelay=on".format(port)
    )
    arguments = [
        str(qemu),
        "-L",
        str(FIRMWARE_DIR),
        "-machine",
        "vibtanium",
        "-m",
        "128M",
        "-smp",
        "1",
        "-S",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        monitor_spec,
        "-no-reboot",
    ]
    if one_bundle_per_tb:
        # QEMU calls this property one-insn-per-tb.  IA-64's translator loop
        # consumes one complete 16-byte bundle per translate_insn callback, so
        # the property deterministically forces one bundle per TB here.  This
        # is stronger than merely crossing a host opcode-buffer threshold and
        # directly exercises the migrated issue-group continuation state.
        arguments.extend(("-accel", "tcg,one-insn-per-tb=on"))
    arguments.extend(_loader_arguments(program))

    trace_directory: Optional[tempfile.TemporaryDirectory] = None
    trace_path: Optional[Path] = None
    if (typed_fault_trace_ip is not None or
            typed_nat_fault_trace_ip is not None or
            typed_direct_trace_ips or
            typed_branch_traces or
            typed_indirect_traces or
            typed_loop_traces or
            typed_call_traces or
            typed_return_traces or
            typed_rfi_traces or
            typed_pfs_move_traces or
            typed_visibility_states or internal_stop_handoffs or
            automatic_segment_trace_ips or
            overlay_dependency_trace is not None):
        trace_directory = tempfile.TemporaryDirectory(
            prefix="ia64-typed-trace-"
        )
        trace_path = Path(trace_directory.name) / "tcg-op.log"
        arguments.extend(("-d", "op", "-D", str(trace_path)))

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    process: Optional[subprocess.Popen] = None
    monitor: Optional[socket.socket] = None
    snapshot: Optional[Snapshot] = None
    failure: Optional[Exception] = None
    process_output = ""

    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_child_environment(state_cache=state_cache),
            creationflags=creationflags,
        )
        monitor = _connect_monitor(process, port)
        _recv_hmp_prompt(monitor)

        deadline = time.monotonic() + PROGRAM_TIMEOUT
        delay = 0.01
        last_ip: Optional[int] = None
        while time.monotonic() < deadline:
            _hmp_command(monitor, "cont")
            time.sleep(delay)
            _hmp_command(monitor, "stop")
            # Stopping before the dump also forces any live TCG state cache to
            # be synchronized back into CPUIA64State.
            candidate = parse_snapshot(_hmp_command(monitor, "info registers"))
            last_ip = candidate.ip
            if candidate.ip == program.terminal_ip:
                snapshot = candidate
                break
            delay = min(delay * 2, 0.1)

        if snapshot is None:
            raise HarnessError(
                "program {!r} did not reach terminal IP 0x{:x}; last IP was {}"
                .format(
                    program.name,
                    program.terminal_ip,
                    "unavailable" if last_ip is None else "0x{:x}".format(last_ip),
                )
            )
    except Exception as exc:  # Preserve diagnostics while always cleaning up.
        failure = exc
    finally:
        if monitor is not None:
            try:
                monitor.close()
            except OSError:
                pass
        if process is not None:
            try:
                process_output = _terminate_child(process)
            except Exception as cleanup_exc:
                if failure is None:
                    failure = cleanup_exc

    if failure is None and trace_path is not None:
        try:
            trace = trace_path.read_text(encoding="utf-8", errors="replace")
            if typed_fault_trace_ip is not None:
                _require_typed_fault_trace(trace, typed_fault_trace_ip)
            if typed_nat_fault_trace_ip is not None:
                _require_typed_nat_fault_trace(
                    trace, typed_nat_fault_trace_ip
                )
            for bundle_ip in typed_direct_trace_ips:
                _require_typed_direct_trace(trace, bundle_ip)
            for bundle_ip, target, fallthrough in typed_branch_traces:
                _require_typed_branch_trace(
                    trace, bundle_ip, target, fallthrough
                )
            for bundle_ip, branches, predicate_splits in \
                    typed_indirect_traces:
                _require_typed_indirect_trace(
                    trace, bundle_ip, branches, predicate_splits
                )
            for bundle_ip, target, expect_rotation_helper in \
                    typed_loop_traces:
                _require_typed_loop_trace(
                    trace, bundle_ip, target, expect_rotation_helper
                )
            for bundle_ip, target, indirect, predicate_splits in \
                    typed_call_traces:
                _require_typed_call_trace(
                    trace, bundle_ip, target, indirect, predicate_splits
                )
            for bundle_ip, predicate_splits in typed_return_traces:
                _require_typed_return_trace(
                    trace, bundle_ip, predicate_splits
                )
            for bundle_ip in typed_rfi_traces:
                _require_typed_rfi_trace(trace, bundle_ip)
            for (bundle_ip, require_read, require_write,
                 require_overlay_select, require_nat_fault_path) in \
                    typed_pfs_move_traces:
                _require_typed_pfs_move_trace(
                    trace, bundle_ip, require_read, require_write,
                    require_overlay_select, require_nat_fault_path
                )
            for bundle_ip, expected_state in typed_visibility_states:
                _require_source_visibility_trace(
                    trace, bundle_ip, expected_state
                )
            for bundle_ip in internal_stop_handoffs:
                _require_internal_stop_handoff_trace(trace, bundle_ip)
            if automatic_segment_trace_ips:
                _require_automatic_segmentation_trace(
                    trace, automatic_segment_trace_ips
                )
            if overlay_dependency_trace is not None:
                _require_overlay_dependency_trace(
                    trace, *overlay_dependency_trace
                )
        except Exception as trace_exc:
            failure = trace_exc
    if trace_directory is not None:
        trace_directory.cleanup()

    if failure is not None:
        detail = "{}".format(failure)
        if process_output.strip():
            detail += "\nQEMU output:\n" + process_output.strip()
        raise HarnessError(detail) from failure
    assert snapshot is not None
    return snapshot


def run_ri_restart(qemu: Path, program: Program, start_slot: int, *,
                   register_writes: Sequence[Tuple[int, int]] = ()) \
        -> Tuple[Snapshot, str]:
    """Enter a TB at a nonzero architectural RI without a breakpoint."""
    if start_slot < 0 or start_slot >= 3:
        raise ValueError("restart slot must be in the range 0..2")

    monitor_port = _free_tcp_port()
    gdb_port = _free_tcp_port()
    trace_directory = tempfile.TemporaryDirectory(
        prefix="ia64-typed-ri-restart-"
    )
    trace_path = Path(trace_directory.name) / "tcg-op.log"
    arguments = [
        str(qemu),
        "-L",
        str(FIRMWARE_DIR),
        "-machine",
        "vibtanium",
        "-m",
        "128M",
        "-smp",
        "1",
        "-S",
        "-display",
        "none",
        "-serial",
        "none",
        "-monitor",
        "tcp:127.0.0.1:{},server=on,wait=off,nodelay=on".format(
            monitor_port
        ),
        "-gdb",
        "tcp:127.0.0.1:{},server=on,wait=off".format(gdb_port),
        "-no-reboot",
        "-accel",
        "tcg,one-insn-per-tb=on",
        "-d",
        "op",
        "-D",
        str(trace_path),
    ]
    arguments.extend(_loader_arguments(program))

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    process: Optional[subprocess.Popen] = None
    monitor: Optional[socket.socket] = None
    gdb: Optional[socket.socket] = None
    snapshot: Optional[Snapshot] = None
    trace = ""
    process_output = ""
    failure: Optional[Exception] = None
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_child_environment(),
            creationflags=creationflags,
        )
        monitor = _connect_monitor(process, monitor_port)
        _recv_hmp_prompt(monitor)
        gdb = _connect_gdb(process, gdb_port)
        initial_stop = _gdb_rsp_command(gdb, "?")
        if not initial_stop.startswith(("S05", "T05")):
            raise HarnessError(
                "RI test GDB stub did not begin stopped: {}".format(
                    initial_stop
                )
            )

        initial = parse_snapshot(_hmp_command(monitor, "info registers"))
        # IA-64's GDB register file numbers GRs directly, followed by IP=128
        # and PSR=129.  Optional writes seed case-specific operands before the
        # architectural IP/RI pair is published atomically to translation.
        for regnum, value in register_writes:
            _gdb_write_u64(gdb, regnum, value)
        _gdb_write_u64(gdb, IA64_GDB_IP_REGNUM, program.entry)
        restart_psr = (
            (initial.psr & ~(3 << IA64_PSR_RI_SHIFT)) |
            (start_slot << IA64_PSR_RI_SHIFT)
        )
        _gdb_write_u64(gdb, IA64_GDB_PSR_REGNUM, restart_psr)

        prepared = parse_snapshot(_hmp_command(monitor, "info registers"))
        if (prepared.ip != program.entry or
                ((prepared.psr >> IA64_PSR_RI_SHIFT) & 3) != start_slot):
            raise HarnessError(
                "GDB setup did not publish IP 0x{:x}/RI={}: "
                "IP=0x{:x} PSR=0x{:x}".format(
                    program.entry, start_slot, prepared.ip, prepared.psr
                )
            )

        # No debugger breakpoint participates in execution.  Closing the
        # setup connection leaves the normal HMP run/stop loop as the sole
        # scheduler and avoids a synthetic suffix-specific code path.
        gdb.close()
        gdb = None
        deadline = time.monotonic() + PROGRAM_TIMEOUT
        delay = 0.01
        last_ip: Optional[int] = None
        while time.monotonic() < deadline:
            _hmp_command(monitor, "cont")
            time.sleep(delay)
            _hmp_command(monitor, "stop")
            candidate = parse_snapshot(
                _hmp_command(monitor, "info registers")
            )
            last_ip = candidate.ip
            if candidate.ip == program.terminal_ip:
                snapshot = candidate
                break
            delay = min(delay * 2, 0.1)
        if snapshot is None:
            raise HarnessError(
                "RI restart did not reach terminal IP 0x{:x}; "
                "last IP was {}".format(
                    program.terminal_ip,
                    "unavailable" if last_ip is None else
                    "0x{:x}".format(last_ip),
                )
            )
    except Exception as exc:
        failure = exc
    finally:
        for stream in (gdb, monitor):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if process is not None:
            try:
                process_output = _terminate_child(process)
            except Exception as cleanup_exc:
                if failure is None:
                    failure = cleanup_exc

    if failure is None:
        try:
            trace = trace_path.read_text(encoding="utf-8", errors="replace")
        except Exception as trace_exc:
            failure = trace_exc
    trace_directory.cleanup()

    if failure is not None:
        detail = "{}".format(failure)
        if process_output.strip():
            detail += "\nQEMU output:\n" + process_output.strip()
        raise HarnessError(detail) from failure
    assert snapshot is not None
    return snapshot, trace


def run_savevm_migration(qemu: Path, program: Program,
                          checkpoint_ip: int,
                          preserve_fault_slot: bool = False) -> MigrationResult:
    qemu_img_name = "qemu-img.exe" if qemu.suffix.lower() == ".exe" else "qemu-img"
    qemu_img = qemu.with_name(qemu_img_name)
    if not qemu_img.is_file():
        raise HarnessError(
            "two-QEMU save/load migration needs the sibling qemu-img: {}"
            .format(qemu_img)
        )

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    source_process: Optional[subprocess.Popen] = None
    destination_process: Optional[subprocess.Popen] = None
    source_monitor: Optional[socket.socket] = None
    destination_monitor: Optional[socket.socket] = None
    gdb: Optional[socket.socket] = None
    source_output = ""
    destination_output = ""
    failure: Optional[Exception] = None
    checkpoint: Optional[Snapshot] = None
    restored: Optional[Snapshot] = None
    final: Optional[Snapshot] = None
    source_trace = ""
    destination_trace = ""

    with tempfile.TemporaryDirectory(
        prefix="ia64-typed-migration-"
    ) as directory:
        temporary = Path(directory)
        disk_path = temporary / "migration-state.qcow2"
        source_trace_path = temporary / "source-op.log"
        destination_trace_path = temporary / "destination-op.log"
        try:
            image = subprocess.run(
                [str(qemu_img), "create", "-f", "qcow2",
                 str(disk_path), "192M"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=MIGRATION_TIMEOUT,
                creationflags=creationflags,
            )
            if image.returncode != 0:
                raise HarnessError(
                    "qemu-img could not create the migration snapshot: {}"
                    .format((image.stdout or "").strip())
                )

            common_arguments = [
                str(qemu),
                "-L",
                str(FIRMWARE_DIR),
                "-machine",
                "vibtanium",
                "-m",
                "128M",
                "-smp",
                "1",
                "-S",
                "-display",
                "none",
                "-serial",
                "none",
                "-no-reboot",
                "-accel",
                "tcg,one-insn-per-tb=on",
                "-drive",
                "if=none,id=typed-migration-state,file={},format=qcow2"
                .format(disk_path),
            ]
            common_arguments.extend(_loader_arguments(program))

            source_monitor_port = _free_tcp_port()
            gdb_port = _free_tcp_port()
            source_arguments = common_arguments + [
                "-monitor",
                "tcp:127.0.0.1:{},server=on,wait=off,nodelay=on"
                .format(source_monitor_port),
                "-gdb",
                "tcp:127.0.0.1:{},server=on,wait=off".format(gdb_port),
                "-d",
                "op",
                "-D",
                str(source_trace_path),
            ]
            source_process = subprocess.Popen(
                source_arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=_child_environment(),
                creationflags=creationflags,
            )
            source_monitor = _connect_monitor(
                source_process, source_monitor_port
            )
            _recv_hmp_prompt(source_monitor)
            gdb = _connect_gdb(source_process, gdb_port)
            initial_stop = _gdb_rsp_command(gdb, "?")
            if not initial_stop.startswith(("S05", "T05")):
                raise HarnessError(
                    "source GDB stub did not begin stopped: {}".format(
                        initial_stop
                    )
                )
            breakpoint = _gdb_rsp_command(
                gdb, "Z0,{:x},10".format(checkpoint_ip)
            )
            if breakpoint != "OK":
                raise HarnessError(
                    "source GDB stub rejected checkpoint 0x{:x}: {}"
                    .format(checkpoint_ip, breakpoint)
                )
            _gdb_rsp_send(gdb, "c")
            stop = _gdb_rsp_receive(gdb, PROGRAM_TIMEOUT)
            if not stop.startswith(("S05", "T05")):
                raise HarnessError(
                    "source did not stop at the migration breakpoint: {}"
                    .format(stop)
                )
            checkpoint = parse_snapshot(
                _hmp_command(source_monitor, "info registers")
            )
            if checkpoint.ip != checkpoint_ip:
                raise HarnessError(
                    "migration breakpoint expected IP 0x{:x}, got 0x{:x}"
                    .format(checkpoint_ip, checkpoint.ip)
                )

            _hmp_command(source_monitor, "savevm typed-active")
            snapshots = _hmp_command(source_monitor, "info snapshots")
            if re.search(
                r"(?m)^--\s+typed-active\s+", snapshots
            ) is None:
                raise HarnessError(
                    "savevm did not persist the typed-active checkpoint:\n{}"
                    .format(snapshots)
                )

            gdb.close()
            gdb = None
            source_monitor.close()
            source_monitor = None
            source_output = _terminate_child(source_process)
            source_process = None
            source_trace = source_trace_path.read_text(
                encoding="utf-8", errors="replace"
            )

            destination_monitor_port = _free_tcp_port()
            destination_arguments = common_arguments + [
                "-monitor",
                "tcp:127.0.0.1:{},server=on,wait=off,nodelay=on"
                .format(destination_monitor_port),
                "-d",
                "op",
                "-D",
                str(destination_trace_path),
            ]
            destination_process = subprocess.Popen(
                destination_arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=_child_environment(),
                creationflags=creationflags,
            )
            destination_monitor = _connect_monitor(
                destination_process, destination_monitor_port
            )
            _recv_hmp_prompt(destination_monitor)
            _hmp_command(destination_monitor, "loadvm typed-active")
            restored = parse_snapshot(
                _hmp_command(destination_monitor, "info registers")
            )

            deadline = time.monotonic() + PROGRAM_TIMEOUT
            delay = 0.01
            while time.monotonic() < deadline:
                _hmp_command(destination_monitor, "cont")
                time.sleep(delay)
                _hmp_command(destination_monitor, "stop")
                candidate = parse_snapshot(
                    _hmp_command(destination_monitor, "info registers")
                )
                if candidate.ip == program.terminal_ip:
                    final = candidate
                    break
                delay = min(delay * 2, 0.1)
            if final is None:
                raise HarnessError(
                    "migration destination did not reach terminal IP 0x{:x}"
                    .format(program.terminal_ip)
                )

            destination_monitor.close()
            destination_monitor = None
            destination_output = _terminate_child(destination_process)
            destination_process = None
            destination_trace = destination_trace_path.read_text(
                encoding="utf-8", errors="replace"
            )
        except Exception as exc:
            failure = exc
        finally:
            for stream in (gdb, source_monitor, destination_monitor):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            if source_process is not None:
                try:
                    source_output += _terminate_child(source_process)
                except Exception as cleanup_exc:
                    if failure is None:
                        failure = cleanup_exc
            if destination_process is not None:
                try:
                    destination_output += _terminate_child(
                        destination_process
                    )
                except Exception as cleanup_exc:
                    if failure is None:
                        failure = cleanup_exc

        if failure is not None:
            detail = "{}".format(failure)
            if source_output.strip():
                detail += "\nSource QEMU output:\n" + source_output.strip()
            if destination_output.strip():
                detail += ("\nDestination QEMU output:\n" +
                           destination_output.strip())
            raise HarnessError(detail) from failure

    assert checkpoint is not None
    assert restored is not None
    assert final is not None
    return MigrationResult(
        checkpoint=checkpoint,
        restored=restored,
        final=final,
        source_trace=source_trace,
        destination_trace=destination_trace,
    )


def snapshot_differences(left: Snapshot, right: Snapshot) -> List[str]:
    differences: List[str] = []
    for field in dataclasses.fields(Snapshot):
        name = field.name
        left_value = getattr(left, name)
        right_value = getattr(right, name)
        if left_value == right_value:
            continue
        if name == "gr":
            for reg, (left_gr, right_gr) in enumerate(zip(left_value, right_value)):
                if left_gr != right_gr:
                    differences.append(
                        "r{}: 0x{:016x} != 0x{:016x}".format(
                            reg, left_gr, right_gr
                        )
                    )
        elif name == "br":
            for reg, (left_br, right_br) in enumerate(zip(left_value, right_value)):
                if left_br != right_br:
                    differences.append(
                        "b{}: 0x{:016x} != 0x{:016x}".format(
                            reg, left_br, right_br
                        )
                    )
        elif isinstance(left_value, int) and isinstance(right_value, int):
            differences.append(
                "{}: 0x{:x} != 0x{:x}".format(name, left_value, right_value)
            )
        else:
            differences.append("{}: {!r} != {!r}".format(
                name, left_value, right_value
            ))
    return differences


def successful_snapshot_differences(left: Snapshot,
                                    right: Snapshot) -> List[str]:
    """Compare architectural success state, excluding fault scratch state.

    ``current_slot_*`` is diagnostic state for precise interruption collection,
    not an architectural success result.  Fault tests assert those fields
    explicitly and continue to use the unfiltered comparison where appropriate.
    """
    cleared = dict(
        slot_valid=False,
        slot_ip=0,
        slot_ri=0,
        slot_type=0,
        slot_raw=0,
    )
    return snapshot_differences(
        dataclasses.replace(left, **cleared),
        dataclasses.replace(right, **cleared),
    )


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise HarnessError(message)


def test_core_equality(qemu: Path) -> str:
    program = core_program()
    snapshot = run_program(
        qemu, program, typed_direct_trace_ips=(0x10,)
    )

    _require(snapshot.ip == 0x20, "core program did not stop at 0x20")
    _require(snapshot.gr[0] == 0, "r0 lost its immutable-zero value")
    _require(snapshot.gr[1] == 42, "ADDS result r1 is not 42")
    _require(snapshot.gr[2] == 7, "ADDS result r2 is not 7")
    _require(snapshot.psr == 0, "core program unexpectedly changed PSR")
    _require(snapshot.pr == 1, "core program unexpectedly changed PR")
    _require(snapshot.cfm == 0, "core program unexpectedly changed CFM")
    _require(
        snapshot.nat_high == 0 and snapshot.nat_low == 0,
        "core program unexpectedly set a NaT bit",
    )

    overlay = run_program(
        qemu, ordinary_source_overlay_program(),
        typed_direct_trace_ips=(0x20, 0x30, 0x50, 0x60),
    )
    _require(overlay.gr[1] == 2,
             "repeated typed writers did not leave the final live GR value")
    _require(overlay.gr[2] == 5,
             "repeated writers overwrote the saved group-entry GR value")
    _require(overlay.gr[3] == 11,
             "ordinary predicate qualifier did not use the saved PR image")
    _require(overlay.gr[5] == 2 and overlay.gr[6] == 12,
             "the stop did not expose final GR/PR state to the next group")
    _require(overlay.pr == ((1 << 0) | (1 << 2)),
             "predicate overlay invariant left the wrong live PR image")

    stacked = run_program(
        qemu, stacked_gr_pair_program(),
        typed_direct_trace_ips=(0x20, 0x30, 0x40, 0x50),
    )
    _require(stacked.cfm == 0x206,
             "stacked setup expected CFM=0x206, got 0x{:x}".format(
                 stacked.cfm
             ))
    _require(stacked.gr[32] == 1 and stacked.gr[33] == 7,
             "stacked live writes retired to the wrong logical registers")
    _require(stacked.gr[34] == 10,
             "duplicate stacked source did not use saved group-entry r32")
    _require(stacked.gr[35] == 0,
             "false-predicated stacked destination was modified")
    _require(stacked.nat_high == 0 and stacked.nat_low == 0,
             "stacked value/NaT pair introduced an unexpected NaT")
    return ("literal core goldens, direct TCG traces, and the ordinary-source "
            "overlay invariant cover repeated GR writers, PR qualifiers, stop "
            "visibility, and one-slot stacked value/NaT mapping reused by "
            "duplicate sources and retirement")


def test_scalar_integer_expansion(qemu: Path) -> str:
    shift_program = scalar_shift_bitfield_program()
    shift = run_program(qemu, shift_program)

    mask64 = (1 << 64) - 1
    shift_expected = {
        13: 0x10,
        14: 0x0fffffffffffffff,
        15: mask64,
        16: 0,
        17: 0,
        18: mask64,
        19: 1 << 40,
        20: 0x4000000000000008,
        21: 0x23400,
        22: 0xfff0,
        23: 0x7f34,
        24: 0xf1234,
        25: 0x23,
        26: mask64 - 0x7f,
        27: mask64 - 0x7f,
        28: 0xff,
        29: 64,
        30: 64,
        31: 8,
    }
    for reg, expected in shift_expected.items():
        _require(
            shift.gr[reg] == expected,
            "shift/bitfield r{} expected 0x{:x}, got 0x{:x}".format(
                reg, expected, shift.gr[reg]
            ),
        )

    multiply_program = scalar_multiply_extension_program()
    multiply = run_program(qemu, multiply_program)

    multiply_expected = {
        8: 0x0000000300000000,
        9: 0x00000004fffffffb,
        10: 0x0000000f00000000,
        11: 17,
        12: 8,
        13: 4,
        14: mask64,
        15: mask64,
        16: 0xffff,
        17: 0xffffffff,
        18: 77,
        19: 0x48,
    }
    for reg, expected in multiply_expected.items():
        _require(
            multiply.gr[reg] == expected,
            "multiply/extension r{} expected 0x{:x}, got 0x{:x}".format(
                reg, expected, multiply.gr[reg]
            ),
        )
    _require(multiply.nat_low == 0 and multiply.nat_high == 0,
             "scalar expansion unexpectedly produced NaT state")
    return ("two scalar families match independent literal goldens, including "
            "large counts, aliases, and false predicates")


def test_predicate_transaction(qemu: Path) -> str:
    program = predicate_compare_program()
    snapshot = run_program(qemu, program)

    expected_pr = (
        (1 << 0) | (1 << 1) | (1 << 4) | (1 << 5) |
        (1 << 7) | (1 << 10) | (1 << 11)
    )
    _require(snapshot.ip == program.terminal_ip,
             "predicate program did not reach its terminal bundle")
    _require(
        snapshot.pr == expected_pr,
        "predicate golden expected PR=0x{:x}, got 0x{:x}".format(
            expected_pr, snapshot.pr
        ),
    )
    expected_gr = {
        20: 101,
        21: 0,
        22: 104,
        23: 105,
        24: 107,
        25: 110,
        26: 111,
        27: 0,
    }
    for reg, expected in expected_gr.items():
        _require(
            snapshot.gr[reg] == expected,
            "predicate consumer r{} expected {}, got {}".format(
                reg, expected, snapshot.gr[reg]
            ),
        )
    _require(snapshot.nat_low == 0 and snapshot.nat_high == 0,
             "A6 compare golden unexpectedly changed NaT state")
    return ("A6 64-bit/cmp4 comparisons and false-qp .unc match the "
            "architectural golden across multi-slot PR transactions")


def test_integer_compare_conformance(qemu: Path) -> str:
    normal_program, normal_compare_ips = normal_compare_conformance_program()
    normal = run_program(
        qemu,
        normal_program,

        typed_direct_trace_ips=normal_compare_ips,
        one_bundle_per_tb=True,
    )
    _require(not normal.exception_pending and normal.exception_kind == "none",
             "normal compare conformance program raised an exception")

    # Literal SDM results for LT/LTU/EQ at both widths, followed by a
    # false-qualified .unc clear and a successful NaT-source assignment.
    normal_images = (
        0x041,  # 64-bit: -1 < 0.
        0x081,  # 64-bit unsigned: UINT64_MAX !< 0xffffffff.
        0x041,  # 64-bit: -1 == -1.
        0x081,  # cmp4 signed: 0 !< -1.
        0x041,  # cmp4 unsigned: 0 < 0xffffffff.
        0x041,  # cmp4: low32(-1) == 0xffffffff.
        0x001,  # false p5 still makes cmp.unc clear p6 and p7.
        0x001,  # a NaT source makes normal cmp write 0,0 without fault.
    )
    for index, expected in enumerate(normal_images):
        reg = 12 + index
        _require(
            normal.gr[reg] == expected,
            "normal compare case {} snapshot r{} expected 0x{:x}, got "
            "0x{:x}".format(index + 1, reg, expected, normal.gr[reg]),
        )
    _require(normal.gr[7] == 0xffffffff,
             "normal cmp4 discriminator was not constructed")
    _require(normal.gr[11] == 0x123456789abcdef0,
             "normal compare changed its NaT source value")
    _require(normal.nat_low == (1 << 11) and normal.nat_high == 0,
             "normal compare consumed or changed its NaT source")
    _require(normal.pr == 1,
             "final normal NaT assignment expected PR=1, got 0x{:x}"
             .format(normal.pr))

    program, compare_ips = parallel_compare_conformance_program()
    snapshot = run_program(
        qemu,
        program,

        typed_direct_trace_ips=compare_ips,
        one_bundle_per_tb=True,
    )

    _require(not snapshot.exception_pending,
             "parallel compare conformance program raised an exception")
    _require(snapshot.exception_kind == "none",
             "parallel compare conformance left a non-none exception kind")

    # Literal SDM predicate images, including hard-wired p0.  Case 2 proves
    # AND-false clears p2 and case 5 proves OR-true sets p2; the reference
    # fork's complement-based p2 updates fail both cases.
    expected_images = (
        0x0c1,  # A8 AND true: preserve 11.
        0x001,  # A7 AND false: clear both.
        0x001,  # A6 AND NaT: clear both.
        0x041,  # A6 cmp4 AND false qp: preserve 10.
        0x0c1,  # A8 cmp4 OR true: set both.
        0x001,  # A6 OR false: preserve 00.
        0x001,  # A7 OR NaT: preserve 00.
        0x041,  # A8 OR false qp: preserve 10.
        0x041,  # A7 cmp4 OR.ANDCM true: produce 10.
        0x081,  # A6 cmp4 OR.ANDCM false: preserve 01.
        0x081,  # A8 OR.ANDCM NaT: preserve 01.
        0x081,  # A7 OR.ANDCM false qp: preserve 01.
    )
    for index, expected in enumerate(expected_images):
        reg = 12 + index
        _require(
            snapshot.gr[reg] == expected,
            "parallel compare case {} snapshot r{} expected 0x{:x}, "
            "got 0x{:x}".format(index + 1, reg, expected,
                                snapshot.gr[reg]),
        )

    _require(snapshot.gr[7] == 0xffffffff,
             "cmp4 zero-extension discriminator was not constructed")
    _require(snapshot.gr[8] == 0x100000000,
             "cmp4 high-word discriminator was not constructed")
    _require(snapshot.gr[11] == 0x123456789abcdef0,
             "NaT compare source value changed unexpectedly")
    _require(snapshot.nat_low == (1 << 11) and snapshot.nat_high == 0,
             "parallel compares consumed or changed their NaT source")

    # Literal post-transaction images.  r24 covers same-target WAW for all
    # three completers across a forced TB split; r25 covers an old-true qp
    # alias across another split; r26/r27 cover p0 as each destination.
    transaction_images = {
        24: 0x059,
        25: 0x301,
        26: 0x001,
        27: 0x041,
    }
    for reg, expected in transaction_images.items():
        _require(
            snapshot.gr[reg] == expected,
            "parallel compare transaction r{} expected 0x{:x}, got "
            "0x{:x}".format(reg, expected, snapshot.gr[reg]),
        )
    _require(snapshot.pr == 0x041,
             "final p0/p6 destination image expected 0x41, got 0x{:x}"
             .format(snapshot.pr))

    rotating = run_program(
        qemu,
        rotating_parallel_compare_program(),

        typed_direct_trace_ips=(0x40,),
        one_bundle_per_tb=True,
    )
    _require(not rotating.exception_pending and
             rotating.exception_kind == "none",
             "rotating parallel compare raised an exception")
    _require(((rotating.cfm >> 32) & 0x3f) == 47,
             "br.ctop did not establish rrb_pr=47")
    _require(rotating.pr == 0x10001,
             "rotating p17/p16 physical image expected 0x10001, got 0x{:x}"
             .format(rotating.pr))
    _require(rotating.gr[29] == 0x66 and rotating.gr[30] == 0,
             "logical rotating-predicate consumers did not observe p17=1, "
             "p16=0")

    fault_raw = cmp_merge_rr(10, 10, 0, 0, "and", "eq")
    fault = run_program(
        qemu,
        merge_equal_target_fault_program(),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x30,
    )
    _require_illegal_operation(
        fault,
        fault_ip=0x30,
        fault_slot=2,
        fault_raw=fault_raw,
        collection_enabled=True,
        expected_iipa=0x30,
    )
    _require(fault.pr == 1,
             "qualified equal-target merge changed a predicate")
    _require(fault.gr[20] == 77,
             "equal-target merge fault lost its retired prefix")
    _require(fault.gr[21] == 0,
             "instruction after equal-target merge fault executed")

    nullified = run_program(
        qemu,
        merge_equal_target_predicated_off_program(),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x30,
    )
    _require(not nullified.exception_pending and
             nullified.exception_kind == "none",
             "false-qp equal-target merge unexpectedly faulted")
    _require(nullified.pr == 0x401,
             "false-qp equal-target merge changed p10")
    _require(nullified.gr[22] == 0x55,
             "slot after false-qp equal-target merge did not execute")

    a7_raw = cmp_merge_zero(10, 10, 0, "and", "gt")
    a7_fault = run_program(
        qemu,
        a7_equal_target_fault_program(),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x30,
    )
    _require_illegal_operation(
        a7_fault,
        fault_ip=0x30,
        fault_slot=2,
        fault_raw=a7_raw,
        collection_enabled=True,
        expected_iipa=0x30,
    )
    _require(a7_fault.pr == 1,
             "qualified A7 equal-target fault changed a predicate")
    _require(a7_fault.gr[20] == 77 and a7_fault.gr[21] == 0,
             "A7 equal-target fault did not commit only its prefix")

    a8_raw = cmp_imm(12, 12, -1, 0, "eq", width=4)
    a8_fault = run_program(
        qemu,
        a8_cmp4_equal_target_fault_program(),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x30,
    )
    _require_illegal_operation(
        a8_fault,
        fault_ip=0x30,
        fault_slot=2,
        fault_raw=a8_raw,
        collection_enabled=True,
        expected_iipa=0x30,
    )
    _require(a8_fault.pr == 1,
             "qualified A8 cmp4 equal-target fault changed a predicate")
    _require(a8_fault.gr[23] == 91 and a8_fault.gr[24] == 0,
             "A8 cmp4 equal-target fault did not commit only its prefix")

    a8_nullified = run_program(
        qemu,
        a8_cmp4_equal_target_predicated_off_program(),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x30,
    )
    _require(not a8_nullified.exception_pending and
             a8_nullified.exception_kind == "none",
             "false-qp A8 cmp4 equal-target compare unexpectedly faulted")
    _require(a8_nullified.pr == 0x1001,
             "false-qp A8 cmp4 equal-target compare changed p12")
    _require(a8_nullified.gr[22] == 0x55,
             "slot after false-qp A8 cmp4 compare did not execute")

    return (
        "literal SDM goldens cover every canonical normal A8 opcode, .unc, "
        "normal NaT assignment, all parallel update classes, M/I, cmp/cmp4, "
        "p0, rotating p16/p17 at rrb_pr=47, same-group WAW and qp alias, "
        "plus qualified A6/A7/A8 and nullified equal-target legality; every "
        "tested compare trace rejects generic execution helpers"
    )


def _require_register_nat_consumption(snapshot: Snapshot, *, fault_ip: int,
                                      fault_slot: int, fault_raw: int,
                                      expected_iipa: int,
                                      terminal_ip: Optional[int] = None) \
        -> None:
    expected_isr = (
        IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION
        | (fault_slot << IA64_ISR_EI_SHIFT)
    )
    expected_terminal = (
        IA64_REGISTER_NAT_CONSUMPTION_VECTOR
        if terminal_ip is None else terminal_ip
    )
    _require(
        snapshot.ip == expected_terminal,
        "Register NaT Consumption handler did not reach 0x{:x}; got 0x{:x}"
        .format(expected_terminal, snapshot.ip),
    )
    _require(not snapshot.psr_ic_inflight,
             "Register NaT Consumption did not serialize PSR.ic state")
    _require(snapshot.exception_pending,
             "Register NaT Consumption left no pending exception record")
    _require(
        snapshot.exception_kind == "register-nat-consumption",
        "expected register-nat-consumption, got {!r}".format(
            snapshot.exception_kind
        ),
    )
    _require(
        snapshot.exception_vector == IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        "exception record has vector 0x{:x}, expected 0x{:x}".format(
            snapshot.exception_vector,
            IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        ),
    )
    _require(
        snapshot.exception_source == fault_ip and
        snapshot.exception_address == fault_ip,
        "exception source/address expected 0x{:x}, got 0x{:x}/0x{:x}"
        .format(
            fault_ip, snapshot.exception_source, snapshot.exception_address
        ),
    )
    _require(
        snapshot.cr_isr == expected_isr,
        "slot {} Register NaT Consumption expected ISR=0x{:x}, got 0x{:x}"
        .format(fault_slot, expected_isr, snapshot.cr_isr),
    )
    _require(snapshot.slot_valid, "faulting MOV_GRPR slot was not published")
    _require(
        snapshot.slot_ip == fault_ip and snapshot.slot_ri == fault_slot,
        "fault slot expected 0x{:x}:{}; got 0x{:x}:{}".format(
            fault_ip, fault_slot, snapshot.slot_ip, snapshot.slot_ri
        ),
    )
    _require(
        snapshot.slot_type == IA64_SLOT_TYPE_I and
        snapshot.slot_raw == (fault_raw & SLOT_MASK),
        "fault slot type/raw expected I/0x{:x}, got {}/0x{:x}".format(
            fault_raw & SLOT_MASK, snapshot.slot_type, snapshot.slot_raw
        ),
    )
    _require(
        snapshot.cr_iip == fault_ip,
        "collected IIP expected 0x{:x}, got 0x{:x}".format(
            fault_ip, snapshot.cr_iip
        ),
    )
    _require(
        snapshot.cr_iipa == expected_iipa,
        "collected IIPA expected 0x{:x}, got 0x{:x}".format(
            expected_iipa, snapshot.cr_iipa
        ),
    )
    _require(
        (snapshot.cr_ipsr & IA64_PSR_IC) != 0 and
        ((snapshot.cr_ipsr >> IA64_PSR_RI_SHIFT) & 3) == fault_slot,
        "collected IPSR does not preserve IC and slot {}".format(fault_slot),
    )


def test_predicate_register_moves(qemu: Path) -> str:
    program = predicate_register_move_program()
    snapshot = run_program(
        qemu,
        program,

        typed_direct_trace_ips=(
            0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        ),
    )

    entry_image = 0x2b
    low_image = 0x35
    signed_image = 0xffffffffffff0035
    _require(snapshot.ip == program.terminal_ip,
             "predicate-register move program missed its terminal bundle")
    _require(not snapshot.exception_pending and snapshot.exception_kind == "none",
             "false-qualified NaT source unexpectedly raised an exception")
    _require(
        snapshot.gr[20] == entry_image,
        "same-group MOV_PRGR expected entry PR 0x{:x}, got 0x{:x}".format(
            entry_image, snapshot.gr[20]
        ),
    )
    _require(
        snapshot.gr[21] == low_image,
        "masked low PR image expected 0x{:x}, got 0x{:x}".format(
            low_image, snapshot.gr[21]
        ),
    )
    _require(
        snapshot.gr[22] == signed_image,
        "negative imm44 expected 0x{:x}, got 0x{:x}".format(
            signed_image, snapshot.gr[22]
        ),
    )
    _require(
        snapshot.gr[27] == low_image,
        "I23 high-48 clear expected 0x{:x}, got 0x{:x}".format(
            low_image, snapshot.gr[27]
        ),
    )
    _require(
        snapshot.gr[23] == signed_image and
        snapshot.gr[26] == signed_image and snapshot.pr == signed_image,
        "high-48 restore/final PR expected 0x{:x}; got "
        "r23=0x{:x} r26=0x{:x} PR=0x{:x}".format(
            signed_image, snapshot.gr[23], snapshot.gr[26], snapshot.pr
        ),
    )
    _require(snapshot.pr & 1,
             "packed predicate-register moves did not preserve p0=true")
    _require(snapshot.gr[25] == 99,
             "false-qualified MOV_PRGR modified its destination")
    _require(snapshot.gr[24] == 0,
             "false-qualified MOV_GRPR modified its NaT source")
    _require(
        snapshot.nat_low == (1 << 24) and snapshot.nat_high == 0,
        "MOV_PRGR did not clear only destination r20's NaT: 0x{:x}:0x{:x}"
        .format(snapshot.nat_high, snapshot.nat_low),
    )

    for mask in (0x3e, 0):
        fault_program = predicate_register_nat_fault_program(mask)
        fault_raw = mov_grpr(4, mask, qp=6)
        fault = run_program(
            qemu,
            fault_program,

            preserve_fault_slot=True,
            typed_nat_fault_trace_ip=0x80,
        )
        _require_register_nat_consumption(
            fault,
            fault_ip=0x80,
            fault_slot=2,
            fault_raw=fault_raw,
            expected_iipa=0x80,
        )
        _require(
            fault.gr[23] == 66,
            "mask 0x{:x} Register NaT Consumption lost the earlier "
            "same-group GR write".format(mask),
        )
        _require(
            fault.pr == ((1 << 0) | (1 << 6)),
            "mask 0x{:x} faulting MOV_GRPR changed PR: expected 0x41, "
            "got 0x{:x}".format(mask, fault.pr),
        )
        _require(
            fault.gr[4] == 85 and fault.nat_low == 0 and
            fault.nat_high == 0,
            "mask 0x{:x} fault did not commit the same-group r4/NaT "
            "overwrite after consuming its older entry image".format(mask),
        )

    return (
        "I23/I24/I25 direct TCG passes independent packed-image, signed-imm, "
        "p0, nullification, same-group visibility, and NaT-clear goldens; "
        "qualified MOV_GRPR raises the exact collected Register NaT "
        "Consumption state for nonzero and zero masks after committing only "
        "its prefix"
    )


def test_branch_register_moves(qemu: Path) -> str:
    program = branch_register_move_program()
    snapshot = run_program(
        qemu,
        program,

        typed_direct_trace_ips=(
            0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
            0xf0, 0x100, 0x110, 0x120,
        ),
        one_bundle_per_tb=True,
    )

    _require(snapshot.ip == program.terminal_ip,
             "branch-register move program missed its terminal bundle")
    _require(not snapshot.exception_pending and
             snapshot.exception_kind == "none",
             "false-qualified NaT source unexpectedly raised an exception")
    expected_br = (0, 0x111, 0x222, 0x333, 0, 0x222, 0x222, 0)
    _require(
        snapshot.br == expected_br,
        "branch-register image expected {!r}, got {!r}".format(
            expected_br, snapshot.br
        ),
    )
    expected_gr = {
        20: 0x111,
        21: 0x222,
        22: 0x333,
        23: 0x555,
        24: 0x222,
        25: 0x111,
        26: 0x111,
        30: 0x111,
        31: program.data[0].value,
    }
    for reg, expected in expected_gr.items():
        _require(
            snapshot.gr[reg] == expected,
            "branch-register move r{} expected 0x{:x}, got 0x{:x}".format(
                reg, expected, snapshot.gr[reg]
            ),
        )
    _require(
        snapshot.nat_low == (1 << 31) and snapshot.nat_high == 0,
        "qualified/nullified BR moves expected only NaT(r31), got "
        "0x{:x}:0x{:x}".format(snapshot.nat_high, snapshot.nat_low),
    )
    _require(snapshot.pr == 0x41,
             "branch-register predication expected PR=0x41, got 0x{:x}"
             .format(snapshot.pr))

    fault_program = branch_register_nat_fault_program()
    fault_raw = mov_grbr(2, 4, qp=6)
    fault = run_program(
        qemu,
        fault_program,

        preserve_fault_slot=True,
        typed_nat_fault_trace_ip=0x90,
        typed_direct_trace_ips=(0x80,),
        one_bundle_per_tb=True,
    )
    _require_register_nat_consumption(
        fault,
        fault_ip=0x90,
        fault_slot=1,
        fault_raw=fault_raw,
        expected_iipa=0x90,
    )
    _require(
        fault.gr[4] == 85 and fault.nat_low == 0 and fault.nat_high == 0,
        "fault did not retire the r4/NaT overwrite before consuming its "
        "saved group-entry pair",
    )
    _require(
        fault.br[1] == 0x111 and fault.br[2] == 0 and
        fault.br[3] == 0x333,
        "Register NaT Consumption did not commit only the BR prefix: "
        "b1=0x{:x} b2=0x{:x} b3=0x{:x}".format(
            fault.br[1], fault.br[2], fault.br[3]
        ),
    )
    _require(fault.pr == 0x41,
             "faulting MOV_GRBR changed its qualifying predicate image")

    return (
        "I21/I22 direct TCG covers unconditional and true/false-qualified "
        "moves, GR/BR destination WAWs, NaT-clear/nullification ordering, "
        "and a forced cross-TB ordinary b5 shadow; qualified MOV_GRBR "
        "raises exact slot-1 Register NaT Consumption after committing only "
        "its earlier GR/BR prefix"
    )


def test_pfs_register_moves(qemu: Path) -> str:
    """Architectural, IR, fault, and migration goldens for AR.PFS moves."""
    program = pfs_register_move_program()
    snapshot = run_program(
        qemu,
        program,

        typed_pfs_move_traces=(
            (0x90, True, True, False, True),
            (0xa0, True, False, True, False),
            (0xb0, True, False, False, False),
            (0xc0, False, True, False, True),
            (0xd0, True, False, True, False),
            (0xe0, True, False, False, False),
            (0xf0, True, True, True, True),
            (0x100, True, False, True, False),
            (0x110, True, False, False, False),
            (0x130, True, False, False, False),
        ),
        one_bundle_per_tb=True,
    )
    _require(snapshot.ip == program.terminal_ip,
             "AR.PFS move program missed its terminal bundle")
    _require(not snapshot.exception_pending and
             snapshot.exception_kind == "none",
             "false-qualified NaT PFS source unexpectedly faulted")
    expected = {
        20: 0x111,
        21: 0x111,
        22: 0x222,
        23: 0x222,
        24: 0x444,
        25: 0x444,
        26: 0x444,
        27: 0x444,
        28: 0x555,
        29: 0x444,
        30: 0,
        31: program.data[0].value,
    }
    for reg, value in expected.items():
        _require(
            snapshot.gr[reg] == value,
            "AR.PFS move r{} expected 0x{:x}, got 0x{:x}".format(
                reg, value, snapshot.gr[reg]
            ),
        )
    _require(snapshot.gr[0] == 0, "AR.PFS moves changed architectural r0")
    _require(
        snapshot.nat_low == (1 << 31) and snapshot.nat_high == 0,
        "AR.PFS reads must clear only qualified destination NaT(r30); got "
        "0x{:x}:0x{:x}".format(snapshot.nat_high, snapshot.nat_low),
    )
    _require(snapshot.pr == 0x41,
             "AR.PFS qualification matrix expected PR=0x41, got 0x{:x}"
             .format(snapshot.pr))

    fault_program = pfs_register_nat_fault_program()
    fault_raw = mov_gr_to_pfs(4, qp=6)
    fault = run_program(
        qemu,
        fault_program,

        preserve_fault_slot=True,
        typed_nat_fault_trace_ip=0x90,
        typed_pfs_move_traces=(
            (0x90, True, True, True, True),
            (IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
             True, False, False, False),
        ),
        one_bundle_per_tb=True,
    )
    _require_register_nat_consumption(
        fault,
        fault_ip=0x90,
        fault_slot=1,
        fault_raw=fault_raw,
        expected_iipa=0x90,
        terminal_ip=fault_program.terminal_ip,
    )
    _require(
        fault.gr[4] == 85 and fault.nat_low == 0 and fault.nat_high == 0,
        "fault did not commit the prior r4/NaT overwrite",
    )
    _require(
        fault.gr[23] == 66 and fault.gr[24] == 0x111 and
        fault.gr[25] == 0,
        "faulting PFS write changed PFS/overlay or executed its suffix: "
        "r23=0x{:x} handler-PFS=0x{:x} suffix=0x{:x}".format(
            fault.gr[23], fault.gr[24], fault.gr[25]
        ),
    )
    _require(fault.pr == 0x41,
             "faulting PFS write changed its qualifying predicate image")

    migration_program = pfs_register_migration_program()
    migration = run_savevm_migration(
        qemu, migration_program, checkpoint_ip=0x40
    )
    _require(not migration.checkpoint.exception_pending,
             "PFS-overlay source checkpoint has a pending exception")
    _require(
        migration.checkpoint.ip == 0x40 and
        migration.checkpoint.gr[10] == 0x111 and
        migration.checkpoint.gr[11] == 0x222 and
        migration.checkpoint.gr[20] == 0 and
        migration.checkpoint.gr[21] == 0 and
        migration.checkpoint.gr[22] == 0,
        "source did not stop after exactly the open PFS producer",
    )
    restored_differences = snapshot_differences(
        migration.checkpoint, migration.restored
    )
    _require(
        not restored_differences,
        "fresh QEMU did not restore the exact visible PFS checkpoint:\n  "
        + "\n  ".join(restored_differences),
    )
    _require(not migration.final.exception_pending and
             migration.final.ip == migration_program.terminal_ip,
             "PFS-overlay migration destination did not terminate cleanly")
    _require(
        migration.final.gr[20] == 0x111 and
        migration.final.gr[21] == 0x111 and
        migration.final.gr[22] == 0x222,
        "restored PFS overlay lost saved A or live B: "
        "r20=0x{:x} r21=0x{:x} r22=0x{:x}".format(
            migration.final.gr[20], migration.final.gr[21],
            migration.final.gr[22]
        ),
    )
    _require_typed_pfs_move_trace(
        migration.source_trace, 0x30, False, True, False, True
    )
    _require_typed_pfs_move_trace(
        migration.destination_trace, 0x40, True, False, True, False
    )
    _require_pfs_shadow_savevm_trace(
        migration.source_trace, migration.destination_trace, 0x30, 0x40
    )

    def is_pfs_move(raw: int) -> bool:
        return (
            ((raw >> 37) & 0xf) == 0 and
            ((raw >> 27) & 0x3f) in (0x2a, 0x32) and
            ((raw >> 20) & 0x7f) == IA64_AR_PFS
        )

    encoding_count = sum(
        is_pfs_move(raw)
        for corpus_program in (program, fault_program, migration_program)
        for bundle in corpus_program.bundles
        for raw in (bundle.slot0, bundle.slot1, bundle.slot2)
    )
    _require(
        encoding_count == 26,
        "AR.PFS corpus drifted from 26 exact encodings to {}".format(
            encoding_count
        ),
    )
    return (
        "26 exact legal I26/I28 AR.PFS encodings across three forced-TB "
        "programs cover p0/true/false qualification, r0 source, first-write and "
        "last-live WAW ordering, stopped/no-stop ordinary visibility, NaT "
        "nullification and precise prefix faulting, plus a real two-QEMU "
        "save/load of saved/live PFS and branch-forward provenance"
    )


def _require_illegal_operation(snapshot: Snapshot, *, fault_ip: int,
                               fault_slot: int, fault_raw: int,
                               collection_enabled: bool,
                               expected_iipa: Optional[int],
                               expected_slot_type: int = IA64_SLOT_TYPE_I,
                               expected_ni: Optional[bool] = None) -> None:
    if expected_ni is None:
        expected_ni = not collection_enabled
    expected_isr = fault_slot << IA64_ISR_EI_SHIFT
    if expected_ni:
        expected_isr |= IA64_ISR_NI

    _require(
        snapshot.ip == IA64_GENERAL_EXCEPTION_VECTOR,
        "Illegal Operation did not enter vector 0x{:x}".format(
            IA64_GENERAL_EXCEPTION_VECTOR
        ),
    )
    _require(not snapshot.psr_ic_inflight,
             "interruption entry did not serialize PSR.ic state")
    _require(snapshot.exception_pending,
             "Illegal Operation did not leave a pending exception record")
    _require(
        snapshot.exception_kind == "illegal-operation",
        "expected illegal-operation, got {!r}".format(
            snapshot.exception_kind
        ),
    )
    _require(
        snapshot.exception_vector == IA64_GENERAL_EXCEPTION_VECTOR,
        "exception record has vector 0x{:x}, expected 0x{:x}".format(
            snapshot.exception_vector, IA64_GENERAL_EXCEPTION_VECTOR
        ),
    )
    _require(
        snapshot.exception_source == fault_ip and
        snapshot.exception_address == fault_ip,
        "exception source/address expected 0x{:x}, got 0x{:x}/0x{:x}".format(
            fault_ip, snapshot.exception_source, snapshot.exception_address
        ),
    )
    _require(
        snapshot.cr_isr == expected_isr,
        "slot {} Illegal Operation expected ISR=0x{:x}, got 0x{:x}".format(
            fault_slot, expected_isr, snapshot.cr_isr
        ),
    )
    _require(snapshot.slot_valid, "faulting slot was not published")
    _require(
        snapshot.slot_ip == fault_ip and snapshot.slot_ri == fault_slot,
        "fault slot expected 0x{:x}:{}; got 0x{:x}:{}".format(
            fault_ip, fault_slot, snapshot.slot_ip, snapshot.slot_ri
        ),
    )
    _require(
        snapshot.slot_type == expected_slot_type and
        snapshot.slot_raw == (fault_raw & SLOT_MASK),
        "fault slot type/raw expected {}/0x{:x}, got {}/0x{:x}".format(
            expected_slot_type, fault_raw & SLOT_MASK,
            snapshot.slot_type, snapshot.slot_raw
        ),
    )

    if collection_enabled:
        _require(
            snapshot.cr_iip == fault_ip,
            "collected IIP expected 0x{:x}, got 0x{:x}".format(
                fault_ip, snapshot.cr_iip
            ),
        )
        _require(
            (snapshot.cr_ipsr & IA64_PSR_IC) != 0,
            "collected IPSR did not preserve PSR.ic",
        )
        _require(
            ((snapshot.cr_ipsr >> IA64_PSR_RI_SHIFT) & 3) == fault_slot,
            "collected IPSR.ri does not identify slot {}".format(fault_slot),
        )
    if expected_iipa is not None:
        _require(
            snapshot.cr_iipa == expected_iipa,
            "collected IIPA expected 0x{:x}, got 0x{:x}".format(
                expected_iipa, snapshot.cr_iipa
            ),
        )


def test_equal_target_precise_faults(qemu: Path) -> str:
    predicated_off = run_program(
        qemu, equal_target_predicated_off_program(),
        preserve_fault_slot=True,
        typed_fault_trace_ip=0x40,
    )
    _require(not predicated_off.exception_pending,
             "false-qp normal equal-target compare unexpectedly faulted")
    _require(predicated_off.exception_kind == "none",
             "false-qp normal compare left a non-none exception kind")
    _require(predicated_off.pr == ((1 << 0) | (1 << 10)),
             "false-qp equal-target compare changed its destination")
    _require(predicated_off.gr[22] == 0x55,
             "instruction after false-qp compare did not execute")

    prefix = run_program(
        qemu, equal_target_prefix_fault_program(),
        preserve_fault_slot=True,
        typed_fault_trace_ip=0x50,
    )
    _require_illegal_operation(
        prefix,
        fault_ip=0x50,
        fault_slot=1,
        fault_raw=cmp_rr(12, 12, 0, 0, "eq"),
        collection_enabled=True,
        expected_iipa=0x50,
    )
    _require(prefix.pr == ((1 << 0) | (1 << 1) | (1 << 12)),
             "fault did not commit prior PR writes or changed p12")
    _require(prefix.gr[20] == 77,
             "fault did not commit an earlier same-group GR write")
    _require(prefix.gr[21] == 0,
             "instruction after the fault executed")

    unc = run_program(
        qemu, equal_target_unc_nat_fault_program(),
        preserve_fault_slot=True,
        typed_fault_trace_ip=0x70,
    )
    _require_illegal_operation(
        unc,
        fault_ip=0x70,
        fault_slot=2,
        fault_raw=cmp_rr(14, 14, 4, 4, "eq", unc=True, qp=15),
        collection_enabled=True,
        expected_iipa=0x70,
    )
    _require(unc.pr == ((1 << 0) | (1 << 14)),
             "false-qp cmp.unc cleared its equal predicate destination")
    _require(unc.gr[4] == 0x123456789abcdef0 and unc.nat_low == (1 << 4),
             "equal-target fault consumed or changed its NaT source")
    _require(unc.gr[23] == 66,
             "cmp.unc fault lost its earlier same-group write")
    _require(unc.gr[24] == 0,
             "instruction after cmp.unc fault executed")

    old_true_alias = run_program(
        qemu, equal_target_old_true_alias_program(),
        preserve_fault_slot=True,
        typed_fault_trace_ip=0x20,
    )
    _require_illegal_operation(
        old_true_alias,
        fault_ip=0x20,
        fault_slot=1,
        fault_raw=cmp_rr(9, 9, 0, 0, "eq", qp=9),
        collection_enabled=False,
        expected_iipa=None,
    )
    _require(old_true_alias.pr == ((1 << 0) | (1 << 9)),
             "qp/p1/p2 alias did not preserve its old-true predicate")
    _require(old_true_alias.gr[26] == 0,
             "instruction after old-true alias fault executed")

    return ("normal and .unc equal-target rules, exact EI/NI fault state, "
            "NaT priority, prefix commit, and old-true qp alias all match "
            "the architectural contract; deterministic TCG op traces reject "
            "generic execution-helper dispatch for every tested bundle")


def _require_data_tlb_outcome(snapshot: Snapshot, *, kind: str,
                              vector: int, expected_isr: int) -> None:
    _require(
        snapshot.ip == vector,
        "{} did not enter vector 0x{:x}; got 0x{:x}".format(
            kind, vector, snapshot.ip
        ),
    )
    _require(snapshot.exception_pending,
             "{} did not leave a pending exception record".format(kind))
    _require(not snapshot.psr_ic_inflight,
             "{} entry did not serialize PSR.ic state".format(kind))
    _require(
        snapshot.exception_kind == kind,
        "expected {}, got {!r}".format(kind, snapshot.exception_kind),
    )
    _require(
        snapshot.exception_vector == vector and
        snapshot.exception_source == 0x60 and
        snapshot.exception_address == 0x1000,
        "{} record expected vector/source/address 0x{:x}/0x60/0x1000, "
        "got 0x{:x}/0x{:x}/0x{:x}".format(
            kind, vector, snapshot.exception_vector,
            snapshot.exception_source, snapshot.exception_address
        ),
    )
    _require(
        snapshot.cr_isr == expected_isr,
        "{} expected CR.ISR=0x{:x}, got 0x{:x}".format(
            kind, expected_isr, snapshot.cr_isr
        ),
    )
    _require(
        snapshot.cr_ipsr == 0 and snapshot.cr_iip == 0 and
        snapshot.cr_iipa == 0 and snapshot.cr_ifa == 0,
        "IC=0 fault changed collection-only resources: "
        "IPSR=0x{:x} IIP=0x{:x} IIPA=0x{:x} IFA=0x{:x}".format(
            snapshot.cr_ipsr, snapshot.cr_iip,
            snapshot.cr_iipa, snapshot.cr_ifa
        ),
    )


def test_psr_ic_inflight_policy(qemu: Path) -> str:
    fault = cmp_rr(12, 12, 0, 0, "eq")

    serialized_i = run_program(
        qemu,
        psr_ic_illegal_program(
            "IC=1 serialized by srlz.i", srlz_i()
        ),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x30,
    )
    _require_illegal_operation(
        serialized_i,
        fault_ip=0x30,
        fault_slot=1,
        fault_raw=fault,
        collection_enabled=True,
        expected_iipa=0x30,
        expected_ni=False,
    )

    serialized_d = run_program(
        qemu,
        psr_ic_illegal_program(
            "IC=1 serialized by srlz.d", srlz_d()
        ),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x30,
    )
    _require_illegal_operation(
        serialized_d,
        fault_ip=0x30,
        fault_slot=1,
        fault_raw=fault,
        collection_enabled=True,
        expected_iipa=0x30,
        expected_ni=False,
    )

    immediate = run_program(
        qemu,
        psr_ic_immediate_fault_program(),

        preserve_fault_slot=True,
    )
    immediate_expected_isr = (1 << IA64_ISR_EI_SHIFT) | IA64_ISR_R | IA64_ISR_NI
    _require(
        immediate.ip == IA64_UNALIGNED_DATA_REFERENCE_VECTOR and
        immediate.exception_pending and
        immediate.exception_kind == "unaligned-data-reference" and
        immediate.exception_vector == IA64_UNALIGNED_DATA_REFERENCE_VECTOR and
        immediate.exception_source == 0x20 and
        immediate.exception_address == 0xFFF,
        "immediate post-SSM load did not raise precise Unaligned Data Reference",
    )
    _require(
        immediate.slot_valid and immediate.slot_ip == 0x20 and
        immediate.slot_ri == 1 and immediate.slot_type == IA64_SLOT_TYPE_M and
        immediate.slot_raw == ld8_fill(10, 9),
        "immediate post-SSM fault did not publish exact M-slot state",
    )
    _require(
        immediate.cr_isr == immediate_expected_isr and
        immediate.cr_iip == 0x20 and immediate.cr_ifa == 0xFFF and
        immediate.cr_iipa == 0 and
        (immediate.cr_ipsr & IA64_PSR_IC) != 0 and
        ((immediate.cr_ipsr >> IA64_PSR_RI_SHIFT) & 3) == 1,
        "immediate post-SSM fault has wrong ISR/IIP/IFA/IIPA/IPSR",
    )
    _require(not immediate.psr_ic_inflight,
             "immediate fault entry did not serialize PSR.ic state")

    sync_retained = run_program(
        qemu,
        psr_ic_illegal_program(
            "sync.i retains an in-flight IC transition", sync_i()
        ),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x30,
    )
    _require_illegal_operation(
        sync_retained,
        fault_ip=0x30,
        fault_slot=1,
        fault_raw=fault,
        collection_enabled=True,
        expected_iipa=0x30,
        expected_ni=True,
    )

    nested = run_program(
        qemu,
        psr_ic_data_tlb_program(
            "IC=0 serialized Data Nested TLB", srlz_d(),
            IA64_DATA_NESTED_TLB_VECTOR,
        ),

    )
    _require_data_tlb_outcome(
        nested,
        kind="data-nested-tlb",
        vector=IA64_DATA_NESTED_TLB_VECTOR,
        # Data Nested preserves the pre-existing interruption resources.
        expected_isr=0,
    )

    in_flight_miss = run_program(
        qemu,
        psr_ic_data_tlb_program(
            "IC=0 in-flight Alternate Data TLB", sync_i(),
            IA64_ALTERNATE_DATA_TLB_VECTOR,
        ),

    )
    _require_data_tlb_outcome(
        in_flight_miss,
        kind="alternate-data-tlb-miss",
        vector=IA64_ALTERNATE_DATA_TLB_VECTOR,
        expected_isr=IA64_ISR_R | IA64_ISR_NI,
    )

    rfi_snapshot = run_program(
        qemu,
        psr_ic_rfi_serialization_program(),

        preserve_fault_slot=True,
        typed_fault_trace_ip=0x50,
        typed_rfi_traces=(0x5440,),
    )
    _require(
        rfi_snapshot.exception_pending and
        rfi_snapshot.exception_kind == "illegal-operation" and
        rfi_snapshot.exception_vector == IA64_GENERAL_EXCEPTION_VECTOR and
        rfi_snapshot.exception_source == 0x50 and
        rfi_snapshot.exception_address == 0x50,
        "RFI round trip did not reach the second Illegal Operation",
    )
    _require(
        rfi_snapshot.cr_isr == (1 << IA64_ISR_EI_SHIFT),
        "RFI did not clear the handler-created IC transition: "
        "second ISR=0x{:x}".format(rfi_snapshot.cr_isr),
    )
    _require(
        (rfi_snapshot.cr_ipsr & IA64_PSR_IC) != 0 and
        rfi_snapshot.cr_iip == 0x50 and rfi_snapshot.cr_iipa == 0x50,
        "second collected fault after RFI has wrong IPSR/IIP/IIPA: "
        "0x{:x}/0x{:x}/0x{:x}".format(
            rfi_snapshot.cr_ipsr, rfi_snapshot.cr_iip,
            rfi_snapshot.cr_iipa
        ),
    )
    _require((rfi_snapshot.pr & (1 << 1)) == 0,
             "first-entry handler did not nullify the resumed first fault")
    _require(
        rfi_snapshot.gr[8] == 1,
        "RFI did not restore IPSR.ri=1 exactly; pre-fault slot 0 replayed "
        "{} times".format(rfi_snapshot.gr[8]),
    )


    _require(not rfi_snapshot.psr_ic_inflight,
             "second interruption entry left PSR.ic transition in flight")

    migration = run_savevm_migration(
        qemu, psr_ic_migration_program(), checkpoint_ip=0x20,
        preserve_fault_slot=True,
    )
    _require(
        migration.checkpoint.ip == 0x20 and
        (migration.checkpoint.psr & IA64_PSR_IC) != 0 and
        migration.checkpoint.psr_ic_inflight,
        "source checkpoint did not capture visible IC=1/in-flight state",
    )
    checkpoint_arch = dataclasses.replace(
        migration.checkpoint, slot_valid=False, slot_ip=0, slot_ri=0,
        slot_type=0, slot_raw=0
    )
    restored_arch = dataclasses.replace(
        migration.restored, slot_valid=False, slot_ip=0, slot_ri=0,
        slot_type=0, slot_raw=0
    )
    migration_differences = snapshot_differences(
        checkpoint_arch, restored_arch
    )
    _require(
        not migration_differences,
        "fresh QEMU did not restore exact in-flight PSR.ic state:\n  " +
        "\n  ".join(migration_differences),
    )
    _require(
        migration.final.ip == IA64_UNALIGNED_DATA_REFERENCE_VECTOR and
        migration.final.exception_kind == "unaligned-data-reference" and
        migration.final.exception_source == 0x30 and
        migration.final.exception_address == 0xFFF and
        migration.final.slot_valid and migration.final.slot_ip == 0x30 and
        migration.final.slot_ri == 0 and
        migration.final.slot_type == IA64_SLOT_TYPE_M and
        migration.final.slot_raw == ld8_fill(10, 9),
        "migrated in-flight state did not reach the precise destination fault",
    )
    _require(
        migration.final.cr_isr == (IA64_ISR_R | IA64_ISR_NI) and
        migration.final.cr_iip == 0x30 and
        migration.final.cr_ifa == 0xFFF and
        migration.final.cr_iipa == 0x20 and
        not migration.final.psr_ic_inflight,
        "migrated fault lost NI, collection state, IIPA, or entry serialization",
    )

    return (
        "all four visible-IC/in-flight rows pass: srlz.i and srlz.d clear "
        "the transition, sync.i retains it, immediate post-SSM IIPA uses "
        "pre-instruction IC, serialized IC=0 selects Data Nested while "
        "in-flight IC=0 keeps Alternate Data TLB, RFI clears a "
        "handler-created transition, and a fresh-QEMU savevm round trip "
        "preserves the in-flight bit"
    )


def timer_external_interrupt_rfi_program() -> Program:
    """Arm CR.ITM in guest code and return from the real CPU interrupt hook."""
    return Program(
        name="timer HARD to cpu_exec_interrupt to typed RFI",
        bundles=(
            # Capture the clock-backed ITC while constructing an unmasked,
            # architecturally valid local timer vector and a deadline delta.
            # A one-tick deadline can already be stale by the CR.ITM write;
            # use 2^24 ticks so this tests a genuinely armed future equality.
            Bundle(0x10, 0x01, mov_m_argr(10, IA64_AR_ITC),
                   adds(12, 0x40, 0), adds(13, 1, 0)),
            Bundle(0x20, 0x01, nop_m(), shl_imm(13, 13, 24), nop_i()),
            Bundle(0x30, 0x01, nop_m(), add(11, 10, 13), nop_i()),
            Bundle(0x40, 0x01, mov_grcr(IA64_CR_ITV, 12),
                   nop_i(), nop_i()),
            Bundle(0x50, 0x01, mov_grcr(IA64_CR_ITM, 11),
                   nop_i(), nop_i()),
            # The timer callback may only kick HARD; the vCPU interrupt hook
            # must latch IRR and deliver the external vector once it expires.
            Bundle(0x60, 0x01, ssm(IA64_PSR_IC | IA64_PSR_I),
                   nop_i(), nop_i()),
            # Poll the handler marker.  Whichever loop bundle was interrupted
            # is resumed by RFI before p1 can select the terminal spin.
            Bundle(0x70, 0x01, nop_m(),
                   cmp_rr(1, 2, 0, 20, "lt"), nop_i()),
            Bundle(0x80, 0x11, nop_m(), nop_i(),
                   br_cond(0x80, 0xa0, qp=1)),
            Bundle(0x90, 0x11, nop_m(), nop_i(), br_cond(0x90, 0x70)),
            spin_bundle(0xa0),
            # External-interrupt vector.  Reading IVR consumes the pending
            # vector and proves the architectural IRR/IVR path ran; r20 is the
            # independently visible handler marker.
            Bundle(0x3000, 0x01, mov_crgr(15, IA64_CR_IVR),
                   adds(20, 1, 0), nop_i()),
            Bundle(0x3010, 0x11, nop_m(), nop_i(), rfi()),
        ),
        terminal_ip=0xa0,
    )


def nested_self_ipi_program() -> Program:
    """Nest a higher-priority self-IPI behind an in-service base vector."""
    return Program(
        name="per-vector Local-SAPIC nested self-IPI and ordered EOI",
        bundles=(
            # Load the Processor Interrupt Block address, queue vector 0x40
            # while PSR.i=0, then enable collection and delivery in distinct
            # serialized steps.  r24 is set only after both handlers unwind.
            Bundle(0x10, 0x01, nop_m(), adds(3, 0x1000, 0),
                   adds(4, 0x40, 0)),
            Bundle(0x20, 0x01, ld8(2, 3), adds(5, 0x80, 0), nop_i()),
            Bundle(0x30, 0x01, st8(4, 2), nop_i(), nop_i()),
            Bundle(0x40, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
            Bundle(0x50, 0x01, srlz_d(), nop_i(), nop_i()),
            Bundle(0x60, 0x01, ssm(IA64_PSR_I), nop_i(), nop_i()),
            Bundle(0x70, 0x01, nop_m(),
                   cmp_rr(1, 2, 0, 24, "lt"), nop_i()),
            Bundle(0x80, 0x11, nop_m(), nop_i(),
                   br_cond(0x80, 0xa0, qp=1)),
            Bundle(0x90, 0x11, nop_m(), nop_i(), br_cond(0x90, 0x70)),
            spin_bundle(0xa0),

            # Both deliveries enter the same external-interrupt vector.  The
            # IVR read atomically moves the selected vector from IRR to ISR;
            # dispatch in a later group so it observes the new r15 value.
            Bundle(0x3000, 0x01, mov_crgr(15, IA64_CR_IVR),
                   nop_i(), nop_i()),
            Bundle(0x3010, 0x01, nop_m(),
                   cmp_rr(1, 2, 5, 15, "eq"), nop_i()),
            Bundle(0x3020, 0x11, nop_m(), nop_i(),
                   br_cond(0x3020, 0x3180, qp=1)),

            # Outer vector 0x40: preserve its interruption resources before
            # allowing the nested vector to overwrite CR.IIP/IPSR/IFS.  The
            # higher vector is queued with I=0, then IC is serialized before
            # I is enabled.  A single-latch model hangs in the marker loop.
            Bundle(0x3030, 0x01, nop_m(), adds(22, 0, 15),
                   adds(20, 1, 20)),
            Bundle(0x3040, 0x01, mov_crgr(8, IA64_CR_IIP),
                   nop_i(), nop_i()),
            Bundle(0x3050, 0x01, mov_crgr(9, IA64_CR_IPSR),
                   nop_i(), nop_i()),
            Bundle(0x3060, 0x01, mov_crgr(10, IA64_CR_IFS),
                   nop_i(), nop_i()),
            Bundle(0x3070, 0x01, st8(5, 2), nop_i(), nop_i()),
            Bundle(0x3080, 0x01, ssm(IA64_PSR_IC), nop_i(), nop_i()),
            Bundle(0x3090, 0x01, srlz_d(), nop_i(), nop_i()),
            Bundle(0x30a0, 0x01, ssm(IA64_PSR_I), nop_i(), nop_i()),
            Bundle(0x30b0, 0x01, nop_m(),
                   cmp_rr(1, 2, 0, 21, "lt"), nop_i()),
            Bundle(0x30c0, 0x11, nop_m(), nop_i(),
                   br_cond(0x30c0, 0x30e0, qp=1)),
            Bundle(0x30d0, 0x11, nop_m(), nop_i(),
                   br_cond(0x30d0, 0x30b0)),

            # CR interruption resources cannot be accessed with PSR.ic=1.
            # Disable I and IC together, serialize, restore the outer image,
            # and EOI.  EOI must now remove vector 0x40, since the nested path
            # removed only the highest in-service vector 0x80.
            Bundle(0x30e0, 0x01, rsm(IA64_PSR_IC | IA64_PSR_I),
                   nop_i(), nop_i()),
            Bundle(0x30f0, 0x01, srlz_d(), nop_i(), nop_i()),
            Bundle(0x3100, 0x01, mov_grcr(IA64_CR_IIP, 8),
                   nop_i(), nop_i()),
            Bundle(0x3110, 0x01, mov_grcr(IA64_CR_IPSR, 9),
                   nop_i(), nop_i()),
            Bundle(0x3120, 0x01, mov_grcr(IA64_CR_IFS, 10),
                   nop_i(), nop_i()),
            Bundle(0x3130, 0x01, mov_grcr(IA64_CR_EOI, 0),
                   adds(24, 1, 0), nop_i()),
            Bundle(0x3140, 0x11, nop_m(), nop_i(), rfi()),

            # Nested vector 0x80: record exact IVR selection, EOI only the
            # highest in-service vector, and return to the outer handler.
            Bundle(0x3180, 0x01, nop_m(), adds(23, 0, 15),
                   adds(21, 1, 21)),
            Bundle(0x3190, 0x01, mov_grcr(IA64_CR_EOI, 0),
                   nop_i(), nop_i()),
            Bundle(0x31a0, 0x11, nop_m(), nop_i(), rfi()),
        ),
        terminal_ip=0xa0,
        data=(DataWord(0x1000, 0xfee00000, 8),),
    )


def privileged_rfi_program() -> Program:
    """Execute RFI at CPL3 with a visible successful same-group prefix."""
    return Program(
        name="typed RFI current-CPL privileged-operation fault",
        bundles=(
            Bundle(0x10, 0x01, nop_m(), adds(9, 0x1000, 0),
                   adds(8, 0x1008, 0)),
            Bundle(0x20, 0x01, ld8(10, 9), nop_i(), nop_i()),
            Bundle(0x30, 0x01, ld8(11, 8), nop_i(), nop_i()),
            Bundle(0x40, 0x01, nop_m(), adds(12, 0xa0, 0),
                   adds(13, 0x200, 0)),
            Bundle(0x50, 0x01, nop_m(), mov_gr_to_pfs(10),
                   mov_grbr(6, 12)),
            # Poison the saved RFI target.  A premature restore reaches 0x200
            # instead of the General Exception vector.
            Bundle(0x60, 0x01, mov_grcr(IA64_CR_IIP, 13),
                   nop_i(), nop_i()),
            Bundle(0x70, 0x01, mov_gr_to_psr_l(11), nop_i(), nop_i()),
            Bundle(0x80, 0x01, srlz_i(), nop_i(), nop_i()),
            Bundle(0x90, 0x11, nop_m(), nop_i(), br_ret(6)),
            # Slot 1 is the successful prefix.  Slot 2 must fault before RFI
            # retirement, CR restoration, target commit, or mandatory fills.
            Bundle(0xa0, 0x11, nop_m(), adds(20, 1, 20), rfi()),
            spin_bundle(0x200),
            _illegal_vector_spin(),
        ),
        terminal_ip=IA64_GENERAL_EXCEPTION_VECTOR,
        data=(
            DataWord(0x1000, 3 << 62, 8),
            DataWord(0x1008, IA64_PSR_IC, 8),
        ),
    )


def test_timer_external_interrupt_rfi(qemu: Path) -> str:
    snapshot = run_program(
        qemu,
        timer_external_interrupt_rfi_program(),

        typed_rfi_traces=(0x3010,),
        one_bundle_per_tb=True,
    )
    _require(
        snapshot.ip == 0xa0 and snapshot.gr[20] == 1 and
        snapshot.gr[15] == 0x40,
        "guest timer handler did not consume vector 0x40 and return: "
        "IP=0x{:x} marker={} IVR=0x{:x}".format(
            snapshot.ip, snapshot.gr[20], snapshot.gr[15]
        ),
    )
    _require(
        snapshot.exception_pending and
        snapshot.exception_kind == "external-interrupt" and
        snapshot.exception_vector == 0x3000 and
        snapshot.exception_source in (0x60, 0x70, 0x80, 0x90),
        "HARD did not traverse cpu_exec_interrupt and architectural external "
        "delivery: kind={!r} vector=0x{:x} source=0x{:x}".format(
            snapshot.exception_kind, snapshot.exception_vector,
            snapshot.exception_source,
        ),
    )
    _require(
        (snapshot.cr_ipsr & (IA64_PSR_IC | IA64_PSR_I)) ==
        (IA64_PSR_IC | IA64_PSR_I) and
        (snapshot.cr_isr & (IA64_ISR_R | IA64_ISR_RS | IA64_ISR_IR)) == 0,
        "external delivery/RFI did not preserve enabled IPSR or produced "
        "memory/RSE ISR bits: IPSR=0x{:x} ISR=0x{:x}".format(
            snapshot.cr_ipsr, snapshot.cr_isr
        ),
    )

    privileged = run_program(
        qemu,
        privileged_rfi_program(),

        preserve_fault_slot=True,
        typed_rfi_traces=(0xa0,),
        one_bundle_per_tb=True,
    )
    expected_isr = (2 << IA64_ISR_EI_SHIFT) | 0x10
    _require(
        privileged.ip == IA64_GENERAL_EXCEPTION_VECTOR and
        privileged.exception_pending and
        privileged.exception_kind == "general-exception" and
        privileged.exception_vector == IA64_GENERAL_EXCEPTION_VECTOR and
        privileged.exception_source == 0xa0 and
        privileged.exception_address == 0xa0,
        "CPL3 RFI did not deliver its General Exception at the issuing "
        "bundle: IP=0x{:x} kind={!r} vector/source/address="
        "0x{:x}/0x{:x}/0x{:x}".format(
            privileged.ip, privileged.exception_kind,
            privileged.exception_vector, privileged.exception_source,
            privileged.exception_address,
        ),
    )
    _require(
        privileged.cr_isr == expected_isr and
        privileged.cr_iip == 0xa0 and privileged.cr_iipa == 0xa0 and
        ((privileged.cr_ipsr >> 32) & 3) == 3 and
        ((privileged.cr_ipsr >> IA64_PSR_RI_SHIFT) & 3) == 2 and
        (privileged.cr_ipsr & IA64_PSR_IC) != 0,
        "CPL3 RFI expected ISR.code=0x10/EI2 and pre-restore CPL3/RI2: "
        "ISR=0x{:x} IIP/IIPA=0x{:x}/0x{:x} IPSR=0x{:x}".format(
            privileged.cr_isr, privileged.cr_iip, privileged.cr_iipa,
            privileged.cr_ipsr,
        ),
    )
    _require(
        privileged.slot_valid and privileged.slot_ip == 0xa0 and
        privileged.slot_ri == 2 and privileged.slot_raw == rfi() and
        privileged.gr[20] == 1,
        "CPL3 RFI did not preserve the exact slot while retiring only its "
        "successful prefix: slot={}/0x{:x}/{} raw=0x{:x} r20={}".format(
            privileged.slot_valid, privileged.slot_ip, privileged.slot_ri,
            privileged.slot_raw, privileged.gr[20],
        ),
    )
    return (
        "guest CR.ITM expiry raises HARD, the vCPU cpu_exec_interrupt hook "
        "latches and delivers vector 0x40, the handler consumes IVR, and one "
        "typed RFI resumes the interrupted loop; a separate CPL3 RFI retires "
        "only its same-group prefix and delivers exact General Exception "
        "ISR.code=0x10 at RI2 before restoring poisoned CR state"
    )


def test_nested_self_ipi(qemu: Path) -> str:
    snapshot = run_program(
        qemu,
        nested_self_ipi_program(),

        typed_rfi_traces=(0x3140, 0x31a0),
        one_bundle_per_tb=True,
    )
    _require(
        snapshot.ip == 0xa0 and
        snapshot.gr[20] == 1 and snapshot.gr[21] == 1 and
        snapshot.gr[22] == 0x40 and snapshot.gr[23] == 0x80 and
        snapshot.gr[24] == 1,
        "nested self-IPI did not acquire/unwind each vector exactly once: "
        "IP=0x{:x} outer={} nested={} IVRs=0x{:x}/0x{:x} done={}".format(
            snapshot.ip, snapshot.gr[20], snapshot.gr[21],
            snapshot.gr[22], snapshot.gr[23], snapshot.gr[24]
        ),
    )
    _require(
        snapshot.exception_pending and
        snapshot.exception_kind == "external-interrupt" and
        snapshot.exception_vector == 0x3000 and
        snapshot.exception_source in (0x30a0, 0x30b0, 0x30c0, 0x30d0),
        "higher self-IPI did not interrupt the enabled outer handler: "
        "kind={!r} vector/source=0x{:x}/0x{:x}".format(
            snapshot.exception_kind, snapshot.exception_vector,
            snapshot.exception_source
        ),
    )
    _require(
        (snapshot.psr & (IA64_PSR_IC | IA64_PSR_I)) ==
        (IA64_PSR_IC | IA64_PSR_I),
        "nested/outer RFI did not restore enabled mainline PSR: "
        "PSR=0x{:x}".format(snapshot.psr),
    )
    return (
        "a guest self-IPI acquires vector 0x40, enables nesting, acquires "
        "higher vector 0x80 concurrently in service, EOIs 0x80 then 0x40, "
        "and executes two typed RFIs back to the interrupted mainline"
    )


def test_nat_golden(qemu: Path) -> str:
    program = nat_program()
    snapshot = run_program(qemu, program)
    data_value = program.data[0].value
    mask64 = (1 << 64) - 1
    architectural_nat = (
        sum(1 << reg for reg in range(10, 19))
        | sum(1 << reg for reg in range(20, 25))
    )
    _require(snapshot.ip == 0xb0, "NaT program did not stop at 0xb0")
    _require(snapshot.gr[8] == 1, "NaT setup did not create the UNAT mask")
    _require(snapshot.gr[9] == 0x1000, "NaT setup address is wrong")
    _require(snapshot.gr[10] == data_value, "ld8.fill value is wrong")
    _require(snapshot.gr[11] == data_value, "ADD value is wrong")
    _require(
        snapshot.gr[12] == (data_value + 1) & ((1 << 64) - 1),
        "ADDS value is wrong",
    )
    addp4_minus_one = (
        ((data_value - 1) & 0xffffffff)
        | (((data_value >> 30) & 3) << 61)
    )
    addp4_one = (
        ((data_value + 1) & 0xffffffff)
        | (((data_value >> 30) & 3) << 61)
    )
    propagated_values = {
        13: (data_value << 1) & mask64,
        14: (data_value << 4) & mask64,
        15: data_value & 0xff,
        16: mask64 - 0xf,
        17: data_value.bit_count(),
        18: addp4_minus_one,
        19: 0xff,
        20: 0,
        21: ((data_value << 60) | (1 >> 4)) & mask64,
        22: (data_value & ~0xff) | 1,
        23: data_value & 0xffffffff,
        24: addp4_one,
    }
    for reg, expected in propagated_values.items():
        _require(
            snapshot.gr[reg] == expected,
            "NaT payload r{} expected 0x{:x}, got 0x{:x}".format(
                reg, expected, snapshot.gr[reg]
            ),
        )
    _require(snapshot.unat == 1, "AR.UNAT setup was not preserved")
    _require(snapshot.nat_high == 0, "NaT golden set an unexpected high bit")
    _require(
        snapshot.nat_low == architectural_nat,
        "typed execution failed the architectural NaT golden: expected "
        "0x{:x}, got 0x{:x}".format(architectural_nat, snapshot.nat_low),
    )

    overlay_program = ordinary_source_nat_overlay_program()
    overlay = run_program(
        qemu, overlay_program,
        typed_direct_trace_ips=(0x40,),
    )
    _require(
        overlay.gr[10] == 1 and
        overlay.gr[11] == overlay_program.data[0].value,
        "saved ordinary GR value was not paired with its saved NaT",
    )
    _require(
        overlay.nat_low == (1 << 11) and overlay.nat_high == 0,
        "ordinary-source NaT overlay did not move the saved NaT to r11",
    )

    return (
        "typed execution matches the architectural NaT propagation bitmap "
        "and the saved ordinary-source GR+NaT overlay invariant"
    )


def test_typed_group_tb_continuation(qemu: Path) -> str:
    tested_lengths = (5, 6, 16)
    for bundle_count in tested_lengths:
        program = long_no_stop_scalar_program(bundle_count)
        group_ips = tuple(0x10 + index * 0x10
                          for index in range(bundle_count))
        snapshot = run_program(
            qemu,
            program,

            typed_direct_trace_ips=group_ips,
            typed_visibility_states=tuple(
                (bundle_ip, 3 if index == 0 else 2)
                for index, bundle_ip in enumerate(group_ips)
            ),
            one_bundle_per_tb=True,
        )
        _require(
            snapshot.ip == program.terminal_ip,
            "{}-bundle group did not reach terminal IP 0x{:x}".format(
                bundle_count, program.terminal_ip
            ),
        )
        _require(
            not snapshot.exception_pending,
            "{}-bundle group raised {} at 0x{:x}".format(
                bundle_count,
                snapshot.exception_kind,
                snapshot.exception_source,
            ),
        )
        for index in range(bundle_count):
            reg = index + 1
            expected = 0x100 + index
            _require(
                snapshot.gr[reg] == expected,
                "{}-bundle group expected r{}=0x{:x}, got 0x{:x}".format(
                    bundle_count, reg, expected, snapshot.gr[reg]
                ),
            )

    # Exercise the production reservation/op-budget split without the test
    # accelerator override.  All 16 bundles are on one guest page and have no
    # control-flow boundary, so multiple OP blocks prove automatic typed
    # segmentation rather than one-insn-per-tb or page-boundary behavior.
    automatic_program = long_no_stop_scalar_program(16)
    automatic_ips = tuple(0x10 + index * 0x10 for index in range(16))
    automatic = run_program(
        qemu,
        automatic_program,

        typed_direct_trace_ips=automatic_ips,
        typed_visibility_states=tuple(
            (bundle_ip, 3 if index == 0 else 2)
            for index, bundle_ip in enumerate(automatic_ips)
        ),
        automatic_segment_trace_ips=automatic_ips,
    )
    _require(automatic.ip == automatic_program.terminal_ip,
             "automatic 16-bundle segmentation missed its terminal IP")
    _require(not automatic.exception_pending,
             "automatic 16-bundle segmentation raised {} at 0x{:x}".format(
                 automatic.exception_kind, automatic.exception_source
             ))
    for index in range(16):
        reg = index + 1
        expected = 0x100 + index
        _require(
            automatic.gr[reg] == expected,
            "automatic segmentation expected r{}=0x{:x}, got 0x{:x}"
            .format(reg, expected, automatic.gr[reg]),
        )

    return (
        "5-, 6-, and 16-bundle no-stop scalar groups survive an explicit "
        "one-bundle-per-TB split, and the normal 16-bundle run segments "
        "automatically on its TCG op budget; every continuation segment has "
        "direct TCG operations and no exec_bundle/exec_slot call"
    )


def test_page_crossing_overlay_continuation(qemu: Path) -> str:
    program = page_crossing_overlay_continuation_program()
    snapshot = run_program(
        qemu,
        program,

        # These are the two halves of the same issue group.  Naming both IPs
        # makes the -d op trace reject generic dispatch on either side
        # of the 0xff0/0x1000 translation-page boundary.
        typed_direct_trace_ips=(0xfa0, 0xff0, 0x1000),
        typed_visibility_states=((0xfa0, 3), (0xff0, 3), (0x1000, 2)),
        overlay_dependency_trace=(0xfa0, 0xff0, 0x1000),
    )
    data_value = program.data[0].value

    _require(snapshot.ip == 0x1010,
             "page-crossing group did not reach its terminal branch")
    _require(not snapshot.exception_pending,
             "page-crossing group raised {} at 0x{:x}".format(
                 snapshot.exception_kind, snapshot.exception_source
             ))
    _require(snapshot.gr[10] == 1,
             "the retired 0xff0 write to r10 was lost")
    _require(snapshot.gr[1] == 5,
             "dependency-free control did not retire its live r1 write")
    _require(snapshot.gr[11] == data_value,
             "the 0x1000 consumer did not see saved group-entry r10")
    _require(snapshot.gr[12] == 99,
             "the 0x1000 qp=1 consumer did not see saved group-entry p1")
    _require(snapshot.nat_high == 0 and snapshot.nat_low == (1 << 11),
             "saved r10 NaT was not paired with its value across the page: "
             "got 0x{:x}:0x{:x}".format(
                 snapshot.nat_high, snapshot.nat_low
             ))
    _require(snapshot.pr == ((1 << 0) | (1 << 2)),
             "live predicate result after the closing stop is wrong: "
             "0x{:x}".format(snapshot.pr))

    return (
        "the dependency-free 0xfa0 group emits no saved-mask/PR-validity "
        "traffic, while the true 0xff0 producer persists exact GR+NaT/PR "
        "ordinary sources and selects them directly at 0x1000"
    )


def test_internal_stop_typed_handoff(qemu: Path) -> str:
    program = internal_stop_typed_handoff_program()
    snapshot = run_program(
        qemu,
        program,

        typed_direct_trace_ips=(0xff0,),
        typed_visibility_states=((0xff0, 3),),
        internal_stop_handoffs=(0x1000,),
        one_bundle_per_tb=True,
    )

    _require(snapshot.ip == 0x1010,
             "internal-stop handoff did not reach its terminal branch")
    _require(not snapshot.exception_pending,
             "internal-stop handoff raised {} at 0x{:x}".format(
                 snapshot.exception_kind, snapshot.exception_source
             ))
    _require(snapshot.gr[1] == 0 and snapshot.gr[2] == 0,
             "false-predicate open group unexpectedly wrote an overlay "
             "destination")
    _require(snapshot.gr[3] == 11,
             "typed prefix was lost or replayed from slot zero: expected "
             "r3=11, got 0x{:x}".format(snapshot.gr[3]))
    _require(snapshot.gr[8] == 0x1000,
             "fresh RI=2 typed mov-IP suffix did not execute")

    nonempty_program = nonempty_overlay_internal_stop_handoff_program()
    nonempty = run_program(
        qemu,
        nonempty_program,

        typed_direct_trace_ips=(0xff0,),
        typed_visibility_states=((0xff0, 3),),
        internal_stop_handoffs=(0x1000,),
        one_bundle_per_tb=True,
    )
    _require(nonempty.ip == 0x1010,
             "nonempty-overlay handoff missed its terminal branch")
    _require(not nonempty.exception_pending,
             "nonempty-overlay handoff raised {} at 0x{:x}".format(
                 nonempty.exception_kind, nonempty.exception_source
             ))
    _require(
        nonempty.gr[10] == 1 and
        nonempty.gr[11] == nonempty_program.data[0].value,
        "nonempty handoff lost the live r10 write or saved r10 payload",
    )
    _require(
        nonempty.nat_high == 0 and nonempty.nat_low == (1 << 11),
        "saved GR+NaT overlay did not retire before the fresh typed group: "
        "0x{:x}:0x{:x}".format(nonempty.nat_high, nonempty.nat_low),
    )
    _require(nonempty.pr == ((1 << 0) | (1 << 2)),
             "post-stop live predicate image is wrong: 0x{:x}".format(
                 nonempty.pr
             ))
    _require(nonempty.gr[12] == 0x1000,
             "p2-qualified typed mov-IP suffix did not execute")

    return (
        "empty and nonempty typed overlays legitimately continue across the "
        "0xff0 page boundary, retire through the slot-1 stop, clear ownership, "
        "and execute the fresh typed suffix in the same callback"
    )


def _c_source_section(source: str, start: str, end: str) -> str:
    begin = source.find(start)
    finish = source.find(end, begin + len(start))
    if begin < 0 or finish < 0:
        raise HarnessError(
            "missing C source guard section {!r} through {!r}".format(
                start, end
            )
        )
    return source[begin:finish]


def test_continuation_structural_invariants(qemu: Path) -> str:
    source_path = (
        Path(__file__).resolve().parents[2] / "target" / "ia64" /
        "translate.c"
    )
    source = source_path.read_text(encoding="utf-8")
    preflight = _c_source_section(
        source,
        "static bool ia64_tr_preflight_rewrite_region",
        "static G_NORETURN void ia64_tr_fail_typed_continuation",
    )
    insn_start = _c_source_section(
        source,
        "static void ia64_tr_insn_start",
        "static void ia64_tr_publish_restart_ri",
    )
    restart_ri = _c_source_section(
        source,
        "static void ia64_tr_publish_restart_ri",
        "static void ia64_tr_emit_invalid_template",
    )
    invalid_template = _c_source_section(
        source,
        "static void ia64_tr_emit_invalid_template",
        "static bool ia64_tr_gr_is_stacked",
    )
    translate_insn = _c_source_section(
        source,
        "static void ia64_tr_translate_insn",
        "static void ia64_tr_tb_stop",
    )
    rse_static_noreturn = _c_source_section(
        source,
        "static bool ia64_tr_rse_spine_is_static_noreturn",
        "static void ia64_tr_rewrite_plan_reset",
    )

    _require(
        "!ctx->instruction_group_start && !ctx->typed_group_active" in
        preflight and
        "ia64_decode_instruction_bundle" in preflight and
        "ia64_tr_preflight_decoded_bundle" in preflight and
        "ia64_tr_rewrite_plan_append_bundle" in preflight,
        "typed preflight must reject an ownerless continuation and validate "
        "every admitted decoded bundle into the typed plan",
    )
    _require(
        "ia64_tr_first_rse_static_noreturn" in preflight and
        "rse_static_noreturn" in preflight and
        "accepted_last_slot = MIN(accepted_last_slot, rse_last_slot)" in
        preflight and
        "insn->r1 >= IA64_STATIC_GR_COUNT + sof" in rse_static_noreturn,
        "typed preflight must cap its durable plan at a statically faulting "
        "RSE instruction",
    )
    _require(
        re.search(
            r"if\s*\(ctx->base\.plugin_enabled\)\s*\{.*?"
            r"segment_bundles\s*=\s*MIN\(segment_bundles,\s*1u\s*\)",
            preflight,
            re.DOTALL,
        ) is not None,
        "plugin-active typed preflight must cap a segment at one bundle",
    )

    _require(
        re.search(
            r"dcbase->pc_next\s*==\s*dcbase->pc_first\s*\?\s*"
            r"ia64_tcg_tb_flags_ri",
            insn_start,
        ) is not None,
        "insn_start RI must select the TB-entry RI only at pc_first",
    )
    insn_start_call = re.search(
        r"tcg_gen_insn_start\s*\(.*?\);", insn_start, re.DOTALL
    )
    _require(insn_start_call is not None,
             "typed translator lacks tcg_gen_insn_start")
    _require(
        "ia64_tcg_tb_flags_ri" not in insn_start_call.group(0),
        "tcg_gen_insn_start must consume the pc-sensitive RI value, not "
        "the raw TB-entry RI",
    )
    _require(
        re.search(
            r"if\s*\(restart_ri\s*>=\s*IA64_SLOT_COUNT\)\s*\{\s*"
            r"restart_ri\s*=\s*0\s*;\s*\}",
            insn_start,
            re.DOTALL,
        ) is not None,
        "reserved architectural RI=3 must canonicalize to slot zero in "
        "insn_start metadata",
    )

    _require(
        "offsetof(CPUIA64State, ri))" in restart_ri and
        "offsetof(CPUIA64State, ri_dirty))" in restart_ri,
        "restart-RI publication must store both RI and ri_dirty",
    )
    _require(
        invalid_template.find("ia64_tr_sync_state_cache(ctx)") <
        invalid_template.find("ia64_tr_publish_fault_state(") <
        invalid_template.find("gen_helper_raise_illegal_operation(tcg_env)"),
        "an invalid template must synchronize its typed prefix, publish the "
        "requested fault slot, and raise Illegal Operation directly",
    )

    preflight_call = translate_insn.find(
        "ctx->typed_segment_active = ia64_tr_preflight_rewrite_region("
    )
    preflight_fail = translate_insn.find(
        "if (!ctx->typed_segment_active)", preflight_call
    )
    typed_assert = translate_insn.find(
        "g_assert(ctx->typed_segment_active)", preflight_fail
    )
    typed_lowering = translate_insn.find(
        "ia64_tr_try_decoded_bundle(", typed_assert
    )
    _require(
        0 <= preflight_call < preflight_fail < typed_assert < typed_lowering,
        "the production callback must preflight every valid bundle, fail "
        "closed on an internal ownership violation, and lower only through "
        "the typed bundle path",
    )

    for forbidden in (
        "gen_helper_exec_bundle(",
        "gen_helper_exec_bundle_lookup_ptr(",
        "gen_helper_exec_slot(",
        "ia64_tr_emit_firmware_call_gate",
        "ia64_tr_full_tcg_rewrite_enabled",
        "ia64_tr_translate_fast_bundle",
        "ia64_tr_translate_partial_bundle",
    ):
        _require(
            forbidden not in source,
            "typed-only translator retains removed production path {!r}"
            .format(forbidden),
        )

    for spans_next_bundle in (False, True):
        program = invalid_alloc_plan_boundary_program(spans_next_bundle)
        fault = run_program(
            qemu, program, preserve_fault_slot=True,
            typed_fault_trace_ip=0x30,
        )
        _require_illegal_operation(
            fault, fault_ip=0x30, fault_slot=0,
            fault_raw=alloc(34, 1, 1, 0), collection_enabled=True,
            expected_iipa=None, expected_slot_type=IA64_SLOT_TYPE_M,
        )
        _require(
            fault.gr[20] == 0 and fault.gr[21] == 0,
            "statically invalid alloc executed a planned suffix: "
            "r20=0x{:x} r21=0x{:x}".format(
                fault.gr[20], fault.gr[21]
            ),
        )

    return (
        "typed preflight owns every valid bundle and plugin split, caps "
        "single- and multi-bundle plans at exact static RSE faults, RI "
        "metadata is callback-precise, invalid templates raise directly, and "
        "the production callback contains no generic, hybrid, or "
        "firmware-magic dispatch path"
    )


def test_typed_epoch_savevm_migration(qemu: Path) -> str:
    program = typed_epoch_migration_program()
    result = run_savevm_migration(qemu, program, checkpoint_ip=0x20)

    _require(not result.checkpoint.exception_pending,
             "source checkpoint has a pending exception")
    _require(
        result.checkpoint.ip == 0x20 and
        result.checkpoint.gr[1] == 5 and
        result.checkpoint.gr[2] == 0 and
        result.checkpoint.gr[3] == 0 and
        result.checkpoint.gr[4] == 9,
        "source did not stop after exactly the typed 0x10 prefix",
    )
    restored_differences = snapshot_differences(
        result.checkpoint, result.restored
    )
    _require(
        not restored_differences,
        "fresh QEMU did not restore the exact architectural checkpoint:\n  "
        + "\n  ".join(restored_differences),
    )

    _require(not result.final.exception_pending,
             "migration destination has a pending exception")
    _require(result.final.ip == 0x30,
             "migration destination missed terminal IP 0x30")
    _require(
        result.final.gr[1] == 5 and
        result.final.gr[2] == 0 and
        result.final.gr[3] == 7 and
        result.final.gr[4] == 9,
        "migrated typed continuation lost its saved source view or retired "
        "prefix: r1=0x{:x} r2=0x{:x} r3=0x{:x} r4=0x{:x}".format(
            result.final.gr[1], result.final.gr[2],
            result.final.gr[3], result.final.gr[4]
        ),
    )

    _require_typed_direct_trace(result.source_trace, 0x10)
    _require_source_visibility_trace(result.source_trace, 0x10, 3)
    _require_typed_direct_trace(result.destination_trace, 0x20)
    _require_source_visibility_trace(result.destination_trace, 0x20, 2)

    return (
        "a breakpoint-stable active typed epoch survives savevm into a fresh "
        "QEMU; restored ownership selects direct TCG and the saved r1 view "
        "closes with exact state"
    )


def test_typed_branch_forward_savevm_migration(qemu: Path) -> str:
    program = typed_branch_forward_migration_program()
    result = run_savevm_migration(qemu, program, checkpoint_ip=0x20)

    _require(not result.checkpoint.exception_pending,
             "compare-to-branch source checkpoint has a pending exception")
    _require(
        result.checkpoint.ip == 0x20 and result.checkpoint.pr == 0x41,
        "source did not checkpoint the open epoch after p6=1,p7=0: "
        "IP=0x{:x} PR=0x{:x}".format(
            result.checkpoint.ip, result.checkpoint.pr
        ),
    )
    restored_differences = snapshot_differences(
        result.checkpoint, result.restored
    )
    _require(
        not restored_differences,
        "fresh QEMU did not restore the exact branch checkpoint:\n  "
        + "\n  ".join(restored_differences),
    )

    _require(not result.final.exception_pending,
             "compare-to-branch migration destination has a pending exception")
    _require(
        result.final.ip == program.terminal_ip,
        "restored branch used the saved entry predicate instead of its "
        "forwarded p6 result: IP=0x{:x}".format(result.final.ip),
    )
    _require(
        result.final.pr == 0x41,
        "restored branch did not retain its retired predicate pair",
    )

    _require_typed_direct_trace(result.source_trace, 0x10)
    _require_source_visibility_trace(result.source_trace, 0x10, 3)
    _require_typed_branch_trace(
        result.destination_trace, 0x20, 0x40, 0x30
    )
    _require_source_visibility_trace(result.destination_trace, 0x20, 2)
    _require_branch_forward_savevm_trace(
        result.source_trace, result.destination_trace, 0x10, 0x20, 6
    )

    return (
        "an open compare-to-branch epoch preserves its explicit physical PR "
        "forward mask through savevm; a fresh typed destination consumes "
        "forwarded p6 and takes the direct TCG branch"
    )


def test_typed_br_shadow_savevm_migration(qemu: Path) -> str:
    program = branch_register_migration_program()
    result = run_savevm_migration(qemu, program, checkpoint_ip=0x40)

    _require(not result.checkpoint.exception_pending,
             "BR-shadow source checkpoint has a pending exception")
    _require(
        result.checkpoint.ip == 0x40 and
        result.checkpoint.br[5] == 0x222 and
        result.checkpoint.gr[20] == 0 and result.checkpoint.gr[21] == 0,
        "source did not stop after exactly the live b5 producer: "
        "IP=0x{:x} b5=0x{:x} r20=0x{:x} r21=0x{:x}".format(
            result.checkpoint.ip, result.checkpoint.br[5],
            result.checkpoint.gr[20], result.checkpoint.gr[21]
        ),
    )
    restored_differences = snapshot_differences(
        result.checkpoint, result.restored
    )
    _require(
        not restored_differences,
        "fresh QEMU did not restore the exact BR-shadow checkpoint:\n  "
        + "\n  ".join(restored_differences),
    )

    _require(not result.final.exception_pending,
             "BR-shadow migration destination has a pending exception")
    _require(result.final.ip == program.terminal_ip,
             "BR-shadow migration destination missed terminal IP 0x50")
    _require(
        result.final.br[5] == 0x222 and
        result.final.gr[20] == 0x111 and result.final.gr[21] == 0x111,
        "restored ordinary BR reads lost group-entry b5: "
        "b5=0x{:x} r20=0x{:x} r21=0x{:x}".format(
            result.final.br[5], result.final.gr[20], result.final.gr[21]
        ),
    )

    _require_typed_direct_trace(result.source_trace, 0x30)
    _require_source_visibility_trace(result.source_trace, 0x30, 3)
    _require_typed_direct_trace(result.destination_trace, 0x40)
    _require_source_visibility_trace(result.destination_trace, 0x40, 2)
    _require_br_shadow_savevm_trace(
        result.source_trace, result.destination_trace, 0x30, 0x40, 5
    )

    return (
        "an open b5 write survives a real two-QEMU save/load: the fresh "
        "typed destination consumes serialized group-entry b5 "
        "through saved_br_mask while source IR establishes a distinct "
        "branch-forward provenance byte and restored close clears both"
    )


def test_typed_application_move_ri_restart(qemu: Path) -> str:
    program = typed_application_move_ri_restart_program()
    snapshot, trace = run_ri_restart(
        qemu, program, start_slot=2,
        register_writes=((1, 10), (8, 7), (9, program.data[0].address)),
    )

    _require(not snapshot.exception_pending,
             "typed application-move RI=2 restart has a pending exception")
    _require(snapshot.ip == program.terminal_ip,
             "typed application-move RI=2 restart missed its terminal branch")
    _require(
        snapshot.gr[1] == 10 and snapshot.gr[5] == 0,
        "typed restart replayed skipped slot 0 or 1: r1=0x{:x} r5=0x{:x}"
        .format(snapshot.gr[1], snapshot.gr[5]),
    )
    _require(
        snapshot.gr[8] == 7 and snapshot.gr[9] == program.data[0].address and
        snapshot.gr[10] == 7,
        "typed restart did not execute and read back the slot-2 AR.LC write",
    )
    _require(snapshot.nat_high == 0 and snapshot.nat_low == 0,
             "skipped slot-0 ld8.fill unexpectedly changed NaT state")
    _require_typed_application_move_restart_trace(
        trace, program.entry, 2, 0x20
    )

    return (
        "typed application-move lowering enters at TB RI=2: visible "
        "non-idempotent slots 0/1 stay skipped while slot 2 writes AR.LC "
        "and the next bundle reads it back"
    )


def test_typed_branch_ri_restart(qemu: Path) -> str:
    short_program = typed_short_branch_ri_restart_program()
    short, short_trace = run_ri_restart(
        qemu, short_program, start_slot=2,
    )
    _require(not short.exception_pending,
             "typed B1 RI=2 restart has a pending exception")
    _require(short.ip == short_program.terminal_ip,
             "typed B1 RI=2 restart missed its branch target")
    _require(
        short.gr[5] == 0 and not (short.pr & (1 << 6)) and
        not (short.pr & (1 << 7)),
        "typed B1 RI=2 restart replayed a skipped slot: "
        "r5=0x{:x} pr=0x{:x}".format(short.gr[5], short.pr),
    )
    _require(
        ((short.psr >> IA64_PSR_RI_SHIFT) & 3) == 0,
        "typed B1 branch exit did not clear architectural RI",
    )
    _require_typed_branch_trace(
        short_trace, short_program.entry, short_program.terminal_ip, None
    )

    long_program = typed_long_branch_ri_restart_program()
    long, long_trace = run_ri_restart(
        qemu, long_program, start_slot=1,
    )
    _require(not long.exception_pending,
             "typed X3 RI=1 restart has a pending exception")
    _require(long.ip == long_program.terminal_ip,
             "typed X3 RI=1 restart missed its long-branch target")
    _require(
        not (long.pr & (1 << 6)) and not (long.pr & (1 << 7)),
        "typed X3 RI=1 restart replayed its skipped M-slot compare: "
        "pr=0x{:x}".format(long.pr),
    )
    _require(
        ((long.psr >> IA64_PSR_RI_SHIFT) & 3) == 0,
        "typed X3 branch exit did not clear architectural RI",
    )
    _require_typed_branch_trace(
        long_trace, long_program.entry, long_program.terminal_ip, None
    )

    return (
        "typed B1 RI=2 and logical L/X RI=1 restart at the requested slot, "
        "leave skipped poison slots untouched, clear PSR.ri, and exit through "
        "direct branch TCG"
    )


def test_predicate_tests_and_direct_branches(qemu: Path) -> str:
    def run_branch(program: Program, source: int, target: int,
                   fallthrough: Optional[int], *,
                   state_cache: bool = False) -> Snapshot:
        snapshot = run_program(
            qemu, program,
            typed_branch_traces=((source, target, fallthrough),),
            state_cache=state_cache,
        )
        _require(
            not snapshot.exception_pending and
            snapshot.exception_kind == "none",
            "{} raised an unexpected exception".format(program.name),
        )
        return snapshot

    true_forward = run_branch(
        same_bundle_branch_forward_true_program(),
        0x10, 0x30, 0x20,
    )
    _require(
        true_forward.pr & (1 << 6) and
        not (true_forward.pr & (1 << 7)),
        "true compare did not retire p6=1,p7=0 before its branch",
    )

    false_forward = run_branch(
        same_bundle_branch_forward_false_program(),
        0x20, 0x40, 0x30,
    )
    _require(
        not (false_forward.pr & (1 << 6)) and
        false_forward.pr & (1 << 7),
        "false compare did not retire p6=0,p7=1 before fallthrough",
    )

    nullified = run_branch(
        nullified_branch_producer_program(),
        0x20, 0x40, 0x30,
    )
    _require(
        nullified.pr & (1 << 6) and
        not (nullified.pr & (1 << 7)),
        "nullified compare changed its branch-visible predicate pair",
    )

    cross_true = run_branch(
        cross_page_branch_forward_program(True),
        0x1000, 0x1020, 0x1010,
    )
    cross_false = run_branch(
        cross_page_branch_forward_program(False),
        0x1000, 0x1020, 0x1010,
    )
    _require(
        cross_true.pr & (1 << 6) and
        not (cross_false.pr & (1 << 6)),
        "page-split forwarding lost the true/false predicate distinction",
    )

    rotating_true = run_branch(
        rotating_branch_forward_program(True),
        0x40, 0x60, 0x50,
    )
    rotating_false = run_branch(
        rotating_branch_forward_program(False),
        0x40, 0x60, 0x50,
    )
    _require(
        rotating_true.ip == 0x60 and rotating_false.ip == 0x50,
        "physical forward-mask mapping ignored rotating logical qp",
    )

    no_stop_fallthrough = run_branch(
        no_stop_branch_epoch_program(False),
        0x10, 0x40, 0x20,
        state_cache=True,
    )
    _require(
        no_stop_fallthrough.gr[1] == 1 and
        no_stop_fallthrough.gr[2] == 0,
        "not-taken no-stop branch did not preserve the ordinary source epoch",
    )
    no_stop_taken = run_branch(
        no_stop_branch_epoch_program(True),
        0x10, 0x30, 0x20,
        state_cache=True,
    )
    _require(
        no_stop_taken.gr[1] == 1 and no_stop_taken.gr[2] == 1,
        "taken no-stop branch did not start a fresh target source epoch",
    )

    for kind, source, target, fallthrough in (
        ("tbit", 0x20, 0x40, 0x30),
        ("tnat", 0x40, 0x60, 0x50),
        ("tf", 0x10, 0x30, 0x20),
    ):
        tested = run_branch(
            predicate_test_branch_program(kind),
            source, target, fallthrough,
        )
        _require(
            tested.pr & (1 << 6) and not (tested.pr & (1 << 7)),
            "{} did not produce and forward p6=1,p7=0".format(kind),
        )

    far = 0x02000040
    far_forwarded = run_branch(
        far_long_branch_program("forwarded"),
        0x20, far, 0x30,
    )
    _require(
        far_forwarded.pr & (1 << 6),
        "same-MLX compare result was not visible to brl.cond",
    )
    run_branch(
        far_long_branch_program("false"),
        0x20, far, 0x30,
    )
    run_branch(
        far_long_branch_program("backward"),
        far, 0x40, None,
    )

    return (
        "typed B1/X3 branches pass exact target/fallthrough goldens for "
        "same-bundle, nullified, page-split, rotating, no-stop epoch, and "
        "state-cache cases; tbit/tnat/tf results forward without generic "
        "dispatch, and forward/false/backward imm60 MLX branches are exact"
    )


def test_typed_indirect_and_nonterminal_branches(qemu: Path) -> str:
    forwarding_program = indirect_branch_forwarding_program()
    forwarding = run_program(
        qemu,
        forwarding_program,

        typed_direct_trace_ips=(0x30, 0xb0),
        typed_indirect_traces=((0x40, 1, 0), (0xc0, 1, 0)),
        one_bundle_per_tb=True,
    )
    _require(not forwarding.exception_pending,
             "typed indirect forwarding program has a pending exception")
    _require(forwarding.ip == forwarding_program.terminal_ip,
             "typed indirect forwarding missed aligned target 0xf0")
    _require(
        forwarding.br[1] == 0x97 and forwarding.gr[20] == 0x73,
        "same-group b1 views collapsed: live/branch=0x{:x}, "
        "ordinary r20=0x{:x}".format(
            forwarding.br[1], forwarding.gr[20]
        ),
    )
    _require(
        forwarding.br[2] == 0xf3 and forwarding.gr[21] == 0xf3,
        "false-qualified b2 writer changed live or ordinary state: "
        "b2=0x{:x} r21=0x{:x}".format(
            forwarding.br[2], forwarding.gr[21]
        ),
    )

    suppression_program = nonterminal_indirect_suppression_program()
    suppression = run_program(
        qemu,
        suppression_program,

        typed_indirect_traces=((0x50, 2, 1), (0x70, 2, 1)),
        one_bundle_per_tb=True,
    )
    _require(not suppression.exception_pending,
             "taken nonterminal indirect program has a pending exception")
    _require(
        suppression.ip == suppression_program.terminal_ip and
        suppression.gr[22] == 0x55,
        "true p6 slot-1 branch failed to suppress the p0 poison suffix: "
        "IP=0x{:x} r22=0x{:x}".format(
            suppression.ip, suppression.gr[22]
        ),
    )

    frontier_program = nonterminal_indirect_frontier_program()
    frontier = run_program(
        qemu,
        frontier_program,

        typed_direct_trace_ips=(0x20, 0x40, 0x60, 0x80),
        typed_indirect_traces=((0x30, 2, 2), (0x70, 2, 2)),
        one_bundle_per_tb=True,
    )
    _require(not frontier.exception_pending,
             "false-arm indirect frontier program has a pending exception")
    _require(frontier.ip == frontier_program.terminal_ip,
             "false-arm indirect CFG did not reach sequential terminal IP")
    _require(
        frontier.gr[1] == 11 and frontier.gr[2] == 10,
        "no-stop false arms lost the open ordinary-source frontier: "
        "r1=0x{:x} r2=0x{:x}".format(frontier.gr[1], frontier.gr[2]),
    )
    _require(
        frontier.gr[3] == 21 and frontier.gr[4] == 21,
        "slot-2 stop failed to expose the closed live source: "
        "r3=0x{:x} r4=0x{:x}".format(frontier.gr[3], frontier.gr[4]),
    )

    return (
        "ten typed B4 branches cover p0, true p6, false p7, low-bit "
        "target alignment, ordinary-versus-forwarded BR selection, a "
        "nullified writer, false-to-later-taken ordering, taken-suffix "
        "suppression, two-branch fallthrough, stop/no-stop frontiers, and "
        "forced TB continuation without generic execution helpers"
    )


def test_typed_loop_branches(qemu: Path) -> str:
    def expected_cfm(sof: int, sol: int, sor: int,
                     rotations: int) -> int:
        rotating_grs = sor * 8
        rrb_gr = (-rotations) % rotating_grs if rotating_grs else 0
        return (
            sof
            | (sol << 7)
            | (sor << 14)
            | (rrb_gr << 18)
            | ((-rotations % 96) << 25)
            | ((-rotations % 48) << 32)
        )

    ri_program = application_move_forced_tb_ri_program()
    ri_snapshot = run_program(
        qemu, ri_program, one_bundle_per_tb=True
    )
    _require(
        ri_snapshot.gr[20] == 0 and ri_snapshot.gr[21] == 0x15,
        "successful AR helper leaked its slot across a forced TB or lost "
        "ordinary/live EC selection: same=0x{:x} next=0x{:x}".format(
            ri_snapshot.gr[20], ri_snapshot.gr[21]
        ),
    )

    matrix_rows = 0
    loop_encodings = 0
    for kind in ("cloop", "ctop", "cexit", "wtop", "wexit"):
        program, expectations, traces, rotations = loop_matrix_program(kind)
        snapshot = run_program(
            qemu,
            program,

            typed_loop_traces=traces,
            one_bundle_per_tb=True,
        )
        _require(not snapshot.exception_pending,
                 "{} loop matrix has a pending exception".format(kind))
        _require(snapshot.ip == program.terminal_ip,
                 "{} loop matrix missed its terminal bundle".format(kind))

        for expectation in expectations:
            output = expectation.output_base
            expected_marker = (
                expectation.new_marker if expectation.taken
                else expectation.old_marker
            )
            observed = snapshot.gr[output:output + 5]
            expected = (
                expected_marker,
                int(expectation.rotated),
                int(expectation.injected),
                expectation.final_lc & U64_MASK,
                expectation.final_ec & U64_MASK,
            )
            _require(
                observed == expected,
                "{} expected marker/rotate/inject/LC/EC {}, got {}"
                .format(
                    expectation.label,
                    tuple("0x{:x}".format(value) for value in expected),
                    tuple("0x{:x}".format(value) for value in observed),
                ),
            )
        _require(
            snapshot.cfm == expected_cfm(80, 80, 0, rotations),
            "{} loop matrix expected {} rotations in CFM, got 0x{:x}"
            .format(kind, rotations, snapshot.cfm),
        )
        matrix_rows += len(expectations)
        loop_encodings += len(traces)

    _require(matrix_rows == 35,
             "loop truth-table generator drifted from its exact 35 rows")

    wrap_program, wrap_traces = loop_rotation_wrap_program()
    wrapped = run_program(
        qemu,
        wrap_program,

        typed_direct_trace_ips=(wrap_program.terminal_ip - 0x10,),
        typed_loop_traces=wrap_traces,
        one_bundle_per_tb=True,
    )
    _require(not wrapped.exception_pending,
             "49-rotation wrap program has a pending exception")
    _require(wrapped.ip == wrap_program.terminal_ip,
             "49-rotation wrap program missed its terminal bundle")
    _require(wrapped.gr[20] == 0,
             "49 CTOP updates did not decrement LC from 49 to zero")
    _require(
        wrapped.cfm == expected_cfm(8, 8, 1, 49),
        "49 rotations did not wrap RRB.GR/FR/PR to 7/47/47: CFM=0x{:x}"
        .format(wrapped.cfm),
    )
    _require(
        wrapped.gr[32] == 0x777 and
        wrapped.gr[33] == 0x123456789abcdef0 and
        wrapped.gr[21] == 0x123456789abcdef0,
        "SOR=8 logical mirror did not rotate r39/r32 to r32/r33 or "
        "project r33 into static r21: r32=0x{:x} r33=0x{:x} r21=0x{:x}"
        .format(
            wrapped.gr[32], wrapped.gr[33], wrapped.gr[21]
        ),
    )
    _require(
        wrapped.nat_low == (1 << 21) and wrapped.nat_high == 0,
        "SOR=8 NaT mirror did not rotate NaT(r32) to NaT(r33) and "
        "project it into static r21: "
        "NaT=0x{:x}:0x{:x}".format(
            wrapped.nat_high, wrapped.nat_low
        ),
    )
    _require(
        wrapped.pr & 0xffffffffffff0000 == 0xffffffffffff0000,
        "49 true p63 injections did not fill all 48 rotating predicates: "
        "PR=0x{:x}".format(wrapped.pr),
    )
    loop_encodings += len(wrap_traces)

    overlay_program = loop_rotating_overlay_program()
    overlay = run_program(
        qemu,
        overlay_program,

        typed_direct_trace_ips=(0x70, 0xa0),
        typed_loop_traces=((0x80, 0xc0, True),),
        one_bundle_per_tb=True,
    )
    _require(not overlay.exception_pending,
             "rotating open-overlay program has a pending exception")
    _require(overlay.ip == overlay_program.terminal_ip,
             "false CTOP unexpectedly took its poison target")
    _require(
        overlay.gr[20] == 0x123456789abcdef0 and
        overlay.gr[21] == 0 and overlay.gr[22] == 0x555,
        "rotated saved/live r33 views collapsed: saved=0x{:x} EC=0x{:x} "
        "live=0x{:x}".format(
            overlay.gr[20], overlay.gr[21], overlay.gr[22]
        ),
    )
    _require(
        overlay.nat_low == (1 << 20) and overlay.nat_high == 0,
        "rotated saved r33 lost its NaT or leaked it into the live view: "
        "NaT=0x{:x}:0x{:x}".format(
            overlay.nat_high, overlay.nat_low
        ),
    )
    _require(
        overlay.cfm == expected_cfm(8, 8, 1, 1),
        "false EC=1 CTOP did not perform exactly one modulo rotation: "
        "CFM=0x{:x}".format(overlay.cfm),
    )
    loop_encodings += 1

    suppression_program = loop_first_taken_suppression_program()
    suppressed = run_program(
        qemu,
        suppression_program,

        typed_branch_traces=((0x50, 0x80, 0x60),),
        typed_loop_traces=((0x50, 0xa0, True),),
        one_bundle_per_tb=True,
    )
    _require(not suppressed.exception_pending,
             "first-taken loop suppression has a pending exception")
    _require(suppressed.ip == suppression_program.terminal_ip,
             "first direct branch failed to suppress the loop suffix")
    _require(
        suppressed.gr[20] == 1 and
        suppressed.cfm == expected_cfm(8, 8, 1, 0) and
        suppressed.pr & 0xffffffffffff0000 == 0,
        "suppressed CTOP changed LC, RRBs, or rotating predicates: "
        "LC=0x{:x} CFM=0x{:x} PR=0x{:x}".format(
            suppressed.gr[20], suppressed.cfm, suppressed.pr
        ),
    )
    loop_encodings += 1

    _require(loop_encodings == 86,
             "loop branch corpus drifted from its exact 86 encodings")
    return (
        "35 exhaustive CLOOP/CTOP/CEXIT/WTOP/WEXIT truth-table rows, a "
        "49-rotation RRB/PR/SOR+NaT wrap, one false/no-stop rotating-overlay "
        "case, and one first-taken suppression case provide 38 semantic "
        "subtests and 86 typed loop encodings across eight programs"
    )


def test_typed_call_branches(qemu: Path) -> str:
    """Architectural and IR goldens for B3, X4, and B5 call lowering."""
    program_count = 0
    call_encodings = 0

    frame_program = call_frame_architectural_program()
    frame = run_program(
        qemu,
        frame_program,

        typed_call_traces=((0xc0, 0x120, False, 1),),
        one_bundle_per_tb=True,
    )
    _require(not frame.exception_pending,
             "architectural B3 call-frame program has a pending exception")
    _require(frame.ip == frame_program.terminal_ip,
             "architectural B3 call-frame program missed its terminal IP")
    caller_cfm = 6 | (4 << 7)
    expected_pfs = caller_cfm | (0x2a << 52) | (3 << 62)
    _require(
        frame.gr[22] == expected_pfs,
        "B3 call did not pack old CFM/EC/CPL into PFS: expected 0x{:x}, "
        "got 0x{:x}".format(expected_pfs, frame.gr[22]),
    )
    _require(
        frame.br[2] == 0xd0,
        "B3 call link is not bundle+16: b2=0x{:x}".format(frame.br[2]),
    )
    _require(
        frame.cfm == 2 and frame.rse_base == 4 and
        frame.rse_bsp == 0x1020 and
        frame.rse_bspstore == 0x1000 and frame.rse_bspload == 0x1000,
        "call-frame remap expected CFM=2/base=4/BSP=0x1020 and "
        "BSPSTORE=BSPLOAD=0x1000; got CFM=0x{:x}/base={}/"
        "BSP=0x{:x}/0x{:x}/0x{:x}".format(
            frame.cfm, frame.rse_base, frame.rse_bsp,
            frame.rse_bspstore, frame.rse_bspload
        ),
    )
    _require(
        frame.gr[20] == 0x666 and
        frame.gr[21] == 0x123456789abcdef0 and
        frame.nat_low == (1 << 21) and frame.nat_high == 0,
        "dirty stacked outputs did not remap with coherent value/NaT: "
        "r20=0x{:x} r21=0x{:x} NaT=0x{:x}:0x{:x}".format(
            frame.gr[20], frame.gr[21], frame.nat_high, frame.nat_low
        ),
    )
    _require(
        frame.gr[23] == 0x2a and ((frame.psr >> 32) & 3) == 3,
        "call changed live EC/CPL instead of only capturing them: "
        "EC=0x{:x} PSR=0x{:x}".format(frame.gr[23], frame.psr),
    )
    _require(
        frame.gr[24] == 1,
        "call-frame entry left a caller-stacked ALAT entry observable",
    )
    program_count += 1
    call_encodings += 1

    b3_program = b3_backward_forwarded_call_program()
    b3 = run_program(
        qemu,
        b3_program,

        typed_call_traces=((0x40, 0x10, False, 1),),
        one_bundle_per_tb=True,
    )
    _require(not b3.exception_pending and b3.ip == b3_program.terminal_ip,
             "backward B3 call did not reach its target")
    _require(
        b3.br[1] == 0x50 and bool(b3.pr & (1 << 6)) and
        b3.cfm == 0 and b3.rse_base == 0,
        "same-group true predicate did not select backward B3 call: "
        "b1=0x{:x} PR=0x{:x} CFM=0x{:x} base={}".format(
            b3.br[1], b3.pr, b3.cfm, b3.rse_base
        ),
    )
    program_count += 1
    call_encodings += 1

    x4_expectations = {
        "true": (11, 0x70, 0, True),
        "false": (10, 0x777, 0x555, False),
        "nullified": (11, 0x70, 0, True),
    }
    for mode, (marker, link, pfs, predicate) in x4_expectations.items():
        x4_program = x4_equal_fallthrough_call_program(mode)
        x4 = run_program(
            qemu,
            x4_program,

            typed_call_traces=((0x60, 0x70, False, 1),),
            one_bundle_per_tb=True,
        )
        _require(not x4.exception_pending and
                 x4.ip == x4_program.terminal_ip,
                 "{} equal-fallthrough X4 call did not terminate".format(
                     mode
                 ))
        _require(
            x4.gr[20] == marker and x4.br[2] == link and
            x4.gr[21] == pfs and
            bool(x4.pr & (1 << 6)) == predicate,
            "{} X4 call expected marker/link/PFS/p6 "
            "(0x{:x},0x{:x},0x{:x},{}), got "
            "(0x{:x},0x{:x},0x{:x},{})".format(
                mode, marker, link, pfs, int(predicate),
                x4.gr[20], x4.br[2], x4.gr[21],
                int(bool(x4.pr & (1 << 6)))
            ),
        )
        _require(
            x4.cfm == 0 and x4.rse_base == 0 and x4.rse_bsp == 0,
            "{} X4 call changed its zero-sized frame unexpectedly".format(
                mode
            ),
        )
        program_count += 1
        call_encodings += 1

    far_program = x4_far_backward_call_program()
    far = run_program(
        qemu,
        far_program,

        typed_call_traces=((0x02000000, 0x10, False, 1),),
        one_bundle_per_tb=True,
    )
    _require(not far.exception_pending and far.ip == far_program.terminal_ip,
             "far backward X4 call did not reach its signed imm60 target")
    _require(
        far.br[4] == 0x02000010 and far.cfm == 0 and far.rse_base == 0,
        "far X4 link/frame mismatch: b4=0x{:x} CFM=0x{:x} base={}"
        .format(far.br[4], far.cfm, far.rse_base),
    )
    program_count += 1
    call_encodings += 1

    alias_program = indirect_alias_forwarded_call_program()
    alias = run_program(
        qemu,
        alias_program,

        typed_call_traces=((0x40, None, True, 1),),
        one_bundle_per_tb=True,
    )
    _require(not alias.exception_pending and
             alias.ip == alias_program.terminal_ip,
             "forwarded/aliased B5 call missed its aligned target")
    _require(
        alias.gr[20] == 0x187 and alias.br[3] == 0x50 and
        alias.gr[21] == 0 and alias.cfm == 0 and alias.rse_base == 0 and
        bool(alias.pr & (1 << 6)),
        "B5 failed ordinary-shadow/forward-target/b1==b2 latching: "
        "r20=0x{:x} b3=0x{:x} PFS=0x{:x} CFM=0x{:x} base={} "
        "PR=0x{:x}".format(
            alias.gr[20], alias.br[3], alias.gr[21], alias.cfm,
            alias.rse_base, alias.pr
        ),
    )
    program_count += 1
    call_encodings += 1

    false_b5_program = indirect_false_call_program()
    false_b5 = run_program(
        qemu,
        false_b5_program,

        typed_call_traces=((0x50, None, True, 1),),
        one_bundle_per_tb=True,
    )
    _require(not false_b5.exception_pending and
             false_b5.ip == false_b5_program.terminal_ip,
             "stopped false B5 call did not follow its fallthrough")
    _require(
        false_b5.gr[20] == 11 and false_b5.br[2] == 0x777 and
        false_b5.gr[21] == 0x55 and
        false_b5.cfm == 0 and false_b5.rse_base == 0 and
        not bool(false_b5.pr & (1 << 6)),
        "stopped false B5 did not expose a closed epoch while preserving "
        "link/PFS/frame: r20=0x{:x} b2=0x{:x} PFS=0x{:x} "
        "CFM=0x{:x} base={} PR=0x{:x}".format(
            false_b5.gr[20], false_b5.br[2], false_b5.gr[21],
            false_b5.cfm, false_b5.rse_base, false_b5.pr
        ),
    )
    program_count += 1
    call_encodings += 1

    suppression_program = call_first_taken_suppression_program()
    suppressed = run_program(
        qemu,
        suppression_program,

        typed_branch_traces=((0x60, 0x90, None),),
        typed_call_traces=((0x60, 0xb0, False, 1),),
        one_bundle_per_tb=True,
    )
    _require(not suppressed.exception_pending and
             suppressed.ip == suppression_program.terminal_ip,
             "first-taken call-suppression program did not terminate")
    _require(
        suppressed.cfm == caller_cfm and suppressed.rse_base == 0 and
        suppressed.rse_bsp == 0 and suppressed.br[2] == 0x777 and
        suppressed.gr[20] == 0x555 and suppressed.gr[21] == 1,
        "earlier branch failed to suppress call link/PFS/RSE effects: "
        "CFM=0x{:x} base={} BSP=0x{:x} b2=0x{:x} "
        "PFS=0x{:x} EC=0x{:x}".format(
            suppressed.cfm, suppressed.rse_base, suppressed.rse_bsp,
            suppressed.br[2], suppressed.gr[20], suppressed.gr[21]
        ),
    )
    program_count += 1
    call_encodings += 1

    _require(program_count == 9 and call_encodings == 9,
             "typed call corpus drifted from its exact nine programs/calls")
    return (
        "nine forced-one-bundle-TB call programs cover B3/X4 forward and "
        "backward targets, B5 forwarding/alignment/b1==b2 latching, p0 and "
        "same-group true/false/nullified predicates, stopped/no-stop and "
        "equal-fallthrough visibility, link/PFS/RSE/output+NaT/ALAT frame "
        "semantics, and first-taken suppression with one focused helper "
        "site per direct-TCG call CFG"
    )


def test_typed_return_branches(qemu: Path) -> str:
    """Architectural and IR goldens for typed B4 BR_RET lowering."""
    program_count = 0
    return_encodings = 0

    for mode in ("p0", "true", "false"):
        program, restored_pfs = typed_return_clean_program(mode)
        snapshot = run_program(
            qemu,
            program,

            typed_return_traces=((0x90, 3 if mode == "p0" else 4),),
            one_bundle_per_tb=True,
        )
        taken = mode != "false"
        _require(not snapshot.exception_pending and
                 snapshot.exception_kind == "none",
                 "{} clean BR_RET raised an exception".format(mode))
        _require(snapshot.ip == program.terminal_ip,
                 "{} BR_RET missed its {} path terminal".format(
                     mode, "taken" if taken else "fallthrough"
                 ))
        _require(
            snapshot.gr[20] == 0x111 and snapshot.gr[21] == 0x187,
            "{} BR_RET lost ordinary AR.PFS/BR group-entry values: "
            "r20=0x{:x} r21=0x{:x}".format(
                mode, snapshot.gr[20], snapshot.gr[21]
            ),
        )
        _require(
            snapshot.br[6] == 0x107 and snapshot.gr[23] == restored_pfs,
            "{} BR_RET did not retain live forwarded b6/PFS: "
            "b6=0x{:x} PFS=0x{:x}".format(
                mode, snapshot.br[6], snapshot.gr[23]
            ),
        )
        _require(
            snapshot.cfm == (4 if taken else 0) and
            snapshot.gr[22] == (0x2a if taken else 0),
            "{} BR_RET frame result expected CFM/EC (0x{:x},0x{:x}), "
            "got (0x{:x},0x{:x})".format(
                mode, 4 if taken else 0, 0x2a if taken else 0,
                snapshot.cfm, snapshot.gr[22]
            ),
        )
        _require(
            snapshot.rse_base == 0 and snapshot.rse_bsp == 0 and
            snapshot.rse_bspstore == 0 and snapshot.rse_bspload == 0,
            "{} clean return unexpectedly moved or filled the RSE: "
            "base={} BSP=0x{:x}/0x{:x}/0x{:x}".format(
                mode, snapshot.rse_base, snapshot.rse_bsp,
                snapshot.rse_bspstore, snapshot.rse_bspload
            ),
        )
        _require(snapshot.pr == 0x41,
                 "{} return predicate setup expected PR=0x41, got 0x{:x}"
                 .format(mode, snapshot.pr))
        program_count += 1
        return_encodings += 1

    trap_rows = (
        (
            "LP-over-TB",
            IA64_PSR_IC | IA64_PSR_LP | IA64_PSR_TB,
            IA64_LOWER_PRIVILEGE_TRANSFER_VECTOR,
            "lower-privilege-transfer",
            6,
        ),
        (
            "TB-only",
            IA64_PSR_IC | IA64_PSR_TB,
            IA64_TAKEN_BRANCH_TRAP_VECTOR,
            "taken-branch-trap",
            4,
        ),
    )
    for label, psr_bits, vector, kind, isr_code in trap_rows:
        program, restored_pfs = typed_return_trap_program(psr_bits, vector)
        snapshot = run_program(
            qemu,
            program,

            typed_return_traces=((0xa0, 3),),
            one_bundle_per_tb=True,
        )
        _require(snapshot.ip == program.terminal_ip,
                 "{} BR_RET did not enter its handler".format(label))
        _require(snapshot.exception_pending and
                 snapshot.exception_kind == kind and
                 snapshot.exception_vector == vector,
                 "{} expected {} at vector 0x{:x}, got {}/0x{:x}".format(
                     label, kind, vector, snapshot.exception_kind,
                     snapshot.exception_vector
                 ))
        _require(
            snapshot.exception_source == 0x100 and
            snapshot.exception_address == 0x100 and
            snapshot.cr_iip == 0x100 and snapshot.cr_iipa == 0xa0,
            "{} trap was not attributed to committed target/source: "
            "EXC=0x{:x}/0x{:x} IIP=0x{:x} IIPA=0x{:x}".format(
                label, snapshot.exception_source,
                snapshot.exception_address, snapshot.cr_iip,
                snapshot.cr_iipa
            ),
        )
        expected_isr = (2 << IA64_ISR_EI_SHIFT) | isr_code
        _require(
            snapshot.cr_isr == expected_isr,
            "{} expected ISR=0x{:x}, got 0x{:x}".format(
                label, expected_isr, snapshot.cr_isr
            ),
        )
        _require(
            (snapshot.cr_ipsr & IA64_PSR_IC) != 0 and
            ((snapshot.cr_ipsr >> 32) & 3) == 3 and
            (snapshot.cr_ipsr & (IA64_PSR_LP | IA64_PSR_TB)) ==
            (psr_bits & (IA64_PSR_LP | IA64_PSR_TB)),
            "{} trap did not collect post-return CPL/LP/TB state: "
            "IPSR=0x{:x}".format(label, snapshot.cr_ipsr),
        )
        _require(
            snapshot.cfm == 4 and snapshot.gr[22] == 0x2a and
            snapshot.gr[23] == restored_pfs,
            "{} trap preceded frame restoration: CFM=0x{:x} EC=0x{:x} "
            "PFS=0x{:x}".format(
                label, snapshot.cfm, snapshot.gr[22], snapshot.gr[23]
            ),
        )
        _require(
            snapshot.gr[20] == 0x111 and snapshot.gr[21] == 0x187 and
            snapshot.br[6] == 0x107,
            "{} trap lost ordinary/forwarded PFS-BR selection: "
            "r20=0x{:x} r21=0x{:x} b6=0x{:x}".format(
                label, snapshot.gr[20], snapshot.gr[21], snapshot.br[6]
            ),
        )
        _require(
            snapshot.rse_base == 0 and snapshot.rse_bsp == 0 and
            snapshot.rse_bspstore == 0 and snapshot.rse_bspload == 0,
            "{} trap path performed an unexpected clean-frame load".format(
                label
            ),
        )
        program_count += 1
        return_encodings += 1

    fill_program, fill_pfs, backing = \
        typed_return_incomplete_fill_program()
    filled = run_program(
        qemu,
        fill_program,

        typed_return_traces=((0x40, 3),),
        one_bundle_per_tb=True,
    )
    _require(not filled.exception_pending and
             filled.exception_kind == "none" and
             filled.ip == fill_program.terminal_ip,
             "SOL4 mandatory-fill BR_RET did not reach its target cleanly")
    _require(
        filled.cfm == (4 | (4 << 7)) and filled.gr[22] == 0x2a and
        filled.gr[23] == fill_pfs and filled.br[6] == 0x107,
        "SOL4 fill lost restored CFM/EC/PFS or aligned BR target: "
        "CFM=0x{:x} EC=0x{:x} PFS=0x{:x} b6=0x{:x}".format(
            filled.cfm, filled.gr[22], filled.gr[23], filled.br[6]
        ),
    )
    _require(
        filled.gr[32:36] == backing,
        "SOL4 fill expected r32-r35 {}, got {}".format(
            tuple("0x{:x}".format(value) for value in backing),
            tuple("0x{:x}".format(value) for value in filled.gr[32:36]),
        ),
    )
    _require(
        (filled.nat_low & (0xf << 32)) == 0,
        "zero RNAT collection word left a NaT on filled r32-r35: "
        "NaT=0x{:x}:0x{:x}".format(filled.nat_high, filled.nat_low),
    )
    _require(
        filled.rse_base == 92 and filled.rse_bsp == 0xfd8 and
        filled.rse_bspstore == 0xfd8 and filled.rse_bspload == 0xfd8,
        "SOL4 mandatory fills did not complete the 0x1000 backing span: "
        "base={} BSP=0x{:x}/0x{:x}/0x{:x}".format(
            filled.rse_base, filled.rse_bsp, filled.rse_bspstore,
            filled.rse_bspload
        ),
    )
    program_count += 1
    return_encodings += 1

    for label, psr_bits, vector, kind, isr_code in trap_rows:
        program, restored_pfs, backing = \
            typed_return_incomplete_trap_program(psr_bits, vector)
        snapshot = run_program(
            qemu,
            program,

            typed_return_traces=((0x80, 3),),
            one_bundle_per_tb=True,
        )
        incomplete_label = "incomplete-{}".format(label)
        _require(snapshot.ip == program.terminal_ip,
                 "{} BR_RET did not enter its handler".format(
                     incomplete_label
                 ))
        _require(snapshot.exception_pending and
                 snapshot.exception_kind == kind and
                 snapshot.exception_vector == vector,
                 "{} expected {} at vector 0x{:x}, got {}/0x{:x}".format(
                     incomplete_label, kind, vector,
                     snapshot.exception_kind, snapshot.exception_vector
                 ))
        _require(
            snapshot.exception_source == 0x100 and
            snapshot.exception_address == 0x100 and
            snapshot.cr_iip == 0x100 and snapshot.cr_iipa == 0x80 and
            ((snapshot.cr_ipsr >> IA64_PSR_RI_SHIFT) & 3) == 0,
            "{} trap lacks target IIP/RI0 or source bundle attribution: "
            "EXC=0x{:x}/0x{:x} IIP=0x{:x} IIPA=0x{:x} IPSR=0x{:x}"
            .format(
                incomplete_label, snapshot.exception_source,
                snapshot.exception_address, snapshot.cr_iip,
                snapshot.cr_iipa, snapshot.cr_ipsr
            ),
        )
        expected_isr = (2 << IA64_ISR_EI_SHIFT) | IA64_ISR_IR | isr_code
        _require(
            snapshot.cr_isr == expected_isr and
            (snapshot.cr_isr & (IA64_ISR_RS | IA64_ISR_IR)) == IA64_ISR_IR,
            "{} expected EI2/IR1/RS0 ISR=0x{:x}, got 0x{:x}".format(
                incomplete_label, expected_isr, snapshot.cr_isr
            ),
        )
        _require(
            (snapshot.cr_ipsr & IA64_PSR_IC) != 0 and
            ((snapshot.cr_ipsr >> 32) & 3) == 3 and
            (snapshot.cr_ipsr & (IA64_PSR_LP | IA64_PSR_TB)) ==
            (psr_bits & (IA64_PSR_LP | IA64_PSR_TB)),
            "{} trap did not collect restored CPL/LP/TB state: "
            "IPSR=0x{:x}".format(incomplete_label, snapshot.cr_ipsr),
        )
        _require(
            snapshot.cfm == (4 | (4 << 7)) and
            snapshot.gr[22] == 0x2a and snapshot.gr[23] == restored_pfs and
            snapshot.br[6] == 0x107,
            "{} trap preceded frame/EC/CPL target restoration: "
            "CFM=0x{:x} EC=0x{:x} PFS=0x{:x} b6=0x{:x}".format(
                incomplete_label, snapshot.cfm, snapshot.gr[22],
                snapshot.gr[23], snapshot.br[6]
            ),
        )
        _require(
            snapshot.rse_base == 92 and snapshot.rse_bsp == 0xfd8 and
            snapshot.rse_bspstore == 0x1000 and
            snapshot.rse_bspload == 0x1000,
            "{} trap did not preserve the exact pre-fill backing gap: "
            "base={} BSP=0x{:x}/0x{:x}/0x{:x}".format(
                incomplete_label, snapshot.rse_base, snapshot.rse_bsp,
                snapshot.rse_bspstore, snapshot.rse_bspload
            ),
        )
        _require(
            snapshot.gr[32:36] == (0, 0, 0, 0) and
            (snapshot.nat_low & (0xf << 32)) == 0,
            "{} trap executed a mandatory fill before delivery: "
            "r32-r35={} NaT=0x{:x}:0x{:x}".format(
                incomplete_label,
                tuple("0x{:x}".format(value)
                      for value in snapshot.gr[32:36]),
                snapshot.nat_high, snapshot.nat_low
            ),
        )
        _require(
            snapshot.gr[24:28] == backing,
            "{} handler found changed backing payload: expected {}, got {}"
            .format(
                incomplete_label,
                tuple("0x{:x}".format(value) for value in backing),
                tuple("0x{:x}".format(value)
                      for value in snapshot.gr[24:28]),
            ),
        )
        program_count += 1
        return_encodings += 1

    # All four restored registers plus an RNAT word fit inside one 4 KiB
    # translation page, and every downward page crossing reaches the RNAT slot
    # at page_base-8 before a lower-page register.  Real SoftMMU can therefore
    # select the first register or the post-prefix RNAT boundary, but cannot
    # select arbitrary middle/last register reads without a test-only sub-page
    # fault injector.  The step-reader unit matrix separately covers register
    # callback failures at indices 0, 2 and 4; these rows add the two genuinely
    # realizable guest-MMU/RFI paths.
    fill_fault_isr = IA64_ISR_R | IA64_ISR_RS | IA64_ISR_IR

    fault_program, fault_pfs, backing, replacement = \
        typed_return_register_fill_fault_program()
    faulted = run_program(
        qemu,
        fault_program,

        typed_return_traces=((0xa0, 3),),
        typed_rfi_traces=(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x60,),
        one_bundle_per_tb=True,
    )
    _require(
        faulted.ip == fault_program.terminal_ip and
        faulted.exception_pending and
        faulted.exception_kind == "alternate-data-tlb-miss" and
        faulted.exception_vector == IA64_ALTERNATE_DATA_TLB_VECTOR,
        "first-register fill fault did not RFI-resume to its terminal: "
        "IP=0x{:x} EXC={}/0x{:x}".format(
            faulted.ip, faulted.exception_kind, faulted.exception_vector
        ),
    )
    _require(
        faulted.exception_source == 0x100 and
        faulted.exception_address == 0x8018 and
        faulted.cr_iip == 0x100 and faulted.cr_ifa == 0x8018 and
        faulted.cr_iipa == 0xa0,
        "first-register fault lacks committed target/IFA/source state: "
        "EXC=0x{:x}/0x{:x} IIP=0x{:x} IFA=0x{:x} IIPA=0x{:x}"
        .format(
            faulted.exception_source, faulted.exception_address,
            faulted.cr_iip, faulted.cr_ifa, faulted.cr_iipa
        ),
    )
    _require(
        faulted.cr_isr == fill_fault_isr and
        faulted.gr[6] == fill_fault_isr,
        "first-register fault expected exact R/RS/IR ISR=0x{:x}, got "
        "CR/gr=0x{:x}/0x{:x}".format(
            fill_fault_isr, faulted.cr_isr, faulted.gr[6]
        ),
    )
    _require(
        faulted.gr[5] == 0 and
        faulted.gr[12] == (IA64_PSR_IC | IA64_PSR_RT) and
        ((faulted.gr[12] >> IA64_PSR_RI_SHIFT) & 3) == 0 and
        faulted.cr_ipsr == IA64_PSR_IC and
        (faulted.psr & (IA64_PSR_IC | IA64_PSR_RT)) == IA64_PSR_IC,
        "first-register handler did not observe IFS.v=0 or clear only saved "
        "RT: IFS=0x{:x} saved-IPSR=0x{:x} CR.IPSR=0x{:x} PSR=0x{:x}"
        .format(
            faulted.gr[5], faulted.gr[12], faulted.cr_ipsr, faulted.psr
        ),
    )
    _require(
        faulted.cfm == (4 | (4 << 7)) and
        faulted.gr[22] == 0x2a and faulted.gr[23] == fault_pfs and
        faulted.br[6] == 0x107,
        "first-register RFI path lost the restored return frame: "
        "CFM=0x{:x} EC=0x{:x} PFS=0x{:x} b6=0x{:x}".format(
            faulted.cfm, faulted.gr[22], faulted.gr[23], faulted.br[6]
        ),
    )
    _require(
        faulted.rse_base == 92 and faulted.rse_bsp == 0x8000 and
        faulted.rse_bspstore == 0x8000 and
        faulted.rse_bspload == 0x8000,
        "first-register RFI did not finish the exact backing span: "
        "base={} BSP=0x{:x}/0x{:x}/0x{:x}".format(
            faulted.rse_base, faulted.rse_bsp, faulted.rse_bspstore,
            faulted.rse_bspload
        ),
    )
    _require(
        faulted.gr[32:36] == backing[:3] + (replacement,) and
        faulted.gr[25] == replacement,
        "faulting register read committed before the miss or did not retry: "
        "frame={} memory=0x{:x}".format(
            tuple("0x{:x}".format(value) for value in faulted.gr[32:36]),
            faulted.gr[25]
        ),
    )

    # Stop at the handler-visible RFI after interruption delivery has exposed
    # IFS.v=0 continuation state, then make a new QEMU process load and execute
    # that RFI.  This catches accidental dependence on source-process helper
    # state, pending-fill replay, or a translation cached before savevm.
    fault_migration = run_savevm_migration(
        qemu,
        fault_program,
        checkpoint_ip=IA64_ALTERNATE_DATA_TLB_VECTOR + 0x60,
        preserve_fault_slot=True,
    )
    checkpoint_differences = successful_snapshot_differences(
        fault_migration.checkpoint, fault_migration.restored
    )
    _require(
        not checkpoint_differences,
        "fresh-process RFI load changed its architectural checkpoint:\n  " +
        "\n  ".join(checkpoint_differences),
    )
    _require(
        fault_migration.checkpoint.ip ==
        IA64_ALTERNATE_DATA_TLB_VECTOR + 0x60 and
        fault_migration.checkpoint.gr[5] == 0 and
        fault_migration.checkpoint.cr_ipsr == IA64_PSR_IC,
        "RFI migration checkpoint did not expose IFS.v=0 continuation: "
        "IP=0x{:x} saved-IFS=0x{:x} IPSR=0x{:x}".format(
            fault_migration.checkpoint.ip,
            fault_migration.checkpoint.gr[5],
            fault_migration.checkpoint.cr_ipsr,
        ),
    )
    _require_typed_rfi_trace(
        fault_migration.destination_trace,
        IA64_ALTERNATE_DATA_TLB_VECTOR + 0x60,
    )
    migrated_fault = fault_migration.final
    _require(
        migrated_fault.ip == fault_program.terminal_ip and
        migrated_fault.cfm == (4 | (4 << 7)) and
        migrated_fault.gr[22] == 0x2a and
        migrated_fault.gr[23] == fault_pfs and
        migrated_fault.gr[32:36] == backing[:3] + (replacement,) and
        migrated_fault.gr[25] == replacement and
        migrated_fault.rse_base == 92 and
        migrated_fault.rse_bsp == 0x8000 and
        migrated_fault.rse_bspstore == 0x8000 and
        migrated_fault.rse_bspload == 0x8000,
        "fresh destination did not finish the IFS.v=0 RFI frame exactly: "
        "IP=0x{:x} CFM=0x{:x} EC=0x{:x} PFS=0x{:x} "
        "frame={} memory=0x{:x} RSE={}/0x{:x}/0x{:x}/0x{:x}".format(
            migrated_fault.ip, migrated_fault.cfm, migrated_fault.gr[22],
            migrated_fault.gr[23],
            tuple("0x{:x}".format(value)
                  for value in migrated_fault.gr[32:36]),
            migrated_fault.gr[25], migrated_fault.rse_base,
            migrated_fault.rse_bsp, migrated_fault.rse_bspstore,
            migrated_fault.rse_bspload,
        ),
    )
    program_count += 1
    return_encodings += 1

    rnat_program, rnat_pfs, backing, poison = \
        typed_return_rnat_fill_fault_program()
    rnat_faulted = run_program(
        qemu,
        rnat_program,

        typed_return_traces=((0x120, 3),),
        typed_rfi_traces=(IA64_ALTERNATE_DATA_TLB_VECTOR + 0x90,),
        one_bundle_per_tb=True,
    )
    _require(
        rnat_faulted.ip == rnat_program.terminal_ip and
        rnat_faulted.exception_pending and
        rnat_faulted.exception_kind == "alternate-data-tlb-miss" and
        rnat_faulted.exception_vector == IA64_ALTERNATE_DATA_TLB_VECTOR,
        "RNAT prefix fault did not RFI-resume to its terminal: "
        "IP=0x{:x} EXC={}/0x{:x}".format(
            rnat_faulted.ip, rnat_faulted.exception_kind,
            rnat_faulted.exception_vector
        ),
    )
    _require(
        rnat_faulted.exception_source == 0x200 and
        rnat_faulted.exception_address == 0x7ff8 and
        rnat_faulted.cr_iip == 0x200 and rnat_faulted.cr_ifa == 0x7ff8 and
        rnat_faulted.cr_iipa == 0x120,
        "RNAT fault lacks committed target/IFA/source state: "
        "EXC=0x{:x}/0x{:x} IIP=0x{:x} IFA=0x{:x} IIPA=0x{:x}"
        .format(
            rnat_faulted.exception_source, rnat_faulted.exception_address,
            rnat_faulted.cr_iip, rnat_faulted.cr_ifa,
            rnat_faulted.cr_iipa
        ),
    )
    _require(
        rnat_faulted.cr_isr == fill_fault_isr and
        rnat_faulted.gr[11] == fill_fault_isr,
        "RNAT fault expected exact R/RS/IR ISR=0x{:x}, got "
        "CR/gr=0x{:x}/0x{:x}".format(
            fill_fault_isr, rnat_faulted.cr_isr, rnat_faulted.gr[11]
        ),
    )
    _require(
        rnat_faulted.gr[10] == 0 and
        rnat_faulted.gr[12] == (IA64_PSR_IC | IA64_PSR_RT) and
        ((rnat_faulted.gr[12] >> IA64_PSR_RI_SHIFT) & 3) == 0 and
        rnat_faulted.cr_ipsr == IA64_PSR_IC and
        (rnat_faulted.psr & (IA64_PSR_IC | IA64_PSR_RT)) == IA64_PSR_IC,
        "RNAT handler did not observe IFS.v=0 or clear only saved RT: "
        "IFS=0x{:x} saved-IPSR=0x{:x} CR.IPSR=0x{:x} PSR=0x{:x}"
        .format(
            rnat_faulted.gr[10], rnat_faulted.gr[12],
            rnat_faulted.cr_ipsr, rnat_faulted.psr
        ),
    )
    _require(
        rnat_faulted.cfm == (4 | (4 << 7)) and
        rnat_faulted.gr[22] == 0x2a and
        rnat_faulted.gr[23] == rnat_pfs and rnat_faulted.br[6] == 0x207,
        "RNAT RFI path lost the restored return frame: "
        "CFM=0x{:x} EC=0x{:x} PFS=0x{:x} b6=0x{:x}".format(
            rnat_faulted.cfm, rnat_faulted.gr[22],
            rnat_faulted.gr[23], rnat_faulted.br[6]
        ),
    )
    _require(
        rnat_faulted.rse_base == 92 and rnat_faulted.rse_bsp == 0x7ff0 and
        rnat_faulted.rse_bspstore == 0x7ff0 and
        rnat_faulted.rse_bspload == 0x7ff0 and
        rnat_faulted.rse_rnat == (1 << 62),
        "RNAT RFI did not finish the exact cross-page backing span: "
        "base={} BSP=0x{:x}/0x{:x}/0x{:x} RNAT=0x{:x}".format(
            rnat_faulted.rse_base, rnat_faulted.rse_bsp,
            rnat_faulted.rse_bspstore, rnat_faulted.rse_bspload,
            rnat_faulted.rse_rnat
        ),
    )
    _require(
        rnat_faulted.gr[32:36] == backing and
        (rnat_faulted.pr & ((1 << 6) | (1 << 7))) == (1 << 7),
        "RNAT retry lost the final frame values or r32 NaT: frame={} "
        "PR=0x{:x}".format(
            tuple("0x{:x}".format(value)
                  for value in rnat_faulted.gr[32:36]),
            rnat_faulted.pr
        ),
    )
    _require(
        rnat_faulted.gr[25:29] == poison + (1 << 62,),
        "RNAT handler did not poison the committed prefix/RNAT memory: {}"
        .format(tuple("0x{:x}".format(value)
                      for value in rnat_faulted.gr[25:29])),
    )
    program_count += 1
    return_encodings += 1

    _require(program_count == 10 and return_encodings == 10,
             "typed return corpus drifted from ten programs/returns")
    return (
        "ten forced-one-bundle-TB BR_RET programs cover p0/true/false, "
        "aligned dynamic targets, same-group BR and AR.PFS forwarding versus "
        "ordinary overlay reads, clean and four-word incomplete SOL4 frame "
        "restoration across an RNAT slot, post-target trap state, pre-fill "
        "IR1/RS0 evidence, lower-privilege-over-taken-branch priority, and "
        "real SoftMMU first-register/RNAT R/RS/IR faults resumed by IFS.v=0 "
        "RFI with fault-word retry and committed-prefix idempotence, including "
        "a fresh-process save/load at the handler RFI; every return and RFI "
        "has direct typed ownership and one ordered focused-helper chain"
    )


def test_predicate_test_conformance(qemu: Path) -> str:
    matrix_program, observations = predicate_test_conformance_program()
    matrix = run_program(
        qemu, matrix_program,
        typed_direct_trace_ips=tuple(row[3] for row in observations),
        one_bundle_per_tb=True,
    )
    _require(not matrix.exception_pending,
             "predicate-test semantic matrix has a pending exception")
    _require(matrix.ip == matrix_program.terminal_ip,
             "predicate-test semantic matrix missed its terminal bundle")
    _require(
        matrix.gr[11] == 0x123456789abcdef0 and
        matrix.nat_low == (1 << 11),
        "predicate-test matrix did not preserve its NaT-tagged tbit/tnat "
        "source: r11=0x{:x} NaT=0x{:x}".format(
            matrix.gr[11], matrix.nat_low
        ),
    )
    for label, output, expected, _test_ip in observations:
        _require(
            matrix.gr[output] == expected,
            "{} expected PR image 0x{:x}, got r{}=0x{:x}".format(
                label, expected, output, matrix.gr[output]
            ),
        )

    alias_program = predicate_test_equal_target_alias_fault_program()
    alias = run_program(
        qemu, alias_program, preserve_fault_slot=True,
        typed_fault_trace_ip=0x70,
    )
    alias_raw = predicate_test(
        "tbit", 10, 10, relation="z", update="normal",
        r3=11, immediate=0, qp=10,
    )
    _require_illegal_operation(
        alias, fault_ip=0x70, fault_slot=2, fault_raw=alias_raw,
        collection_enabled=True, expected_iipa=0x70,
    )
    _require(
        alias.pr == ((1 << 0) | (1 << 10)) and
        alias.gr[11] == 0x123456789abcdef0 and
        alias.nat_low == (1 << 11),
        "qualified equal-target tbit changed its old-true target or source",
    )
    _require(alias.gr[20] == 77 and alias.gr[21] == 0,
             "qualified equal-target tbit did not retire only its prefix")

    predicated_off_program = \
        predicate_test_equal_target_predicated_off_program()
    predicated_off = run_program(
        qemu, predicated_off_program,
        preserve_fault_slot=True, typed_fault_trace_ip=0x60,
    )
    _require(not predicated_off.exception_pending,
             "false-qp normal equal-target tbit unexpectedly faulted")
    _require(
        predicated_off.ip == predicated_off_program.terminal_ip and
        predicated_off.pr == ((1 << 0) | (1 << 10)) and
        predicated_off.gr[22] == 0x55,
        "false-qp equal-target tbit changed p10 or suppressed its suffix",
    )
    _require(
        predicated_off.gr[11] == 0x123456789abcdef0 and
        predicated_off.nat_low == (1 << 11),
        "false-qp equal-target tbit changed its NaT source",
    )

    unc_program = predicate_test_equal_target_unc_fault_program()
    unc = run_program(
        qemu, unc_program, preserve_fault_slot=True,
        typed_fault_trace_ip=0x80,
    )
    unc_raw = predicate_test(
        "tbit", 10, 10, relation="z", update="normal",
        r3=11, immediate=0, unc=True, qp=5,
    )
    _require_illegal_operation(
        unc, fault_ip=0x80, fault_slot=2, fault_raw=unc_raw,
        collection_enabled=True, expected_iipa=0x80,
    )
    _require(
        unc.pr == ((1 << 0) | (1 << 10)) and
        unc.gr[11] == 0x123456789abcdef0 and
        unc.nat_low == (1 << 11),
        "false-qp equal-target tbit.unc changed its target or NaT source",
    )
    _require(unc.gr[23] == 66 and unc.gr[24] == 0,
             "equal-target tbit.unc did not retire only its prefix")

    return (
        "nine literal PR-image rows cover NaT, normal/.unc, AND/OR/OR.ANDCM, "
        "TNAT data, and CPUID[4] bits; three exact equal-target cases prove "
        "qualification, .unc precedence, prefix retirement, and source/target "
        "non-effects without generic execution helpers"
    )


def _print_failure(exc: Exception) -> None:
    for line in str(exc).splitlines() or [repr(exc)]:
        print("# " + line)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--qemu",
        required=True,
        type=Path,
        help="path to qemu-system-ia64 (an .exe is accepted on Windows)",
    )
    args = parser.parse_args(argv)
    qemu = args.qemu.expanduser().resolve()

    print("TAP version 13")
    print("1..27")
    if not qemu.is_file():
        print("not ok 1 - core integer equality")
        print("not ok 2 - NaT architectural golden")
        print("not ok 3 - scalar integer expansion")
        print("not ok 4 - predicate transaction and A6 compare")
        print("not ok 5 - integer compare conformance")
        print("not ok 6 - precise equal-target A6 faults")
        print("not ok 7 - typed issue-group TB continuation")
        print("not ok 8 - page-crossing overlay continuation")
        print("not ok 9 - internal-stop typed ownership handoff")
        print("not ok 10 - typed continuation structural invariants")
        print("not ok 11 - typed epoch savevm migration resume")
        print("not ok 12 - typed application-move RI restart")
        print("not ok 13 - PSR.ic in-flight serialization policy")
        print("not ok 14 - direct predicate-register moves")
        print("not ok 15 - predicate tests and direct branches")
        print("not ok 16 - typed branch RI restart")
        print("not ok 17 - typed branch-forward savevm migration")
        print("not ok 18 - predicate-test conformance")
        print("not ok 19 - direct branch-register moves")
        print("not ok 20 - typed BR-shadow savevm migration")
        print("not ok 21 - typed indirect and nonterminal branches")
        print("not ok 22 - typed loop branches")
        print("not ok 23 - typed call branches")
        print("not ok 24 - typed AR.PFS register moves")
        print("not ok 25 - typed return branches")
        print("not ok 26 - timer external interrupt and typed RFI")
        print("not ok 27 - nested self-IPI and ordered EOI")
        print("# QEMU executable does not exist: {}".format(qemu))
        return 1

    tests = (
        ("core integer equality", test_core_equality),
        ("NaT architectural golden", test_nat_golden),
        ("scalar integer expansion", test_scalar_integer_expansion),
        ("predicate transaction and A6 compare", test_predicate_transaction),
        ("integer compare conformance", test_integer_compare_conformance),
        ("precise equal-target A6 faults", test_equal_target_precise_faults),
        ("typed issue-group TB continuation",
         test_typed_group_tb_continuation),
        ("page-crossing overlay continuation",
         test_page_crossing_overlay_continuation),
        ("internal-stop typed ownership handoff",
         test_internal_stop_typed_handoff),
        ("typed continuation structural invariants",
         test_continuation_structural_invariants),
        ("typed epoch savevm migration resume",
         test_typed_epoch_savevm_migration),
        ("typed application-move RI restart",
         test_typed_application_move_ri_restart),
        ("PSR.ic in-flight serialization policy",
         test_psr_ic_inflight_policy),
        ("direct predicate-register moves", test_predicate_register_moves),
        ("predicate tests and direct branches",
         test_predicate_tests_and_direct_branches),
        ("typed branch RI restart", test_typed_branch_ri_restart),
        ("typed branch-forward savevm migration",
         test_typed_branch_forward_savevm_migration),
        ("predicate-test conformance", test_predicate_test_conformance),
        ("direct branch-register moves", test_branch_register_moves),
        ("typed BR-shadow savevm migration",
         test_typed_br_shadow_savevm_migration),
        ("typed indirect and nonterminal branches",
         test_typed_indirect_and_nonterminal_branches),
        ("typed loop branches", test_typed_loop_branches),
        ("typed call branches", test_typed_call_branches),
        ("typed AR.PFS register moves", test_pfs_register_moves),
        ("typed return branches", test_typed_return_branches),
        ("timer external interrupt and typed RFI",
         test_timer_external_interrupt_rfi),
        ("nested self-IPI and ordered EOI", test_nested_self_ipi),
    )
    failures = 0
    for index, (name, test) in enumerate(tests, start=1):
        try:
            detail = test(qemu)
            print("ok {} - {}".format(index, name))
            print("# " + detail)
        except Exception as exc:
            failures += 1
            print("not ok {} - {}".format(index, name))
            _print_failure(exc)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
