#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent no-OS goldens for IA-64 floating-compute full TCG.

The legacy raw-slot executor is intentionally not an oracle here.  Expected
values are literal architectural results derived from Intel SDM volume 3,
F1--F14 and M18--M19.  The matrix names all 67 live opcodes; FMOV is covered
only by illegal-encoding tests because it is not an IA-64 instruction.

Use ``--self-check`` without a QEMU binary to validate the inventory,
encoders, and literal-golden shape.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Callable, Dict, Iterable, List, Sequence, Tuple


sys.path.insert(0, str(Path(__file__).resolve().parent))
from ia64_fp_tcg_spec import (  # noqa: E402
    FMOV_CATCHALL_FORM_PAIRS,
    FMOV_ILLEGAL_FORM_PAIRS,
    FMOV_MISDECODED_LIVE_ALIAS_PAIRS,
    FP_EXACT_DIRECT_OPCODE_NAMES,
    FP_LIVE_OPCODE_NAMES,
    FP_LIVE_OPCODES,
)


U64_MASK = (1 << 64) - 1
SLOT_MASK = (1 << 41) - 1
FPSR_RESET = 0x0009804C0270033F
FP_FAULT_VECTOR = 0x5C00
FP_TRAP_VECTOR = 0x5D00
DISABLED_FP_VECTOR = 0x5500
ILLEGAL_VECTOR = 0x5400
PSR_DFL = 1 << 18
PSR_DFH = 1 << 19
AR_UNAT = 36
AR_FPSR = 40


def bitfield(value: int, low: int, width: int) -> int:
    return (value & ((1 << width) - 1)) << low


def op(major: int) -> int:
    return bitfield(major, 37, 4)


def raw_setf(kind: str, f1: int, r2: int, qp: int = 0) -> int:
    form = {"sig": 0xE1, "exp": 0xE9, "s": 0xF1, "d": 0xF9}[kind]
    return (op(6) | bitfield(form, 27, 9) | bitfield(r2, 13, 7)
            | bitfield(f1, 6, 7) | bitfield(qp, 0, 6))


def raw_getf(kind: str, r1: int, f2: int, qp: int = 0) -> int:
    form = {"sig": 0xE1, "exp": 0xE9, "s": 0xF1, "d": 0xF9}[kind]
    return (op(4) | bitfield(form, 27, 9) | bitfield(f2, 13, 7)
            | bitfield(r1, 6, 7) | bitfield(qp, 0, 6))


def raw_f1(major: int, f1: int, f2: int, f3: int, f4: int,
           sf: int = 0, x: int = 0, qp: int = 0) -> int:
    return (op(major) | bitfield(x, 36, 1) | bitfield(sf, 34, 2)
            | bitfield(f4, 27, 7) | bitfield(f3, 20, 7)
            | bitfield(f2, 13, 7) | bitfield(f1, 6, 7)
            | bitfield(qp, 0, 6))


def raw_f8(major: int, form: int, f1: int = 8, f2: int = 2,
           f3: int = 3, sf: int = 0, qp: int = 0) -> int:
    return (op(major) | bitfield(sf, 34, 2) | bitfield(form, 27, 6)
            | bitfield(f3, 20, 7) | bitfield(f2, 13, 7)
            | bitfield(f1, 6, 7) | bitfield(qp, 0, 6))


def raw_f9(major: int, form: int, f1: int = 8, f2: int = 2,
           f3: int = 3, qp: int = 0) -> int:
    # bits 36:34 and bit 33 are architecturally fixed zero.
    return (op(major) | bitfield(form, 27, 6) | bitfield(f3, 20, 7)
            | bitfield(f2, 13, 7) | bitfield(f1, 6, 7)
            | bitfield(qp, 0, 6))


def raw_fcvt(form: int, f1: int = 8, f2: int = 2, major: int = 0,
             sf: int = 0, qp: int = 0) -> int:
    return (op(major) | bitfield(sf, 34, 2) | bitfield(form, 27, 6)
            | bitfield(f2, 13, 7) | bitfield(f1, 6, 7)
            | bitfield(qp, 0, 6))


def raw_approx(major: int, reciprocal_sqrt: bool, f1: int = 8,
               f2: int = 2, f3: int = 3, p2: int = 6, sf: int = 0,
               qp: int = 0) -> int:
    return (op(major) | bitfield(reciprocal_sqrt, 36, 1)
            | bitfield(sf, 34, 2) | bitfield(1, 33, 1)
            | bitfield(p2, 27, 6) | bitfield(f3, 20, 7)
            | bitfield(f2, 13, 7) | bitfield(f1, 6, 7)
            | bitfield(qp, 0, 6))


def raw_fcmp(p1: int = 5, p2: int = 6, f2: int = 2, f3: int = 3,
             relation: str = "lt", sf: int = 0, unc: bool = False,
             qp: int = 0) -> int:
    ra, rb = {"eq": (0, 0), "lt": (0, 1), "le": (1, 0),
              "unord": (1, 1)}[relation]
    return (op(4) | bitfield(rb, 36, 1) | bitfield(sf, 34, 2)
            | bitfield(ra, 33, 1) | bitfield(p2, 27, 6)
            | bitfield(f3, 20, 7) | bitfield(f2, 13, 7)
            | bitfield(unc, 12, 1) | bitfield(p1, 6, 6)
            | bitfield(qp, 0, 6))


def raw_fclass(class_mask: int, p1: int = 5, p2: int = 6,
               f2: int = 2, unc: bool = False, qp: int = 0) -> int:
    return (op(5) | bitfield(class_mask & 3, 33, 2)
            | bitfield(p2, 27, 6) | bitfield(class_mask >> 2, 20, 7)
            | bitfield(f2, 13, 7) | bitfield(unc, 12, 1)
            | bitfield(p1, 6, 6) | bitfield(qp, 0, 6))


def raw_fsetc(sf: int, amask: int, omask: int, qp: int = 0) -> int:
    return (bitfield(sf, 34, 2) | bitfield(0x04, 27, 6)
            | bitfield(omask, 20, 7) | bitfield(amask, 13, 7)
            | bitfield(qp, 0, 6))


def raw_fclrf(sf: int, qp: int = 0) -> int:
    return bitfield(sf, 34, 2) | bitfield(0x05, 27, 6) | bitfield(qp, 0, 6)


def raw_fchkf(sf: int, displacement: int, qp: int = 0) -> int:
    if displacement % 16:
        raise ValueError("fchkf target displacement must be bundle aligned")
    immediate = (displacement // 16) & ((1 << 21) - 1)
    return (bitfield(immediate >> 20, 36, 1) | bitfield(sf, 34, 2)
            | bitfield(0x08, 27, 6) | bitfield(immediate, 6, 20)
            | bitfield(qp, 0, 6))


def raw_xma(kind: str, f1: int = 8, f2: int = 2, f3: int = 3,
            f4: int = 4, qp: int = 0) -> int:
    x2 = {"l": 0, "hu": 2, "h": 3}[kind]
    if kind == "hu" and f2 == 0:
        # The f2==f0 specialization is architecturally xmpy.hu.
        pass
    return (op(0xE) | bitfield(1, 36, 1) | bitfield(x2, 34, 2)
            | bitfield(f4, 27, 7) | bitfield(f3, 20, 7)
            | bitfield(f2, 13, 7) | bitfield(f1, 6, 7)
            | bitfield(qp, 0, 6))


def raw_fselect(f1: int = 8, mask: int = 2, left: int = 3,
                right: int = 4, qp: int = 0) -> int:
    return (op(0xE) | bitfield(right, 27, 7) | bitfield(left, 20, 7)
            | bitfield(mask, 13, 7) | bitfield(f1, 6, 7)
            | bitfield(qp, 0, 6))


def raw_reserved_fmov(sf: int, form: int, qp: int = 0) -> int:
    return (bitfield(sf, 34, 2) | bitfield(form, 27, 6)
            | bitfield(3, 20, 7) | bitfield(2, 13, 7)
            | bitfield(8, 6, 7) | bitfield(qp, 0, 6))


@dataclasses.dataclass(frozen=True)
class FrSource:
    reg: int
    kind: str
    value: int


Encoder = Callable[[int], int]


@dataclasses.dataclass(frozen=True)
class FloatingCase:
    opcode: str
    unit: str
    encode: Encoder
    sources: Tuple[FrSource, ...]
    observe: str
    expected: int = 0
    mask: int = U64_MASK
    pr_expected: int | None = None
    pr_mask: int = 0
    pre_fpsr: int | None = None
    custom: bool = False


def src(reg: int, kind: str, value: int) -> FrSource:
    return FrSource(reg, kind, value & U64_MASK)


def fcase(opcode: str, raw: int, sources: Sequence[FrSource], observe: str,
          expected: int = 0, **kwargs) -> FloatingCase:
    return FloatingCase(opcode, "F", lambda _out, raw=raw: raw,
                        tuple(sources), observe, expected, **kwargs)


def make_cases() -> Tuple[FloatingCase, ...]:
    d = {
        "one": 0x3FF0000000000000,
        "one_half": 0x3FF8000000000000,
        "two": 0x4000000000000000,
        "two_quarter": 0x4002000000000000,
        "two_half": 0x4004000000000000,
        "three": 0x4008000000000000,
        "ten": 0x4024000000000000,
        "neg_two": 0xC000000000000000,
    }
    packed_a = 0x3FC00000C0000000       # +1.5, -2.0
    packed_b = 0x400000003F000000       # +2.0, +0.5
    packed_c = 0x3F80000040400000       # +1.0, +3.0
    bits_a = 0x11223344800000AA
    bits_b = 0xAABBCCDD7F000055
    select_mask = 0xFF00FF00FF00FF00
    select_a = 0x1122334455667788
    select_b = 0x8877665544332211
    select_expected = ((select_a & select_mask) |
                       (select_b & ~select_mask)) & U64_MASK
    sf1_shift = 6 + 13
    fsetc_expected = ((FPSR_RESET & ~(0x7F << sf1_shift)) |
                      (0x20 << sf1_shift))
    sf2_flags = 0x3F << (6 + 2 * 13 + 7)
    fclrf_input = FPSR_RESET | sf2_flags

    cases = (
        fcase("IA64_OP_FADD", raw_f1(8, 8, 2, 3, 1),
              (src(2, "d", d["one_half"]), src(3, "d", d["two_quarter"])),
              "d", 0x400E000000000000),                         # 3.75
        fcase("IA64_OP_FSUB", raw_f1(0xA, 8, 3, 2, 1),
              (src(2, "d", d["two_quarter"]), src(3, "d", d["one_half"])),
              "d", 0x3FE8000000000000),                         # 0.75
        fcase("IA64_OP_FMPY", raw_f1(8, 8, 0, 2, 3),
              (src(2, "d", d["one_half"]), src(3, "d", d["two_quarter"])),
              "d", 0x400B000000000000),                         # 3.375
        fcase("IA64_OP_FMA", raw_f1(8, 8, 2, 3, 4),
              (src(2, "d", d["one"]), src(3, "d", d["two"]),
               src(4, "d", d["three"])), "d", 0x401C000000000000),
        fcase("IA64_OP_FMS", raw_f1(0xA, 8, 2, 3, 4),
              (src(2, "d", d["one"]), src(3, "d", d["two"]),
               src(4, "d", d["three"])), "d", 0x4014000000000000),
        fcase("IA64_OP_FNMA", raw_f1(0xC, 8, 2, 3, 4),
              (src(2, "d", d["one"]), src(3, "d", d["two"]),
               src(4, "d", d["three"])), "d", 0xC014000000000000),
        fcase("IA64_OP_FNORM", raw_f1(8, 8, 0, 2, 1),
              (src(2, "d", d["one_half"]),), "d", d["one_half"]),

        fcase("IA64_OP_XMA_L", raw_xma("l"),
              (src(2, "sig", 5), src(3, "sig", 0x8000000000000000),
               src(4, "sig", 2)), "sig", 5),
        fcase("IA64_OP_XMA_H", raw_xma("h"),
              (src(2, "sig", 5), src(3, "sig", 0x8000000000000000),
               src(4, "sig", 2)), "sig", U64_MASK),
        fcase("IA64_OP_XMA_HU", raw_xma("hu"),
              (src(2, "sig", 5), src(3, "sig", 0x8000000000000000),
               src(4, "sig", 2)), "sig", 1),
        fcase("IA64_OP_XMPY_HU", raw_xma("hu", f2=0),
              (src(3, "sig", 0x8000000000000000), src(4, "sig", 2)),
              "sig", 1),
        fcase("IA64_OP_FSELECT", raw_fselect(),
              (src(2, "sig", select_mask), src(3, "sig", select_a),
               src(4, "sig", select_b)), "sig", select_expected),

        fcase("IA64_OP_FCMP", raw_fcmp(),
              (src(2, "d", d["one_half"]), src(3, "d", d["two_quarter"])),
              "none", pr_expected=1 << 5, pr_mask=(1 << 5) | (1 << 6)),
        fcase("IA64_OP_FCLASS", raw_fclass(0x12),
              (src(2, "d", 0xBFF0000000000000),), "none",
              pr_expected=1 << 5, pr_mask=(1 << 5) | (1 << 6)),
        fcase("IA64_OP_FMIN", raw_f8(0, 0x14),
              (src(2, "d", d["one_half"]), src(3, "d", d["neg_two"])),
              "d", d["neg_two"]),
        fcase("IA64_OP_FMAX", raw_f8(0, 0x15),
              (src(2, "d", d["one_half"]), src(3, "d", d["neg_two"])),
              "d", d["one_half"]),
        fcase("IA64_OP_FAMIN", raw_f8(0, 0x16),
              (src(2, "d", d["one_half"]), src(3, "d", d["neg_two"])),
              "d", d["one_half"]),
        fcase("IA64_OP_FAMAX", raw_f8(0, 0x17),
              (src(2, "d", d["one_half"]), src(3, "d", d["neg_two"])),
              "d", d["neg_two"]),

        fcase("IA64_OP_FRCPA", raw_approx(0, False),
              (src(2, "d", d["one"]), src(3, "d", d["one"])),
              "sig", 0xFF80000000000000,
              pr_expected=1 << 6, pr_mask=1 << 6),
        fcase("IA64_OP_FPRCPA", raw_approx(1, False),
              (src(2, "sig", 0x3F8000003F800000),
               src(3, "sig", 0x3F80000040000000)),
              "sig", 0x3F7F80003EFF8000,
              pr_expected=1 << 6, pr_mask=1 << 6),
        fcase("IA64_OP_FPRSQRTA", raw_approx(1, True),
              (src(3, "sig", 0x3F80000040800000),),
              "sig", 0x3F7F80003EFF8000,
              pr_expected=1 << 6, pr_mask=1 << 6),
        fcase("IA64_OP_FRSQRTA", raw_approx(0, True),
              (src(3, "d", d["one"]),), "sig", 0xFF80000000000000,
              pr_expected=1 << 6, pr_mask=1 << 6),

        fcase("IA64_OP_FCVT_XF", raw_fcvt(0x1C),
              (src(2, "sig", 0xFFFFFFFFFFFFFFFD),),
              "d", 0xC008000000000000),
        fcase("IA64_OP_FCVT_FX", raw_fcvt(0x18),
              (src(2, "d", 0x400C000000000000),), "sig", 4),
        fcase("IA64_OP_FCVT_FXU", raw_fcvt(0x1B),
              (src(2, "d", 0x4006000000000000),), "sig", 2),
        fcase("IA64_OP_FPABS", raw_f9(1, 0x10, f2=0, f3=2),
              (src(2, "sig", packed_a),), "sig", 0x3FC0000040000000),
        fcase("IA64_OP_FPNEG", raw_f9(1, 0x11, f2=2, f3=2),
              (src(2, "sig", packed_a),), "sig", 0xBFC0000040000000),
        fcase("IA64_OP_FPNEGABS", raw_f9(1, 0x11, f2=0, f3=2),
              (src(2, "sig", packed_a),), "sig", 0xBFC00000C0000000),

        FloatingCase("IA64_OP_GETF_D", "M",
                     lambda out: raw_getf("d", out, 2),
                     (src(2, "d", 0xC019000000000000),), "gr",
                     0xC019000000000000),
        FloatingCase("IA64_OP_GETF_S", "M",
                     lambda out: raw_getf("s", out, 2),
                     (src(2, "s", 0xC0600000),), "gr", 0xC0600000),
        FloatingCase("IA64_OP_GETF_EXP", "M",
                     lambda out: raw_getf("exp", out, 2),
                     (src(2, "exp", 0x28001),), "gr", 0x28001),
        FloatingCase("IA64_OP_GETF_SIG", "M",
                     lambda out: raw_getf("sig", out, 2),
                     (src(2, "sig", bits_a),), "gr", bits_a),
        FloatingCase("IA64_OP_SETF_D", "M",
                     lambda _out: raw_setf("d", 8, 2), (), "d",
                     0xC019000000000000),
        FloatingCase("IA64_OP_SETF_S", "M",
                     lambda _out: raw_setf("s", 8, 2), (), "s", 0xC0600000),
        FloatingCase("IA64_OP_SETF_EXP", "M",
                     lambda _out: raw_setf("exp", 8, 2), (), "exp", 0x28001),
        FloatingCase("IA64_OP_SETF_SIG", "M",
                     lambda _out: raw_setf("sig", 8, 2), (), "sig", bits_a),

        fcase("IA64_OP_FMERGE", raw_f9(0, 0x11),
              (src(2, "d", d["neg_two"]), src(3, "d", d["one_half"])),
              "d", d["one_half"]),
        fcase("IA64_OP_FMERGE_S", raw_f9(0, 0x10),
              (src(2, "d", d["neg_two"]), src(3, "d", d["one_half"])),
              "d", 0xBFF8000000000000),
        fcase("IA64_OP_FMERGE_SE", raw_f9(0, 0x12),
              (src(2, "d", d["neg_two"]), src(3, "d", d["one_half"])),
              "d", 0xC008000000000000),
        fcase("IA64_OP_FSETC", raw_fsetc(1, 0, 0x20), (), "fpsr",
              fsetc_expected, pre_fpsr=FPSR_RESET),
        fcase("IA64_OP_FCLRF", raw_fclrf(2), (), "fpsr",
              fclrf_input & ~sf2_flags, pre_fpsr=fclrf_input),
        FloatingCase("IA64_OP_FCHKF", "F",
                     lambda _out: raw_fchkf(1, 0x20), (), "none",
                     custom=True),
        fcase("IA64_OP_FPACK", raw_f9(0, 0x28),
              (src(2, "d", d["one_half"]), src(3, "d", d["neg_two"])),
              "sig", packed_a),

        fcase("IA64_OP_FAND", raw_f9(0, 0x2C),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", bits_a & bits_b),
        fcase("IA64_OP_FANDCM", raw_f9(0, 0x2D),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", bits_a & ~bits_b & U64_MASK),
        fcase("IA64_OP_FOR", raw_f9(0, 0x2E),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", bits_a | bits_b),
        fcase("IA64_OP_FXOR", raw_f9(0, 0x2F),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", bits_a ^ bits_b),
        fcase("IA64_OP_FSWAP", raw_f9(0, 0x34),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", 0x7F00005511223344),
        fcase("IA64_OP_FSWAP_NL", raw_f9(0, 0x35),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", 0xFF00005511223344),
        fcase("IA64_OP_FSWAP_NR", raw_f9(0, 0x36),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", 0x7F00005591223344),
        fcase("IA64_OP_FMIX_LR", raw_f9(0, 0x39),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", 0x112233447F000055),
        fcase("IA64_OP_FMIX_R", raw_f9(0, 0x3A),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", 0x800000AA7F000055),
        fcase("IA64_OP_FMIX_L", raw_f9(0, 0x3B),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", 0x11223344AABBCCDD),
        fcase("IA64_OP_FSXT_R", raw_f9(0, 0x3C),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", 0xFFFFFFFF7F000055),
        fcase("IA64_OP_FSXT_L", raw_f9(0, 0x3D),
              (src(2, "sig", bits_a), src(3, "sig", bits_b)),
              "sig", 0x00000000AABBCCDD),

        fcase("IA64_OP_FPMERGE", raw_f9(1, 0x11),
              (src(2, "sig", packed_a), src(3, "sig", 0xC02000003F000000)),
              "sig", 0xC02000003F000000),
        fcase("IA64_OP_FPMERGE_S", raw_f9(1, 0x10),
              (src(2, "sig", packed_a), src(3, "sig", 0xC02000003F000000)),
              "sig", 0x40200000BF000000),
        fcase("IA64_OP_FPMERGE_SE", raw_f9(1, 0x12),
              (src(2, "sig", packed_a), src(3, "sig", 0xC02000003F000000)),
              "sig", 0x3FA00000C0000000),
        fcase("IA64_OP_FPMIN", raw_f8(1, 0x14),
              (src(2, "sig", packed_a), src(3, "sig", packed_b)),
              "sig", packed_a),
        fcase("IA64_OP_FPMAX", raw_f8(1, 0x15),
              (src(2, "sig", packed_a), src(3, "sig", packed_b)),
              "sig", packed_b),
        fcase("IA64_OP_FPAMIN", raw_f8(1, 0x16),
              (src(2, "sig", packed_a), src(3, "sig", packed_b)),
              "sig", 0x3FC000003F000000),
        fcase("IA64_OP_FPAMAX", raw_f8(1, 0x17),
              (src(2, "sig", packed_a), src(3, "sig", packed_b)),
              "sig", 0x40000000C0000000),
        fcase("IA64_OP_FPCMP", raw_f8(1, 0x31),
              (src(2, "sig", packed_a), src(3, "sig", packed_b)),
              "sig", U64_MASK),
        fcase("IA64_OP_FPCVT", raw_fcvt(0x18, major=1),
              (src(2, "sig", packed_a),), "sig", 0x00000002FFFFFFFE),
        fcase("IA64_OP_FPMA", raw_f1(9, 8, 2, 3, 4, x=1),
              (src(2, "sig", packed_c), src(3, "sig", packed_a),
               src(4, "sig", packed_b)), "sig", 0x4080000040000000),
        fcase("IA64_OP_FPMS", raw_f1(0xB, 8, 2, 3, 4, x=1),
              (src(2, "sig", packed_c), src(3, "sig", packed_a),
               src(4, "sig", packed_b)), "sig", 0x40000000C0800000),
        fcase("IA64_OP_FPNMA", raw_f1(0xD, 8, 2, 3, 4, x=1),
              (src(2, "sig", packed_c), src(3, "sig", packed_a),
               src(4, "sig", packed_b)), "sig", 0xC000000040800000),
    )
    return cases


def validate_runtime_contract() -> None:
    cases = make_cases()
    actual = tuple(case.opcode for case in cases)
    expected = tuple(op.opcode for op in FP_LIVE_OPCODES)
    if actual != expected:
        raise AssertionError(
            "runtime FP inventory drift: missing={}, extra={}, order={}".format(
                sorted(set(expected) - set(actual)),
                sorted(set(actual) - set(expected)), actual != expected,
            )
        )
    if len(set(actual)) != 67 or set(actual) != FP_LIVE_OPCODE_NAMES:
        raise AssertionError("runtime FP inventory is not 67 unique live rows")
    by_name = {op.opcode: op for op in FP_LIVE_OPCODES}
    for case in cases:
        raw = case.encode(8)
        if raw & ~SLOT_MASK:
            raise AssertionError(case.opcode + " encoding exceeds 41 bits")
        if case.unit != by_name[case.opcode].unit:
            raise AssertionError(case.opcode + " unit mismatch")
        if case.observe not in {"none", "gr", "d", "s", "exp", "sig", "fpsr"}:
            raise AssertionError(case.opcode + " observation kind")
        if not case.custom and case.observe == "none" and case.pr_expected is None:
            raise AssertionError(case.opcode + " has no runtime witness")
        for source in case.sources:
            if source.kind not in {"d", "s", "exp", "sig"}:
                raise AssertionError(case.opcode + " source format")
    if len(FMOV_ILLEGAL_FORM_PAIRS) != 136:
        raise AssertionError("former FMOV illegal inventory is not 136")
    if len(FMOV_MISDECODED_LIVE_ALIAS_PAIRS) != 12:
        raise AssertionError("former FMOV live-alias inventory is not 12")
    if len(FMOV_CATCHALL_FORM_PAIRS) != 148:
        raise AssertionError("former FMOV total collision inventory is not 148")
    illegal_samples = {(0, 0x02), (0, 0x3F), (1, 0x02), (3, 0x3F)}
    if not illegal_samples <= set(FMOV_ILLEGAL_FORM_PAIRS):
        raise AssertionError("former FMOV illegal runtime samples drifted")
    live_alias_samples = {(1, 0x10), (3, 0x28)}
    if not live_alias_samples <= set(FMOV_MISDECODED_LIVE_ALIAS_PAIRS):
        raise AssertionError("former FMOV live-alias samples drifted")
    # Intel recommends zero in ignored fields, so the independent encoders
    # emit the canonical spelling even though nonzero aliases remain valid.
    for opcode in ("IA64_OP_FCVT_XF", "IA64_OP_FPACK", "IA64_OP_FAND",
                   "IA64_OP_FPABS", "IA64_OP_FPMERGE_SE"):
        raw = next(case.encode(8) for case in cases if case.opcode == opcode)
        if (raw >> 34) & 7:
            raise AssertionError(opcode + " violates bits-36:34 fixed zero")


def load_harness(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("ia64_full_tcg_harness", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import IA-64 harness from {}".format(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Builder:
    def __init__(self, harness: ModuleType, name: str):
        self.h = harness
        self.name = name
        self.address = 0x10
        self.data_address = 0x1000
        self.bundles: List[object] = []
        self.data: List[object] = []

    def add(self, template: int, slot0: int, slot1: int, slot2: int) -> int:
        address = self.address
        self.bundles.append(self.h.Bundle(address, template, slot0, slot1, slot2))
        self.address += 0x10
        return address

    def loads(self, values: Sequence[Tuple[int, int]]) -> None:
        if not values:
            return
        base = self.data_address
        for index, (_, value) in enumerate(values):
            self.data.append(self.h.DataWord(base + index * 8,
                                             value & U64_MASK, 8))
        self.add(0x01, self.h.nop_m(), self.h.adds(1, base, 0), self.h.nop_i())
        for index, (reg, _) in enumerate(values):
            advance = self.h.adds(1, 8, 1) if index + 1 < len(values) \
                else self.h.nop_i()
            self.add(0x01, self.h.ld8(reg, 1), advance, self.h.nop_i())
        self.data_address += len(values) * 8

    def set_fr(self, source: FrSource, gr: int) -> None:
        self.add(0x01, raw_setf(source.kind, source.reg, gr),
                 self.h.nop_i(), self.h.nop_i())

    def f(self, raw: int, *, template: int = 0x0D) -> int:
        return self.add(template, self.h.nop_m(), raw, self.h.nop_i())

    def m(self, raw: int) -> int:
        return self.add(0x01, raw, self.h.nop_i(), self.h.nop_i())

    def i(self, raw: int) -> int:
        return self.add(0x01, self.h.nop_m(), raw, self.h.nop_i())

    def finish(self):
        terminal = self.address
        self.bundles.append(self.h.spin_bundle(terminal))
        return self.h.Program(self.name, tuple(self.bundles), terminal,
                              tuple(self.data))


@dataclasses.dataclass(frozen=True)
class BuiltMatrix:
    program: object
    expected: Dict[int, Tuple[int, int, str]]
    trace_ips: Tuple[int, ...]


def _case_cost(case: FloatingCase) -> int:
    return int(case.observe != "none") + int(case.pr_expected is not None)


def matrix_chunks(cases: Sequence[FloatingCase], limit: int = 20) \
        -> Tuple[Tuple[FloatingCase, ...], ...]:
    chunks: List[List[FloatingCase]] = [[]]
    used = 0
    for case in cases:
        cost = _case_cost(case)
        if chunks[-1] and used + cost > limit:
            chunks.append([])
            used = 0
        chunks[-1].append(case)
        used += cost
    return tuple(tuple(chunk) for chunk in chunks if chunk)


def build_matrix(harness: ModuleType, number: int,
                 cases: Sequence[FloatingCase]) -> BuiltMatrix:
    builder = Builder(harness, "FP semantic matrix {}".format(number))
    expected: Dict[int, Tuple[int, int, str]] = {}
    traces: List[int] = []
    out = 8
    # PSR.dfl/dfh are disable bits: clear both before touching ordinary FRs.
    builder.m(harness.rsm(PSR_DFL | PSR_DFH))

    for case in cases:
        if case.custom:
            continue
        if case.pre_fpsr is not None:
            builder.loads(((7, case.pre_fpsr),))
            builder.m(harness.mov_m_grar(AR_FPSR, 7))

        # SETF rows use r2 as their architected input rather than a setup FR.
        if case.opcode.startswith("IA64_OP_SETF_"):
            builder.loads(((2, case.expected),))
        elif case.sources:
            loads = tuple((2 + index, source.value)
                          for index, source in enumerate(case.sources))
            builder.loads(loads)
            for index, source in enumerate(case.sources):
                builder.set_fr(source, 2 + index)

        result_reg = out if case.observe != "none" else 8
        raw = case.encode(result_reg)
        trace = builder.f(raw) if case.unit == "F" else builder.m(raw)
        traces.append(trace)

        if case.observe in {"d", "s", "exp", "sig"}:
            builder.m(raw_getf(case.observe, result_reg, 8))
            expected[result_reg] = (case.expected & U64_MASK,
                                    case.mask & U64_MASK, case.opcode)
            out += 1
        elif case.observe == "gr":
            expected[result_reg] = (case.expected & U64_MASK,
                                    case.mask & U64_MASK, case.opcode)
            out += 1
        elif case.observe == "fpsr":
            builder.m(harness.mov_m_argr(result_reg, AR_FPSR))
            expected[result_reg] = (case.expected & U64_MASK,
                                    case.mask & U64_MASK, case.opcode)
            out += 1

        if case.pr_expected is not None:
            builder.i(harness.mov_prgr(out))
            expected[out] = (case.pr_expected, case.pr_mask,
                             case.opcode + " predicates")
            out += 1

    if out > 32:
        raise AssertionError("FP matrix exhausted static GR outputs")
    return BuiltMatrix(builder.finish(), expected, tuple(traces))


def test_semantic_matrix(harness: ModuleType, qemu: Path,
                         _full_only: bool = False) -> str:
    cases = make_cases()
    chunks = matrix_chunks(cases)
    checked = 0
    failures: List[str] = []
    for number, chunk in enumerate(chunks, 1):
        matrix = build_matrix(harness, number, chunk)
        snapshot = harness.run_program(
            qemu, matrix.program,
            typed_direct_trace_ips=matrix.trace_ips,
        )
        for reg, (expected, mask, label) in matrix.expected.items():
            actual = snapshot.gr[reg]
            if (actual & mask) != (expected & mask):
                failures.append(
                    "{} r{} mask 0x{:016x}: expected 0x{:016x}, "
                    "got 0x{:016x}".format(
                        label, reg, mask, expected, actual))
            checked += 1
    expected_checks = sum(_case_cost(case) for case in cases)
    if checked != expected_checks:
        raise AssertionError("FP matrix witness count drift")
    if {case.opcode for case in cases} != FP_LIVE_OPCODE_NAMES:
        raise AssertionError("67-row runtime inventory drift")
    if failures:
        raise AssertionError("; ".join(failures))
    return ("67 live FP rows match independent literal goldens across "
            "{} no-OS matrices".format(len(chunks)))


def test_direct_predication(harness: ModuleType, qemu: Path,
                            _full_only: bool = False) -> str:
    """A false qualifier suppresses legality, disabled checks, and writes."""
    poison = 0xDEADBEEF01234567
    builder = Builder(harness, "exact FP false-predicate priority")
    builder.m(harness.rsm(PSR_DFL | PSR_DFH))
    builder.loads(((2, poison),))
    builder.m(raw_setf("sig", 8, 2))
    builder.m(harness.ssm(PSR_DFL | PSR_DFH))

    # The first row would be illegal because f0 is read-only; the second would
    # take a Disabled FP Register fault and overwrite f8.  p1 is reset-false,
    # so neither check nor either side effect is architecturally active.
    false_illegal = builder.f(raw_f9(
        0, 0x2C, f1=0, f2=2, f3=32, qp=1))
    false_write = builder.f(raw_f9(
        0, 0x2C, f1=8, f2=2, f3=32, qp=1))
    builder.m(harness.rsm(PSR_DFL | PSR_DFH))
    builder.m(raw_getf("sig", 20, 8))

    snapshot = harness.run_program(
        qemu, builder.finish(),
        typed_direct_trace_ips=(false_illegal, false_write),
    )
    if snapshot.exception_pending or snapshot.gr[20] != poison:
        raise AssertionError(
            "false direct-FP qualifier did not suppress fault/write")
    return "false qp suppresses f0 illegality, DFL/DFH faults, and FR writes"


def test_direct_group_overlay(harness: ModuleType, qemu: Path,
                              _full_only: bool = False) -> str:
    """Every read in a no-stop group selects the FR entry image."""
    left = 0xFFFF0000FFFF0000
    right = 0x0F0F0F0F0F0F0F0F
    mask = 0x00FF00FF00FF00FF
    entry = 0x11223344800000AA
    builder = Builder(harness, "exact FP same-group entry image and WAW")
    builder.m(harness.rsm(PSR_DFL | PSR_DFH))
    builder.loads(((2, left), (3, right), (4, mask), (5, entry)))
    for fr, gr in ((2, 2), (3, 3), (4, 4), (8, 5)):
        builder.m(raw_setf("sig", fr, gr))

    # Template 0x0c has no trailing stop.  The second f8 writer aliases f8 as
    # a source, and the f9 writer reads it again: both must see `entry`, not
    # the first writer's eager retired value.  The final WAW still wins.
    first = builder.f(raw_f9(
        0, 0x2C, f1=8, f2=2, f3=3), template=0x0C)
    waw = builder.f(raw_f9(
        0, 0x2D, f1=8, f2=8, f3=4), template=0x0C)
    alias = builder.f(raw_f9(
        0, 0x2E, f1=9, f2=8, f3=4), template=0x0D)
    builder.m(raw_getf("sig", 20, 8))
    builder.m(raw_getf("sig", 21, 9))

    snapshot = harness.run_program(
        qemu, builder.finish(),
        typed_direct_trace_ips=(first, waw, alias),
    )
    expected_waw = entry & ~mask & U64_MASK
    expected_alias = entry | mask
    if snapshot.gr[20] != expected_waw:
        raise AssertionError(
            "same-group WAW source bypassed the f8 entry image")
    if snapshot.gr[21] != expected_alias:
        raise AssertionError(
            "same-group FR consumer observed an eager f8 write")
    return "no-stop FR reads use the entry image and the final WAW retires"


def test_direct_natval(harness: ModuleType, qemu: Path,
                       _full_only: bool = False) -> str:
    """NaTVal propagates through every normalized direct source layout."""
    program = harness.Program(
        "exact FP NaTVal source-layout propagation",
        (
            harness.Bundle(0x10, 0x01,
                           harness.rsm(PSR_DFL | PSR_DFH),
                           harness.adds(8, 1, 0),
                           harness.adds(9, 0x1000, 0)),
            harness.Bundle(0x20, 0x01,
                           harness.mov_m_grar(AR_UNAT, 8),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x30, 0x01, harness.ld8_fill(2, 9),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x40, 0x01, harness.nop_m(),
                           harness.adds(3, 3, 0),
                           harness.adds(4, 5, 0)),
            harness.Bundle(0x50, 0x01, raw_setf("sig", 2, 2),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x60, 0x01, raw_setf("sig", 3, 3),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x70, 0x01, raw_setf("sig", 4, 4),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x80, 0x0D, harness.nop_m(),
                           raw_fcvt(0x1C, f1=8, f2=2), harness.nop_i()),
            harness.Bundle(0x90, 0x0D, harness.nop_m(),
                           raw_f9(0, 0x2C, f1=9, f2=3, f3=2),
                           harness.nop_i()),
            harness.Bundle(0xA0, 0x0D, harness.nop_m(),
                           raw_xma("l", f1=10, f2=3, f3=4, f4=2),
                           harness.nop_i()),
            harness.Bundle(0xB0, 0x0D, harness.nop_m(),
                           raw_xma("hu", f1=11, f2=0, f3=3, f4=2),
                           harness.nop_i()),
            harness.Bundle(0xC0, 0x01, raw_getf("exp", 20, 8),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xD0, 0x01, raw_getf("exp", 21, 9),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xE0, 0x01, raw_getf("exp", 22, 10),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0xF0, 0x01, raw_getf("exp", 23, 11),
                           harness.nop_i(), harness.nop_i()),
            harness.spin_bundle(0x100),
        ),
        0x100, (harness.DataWord(0x1000, 0x1122334455667788, 8),),
    )
    snapshot = harness.run_program(
        qemu, program,
        typed_direct_trace_ips=(0x80, 0x90, 0xA0, 0xB0),
    )
    if (snapshot.exception_pending or
            any(snapshot.gr[reg] != 0x1FFFE for reg in range(20, 24))):
        raise AssertionError(
            "direct unary/binary/ternary/XMPY source did not propagate NaTVal")
    return "NaTVal propagates through unary, binary, ternary, and XMPY layouts"


def test_direct_illegal_before_disabled(harness: ModuleType, qemu: Path,
                                        _full_only: bool = False) -> str:
    """Read-only f0/f1 destination legality precedes DFL/DFH checks."""
    for destination in (0, 1):
        raw = raw_f9(0, 0x2C, f1=destination, f2=2, f3=32)
        program = harness.Program(
            "exact FP f{} legality before disabled".format(destination),
            (
                harness.Bundle(0x10, 0x01,
                               harness.ssm(PSR_DFL | PSR_DFH),
                               harness.nop_i(), harness.nop_i()),
                harness.Bundle(0x20, 0x0D, harness.nop_m(), raw,
                               harness.nop_i()),
                harness.spin_bundle(ILLEGAL_VECTOR),
            ), ILLEGAL_VECTOR,
        )
        snapshot = harness.run_program(
            qemu, program, preserve_fault_slot=True,
            typed_direct_trace_ips=(0x20,),
        )
        if (not snapshot.exception_pending or
                snapshot.exception_vector != ILLEGAL_VECTOR or
                (snapshot.cr_isr & 0xFFFF) != 0):
            raise AssertionError(
                "f{} destination checked DFL/DFH before illegality".format(
                    destination))
    return "f0/f1 destinations take Illegal Operation before disabled-FR checks"


def test_direct_disabled_operand_order(harness: ModuleType, qemu: Path,
                                       _full_only: bool = False) -> str:
    """Disabled-FR classification follows destination, f2, then f3 order."""
    cases = (
        ("low destination before high source", PSR_DFL | PSR_DFH,
         8, 32, 33, 1),
        ("high destination before low source", PSR_DFL | PSR_DFH,
         40, 2, 3, 2),
        ("low second source", PSR_DFL, 40, 32, 2, 1),
        ("high second source", PSR_DFH, 8, 2, 32, 2),
    )
    for label, disable, destination, source2, source3, code in cases:
        raw = raw_f9(0, 0x2C, f1=destination, f2=source2, f3=source3)
        program = harness.Program(
            "exact FP disabled order " + label,
            (
                harness.Bundle(0x10, 0x01, harness.ssm(disable),
                               harness.nop_i(), harness.nop_i()),
                harness.Bundle(0x20, 0x0D, harness.nop_m(), raw,
                               harness.nop_i()),
                harness.spin_bundle(DISABLED_FP_VECTOR),
            ), DISABLED_FP_VECTOR,
        )
        snapshot = harness.run_program(
            qemu, program, preserve_fault_slot=True,
            typed_direct_trace_ips=(0x20,),
        )
        if (not snapshot.exception_pending or
                snapshot.exception_vector != DISABLED_FP_VECTOR or
                (snapshot.cr_isr & 0xFFFF) != code):
            raise AssertionError(
                "{}: expected disabled-FR code {}, got 0x{:x}".format(
                    label, code, snapshot.cr_isr & 0xFFFF))
    return "DFL/DFH faults follow destination/f2/f3 order and low/high codes"


def _load_constant_prefix(harness: ModuleType, values: Sequence[Tuple[int, int]],
                          start: int = 0x10, data_base: int = 0x1000):
    bundles = []
    data = tuple(harness.DataWord(data_base + index * 8, value, 8)
                 for index, (_, value) in enumerate(values))
    address = start
    bundles.append(harness.Bundle(address, 0x01, harness.nop_m(),
                                  harness.adds(1, data_base, 0), harness.nop_i()))
    address += 0x10
    for index, (reg, _) in enumerate(values):
        advance = harness.adds(1, 8, 1) if index + 1 < len(values) \
            else harness.nop_i()
        bundles.append(harness.Bundle(address, 0x01, harness.ld8(reg, 1),
                                      advance, harness.nop_i()))
        address += 0x10
    return bundles, data, address


def test_fchkf_control(harness: ModuleType, qemu: Path,
                       _full_only: bool = False) -> str:
    sf = 1
    flag = 1 << (6 + 13 * sf + 7 + 5)  # sf1 inexact flag
    prefix, data, address = _load_constant_prefix(
        harness, ((7, FPSR_RESET | flag),)
    )
    bundles = list(prefix)
    bundles.append(harness.Bundle(address, 0x01,
                                  harness.rsm(PSR_DFL | PSR_DFH),
                                  harness.nop_i(), harness.nop_i()))
    address += 0x10
    bundles.append(harness.Bundle(address, 0x01,
                                  harness.mov_m_grar(AR_FPSR, 7),
                                  harness.nop_i(), harness.nop_i()))
    address += 0x10
    bundles.append(harness.Bundle(address, 0x01, harness.nop_m(),
                                  harness.adds(20, 0x111, 0), harness.nop_i()))
    address += 0x10
    first = address
    bundles.append(harness.Bundle(address, 0x0D, harness.nop_m(),
                                  raw_fchkf(sf, 0x20), harness.nop_i()))
    address += 0x10
    bundles.append(harness.Bundle(address, 0x01, harness.nop_m(),
                                  harness.adds(20, 0xBAD, 0), harness.nop_i()))
    address += 0x10
    bundles.append(harness.Bundle(address, 0x0D, harness.nop_m(),
                                  raw_fclrf(sf), harness.nop_i()))
    address += 0x10
    bundles.append(harness.Bundle(address, 0x01, harness.nop_m(),
                                  harness.adds(21, 0x222, 0), harness.nop_i()))
    address += 0x10
    second = address
    bundles.append(harness.Bundle(address, 0x0D, harness.nop_m(),
                                  raw_fchkf(sf, 0x20), harness.nop_i()))
    address += 0x10
    bundles.append(harness.Bundle(address, 0x01, harness.nop_m(),
                                  harness.adds(21, 0x333, 0), harness.nop_i()))
    address += 0x10
    bundles.append(harness.spin_bundle(address))
    program = harness.Program("fchkf flags branch and clear", tuple(bundles),
                              address, data)
    snapshot = harness.run_program(
        qemu, program, typed_direct_trace_ips=(first, second)
    )
    if snapshot.gr[20] != 0x111 or snapshot.gr[21] != 0x333:
        raise AssertionError("fchkf branch/clear outcome is wrong")
    return "fchkf branches on an exposed sf1 flag and falls through after fclrf"


def test_qualification_and_group(harness: ModuleType, qemu: Path,
                                 _full_only: bool = False) -> str:
    builder = Builder(harness, "FP qualification and same-group FR overlay")
    builder.m(harness.rsm(PSR_DFL | PSR_DFH))
    poison = 0xDEADBEEF01234567
    builder.loads(((2, 1 << 6), (3, poison)))
    builder.i(harness.mov_grpr(2, 1 << 6))
    builder.m(raw_setf("sig", 8, 3))
    false_ip = builder.f(raw_approx(0, False, qp=1))
    builder.m(raw_getf("sig", 20, 8))
    builder.i(harness.mov_prgr(21))

    builder.loads(((2, 0x3FF0000000000000),
                   (3, 0x4000000000000000),
                   (4, 0x4024000000000000)))
    builder.m(raw_setf("d", 2, 2))
    builder.m(raw_setf("d", 3, 3))
    builder.m(raw_setf("d", 8, 4))
    producer = builder.f(raw_f1(8, 8, 2, 3, 1), template=0x0C)
    consumer = builder.f(raw_f1(8, 9, 8, 2, 1), template=0x0D)
    builder.m(raw_getf("d", 22, 8))
    builder.m(raw_getf("d", 23, 9))
    snapshot = harness.run_program(
        qemu, builder.finish(),
        typed_direct_trace_ips=(false_ip, producer, consumer),
    )
    if snapshot.gr[20] != poison or snapshot.gr[21] & (1 << 6):
        raise AssertionError("false qp changed f8 or failed to clear p6")
    if snapshot.gr[22] != 0x4008000000000000:  # 1 + 2 = 3
        raise AssertionError("same-group FP producer result is wrong")
    if snapshot.gr[23] != 0x4026000000000000:  # old f8(10) + 1 = 11
        raise AssertionError("FP consumer read a live same-group f8")
    return "false qp preserves FR and clears approximation p2; FR reads use group entry"


def _fp_exception_program(harness: ModuleType, trap: bool):
    if trap:
        values = ((2, 0x4004000000000000),
                  (3, 0xDEADBEEF01234567),
                  (7, FPSR_RESET & ~(1 << 5)))
        vector = FP_TRAP_VECTOR
    else:
        values = ((2, 0), (3, 0), (4, 0xDEADBEEF01234567),
                  (7, FPSR_RESET & ~1))
        vector = FP_FAULT_VECTOR
    prefix, data, address = _load_constant_prefix(harness, values)
    bundles = list(prefix)
    bundles.append(harness.Bundle(address, 0x01,
                                  harness.rsm(PSR_DFL | PSR_DFH),
                                  harness.nop_i(), harness.nop_i()))
    address += 0x10
    bundles.append(harness.Bundle(address, 0x01,
                                  harness.mov_m_grar(AR_FPSR, 7),
                                  harness.nop_i(), harness.nop_i()))
    address += 0x10
    if trap:
        bundles.append(harness.Bundle(address, 0x01, raw_setf("d", 2, 2),
                                      harness.nop_i(), harness.nop_i()))
        address += 0x10
        bundles.append(harness.Bundle(address, 0x01, raw_setf("sig", 8, 3),
                                      harness.nop_i(), harness.nop_i()))
        address += 0x10
        fault_ip = address
        raw = raw_fcvt(0x18)
    else:
        for fr, gr in ((2, 2), (3, 3), (8, 4)):
            bundles.append(harness.Bundle(address, 0x01, raw_setf(
                "d" if fr != 8 else "sig", fr, gr), harness.nop_i(), harness.nop_i()))
            address += 0x10
        fault_ip = address
        raw = raw_approx(0, False)
    bundles.append(harness.Bundle(address, 0x0D, harness.nop_m(), raw,
                                  harness.nop_i()))
    bundles.append(harness.Bundle(vector, 0x01, harness.rsm(PSR_DFL | PSR_DFH),
                                  harness.nop_i(), harness.nop_i()))
    bundles.append(harness.Bundle(vector + 0x10, 0x01,
                                  raw_getf("sig", 20, 8),
                                  harness.nop_i(), harness.nop_i()))
    bundles.append(harness.Bundle(vector + 0x20, 0x01,
                                  harness.mov_m_argr(21, AR_FPSR),
                                  harness.nop_i(), harness.nop_i()))
    bundles.append(harness.spin_bundle(vector + 0x30))
    program = harness.Program("FP {} transaction".format(
        "trap" if trap else "fault"), tuple(bundles), vector + 0x30, data)
    return program, fault_ip


def test_fp_fault_and_trap(harness: ModuleType, qemu: Path,
                           _full_only: bool = False) -> str:
    fault_program, fault_ip = _fp_exception_program(harness, False)
    faulted = harness.run_program(
        qemu, fault_program, typed_direct_trace_ips=(fault_ip,)
    )
    if (not faulted.exception_pending or
            faulted.exception_vector != FP_FAULT_VECTOR):
        raise AssertionError("invalid operation did not enter FP fault vector")
    if faulted.gr[20] != 0xDEADBEEF01234567:
        raise AssertionError("pre-result FP fault committed f8")

    trap_program, trap_ip = _fp_exception_program(harness, True)
    trapped = harness.run_program(
        qemu, trap_program, typed_direct_trace_ips=(trap_ip,)
    )
    if (not trapped.exception_pending or
            trapped.exception_vector != FP_TRAP_VECTOR):
        raise AssertionError("inexact conversion did not enter FP trap vector")
    if trapped.gr[20] != 2:
        raise AssertionError("post-result FP trap did not commit f8")
    inexact_flag = 1 << (6 + 7 + 5)
    if not (trapped.gr[21] & inexact_flag):
        raise AssertionError("post-result FP trap did not commit FPSR.I")
    return "FP V fault rolls back result; FP I trap exposes committed result and FPSR"


def test_disabled_fp(harness: ModuleType, qemu: Path,
                     _full_only: bool = False) -> str:
    raw = raw_f1(8, 8, 2, 3, 1)
    program = harness.Program(
        "disabled low FP partition",
        (harness.Bundle(0x10, 0x01, harness.ssm(PSR_DFL),
                        harness.nop_i(), harness.nop_i()),
         harness.Bundle(0x20, 0x0D, harness.nop_m(), raw, harness.nop_i()),
         harness.spin_bundle(DISABLED_FP_VECTOR)),
        DISABLED_FP_VECTOR,
    )
    snapshot = harness.run_program(qemu, program)
    if (not snapshot.exception_pending or
            snapshot.exception_vector != DISABLED_FP_VECTOR):
        raise AssertionError("low FR access did not raise disabled-FP fault")
    return "low-partition FR access faults at vector 0x5500 while PSR.dfl is set"


def test_reserved_fmov(harness: ModuleType, qemu: Path,
                       _full_only: bool = False) -> str:
    samples = ((0, 0x02), (0, 0x3F), (1, 0x02), (3, 0x3F))
    for ignored_35_34, form in samples:
        raw = raw_reserved_fmov(ignored_35_34, form)
        program = harness.Program(
            "reserved former FMOV ignored{} form{:02x}".format(
                ignored_35_34, form
            ),
            (harness.Bundle(0x10, 0x0D, harness.nop_m(), raw, harness.nop_i()),
             harness.spin_bundle(ILLEGAL_VECTOR)), ILLEGAL_VECTOR,
        )
        snapshot = harness.run_program(qemu, program)
        if (not snapshot.exception_pending or
                snapshot.exception_vector != ILLEGAL_VECTOR):
            raise AssertionError("reserved ignored/form {}/0x{:02x} executed".format(
                ignored_35_34, form
            ))

    false_raw = raw_reserved_fmov(3, 0x3F, qp=1)
    false_program = harness.Program(
        "false-predicated reserved former FMOV",
        (harness.Bundle(0x10, 0x0D, harness.nop_m(), false_raw,
                        harness.nop_i()),
         harness.spin_bundle(0x20)),
        0x20,
    )
    false_snapshot = harness.run_program(qemu, false_program)
    if false_snapshot.exception_pending:
        raise AssertionError("false-predicated reserved former FMOV faulted")
    return ("four representatives of the 136 illegal former-FMOV pairs fault; "
            "a false-predicated representative is suppressed")


def test_nat_bridge(harness: ModuleType, qemu: Path,
                    full_only: bool = False) -> str:
    if full_only:
        raise AssertionError("full-only NaT bridge fixture was not filtered")
    program = harness.Program(
        "GR NaT to FR NaTVal round trip",
        (harness.Bundle(0x10, 0x01, harness.rsm(PSR_DFL | PSR_DFH),
                        harness.adds(8, 1, 0), harness.adds(9, 0x1000, 0)),
         harness.Bundle(0x20, 0x01, harness.mov_m_grar(AR_UNAT, 8),
                        harness.nop_i(), harness.nop_i()),
         harness.Bundle(0x30, 0x01, harness.ld8_fill(2, 9),
                        harness.nop_i(), harness.nop_i()),
         harness.Bundle(0x40, 0x01, raw_setf("sig", 8, 2),
                        harness.nop_i(), harness.nop_i()),
         harness.Bundle(0x50, 0x01, raw_getf("sig", 10, 8),
                        harness.nop_i(), harness.nop_i()),
         harness.spin_bundle(0x60)),
        0x60, (harness.DataWord(0x1000, 0x1122334455667788, 8),),
    )
    snapshot = harness.run_program(
        qemu, program, typed_direct_trace_ips=(0x40, 0x50)
    )
    if not (snapshot.nat_low & (1 << 10)):
        raise AssertionError("FR NaTVal did not return as a GR NaT")
    return "setf/getf bridge a real ld8.fill NaT through FR NaTVal"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path)
    parser.add_argument("--harness", type=Path)
    parser.add_argument("--full-only", action="store_true")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args()

    validate_runtime_contract()
    if args.self_check:
        print("IA-64 FP runtime contract passed: 67 live rows, "
              "136 illegal + 12 live former-FMOV collisions")
        return 0
    if args.qemu is None or args.harness is None:
        parser.error("--qemu and --harness are required unless --self-check is used")
    harness = load_harness(args.harness)
    tests = [
        ("67-row decoded FP literals", test_semantic_matrix),
        ("exact direct predication", test_direct_predication),
        ("exact direct FR group overlay", test_direct_group_overlay),
        ("exact direct NaTVal propagation", test_direct_natval),
        ("exact direct f0/f1 priority", test_direct_illegal_before_disabled),
        ("exact direct DFL/DFH order", test_direct_disabled_operand_order),
        ("FPSR control branch", test_fchkf_control),
        ("focused qualification and FR group overlay",
         test_qualification_and_group),
        ("focused FP fault and trap transaction", test_fp_fault_and_trap),
        ("focused disabled FP", test_disabled_fp),
        ("reserved former FMOV", test_reserved_fmov),
        ("focused NaT bridge", test_nat_bridge),
    ]

    print("TAP version 13")
    print("1..{}".format(len(tests)))
    failed = False
    for number, (name, function) in enumerate(tests, 1):
        try:
            detail = function(harness, args.qemu.resolve(), args.full_only)
            print("ok {} - {}".format(number, name))
            print("# " + detail)
        except Exception as exc:
            failed = True
            print("not ok {} - {}".format(number, name))
            print("# " + str(exc).replace("\n", "\n# "))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
