#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent no-OS goldens for every admitted IA-64 scalar integer row."""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Callable, Dict, List, Sequence, Tuple


U64_MASK = (1 << 64) - 1
SCALAR_OPCODES = (
    "IA64_OP_MOVL", "IA64_OP_ADDS", "IA64_OP_ADDL",
    "IA64_OP_ADD", "IA64_OP_ADD_ONE", "IA64_OP_SUB",
    "IA64_OP_SUB_ONE", "IA64_OP_SUB_IMM", "IA64_OP_AND",
    "IA64_OP_ANDCM", "IA64_OP_OR", "IA64_OP_XOR",
    "IA64_OP_AND_IMM", "IA64_OP_ANDCM_IMM", "IA64_OP_OR_IMM",
    "IA64_OP_XOR_IMM", "IA64_OP_SHLADD", "IA64_OP_SHL",
    "IA64_OP_SHR", "IA64_OP_SHRU", "IA64_OP_SHRP_IMM",
    "IA64_OP_DEPZ", "IA64_OP_DEPZ_IMM", "IA64_OP_DEP",
    "IA64_OP_DEP_IMM", "IA64_OP_EXTR", "IA64_OP_EXTRU",
    "IA64_OP_SXT1", "IA64_OP_SXT2", "IA64_OP_SXT4",
    "IA64_OP_ZXT1", "IA64_OP_ZXT2", "IA64_OP_ZXT4",
    "IA64_OP_SHLADDP4", "IA64_OP_MPY4", "IA64_OP_MPYSHL4",
    "IA64_OP_POPCNT", "IA64_OP_CLZ", "IA64_OP_ADDP4",
    "IA64_OP_ADDP4_IMM",
)
TWO_SOURCE_OPCODES = {
    "IA64_OP_ADD", "IA64_OP_ADD_ONE", "IA64_OP_SUB",
    "IA64_OP_SUB_ONE", "IA64_OP_AND", "IA64_OP_ANDCM",
    "IA64_OP_OR", "IA64_OP_XOR", "IA64_OP_SHLADD",
    "IA64_OP_SHL", "IA64_OP_SHR", "IA64_OP_SHRU",
    "IA64_OP_SHRP_IMM", "IA64_OP_DEP", "IA64_OP_SHLADDP4",
    "IA64_OP_MPY4", "IA64_OP_MPYSHL4", "IA64_OP_ADDP4",
}
NO_SOURCE_OPCODES = {"IA64_OP_MOVL", "IA64_OP_DEPZ_IMM"}
CHARACTER_OPCODES = {
    "IA64_OP_MUX1", "IA64_OP_MUX2", "IA64_OP_CZX1_L",
    "IA64_OP_CZX1_R", "IA64_OP_CZX2_L", "IA64_OP_CZX2_R",
}
XMA_OPCODES = {
    "IA64_OP_XMA_L", "IA64_OP_XMA_H", "IA64_OP_XMA_HU",
    "IA64_OP_XMPY_HU",
}


def bitfield(value: int, low: int, width: int) -> int:
    return (value & ((1 << width) - 1)) << low


def op(major: int) -> int:
    return bitfield(major, 37, 4)


def raw_a3(r1: int, x4: int, x2b: int, r2: int = 2, r3: int = 3,
           qp: int = 0, immediate: int | None = None) -> int:
    raw = (op(8) | bitfield(x4, 29, 4) | bitfield(x2b, 27, 2) |
           bitfield(r3, 20, 7) | bitfield(r1, 6, 7) |
           bitfield(qp, 0, 6))
    if immediate is None:
        return raw | bitfield(r2, 13, 7)
    encoded = immediate & 0xff
    return (raw | bitfield(encoded, 13, 7) |
            bitfield(encoded >> 7, 36, 1))


def raw_adds(r1: int, immediate: int, r3: int = 3,
             qp: int = 0) -> int:
    encoded = immediate & 0x3fff
    return (op(8) | bitfield(2, 34, 2) |
            bitfield(encoded, 13, 7) |
            bitfield(encoded >> 7, 27, 6) |
            bitfield(encoded >> 13, 36, 1) |
            bitfield(r3, 20, 7) | bitfield(r1, 6, 7) |
            bitfield(qp, 0, 6))


def raw_addl(r1: int, immediate: int, r3: int = 2,
             qp: int = 0) -> int:
    if not 0 <= r3 <= 3:
        raise ValueError("addl source must be r0 through r3")
    encoded = immediate & 0x3fffff
    return (op(9) | bitfield(encoded, 13, 7) |
            bitfield(encoded >> 7, 27, 9) |
            bitfield(encoded >> 16, 22, 5) |
            bitfield(encoded >> 21, 36, 1) |
            bitfield(r3, 20, 2) | bitfield(r1, 6, 7) |
            bitfield(qp, 0, 6))


def raw_shladd(r1: int, count: int, pointer: bool = False,
               r2: int = 2, r3: int = 3, qp: int = 0) -> int:
    if not 1 <= count <= 4:
        raise ValueError("shladd count must be in [1, 4]")
    return raw_a3(r1, 6 if pointer else 4, count - 1,
                  r2=r2, r3=r3, qp=qp)


def raw_addp4(r1: int, r2: int = 2, r3: int = 3,
              qp: int = 0) -> int:
    return raw_a3(r1, 2, 0, r2=r2, r3=r3, qp=qp)


def raw_addp4_imm(r1: int, immediate: int, r3: int = 3,
                  qp: int = 0) -> int:
    encoded = immediate & 0x3fff
    return (op(8) | bitfield(3, 34, 2) |
            bitfield(encoded, 13, 7) |
            bitfield(encoded >> 7, 27, 6) |
            bitfield(encoded >> 13, 36, 1) |
            bitfield(r3, 20, 7) | bitfield(r1, 6, 7) |
            bitfield(qp, 0, 6))


def raw_shift(r1: int, kind: str, r2: int = 2, r3: int = 3,
              qp: int = 0) -> int:
    x6 = {"shru": 0, "shr": 4, "shl": 8}[kind]
    if kind == "shl":
        count_field, value_field = r2, r3
    else:
        count_field, value_field = r2, r3
    raw = (op(7) | bitfield(1, 36, 1) | bitfield(1, 33, 1) |
           bitfield(x6, 27, 6) | bitfield(r1, 6, 7) |
           bitfield(qp, 0, 6))
    if kind == "shl":
        return raw | bitfield(count_field, 20, 7) | bitfield(value_field, 13, 7)
    return raw | bitfield(value_field, 20, 7) | bitfield(count_field, 13, 7)


def raw_shrp(r1: int, count: int, r2: int = 2, r3: int = 3,
             qp: int = 0) -> int:
    return (op(5) | bitfield(3, 34, 2) | bitfield(count, 27, 6) |
            bitfield(r3, 20, 7) | bitfield(r2, 13, 7) |
            bitfield(r1, 6, 7) | bitfield(qp, 0, 6))


def raw_depz(r1: int, pos: int, length: int, r2: int = 2,
             qp: int = 0) -> int:
    return (op(5) | bitfield(r1, 6, 7) | bitfield(r2, 13, 7) |
            bitfield(63 - pos, 20, 7) | bitfield(length - 1, 27, 6) |
            bitfield(1, 33, 1) | bitfield(1, 34, 2) |
            bitfield(qp, 0, 6))


def raw_depz_imm(r1: int, immediate: int, pos: int, length: int,
                 qp: int = 0) -> int:
    encoded = immediate & 0xff
    return (op(5) | bitfield(r1, 6, 7) |
            bitfield(encoded, 13, 7) | bitfield(127 - pos, 20, 7) |
            bitfield(length - 1, 27, 6) | bitfield(1, 33, 1) |
            bitfield(1, 34, 2) | bitfield(encoded >> 7, 36, 1) |
            bitfield(qp, 0, 6))


def raw_dep(r1: int, pos: int, length: int, r2: int = 2, r3: int = 3,
            qp: int = 0) -> int:
    cpos = 63 - pos
    return (op(4) | bitfield(length - 1, 27, 4) |
            bitfield(cpos, 31, 2) | bitfield(cpos >> 2, 33, 1) |
            bitfield(cpos >> 3, 34, 2) | bitfield(cpos >> 5, 36, 1) |
            bitfield(r3, 20, 7) | bitfield(r2, 13, 7) |
            bitfield(r1, 6, 7) | bitfield(qp, 0, 6))


def raw_dep_imm(r1: int, fill: int, pos: int, length: int, r3: int = 3,
                qp: int = 0) -> int:
    return (op(5) | bitfield(r1, 6, 7) |
            bitfield((63 - pos) << 1, 13, 7) |
            bitfield(r3, 20, 7) | bitfield(length - 1, 27, 6) |
            bitfield(1, 33, 1) | bitfield(3, 34, 2) |
            bitfield(fill, 36, 1) | bitfield(qp, 0, 6))


def raw_extr(r1: int, pos: int, length: int, signed: bool,
             r3: int = 3, qp: int = 0) -> int:
    return (op(5) | bitfield(r1, 6, 7) |
            bitfield((pos << 1) | int(signed), 13, 7) |
            bitfield(r3, 20, 7) | bitfield(length - 1, 27, 6) |
            bitfield(1, 34, 2) | bitfield(qp, 0, 6))


def raw_extend(r1: int, width: int, signed: bool, r3: int = 3,
               qp: int = 0) -> int:
    x6 = ({1: 0x14, 2: 0x15, 4: 0x16}[width] if signed else
          {1: 0x10, 2: 0x11, 4: 0x12}[width])
    return (bitfield(x6, 27, 6) | bitfield(r3, 20, 7) |
            bitfield(r1, 6, 7) | bitfield(qp, 0, 6))


def raw_mpy(r1: int, high_left: bool, r2: int = 2, r3: int = 3,
            qp: int = 0) -> int:
    return (op(7) | bitfield(1, 36, 1) |
            bitfield(0x1e if high_left else 0x1a, 27, 6) |
            bitfield(r3, 20, 7) | bitfield(r2, 13, 7) |
            bitfield(r1, 6, 7) | bitfield(qp, 0, 6))


def raw_count(r1: int, leading: bool, r3: int = 3, qp: int = 0,
              reserved_r2: int = 0) -> int:
    return (op(7) | bitfield(0x1a if leading else 0x12, 27, 6) |
            bitfield(3, 33, 3) | bitfield(r3, 20, 7) |
            bitfield(reserved_r2, 13, 7) | bitfield(r1, 6, 7) |
            bitfield(qp, 0, 6))


def movl_bundle(harness: ModuleType, address: int, reg: int, value: int,
                qp: int = 0):
    value &= U64_MASK
    l_slot = (value >> 22) & ((1 << 41) - 1)
    x_slot = (bitfield(reg, 6, 7) | bitfield(value, 13, 7) |
              bitfield(value >> 21, 21, 1) |
              bitfield(value >> 16, 22, 5) |
              bitfield(value >> 7, 27, 9) |
              bitfield(value >> 63, 36, 1) | op(6) |
              bitfield(qp, 0, 6))
    return harness.Bundle(address, 0x05, harness.nop_m(), l_slot, x_slot)


def signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def mask(pos: int, length: int) -> int:
    return (((1 << length) - 1) << pos) & U64_MASK


def golden_shift(kind: str, count: int, value: int) -> int:
    if kind == "shl":
        return 0 if count >= 64 else (value << count) & U64_MASK
    if kind == "shru":
        return 0 if count >= 64 else (value & U64_MASK) >> count
    return (signed(value, 64) >> min(count, 63)) & U64_MASK


def golden_shrp(left: int, right: int, count: int) -> int:
    if count == 0:
        return right & U64_MASK
    return ((left << (64 - count)) | ((right & U64_MASK) >> count)) & U64_MASK


def golden_addp4(left: int, right: int) -> int:
    low = (left + right) & 0xffffffff
    return low | (((right >> 30) & 3) << 61)


Encoder = Callable[[int, int, int, int], int]


@dataclasses.dataclass(frozen=True)
class ScalarCase:
    opcode: str
    unit: str
    encode: Encoder | None
    source2: int
    source3: int
    expected: int
    movl_value: int = 0


def _normal_case(opcode: str, unit: str, encode: Encoder,
                 source2: int, source3: int, expected: int) -> ScalarCase:
    return ScalarCase(opcode, unit, encode, source2 & U64_MASK,
                      source3 & U64_MASK, expected & U64_MASK)


def make_cases(edge: bool = False) -> Tuple[ScalarCase, ...]:
    a = (U64_MASK if edge else 0xFEDCBA9876543210)
    b = (0x8000000000000001 if edge else 0x0123456789ABCDEF)
    imm14 = -8192 if edge else -17
    imm22 = (1 << 21) - 1 if edge else -0x12345
    imm8 = -128 if edge else -37
    shl_count = 4 if edge else 3
    variable_count = 65 if edge else 9
    funnel_count = 63 if edge else 11
    depz_pos, depz_len = ((0, 64) if edge else (5, 13))
    dep_pos, dep_len = ((48, 16) if edge else (11, 13))
    extr_pos, extr_len = ((63, 1) if edge else (8, 12))
    depimm_pos, depimm_len = ((0, 64) if edge else (13, 9))
    movl_value = 0x8000000000000001 if edge else 0xFEDCBA9876543210

    cases: List[ScalarCase] = [
        ScalarCase("IA64_OP_MOVL", "L", None, a, b, movl_value, movl_value),
        _normal_case("IA64_OP_ADDS", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_adds(r1, imm14, r3, qp),
                     a, b, b + imm14),
        _normal_case("IA64_OP_ADDL", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_addl(r1, imm22, r2, qp),
                     a, b, a + imm22),
        _normal_case("IA64_OP_ADD", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 0, 0, r2, r3, qp),
                     a, b, a + b),
        _normal_case("IA64_OP_ADD_ONE", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 0, 1, r2, r3, qp),
                     a, b, a + b + 1),
        _normal_case("IA64_OP_SUB", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 1, 1, r2, r3, qp),
                     a, b, a - b),
        _normal_case("IA64_OP_SUB_ONE", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 1, 0, r2, r3, qp),
                     a, b, a - b - 1),
        _normal_case("IA64_OP_SUB_IMM", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 9, 1, r2, r3, qp, imm8),
                     a, b, imm8 - b),
        _normal_case("IA64_OP_AND", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 3, 0, r2, r3, qp),
                     a, b, a & b),
        _normal_case("IA64_OP_ANDCM", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 3, 1, r2, r3, qp),
                     a, b, a & ~b),
        _normal_case("IA64_OP_OR", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 3, 2, r2, r3, qp),
                     a, b, a | b),
        _normal_case("IA64_OP_XOR", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 3, 3, r2, r3, qp),
                     a, b, a ^ b),
        _normal_case("IA64_OP_AND_IMM", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 0xb, 0, r2, r3, qp, imm8),
                     a, b, b & imm8),
        _normal_case("IA64_OP_ANDCM_IMM", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 0xb, 1, r2, r3, qp, imm8),
                     a, b, imm8 & ~b),
        _normal_case("IA64_OP_OR_IMM", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 0xb, 2, r2, r3, qp, imm8),
                     a, b, b | imm8),
        _normal_case("IA64_OP_XOR_IMM", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_a3(r1, 0xb, 3, r2, r3, qp, imm8),
                     a, b, b ^ imm8),
        _normal_case("IA64_OP_SHLADD", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_shladd(r1, shl_count, False, r2, r3, qp),
                     a, b, (a << shl_count) + b),
        _normal_case("IA64_OP_SHL", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_shift(r1, "shl", r2, r3, qp),
                     variable_count, b, golden_shift("shl", variable_count, b)),
        _normal_case("IA64_OP_SHR", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_shift(r1, "shr", r2, r3, qp),
                     variable_count, a, golden_shift("shr", variable_count, a)),
        _normal_case("IA64_OP_SHRU", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_shift(r1, "shru", r2, r3, qp),
                     variable_count, a, golden_shift("shru", variable_count, a)),
        _normal_case("IA64_OP_SHRP_IMM", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_shrp(r1, funnel_count, r2, r3, qp),
                     a, b, golden_shrp(a, b, funnel_count)),
        _normal_case("IA64_OP_DEPZ", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_depz(r1, depz_pos, depz_len, r2, qp),
                     a, b, (a << depz_pos) & mask(depz_pos, depz_len)),
        _normal_case("IA64_OP_DEPZ_IMM", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_depz_imm(r1, imm8, depz_pos, depz_len, qp),
                     a, b, (signed(imm8, 8) << depz_pos) & mask(depz_pos, depz_len)),
        _normal_case("IA64_OP_DEP", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_dep(r1, dep_pos, dep_len, r2, r3, qp),
                     a, b, (b & ~mask(dep_pos, dep_len)) | ((a << dep_pos) & mask(dep_pos, dep_len))),
        _normal_case("IA64_OP_DEP_IMM", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_dep_imm(r1, 1, depimm_pos, depimm_len, r3, qp),
                     a, b, b | mask(depimm_pos, depimm_len)),
        _normal_case("IA64_OP_EXTR", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_extr(r1, extr_pos, extr_len, True, r3, qp),
                     a, b, signed((b >> extr_pos) & ((1 << extr_len) - 1), extr_len)),
        _normal_case("IA64_OP_EXTRU", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_extr(r1, extr_pos, extr_len, False, r3, qp),
                     a, b, (b >> extr_pos) & ((1 << extr_len) - 1)),
    ]
    for width in (1, 2, 4):
        cases.append(_normal_case(
            f"IA64_OP_SXT{width}", "I",
            lambda r1, r2=2, r3=3, qp=0, width=width:
                raw_extend(r1, width, True, r3, qp),
            a, b, signed(b, width * 8)))
    for width in (1, 2, 4):
        cases.append(_normal_case(
            f"IA64_OP_ZXT{width}", "I",
            lambda r1, r2=2, r3=3, qp=0, width=width:
                raw_extend(r1, width, False, r3, qp),
            a, b, b & ((1 << (width * 8)) - 1)))
    cases.extend((
        _normal_case("IA64_OP_SHLADDP4", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_shladd(r1, shl_count, True, r2, r3, qp),
                     a, b, golden_addp4((a << shl_count) & U64_MASK, b)),
        _normal_case("IA64_OP_MPY4", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_mpy(r1, False, r2, r3, qp),
                     a, b, (a & 0xffffffff) * (b & 0xffffffff)),
        _normal_case("IA64_OP_MPYSHL4", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_mpy(r1, True, r2, r3, qp),
                     a, b, ((((a >> 32) & 0xffffffff) * (b & 0xffffffff)) & 0xffffffff) << 32),
        _normal_case("IA64_OP_POPCNT", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_count(r1, False, r3, qp),
                     a, b, (b & U64_MASK).bit_count()),
        _normal_case("IA64_OP_CLZ", "I",
                     lambda r1, r2=2, r3=3, qp=0: raw_count(r1, True, r3, qp),
                     a, b, 64 if not b else 64 - (b & U64_MASK).bit_length()),
        _normal_case("IA64_OP_ADDP4", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_addp4(r1, r2, r3, qp),
                     a, b, golden_addp4(a, b)),
        _normal_case("IA64_OP_ADDP4_IMM", "A",
                     lambda r1, r2=2, r3=3, qp=0: raw_addp4_imm(r1, imm14, r3, qp),
                     a, b, golden_addp4(imm14, b)),
    ))
    if tuple(case.opcode for case in cases) != SCALAR_OPCODES:
        raise AssertionError("scalar runtime opcode inventory drifted")
    return tuple(cases)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@dataclasses.dataclass(frozen=True)
class BuiltMatrix:
    program: object
    expected: Dict[int, int]
    trace_ips: Tuple[int, ...]


def build_matrix(harness: ModuleType, name: str,
                 cases: Sequence[ScalarCase], m_slots: bool = False) -> BuiltMatrix:
    bundles: List[object] = []
    data: List[object] = []
    expected: Dict[int, int] = {}
    traces: List[int] = []
    address = 0x10
    data_address = 0x1000

    for destination, case in enumerate(cases, 8):
        base = data_address
        data.extend((harness.DataWord(base, case.source2, 8),
                     harness.DataWord(base + 8, case.source3, 8)))
        bundles.append(harness.Bundle(address, 0x01, harness.nop_m(),
                                      harness.adds(1, base, 0), harness.nop_i()))
        address += 0x10
        bundles.append(harness.Bundle(address, 0x01, harness.ld8(2, 1),
                                      harness.adds(1, 8, 1), harness.nop_i()))
        address += 0x10
        bundles.append(harness.Bundle(address, 0x01, harness.ld8(3, 1),
                                      harness.nop_i(), harness.nop_i()))
        address += 0x10
        if case.unit == "L":
            bundles.append(movl_bundle(harness, address, destination,
                                       case.movl_value))
        else:
            if case.encode is None:
                raise AssertionError(case.opcode + " lacks an encoder")
            raw = case.encode(destination, 2, 3, 0)
            if m_slots:
                if case.unit != "A":
                    raise AssertionError(case.opcode + " cannot use an M slot")
                bundles.append(harness.Bundle(address, 0x03, raw,
                                              harness.nop_i(), harness.nop_i()))
            else:
                bundles.append(harness.Bundle(address, 0x03, harness.nop_m(),
                                              raw, harness.nop_i()))
        traces.append(address)
        expected[destination] = case.expected
        address += 0x10
        data_address += 0x10
    bundles.append(harness.spin_bundle(address))
    return BuiltMatrix(harness.Program(name=name, bundles=tuple(bundles),
                                       terminal_ip=address, data=tuple(data)),
                       expected, tuple(traces))


def _check_matrix(harness: ModuleType, qemu: Path, matrix: BuiltMatrix) -> int:
    snapshot = harness.run_program(qemu, matrix.program,
                                   typed_direct_trace_ips=matrix.trace_ips)
    if snapshot.exception_pending:
        raise AssertionError(matrix.program.name + " raised an exception")
    for reg, expected in matrix.expected.items():
        if snapshot.gr[reg] != expected:
            raise AssertionError(
                "{} r{} expected 0x{:016x}, got 0x{:016x}".format(
                    matrix.program.name, reg, expected, snapshot.gr[reg]))
    return len(matrix.expected)


def test_semantic_model_matrix(harness: ModuleType, qemu: Path) -> str:
    checked = 0
    for edge in (False, True):
        cases = make_cases(edge)
        for chunk_no, start in enumerate(range(0, len(cases), 20), 1):
            matrix = build_matrix(
                harness, "scalar {} matrix {}".format(
                    "edge" if edge else "base", chunk_no),
                cases[start:start + 20])
            checked += _check_matrix(harness, qemu, matrix)
    if checked != 80:
        raise AssertionError("scalar model matrix did not check 80 rows")
    return ("80 generated base/boundary rows cover the exact 40-opcode "
            "scalar admission set with independent integer goldens")


def test_integer_multiply_add_forms(harness: ModuleType, qemu: Path) -> str:
    fp = load_module(Path(__file__).with_name("test-ia64-fp-tcg.py"),
                     "_ia64_scalar_xma_fp")
    cases = tuple(case for case in fp.make_cases()
                  if case.opcode in XMA_OPCODES)
    if {case.opcode for case in cases} != XMA_OPCODES:
        raise AssertionError("integer XMA runtime inventory drifted")
    matrix = fp.build_matrix(harness, 1, cases)
    snapshot = harness.run_program(qemu, matrix.program,
                                   typed_direct_trace_ips=matrix.trace_ips)
    for reg, (expected, result_mask, label) in matrix.expected.items():
        if (snapshot.gr[reg] & result_mask) != (expected & result_mask):
            raise AssertionError(label + " integer multiply-add mismatch")

    poison = 0xDEADBEEF01234567
    builder = fp.Builder(harness, "false XMA suppresses disabled checks")
    builder.m(harness.rsm(fp.PSR_DFL | fp.PSR_DFH))
    builder.loads(((2, poison),))
    builder.m(fp.raw_setf("sig", 8, 2))
    builder.m(harness.ssm(fp.PSR_DFL | fp.PSR_DFH))
    false_xma = builder.f(fp.raw_xma(
        "l", f1=8, f2=32, f3=33, f4=34, qp=1))
    builder.m(harness.rsm(fp.PSR_DFL | fp.PSR_DFH))
    builder.m(fp.raw_getf("sig", 20, 8))
    false_snapshot = harness.run_program(
        qemu, builder.finish(), typed_direct_trace_ips=(false_xma,))
    if false_snapshot.exception_pending or false_snapshot.gr[20] != poison:
        raise AssertionError("false XMA did not suppress disabled checks/write")

    disabled_raw = fp.raw_xma("l", f1=8, f2=32, f3=3, f4=4)
    disabled_program = harness.Program(
        "XMA high source disabled fault",
        (
            harness.Bundle(0x10, 0x01, harness.ssm(fp.PSR_DFH),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x20, 0x0D, harness.nop_m(), disabled_raw,
                           harness.nop_i()),
            harness.spin_bundle(fp.DISABLED_FP_VECTOR),
        ), fp.DISABLED_FP_VECTOR)
    disabled = harness.run_program(
        qemu, disabled_program, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x20,))
    if (not disabled.exception_pending or
            disabled.exception_vector != fp.DISABLED_FP_VECTOR or
            (disabled.cr_isr & 0xffff) != 2):
        raise AssertionError("XMA did not report its high disabled source")

    fp.test_direct_natval(harness, qemu)
    return ("xma.l/xma.h/xma.hu/xmpy.hu match literal 128-bit goldens; "
            "false qp, exact disabled-source fault, and NaTVal propagation pass")


def test_character_byte_forms(harness: ModuleType, qemu: Path) -> str:
    packed = load_module(Path(__file__).with_name("test-ia64-packed-tcg.py"),
                         "_ia64_scalar_character_packed")
    cases = tuple(case for case in packed.make_cases()
                  if case.opcode in CHARACTER_OPCODES)
    if {case.opcode for case in cases} != CHARACTER_OPCODES:
        raise AssertionError("character/byte runtime inventory drifted")
    matrix = packed.build_matrix(harness, "character and byte forms", cases,
                                 False)
    _check_matrix(harness, qemu, BuiltMatrix(
        matrix.program, matrix.expected, matrix.direct_trace_ips))
    return "mux1/mux2 and all czx byte/halfword scans match lane-unique goldens"


def _alias_matrix(harness: ModuleType) -> BuiltMatrix:
    cases = tuple(case for case in make_cases(False)
                  if case.opcode in TWO_SOURCE_OPCODES)
    if len(cases) != 18:
        raise AssertionError("two-source scalar inventory drifted")
    bundles: List[object] = []
    data: List[object] = []
    expected: Dict[int, int] = {}
    traces: List[int] = []
    address = 0x10
    data_address = 0x1000
    for destination, case in enumerate(cases, 8):
        data.extend((harness.DataWord(data_address, case.source2, 8),
                     harness.DataWord(data_address + 8, case.source3, 8)))
        bundles.append(harness.Bundle(address, 0x01, harness.nop_m(),
                                      harness.adds(1, data_address, 0), harness.nop_i()))
        address += 0x10
        bundles.append(harness.Bundle(address, 0x01,
                                      harness.ld8(destination, 1),
                                      harness.adds(1, 8, 1), harness.nop_i()))
        address += 0x10
        bundles.append(harness.Bundle(address, 0x01, harness.ld8(3, 1),
                                      harness.nop_i(), harness.nop_i()))
        address += 0x10
        if case.encode is None:
            raise AssertionError(case.opcode + " lacks an alias encoder")
        raw = case.encode(destination, destination, 3, 0)
        bundles.append(harness.Bundle(address, 0x03, harness.nop_m(), raw,
                                      harness.nop_i()))
        traces.append(address)
        expected[destination] = case.expected
        address += 0x10
        data_address += 0x10
    bundles.append(harness.spin_bundle(address))
    return BuiltMatrix(harness.Program(
        name="scalar destination/source aliases", bundles=tuple(bundles),
        terminal_ip=address, data=tuple(data)), expected, tuple(traces))


def _nat_matrix(harness: ModuleType, cases: Sequence[ScalarCase],
                name: str) -> Tuple[object, Dict[int, bool], Tuple[int, ...]]:
    bundles: List[object] = [
        harness.Bundle(0x10, 0x03, harness.nop_m(),
                       harness.adds(8, 3, 0), harness.nop_i()),
        harness.Bundle(0x20, 0x01, harness.mov_m_grar(36, 8),
                       harness.nop_i(), harness.nop_i()),
    ]
    address = 0x30
    traces: List[int] = []
    expected: Dict[int, bool] = {}
    for destination, case in enumerate(cases, 8):
        bundles.append(harness.Bundle(address, 0x01, harness.nop_m(),
                                      harness.adds(1, 0x1000, 0), harness.nop_i()))
        address += 0x10
        if case.opcode in NO_SOURCE_OPCODES:
            bundles.append(harness.Bundle(address, 0x01,
                                          harness.ld8_fill(destination, 1),
                                          harness.nop_i(), harness.nop_i()))
        else:
            bundles.append(harness.Bundle(address, 0x01,
                                          harness.ld8_fill(2, 1),
                                          harness.adds(1, 8, 1), harness.nop_i()))
            address += 0x10
            bundles.append(harness.Bundle(address, 0x01,
                                          harness.ld8_fill(3, 1),
                                          harness.nop_i(), harness.nop_i()))
        address += 0x10
        if case.unit == "L":
            bundles.append(movl_bundle(harness, address, destination,
                                       case.movl_value))
        else:
            if case.encode is None:
                raise AssertionError(case.opcode + " lacks a NaT encoder")
            bundles.append(harness.Bundle(
                address, 0x03, harness.nop_m(),
                case.encode(destination, 2, 3, 0), harness.nop_i()))
        traces.append(address)
        expected[destination] = case.opcode not in NO_SOURCE_OPCODES
        address += 0x10
    bundles.append(harness.spin_bundle(address))
    return (harness.Program(
        name=name, bundles=tuple(bundles), terminal_ip=address,
        data=(harness.DataWord(0x1000, 0x1122334455667788, 8),
              harness.DataWord(0x1008, 0x8877665544332211, 8))),
            expected, tuple(traces))


def _test_predication(harness: ModuleType, qemu: Path) -> None:
    poison = 0xBADF00D0BADF00D
    bundles: List[object] = [
        harness.Bundle(0x10, 0x03, harness.nop_m(),
                       harness.adds(8, 1, 0), harness.nop_i()),
        harness.Bundle(0x20, 0x01, harness.mov_m_grar(36, 8),
                       harness.nop_i(), harness.nop_i()),
        harness.Bundle(0x30, 0x03, harness.nop_m(),
                       harness.adds(1, 0x1000, 0), harness.nop_i()),
        harness.Bundle(0x40, 0x01, harness.ld8_fill(31, 1),
                       harness.nop_i(), harness.nop_i()),
        harness.Bundle(0x50, 0x03, harness.nop_m(),
                       harness.adds(1, 0x1010, 0), harness.nop_i()),
        harness.Bundle(0x60, 0x01, harness.ld8(2, 1),
                       harness.adds(1, 8, 1), harness.nop_i()),
        harness.Bundle(0x70, 0x01, harness.ld8(3, 1),
                       harness.nop_i(), harness.nop_i()),
    ]
    address = 0x80
    for case in make_cases(False):
        if case.unit == "L":
            bundles.append(movl_bundle(harness, address, 31,
                                       case.movl_value, qp=1))
        else:
            if case.encode is None:
                raise AssertionError(case.opcode + " lacks a predicate encoder")
            bundles.append(harness.Bundle(
                address, 0x03, harness.nop_m(),
                case.encode(31, 2, 3, 1), harness.nop_i()))
        address += 0x10
    bundles.append(harness.Bundle(
        address, 0x03, harness.nop_m(),
        raw_count(31, False, 3, qp=1, reserved_r2=1), harness.nop_i()))
    address += 0x10
    bundles.append(harness.spin_bundle(address))
    program = harness.Program(
        name="all scalar false qualifiers and reserved priority",
        bundles=tuple(bundles), terminal_ip=address,
        data=(harness.DataWord(0x1000, poison, 8),
              harness.DataWord(0x1010, 7, 8),
              harness.DataWord(0x1018, 11, 8)))
    snapshot = harness.run_program(qemu, program)
    if (snapshot.exception_pending or snapshot.gr[31] != poison or
            not (snapshot.nat_low & (1 << 31))):
        raise AssertionError("false scalar qualifiers changed value/NaT or faulted")


def _test_reserved_fault(harness: ModuleType, qemu: Path) -> None:
    vector = harness.IA64_GENERAL_EXCEPTION_VECTOR
    program = harness.Program(
        name="enabled POPCNT reserved r2 field",
        bundles=(
            harness.Bundle(0x10, 0x01, harness.ssm(harness.IA64_PSR_IC),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x20, 0x01, harness.srlz_i(),
                           harness.nop_i(), harness.nop_i()),
            movl_bundle(harness, 0x30, 31, 0x123),
            harness.Bundle(0x40, 0x03, harness.nop_m(),
                           raw_count(31, False, 3, reserved_r2=1),
                           harness.adds(30, 0x456, 0)),
            harness.Bundle(vector, 0x11, harness.nop_m(), harness.nop_i(),
                           harness.br_cond(vector, vector)),
        ), terminal_ip=vector)
    snapshot = harness.run_program(
        qemu, program, preserve_fault_slot=True,
        typed_direct_trace_ips=(0x40,))
    if (snapshot.ip != vector or snapshot.exception_kind != "illegal-operation" or
            snapshot.cr_iip != 0x40 or not snapshot.slot_valid or
            snapshot.slot_ip != 0x40 or snapshot.slot_ri != 1):
        raise AssertionError("reserved POPCNT lost precise Illegal Operation state")
    if snapshot.gr[31] != 0x123 or snapshot.gr[30] != 0:
        raise AssertionError("reserved POPCNT modified target or suffix")


def test_state_legality_matrix(harness: ModuleType, qemu: Path) -> str:
    checked = _check_matrix(harness, qemu, _alias_matrix(harness))
    a_cases = tuple(case for case in make_cases(False) if case.unit == "A")
    checked += _check_matrix(
        harness, qemu,
        build_matrix(harness, "scalar A-unit M-slot forms", a_cases, True))
    nat_checked = 0
    cases = make_cases(False)
    for chunk_no, start in enumerate(range(0, len(cases), 20), 1):
        program, expected, traces = _nat_matrix(
            harness, cases[start:start + 20],
            f"scalar NaT matrix {chunk_no}")
        snapshot = harness.run_program(qemu, program,
                                       typed_direct_trace_ips=traces)
        for reg, expected_nat in expected.items():
            actual_nat = bool(snapshot.nat_low & (1 << reg))
            if actual_nat != expected_nat:
                raise AssertionError(
                    f"scalar NaT r{reg} expected {int(expected_nat)}, "
                    f"got {int(actual_nat)}")
            nat_checked += 1
    _test_predication(harness, qemu)
    _test_reserved_fault(harness, qemu)
    return (f"{checked} alias/legal-slot results and {nat_checked} NaT rows "
            "pass; all 40 false qualifiers plus reserved-field priority and "
            "precise fault state pass")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    args = parser.parse_args()
    harness = load_module(args.harness, "_ia64_scalar_tcg_harness")
    tests = (
        ("80-row scalar semantic/model matrix", test_semantic_model_matrix),
        ("integer multiply-add forms", test_integer_multiply_add_forms),
        ("character and byte forms", test_character_byte_forms),
        ("scalar state and legality matrix", test_state_legality_matrix),
    )
    print("TAP version 13")
    print(f"1..{len(tests)}")
    failed = False
    for number, (name, function) in enumerate(tests, 1):
        try:
            detail = function(harness, args.qemu.resolve())
            print(f"ok {number} - {name}")
            print("# " + detail)
        except Exception as exc:
            failed = True
            print(f"not ok {number} - {name}")
            print("# " + str(exc).replace("\n", "\n# "))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
