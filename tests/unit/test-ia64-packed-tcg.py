#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent runtime goldens for IA-64 packed-integer direct TCG."""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import Callable, Dict, List, Sequence, Tuple


U64_MASK = (1 << 64) - 1
PACKED_OPCODES = (
    "IA64_OP_PADD1", "IA64_OP_PADD2", "IA64_OP_PADD4",
    "IA64_OP_PSUB1", "IA64_OP_PSUB2", "IA64_OP_PSUB4",
    "IA64_OP_PSHLADD2", "IA64_OP_PSHRADD2",
    "IA64_OP_PAVG1", "IA64_OP_PAVG2",
    "IA64_OP_PAVGSUB1", "IA64_OP_PAVGSUB2",
    "IA64_OP_PCMP1_EQ", "IA64_OP_PCMP1_GT",
    "IA64_OP_PCMP2_EQ", "IA64_OP_PCMP2_GT",
    "IA64_OP_PCMP4_EQ", "IA64_OP_PCMP4_GT",
    "IA64_OP_PMAX1_U", "IA64_OP_PMAX2",
    "IA64_OP_PMIN1_U", "IA64_OP_PMIN2",
    "IA64_OP_PMPY2_L", "IA64_OP_PMPY2_R",
    "IA64_OP_PMPYSH2", "IA64_OP_PMPYSH2_U",
    "IA64_OP_PSHL2", "IA64_OP_PSHL4",
    "IA64_OP_PSHR2", "IA64_OP_PSHR2_U",
    "IA64_OP_PSHR4", "IA64_OP_PSHR4_U",
    "IA64_OP_PSAD1", "IA64_OP_MUX1", "IA64_OP_MUX2",
    "IA64_OP_MIX1_L", "IA64_OP_MIX1_R",
    "IA64_OP_MIX2_L", "IA64_OP_MIX2_R",
    "IA64_OP_MIX4_L", "IA64_OP_MIX4_R",
    "IA64_OP_PACK2_SSS", "IA64_OP_PACK2_USS", "IA64_OP_PACK4_SSS",
    "IA64_OP_UNPACK1_H", "IA64_OP_UNPACK1_L",
    "IA64_OP_UNPACK2_H", "IA64_OP_UNPACK2_L",
    "IA64_OP_UNPACK4_H", "IA64_OP_UNPACK4_L",
    "IA64_OP_CZX1_L", "IA64_OP_CZX1_R",
    "IA64_OP_CZX2_L", "IA64_OP_CZX2_R",
)


def bitfield(value: int, low: int, width: int) -> int:
    return (value & ((1 << width) - 1)) << low


def op(major: int) -> int:
    return bitfield(major, 37, 4)


def _size_fields(bits: int) -> Tuple[int, int]:
    return {8: (0, 0), 16: (0, 1), 32: (1, 0)}[bits]


def raw_a9(r1: int, bits: int, x4: int, x2b: int,
           r2: int = 2, r3: int = 3, qp: int = 0) -> int:
    za, zb = _size_fields(bits)
    return (
        op(8) | bitfield(za, 36, 1) | bitfield(1, 34, 2)
        | bitfield(zb, 33, 1) | bitfield(x4, 29, 4)
        | bitfield(x2b, 27, 2) | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7) | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def raw_i2(r1: int, za: int, zb: int, x2b: int, x2c: int,
           r2: int = 2, r3: int = 3, qp: int = 0) -> int:
    return (
        op(7) | bitfield(za, 36, 1) | bitfield(2, 34, 2)
        | bitfield(zb, 33, 1) | bitfield(x2c, 30, 2)
        | bitfield(x2b, 28, 2) | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7) | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def raw_pmpyshr(r1: int, signed: bool, shift: int,
                r2: int = 2, r3: int = 3, qp: int = 0) -> int:
    x2c = {0: 0, 7: 1, 15: 2, 16: 3}[shift]
    return (
        op(7) | bitfield(1, 33, 1) | bitfield(x2c, 30, 2)
        | bitfield(3 if signed else 1, 28, 2)
        | bitfield(r3, 20, 7) | bitfield(r2, 13, 7)
        | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)
    )


def raw_pshl_variable(r1: int, bits: int, r2: int = 2, r3: int = 3,
                      qp: int = 0) -> int:
    za, zb = _size_fields(bits)
    return (
        op(7) | bitfield(za, 36, 1) | bitfield(zb, 33, 1)
        | bitfield(0x08, 27, 6) | bitfield(r3, 20, 7)
        | bitfield(r2, 13, 7) | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def raw_pshl_fixed(r1: int, bits: int, count: int, r2: int = 2,
                   qp: int = 0) -> int:
    za, zb = _size_fields(bits)
    return (
        op(7) | bitfield(za, 36, 1) | bitfield(3, 34, 2)
        | bitfield(zb, 33, 1) | bitfield(1, 30, 2)
        | bitfield(1, 28, 2) | bitfield(31 - count, 20, 5)
        | bitfield(r2, 13, 7) | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def raw_pshr(r1: int, bits: int, unsigned: bool, count: int | None,
             r2: int = 2, r3: int = 3, qp: int = 0) -> int:
    signatures = {
        (16, False, False): 0x0E220000000,
        (16, True, False): 0x0E200000000,
        (16, False, True): 0x0E630000000,
        (16, True, True): 0x0E610000000,
        (32, False, False): 0x0F020000000,
        (32, True, False): 0x0F000000000,
        (32, False, True): 0x0F430000000,
        (32, True, True): 0x0F410000000,
    }
    fixed = count is not None
    raw = signatures[(bits, unsigned, fixed)]
    raw |= bitfield(r3, 20, 7) | bitfield(r1, 6, 7) | bitfield(qp, 0, 6)
    if fixed:
        raw |= bitfield(count, 14, 5)
    else:
        raw |= bitfield(r2, 13, 7)
    return raw


def raw_mux(r1: int, bits: int, immediate: int, r2: int = 2,
            qp: int = 0) -> int:
    return (
        op(7) | bitfield(3, 34, 2) | bitfield(bits == 16, 33, 1)
        | bitfield(2, 30, 2) | bitfield(2, 28, 2)
        | bitfield(immediate, 20, 8 if bits == 16 else 4)
        | bitfield(r2, 13, 7) | bitfield(r1, 6, 7)
        | bitfield(qp, 0, 6)
    )


def raw_czx(r1: int, bits: int, left: bool, r3: int = 3,
            qp: int = 0) -> int:
    x6 = {(8, True): 0x18, (8, False): 0x1C,
          (16, True): 0x19, (16, False): 0x1D}[(bits, left)]
    return (bitfield(x6, 27, 6) | bitfield(r3, 20, 7)
            | bitfield(r1, 6, 7) | bitfield(qp, 0, 6))


def lanes(value: int, bits: int) -> List[int]:
    mask = (1 << bits) - 1
    return [(value >> offset) & mask for offset in range(0, 64, bits)]


def join_lanes(values: Sequence[int], bits: int) -> int:
    mask = (1 << bits) - 1
    return sum((value & mask) << (index * bits)
               for index, value in enumerate(values)) & U64_MASK


def signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def saturate(value: int, bits: int, signed_result: bool) -> int:
    if signed_result:
        minimum = -(1 << (bits - 1))
        maximum = (1 << (bits - 1)) - 1
    else:
        minimum = 0
        maximum = (1 << bits) - 1
    return min(max(value, minimum), maximum) & ((1 << bits) - 1)


def golden_addsub(a: int, b: int, bits: int, modifier: int,
                  subtract: bool) -> int:
    result = []
    for left, right in zip(lanes(a, bits), lanes(b, bits)):
        if modifier == 1:
            x, y, signed_result = signed(left, bits), signed(right, bits), True
        elif modifier == 3:
            x, y, signed_result = left, signed(right, bits), False
        else:
            x, y, signed_result = left, right, False
        value = x - y if subtract else x + y
        result.append(value if modifier == 0 else
                      saturate(value, bits, signed_result))
    return join_lanes(result, bits)


def golden_average(a: int, b: int, bits: int, raz: bool) -> int:
    result = []
    for left, right in zip(lanes(a, bits), lanes(b, bits)):
        total = left + right
        result.append((total + 1) >> 1 if raz else
                      (total >> 1) | (total & 1))
    return join_lanes(result, bits)


def golden_average_sub(a: int, b: int, bits: int) -> int:
    extended_mask = (1 << (bits + 1)) - 1
    values = []
    for left, right in zip(lanes(a, bits), lanes(b, bits)):
        difference = (left - right) & extended_mask
        values.append((difference >> 1) | (difference & 1))
    return join_lanes(values, bits)


def golden_compare(a: int, b: int, bits: int, greater: bool) -> int:
    mask = (1 << bits) - 1
    values = []
    for left, right in zip(lanes(a, bits), lanes(b, bits)):
        match = (signed(left, bits) > signed(right, bits)
                 if greater else left == right)
        values.append(mask if match else 0)
    return join_lanes(values, bits)


def golden_shift_add(a: int, b: int, count: int, left_shift: bool) -> int:
    values = []
    for raw_left, raw_right in zip(lanes(a, 16), lanes(b, 16)):
        x, y = signed(raw_left, 16), signed(raw_right, 16)
        if left_shift:
            shifted = x << count
            if shifted > 0x7FFF:
                value = 0x7FFF
            elif shifted < -0x8000:
                value = -0x8000
            else:
                value = min(max(shifted + y, -0x8000), 0x7FFF)
        else:
            value = min(max((x >> count) + y, -0x8000), 0x7FFF)
        values.append(value)
    return join_lanes(values, 16)


def golden_minmax(a: int, b: int, bits: int, maximum: bool,
                  signed_values: bool) -> int:
    values = []
    for left, right in zip(lanes(a, bits), lanes(b, bits)):
        x = signed(left, bits) if signed_values else left
        y = signed(right, bits) if signed_values else right
        take_left = x > y if maximum else x < y
        values.append(left if take_left else right)
    return join_lanes(values, bits)


def golden_multiply_pair(a: int, b: int, left_form: bool) -> int:
    first = 1 if left_form else 0
    products = []
    a_lanes, b_lanes = lanes(a, 16), lanes(b, 16)
    for lane in (first, first + 2):
        products.append(signed(a_lanes[lane], 16)
                        * signed(b_lanes[lane], 16))
    return join_lanes(products, 32)


def golden_multiply_shift(a: int, b: int, shift: int,
                          signed_form: bool) -> int:
    values = []
    for left, right in zip(lanes(a, 16), lanes(b, 16)):
        if signed_form:
            product = signed(left, 16) * signed(right, 16)
        else:
            product = left * right
        values.append(product >> shift)
    return join_lanes(values, 16)


def golden_shift(value: int, count: int, bits: int, right: bool,
                 signed_form: bool = False) -> int:
    amount = min(count & U64_MASK, bits)
    values = []
    for element in lanes(value, bits):
        if right:
            operand = signed(element, bits) if signed_form else element
            values.append(operand >> amount)
        else:
            values.append(element << amount)
    return join_lanes(values, bits)


def golden_psad(a: int, b: int) -> int:
    return sum(abs(left - right)
               for left, right in zip(lanes(a, 8), lanes(b, 8)))


MUX1 = {
    0x0: (0, 0, 0, 0, 0, 0, 0, 0),
    0x8: (0, 4, 2, 6, 1, 5, 3, 7),
    0x9: (0, 4, 1, 5, 2, 6, 3, 7),
    0xA: (0, 2, 4, 6, 1, 3, 5, 7),
    0xB: (7, 6, 5, 4, 3, 2, 1, 0),
}


def golden_mux(value: int, bits: int, immediate: int) -> int:
    indexes = (MUX1[immediate] if bits == 8 else
               tuple((immediate >> (2 * lane)) & 3 for lane in range(4)))
    source = lanes(value, bits)
    return join_lanes([source[index] for index in indexes], bits)


def golden_mix(a: int, b: int, bits: int, left_form: bool) -> int:
    source_a, source_b = lanes(a, bits), lanes(b, bits)
    result = []
    for pair in range(len(source_a) // 2):
        lane = pair * 2 + (1 if left_form else 0)
        result.extend((source_b[lane], source_a[lane]))
    return join_lanes(result, bits)


def golden_pack(a: int, b: int, input_bits: int,
                unsigned_result: bool) -> int:
    output_bits = input_bits // 2
    values = []
    for source in (a, b):
        for element in lanes(source, input_bits):
            values.append(saturate(signed(element, input_bits), output_bits,
                                   not unsigned_result))
    return join_lanes(values, output_bits)


def golden_unpack(a: int, b: int, bits: int, high: bool) -> int:
    source_a, source_b = lanes(a, bits), lanes(b, bits)
    half = len(source_a) // 2
    base = half if high else 0
    result = []
    for lane in range(base, base + half):
        result.extend((source_b[lane], source_a[lane]))
    return join_lanes(result, bits)


def golden_czx(value: int, bits: int, left: bool) -> int:
    source = lanes(value, bits)
    order = range(len(source) - 1, -1, -1) if left else range(len(source))
    for index, lane in enumerate(order):
        if source[lane] == 0:
            return index
    return len(source)


Encoder = Callable[[int, int], int]


@dataclasses.dataclass(frozen=True)
class PackedCase:
    opcode: str
    encode: Encoder
    source2: int
    source3: int
    expected: int


def a9_encoder(bits: int, x4: int, x2b: int) -> Encoder:
    return lambda r1, qp=0: raw_a9(r1, bits, x4, x2b, qp=qp)


def i2_encoder(za: int, zb: int, x2b: int, x2c: int) -> Encoder:
    return lambda r1, qp=0: raw_i2(r1, za, zb, x2b, x2c, qp=qp)


def make_cases() -> Tuple[PackedCase, ...]:
    arithmetic_a = 0x7FFF8000FF807F01
    arithmetic_b = 0x00018001FF7F01FF
    minmax_a = 0x80017F00FF105522
    minmax_b = 0x7F0180FFFF001133
    multiply_a = 0xFFFB0004FFFD0002
    multiply_b = 0xFFF7FFF800070006
    layout_a = 0x0706050403020100
    layout_b = 0xF7F6F5F4F3F2F1F0
    pack_a = 0x00FF007F0000FFFF
    pack_b = 0x01900080FF7FFF38
    pack4_a = 0x00007FFFFFFF63C0
    pack4_b = 0xFFFF7FFF00009C40
    zero_scan = 0x1122003344550066
    shift_value = 0x80017FFF0001FFFE

    cases = (
        PackedCase("IA64_OP_PADD1", a9_encoder(8, 0, 0), arithmetic_a,
                   arithmetic_b, golden_addsub(arithmetic_a, arithmetic_b,
                                                8, 0, False)),
        PackedCase("IA64_OP_PADD2", a9_encoder(16, 0, 1), arithmetic_a,
                   arithmetic_b, golden_addsub(arithmetic_a, arithmetic_b,
                                                16, 1, False)),
        PackedCase("IA64_OP_PADD4", a9_encoder(32, 0, 0), arithmetic_a,
                   arithmetic_b, golden_addsub(arithmetic_a, arithmetic_b,
                                                32, 0, False)),
        PackedCase("IA64_OP_PSUB1", a9_encoder(8, 1, 2), arithmetic_a,
                   arithmetic_b, golden_addsub(arithmetic_a, arithmetic_b,
                                                8, 2, True)),
        PackedCase("IA64_OP_PSUB2", a9_encoder(16, 1, 3), arithmetic_a,
                   arithmetic_b, golden_addsub(arithmetic_a, arithmetic_b,
                                                16, 3, True)),
        PackedCase("IA64_OP_PSUB4", a9_encoder(32, 1, 0), arithmetic_a,
                   arithmetic_b, golden_addsub(arithmetic_a, arithmetic_b,
                                                32, 0, True)),
        PackedCase("IA64_OP_PSHLADD2", a9_encoder(16, 4, 2), arithmetic_a,
                   arithmetic_b, golden_shift_add(arithmetic_a, arithmetic_b,
                                                  3, True)),
        PackedCase("IA64_OP_PSHRADD2", a9_encoder(16, 6, 1), arithmetic_a,
                   arithmetic_b, golden_shift_add(arithmetic_a, arithmetic_b,
                                                  2, False)),
        PackedCase("IA64_OP_PAVG1", a9_encoder(8, 2, 2), arithmetic_a,
                   arithmetic_b, golden_average(arithmetic_a, arithmetic_b,
                                                8, False)),
        PackedCase("IA64_OP_PAVG2", a9_encoder(16, 2, 3), arithmetic_a,
                   arithmetic_b, golden_average(arithmetic_a, arithmetic_b,
                                                16, True)),
        PackedCase("IA64_OP_PAVGSUB1", a9_encoder(8, 3, 2), arithmetic_a,
                   arithmetic_b, golden_average_sub(arithmetic_a,
                                                    arithmetic_b, 8)),
        PackedCase("IA64_OP_PAVGSUB2", a9_encoder(16, 3, 2), arithmetic_a,
                   arithmetic_b, golden_average_sub(arithmetic_a,
                                                    arithmetic_b, 16)),
        PackedCase("IA64_OP_PCMP1_EQ", a9_encoder(8, 9, 0), arithmetic_a,
                   arithmetic_b, golden_compare(arithmetic_a, arithmetic_b,
                                                8, False)),
        PackedCase("IA64_OP_PCMP1_GT", a9_encoder(8, 9, 1), arithmetic_a,
                   arithmetic_b, golden_compare(arithmetic_a, arithmetic_b,
                                                8, True)),
        PackedCase("IA64_OP_PCMP2_EQ", a9_encoder(16, 9, 0), arithmetic_a,
                   arithmetic_b, golden_compare(arithmetic_a, arithmetic_b,
                                                16, False)),
        PackedCase("IA64_OP_PCMP2_GT", a9_encoder(16, 9, 1), arithmetic_a,
                   arithmetic_b, golden_compare(arithmetic_a, arithmetic_b,
                                                16, True)),
        PackedCase("IA64_OP_PCMP4_EQ", a9_encoder(32, 9, 0), arithmetic_a,
                   arithmetic_b, golden_compare(arithmetic_a, arithmetic_b,
                                                32, False)),
        PackedCase("IA64_OP_PCMP4_GT", a9_encoder(32, 9, 1), arithmetic_a,
                   arithmetic_b, golden_compare(arithmetic_a, arithmetic_b,
                                                32, True)),
        PackedCase("IA64_OP_PMAX1_U", i2_encoder(0, 0, 1, 1), minmax_a,
                   minmax_b, golden_minmax(minmax_a, minmax_b, 8, True,
                                           False)),
        PackedCase("IA64_OP_PMAX2", i2_encoder(0, 1, 3, 1), minmax_a,
                   minmax_b, golden_minmax(minmax_a, minmax_b, 16, True,
                                           True)),
        PackedCase("IA64_OP_PMIN1_U", i2_encoder(0, 0, 1, 0), minmax_a,
                   minmax_b, golden_minmax(minmax_a, minmax_b, 8, False,
                                           False)),
        PackedCase("IA64_OP_PMIN2", i2_encoder(0, 1, 3, 0), minmax_a,
                   minmax_b, golden_minmax(minmax_a, minmax_b, 16, False,
                                           True)),
        PackedCase("IA64_OP_PMPY2_L", i2_encoder(0, 1, 3, 3), multiply_a,
                   multiply_b, golden_multiply_pair(multiply_a, multiply_b,
                                                    True)),
        PackedCase("IA64_OP_PMPY2_R", i2_encoder(0, 1, 1, 3), multiply_a,
                   multiply_b, golden_multiply_pair(multiply_a, multiply_b,
                                                    False)),
        PackedCase("IA64_OP_PMPYSH2",
                   lambda r1, qp=0: raw_pmpyshr(r1, True, 7, qp=qp),
                   multiply_a, multiply_b,
                   golden_multiply_shift(multiply_a, multiply_b, 7, True)),
        PackedCase("IA64_OP_PMPYSH2_U",
                   lambda r1, qp=0: raw_pmpyshr(r1, False, 15, qp=qp),
                   multiply_a, multiply_b,
                   golden_multiply_shift(multiply_a, multiply_b, 15, False)),
        PackedCase("IA64_OP_PSHL2",
                   lambda r1, qp=0: raw_pshl_variable(r1, 16, qp=qp),
                   shift_value, 20,
                   golden_shift(shift_value, 20, 16, False)),
        PackedCase("IA64_OP_PSHL4",
                   lambda r1, qp=0: raw_pshl_fixed(r1, 32, 5, qp=qp),
                   shift_value, 0,
                   golden_shift(shift_value, 5, 32, False)),
        PackedCase("IA64_OP_PSHR2",
                   lambda r1, qp=0: raw_pshr(r1, 16, False, None, qp=qp),
                   20, shift_value,
                   golden_shift(shift_value, 20, 16, True, True)),
        PackedCase("IA64_OP_PSHR2_U",
                   lambda r1, qp=0: raw_pshr(r1, 16, True, 17, qp=qp),
                   0, shift_value,
                   golden_shift(shift_value, 17, 16, True, False)),
        PackedCase("IA64_OP_PSHR4",
                   lambda r1, qp=0: raw_pshr(r1, 32, False, None, qp=qp),
                   40, shift_value,
                   golden_shift(shift_value, 40, 32, True, True)),
        PackedCase("IA64_OP_PSHR4_U",
                   lambda r1, qp=0: raw_pshr(r1, 32, True, 7, qp=qp),
                   0, shift_value,
                   golden_shift(shift_value, 7, 32, True, False)),
        PackedCase("IA64_OP_PSAD1", i2_encoder(0, 0, 3, 2), layout_a,
                   layout_b, golden_psad(layout_a, layout_b)),
        PackedCase("IA64_OP_MUX1",
                   lambda r1, qp=0: raw_mux(r1, 8, 0xB, qp=qp),
                   layout_a, 0, golden_mux(layout_a, 8, 0xB)),
        PackedCase("IA64_OP_MUX2",
                   lambda r1, qp=0: raw_mux(r1, 16, 0x1B, qp=qp),
                   layout_a, 0, golden_mux(layout_a, 16, 0x1B)),
        PackedCase("IA64_OP_MIX1_L", i2_encoder(0, 0, 2, 2), layout_a,
                   layout_b, golden_mix(layout_a, layout_b, 8, True)),
        PackedCase("IA64_OP_MIX1_R", i2_encoder(0, 0, 0, 2), layout_a,
                   layout_b, golden_mix(layout_a, layout_b, 8, False)),
        PackedCase("IA64_OP_MIX2_L", i2_encoder(0, 1, 2, 2), layout_a,
                   layout_b, golden_mix(layout_a, layout_b, 16, True)),
        PackedCase("IA64_OP_MIX2_R", i2_encoder(0, 1, 0, 2), layout_a,
                   layout_b, golden_mix(layout_a, layout_b, 16, False)),
        PackedCase("IA64_OP_MIX4_L", i2_encoder(1, 0, 2, 2), layout_a,
                   layout_b, golden_mix(layout_a, layout_b, 32, True)),
        PackedCase("IA64_OP_MIX4_R", i2_encoder(1, 0, 0, 2), layout_a,
                   layout_b, golden_mix(layout_a, layout_b, 32, False)),
        PackedCase("IA64_OP_PACK2_SSS", i2_encoder(0, 1, 2, 0), pack_a,
                   pack_b, golden_pack(pack_a, pack_b, 16, False)),
        PackedCase("IA64_OP_PACK2_USS", i2_encoder(0, 1, 0, 0), pack_a,
                   pack_b, golden_pack(pack_a, pack_b, 16, True)),
        PackedCase("IA64_OP_PACK4_SSS", i2_encoder(1, 0, 2, 0), pack4_a,
                   pack4_b, golden_pack(pack4_a, pack4_b, 32, False)),
        PackedCase("IA64_OP_UNPACK1_H", i2_encoder(0, 0, 0, 1), layout_a,
                   layout_b, golden_unpack(layout_a, layout_b, 8, True)),
        PackedCase("IA64_OP_UNPACK1_L", i2_encoder(0, 0, 2, 1), layout_a,
                   layout_b, golden_unpack(layout_a, layout_b, 8, False)),
        PackedCase("IA64_OP_UNPACK2_H", i2_encoder(0, 1, 0, 1), layout_a,
                   layout_b, golden_unpack(layout_a, layout_b, 16, True)),
        PackedCase("IA64_OP_UNPACK2_L", i2_encoder(0, 1, 2, 1), layout_a,
                   layout_b, golden_unpack(layout_a, layout_b, 16, False)),
        PackedCase("IA64_OP_UNPACK4_H", i2_encoder(1, 0, 0, 1), layout_a,
                   layout_b, golden_unpack(layout_a, layout_b, 32, True)),
        PackedCase("IA64_OP_UNPACK4_L", i2_encoder(1, 0, 2, 1), layout_a,
                   layout_b, golden_unpack(layout_a, layout_b, 32, False)),
        PackedCase("IA64_OP_CZX1_L",
                   lambda r1, qp=0: raw_czx(r1, 8, True, qp=qp),
                   0, zero_scan, golden_czx(zero_scan, 8, True)),
        PackedCase("IA64_OP_CZX1_R",
                   lambda r1, qp=0: raw_czx(r1, 8, False, qp=qp),
                   0, zero_scan, golden_czx(zero_scan, 8, False)),
        PackedCase("IA64_OP_CZX2_L",
                   lambda r1, qp=0: raw_czx(r1, 16, True, qp=qp),
                   0, zero_scan, golden_czx(zero_scan, 16, True)),
        PackedCase("IA64_OP_CZX2_R",
                   lambda r1, qp=0: raw_czx(r1, 16, False, qp=qp),
                   0, zero_scan, golden_czx(zero_scan, 16, False)),
    )
    if tuple(case.opcode for case in cases) != PACKED_OPCODES:
        raise AssertionError("runtime packed opcode inventory drifted")
    return cases


def load_harness(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("ia64_full_tcg_harness", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import IA-64 harness from {}".format(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def movl_bundle(harness: ModuleType, address: int, reg: int,
                value: int):
    value &= U64_MASK
    l_slot = (value >> 22) & ((1 << 41) - 1)
    x_slot = (
        bitfield(reg, 6, 7) | bitfield(value & 0x7F, 13, 7)
        | bitfield((value >> 21) & 1, 21, 1)
        | bitfield((value >> 16) & 0x1F, 22, 5)
        | bitfield((value >> 7) & 0x1FF, 27, 9)
        | bitfield((value >> 63) & 1, 36, 1) | op(6)
    )
    # MLX template 0x05 closes the group after the long instruction.
    return harness.Bundle(address, 0x05, harness.nop_m(), l_slot, x_slot)


@dataclasses.dataclass(frozen=True)
class BuiltMatrix:
    program: object
    expected: Dict[int, int]
    direct_trace_ips: Tuple[int, ...]
    alias_expected: int | None
    poison_expected: int | None


def build_matrix(harness: ModuleType, name: str,
                 cases: Sequence[PackedCase], extras: bool) -> BuiltMatrix:
    bundles = []
    address = 0x10
    data_address = 0x1000
    data_words = []
    current_sources = None
    expected: Dict[int, int] = {}
    direct_trace_ips: List[int] = []

    def append_constant_loads(values: Sequence[Tuple[int, int]]) -> None:
        """Load constants through already-typed ordinary memory operations.

        MOVL is deliberately not used as test scaffolding here so the packed
        gate does not depend on an unrelated long-instruction admission
        detail.  Loader-backed LD8 setup keeps the semantic matrix focused on
        the packed instructions under test.
        """
        nonlocal address, data_address

        base = data_address
        for index, (_, value) in enumerate(values):
            data_words.append(harness.DataWord(
                base + index * 8, value & U64_MASK, 8
            ))
        bundles.append(harness.Bundle(
            address, 0x01, harness.nop_m(),
            harness.adds(1, base, 0), harness.nop_i()
        ))
        address += 0x10
        for index, (reg, _) in enumerate(values):
            advance = (
                harness.adds(1, 8, 1)
                if index + 1 < len(values) else harness.nop_i()
            )
            bundles.append(harness.Bundle(
                address, 0x01, harness.ld8(reg, 1),
                advance, harness.nop_i()
            ))
            address += 0x10
        data_address += len(values) * 8

    for destination, case in enumerate(cases, start=4):
        sources = (case.source2 & U64_MASK, case.source3 & U64_MASK)
        if sources != current_sources:
            append_constant_loads(((2, sources[0]), (3, sources[1])))
            current_sources = sources
        bundles.append(harness.Bundle(
            address, 0x03, harness.nop_m(), case.encode(destination, 0),
            harness.nop_i()
        ))
        direct_trace_ips.append(address)
        expected[destination] = case.expected & U64_MASK
        address += 0x10

    alias_expected = None
    poison_expected = None
    if extras:
        alias_source2 = 0x0706050403020100
        alias_source3 = 0x0101010101010101
        append_constant_loads((
            (2, alias_source2), (3, alias_source3),
            (31, 0xBADF00D0BADF00D),
        ))

        # p1 is initially false: no value or NaT write may retire.
        bundles.append(harness.Bundle(
            address, 0x03, harness.nop_m(),
            raw_a9(31, 8, 0, 0, qp=1), harness.nop_i()
        ))
        direct_trace_ips.append(address)
        poison_expected = 0xBADF00D0BADF00D
        address += 0x10

        # Both packed operations are in one issue group.  The second must read
        # the immutable group-entry r2, not the first operation's live result.
        bundles.append(harness.Bundle(
            address, 0x01, harness.nop_m(), raw_a9(2, 8, 0, 0),
            raw_a9(1, 8, 0, 0, r2=2, r3=0)
        ))
        direct_trace_ips.append(address)
        alias_expected = alias_source2
        address += 0x10

    bundles.append(harness.spin_bundle(address))
    return BuiltMatrix(
        program=harness.Program(name=name, bundles=tuple(bundles),
                                terminal_ip=address,
                                data=tuple(data_words)),
        expected=expected,
        direct_trace_ips=tuple(direct_trace_ips),
        alias_expected=alias_expected,
        poison_expected=poison_expected,
    )


def test_semantic_matrix(harness: ModuleType, qemu: Path) -> str:
    cases = make_cases()
    matrices = (
        build_matrix(harness, "packed direct TCG matrix A", cases[:27], True),
        build_matrix(harness, "packed direct TCG matrix B", cases[27:], False),
    )
    checked = 0
    for matrix in matrices:
        rewritten = harness.run_program(
            qemu, matrix.program,
            typed_direct_trace_ips=matrix.direct_trace_ips,
        )
        for reg, expected in matrix.expected.items():
            if rewritten.gr[reg] != expected:
                raise AssertionError(
                    "packed r{} expected 0x{:016x}, got 0x{:016x}".format(
                        reg, expected, rewritten.gr[reg]
                    )
                )
            checked += 1
        if matrix.alias_expected is not None:
            if rewritten.gr[1] != matrix.alias_expected:
                raise AssertionError("same-group packed alias read live r2")
            expected_r2 = golden_addsub(
                0x0706050403020100, 0x0101010101010101, 8, 0, False
            )
            if rewritten.gr[2] != expected_r2:
                raise AssertionError("packed r1==r2 alias wrote wrong value")
        if (matrix.poison_expected is not None and
                rewritten.gr[31] != matrix.poison_expected):
            raise AssertionError("false packed qualifier modified r31")
    if checked != 54:
        raise AssertionError("packed runtime matrix did not check 54 rows")

    return ("54 independent lane goldens match typed direct TCG; false-qp "
            "and same-group destination/source alias coverage also pass")


def test_nat_propagation(harness: ModuleType, qemu: Path) -> str:
    data = 0x0706050403020100
    program = harness.Program(
        name="packed NaT propagation",
        bundles=(
            harness.Bundle(0x10, 0x03, harness.nop_m(),
                           harness.adds(8, 1, 0),
                           harness.adds(9, 0x1000, 0)),
            harness.Bundle(0x20, 0x03, harness.mov_m_grar(36, 8),
                           harness.adds(3, 1, 0), harness.nop_i()),
            harness.Bundle(0x30, 0x01, harness.ld8_fill(2, 9),
                           harness.nop_i(), harness.nop_i()),
            harness.Bundle(0x40, 0x03, harness.nop_m(),
                           raw_i2(10, 0, 0, 3, 2), harness.nop_i()),
            harness.spin_bundle(0x50),
        ),
        terminal_ip=0x50,
        data=(harness.DataWord(0x1000, data, 8),),
    )
    snapshot = harness.run_program(
        qemu, program, typed_direct_trace_ips=(0x40,)
    )
    expected = golden_psad(data, 1)
    if snapshot.gr[10] != expected:
        raise AssertionError("NaT-carrying PSAD produced the wrong value")
    if not (snapshot.nat_low & (1 << 10)):
        raise AssertionError("packed source NaT did not propagate to r10")
    return "PSAD propagates a real ld8.fill NaT through the staged GR/NaT pair"


def test_generated_density(harness: ModuleType, qemu: Path) -> str:
    cases = make_cases()
    matrices = (
        build_matrix(harness, "packed density matrix A", cases[:27], True),
        build_matrix(harness, "packed density matrix B", cases[27:], False),
    )
    lines: List[str] = []
    for label, matrix in zip(("packed_integer_A", "packed_integer_B"),
                             matrices):
        trace_pc = matrix.direct_trace_ips[0]
        snapshot, row, operations = harness._density_profile_program(
            qemu, matrix.program, trace_pc, trace_pc,
            one_bundle_per_tb=True,
        )
        if snapshot.ip != matrix.program.terminal_ip or \
                snapshot.exception_pending:
            raise AssertionError(label + " density run failed architecturally")
        for reg, expected in matrix.expected.items():
            if snapshot.gr[reg] != expected:
                raise AssertionError(
                    "{} density rerun r{} expected 0x{:016x}, got "
                    "0x{:016x}".format(
                        label, reg, expected, snapshot.gr[reg]
                    )
                )
        if int(row["integer"]) < 1:
            raise AssertionError(label + " row lacks a packed integer slot")
        lines.append(harness._density_line(label, row, operations))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    args = parser.parse_args()
    harness = load_harness(args.harness)

    tests = [
        ("54-row packed semantic matrix", test_semantic_matrix),
        ("packed NaT propagation", test_nat_propagation),
        ("packed family generated-code density", test_generated_density),
    ]
    print("TAP version 13")
    print("1..{}".format(len(tests)))
    failed = False
    for number, (name, function) in enumerate(tests, 1):
        try:
            detail = function(harness, args.qemu.resolve())
            print("ok {} - {}".format(number, name))
            for line in detail.splitlines():
                print("# " + line)
        except Exception as exc:
            failed = True
            print("not ok {} - {}".format(number, name))
            print("# " + str(exc).replace("\n", "\n# "))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
