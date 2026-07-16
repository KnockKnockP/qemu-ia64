#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""No-OS runtime gate for the remaining 63 IA-64 data-plane rows.

The two admission programs execute every primary encoding and every live
normalizing alias under a false predicate, which exercises decode, typed
admission, predicate placement, and direct-TCG trace rejection without
creating incidental memory faults.  Active literal-golden programs then cover
atomics, speculative spill/fill and 16-byte AR.CSD traffic, floating memory,
ALAT check loads, cache controls, and line-prefetch base updates.

Run without ``--qemu`` (or with ``--self-check``) to validate the independent
program inventory while the shared translator is being rewritten.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
from pathlib import Path
import sys
from typing import Callable, Dict, List, Optional, Sequence, Tuple


def _load_harness():
    path = Path(__file__).with_name("test-ia64-full-tcg.py")
    spec = importlib.util.spec_from_file_location(
        "_ia64_full_tcg_data_plane_harness", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load IA-64 full-TCG runtime harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


H = _load_harness()
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ia64_data_plane_tcg_spec import (  # noqa: E402
    ALIAS_ENCODINGS,
    DATA_PLANE_OPCODES,
    SPEC_BY_OPCODE,
    atomic,
    cache_control,
    chk_a,
    chk_s,
    floating_load,
    floating_store,
    integer_load,
    integer_spill,
    ld16,
    lfetch,
    primary_encoding,
    st16,
)


IA64_PSR_ED = 1 << 43
IA64_PSR_DFL = 1 << 18
IA64_ISR_NA = 1 << 35
IA64_ISR_CODE_DATA_NAT_PAGE_CONSUMPTION = 0x20
IA64_DISABLED_FP_VECTOR = 0x5500
IA64_DATA_ACCESS_RIGHTS_VECTOR = 0x5300
IA64_DATA_NAT_PAGE_VECTOR = 0x5600
IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR = 0x5B00
IA64_ILLEGAL_OPERATION_VECTOR = 0x5400


def _movl_bundle(address: int, reg: int, value: int) -> object:
    """Encode X2 ``movl r1=imm64`` without borrowing a system-test oracle."""
    value &= (1 << 64) - 1
    l_slot = (value >> 22) & H.SLOT_MASK
    x_slot = (
        H.bitfield(reg, 6, 7)
        | H.bitfield(value & 0x7f, 13, 7)
        | H.bitfield((value >> 21) & 1, 21, 1)
        | H.bitfield((value >> 16) & 0x1f, 22, 5)
        | H.bitfield((value >> 7) & 0x1ff, 27, 9)
        | H.bitfield((value >> 63) & 1, 36, 1)
        | H.bitfield(6, 37, 4)
    )
    return H.Bundle(address, 0x05, H.nop_m(), l_slot, x_slot)


def _checked_field(source: int, target: int) -> int:
    displacement = target - (source & ~0xf)
    if displacement & 0xf:
        raise ValueError("checked-branch target must be bundle aligned")
    scaled = displacement // 16
    if not -(1 << 20) <= scaled < (1 << 20):
        raise ValueError("checked-branch displacement exceeds signed imm21")
    return scaled & ((1 << 21) - 1)


def _chk_s_branch(source: int, target: int, *, reg: int,
                  fp: bool = False, qp: int = 0) -> int:
    field = _checked_field(source, target)
    return (
        chk_s(reg=reg, fp=fp, qp=qp)
        | H.bitfield(field & 0x7f, 6, 7)
        | H.bitfield((field >> 7) & 0x1fff, 20, 13)
        | H.bitfield((field >> 20) & 1, 36, 1)
    )


def _chk_a_branch(source: int, target: int, *, reg: int,
                  fp: bool = False, clear: bool = False,
                  qp: int = 0) -> int:
    field = _checked_field(source, target)
    return (
        chk_a(reg=reg, fp=fp, clear=clear, qp=qp)
        | H.bitfield(field & 0xfffff, 13, 20)
        | H.bitfield((field >> 20) & 1, 36, 1)
    )


def _m_system(x6: int, *, r1: int = 0, r2: int = 0,
              r3: int = 0, qp: int = 0) -> int:
    return (
        H.op(1) | H.bitfield(x6, 27, 6) | H.bitfield(r3, 20, 7)
        | H.bitfield(r2, 13, 7) | H.bitfield(r1, 6, 7)
        | H.bitfield(qp, 0, 6)
    )


def ordinary_load(width: int, r1: int, r3: int, *, qp: int = 0) -> int:
    code = {1: 0, 2: 1, 4: 2, 8: 3}[width]
    return (H.op(4) | H.bitfield(code, 30, 6) | H.bitfield(r3, 20, 7)
            | H.bitfield(r1, 6, 7) | qp)


def _append_i(bundles: List[object], address: int,
              instructions: Sequence[int]) -> int:
    for index in range(0, len(instructions), 2):
        slot2 = (instructions[index + 1]
                 if index + 1 < len(instructions) else H.nop_i())
        bundles.append(H.Bundle(address, 0x03, H.nop_m(),
                                instructions[index], slot2))
        address += 0x10
    return address


def _append_m(bundles: List[object], address: int, raw: int,
              traced: List[int], *, trace: bool = True) -> int:
    bundles.append(H.Bundle(address, 0x01, raw, H.nop_i(), H.nop_i()))
    if trace:
        traced.append(address)
    return address + 0x10


def _finish(name: str, bundles: List[object], address: int,
            data: Sequence[object] = ()) -> object:
    bundles.append(H.spin_bundle(address))
    return H.Program(name=name, bundles=tuple(bundles), terminal_ip=address,
                     data=tuple(data))


def _mapped_pte(physical: int, memory_attribute: int, *,
                access_rights: int = 3) -> int:
    """Present, accessed, dirty, PL0 4-KiB DTC translation image."""
    return (physical | 1 | ((memory_attribute & 7) << 2) |
            (1 << 5) | (1 << 6) | ((access_rights & 7) << 9))


def _append_dtc_install(bundles: List[object], address: int, *,
                        pte_reg: int = 2, virtual_reg: int = 7,
                        itir_reg: int = 4) -> int:
    address = _append_i(
        bundles, address, (H.adds(itir_reg, 12 << 2, 0),),
    )
    for raw in (
        H.mov_grcr(H.IA64_CR_IFA, virtual_reg),
        H.mov_grcr(H.IA64_CR_ITIR, itir_reg),
    ):
        bundles.append(H.Bundle(address, 0x01, raw,
                                H.nop_i(), H.nop_i()))
        address += 0x10
    # ITC.D must end its instruction group.  M_MI places a stop directly
    # after slot 0 while retaining the one-bundle-per-step fixture layout.
    bundles.append(H.Bundle(
        address, 0x0B, _m_system(0x2e, r2=pte_reg),
        H.nop_m(), H.nop_i(),
    ))
    address += 0x10
    for raw in (
        H.srlz_d(),
        H.ssm(H.IA64_PSR_IC | H.IA64_PSR_DT),
        H.srlz_i(),
    ):
        bundles.append(H.Bundle(address, 0x01, raw,
                                H.nop_i(), H.nop_i()))
        address += 0x10
    return address


def _marker_bundle(address: int, reg: int, value: int,
                   target: int) -> object:
    return H.Bundle(address, 0x11, H.nop_m(), H.adds(reg, value, 0),
                    H.br_cond(address, target))


@dataclasses.dataclass(frozen=True)
class RuntimeCase:
    name: str
    program: object
    trace_ips: Tuple[int, ...]
    verify: Callable[[object], str]
    opcode_coverage: Tuple[str, ...]
    preserve_fault_slot: bool = False


def _no_exception(snapshot, label: str) -> None:
    H._require(not snapshot.exception_pending,
               label + " unexpectedly raised " + snapshot.exception_kind)


def _verify_admission(snapshot) -> str:
    _no_exception(snapshot, "predicated-off admission matrix")
    return "all encodings nullified after typed decode/admission"


def primary_admission_case() -> RuntimeCase:
    bundles: List[object] = []
    traced: List[int] = []
    address = 0x10
    for opcode in DATA_PLANE_OPCODES:
        address = _append_m(
            bundles, address, primary_encoding(opcode, qp=1), traced,
            trace=(SPEC_BY_OPCODE[opcode].isa_status !=
                   "decoder-reserved-width"),
        )
    return RuntimeCase(
        "57-live-row primary decode/admission",
        _finish("data-plane primary admission", bundles, address),
        tuple(traced), _verify_admission, tuple(DATA_PLANE_OPCODES),
    )


def alias_admission_case() -> RuntimeCase:
    live = tuple(alias for alias in ALIAS_ENCODINGS
                 if alias.status != "shadowed-by-cmpxchg")
    bundles: List[object] = []
    traced: List[int] = []
    address = 0x10
    for alias in live:
        raw = (alias.raw & ~0x3f) | 1
        address = _append_m(bundles, address, raw, traced)
    coverage = tuple(dict.fromkeys(alias.opcode for alias in live))
    return RuntimeCase(
        "live decoder aliases and completers",
        _finish("data-plane live aliases", bundles, address),
        tuple(traced), _verify_admission, coverage,
    )


def atomic_case() -> RuntimeCase:
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 9, 0),
         H.adds(14, 0x1808, 0), H.adds(15, 0x1810, 0)),
    )
    address = _append_m(
        bundles, address,
        atomic("IA64_OP_XCHG8", r1=20, r2=11, r3=10), traced,
    )
    address = _append_m(
        bundles, address,
        atomic("IA64_OP_FETCHADD8", r1=21, r3=10, inc_index=3), traced,
    )
    address = _append_m(bundles, address, H.ld8(12, 14), traced, trace=False)
    address = _append_m(bundles, address, H.ld8(13, 15), traced, trace=False)
    address = _append_m(
        bundles, address, H.mov_m_grar(32, 12), traced, trace=False
    )
    address = _append_m(
        bundles, address,
        atomic("IA64_OP_CMPXCHG8", r1=22, r2=13, r3=10), traced,
    )
    address = _append_m(bundles, address, H.ld8(23, 10), traced, trace=False)
    program = _finish(
        "xchg/fetchadd/cmpxchg literal semantics", bundles, address,
        (H.DataWord(0x1800, 5, 8), H.DataWord(0x1808, 10, 8),
         H.DataWord(0x1810, 100, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "atomic matrix")
        H._require(
            (snapshot.gr[20], snapshot.gr[21], snapshot.gr[22],
             snapshot.gr[23]) == (5, 9, 10, 100),
            "atomic old values/final memory were {}, {}, {}, {}".format(
                snapshot.gr[20], snapshot.gr[21], snapshot.gr[22],
                snapshot.gr[23]),
        )
        H._require((snapshot.nat_low & sum(1 << reg for reg in range(20, 24))) == 0,
                   "atomic results did not clear NaT")
        return "xchg8 returned 5, fetchadd8 returned 9, cmpxchg8 returned 10 and stored 100"

    return RuntimeCase(
        "active atomic semantics", program, tuple(traced), verify,
        ("IA64_OP_XCHG8", "IA64_OP_FETCHADD8", "IA64_OP_CMPXCHG8"),
    )


def wide_spill_case() -> RuntimeCase:
    low = 0x1122334455667788
    high = 0x99AABBCCDDEEFF00
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(11, 0x1800, 0), H.adds(12, 0x1820, 0),
         H.adds(13, 0x1828, 0), H.adds(15, 0x1810, 0),
         H.adds(16, 0x1840, 0)),
    )
    address = _append_m(bundles, address, H.ld8(10, 15), traced, trace=False)
    address = _append_m(
        bundles, address, integer_load(8, "s", r1=20, r3=10), traced
    )
    address = _append_m(
        bundles, address, integer_spill(8, r2=20, r3=16), traced
    )
    address = _append_m(
        bundles, address, integer_load(8, "fill", r1=21, r3=16), traced
    )
    address = _append_m(bundles, address, ld16(r1=22, r3=11), traced)
    address = _append_m(
        bundles, address, H.mov_m_argr(23, 25), traced, trace=False
    )
    address = _append_m(bundles, address, st16(r2=22, r3=12), traced)
    address = _append_m(bundles, address, H.ld8(24, 12), traced, trace=False)
    address = _append_m(bundles, address, H.ld8(25, 13), traced, trace=False)
    program = _finish(
        "speculative spill/fill and AR.CSD wide memory", bundles, address,
        (H.DataWord(0x1800, low, 8), H.DataWord(0x1808, high, 8),
         H.DataWord(0x1810, 0x40000000, 8),
         H.DataWord(0x1820, 0, 8), H.DataWord(0x1828, 0, 8),
         H.DataWord(0x1840, 0, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "wide/spill matrix")
        H._require(snapshot.gr[22] == low and snapshot.gr[23] == high,
                   "ld16 did not place low address in GR and high address in AR.CSD")
        H._require(snapshot.gr[24] == low and snapshot.gr[25] == high,
                   "st16 did not write GR/AR.CSD pair")
        H._require((snapshot.nat_low & ((1 << 20) | (1 << 21))) ==
                   ((1 << 20) | (1 << 21)),
                   "speculative NaT did not survive st8.spill/ld8.fill")
        H._require(snapshot.unat & (1 << 8),
                   "st8.spill did not copy source NaT to UNAT[8]")
        return "ld8.s deferred, spill/fill copied UNAT[8], and ld16/st16 round-tripped GR+AR.CSD"

    return RuntimeCase(
        "active speculative/wide/spill semantics", program, tuple(traced), verify,
        ("IA64_OP_LD8S", "IA64_OP_ST8SPILL", "IA64_OP_LD8FILL",
         "IA64_OP_LD16", "IA64_OP_ST16"),
    )


def floating_case() -> RuntimeCase:
    single = 0x3FC00000
    double = 0x4002000000000000
    significand = 0x8877665544332211
    external = 0xC123
    spill_sign_exponent = 0x30123
    pair = 0x402000003F800000
    source_addresses = (0x1800, 0x1808, 0x1810, 0x1818, 0x1820, 0x1830)
    output_addresses = (0x1860, 0x1868, 0x1870, 0x1878, 0x1880, 0x1890)
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        tuple(H.adds(reg, value, 0) for reg, value in
              zip(range(10, 22), source_addresses + output_addresses)),
    )
    for load_op, store_op, f1, src_gr, dst_gr in (
        ("IA64_OP_LDFS", "IA64_OP_STFS", 20, 10, 16),
        ("IA64_OP_LDFD", "IA64_OP_STFD", 21, 11, 17),
        ("IA64_OP_LDF8", "IA64_OP_STF8", 22, 12, 18),
    ):
        address = _append_m(
            bundles, address, floating_load(load_op, f1=f1, r3=src_gr), traced
        )
        address = _append_m(
            bundles, address, floating_store(store_op, f2=f1, r3=dst_gr), traced
        )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFPS", f1=24, f2=25, r3=13), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=24, r3=19), traced,
    )
    # The second pair element follows the first output word.
    address = _append_i(bundles, address, (H.adds(22, 0x187c, 0),))
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=25, r3=22), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFE", f1=26, r3=14), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFE", f2=26, r3=20), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=27, r3=15), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STF_SPILL", f2=27, r3=21), traced,
    )
    for width, target, base in (
        (4, 23, 16), (8, 24, 17), (8, 25, 18), (8, 26, 19),
        (8, 27, 20), (8, 28, 21),
    ):
        address = _append_m(
            bundles, address, ordinary_load(width, target, base), traced,
            trace=False,
        )
    address = _append_i(
        bundles, address,
        (H.adds(8, 0x1888, 0), H.adds(9, 0x1898, 0)),
    )
    address = _append_m(
        bundles, address, ordinary_load(2, 29, 8), traced, trace=False,
    )
    address = _append_m(
        bundles, address, ordinary_load(8, 30, 9), traced, trace=False,
    )
    data = (
        H.DataWord(0x1800, single, 4), H.DataWord(0x1808, double, 8),
        H.DataWord(0x1810, significand, 8), H.DataWord(0x1818, pair, 8),
        H.DataWord(0x1820, significand, 8),
        H.DataWord(0x1828, external, 2),
        H.DataWord(0x1830, significand, 8),
        H.DataWord(0x1838, spill_sign_exponent, 8),
        H.DataWord(0x1860, 0, 4), H.DataWord(0x1868, 0, 8),
        H.DataWord(0x1870, 0, 8), H.DataWord(0x1878, 0, 8),
        H.DataWord(0x1880, 0, 8), H.DataWord(0x1888, 0, 8),
        H.DataWord(0x1890, 0, 8), H.DataWord(0x1898, 0, 8),
    )
    program = _finish("floating load/store literal round trips",
                      bundles, address, data)

    def verify(snapshot) -> str:
        _no_exception(snapshot, "floating memory matrix")
        expected = (single, double, significand, pair,
                    significand, significand, external,
                    spill_sign_exponent)
        actual = tuple(snapshot.gr[reg] for reg in range(23, 31))
        H._require(actual == expected,
                   "floating memory round trips were {} not {}".format(
                       tuple(hex(value) for value in actual),
                       tuple(hex(value) for value in expected)))
        return ("single/double/significand/pair plus nonzero extended and "
                "spill payloads round-tripped literal LE bytes")

    return RuntimeCase(
        "active floating memory semantics", program, tuple(traced), verify,
        ("IA64_OP_LDFS", "IA64_OP_STFS", "IA64_OP_LDFD", "IA64_OP_STFD",
         "IA64_OP_LDF8", "IA64_OP_STF8", "IA64_OP_LDFPS",
         "IA64_OP_LDFE", "IA64_OP_STFE", "IA64_OP_LDF_FILL",
         "IA64_OP_STF_SPILL"),
    )


def floating_zero_encoding_case() -> RuntimeCase:
    """Keep architectural zero distinct from unsupported pseudo-infinity."""
    addresses = (
        0x1800, 0x1820, 0x1840, 0x1848,
        0x1880, 0x1888, 0x18A0, 0x18A8, 0x18C0, 0x18C8,
    )
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        tuple(H.adds(reg, value, 0)
              for reg, value in zip(range(10, 20), addresses)),
    )

    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=20, r3=10), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STF_SPILL", f2=20, r3=14), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=21, r3=11), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STF_SPILL", f2=21, r3=16), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFS", f1=22, r3=12), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=22, r3=18), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFD", f1=23, r3=13), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFD", f2=23, r3=19), traced,
    )

    for base, target, width in (
        (14, 20, 8), (15, 21, 8),
        (16, 22, 8), (17, 23, 8),
        (18, 24, 4), (19, 25, 8),
    ):
        address = _append_m(
            bundles, address, ordinary_load(width, target, base), traced,
            trace=False,
        )

    program = _finish(
        "floating architectural zero and pseudo-infinity encodings",
        bundles, address,
        (
            # Exact register-format +0 spill image.
            H.DataWord(0x1800, 0, 8), H.DataWord(0x1808, 0, 8),
            # Same significand, but special exponent: unsupported
            # pseudo-infinity and therefore not a zero alias.
            H.DataWord(0x1820, 0, 8), H.DataWord(0x1828, 0x1FFFF, 8),
            H.DataWord(0x1840, 0x80000000, 4),
            H.DataWord(0x1848, 0, 8),
            H.DataWord(0x1880, 0, 8), H.DataWord(0x1888, 0, 8),
            H.DataWord(0x18A0, 0, 8), H.DataWord(0x18A8, 0, 8),
            H.DataWord(0x18C0, 0, 4), H.DataWord(0x18C8, 0, 8),
        ),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "floating zero encoding matrix")
        expected = (0, 0, 0, 0x1FFFF, 0x80000000, 0)
        actual = tuple(snapshot.gr[reg] for reg in range(20, 26))
        H._require(actual == expected,
                   "zero/pseudo-infinity images were {} not {}".format(
                       tuple(hex(value) for value in actual),
                       tuple(hex(value) for value in expected)))
        return ("spill/fill preserved exp=0 zero and exp=0x1ffff "
                "pseudo-infinity separately; -0 single and +0 double "
                "round-tripped")

    return RuntimeCase(
        "floating zero/pseudo-infinity encoding semantics",
        program, tuple(traced), verify,
        ("IA64_OP_LDF_FILL", "IA64_OP_STF_SPILL",
         "IA64_OP_LDFS", "IA64_OP_STFS",
         "IA64_OP_LDFD", "IA64_OP_STFD"),
    )


def floating_big_endian_case() -> RuntimeCase:
    mantissa = 0x8877665544332211
    external = 0xC123
    spill_sign_exponent = 0x30123
    # DataWord values are little-endian byte images.  These literals encode
    # the architected BE layouts, not helper-internal numeric round trips.
    ext_prefix_image = 0x33445566778823C1
    spill_prefix_image = 0x2301030000000000
    mantissa_be_image = 0x1122334455667788
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 0x1820, 0),
         H.adds(12, 0x1840, 0), H.adds(13, 0x1860, 0)),
    )
    bundles.append(H.Bundle(address, 0x01, H.ssm(1 << 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFE", f1=20, r3=10), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFE", f2=20, r3=12), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=21, r3=11), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STF_SPILL", f2=21, r3=13), traced,
    )
    bundles.append(H.Bundle(address, 0x01, H.rsm(1 << 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_i(
        bundles, address,
        (H.adds(14, 0x1840, 0), H.adds(15, 0x1848, 0),
         H.adds(16, 0x1860, 0), H.adds(17, 0x1868, 0)),
    )
    for width, target, base in (
        (8, 23, 14), (2, 24, 15), (8, 25, 16), (8, 26, 17),
    ):
        address = _append_m(
            bundles, address, ordinary_load(width, target, base), traced,
            trace=False,
        )
    program = _finish(
        "nonzero big-endian extended and spill literal layouts",
        bundles, address,
        (H.DataWord(0x1800, 0x23C1, 2),
         H.DataWord(0x1802, mantissa_be_image, 8),
         H.DataWord(0x1820, spill_prefix_image, 8),
         H.DataWord(0x1828, mantissa_be_image, 8),
         H.DataWord(0x1840, 0, 8), H.DataWord(0x1848, 0, 8),
         H.DataWord(0x1860, 0, 8), H.DataWord(0x1868, 0, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "big-endian floating memory matrix")
        expected = (ext_prefix_image, 0x1122,
                    spill_prefix_image, mantissa_be_image)
        actual = tuple(snapshot.gr[reg] for reg in range(23, 27))
        H._require(actual == expected,
                   "BE extended/spill byte images were {} not {}".format(
                       tuple(hex(value) for value in actual),
                       tuple(hex(value) for value in expected)))
        H._require((snapshot.psr & (1 << 1)) == 0,
                   "BE floating test did not restore PSR.be")
        return ("LDFE/STFE and LDF.FILL/STF.SPILL reproduced exact nonzero "
                "big-endian byte layouts")

    return RuntimeCase(
        "nonzero big-endian extended/spill semantics", program,
        tuple(traced), verify,
        ("IA64_OP_LDFE", "IA64_OP_STFE", "IA64_OP_LDF_FILL",
         "IA64_OP_STF_SPILL"),
    )


def big_endian_wide_pair_case() -> RuntimeCase:
    wide_low = 0x0123456789ABCDEF
    wide_high = 0xFEDCBA9876543210
    wide_low_image = 0xEFCDAB8967452301
    wide_high_image = 0x1032547698BADCFE
    pair_image = 0x000020400000803F
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 0x1820, 0),
         H.adds(12, 0x1840, 0), H.adds(13, 0x1860, 0),
         H.adds(14, 0x1864, 0)),
    )
    bundles.append(H.Bundle(address, 0x01, H.ssm(1 << 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_m(bundles, address, ld16(r1=20, r3=10), traced)
    address = _append_m(
        bundles, address, H.mov_m_argr(21, 25), traced, trace=False
    )
    address = _append_m(bundles, address, st16(r2=20, r3=11), traced)
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFPS", f1=24, f2=25, r3=12), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=24, r3=13), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=25, r3=14), traced,
    )
    bundles.append(H.Bundle(address, 0x01, H.rsm(1 << 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_m(
        bundles, address, ordinary_load(8, 22, 11), traced, trace=False,
    )
    address = _append_i(bundles, address, (H.adds(15, 0x1828, 0),))
    address = _append_m(
        bundles, address, ordinary_load(8, 23, 15), traced, trace=False,
    )
    address = _append_m(
        bundles, address, ordinary_load(8, 26, 13), traced, trace=False,
    )
    program = _finish(
        "big-endian wide and FP-pair address ordering", bundles, address,
        (H.DataWord(0x1800, wide_low_image, 8),
         H.DataWord(0x1808, wide_high_image, 8),
         H.DataWord(0x1820, 0, 8), H.DataWord(0x1828, 0, 8),
         H.DataWord(0x1840, pair_image, 8),
         H.DataWord(0x1860, 0, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "big-endian wide/pair matrix")
        H._require((snapshot.gr[20], snapshot.gr[21]) ==
                   (wide_low, wide_high),
                   "BE ld16 assigned the wrong GR/AR.CSD address halves")
        H._require((snapshot.gr[22], snapshot.gr[23]) ==
                   (wide_low_image, wide_high_image),
                   "BE st16 did not reproduce the two literal byte images")
        H._require(snapshot.gr[26] == pair_image,
                   "BE LDFPS/STFS reversed its low/high-address elements")
        H._require((snapshot.psr & (1 << 1)) == 0,
                   "BE wide/pair test did not restore PSR.be")
        return ("BE LD16/ST16 preserved low-address GR plus high-address "
                "AR.CSD, and LDFPS preserved pair element order")

    return RuntimeCase(
        "big-endian wide and FP-pair semantics", program, tuple(traced),
        verify,
        ("IA64_OP_LD16", "IA64_OP_ST16", "IA64_OP_LDFPS",
         "IA64_OP_STFS"),
    )


def _rotated_fr_setup(target: int, rrb_fr: int) -> List[object]:
    ifs = (1 << 63) | ((rrb_fr & 0x7f) << 25)
    return [
        _movl_bundle(0x10, 2, H.IA64_PSR_IC),
        _movl_bundle(0x20, 3, target),
        _movl_bundle(0x30, 4, ifs),
        H.Bundle(0x40, 0x01, H.mov_grcr(H.IA64_CR_IPSR, 2),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x50, 0x01, H.mov_grcr(H.IA64_CR_IIP, 3),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x60, 0x01, H.mov_grcr(H.IA64_CR_IFS, 4),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x70, 0x11, H.nop_m(), H.nop_i(), H.rfi()),
    ]


def rotated_fp_pair_legal_case() -> RuntimeCase:
    pair = 0x402000003F800000
    target = 0x80
    bundles = _rotated_fr_setup(target, rrb_fr=1)
    traced: List[int] = []
    address = _append_i(
        bundles, target,
        (H.adds(10, 0x1800, 0), H.adds(11, 0x1820, 0),
         H.adds(12, 0x1824, 0)),
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFPS", f1=20, f2=32, r3=10), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=20, r3=11), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=32, r3=12), traced,
    )
    address = _append_m(
        bundles, address, ordinary_load(8, 20, 11), traced, trace=False,
    )
    program = _finish(
        "physical FP-pair legality after FR rotation", bundles, address,
        (H.DataWord(0x1800, pair, 8), H.DataWord(0x1820, 0, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "rotated legal FP pair")
        H._require(((snapshot.cfm >> 25) & 0x7f) == 1,
                   "RFI did not establish rrb_fr=1")
        H._require(snapshot.gr[20] == pair,
                   "logical f20/f32 did not load/store as a legal physical "
                   "even/odd pair")
        return ("rrb_fr=1 mapped logical f20/f32 to physical f20/f33, "
                "making the logically same-parity pair legal")

    return RuntimeCase(
        "rotated physical FP-pair legal semantics", program, tuple(traced),
        verify, ("IA64_OP_LDFPS", "IA64_OP_STFS"),
    )


def rotated_fp_pair_illegal_case() -> RuntimeCase:
    target = 0x80
    bundles = _rotated_fr_setup(target, rrb_fr=1)
    traced: List[int] = []
    address = _append_i(bundles, target, (H.adds(10, 0x1800, 0),))
    fault_ip = address
    fault_raw = floating_load(
        "IA64_OP_LDFPS", f1=20, f2=33, r3=10
    )
    address = _append_m(bundles, address, fault_raw, traced)
    bundles.append(H._exception_vector_spin(IA64_ILLEGAL_OPERATION_VECTOR))
    program = H.Program(
        name="physical FP-pair illegality after FR rotation",
        bundles=tuple(bundles), terminal_ip=IA64_ILLEGAL_OPERATION_VECTOR,
        data=(H.DataWord(0x1800, 0x402000003F800000, 8),),
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.ip == IA64_ILLEGAL_OPERATION_VECTOR and
            snapshot.exception_pending and
            snapshot.exception_kind == "illegal-operation" and
            snapshot.exception_vector == IA64_ILLEGAL_OPERATION_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == fault_ip and
            snapshot.cr_iip == fault_ip and snapshot.cr_isr == 0,
            "rotated logical f20/f33 pair did not raise precise Illegal",
        )
        H._require(snapshot.slot_valid and snapshot.slot_ip == fault_ip and
                   snapshot.slot_ri == 0 and
                   snapshot.slot_type == H.IA64_SLOT_TYPE_M and
                   snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
                   "rotated illegal FP pair lost its exact M-slot image")
        return ("rrb_fr=1 mapped logical f20/f33 to physical f20/f34, "
                "making the logically opposite-parity pair Illegal")

    return RuntimeCase(
        "rotated physical FP-pair Illegal", program, tuple(traced), verify,
        ("IA64_OP_LDFPS",), True,
    )


def alat_cache_hint_case() -> RuntimeCase:
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 8, 0),
         H.adds(12, 0x1800, 0), H.adds(13, 0x1820, 0),
         H.adds(21, 0x222, 0)),
    )
    address = _append_m(
        bundles, address, lfetch(r2=11, r3=10, update="reg"), traced
    )
    address = _append_m(
        bundles, address,
        lfetch(fault=True, r3=12, update="imm", imm=8), traced,
    )
    address = _append_m(
        bundles, address, integer_load(8, "a", r1=20, r3=13), traced
    )
    address = _append_m(bundles, address, H.st8(21, 13), traced, trace=False)
    address = _append_m(
        bundles, address, integer_load(8, "c.nc", r1=20, r3=13), traced
    )
    address = _append_m(
        bundles, address, integer_load(8, "c.clr", r1=20, r3=13), traced
    )
    for raw in (
        cache_control("IA64_OP_FWB"),
        cache_control("IA64_OP_FC", reg=10),
        cache_control("IA64_OP_INVALAT", reg=20),
        cache_control("IA64_OP_INVALA"),
    ):
        address = _append_m(bundles, address, raw, traced)
    program = _finish(
        "ALAT check loads, cache control, and lfetch updates", bundles,
        address, (H.DataWord(0x1800, 0, 8), H.DataWord(0x1820, 0x111, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "ALAT/cache/hint matrix")
        H._require(snapshot.gr[10] == 0x1808 and snapshot.gr[12] == 0x1808,
                   "lfetch register/immediate updates did not run after hint")
        H._require(snapshot.gr[20] == 0x222,
                   "c.nc miss/c.clr hit did not reload then preserve target")
        return "lfetch updates reached 0x1808; store collision forced c.nc reload; c.clr hit preserved 0x222"

    return RuntimeCase(
        "active ALAT/cache/hint semantics", program, tuple(traced), verify,
        ("IA64_OP_LFETCH", "IA64_OP_LFETCH_FAULT", "IA64_OP_LD8A",
         "IA64_OP_LD8C_NC", "IA64_OP_LD8C_CLR", "IA64_OP_FWB",
         "IA64_OP_FC", "IA64_OP_INVALAT", "IA64_OP_INVALA"),
    )


def integer_advanced_nat_page_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 6, physical),
    ]
    traced: List[int] = []
    address = _append_m(
        bundles, 0x40,
        integer_load(8, "a", r1=21, r3=6), traced,
    )
    address = _append_dtc_install(bundles, address)
    fault_ip = address
    fault_raw = integer_load(
        8, "a", r1=21, r3=7, update="imm", imm=8,
    )
    address = _append_m(bundles, address, fault_raw, traced)
    H._require(address == fault_ip + 0x10,
               "integer .a NaTPage fault address drifted")
    bundles.extend((
        H.Bundle(
            IA64_DATA_NAT_PAGE_VECTOR, 0x01,
            _chk_a_branch(IA64_DATA_NAT_PAGE_VECTOR,
                          IA64_DATA_NAT_PAGE_VECTOR + 0x20, reg=21),
            H.nop_i(), H.nop_i(),
        ),
        _marker_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x10, 30, 1,
                       IA64_DATA_NAT_PAGE_VECTOR + 0x30),
        _marker_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x20, 30, 0xBAD,
                       IA64_DATA_NAT_PAGE_VECTOR + 0x30),
        H.spin_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x30),
    ))
    traced.append(IA64_DATA_NAT_PAGE_VECTOR)
    program = H.Program(
        name="LD8.A NaTPage fault retains destination, update, and ALAT",
        bundles=tuple(bundles),
        terminal_ip=IA64_DATA_NAT_PAGE_VECTOR + 0x30,
        data=(H.DataWord(physical, 0x55, 8),),
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.exception_pending and
            snapshot.exception_kind == "data-nat-page-consumption" and
            snapshot.exception_vector == IA64_DATA_NAT_PAGE_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == virtual and
            snapshot.cr_iip == fault_ip and snapshot.cr_ifa == virtual and
            snapshot.cr_isr == H.IA64_ISR_R |
                               IA64_ISR_CODE_DATA_NAT_PAGE_CONSUMPTION,
            "LD8.A did not publish an exact ordinary-read Data-NaT fault",
        )
        H._require(snapshot.gr[7] == virtual and snapshot.gr[21] == 0x55 and
                   not (snapshot.nat_low & (1 << 21)),
                   "LD8.A NaTPage fault changed its base/destination/NaT")
        H._require(snapshot.gr[30] == 1,
                   "LD8.A NaTPage fault invalidated the prior ALAT entry")
        return ("LD8.A raised ordinary-read Data NaT Page with no base, "
                "destination, NaT, or ALAT mutation")

    return RuntimeCase(
        "LD8.A exact NaTPage fault and ALAT retention", program,
        tuple(traced), verify, ("IA64_OP_LD8A", "IA64_OP_CHK_A"),
    )


def fp_advanced_nat_page_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 6, physical),
    ]
    traced: List[int] = []
    address = _append_m(
        bundles, 0x40,
        floating_load("IA64_OP_LDFE", attr="a", f1=20, r3=6), traced,
    )
    address = _append_dtc_install(bundles, address)
    fault_ip = address
    fault_raw = floating_load(
        "IA64_OP_LDFE", attr="a", f1=20, r3=7,
        update="imm", imm=8,
    )
    address = _append_m(bundles, address, fault_raw, traced)
    bundles.extend((
        H.Bundle(
            IA64_DATA_NAT_PAGE_VECTOR, 0x01,
            _chk_a_branch(IA64_DATA_NAT_PAGE_VECTOR,
                          IA64_DATA_NAT_PAGE_VECTOR + 0x20,
                          reg=20, fp=True),
            H.nop_i(), H.nop_i(),
        ),
        _marker_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x10, 30, 1,
                       IA64_DATA_NAT_PAGE_VECTOR + 0x30),
        _marker_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x20, 30, 0xBAD,
                       IA64_DATA_NAT_PAGE_VECTOR + 0x30),
        H.spin_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x30),
    ))
    traced.append(IA64_DATA_NAT_PAGE_VECTOR)
    program = H.Program(
        name="LDFE.A NaTPage fault retains base, FR, and ALAT",
        bundles=tuple(bundles),
        terminal_ip=IA64_DATA_NAT_PAGE_VECTOR + 0x30,
        data=(H.DataWord(physical, 0x8877665544332211, 8),
              H.DataWord(physical + 8, 0xC123, 2)),
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.exception_pending and
            snapshot.exception_kind == "data-nat-page-consumption" and
            snapshot.exception_vector == IA64_DATA_NAT_PAGE_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == virtual and
            snapshot.cr_iip == fault_ip and snapshot.cr_ifa == virtual and
            snapshot.cr_isr == H.IA64_ISR_R |
                               IA64_ISR_CODE_DATA_NAT_PAGE_CONSUMPTION,
            "LDFE.A did not publish an exact ordinary-read Data-NaT fault",
        )
        H._require(snapshot.gr[7] == virtual,
                   "LDFE.A NaTPage fault retired its base update")
        H._require(snapshot.gr[30] == 1,
                   "LDFE.A NaTPage fault invalidated the prior FR ALAT entry")
        return ("LDFE.A raised ordinary-read Data NaT Page and retained its "
                "base plus prior FR ALAT entry")

    return RuntimeCase(
        "LDFE.A exact NaTPage fault and FR ALAT retention", program,
        tuple(traced), verify, ("IA64_OP_LDFE", "IA64_OP_CHK_A"),
    )


def fp_advanced_unsupported_case(memory_attribute: int) -> RuntimeCase:
    if memory_attribute not in (4, 5, 6):
        raise ValueError("LDFE.A unsupported case requires MA4/5/6")
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2,
                     _mapped_pte(physical, memory_attribute)),
        _movl_bundle(0x20, 7, virtual),
    ]
    address = _append_dtc_install(bundles, 0x30)
    fault_ip = address
    fault_raw = floating_load(
        "IA64_OP_LDFE", attr="a", f1=20, r3=7,
        update="imm", imm=8,
    )
    traced: List[int] = []
    _append_m(bundles, address, fault_raw, traced)
    bundles.append(H._exception_vector_spin(
        IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR
    ))
    program = H.Program(
        name="LDFE.A MA{} unsupported reference".format(memory_attribute),
        bundles=tuple(bundles),
        terminal_ip=IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR,
        data=(H.DataWord(physical, 0x8877665544332211, 8),
              H.DataWord(physical + 8, 0xC123, 2)),
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.exception_pending and
            snapshot.exception_kind == "unsupported-data-reference" and
            snapshot.exception_vector ==
                IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == virtual and
            snapshot.cr_iip == fault_ip and snapshot.cr_ifa == virtual and
            snapshot.cr_isr == H.IA64_ISR_R,
            "LDFE.A MA{} did not raise exact Unsupported".format(
                memory_attribute),
        )
        H._require(snapshot.gr[7] == virtual,
                   "LDFE.A Unsupported retired its update")
        H._require(snapshot.slot_valid and snapshot.slot_ip == fault_ip and
                   snapshot.slot_ri == 0 and
                   snapshot.slot_type == H.IA64_SLOT_TYPE_M and
                   snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
                   "LDFE.A Unsupported lost exact fault-slot publication")
        return "LDFE.A MA{} raised WB-only Unsupported".format(
            memory_attribute)

    return RuntimeCase(
        "LDFE.A MA{} WB-only Unsupported".format(memory_attribute),
        program, tuple(traced), verify, ("IA64_OP_LDFE",), True,
    )


def integer_speculative_nat_page_defer_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 8, virtual),
    ]
    traced: List[int] = []
    address = _append_dtc_install(bundles, 0x40)
    address = _append_m(
        bundles, address,
        integer_load(8, "s", r1=20, r3=7,
                     update="imm", imm=8), traced,
    )
    address = _append_m(
        bundles, address,
        integer_load(8, "sa", r1=21, r3=8,
                     update="imm", imm=16), traced,
    )
    check_ip = address
    bundles.extend((
        H.Bundle(check_ip, 0x01,
                 _chk_a_branch(check_ip, check_ip + 0x20, reg=21),
                 H.nop_i(), H.nop_i()),
        _marker_bundle(check_ip + 0x10, 30, 0xBAD, check_ip + 0x30),
        _marker_bundle(check_ip + 0x20, 30, 1, check_ip + 0x30),
        H.spin_bundle(check_ip + 0x30),
    ))
    traced.append(check_ip)
    program = H.Program(
        name="LD8.S/SA NaTPage deferral and update retirement",
        bundles=tuple(bundles), terminal_ip=check_ip + 0x30,
        data=(H.DataWord(physical, 0xDEADBEEF, 8),),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "integer NaTPage speculative deferral")
        H._require(snapshot.gr[7] == virtual + 8 and
                   snapshot.gr[8] == virtual + 16,
                   "LD8.S/SA deferral did not retire base updates")
        H._require((snapshot.nat_low & ((1 << 20) | (1 << 21))) ==
                   ((1 << 20) | (1 << 21)),
                   "LD8.S/SA NaTPage did not stage destination NaTs")
        H._require(snapshot.gr[30] == 1,
                   "LD8.SA NaTPage incorrectly recorded an ALAT entry")
        return ("LD8.S and LD8.SA deferred NaTPage, retired updates, set "
                "destination NaTs, and left no ALAT record")

    return RuntimeCase(
        "LD8.S/SA NaTPage deferral", program, tuple(traced), verify,
        ("IA64_OP_LD8S", "IA64_OP_LD8SA", "IA64_OP_CHK_A"),
    )


def fp_speculative_nat_page_defer_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 8, virtual),
    ]
    traced: List[int] = []
    address = _append_dtc_install(bundles, 0x40)
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFE", attr="s", f1=20, r3=7,
                      update="imm", imm=8), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFE", attr="sa", f1=21, r3=8,
                      update="imm", imm=16), traced,
    )
    first_check = address
    second_check = first_check + 0x40
    terminal = second_check + 0x40
    bundles.extend((
        H.Bundle(first_check, 0x01,
                 _chk_s_branch(first_check, first_check + 0x20,
                               reg=20, fp=True),
                 H.nop_i(), H.nop_i()),
        _marker_bundle(first_check + 0x10, 30, 0xBAD, terminal),
        _marker_bundle(first_check + 0x20, 30, 1, second_check),
        H.Bundle(second_check, 0x01,
                 _chk_s_branch(second_check, second_check + 0x20,
                               reg=21, fp=True),
                 H.nop_i(), H.nop_i()),
        _marker_bundle(second_check + 0x10, 31, 0xBAD, terminal),
        _marker_bundle(second_check + 0x20, 31, 2, terminal),
        H.spin_bundle(terminal),
    ))
    traced.extend((first_check, second_check))
    program = H.Program(
        name="LDFE.S/SA NaTPage NatVal deferral and updates",
        bundles=tuple(bundles), terminal_ip=terminal,
        data=(H.DataWord(physical, 0x8877665544332211, 8),
              H.DataWord(physical + 8, 0xC123, 2)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "FP NaTPage speculative deferral")
        H._require(snapshot.gr[7] == virtual + 8 and
                   snapshot.gr[8] == virtual + 16,
                   "LDFE.S/SA deferral did not retire base updates")
        H._require((snapshot.gr[30], snapshot.gr[31]) == (1, 2),
                   "CHK.S did not observe both deferred FP NatVals")
        return ("LDFE.S and LDFE.SA deferred NaTPage to NatVal and retired "
                "their immediate updates")

    return RuntimeCase(
        "LDFE.S/SA NaTPage NatVal deferral", program, tuple(traced), verify,
        ("IA64_OP_LDFE", "IA64_OP_CHK_S"),
    )


def reserved_width_illegal_case(opcode: str) -> RuntimeCase:
    reserved = {
        "IA64_OP_LD1FILL", "IA64_OP_LD2FILL", "IA64_OP_LD4FILL",
        "IA64_OP_ST1SPILL", "IA64_OP_ST2SPILL", "IA64_OP_ST4SPILL",
    }
    if opcode not in reserved:
        raise ValueError("not a decoder-reserved fill/spill width")
    fault_ip = 0x30
    fault_raw = primary_encoding(opcode, qp=0)
    bundles: List[object] = [
        *H._interruption_collection_setup(),
        H.Bundle(fault_ip, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(IA64_ILLEGAL_OPERATION_VECTOR),
    ]
    program = H.Program(
        name=opcode + " true-predicate precise Illegal Operation",
        bundles=tuple(bundles), terminal_ip=IA64_ILLEGAL_OPERATION_VECTOR,
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.ip == IA64_ILLEGAL_OPERATION_VECTOR and
            snapshot.exception_pending and
            snapshot.exception_kind == "illegal-operation" and
            snapshot.exception_vector == IA64_ILLEGAL_OPERATION_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == fault_ip and
            snapshot.cr_iip == fault_ip and snapshot.cr_isr == 0,
            opcode + " did not raise a precise collected Illegal Operation",
        )
        H._require(snapshot.slot_valid and snapshot.slot_ip == fault_ip and
                   snapshot.slot_ri == 0 and
                   snapshot.slot_type == H.IA64_SLOT_TYPE_M and
                   snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
                   opcode + " lost its exact reserved M-slot image")
        H._require(snapshot.unat == 0 and snapshot.nat_low == 0 and
                   snapshot.gr[20] == 0,
                   opcode + " changed memory-side architectural state")
        return opcode + " true predicate raised exact Illegal Operation"

    return RuntimeCase(
        opcode.removeprefix("IA64_OP_").lower() +
        " true-predicate reserved Illegal", program, (), verify,
        (opcode,), True,
    )


def _require_nonaccess_fault(snapshot, *, fault_ip: int, fault_raw: int,
                             address: int, kind: str, vector: int,
                             base_code: int, subcode: int) -> None:
    expected_isr = H.IA64_ISR_R | IA64_ISR_NA | base_code | subcode
    H._require(
        snapshot.ip == vector and snapshot.exception_pending and
        snapshot.exception_kind == kind and
        snapshot.exception_vector == vector,
        "{} did not reach vector 0x{:x}".format(kind, vector),
    )
    H._require(
        snapshot.exception_source == fault_ip and
        snapshot.exception_address == address and
        snapshot.cr_ifa == address,
        "{} published source/address/IFA 0x{:x}/0x{:x}/0x{:x}, expected "
        "0x{:x}/0x{:x}".format(
            kind, snapshot.exception_source, snapshot.exception_address,
            snapshot.cr_ifa, fault_ip, address),
    )
    H._require(
        snapshot.cr_isr == expected_isr and snapshot.cr_iip == fault_ip,
        "{} expected ISR/IIP 0x{:x}/0x{:x}, got 0x{:x}/0x{:x}".format(
            kind, expected_isr, fault_ip, snapshot.cr_isr,
            snapshot.cr_iip),
    )
    H._require(
        snapshot.slot_valid and snapshot.slot_ip == fault_ip and
        snapshot.slot_ri == 0 and
        snapshot.slot_type == H.IA64_SLOT_TYPE_M and
        snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
        kind + " lost exact M-slot publication",
    )


def lfetch_nat_fault_case() -> RuntimeCase:
    bundles: List[object] = list(H._interruption_collection_setup())
    traced: List[int] = []
    address = _append_i(
        bundles, 0x30,
        (H.adds(1, 1, 0), H.adds(2, 0x1000, 0)),
    )
    address = _append_m(
        bundles, address, H.mov_m_grar(36, 1), traced, trace=False
    )
    address = _append_m(
        bundles, address, H.ld8_fill(10, 2), traced, trace=False
    )
    fault_ip = address
    fault_raw = lfetch(fault=True, r3=10, update="imm", imm=8)
    address = _append_m(bundles, address, fault_raw, traced)
    bundles.append(H._exception_vector_spin(
        H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR
    ))
    program = H.Program(
        name="lfetch.fault exact address-NaT interruption",
        bundles=tuple(bundles),
        terminal_ip=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(H.DataWord(0x1000, 0x8000, 8),),
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=fault_ip, fault_raw=fault_raw,
            address=fault_ip, kind="register-nat-consumption",
            vector=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
            base_code=H.IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION,
            subcode=4,
        )
        H._require(snapshot.gr[10] == 0x8000 and
                   (snapshot.nat_low & (1 << 10)),
                   "faulting lfetch consumed or updated its NaT base")
        return "base NaT raised exact R|NA Register-NaT code 0x14 before update"

    return RuntimeCase(
        "lfetch.fault exact base-NaT ISR", program, tuple(traced), verify,
        ("IA64_OP_LFETCH_FAULT",), True,
    )


def lfetch_translation_fault_case() -> RuntimeCase:
    bundles: List[object] = list(H._interruption_collection_setup())
    traced: List[int] = []
    bundles.append(_movl_bundle(0x30, 10, 0x8000))
    bundles.append(H.Bundle(0x40, 0x01, H.ssm(H.IA64_PSR_DT),
                            H.nop_i(), H.nop_i()))
    bundles.append(H.Bundle(0x50, 0x01, H.srlz_i(),
                            H.nop_i(), H.nop_i()))
    fault_ip = 0x60
    fault_raw = lfetch(fault=True, r3=10, update="imm", imm=8)
    _append_m(bundles, fault_ip, fault_raw, traced)
    bundles.append(H._exception_vector_spin(
        H.IA64_ALTERNATE_DATA_TLB_VECTOR
    ))
    program = H.Program(
        name="lfetch.fault exact translated-miss interruption",
        bundles=tuple(bundles),
        terminal_ip=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=fault_ip, fault_raw=fault_raw,
            address=0x8000, kind="alternate-data-tlb-miss",
            vector=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
            base_code=0, subcode=4,
        )
        H._require(snapshot.gr[10] == 0x8000 and
                   not (snapshot.nat_low & (1 << 10)),
                   "translated lfetch fault retired its immediate update")
        return "translated miss raised exact R|NA code 4 and suppressed update"

    return RuntimeCase(
        "lfetch.fault exact translated-miss ISR", program, tuple(traced),
        verify, ("IA64_OP_LFETCH_FAULT",), True,
    )


def nat_page_fault_case(opcode: str) -> RuntimeCase:
    if opcode not in ("IA64_OP_FC", "IA64_OP_LFETCH_FAULT"):
        raise ValueError("NaTPage case requires fc or lfetch.fault")
    virtual = 0x8000
    physical = 0x2000
    # P=1, ma=7, A=1, D=1, pl=0, ar=3 on a 4 KiB translation.
    pte = physical | 0x67d
    subcode = 1 if opcode == "IA64_OP_FC" else 4
    fault_raw = (
        cache_control(opcode, reg=7) if opcode == "IA64_OP_FC" else
        lfetch(fault=True, r3=7, update="imm", imm=8)
    )
    bundles: List[object] = [
        _movl_bundle(0x10, 2, pte),
        _movl_bundle(0x20, 7, virtual),
        H.Bundle(0x30, 0x03, H.nop_m(), H.adds(4, 12 << 2, 0),
                 H.nop_i()),
        H.Bundle(0x40, 0x01, H.mov_grcr(H.IA64_CR_IFA, 7),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x50, 0x01, H.mov_grcr(H.IA64_CR_ITIR, 4),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x60, 0x0B, _m_system(0x2e, r2=2),
                 H.nop_m(), H.nop_i()),
        H.Bundle(0x70, 0x01, H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(0x80, 0x01, H.ssm(H.IA64_PSR_IC | H.IA64_PSR_DT),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x90, 0x01, H.srlz_i(), H.nop_i(), H.nop_i()),
        H.Bundle(0xA0, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
    ]
    program = H.Program(
        name=opcode + " exact NaTPage interruption",
        bundles=tuple(bundles),
        terminal_ip=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(H.DataWord(physical, 0xfeedfacecafebeef, 8),),
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=0xA0, fault_raw=fault_raw,
            address=virtual, kind="data-nat-page-consumption",
            vector=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
            base_code=IA64_ISR_CODE_DATA_NAT_PAGE_CONSUMPTION,
            subcode=subcode,
        )
        H._require(snapshot.gr[7] == virtual,
                   opcode + " NaTPage fault retired an address update")
        return ("NaTPage mapping raised exact R|NA data-NaT code 0x{:x} "
                "without a guest read".format(0x20 | subcode))

    label = "fc" if opcode == "IA64_OP_FC" else "lfetch.fault"
    return RuntimeCase(
        label + " exact NaTPage ISR", program, (0xA0,), verify,
        (opcode,), True,
    )


def lfetch_ed_update_case() -> RuntimeCase:
    restored_psr = IA64_PSR_ED | H.IA64_PSR_DT | H.IA64_PSR_IC
    target = 0xD0
    bundles: List[object] = [
        _movl_bundle(0x10, 2, restored_psr),
        _movl_bundle(0x20, 3, target),
        H.Bundle(0x30, 0x01, H.mov_grcr(H.IA64_CR_IPSR, 2),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x40, 0x01, H.mov_grcr(H.IA64_CR_IIP, 3),
                 H.nop_i(), H.nop_i()),
    ]
    traced: List[int] = []
    address = _append_i(
        bundles, 0x50,
        (H.adds(1, 14, 0), H.adds(4, 0x1000, 0),
         H.adds(5, 0x1008, 0), H.adds(6, 0x1010, 0)),
    )
    bundles.append(H.Bundle(
        address, 0x03, H.mov_m_grar(36, 1),
        H.adds(7, 0x1018, 0), H.nop_i(),
    ))
    address += 0x10
    address = _append_m(bundles, address, H.ld8(10, 4), traced, trace=False)
    address = _append_m(
        bundles, address, H.ld8_fill(11, 5), traced, trace=False
    )
    address = _append_m(
        bundles, address, H.ld8_fill(12, 6), traced, trace=False
    )
    address = _append_m(
        bundles, address, H.ld8_fill(13, 7), traced, trace=False
    )
    H._require(address == 0xC0, "lfetch ED setup address drifted")
    bundles.append(H.Bundle(address, 0x11, H.nop_m(), H.nop_i(), H.rfi()))
    address += 0x10
    H._require(address == target, "lfetch ED RFI target drifted")
    address = _append_m(
        bundles, address,
        lfetch(fault=True, r2=11, r3=10, update="reg"), traced,
    )
    address = _append_m(
        bundles, address,
        lfetch(r3=12, update="imm", imm=8), traced,
    )
    fault_ip = address
    fault_raw = lfetch(fault=True, r3=13)
    address = _append_m(bundles, address, fault_raw, traced)
    bundles.append(H._exception_vector_spin(
        H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR
    ))
    program = H.Program(
        name=("lfetch.fault PSR.ed is one-shot while hint updates still "
              "retire"),
        bundles=tuple(bundles),
        terminal_ip=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(H.DataWord(0x1000, 0x8000, 8),
              H.DataWord(0x1008, 8, 8),
              H.DataWord(0x1010, 0x9000, 8),
              H.DataWord(0x1018, 0xA000, 8)),
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=fault_ip, fault_raw=fault_raw,
            address=fault_ip, kind="register-nat-consumption",
            vector=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
            base_code=H.IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION,
            subcode=4,
        )
        H._require(snapshot.gr[10] == 0x8008 and
                   snapshot.gr[12] == 0x9008,
                   "lfetch updates produced 0x{:x}/0x{:x}".format(
                       snapshot.gr[10], snapshot.gr[12]))
        expected_nat = ((1 << 10) | (1 << 11) | (1 << 12) |
                        (1 << 13))
        H._require((snapshot.nat_low & expected_nat) == expected_nat,
                   "register/immediate lfetch updates lost OR/preserved NaT")
        H._require((snapshot.cr_ipsr & IA64_PSR_ED) == 0,
                   "successful lfetch.fault failed to clear one-shot PSR.ed")
        return ("PSR.ed suppressed one translated miss then cleared; register "
                "update ORed NaT, nonfaulting immediate update preserved NaT, "
                "and the next lfetch.fault consumed its base NaT")

    return RuntimeCase(
        "lfetch.fault one-shot PSR.ed and update retirement", program,
        tuple(traced), verify,
        ("IA64_OP_LFETCH", "IA64_OP_LFETCH_FAULT"), True,
    )


def fc_ed_translation_fault_case() -> RuntimeCase:
    restored_psr = IA64_PSR_ED | H.IA64_PSR_DT | H.IA64_PSR_IC
    target = 0x70
    fault_raw = cache_control("IA64_OP_FC", reg=10)
    bundles: List[object] = [
        _movl_bundle(0x10, 2, restored_psr),
        _movl_bundle(0x20, 3, target),
        _movl_bundle(0x30, 10, 0x8000),
        H.Bundle(0x40, 0x01, H.mov_grcr(H.IA64_CR_IPSR, 2),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x50, 0x01, H.mov_grcr(H.IA64_CR_IIP, 3),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x60, 0x11, H.nop_m(), H.nop_i(), H.rfi()),
        H.Bundle(target, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(H.IA64_ALTERNATE_DATA_TLB_VECTOR),
    ]
    program = H.Program(
        name="fc ignores PSR.ed and raises exact translated miss",
        bundles=tuple(bundles),
        terminal_ip=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=target, fault_raw=fault_raw,
            address=0x8000, kind="alternate-data-tlb-miss",
            vector=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
            base_code=0, subcode=1,
        )
        H._require(snapshot.cr_ipsr & IA64_PSR_ED,
                   "fc translated miss did not collect the active PSR.ed")
        return "fc ignored PSR.ed and raised exact R|NA translated-miss code 1"

    return RuntimeCase(
        "fc PSR.ed-independent translated miss", program, (target,), verify,
        ("IA64_OP_FC",), True,
    )


def fc_nonaccess_accessed_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    # P=1, ma=0, A=0, D=0, pl=0, ar=7.  FC must not inspect A.
    pte = physical | 1 | (7 << 9)
    fault_raw = cache_control("IA64_OP_FC", reg=7)
    bundles: List[object] = [
        _movl_bundle(0x30, 2, pte),
        _movl_bundle(0x40, 7, virtual),
        H.Bundle(0x50, 0x03, H.nop_m(), H.adds(4, 12 << 2, 0),
                 H.nop_i()),
        H.Bundle(0x60, 0x01, H.mov_grcr(H.IA64_CR_IFA, 7),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x70, 0x01, H.mov_grcr(H.IA64_CR_ITIR, 4),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x80, 0x0B, _m_system(0x2e, r2=2),
                 H.nop_m(), H.nop_i()),
        H.Bundle(0x90, 0x01, H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(0xA0, 0x01, H.ssm(H.IA64_PSR_DT),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0xB0, 0x01, H.srlz_i(), H.nop_i(), H.nop_i()),
        H.Bundle(0xC0, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H.spin_bundle(0xD0),
    ]
    program = H.Program(
        name="fc skips the translation accessed bit", bundles=tuple(bundles),
        terminal_ip=0xD0, entry=0x30,
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "fc A-bit non-access lookup")
        H._require(snapshot.gr[7] == virtual,
                   "fc non-access lookup modified its source")
        return "fc completed through a present read mapping with A=0"

    return RuntimeCase(
        "fc non-access A-bit bypass", program, (0xC0,), verify,
        ("IA64_OP_FC",),
    )


def fc_nonaccess_rights_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    target = 0xF0
    restored_psr = H.IA64_PSR_IC | H.IA64_PSR_DT | (3 << 32)
    # P=1, ma=0, A=1, D=0, pl=0, ar=0: CPL3 cannot read it.
    pte = physical | 1 | (1 << 5)
    fault_raw = cache_control("IA64_OP_FC", reg=7)
    bundles: List[object] = [
        _movl_bundle(0x30, 2, pte),
        _movl_bundle(0x40, 7, virtual),
        _movl_bundle(0x50, 5, restored_psr),
        _movl_bundle(0x60, 6, target),
        H.Bundle(0x70, 0x03, H.nop_m(), H.adds(4, 12 << 2, 0),
                 H.nop_i()),
        H.Bundle(0x80, 0x01, H.mov_grcr(H.IA64_CR_IFA, 7),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x90, 0x01, H.mov_grcr(H.IA64_CR_ITIR, 4),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0xA0, 0x0B, _m_system(0x2e, r2=2),
                 H.nop_m(), H.nop_i()),
        H.Bundle(0xB0, 0x01, H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(0xC0, 0x01, H.mov_grcr(H.IA64_CR_IPSR, 5),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0xD0, 0x01, H.mov_grcr(H.IA64_CR_IIP, 6),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0xE0, 0x11, H.nop_m(), H.nop_i(), H.rfi()),
        H.Bundle(target, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(IA64_DATA_ACCESS_RIGHTS_VECTOR),
    ]
    program = H.Program(
        name="fc non-access lookup enforces read AR above CPL0",
        bundles=tuple(bundles), terminal_ip=IA64_DATA_ACCESS_RIGHTS_VECTOR,
        entry=0x30,
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=target, fault_raw=fault_raw,
            address=virtual, kind="data-access-rights",
            vector=IA64_DATA_ACCESS_RIGHTS_VECTOR,
            base_code=0, subcode=1,
        )
        H._require(((snapshot.cr_ipsr >> 32) & 3) == 3,
                   "fc access-rights fault did not collect CPL3")
        return "fc skipped A/key state but enforced read AR at CPL3"

    return RuntimeCase(
        "fc non-access CPL3 read-rights check", program, (target,), verify,
        ("IA64_OP_FC",), True,
    )


def checked_branch_gr_case() -> RuntimeCase:
    def marker(address: int, reg: int, value: int, target: int) -> object:
        return H.Bundle(
            address, 0x11, H.nop_m(), H.adds(reg, value, 0),
            H.br_cond(address, target),
        )

    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(1, 1, 0), H.adds(2, 0x1000, 0)),
    )
    bundles.append(H.Bundle(
        address, 0x03, H.mov_m_grar(36, 1),
        H.adds(13, 0x1800, 0), H.nop_i(),
    ))
    address += 0x10
    address = _append_m(
        bundles, address, H.ld8_fill(10, 2), traced, trace=False
    )
    H._require(address == 0x40, "checked-branch setup address drifted")

    bundles.append(H.Bundle(
        0x40, 0x01, _chk_s_branch(0x40, 0x60, reg=10),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x40)
    bundles.extend((
        marker(0x50, 20, 0x51, 0x80),
        marker(0x60, 20, 1, 0x80),
    ))

    _append_m(
        bundles, 0x80, integer_load(8, "a", r1=21, r3=13), traced
    )
    bundles.append(H.Bundle(
        0x90, 0x01, _chk_a_branch(0x90, 0xB0, reg=21),
        H.adds(25, 5, 0), H.nop_i(),
    ))
    traced.append(0x90)
    bundles.extend((
        marker(0xA0, 22, 2, 0xD0),
        marker(0xB0, 22, 0x52, 0x140),
    ))

    bundles.append(H.Bundle(
        0xD0, 0x01,
        _chk_a_branch(0xD0, 0xF0, reg=21, clear=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0xD0)
    bundles.extend((
        marker(0xE0, 23, 3, 0x110),
        marker(0xF0, 23, 0x53, 0x140),
    ))

    bundles.append(H.Bundle(
        0x110, 0x01, _chk_a_branch(0x110, 0x130, reg=21),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x110)
    bundles.extend((
        marker(0x120, 24, 0x54, 0x140),
        marker(0x130, 24, 4, 0x140),
        H.spin_bundle(0x140),
    ))
    program = H.Program(
        name="checked GR recovery branches and CHK.A clear lifecycle",
        bundles=tuple(bundles), terminal_ip=0x140,
        data=(H.DataWord(0x1000, 0x777, 8),
              H.DataWord(0x1800, 0x1122334455667788, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "checked GR branches")
        H._require(snapshot.gr[20] == 1,
                   "CHK.S did not take recovery on a GR NaT")
        H._require(snapshot.gr[21] == 0x1122334455667788,
                   "advanced load did not seed the checked ALAT entry")
        H._require((snapshot.gr[22], snapshot.gr[23], snapshot.gr[24]) ==
                   (2, 3, 4),
                   "CHK.A hit/CHK.A.CLR hit/post-clear miss markers were {}"
                   .format(snapshot.gr[22:25]))
        H._require(snapshot.gr[25] == 5,
                   "p0 CHK.A hit skipped its later in-bundle false edge")
        H._require(snapshot.nat_low & (1 << 10),
                   "CHK.S consumed the tested GR NaT")
        return ("CHK.S branched on GR NaT; CHK.A retained a hit, CHK.A.CLR "
                "cleared it, and the following typed GR check branched")

    return RuntimeCase(
        "checked GR branch and ALAT clear semantics", program, tuple(traced),
        verify, ("IA64_OP_CHK_S", "IA64_OP_CHK_A",
                 "IA64_OP_CHK_A_CLR"),
    )


def checked_branch_fr_case() -> RuntimeCase:
    def marker(address: int, reg: int, value: int, target: int) -> object:
        return H.Bundle(
            address, 0x11, H.nop_m(), H.adds(reg, value, 0),
            H.br_cond(address, target),
        )

    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 0x1820, 0)),
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=20, r3=10), traced,
    )
    H._require(address == 0x30, "checked FR setup address drifted")
    bundles.append(H.Bundle(
        0x30, 0x01, _chk_s_branch(0x30, 0x50, reg=20, fp=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x30)
    bundles.extend((
        marker(0x40, 20, 0x61, 0x70),
        marker(0x50, 20, 1, 0x70),
    ))

    _append_m(
        bundles, 0x70,
        floating_load("IA64_OP_LDFS", f1=21, r3=11, attr="a"), traced,
    )
    bundles.append(H.Bundle(
        0x80, 0x01, _chk_a_branch(0x80, 0xA0, reg=21, fp=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x80)
    bundles.extend((
        marker(0x90, 22, 2, 0xC0),
        marker(0xA0, 22, 0x62, 0x130),
    ))

    bundles.append(H.Bundle(
        0xC0, 0x01,
        _chk_a_branch(0xC0, 0xE0, reg=21, fp=True, clear=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0xC0)
    bundles.extend((
        marker(0xD0, 23, 3, 0x100),
        marker(0xE0, 23, 0x63, 0x130),
    ))

    bundles.append(H.Bundle(
        0x100, 0x01, _chk_a_branch(0x100, 0x120, reg=21, fp=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x100)
    bundles.extend((
        marker(0x110, 24, 0x64, 0x130),
        marker(0x120, 24, 4, 0x130),
        H.spin_bundle(0x130),
    ))
    program = H.Program(
        name="checked FR NatVal and typed ALAT clear lifecycle",
        bundles=tuple(bundles), terminal_ip=0x130,
        data=(H.DataWord(0x1800, 0, 8),
              H.DataWord(0x1808, 0x1fffe, 8),
              H.DataWord(0x1820, 0x3fc00000, 4)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "checked FR branches")
        H._require((snapshot.gr[20], snapshot.gr[22], snapshot.gr[23],
                    snapshot.gr[24]) == (1, 2, 3, 4),
                   "FR NatVal/hit/clear/miss markers were {}".format(
                       (snapshot.gr[20], snapshot.gr[22], snapshot.gr[23],
                        snapshot.gr[24])))
        return ("CHK.S branched on FR NatVal; typed FR CHK.A retained, "
                "cleared, then missed the advanced-load entry")

    return RuntimeCase(
        "checked FR branch and ALAT clear semantics", program, tuple(traced),
        verify, ("IA64_OP_CHK_S", "IA64_OP_CHK_A",
                 "IA64_OP_CHK_A_CLR"),
    )


def checked_branch_disabled_fr_case() -> RuntimeCase:
    fault_ip = 0x50
    fault_raw = _chk_s_branch(fault_ip, 0x60, reg=20, fp=True)
    bundles: List[object] = [
        *H._interruption_collection_setup(),
        H.Bundle(0x30, 0x01, H.ssm(IA64_PSR_DFL),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x40, 0x01, H.srlz_i(), H.nop_i(), H.nop_i()),
        H.Bundle(fault_ip, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(IA64_DISABLED_FP_VECTOR),
    ]
    program = H.Program(
        name="CHK.S FR disabled-partition interruption",
        bundles=tuple(bundles), terminal_ip=IA64_DISABLED_FP_VECTOR,
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.ip == IA64_DISABLED_FP_VECTOR and
            snapshot.exception_pending and
            snapshot.exception_kind == "disabled-fp-register-low" and
            snapshot.exception_vector == IA64_DISABLED_FP_VECTOR,
            "CHK.S f20 did not raise Disabled FP Register low",
        )
        H._require(
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == fault_ip and
            snapshot.cr_iip == fault_ip and
            snapshot.slot_valid and snapshot.slot_ip == fault_ip and
            snapshot.slot_ri == 0 and
            snapshot.slot_type == H.IA64_SLOT_TYPE_M and
            snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
            "CHK.S disabled-FR fault lost exact source/slot state",
        )
        return "CHK.S f20 raised a precise Disabled FP Register low interruption"

    return RuntimeCase(
        "checked FR disabled-partition fault", program, (fault_ip,), verify,
        ("IA64_OP_CHK_S",), True,
    )


def runtime_cases() -> Tuple[RuntimeCase, ...]:
    return (
        primary_admission_case(), alias_admission_case(), atomic_case(),
        wide_spill_case(), floating_case(), floating_zero_encoding_case(),
        floating_big_endian_case(),
        big_endian_wide_pair_case(),
        rotated_fp_pair_legal_case(), rotated_fp_pair_illegal_case(),
        alat_cache_hint_case(),
        integer_advanced_nat_page_case(), fp_advanced_nat_page_case(),
        *(fp_advanced_unsupported_case(ma) for ma in (4, 5, 6)),
        integer_speculative_nat_page_defer_case(),
        fp_speculative_nat_page_defer_case(),
        *(reserved_width_illegal_case(opcode) for opcode in (
            "IA64_OP_LD1FILL", "IA64_OP_LD2FILL", "IA64_OP_LD4FILL",
            "IA64_OP_ST1SPILL", "IA64_OP_ST2SPILL",
            "IA64_OP_ST4SPILL",
        )),
        lfetch_nat_fault_case(), lfetch_translation_fault_case(),
        nat_page_fault_case("IA64_OP_FC"),
        nat_page_fault_case("IA64_OP_LFETCH_FAULT"),
        lfetch_ed_update_case(), fc_ed_translation_fault_case(),
        fc_nonaccess_accessed_case(), fc_nonaccess_rights_case(),
        checked_branch_gr_case(),
        checked_branch_fr_case(), checked_branch_disabled_fr_case(),
    )


def self_check(cases: Sequence[RuntimeCase]) -> str:
    primary = cases[0]
    H._require(len(primary.program.bundles) - 1 == 63,
               "primary admission inventory is not 63 bundles")
    H._require(len(primary.trace_ips) == 57,
               "primary admission trace is not 57 decoder-live rows")
    H._require(set(primary.opcode_coverage) == set(DATA_PLANE_OPCODES),
               "primary admission coverage drifted")
    live_aliases = [alias for alias in ALIAS_ENCODINGS
                    if alias.status != "shadowed-by-cmpxchg"]
    H._require(len(cases[1].trace_ips) == len(live_aliases),
               "live-alias program length drifted")
    for case in cases:
        addresses = [bundle.address for bundle in case.program.bundles]
        H._require(len(addresses) == len(set(addresses)),
                   case.name + ": duplicate bundle address")
        H._require(case.program.terminal_ip in addresses,
                   case.name + ": terminal bundle missing")
        H._require(set(case.trace_ips) < set(addresses),
                   case.name + ": trace set must exclude terminal bundle")
        for bundle in case.program.bundles:
            for raw in (bundle.slot0, bundle.slot1, bundle.slot2):
                H._require(0 <= raw < (1 << 41),
                           case.name + ": instruction exceeds 41 bits")
    shadowed = [alias for alias in ALIAS_ENCODINGS
                if alias.status == "shadowed-by-cmpxchg"]
    H._require(len(shadowed) == 12,
               "expected 12 split-load branches shadowed by cmpxchg")
    reserved = [opcode for opcode in DATA_PLANE_OPCODES
                if SPEC_BY_OPCODE[opcode].isa_status ==
                "decoder-reserved-width"]
    H._require(len(reserved) == 6,
               "expected six decoder-reserved spill/fill widths")
    return ("{} programs; 63 primary bundles (57 decoder-live); {} live "
            "alias/completer bundles; 12 shadowed split-load encodings; "
            "6 reserved-width rows"
            .format(len(cases), len(live_aliases)))


def run_case(qemu: Path, case: RuntimeCase) -> str:
    snapshot = H.run_program(
        qemu, case.program,
        preserve_fault_slot=case.preserve_fault_slot,
        typed_direct_trace_ips=case.trace_ips,
        one_bundle_per_tb=True,
    )
    return case.verify(snapshot)


def _print_failure(exc: Exception) -> None:
    for line in str(exc).splitlines() or [repr(exc)]:
        print("# " + line)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path,
                        help="path to rewritten qemu-system-ia64")
    parser.add_argument("--self-check", action="store_true",
                        help="construct and validate programs without QEMU")
    args = parser.parse_args(argv)
    cases = runtime_cases()
    detail = self_check(cases)
    if args.self_check or args.qemu is None:
        print("data-plane runtime self-check: " + detail)
        return 0

    qemu = args.qemu.expanduser().resolve()
    print("TAP version 13")
    print("1..{}".format(len(cases)))
    if not qemu.is_file():
        for index, case in enumerate(cases, start=1):
            print("not ok {} - {}".format(index, case.name))
        print("# QEMU executable does not exist: {}".format(qemu))
        return 1
    failures = 0
    for index, case in enumerate(cases, start=1):
        try:
            result = run_case(qemu, case)
            print("ok {} - {}".format(index, case.name))
            print("# " + result)
        except Exception as exc:
            failures += 1
            print("not ok {} - {}".format(index, case.name))
            _print_failure(exc)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
